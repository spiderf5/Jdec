"""The execution engine: frames, control flow, exceptions, calls.

The operand stack is slot-based per JVMS: every long/double occupies two
slots (value + `VOID`). Category knowledge comes from the opcode and the
descriptor, never from the value — that is what keeps `dup2`/`pop2`/`swap`
exact and makes a stack-shape bug loud (`pop2` refuses a missing filler)
instead of silent.
"""

from __future__ import annotations

import math
import struct
import time

from .. import bytecode as BC
from .. import classfile as CF
from ..jint import i32, i64
from .values import (VOID, Arr, Frame, Heap, Inconclusive, JavaThrow, Obj,
                     Opaque, Outcome,
                     Unsupported, _append_text, as_int, default_value,
                     is_opaque, jstr, make_model)

OP_GOTO = 0xA7
OP_GOTO_W = 0xC8
OP_TABLESWITCH = 0xAA
OP_LOOKUPSWITCH = 0xAB

_ICONST = {0x02: -1, 0x03: 0, 0x04: 1, 0x05: 2, 0x06: 3, 0x07: 4, 0x08: 5}

_BUDGET_DEFAULTS = dict(steps=200_000, wall_seconds=2.0, max_depth=16,
                        max_objects=20_000, max_slots=200_000)


class Universe:
    """One side's view of the jar: lazily parsed classes, no JVM."""

    def __init__(self, jar, cache=None):
        import zipfile
        self._zip = zipfile.ZipFile(jar)
        self._cache = cache if cache is not None else {}
        self._own: dict[str, CF.ClassFile] = {}

    def load(self, internal: str):
        if internal in self._own:
            return self._own[internal]
        try:
            data = self._zip.read(internal + ".class")
        except KeyError:
            return self._cache.get(internal)
        cf = CF.parse(data)
        self._own[internal] = cf
        return cf

    def known(self, internal: str) -> bool:
        try:
            self._zip.getinfo(internal + ".class")
            return True
        except KeyError:
            return internal in self._cache

    def super_of(self, internal: str):
        cf = self.load(internal)
        if cf is None or not cf.super_class:
            return None
        entry = cf.cp[cf.super_class] if cf.super_class < len(cf.cp) else None
        if entry and entry[0] == CF.C_CLASS:
            return cf.utf8(entry[1][0])
        return None


class Interp:
    """Execute one method with concrete values on a private heap."""

    def __init__(self, universe: Universe, heap: Heap, models,
                 *, steps: int = 200_000, wall_seconds: float = 2.0,
                 max_depth: int = 16):
        self.universe = universe
        self.heap = heap
        self.models = models
        self.steps = steps
        self.deadline = time.monotonic() + wall_seconds
        self.max_depth = max_depth
        self.depth = 0
        self.count = 0
        self._bsm_cache: dict[int, list] = {}

    # -- entry point ----------------------------------------------------

    def invoke(self, cls: str, name: str, desc: str, receiver, args: list):
        """Run `cls.name(desc)`; returns an `Outcome`."""
        try:
            self._ensure_init(cls)
            value = self._call(cls, name, desc, receiver, args, exact=True)
            out = Outcome("return", value=value)
        except JavaThrow as exc:
            out = Outcome("throw", exception=exc.cls, value=exc.obj)
        except Unsupported as exc:
            out = Outcome("unsupported", reason=str(exc)[:160])
        except Inconclusive as exc:
            out = Outcome("inconclusive", reason=str(exc)[:160])
        except RecursionError:
            out = Outcome("inconclusive", reason="call depth exhausted")
        if is_opaque(out.value) or (out.kind == "throw"
                                    and is_opaque(out.exception)):
            return Outcome("inconclusive", reason="result depends on an "
                                                  "unmodelled call")
        out.steps = self.count
        return out

    # -- class initialization ------------------------------------------

    def _ensure_init(self, cls: str):
        if cls in self.heap.initialized or not self.universe.known(cls):
            return
        self.heap.initialized.add(cls)
        sup = self.universe.super_of(cls)
        if sup and sup != "java/lang/Object":
            self._ensure_init(sup)
        cf = self.universe.load(cls)
        if cf is None:
            return
        init = next((m for m in cf.methods
                     if cf.utf8(m.name_index) == "<clinit>"), None)
        if init is not None:
            self._execute(cf, init, None, [])

    # -- method resolution ---------------------------------------------

    def _find_method(self, cls: str, name: str, desc: str):
        current = cls
        for _ in range(32):
            cf = self.universe.load(current) if self.universe.known(current) \
                else None
            if cf is None:
                return None, None
            for m in cf.methods:
                if cf.utf8(m.name_index) == name \
                        and cf.utf8(m.descriptor_index) == desc:
                    # an abstract/native declaration found on the way up is
                    # not the method to run — keep looking for the concrete
                    # implementation (invokeinterface on a stand-in receiver
                    # starts at the interface itself)
                    ci = BC.method_code(cf, m, decode_insns=False)
                    if ci is None or not ci.code:
                        continue
                    return cf, m
            sup = self.universe.super_of(current)
            if sup is None or sup == "java/lang/Object":
                if name == "<init>" or name == "<clinit>":
                    return None, None
                # Object methods are modelled, never executed
                return None, None
            current = sup
        return None, None

    def _call(self, cls: str, name: str, desc: str, receiver, args: list,
              *, exact: bool = False):
        if self.depth >= self.max_depth:
            raise Unsupported("call depth exhausted")
        cf, member = self._find_method(cls, name, desc) if \
            self.universe.known(cls) else (None, None)
        if member is not None:
            self._ensure_init(cls)
            self.depth += 1
            try:
                result = self._execute(cf, member, receiver, args)
            finally:
                self.depth -= 1
            if result.kind == "return":
                return result.value
            if result.kind == "unsupported":
                raise Unsupported(result.reason)
            raise Inconclusive(result.reason)
        handled, value = self.models.invoke(self, cls, name, desc,
                                            receiver, args)
        if handled:
            return value
        return self.heap.opaque(f"call:{cls}.{name}{desc}")

    # -- the interpreter loop ------------------------------------------

    def _execute(self, cf: CF.ClassFile, member: CF.Member, receiver, args):
        ci = BC.method_code(cf, member, decode_insns=False)
        if ci is None:
            raise Unsupported("abstract or native method")
        if not ci.code:
            raise Unsupported("empty method body")
        order = BC.decode(ci.code)
        desc = cf.utf8(member.descriptor_index)
        is_static = bool(member.access_flags & CF.ACC_STATIC)
        max_locals = ci.max_locals or (len(args) + (0 if is_static else 1) + 4)
        locals_ = [None] * max(max_locals, len(args) + (0 if is_static else 1))
        idx = 0
        if not is_static:
            locals_[0] = receiver
            idx = 1
        for d in _param_descs(desc):
            if idx >= len(locals_):
                break
            locals_[idx] = args.pop(0) if args else None
            if d in ("J", "D") and idx + 1 < len(locals_):
                locals_[idx + 1] = VOID
            idx += 2 if d in ("J", "D") else 1
        frame = Frame(locals_, [])
        index = 0
        ret_desc = desc.split(")", 1)[1]
        while True:
            self.count += 1
            if self.count > self.steps or (self.count % 512 == 0 and
                                           time.monotonic() > self.deadline):
                return Outcome("inconclusive", reason="step or wall-clock "
                                                      "budget exhausted")
            ins = order[index]
            if 0xAC <= ins.op <= 0xB1:               # <t>return
                if ret_desc == "V":
                    return Outcome("return", value=None)
                value = frame.pop2() if ret_desc in ("J", "D") \
                    else frame.pop()
                return Outcome("return", value=value)
            try:
                nxt = self._step(cf, ins, frame, order, index)
            except JavaThrow as exc:
                target = self._handler(cf, ci, ins.pc, exc.cls)
                if target is None:
                    raise
                frame.stack.clear()
                frame.push(exc.obj)
                index = index_of_pc(order, target)
                continue
            except Unsupported as exc:
                # nested calls accumulate their pcs, so the reason names the
                # whole failing path, not just the innermost opcode
                raise Unsupported(f"pc {ins.pc} (0x{ins.op:02x}): {exc}") \
                    from None
            index = index_of_pc(order, nxt)

    def _handler(self, cf: CF.ClassFile, ci, pc: int, exc_cls: str):
        for h in ci.handlers:
            if not (h.start_pc <= pc < h.end_pc):
                continue
            if h.catch_type == 0:
                return h.handler_pc
            entry = cf.cp[h.catch_type] if 0 < h.catch_type < len(cf.cp) else None
            if entry and entry[0] == CF.C_CLASS:
                catch = cf.utf8(entry[1][0])
                if self._is_subclass(exc_cls, catch):
                    return h.handler_pc
        return None

    def _is_subclass(self, sub: str, sup: str) -> bool:
        if sub == sup or sup == "java/lang/Object" or sup == "java/lang/Throwable":
            return True
        current = sub
        for _ in range(32):
            if current == sup:
                return True
            if not self.universe.known(current):
                if current in _THROWABLE_PARENT:
                    current = _THROWABLE_PARENT[current]
                    continue
                return False
            nxt = self.universe.super_of(current)
            if nxt is None:
                return False
            current = nxt
        return False

    # -- one instruction -------------------------------------------------

    def _step(self, cf: CF.ClassFile, ins: BC.Insn, f: Frame,
              order: list[BC.Insn], index: int):
        op = ins.op
        nxt = self._next(order, index)
        if op == 0x00:                                   # nop
            return nxt
        if op == 0x01:                                   # aconst_null
            f.push(None); return nxt
        if 0x02 <= op <= 0x08:                           # iconst_m1..5
            f.push(_ICONST[op]); return nxt
        if op in (0x09, 0x0A):                           # lconst
            f.push2(op - 0x09); return nxt
        if 0x0B <= op <= 0x0D:                           # fconst
            f.push(float(op - 0x0B)); return nxt
        if op in (0x0E, 0x0F):                           # dconst
            f.push2(float(op - 0x0E)); return nxt
        if op in (0x10, 0x11):                           # bipush / sipush
            f.push(ins.arg - 0x100 if (op == 0x10 and ins.arg > 0x7F)
                   else ins.arg - 0x10000 if op == 0x11 and ins.arg > 0x7FFF
                   else ins.arg)
            return nxt
        if op in (0x12, 0x13):                           # ldc
            f.push(self._ldc(cf, ins.arg, wide=False)); return nxt
        if op == 0x14:                                   # ldc2_w
            f.push2(self._ldc(cf, ins.arg, wide=True)); return nxt
        if op in (0x15, 0x17, 0x19):                     # iload/fload/aload
            f.push(f.get(ins.arg)); return nxt
        if op in (0x16, 0x18):                           # lload/dload
            f.push2(f.get(ins.arg)); return nxt
        if 0x1A <= op <= 0x2D:                           # <t>load_<n>
            kind = (op - 0x1A) // 4
            idx = (op - 0x1A) % 4
            if kind in (1, 3):
                f.push2(f.get(idx))
            else:
                f.push(f.get(idx))
            return nxt
        if 0x2E <= op <= 0x35:                           # <t>aload
            i = f.pop_int(); arr = f.pop()
            self._check_array(arr, i)
            value = arr.items[i]
            if op in (0x2F, 0x31):                       # laload/daload
                f.push2(value)
            else:
                f.push(value)
            return nxt
        if 0x36 <= op <= 0x3A:                           # <t>store
            if op in (0x37, 0x39):                       # lstore/dstore
                f.set(ins.arg, f.pop2())
            else:
                f.set(ins.arg, f.pop())
            return nxt
        if 0x3B <= op <= 0x4E:                           # <t>store_<n>
            sub = op - 0x3B
            kind, idx = sub // 4, sub % 4
            f.set(idx, f.pop2() if kind in (1, 3) else f.pop())
            return nxt
        if 0x4F <= op <= 0x56:                           # <t>astore
            if op in (0x50, 0x52):                       # lastore/dastore
                value = f.pop2()
            else:
                value = f.pop()
            i = f.pop_int(); arr = f.pop()
            self._check_array(arr, i)
            arr.items[i] = value
            return nxt
        if op == 0x57:                                   # pop
            f.pop(); return nxt
        if op == 0x58:                                   # pop2
            f.pop(); f.pop(); return nxt
        if 0x59 <= op <= 0x5F:                           # dup family / swap
            self._stack_op(op, f); return nxt
        if 0x60 <= op <= 0x83:                           # arithmetic
            self._arith(op, f); return nxt
        if op == 0x84:                                   # iinc
            f.set(ins.arg, i32(as_int(f.get(ins.arg)) + ins.arg2))
            return nxt
        if 0x85 <= op <= 0x93:                           # conversions
            self._convert(op, f); return nxt
        if op == 0x94:                                   # lcmp
            b = f.pop2(); a = f.pop2()
            f.push((a > b) - (a < b)); return nxt
        if op in (0x95, 0x96):                           # fcmpl / fcmpg
            b = f.pop(); a = f.pop()
            f.push(_fcmp(a, b, cmpl=op == 0x95)); return nxt
        if op in (0x97, 0x98):                           # dcmpl / dcmpg
            b = f.pop2(); a = f.pop2()
            f.push(_fcmp(a, b, cmpl=op == 0x97)); return nxt
        if 0x99 <= op <= 0xA6:                           # branches
            return self._branch(cf, ins, f, self._cond(op, f), order, index)
        if op in (OP_TABLESWITCH, OP_LOOKUPSWITCH):
            return self._switch(cf, ins, f)
        if op in (OP_GOTO, OP_GOTO_W):
            return ins.pc + ins.arg
        if op in (0xB2, 0xB3):                           # get/putstatic
            cls, name, desc = self._member(cf, ins.arg)
            self._ensure_init(cls)
            if op == 0xB2:
                key = (cls, name)
                if key not in self.heap.statics:
                    self.heap.statics[key] = self._static_default(cls, name,
                                                                  desc)
                value = self.heap.statics[key]
                f.push2(value) if desc[0] in "JD" else f.push(value)
            else:
                self.heap.statics[(cls, name)] = \
                    f.pop2() if desc[0] in "JD" else f.pop()
            return nxt
        if op in (0xB4, 0xB5):                           # get/putfield
            cls, name, desc = self._member(cf, ins.arg)
            if op == 0xB4:
                obj = f.pop()
                self._check_obj(obj)
                value = obj.fields.get(name, default_value(desc, self.heap))
                f.push2(value) if desc[0] in "JD" else f.push(value)
            else:
                value = f.pop2() if desc[0] in "JD" else f.pop()
                obj = f.pop()
                self._check_obj(obj)
                obj.fields[name] = value
            return nxt
        if op in (0xB6, 0xB7, 0xB8, 0xB9):
            return self._invoke(cf, ins, f, order, index)
        if op == 0xBA:                                   # invokedynamic
            return self._indy(cf, ins, f, order, index)
        if op == 0xBB:                                   # new
            cls, = self._class(cf, ins.arg)
            self._check_budget_object()
            f.push(Obj(cls, {}))
            return nxt
        if op in (0xBC, 0xBD):                           # newarray/anewarray
            if f.stack and not isinstance(f.stack[-1], (int, bool)):
                raise Unsupported(
                    f"array length is not an int (pc {ins.pc}, op "
                    f"0x{op:02x}): the operand stack is misshaped")
            count = f.pop_int()
            if count < 0:
                raise JavaThrow("java/lang/NegativeArraySizeException",
                                str(count))
            self._check_budget_object(count)
            if op == 0xBD:
                cls, = self._class(cf, ins.arg)
                comp = cls[1:-1] if cls.startswith("L") else cls
            else:
                comp = {4: "I", 5: "J", 6: "F", 7: "D", 8: "Z", 9: "B",
                        10: "S", 11: "C"}.get(ins.arg, "I")
            fill = 0 if comp[0] not in "L[" else \
                default_value(comp if comp.startswith("[")
                              else "L" + comp + ";", self.heap)
            f.push(Arr(comp, [fill] * count))
            return nxt
        if op == 0xBE:                                   # arraylength
            arr = f.pop()
            self._check_array(arr, None)
            f.push(len(arr.items)); return nxt
        if op == 0xBF:                                   # athrow
            obj = f.pop()
            if obj is None:
                raise JavaThrow("java/lang/NullPointerException",
                                "athrow null")
            if not isinstance(obj, Obj):
                raise Unsupported("athrow of a non-object")
            cls, msg = getattr(obj, "throwable", (obj.cls, ""))
            raise JavaThrow(cls, msg, obj)
        if op == 0xC0:                                   # checkcast
            obj = f.pop(); f.push(obj); return nxt
        if op == 0xC1:                                   # instanceof
            obj = f.pop()
            cls, = self._class(cf, ins.arg)
            f.push(self._instanceof(obj, cls)); return nxt
        if op in (0xC2, 0xC3):                           # monitor enter/exit
            f.pop(); return nxt
        if op == 0xC4:                                   # wide
            return self._wide(cf, ins, f, order, index)
        if op == 0xC5:                                   # multianewarray
            for _ in range(ins.arg2):
                f.pop()
            cls, = self._class(cf, ins.arg)
            self._check_budget_object(1)
            f.push(Arr(cls[1:], [])); return nxt
        if op in (0xC6, 0xC7):                           # ifnull/ifnonnull
            v = f.pop()
            taken = (v is None) if op == 0xC6 else (v is not None)
            return self._branch(cf, ins, f, taken, order, index)
        raise Unsupported(f"opcode 0x{op:02x} is not modelled")

    # -- helpers used by _step ------------------------------------------

    @staticmethod
    def _next(order, index):
        if index + 1 >= len(order):
            raise Unsupported("fell off the end of the method")
        return order[index + 1].pc

    def _branch(self, cf, ins, f, taken: bool, order=None, index: int = 0):
        if taken:
            return ins.pc + ins.arg
        return self._next(order, index)

    def _switch(self, cf, ins, f):
        key = f.pop_int()
        if ins.op == OP_TABLESWITCH:
            low = ins.switch_low
            if key < low or key >= low + len(ins.targets) - 1:
                return ins.targets[0]
            return ins.targets[1 + key - low]
        for k, t in zip(ins.switch_keys, ins.targets[1:]):
            if k == key:
                return t
        return ins.targets[0]

    def _cond(self, op: int, f: Frame) -> bool:
        if op in (0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E):
            v = f.pop_int()
            return {0x99: v == 0, 0x9A: v != 0, 0x9B: v < 0,
                    0x9C: v >= 0, 0x9D: v > 0, 0x9E: v <= 0}[op]
        if op in (0xA5, 0xA6):
            # if_acmpeq / if_acmpne compare *references*; routing them through
            # pop_int is how "expected an int, got Obj" happens
            b = f.pop(); a = f.pop()
            return (a is b) if op == 0xA5 else (a is not b)
        b = f.pop_int(); a = f.pop_int()
        return {0x9F: a == b, 0xA0: a != b, 0xA1: a < b, 0xA2: a >= b,
                0xA3: a > b, 0xA4: a <= b}[op]

    def _stack_op(self, op: int, f: Frame):
        """Slot-level stack shuffling: with the VOID filler in place these are
        verbatim JVMS translations, category-2 values included."""
        s = f.stack
        if op == 0x59:                       # dup
            s.append(s[-1])
        elif op == 0x5A:                     # dup_x1
            s.insert(-2, s[-1])
        elif op == 0x5B:                     # dup_x2
            s.insert(-3, s[-1])
        elif op == 0x5C:                     # dup2
            s.extend(s[-2:])
        elif op == 0x5D:                     # dup2_x1
            s[-3:-3] = s[-2:]
        elif op == 0x5E:                     # dup2_x2
            s[-4:-4] = s[-2:]
        elif op == 0x5F:                     # swap
            s[-1], s[-2] = s[-2], s[-1]
        else:
            raise Unsupported("unknown stack opcode")

    # -- arithmetic ------------------------------------------------------

    def _arith(self, op: int, f: Frame):
        kind = _ARITH_KIND[op]
        if kind == "l12":                    # long shift: long value, int count
            count = f.pop_int()
            a = f.pop2()
            result = _ARITH_FN[op](a, count)
            f.push2(result)
            return
        if kind in ("ln", "dn"):             # unary on a category-2 value
            a = f.pop2()
            if kind == "dn":
                _check_float(a)
            f.push2(_ARITH_FN[op](a))
            return
        if kind in ("fn",):
            a = f.pop()
            _check_float(a)
            f.push(_ARITH_FN[op](a))
            return
        if kind in ("l", "d"):
            b = f.pop2(); a = f.pop2()
            if kind == "d":
                _check_float(a); _check_float(b)
            _check_zero(op, a, b)
            f.push2(_ARITH_FN[op](a, b))
            return
        b = f.pop(); a = f.pop()             # i / f
        if kind == "f":
            _check_float(a); _check_float(b)
        _check_zero(op, a, b)
        f.push(_ARITH_FN[op](a, b))

    def _convert(self, op: int, f: Frame):
        src, dst = _CONV_KIND[op]
        v = f.pop2() if src == 2 else f.pop()
        if dst == 2:
            f.push2(_CONV_FN[op](v))
        else:
            f.push(_CONV_FN[op](v))

    def _invoke(self, cf: CF.ClassFile, ins: BC.Insn, f: Frame,
                order: list[BC.Insn], index: int):
        cls, name, desc = self._member(cf, ins.arg)
        args = _pop_args(desc, f)
        receiver = None
        if op_needs_receiver(ins.op):
            receiver = f.pop()
        if ins.op in (0xB6, 0xB9) and receiver is None:
            # invokevirtual/invokeinterface on null is an NPE by spec —
            # making it a throw (not "unsupported") lets both sides agree on
            # it, which is real differential evidence
            raise JavaThrow("java/lang/NullPointerException",
                            f"invokevirtual {cls}.{name} on null")
        if ins.op == 0xB7:                            # invokespecial
            self._check_obj(receiver)
            if name == "<init>" and receiver is not None \
                    and receiver.cls == "java/lang/Object":
                receiver.cls = cls
        value = self._call(cls, name, desc, receiver, args,
                           exact=ins.op in (0xB7, 0xB8))
        if ins.op == 0xB7 and name == "<init>" and value is not None:
            # a model that *built* the object (e.g. `new String(x)` becomes a
            # real str) replaces the hollow receiver reference on the stack
            f.push(value)
        ret = desc.split(")", 1)[1]
        if ret != "V":
            f.push2(value) if ret[0] in "JD" else f.push(value)
        return self._next(order, index)

    def _indy(self, cf: CF.ClassFile, ins: BC.Insn, f: Frame,
              order: list[BC.Insn], index: int):
        entry = cf.cp[ins.arg]
        nt = cf.cp[entry[1][1]]
        name = cf.utf8(nt[1][0]); desc = cf.utf8(nt[1][1])
        args = _pop_args(desc, f)
        ret = desc.split(")", 1)[1]
        if ret == "Ljava/lang/String;":
            recipe = self._concat_recipe(cf, entry[1][0])
            if recipe is not None:
                # makeConcatWithConstants: the recipe carries the literal
                # parts (\u0001 = next dynamic argument). A rewrite that
                # changes a literal must be visible, so the exact recipe
                # matters — ignoring it was a false-same hole.
                f.push(self._expand_recipe(recipe, args))
            else:
                f.push("".join(_append_text(a) for a in args))
            return self._next(order, index)
        lam = self._lambda_site(cf, entry[1][0], name, desc, args)
        if lam is not None:
            f.push(lam)
            return self._next(order, index)
        if ret != "V":
            if ret[0] in "JD":
                f.push2(self.heap.opaque(f"indy:{name}{desc}"))
            else:
                f.push(self.heap.opaque(f"indy:{name}{desc}"))
        return self._next(order, index)

    def _bsm(self, cf: CF.ClassFile):
        """Parsed BootstrapMethods of one class, cached per ClassFile."""
        cached = self._bsm_cache.get(id(cf))
        if cached is None:
            from .. import bsm as B
            try:
                cached = B.parse_bsm(cf) or []
            except Exception:   # noqa: BLE001 - malformed BSM → no lambdas
                cached = []
            self._bsm_cache[id(cf)] = cached
        return cached

    def _concat_recipe(self, cf: CF.ClassFile, bsm_idx: int):
        """The recipe string of a StringConcatFactory bootstrap, or None."""
        bsms = self._bsm(cf)
        if not 0 <= bsm_idx < len(bsms):
            return None
        e = bsms[bsm_idx]
        if e.owner != "java/lang/invoke/StringConcatFactory" \
                or e.name != "makeConcatWithConstants":
            return None
        for kind, value in e.args:
            if kind == "lit" and isinstance(value, str):
                return value
        return None

    @staticmethod
    def _expand_recipe(recipe: str, args: list) -> str:
        out = []
        arg_i = 0
        for ch in recipe:
            if ch == "\x01":                      # \u0001: next argument
                out.append(_append_text(args[arg_i]) if arg_i < len(args)
                           else "null")
                arg_i += 1
            elif ch == "\x02":                    # \u0002: a static constant
                out.append("\x02")               # rare; kept identical
            else:
                out.append(ch)
        return "".join(out)

    def _lambda_site(self, cf: CF.ClassFile, bsm_idx: int, sam_name: str,
                     indy_desc: str, captured: list):
        """Translate a LambdaMetafactory call site into a callable model
        instance, or None when the site is not a recognisable lambda.

        The impl MethodHandle in the bootstrap arguments names the synthetic
        `lambda$...` method (kind 6, static) or the referenced instance method
        (kind 5/7, with the receiver as the first captured value). The SAM
        interface comes from the call site's return descriptor.
        """
        bsms = self._bsm(cf)
        if not 0 <= bsm_idx < len(bsms):
            return None
        e = bsms[bsm_idx]
        if e.owner != "java/lang/invoke/LambdaMetafactory" \
                or e.name != "metafactory":
            return None
        impl = next((v for k, v in e.args if k == "mh"), None)
        if not isinstance(impl, dict) or not impl.get("owner"):
            return None
        ret = indy_desc.split(")", 1)[1]
        if not ret.startswith("L"):
            return None
        sam_cls = ret[1:-1]
        kind = impl.get("kind", 0)
        if kind == 6:                       # static impl: captured lead args
            return Obj(sam_cls, {"_jdec_cls": impl["owner"],
                                 "_jdec_method": impl["name"],
                                 "_jdec_desc": impl.get("desc", "()V"),
                                 "_jdec_captured": list(captured),
                                 "_jdec_kind": 6})
        if kind in (5, 7):                  # instance method reference
            # with captures the receiver is captured[0]; without, the receiver
            # is the SAM call's first argument (`String::length` as
            # `Function<String, Integer>`)
            return Obj(sam_cls, {"_jdec_cls": impl["owner"],
                                 "_jdec_method": impl["name"],
                                 "_jdec_desc": impl.get("desc", "()V"),
                                 "_jdec_captured": list(captured[1:])
                                 if captured else [],
                                 "_jdec_ref": captured[0] if captured
                                 else None,
                                 "_jdec_kind": kind})
        return None

    def _ldc(self, cf: CF.ClassFile, idx: int, *, wide: bool):
        entry = cf.cp[idx] if 0 < idx < len(cf.cp) else None
        if not entry:
            raise Unsupported("ldc of an unreadable constant")
        if entry[0] == CF.C_INTEGER:
            raw = entry[1][0] if isinstance(entry[1], (list, tuple)) else entry[1]
            return int.from_bytes(raw, "big", signed=True) \
                if isinstance(raw, bytes) and len(raw) == 4 else raw
        if entry[0] == CF.C_FLOAT:
            raw = entry[1][0] if isinstance(entry[1], (list, tuple)) else entry[1]
            return struct.unpack(">f", raw)[0] if isinstance(raw, bytes) else raw
        if entry[0] == CF.C_LONG:
            raw = entry[1][0] if isinstance(entry[1], (list, tuple)) else entry[1]
            return int.from_bytes(raw, "big", signed=True) \
                if isinstance(raw, bytes) and len(raw) == 8 else raw
        if entry[0] == CF.C_DOUBLE:
            raw = entry[1][0] if isinstance(entry[1], (list, tuple)) else entry[1]
            return struct.unpack(">d", raw)[0] if isinstance(raw, bytes) else raw
        if entry[0] == CF.C_STRING:
            return self.heap.intern(cf.utf8(entry[1][0]))
        if entry[0] == CF.C_CLASS:
            return Obj("java/lang/Class", {"name": cf.utf8(entry[1][0])})
        raise Unsupported("ldc of an unsupported constant")

    def _member(self, cf: CF.ClassFile, idx: int):
        entry = cf.cp[idx]
        owner = cf.cp[entry[1][0]]
        nt = cf.cp[entry[1][1]]
        cls = cf.utf8(owner[1][0])
        name = cf.utf8(nt[1][0])
        desc = cf.utf8(nt[1][1])
        return cls, name, desc

    def _class(self, cf: CF.ClassFile, idx: int):
        entry = cf.cp[idx]
        return (cf.utf8(entry[1][0]),)

    def _static_default(self, cls: str, name: str, desc: str):
        # a static the class never wrote is null (or 0 for primitives); inventing
        # an array here is how "expected an int, got Arr" happens
        if desc.startswith("L") or desc.startswith("["):
            return None
        return default_value(desc, self.heap)

    def _check_obj(self, obj):
        if obj is None:
            raise JavaThrow("java/lang/NullPointerException", "null receiver")
        if isinstance(obj, Opaque):
            raise Unsupported(f"receiver depends on an unmodelled call "
                              f"({obj.source})")
        if not isinstance(obj, Obj):
            raise Unsupported(f"field access on a non-object "
                              f"({type(obj).__name__})")

    def _check_array(self, arr, index):
        if arr is None:
            raise JavaThrow("java/lang/NullPointerException", "null array")
        if isinstance(arr, Opaque):
            raise Unsupported(f"array depends on an unmodelled call "
                              f"({arr.source})")
        if not isinstance(arr, Arr):
            raise Unsupported(f"array access on a non-array "
                              f"({type(arr).__name__})")
        if index is not None and not 0 <= index < len(arr.items):
            raise JavaThrow("java/lang/ArrayIndexOutOfBoundsException",
                            f"index {index}, length {len(arr.items)}")

    def _check_budget_object(self, count: int = 1):
        if len(self.heap.objects) + count > 20_000:
            raise Unsupported("heap budget exhausted")

    def _instanceof(self, obj, cls: str) -> int:
        if obj is None:
            return 0
        if cls == "java/lang/Object":
            return 1
        if isinstance(obj, str) and cls == "java/lang/String":
            return 1
        if isinstance(obj, Obj):
            if obj.cls == cls:
                return 1
            if self.universe.known(obj.cls):
                return 1 if self._is_subclass(obj.cls, cls) else 0
            if cls.startswith("java/util/") and obj.cls.startswith("java/util/"):
                return 1
        return 0

    def _wide(self, cf: CF.ClassFile, ins: BC.Insn, f: Frame,
              order: list[BC.Insn], index: int):
        sub = ins.arg
        idx = struct.unpack(">H", ins.raw[2:4])[0]
        nxt = self._next(order, index)
        if sub in (0x15, 0x17, 0x19):                 # iload/fload/aload
            f.push(f.get(idx)); return nxt
        if sub in (0x16, 0x18):                       # lload/dload
            f.push2(f.get(idx)); return nxt
        if sub in (0x37, 0x39):                       # lstore/dstore
            f.set(idx, f.pop2()); return nxt
        if 0x36 <= sub <= 0x3A:
            f.set(idx, f.pop()); return nxt
        if sub == 0x84:                               # iinc
            const = struct.unpack(">h", ins.raw[4:6])[0]
            f.set(idx, i32(as_int(f.get(idx)) + const))
            return nxt
        raise Unsupported("wide of an unmodelled sub-opcode")


_THROWABLE_PARENT = {
    "java/lang/NullPointerException": "java/lang/RuntimeException",
    "java/lang/ArithmeticException": "java/lang/RuntimeException",
    "java/lang/IndexOutOfBoundsException": "java/lang/RuntimeException",
    "java/lang/ArrayIndexOutOfBoundsException":
        "java/lang/IndexOutOfBoundsException",
    "java/lang/StringIndexOutOfBoundsException":
        "java/lang/IndexOutOfBoundsException",
    "java/lang/ClassCastException": "java/lang/RuntimeException",
    "java/lang/NumberFormatException": "java/lang/IllegalArgumentException",
    "java/lang/UnsupportedOperationException": "java/lang/RuntimeException",
    "java/io/IOException": "java/lang/Exception",
    "java/io/UncheckedIOException": "java/lang/RuntimeException",
    "java/lang/IllegalArgumentException": "java/lang/RuntimeException",
    "java/lang/IllegalStateException": "java/lang/RuntimeException",
    "java/util/NoSuchElementException": "java/lang/RuntimeException",
    "java/lang/Exception": "java/lang/Throwable",
    "java/lang/RuntimeException": "java/lang/Exception",
    "java/net/ConnectException": "java/io/IOException",
    "java/nio/file/NoSuchFileException": "java/io/IOException",
    "java/nio/file/FileSystemException": "java/io/IOException",
    "java/nio/file/FileAlreadyExistsException": "java/io/IOException",
    "java/lang/ReflectiveOperationException": "java/lang/Exception",
    "java/lang/ClassNotFoundException":
        "java/lang/ReflectiveOperationException",
}


def _jdiv(a: int, b: int, mask) -> int:
    """JVM division truncates toward zero; Python floors."""
    if b == 0:
        raise JavaThrow("java/lang/ArithmeticException", "/ by zero")
    q = abs(a) // abs(b)
    if (a < 0) != (b < 0):
        q = -q
    return mask(q)


def _jrem(a: int, b: int, mask) -> int:
    if b == 0:
        raise JavaThrow("java/lang/ArithmeticException", "/ by zero")
    q = abs(a) // abs(b)
    if (a < 0) != (b < 0):
        q = -q
    return mask(a - b * q)


def _check_zero(op: int, a, b):
    # integer division/rem only; float division by zero is IEEE inf/nan
    if op in (0x6C, 0x6D, 0x70, 0x71) and b == 0:
        raise JavaThrow("java/lang/ArithmeticException", "/ by zero")


def _check_float(v):
    """A float operand must be numeric; an Opaque/Obj here is a tainted
    value that must become Unsupported, never a Python TypeError."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return
    if isinstance(v, bool):
        return
    if isinstance(v, Opaque):
        raise Unsupported(f"expected a float/double, got an Opaque value "
                          f"from {v.source}")
    raise Unsupported(f"expected a float/double, got {type(v).__name__}")


def _fdiv(a, b):
    if math.isnan(a) or math.isnan(b):
        return float("nan")
    if b == 0.0:
        if a == 0.0:
            return float("nan")
        sign = (math.copysign(1.0, a) * math.copysign(1.0, b))
        return float("inf") if sign > 0 else float("-inf")
    try:
        return a / b
    except OverflowError:
        return float("inf") if a > 0 else float("-inf")


def _frem(a, b):
    # JVMS drem: NaN if either is NaN; infinite a or zero b -> NaN;
    # infinite b -> a; else a - b*q with q = trunc(a/b)
    if math.isnan(a) or math.isnan(b):
        return float("nan")
    if math.isinf(a) or b == 0.0:
        return float("nan")
    if math.isinf(b):
        return a
    q = math.trunc(a / b) if b != 0 else 0.0
    r = a - b * q
    if r == 0.0:
        return math.copysign(0.0, a)
    return r


def _fcmp(a, b, *, cmpl: bool) -> int:
    if math.isnan(a) or math.isnan(b):
        return -1 if cmpl else 1
    return (a > b) - (a < b)


def _f2i_clamp(v: float, lo: int, hi: int) -> int:
    if math.isnan(v):
        return 0
    if v >= hi:
        return hi
    if v <= lo:
        return lo
    return int(v)                       # Python int() truncates toward zero


def _int_mask_op(fn):
    return lambda a, b: i32(fn(a, b))


# kind: i = int binop (1,1 -> 1), l = long binop (2,2 -> 2),
#       f = float binop, d = double binop, i12/l12 = shift with int count,
#       in/ln/fn/dn = unary
_ARITH_KIND = {
    0x60: "i", 0x61: "l", 0x62: "f", 0x63: "d",
    0x64: "i", 0x65: "l", 0x66: "f", 0x67: "d",
    0x68: "i", 0x69: "l", 0x6A: "f", 0x6B: "d",
    0x6C: "i", 0x6D: "l", 0x6E: "f", 0x6F: "d",
    0x70: "i", 0x71: "l", 0x72: "f", 0x73: "d",
    0x74: "in", 0x75: "ln", 0x76: "fn", 0x77: "dn",
    0x78: "i12", 0x79: "l12", 0x7A: "i12", 0x7B: "l12",
    0x7C: "i12", 0x7D: "l12",
    0x7E: "i", 0x7F: "l", 0x80: "i", 0x81: "l", 0x82: "i", 0x83: "l",
}

_ARITH_FN = {
    0x60: lambda a, b: i32(as_int(a) + as_int(b)),
    0x61: lambda a, b: i64(as_int(a) + as_int(b)),
    0x62: lambda a, b: a + b,
    0x63: lambda a, b: a + b,
    0x64: lambda a, b: i32(as_int(a) - as_int(b)),
    0x65: lambda a, b: i64(as_int(a) - as_int(b)),
    0x66: lambda a, b: a - b,
    0x67: lambda a, b: a - b,
    0x68: lambda a, b: i32(as_int(a) * as_int(b)),
    0x69: lambda a, b: i64(as_int(a) * as_int(b)),
    0x6A: lambda a, b: a * b,
    0x6B: lambda a, b: a * b,
    0x6C: lambda a, b: _jdiv(as_int(a), as_int(b), i32),
    0x6D: lambda a, b: _jdiv(as_int(a), as_int(b), i64),
    0x6E: _fdiv,
    0x6F: _fdiv,
    0x70: lambda a, b: i32(as_int(a) - as_int(b) *
                           _jdiv(as_int(a), as_int(b), lambda x: x)),
    0x71: lambda a, b: i64(as_int(a) - as_int(b) *
                           _jdiv(as_int(a), as_int(b), lambda x: x)),
    0x72: _frem,
    0x73: _frem,
    0x74: lambda a: i32(-as_int(a)),
    0x75: lambda a: i64(-as_int(a)),
    0x76: lambda a: -a,
    0x77: lambda a: -a,
    0x78: lambda a, b: i32(as_int(a) << (as_int(b) & 0x1F)),
    0x79: lambda a, b: i64(as_int(a) << (as_int(b) & 0x3F)),
    0x7A: lambda a, b: i32(as_int(a) >> (as_int(b) & 0x1F)),
    0x7B: lambda a, b: i64(as_int(a) >> (as_int(b) & 0x3F)),
    0x7C: lambda a, b: i32((as_int(a) & 0xFFFFFFFF) >> (as_int(b) & 0x1F)),
    0x7D: lambda a, b: i64((as_int(a) & 0xFFFFFFFFFFFFFFFF)
                           >> (as_int(b) & 0x3F)),
    0x7E: lambda a, b: i32(as_int(a) & as_int(b)),
    0x7F: lambda a, b: i64(as_int(a) & as_int(b)),
    0x80: lambda a, b: i32(as_int(a) | as_int(b)),
    0x81: lambda a, b: i64(as_int(a) | as_int(b)),
    0x82: lambda a, b: i32(as_int(a) ^ as_int(b)),
    0x83: lambda a, b: i64(as_int(a) ^ as_int(b)),
}

# (source slots, destination slots)
_CONV_KIND = {
    0x85: (1, 2), 0x86: (1, 1), 0x87: (1, 2),
    0x88: (2, 1), 0x89: (2, 1), 0x8A: (2, 2),
    0x8B: (1, 1), 0x8C: (1, 2), 0x8D: (1, 2),
    0x8E: (2, 1), 0x8F: (2, 2), 0x90: (2, 1),
    0x91: (1, 1), 0x92: (1, 1), 0x93: (1, 1),
}

_CONV_FN = {
    0x85: lambda v: i64(as_int(v)),                       # i2l
    0x86: lambda v: float(as_int(v)),                     # i2f
    0x87: lambda v: float(as_int(v)),                     # i2d
    0x88: lambda v: i32(as_int(v)),                       # l2i
    0x89: lambda v: float(as_int(v)),                     # l2f
    0x8A: lambda v: float(as_int(v)),                     # l2d
    0x8B: lambda v: _f2i_clamp(float(v), -0x80000000,
                               0x7FFFFFFF),               # f2i
    0x8C: lambda v: _f2i_clamp(float(v), -0x8000000000000000,
                               0x7FFFFFFFFFFFFFFF),       # f2l
    0x8D: lambda v: float(v),                             # f2d
    0x8E: lambda v: _f2i_clamp(float(v), -0x80000000,
                               0x7FFFFFFF),               # d2i
    0x8F: lambda v: _f2i_clamp(float(v), -0x8000000000000000,
                               0x7FFFFFFFFFFFFFFF),       # d2l
    0x90: lambda v: float(v),                             # d2f
    0x91: lambda v: i32(_signed_byte(as_int(v))),         # i2b
    0x92: lambda v: as_int(v) & 0xFFFF,                   # i2c
    0x93: lambda v: i32(_signed_short(as_int(v))),        # i2s
}


def _signed_byte(v):
    v = int(v) & 0xFF
    return v - 0x100 if v > 0x7F else v


def _signed_short(v):
    v = int(v) & 0xFFFF
    return v - 0x10000 if v > 0x7FFF else v


def op_needs_receiver(op: int) -> bool:
    return op in (0xB6, 0xB7, 0xB9)


def _pop_args(desc: str, f: Frame) -> list:
    """Pop the arguments in reverse: a long/double takes two slots.

    The JVM pushes arguments left-to-right, so the *last* parameter is on top
    of the stack — popping in parameter order would grab a reference where a
    long belongs the moment one method mixes the two (this exact bug produced
    "corrupt operand stack" on every `(J…, ref…)V` signature and one false
    DIFF).
    """
    out = []
    for d in reversed(_param_descs(desc)):
        out.append(f.pop2() if d in ("J", "D") else f.pop())
    out.reverse()
    return out


def _param_descs(desc: str) -> list[str]:
    body = desc[1:desc.index(")")]
    out: list[str] = []
    i = 0
    while i < len(body):
        start = i
        while body[i] == "[":
            i += 1
        if body[i] == "L":
            i = body.index(";", i) + 1
        else:
            i += 1
        out.append(body[start:i])
    return out


def index_of_pc(order: list[BC.Insn], pc: int) -> int:
    for i, ins in enumerate(order):
        if ins.pc == pc:
            return i
    raise Unsupported(f"branch target {pc} is not an instruction boundary")
