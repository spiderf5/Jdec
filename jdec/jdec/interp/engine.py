"""The execution engine: frames, control flow, exceptions, calls."""

from __future__ import annotations

import struct
import time

from .. import bytecode as BC
from .. import classfile as CF
from ..jint import i32, i64
from .values import (Arr, Frame, Heap, Inconclusive, JavaThrow, Obj,
                     Opaque, Outcome,
                     Unsupported, _append_text, as_int, default_value,
                     is_opaque, jstr, make_model)

OP_GOTO = 0xA7
OP_GOTO_W = 0xC8
OP_TABLESWITCH = 0xAA
OP_LOOKUPSWITCH = 0xAB

_BUDGET_DEFAULTS = dict(steps=50_000, wall_seconds=1.0, max_depth=16,
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
        data = None
        try:
            data = self._zip.read(internal + ".class")
        except KeyError:
            cached = self._cache.get(internal)
            return cached
        cf = CF.parse(data)
        self._own[internal] = cf
        return cf

    def known(self, internal: str) -> bool:
        try:
            self._zip.getinfo(internal + ".class")
            return True
        except KeyError:
            return internal in self._cache


class Interp:
    """Execute one method with concrete values on a private heap."""

    def __init__(self, universe: Universe, heap: Heap, models,
                 *, steps: int = 50_000, wall_seconds: float = 1.0,
                 max_depth: int = 16):
        self.universe = universe
        self.heap = heap
        self.models = models
        self.steps = steps
        self.deadline = time.monotonic() + wall_seconds
        self.max_depth = max_depth
        self.depth = 0
        self.count = 0

    # -- entry point ----------------------------------------------------

    def invoke(self, cls: str, name: str, desc: str, receiver, args: list):
        """Run `cls.name(desc)`; returns an `Outcome`."""
        try:
            self._ensure_init(cls)
            value = self._call(cls, name, desc, receiver, args, exact=True)
            kind = "return"
            out = Outcome(kind, value=value)
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
                    return cf, m
            sup = None
            if cf.super_class:
                entry = cf.cp[cf.super_class]
                if entry and entry[0] == CF.C_CLASS:
                    sup = cf.utf8(entry[1][0])
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
            idx += 2 if d in ("J", "D") else 1
        frame = Frame(locals_, [])
        index = 0
        pc = order[0].pc
        ret_desc = desc.split(")", 1)[1]
        while True:
            self.count += 1
            if self.count > self.steps or (self.count % 512 == 0 and
                                           time.monotonic() > self.deadline):
                return Outcome("inconclusive", reason="step or wall-clock "
                                                      "budget exhausted")
            ins = order[index]
            try:
                nxt = self._step(cf, ins, frame, order, index)
            except JavaThrow as exc:
                target = self._handler(ci, pc, exc.cls)
                if target is None:
                    raise
                frame.stack.clear()
                frame.push(exc.obj)
                pc = target
                continue
            if nxt is None:                      # a return instruction
                value = None
                if ret_desc != "V":
                    value = frame.pop()
                return Outcome("return", value=value)
            index = index_of_pc(order, nxt)

    def _handler(self, ci, pc: int, exc_cls: str):
        for h in ci.handlers:
            if not (h.start_pc <= pc < h.end_pc):
                continue
            if h.catch_type == 0:
                return h.handler_pc
            entry = ci.cp[h.catch_type] if 0 < h.catch_type < len(ci.cp) else None
            if entry and entry[0] == CF.C_CLASS:
                catch = ci.utf8(entry[1][0])
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
                known = {"java/lang/Exception", "java/lang/RuntimeException",
                         "java/lang/IllegalArgumentException",
                         "java/lang/IllegalStateException",
                         "java/lang/NullPointerException",
                         "java/lang/ArithmeticException",
                         "java/lang/IndexOutOfBoundsException",
                         "java/lang/ClassCastException",
                         "java/lang/NumberFormatException",
                         "java/lang/UnsupportedOperationException",
                         "java/io/IOException", "java/lang/Error"}
                if current in known:
                    current = {"java/lang/NullPointerException":
                               "java/lang/RuntimeException",
                               "java/lang/ArithmeticException":
                               "java/lang/RuntimeException",
                               "java/lang/IndexOutOfBoundsException":
                               "java/lang/RuntimeException",
                               "java/lang/ClassCastException":
                               "java/lang/RuntimeException",
                               "java/lang/NumberFormatException":
                               "java/lang/IllegalArgumentException",
                               "java/lang/UnsupportedOperationException":
                               "java/lang/RuntimeException",
                               "java/io/IOException": "java/lang/Exception",
                               "java/lang/IllegalArgumentException":
                               "java/lang/RuntimeException",
                               "java/lang/IllegalStateException":
                               "java/lang/RuntimeException",
                               "java/lang/Exception": "java/lang/Throwable",
                               "java/lang/RuntimeException":
                               "java/lang/Exception",
                               "java/lang/Error": "java/lang/Throwable"}[current]
                    continue
                return False
            cf = self.universe.load(current)
            if cf is None:
                return False
            sup_entry = cf.cp[cf.super_class] if cf.super_class else None
            current = cf.utf8(sup_entry[1][0]) if sup_entry else \
                "java/lang/Object"
        return False

    # -- one instruction -------------------------------------------------

    def _step(self, cf: CF.ClassFile, ins: BC.Insn, f: Frame,
              order: list[BC.Insn], index: int):
        op = ins.op
        if op == 0x00:
            return self._next(order, index)
        if op == 0x01:                                   # aconst_null
            f.push(None); return self._next(order, index)
        if 0x02 <= op <= 0x08:
            f.push(_ICONST[op]); return self._next(order, index)
        if op in (0x09, 0x0A):
            f.push(0 if op == 0x09 else 1); return self._next(order, index)
        if op in (0x0B, 0x0C, 0x0D):
            f.push({0x0B: 0.0, 0x0C: 1.0, 0x0D: 2.0}[op])
            return self._next(order, index)
        if op in (0x0E, 0x0F):
            f.push(0.0 if op == 0x0E else 1.0); return self._next(order, index)
        if op in (0x10, 0x11):
            f.push(ins.arg - 0x100 if (op == 0x10 and ins.arg > 0x7F)
                   else ins.arg - 0x10000 if op == 0x11 and ins.arg > 0x7FFF
                   else ins.arg)
            return self._next(order, index)
        if op in (0x12, 0x13):
            f.push(self._ldc(cf, ins.arg, wide=False))
            return self._next(order, index)
        if op == 0x14:
            f.push(self._ldc(cf, ins.arg, wide=True))
            return self._next(order, index)
        if 0x15 <= op <= 0x19:
            f.push(f.get(ins.arg)); return self._next(order, index)
        if 0x1A <= op <= 0x2D:
            idx = (op - 0x1A) if op <= 0x1D else (op - 0x1E) if op <= 0x21 \
                else (op - 0x22) if op <= 0x25 else (op - 0x26) if op <= 0x29 \
                else (op - 0x2A)
            f.push(f.get(idx)); return self._next(order, index)
        if 0x2E <= op <= 0x35:
            index = f.pop_int(); arr = f.pop()
            self._check_array(arr, index)
            f.push(arr.items[index]); return self._next(order, index)
        if 0x36 <= op <= 0x3A:
            f.set(ins.arg, f.pop()); return self._next(order, index)
        if 0x3B <= op <= 0x4E:
            f.set((op - 0x3B) % 4, f.pop()); return self._next(order, index)
        if 0x4F <= op <= 0x56:
            value = f.pop(); index = f.pop_int(); arr = f.pop()
            self._check_array(arr, index)
            arr.items[index] = value; return self._next(order, index)
        if op == 0x57:
            f.pop(); return self._next(order, index)
        if op == 0x58:
            f.pop(); f.pop(); return self._next(order, index)
        if 0x59 <= op <= 0x5F:
            self._stack_op(op, f); return self._next(order, index)
        if 0x60 <= op <= 0x83:
            self._arith(op, f); return self._next(order, index)
        if op == 0x84:
            cur = as_int(f.get(ins.arg))
            f.set(ins.arg, i32(cur + ins.arg2))
            return self._next(order, index)
        if 0x85 <= op <= 0x93:
            self._convert(op, f); return self._next(order, index)
        if op in (0x94, 0x95):
            b = f.pop(); a = f.pop()
            f.push(-1 if a < b else 1 if a > b else 0)
            return self._next(order, index)
        if op in (0x96, 0x97):
            b = f.pop(); a = f.pop()
            f.push(-1 if a < b else 1 if a > b else 0)
            return self._next(order, index)
        if 0x99 <= op <= 0xA6:
            return self._branch(cf, ins, f, self._cond(op, f), order, index)
        if op in (OP_TABLESWITCH, OP_LOOKUPSWITCH):
            return self._switch(cf, ins, f)
        if op in (OP_GOTO, OP_GOTO_W):
            return ins.pc + ins.arg
        if 0xAC <= op <= 0xB1:
            return None                              # handled by the caller
        if op in (0xB2, 0xB3):                       # get/putstatic
            cls, name, desc = self._member(cf, ins.arg)
            self._ensure_init(cls)
            if op == 0xB2:
                key = (cls, name)
                if key not in self.heap.statics:
                    self.heap.statics[key] = self._static_default(cls, name,
                                                                  desc)
                f.push(self.heap.statics[key])
            else:
                self.heap.statics[(cls, name)] = f.pop()
            return self._next(order, index)
        if op in (0xB4, 0xB5):                       # get/putfield
            cls, name, desc = self._member(cf, ins.arg)
            if op == 0xB4:
                obj = f.pop()
                self._check_obj(obj)
                f.push(obj.fields.get(name, default_value(desc, self.heap)))
            else:
                value = f.pop(); obj = f.pop()
                self._check_obj(obj)
                obj.fields[name] = value
            return self._next(order, index)
        if op in (0xB6, 0xB7, 0xB8, 0xB9):
            return self._invoke(cf, ins, f, order, index)
        if op == 0xBA:                               # invokedynamic
            entry = cf.cp[ins.arg]
            nt = cf.cp[entry[1][1]]
            name = cf.utf8(nt[1][0]); desc = cf.utf8(nt[1][1])
            args = _pop_args(desc, f)
            ret = desc.split(")", 1)[1]
            if ret == "Ljava/lang/String;":
                # string concat: the recipe order is the argument order, and
                # both sides run the same model, so the exact recipe constant
                # is not needed for a differential verdict
                f.push("".join(_append_text(a) for a in args))
                return self._next(order, index)
            self.heap.opaque(f"indy:{cls}.{name}")
            f.push(self.heap.opaque(f"indy:{cls}.{name}"))
            return self._next(order, index)
        if op == 0xBB:                               # new
            cls, = self._class(cf, ins.arg)
            self._check_budget_object()
            f.push(Obj(cls, {}))
            return self._next(order, index)
        if op in (0xBC, 0xBD):
            if f.stack and not isinstance(f.stack[-1], (int, bool)):
                raise Unsupported("array length is not an int")
            count = f.pop_int()
            if not isinstance(count, int):
                raise Unsupported(f"newarray count is {type(count).__name__} "
                                  f"at pc {ins.pc} after op "
                                  f"0x{order[index-1].op:02x}")
            if count < 0:
                raise JavaThrow("java/lang/NegativeArraySizeException",
                                str(count))
            comp = {4: "I", 5: "J", 6: "F", 7: "D", 8: "Z", 9: "B",
                    10: "S", 11: "C"}.get(ins.arg, "I")
            if op == 0xBD:
                cls, = self._class(cf, ins.arg)
                comp = cls[1:-1] if cls.startswith("L") else cls
            self._check_budget_object(count)
            f.push(Arr(comp, [default_value("L" + comp + ";" if not
                                            comp.startswith("[") else comp,
                                            self.heap)
                              if comp[0] in "L[" else 0] * count))
            return self._next(order, index)
        if op == 0xBE:
            arr = f.pop()
            self._check_array(arr, None)
            f.push(len(arr.items)); return self._next(order, index)
        if op == 0xBF:
            obj = f.pop()
            if obj is None:
                raise JavaThrow("java/lang/NullPointerException", "athrow null")
            cls, msg = getattr(obj, "throwable", (obj.cls, ""))
            raise JavaThrow(cls, msg, obj)
        if op == 0xC0:                               # checkcast
            obj = f.pop(); f.push(obj); return self._next(order, index)
        if op == 0xC1:                               # instanceof
            obj = f.pop()
            cls, = self._class(cf, ins.arg)
            f.push(self._instanceof(obj, cls)); return self._next(order, index)
        if op in (0xC2, 0xC3):
            f.pop(); return self._next(order, index)
        if op in (OP_GOTO_W,):
            return ins.pc + ins.arg
        if op == 0xC4:                               # wide
            return self._wide(cf, ins, f)
        if op == 0xC5:                               # multianewarray
            for _ in range(ins.arg2):
                f.pop()
            cls, = self._class(cf, ins.arg)
            self._check_budget_object(1)
            f.push(Arr(cls[1:], [])); return self._next(order, index)
        if op == 0xC6 or op == 0xC7:                 # ifnull / ifnonnull
            v = f.pop()
            taken = (v is None) if op == 0xC6 else (v is not None)
            return self._branch(cf, ins, f, taken, order, index)
        raise Unsupported(f"opcode 0x{op:02x} is not modelled")

    # -- helpers used by _step ------------------------------------------

    _ICONST = {0x02: -1, 0x03: 0, 0x04: 1, 0x05: 2, 0x06: 3, 0x07: 4,
               0x08: 5}

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
        b = f.pop_int(); a = f.pop_int()
        return {0x9F: a == b, 0xA0: a != b, 0xA1: a < b, 0xA2: a >= b,
                0xA3: a > b, 0xA4: a <= b}[op]

    def _stack_op(self, op: int, f: Frame):
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
    def _arith(self, op: int, f: Frame):
        wide = op in (0x61, 0x65, 0x69, 0x6D, 0x6F, 0x71, 0x73, 0x7B, 0x7F,
                      0x81, 0x83)
        mask = (lambda v: i64(v)) if wide else (lambda v: i32(v))
        if op in (0x6A, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
                  0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
                  0x80, 0x81, 0x82, 0x83, 0x64, 0x68, 0x6C, 0x6D):
            b = f.pop(); a = f.pop()
        else:
            b = f.pop(); a = f.pop()
        if op in (0x6F, 0x6D, 0x6E):                 # div/rem
            if (as_int(b) if isinstance(b, int) else b) == 0:
                raise JavaThrow("java/lang/ArithmeticException", "/ by zero")
        result = self._arith_apply(op, a, b, mask)
        f.push(result)

    def _arith_apply(self, op: int, a, b, mask):
        if op in (0x69, 0x6D):
            if isinstance(a, float) or isinstance(b, float):
                if b == 0.0:
                    return float("nan") if a == 0 else (float("inf") *
                                                        (1 if a > 0 else -1))
                return a / b
        if op in (0x6E, 0x72):
            if isinstance(a, float) or isinstance(b, float):
                return float("nan") if b == 0 else \
                    float("inf") if a == 0 else a - (a // b) * b
        if op in (0x6A, 0x6B):
            return mask(-as_int(a)) if op == 0x6A else \
                (-as_int(a) if a >= 0 else as_int(a))
        fn = {
            0x60: lambda x, y: i32(x + y), 0x61: lambda x, y: i64(x + y),
            0x62: lambda x, y: x + y, 0x63: lambda x, y: x + y,
            0x64: lambda x, y: i32(x - y), 0x65: lambda x, y: i64(x - y),
            0x66: lambda x, y: x - y, 0x67: lambda x, y: x - y,
            0x68: lambda x, y: i32(x * y), 0x69: lambda x, y: i64(x * y),
            0x6A: lambda x, y: x * y, 0x6B: lambda x, y: x * y,
        }
        if op in fn:
            return fn[op](as_int(a) if op in (0x60, 0x61, 0x64, 0x65, 0x68,
                                              0x69) else a,
                          as_int(b) if op in (0x60, 0x61, 0x64, 0x65, 0x68,
                                              0x69) else b)
        x, y = as_int(a), as_int(b)
        table = {
            0x6C: lambda: i32(int(x / y)) if y else x,
            0x6D: lambda: i64(int(x / y)) if y else x,
            0x6E: lambda: x % y if y else 0, 0x6F: lambda: x % y if y else 0,
            0x70: lambda: i32(x & y), 0x71: lambda: i64(x & y),
            0x72: lambda: x | y, 0x73: lambda: i64(x | y),
            0x74: lambda: x ^ y, 0x75: lambda: i64(x ^ y),
            0x76: lambda: x + y, 0x77: lambda: x + y,
            0x78: lambda: i32(x << (y & 0x1F)), 0x79: lambda: i64(x << (y & 0x3F)),
            0x7A: lambda: i32(x >> (y & 0x1F)), 0x7B: lambda: i64(x >> (y & 0x3F)),
            0x7C: lambda: i32((x & 0xFFFFFFFF) >> (y & 0x1F)),
            0x7D: lambda: i64((x & 0xFFFFFFFFFFFFFFFF) >> (y & 0x3F)),
            0x7E: lambda: i32(x & y), 0x7F: lambda: i64(x & y),
            0x80: lambda: i32(x | y), 0x81: lambda: i64(x | y),
            0x82: lambda: i32(x ^ y), 0x83: lambda: i64(x ^ y),
        }
        return mask(table[op]())

    def _convert(self, op: int, f: Frame):
        v = f.pop()
        raw = as_int(v) if not isinstance(v, (int, float)) else v
        table = {0x85: lambda x: i32(int(x)), 0x86: lambda x: i64(int(x)),
                 0x87: lambda x: float(x), 0x88: lambda x: float(x),
                 0x89: lambda x: i32(int(x)), 0x8A: lambda x: i64(int(x)),
                 0x8B: lambda x: int(x) & 0xFFFF,
                 0x8C: lambda x: i32(int(x)), 0x8D: lambda x: i64(int(x)),
                 0x8E: lambda x: float(x), 0x8F: lambda x: i32(int(x)),
                 0x90: lambda x: i64(int(x)), 0x91: lambda x: _signed_byte(x),
                 0x92: lambda x: _signed_short(x),
                 0x93: lambda x: int(x) & 0xFFFF}
        f.push(table[op](raw))

    def _invoke(self, cf: CF.ClassFile, ins: BC.Insn, f: Frame,
                order: list[BC.Insn], index: int):
        cls, name, desc = self._member(cf, ins.arg)
        args = _pop_args(desc, f)
        receiver = None
        if op_needs_receiver(ins.op):
            receiver = f.pop()
        if ins.op == 0xB7:                            # invokespecial
            self._check_obj(receiver)
            if name == "<init>" and receiver is not None \
                    and receiver.cls in ("java/lang/Object",):
                receiver.cls = cls
        value = self._call(cls, name, desc, receiver, args,
                           exact=ins.op in (0xB7, 0xB8))
        if desc.split(")", 1)[1] != "V":
            f.push(value)
        return self._next(order, index)

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
            text = cf.utf8(entry[1][0])
            return self.heap.intern(text)
        if entry[0] == CF.C_CLASS:
            name = cf.utf8(entry[1][0])
            return Obj("java/lang/Class", {"name": name})
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
        if not isinstance(obj, Obj):
            raise Unsupported("field access on a non-object")

    def _check_array(self, arr, index):
        if arr is None:
            raise JavaThrow("java/lang/NullPointerException", "null array")
        if not isinstance(arr, Arr):
            raise Unsupported("array access on a non-array")
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

    def _wide(self, cf: CF.ClassFile, ins: BC.Insn, f: Frame):
        sub = ins.arg
        index = struct.unpack(">H", ins.raw[2:4])[0]
        if 0x15 <= sub <= 0x19:
            f.push(f.get(index)); return self._next(order, index)
        if 0x36 <= sub <= 0x3A:
            f.set(index, f.pop()); return self._next(order, index)
        if sub == 0x84:
            const = struct.unpack(">h", ins.raw[4:6])[0]
            f.set(index, i32(as_int(f.get(index)) + const))
            return self._next(order, index)
        raise Unsupported("wide of an unmodelled sub-opcode")


_ICONST = {0x02: -1, 0x03: 0, 0x04: 1, 0x05: 2, 0x06: 3, 0x07: 4, 0x08: 5}


def _signed_byte(v):
    v = int(v) & 0xFF
    return v - 0x100 if v > 0x7F else v


def _signed_short(v):
    v = int(v) & 0xFFFF
    return v - 0x10000 if v > 0x7FFF else v


def op_needs_receiver(op: int) -> bool:
    return op in (0xB6, 0xB7, 0xB9)


def _pop_args(desc: str, f: Frame) -> list:
    params = _param_descs(desc)
    args = [f.pop() for _ in params]
    args.reverse()
    return args


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
