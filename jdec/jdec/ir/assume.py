"""Abstract interpretation over a Code array — the verifier's worklist.

Input: a class file, a method, and the **final** code bytes (after any rewrite).
Output: `{pc: Frame}` for every reachable instruction, or `FrameError`.

The caller uses the states at branch targets and handler entries to emit a
StackMapTable. Anything this module cannot model raises `FrameError`, and the
caller reverts the method — guessing a frame is how a class becomes unloadable
in a way that only shows up on someone else's JVM.

Scope, deliberately: no `jsr`/`ret` (Java 6 and earlier), no `wide` beyond
loads/stores/iinc, no exception handlers whose protected range contains an
uninitialized value. Ordinary javac output for Java 8+ is covered.
"""

from __future__ import annotations

import struct

from .. import bytecode as BC
from .. import classfile as CF
from . import types as T
from .types import Frame, FrameError

# --- constant-pool helpers -------------------------------------------------

def _class_name(cf, idx: int) -> str:
    e = cf.cp[idx]
    if not e or e[0] != CF.C_CLASS:
        raise FrameError(f"cp[{idx}] is not a Class entry")
    return cf.utf8(e[1][0])


def _name_and_type(cf, idx: int):
    e = cf.cp[idx]
    if not e or e[0] != CF.C_NAME_AND_TYPE:
        raise FrameError(f"cp[{idx}] is not a NameAndType")
    return cf.utf8(e[1][0]), cf.utf8(e[1][1])


def _member_ref(cf, idx: int):
    e = cf.cp[idx]
    if not e or e[0] not in (CF.C_FIELDREF, CF.C_METHODREF, CF.C_INTERFACE_METHODREF):
        raise FrameError(f"cp[{idx}] is not a field/method ref")
    owner = _class_name(cf, e[1][0])
    name, desc = _name_and_type(cf, e[1][1])
    return owner, name, desc


def _ldc_type(cf, idx: int):
    e = cf.cp[idx]
    if not e:
        raise FrameError(f"cp[{idx}] is empty")
    tag = e[0]
    if tag == CF.C_INTEGER:
        return T.INT
    if tag == CF.C_FLOAT:
        return T.FLOAT
    if tag == CF.C_LONG:
        return T.LONG
    if tag == CF.C_DOUBLE:
        return T.DOUBLE
    if tag == CF.C_STRING:
        return T.obj("java/lang/String")
    if tag == CF.C_CLASS:
        return T.obj("java/lang/Class")
    if tag == CF.C_METHOD_HANDLE:
        return T.obj("java/lang/invoke/MethodHandle")
    if tag == CF.C_METHOD_TYPE:
        return T.obj("java/lang/invoke/MethodType")
    if tag in (CF.C_DYNAMIC, CF.C_INVOKE_DYNAMIC):
        _n, desc = _name_and_type(cf, e[1][1])
        ret = T.return_of_method_descriptor(desc)
        if ret is None:
            return T.obj("java/lang/Object")
        return ret
    raise FrameError(f"ldc of unsupported cp tag {tag}")


# --- stack helpers ---------------------------------------------------------

def _compatible(actual, expect) -> bool:
    """Is `actual` usable where `expect` is wanted?

    Equality is too strict: `String` satisfies an `Object` parameter, and the
    verifier accepts any subtype. The value is never rewritten by this check —
    it only decides whether the instruction is well-formed — so accepting a
    reference where a reference is expected cannot make a frame wrong.
    """
    if expect is None or expect == actual:
        return True
    if T.is_ref(expect):
        return T.is_ref(actual) or actual == T.NULL
    return False


def _pop(f: Frame, expect=None):
    t = f.pop()
    if not _compatible(t, expect):
        raise FrameError(f"expected {expect} on the stack, found {t}")
    return t


def _pop_ref(f: Frame):
    t = f.pop()
    if not (T.is_ref(t) or t == T.NULL or T.is_uninit(t)):
        raise FrameError(f"expected a reference on the stack, found {t}")
    return t


def _load(f: Frame, idx: int) -> None:
    v = f.get_local(idx)
    if v == T.TOP:
        raise FrameError(f"read of undefined local {idx}")
    f.push(v)


def _store(f: Frame, idx: int, expect=None) -> None:
    v = f.pop()
    if not _compatible(v, expect):
        raise FrameError(f"cannot store {v} into a {expect} slot")
    f.set_local(idx, v)


def _array_element(t):
    """Component type of an array verification type."""
    if not T.is_ref(t):
        raise FrameError(f"expected an array reference, found {t}")
    desc = t[1]
    if not desc.startswith("["):
        raise FrameError(f"expected an array type, found {desc}")
    inner = desc[1:]
    return T.type_of_field_descriptor(inner)


def _replace_uninit(f: Frame, token, replacement) -> None:
    for i, t in enumerate(f.locals):
        if t == token:
            f.locals[i] = replacement
    for i, t in enumerate(f.stack):
        if t == token:
            f.stack[i] = replacement


# --- the transfer function -------------------------------------------------

def step(cf, insn: BC.Insn, f: Frame):
    """Apply one instruction to `f`. Returns (jump_targets, falls_through)."""
    op = insn.op

    # ---- constants -------------------------------------------------
    if op == 0x00:                                     # nop
        return [], True
    if op == 0x01:                                     # aconst_null
        f.push(T.NULL)
        return [], True
    if 0x02 <= op <= 0x08:                             # iconst_*
        f.push(T.INT)
        return [], True
    if op in (0x09, 0x0A):                             # lconst_*
        f.push(T.LONG)
        return [], True
    if 0x0B <= op <= 0x0D:                             # fconst_*
        f.push(T.FLOAT)
        return [], True
    if op in (0x0E, 0x0F):                             # dconst_*
        f.push(T.DOUBLE)
        return [], True
    if op in (0x10, 0x11):                             # bipush / sipush
        f.push(T.INT)
        return [], True
    if op in (0x12, 0x13, 0x14):                       # ldc / ldc_w / ldc2_w
        f.push(_ldc_type(cf, insn.arg))
        return [], True

    # ---- loads -----------------------------------------------------
    if 0x15 <= op <= 0x19:
        _load(f, insn.arg)
        return [], True
    if 0x1A <= op <= 0x2D:
        base, idx = (0x1A, op - 0x1A) if op <= 0x1D else \
                    (0x1E, op - 0x1E) if op <= 0x21 else \
                    (0x22, op - 0x22) if op <= 0x25 else \
                    (0x26, op - 0x26) if op <= 0x29 else (0x2A, op - 0x2A)
        _load(f, idx)
        return [], True

    # ---- array loads -----------------------------------------------
    if 0x2E <= op <= 0x35:
        _pop(f, T.INT)
        arr = _pop_ref(f)
        elem = {0x2E: T.INT, 0x2F: T.LONG, 0x30: T.FLOAT, 0x31: T.DOUBLE,
                0x33: T.INT, 0x34: T.INT, 0x35: T.INT}.get(op)
        f.push(elem if elem is not None else _array_element(arr))
        return [], True

    # ---- stores ----------------------------------------------------
    if 0x36 <= op <= 0x3A:
        _store(f, insn.arg)
        return [], True
    if 0x3B <= op <= 0x4E:
        idx = (op - 0x3B) % 4
        _store(f, idx)
        return [], True

    # ---- array stores ----------------------------------------------
    if 0x4F <= op <= 0x56:
        value_t = {0x4F: T.INT, 0x50: T.LONG, 0x51: T.FLOAT, 0x52: T.DOUBLE,
                   0x54: T.INT, 0x55: T.INT, 0x56: T.INT}.get(op)
        if value_t is not None:
            _pop(f, value_t)
        else:
            _pop_ref(f)                    # aastore
        _pop(f, T.INT)
        _pop_ref(f)
        return [], True

    # ---- stack manipulation ----------------------------------------
    if op == 0x57:                                     # pop
        if T.is_wide(f.pop()):
            raise FrameError("pop of a category-2 value")
        return [], True
    if op == 0x58:                                     # pop2
        v = f.pop()
        if not T.is_wide(v):
            if T.is_wide(f.pop()):
                raise FrameError("pop2 straddles a category-2 value")
        return [], True
    if 0x59 <= op <= 0x5F:
        _stack_op(op, f)
        return [], True

    # ---- arithmetic -------------------------------------------------
    if 0x60 <= op <= 0x83:
        _arith(op, f)
        return [], True
    if op == 0x84:                                     # iinc
        cur = f.get_local(insn.arg)
        if cur != T.INT:
            raise FrameError(f"iinc on a {cur} local")
        return [], True

    # ---- conversions / comparisons ----------------------------------
    if 0x85 <= op <= 0x93:
        src, dst = _CONVERSIONS[op]
        _pop(f, src)
        f.push(dst)
        return [], True
    if 0x94 <= op <= 0x98:
        t = {0x94: T.LONG, 0x95: T.FLOAT, 0x96: T.FLOAT,
             0x97: T.DOUBLE, 0x98: T.DOUBLE}[op]
        _pop(f, t)
        _pop(f, t)
        f.push(T.INT)
        return [], True

    # ---- branches ---------------------------------------------------
    if 0x99 <= op <= 0x9E:                             # ifeq .. ifle
        _pop(f, T.INT)
        return [insn.pc + insn.arg], True
    if 0x9F <= op <= 0xA4:                             # if_icmp*
        _pop(f, T.INT)
        _pop(f, T.INT)
        return [insn.pc + insn.arg], True
    if 0xA5 <= op <= 0xA6:                             # if_acmp*
        _pop_ref(f)
        _pop_ref(f)
        return [insn.pc + insn.arg], True
    if op == 0xA7:                                     # goto
        return [insn.pc + insn.arg], False
    if op in (0xA8, 0xA9, 0xC9, 0xCA):                 # jsr / ret / jsr_w / breakpoint
        raise FrameError(f"unsupported opcode 0x{op:02x} (pre-Java-6 subroutine)")
    if op in (0xAA, 0xAB):                             # switch
        _pop(f, T.INT)
        return list(insn.targets), False
    if op in (0xC6, 0xC7):                             # ifnull / ifnonnull
        _pop_ref(f)
        return [insn.pc + insn.arg], True

    # ---- returns ----------------------------------------------------
    if 0xAC <= op <= 0xB1:
        if op == 0xB1:
            pass
        else:
            expect = {0xAC: T.INT, 0xAD: T.LONG, 0xAE: T.FLOAT,
                      0xAF: T.DOUBLE}.get(op)
            if expect is not None:
                _pop(f, expect)
            else:
                _pop_ref(f)
        return [], False

    # ---- fields -----------------------------------------------------
    if 0xB2 <= op <= 0xB5:
        owner, _name, desc = _member_ref(cf, insn.arg)
        ft = T.type_of_field_descriptor(desc)
        if op == 0xB2:                                 # getstatic
            f.push(ft)
        elif op == 0xB3:                               # putstatic
            _pop(f, ft)
        elif op == 0xB4:                               # getfield
            _pop_ref(f)
            f.push(ft)
        else:                                          # putfield
            _pop(f, ft)
            _pop_ref(f)
        return [], True

    # ---- invokes ----------------------------------------------------
    if 0xB6 <= op <= 0xBA:
        if op == 0xBA:                                 # invokedynamic
            e = cf.cp[insn.arg]
            if not e or e[0] != CF.C_INVOKE_DYNAMIC:
                raise FrameError("invokedynamic without a Dynamic entry")
            _n, desc = _name_and_type(cf, e[1][1])
            owner, name = None, "<indy>"
        else:
            owner, name, desc = _member_ref(cf, insn.arg)
        params = T.params_of_method_descriptor(desc)
        for p in reversed(params):
            _pop(f, p)
        if op != 0xB8 and op != 0xBA:                  # not invokestatic / indy
            recv = f.pop()
            if op == 0xB7 and name == "<init>":
                # a constructor call turns the uninitialized token into the
                # class everywhere it appears (JVMS 4.10.1.9)
                if T.is_uninit(recv):
                    cls = T.obj(cf.name) if recv == T.UNINIT_THIS else \
                        T.obj(_class_name(cf, cf.cp[insn.arg][1][0]))
                    _replace_uninit(f, recv, cls)
                else:
                    raise FrameError("<init> called on an initialized value")
        ret = T.return_of_method_descriptor(desc)
        if ret is not None:
            f.push(ret)
        return [], True

    # ---- objects / arrays -------------------------------------------
    if op == 0xBB:                                     # new
        f.push(T.uninit(insn.pc))
        return [], True
    if op == 0xBC:                                     # newarray
        desc = {4: "[Z", 5: "[C", 6: "[F", 7: "[D",
                8: "[B", 9: "[S", 10: "[I", 11: "[J"}.get(insn.arg)
        if desc is None:
            raise FrameError(f"bad newarray atype {insn.arg}")
        _pop(f, T.INT)
        f.push(T.obj(desc))
        return [], True
    if op == 0xBD:                                     # anewarray
        _pop(f, T.INT)
        comp = _class_name(cf, insn.arg)
        # `comp` is a class name or (for nested arrays) a descriptor; the array
        # type is `[` + the component's *field descriptor*
        base = comp if comp.startswith("[") else "L" + comp + ";"
        f.push(T.obj("[" + base))
        return [], True
    if op == 0xBE:                                     # arraylength
        _pop_ref(f)
        f.push(T.INT)
        return [], True
    if op == 0xBF:                                     # athrow
        _pop_ref(f)
        return [], False
    if op == 0xC0:                                     # checkcast
        _pop_ref(f)
        f.push(T.obj(_class_name(cf, insn.arg)))
        return [], True
    if op == 0xC1:                                     # instanceof
        _pop_ref(f)
        f.push(T.INT)
        return [], True
    if op in (0xC2, 0xC3):                             # monitorenter/exit
        _pop_ref(f)
        return [], True
    if op == 0xC5:                                     # multianewarray
        for _ in range(insn.arg2 or 1):
            _pop(f, T.INT)
        f.push(T.obj(_class_name(cf, insn.arg)))
        return [], True
    if op == 0xC8:                                     # goto_w
        return [insn.pc + insn.arg], False
    if op == 0xC4:                                     # wide
        return _wide(insn, f)

    raise FrameError(f"unsupported opcode 0x{op:02x}")


def _wide(insn: BC.Insn, f: Frame):
    sub = insn.arg or 0
    if len(insn.raw) < 2:
        raise FrameError("truncated wide")
    idx = struct.unpack_from(">H", insn.raw, 0)[0]
    if 0x15 <= sub <= 0x19:
        _load(f, idx)
        return [], True
    if 0x36 <= sub <= 0x3A:
        _store(f, idx)
        return [], True
    if sub == 0x84:
        if f.get_local(idx) != T.INT:
            raise FrameError(f"wide iinc on a {f.get_local(idx)} local")
        return [], True
    raise FrameError(f"unsupported wide sub-opcode 0x{sub:02x}")


def _stack_op(op: int, f: Frame) -> None:
    """dup / dup_x1 / dup_x2 / dup2 / dup2_x1 / dup2_x2 / swap."""
    def take():
        if not f.stack:
            raise FrameError("operand stack underflow")
        return f.stack.pop()

    def cat1(v):
        return not T.is_wide(v)

    if op == 0x59:                                     # dup
        v = take()
        if not cat1(v):
            raise FrameError("dup on a category-2 value")
        f.stack += [v, v]
    elif op == 0x5A:                                   # dup_x1
        v1, v2 = take(), take()
        if not (cat1(v1) and cat1(v2)):
            raise FrameError("dup_x1 with a category-2 value")
        f.stack += [v1, v2, v1]
    elif op == 0x5B:                                   # dup_x2
        v1 = take()
        v2 = take()
        if not cat1(v1):
            raise FrameError("dup_x2 with a category-2 top value")
        if cat1(v2):
            v3 = take()
            if not cat1(v3):
                raise FrameError("dup_x2 straddles a category-2 value")
            f.stack += [v1, v3, v2, v1]
        else:
            f.stack += [v1, v2, v1]
    elif op == 0x5C:                                   # dup2
        v1 = take()
        if cat1(v1):
            v2 = take()
            if not cat1(v2):
                raise FrameError("dup2 straddles a category-2 value")
            f.stack += [v2, v1, v2, v1]
        else:
            f.stack += [v1, v1]
    elif op == 0x5D:                                   # dup2_x1
        v1 = take()
        if cat1(v1):
            v2 = take()
            if not cat1(v2):
                raise FrameError("dup2_x1 straddles a category-2 value")
            v3 = take()
            if not cat1(v3):
                raise FrameError("dup2_x1 with a category-2 value")
            f.stack += [v2, v1, v3, v2, v1]
        else:
            v2 = take()
            if not cat1(v2):
                raise FrameError("dup2_x1 with two category-2 values")
            f.stack += [v1, v2, v1]
    elif op == 0x5E:                                   # dup2_x2
        v1 = take()
        if cat1(v1):
            v2 = take()
            if not cat1(v2):
                raise FrameError("dup2_x2 straddles a category-2 value")
            v3 = take()
            if cat1(v3):
                v4 = take()
                if not cat1(v4):
                    raise FrameError("dup2_x2 straddles a category-2 value")
                f.stack += [v2, v1, v4, v3, v2, v1]
            else:
                f.stack += [v2, v1, v3, v2, v1]
        else:
            v2 = take()
            if cat1(v2):
                v3 = take()
                if not cat1(v3):
                    raise FrameError("dup2_x2 straddles a category-2 value")
                f.stack += [v1, v3, v2, v1]
            else:
                f.stack += [v1, v2, v1]
    elif op == 0x5F:                                   # swap
        v1, v2 = take(), take()
        if not (cat1(v1) and cat1(v2)):
            raise FrameError("swap with a category-2 value")
        f.stack += [v1, v2]


_CONVERSIONS = {
    0x85: (T.INT, T.LONG), 0x86: (T.INT, T.FLOAT), 0x87: (T.INT, T.DOUBLE),
    0x88: (T.LONG, T.INT), 0x89: (T.LONG, T.FLOAT), 0x8A: (T.LONG, T.DOUBLE),
    0x8B: (T.FLOAT, T.INT), 0x8C: (T.FLOAT, T.LONG), 0x8D: (T.FLOAT, T.DOUBLE),
    0x8E: (T.DOUBLE, T.INT), 0x8F: (T.DOUBLE, T.LONG), 0x90: (T.DOUBLE, T.FLOAT),
    0x91: (T.INT, T.INT), 0x92: (T.INT, T.INT), 0x93: (T.INT, T.INT),
}


# JVMS orders these by operation (add: i,l,f,d; sub: i,l,f,d; …), NOT by type.
# Getting this wrong is silent: 0x61 would be read as `lsub` instead of `ladd`
# and every long expression produces a frame the verifier rejects.
_ARITH = {
    0x60: (T.INT, 2), 0x61: (T.LONG, 2), 0x62: (T.FLOAT, 2), 0x63: (T.DOUBLE, 2),
    0x64: (T.INT, 2), 0x65: (T.LONG, 2), 0x66: (T.FLOAT, 2), 0x67: (T.DOUBLE, 2),
    0x68: (T.INT, 2), 0x69: (T.LONG, 2), 0x6A: (T.FLOAT, 2), 0x6B: (T.DOUBLE, 2),
    0x6C: (T.INT, 2), 0x6D: (T.LONG, 2), 0x6E: (T.FLOAT, 2), 0x6F: (T.DOUBLE, 2),
    0x70: (T.INT, 2), 0x71: (T.LONG, 2), 0x72: (T.FLOAT, 2), 0x73: (T.DOUBLE, 2),
    0x74: (T.INT, 1), 0x75: (T.LONG, 1), 0x76: (T.FLOAT, 1), 0x77: (T.DOUBLE, 1),
    # shifts take a long/int pair: 0x79 lshl pops (long, int) -> long
    0x78: (T.INT, 2), 0x79: (T.LONG, 2), 0x7A: (T.INT, 2), 0x7B: (T.LONG, 2),
    0x7C: (T.INT, 2), 0x7D: (T.LONG, 2),
    # and/or/xor
    0x7E: (T.INT, 2), 0x7F: (T.LONG, 2), 0x80: (T.INT, 2), 0x81: (T.LONG, 2),
    0x82: (T.INT, 2), 0x83: (T.LONG, 2),
}


def _arith(op: int, f: Frame) -> None:
    kind, arity = _ARITH[op]
    if arity == 1:
        _pop(f, kind)
        f.push(kind)
        return
    if op in (0x79, 0x7B, 0x7D):          # long shifts: shift count is an int
        _pop(f, T.INT)
        _pop(f, T.LONG)
        f.push(T.LONG)
        return
    _pop(f, kind)
    _pop(f, kind)
    f.push(kind)


# --- the worklist ----------------------------------------------------------

def initial_frame(cf, member, max_locals: int) -> Frame:
    desc = cf.utf8(member.descriptor_index)
    is_static = bool(member.access_flags & 0x0008)
    is_ctor = cf.utf8(member.name_index) == "<init>"
    locals_: list = []
    if not is_static:
        locals_.append(T.UNINIT_THIS if is_ctor else T.obj(cf.name))
    for p in T.params_of_method_descriptor(desc):
        locals_.append(p)
        if T.is_wide(p):
            locals_.append(T.TOP)
    if len(locals_) > max_locals:
        raise FrameError(
            f"descriptor needs {len(locals_)} local slots but max_locals is "
            f"{max_locals}")
    return Frame(locals_, [])


def _catch_type(cf, catch_type: int):
    if catch_type == 0:
        return T.obj("java/lang/Throwable")
    return T.obj(_class_name(cf, catch_type))


def compute_frames(cf, member, code: bytes, handlers,
                   max_stack: int, max_locals: int, hier=None) -> dict:
    """`{pc: Frame}` for every reachable instruction. Raises FrameError."""
    try:
        insns = BC.decode(code)
    except BC.BytecodeError as exc:
        raise FrameError(str(exc)) from None
    if not insns:
        raise FrameError("empty code array")
    by_pc = {i.pc: i for i in insns}
    boundaries = sorted(by_pc)

    states: dict = {0: initial_frame(cf, member, max_locals)}
    queue = [0]
    while queue:
        pc = queue.pop()
        insn = by_pc.get(pc)
        if insn is None:
            raise FrameError(f"control flow targets {pc}, which is not an "
                             f"instruction boundary")
        entry = states[pc]
        f = entry.copy()

        # every instruction inside a protected range can transfer to its handler
        for h in handlers:
            if h.start_pc <= pc < h.end_pc:
                hf = Frame(entry.locals[:max_locals], [_catch_type(cf, h.catch_type)])
                if len(hf.locals) < max_locals:
                    hf.locals += [T.TOP] * (max_locals - len(hf.locals))
                _propagate(hf, h.handler_pc, states, queue, max_locals, by_pc, hier)

        targets, falls = step(cf, insn, f)
        if sum(T.slot_width(t) for t in f.stack) > max_stack:
            raise FrameError(f"stack exceeds max_stack ({max_stack}) at {pc}")

        for tgt in targets:
            _propagate(f.copy(), tgt, states, queue, max_locals, by_pc, hier)
        if falls:
            nxt = pc + insn.length
            if nxt >= len(code):
                raise FrameError(f"control flow falls off the end of the code "
                                 f"({len(code)} bytes) at {pc}")
            _propagate(f, nxt, states, queue, max_locals, by_pc, hier)

    # A handler's stack value is a caught exception, and every catch type is a
    # Throwable by definition — so when the common-supertype search falls back
    # to Object (the JDK chain of a third-party exception is not in the index),
    # Throwable is both sound and as precise as the verifier will ever need.
    # `athrow` and `Logger.error(String, Object, Throwable)` both depend on it.
    # Skipped when a plain branch also targets the handler: then the incoming
    # value need not be throwable at all.
    branch_targets = set()
    for i in insns:
        branch_targets.update(i.jump_targets())
    for h in handlers:
        st = states.get(h.handler_pc)
        if not st or not st.stack or h.handler_pc in branch_targets:
            continue
        if st.stack[0] == T.OBJECT:
            st.stack[0] = T.obj("java/lang/Throwable")
    return states


def _propagate(frame: Frame, target: int, states: dict, queue: list,
               max_locals: int, by_pc: dict, hier=None) -> None:
    if target not in by_pc:
        raise FrameError(f"control flow targets {target}, which is not an "
                         f"instruction boundary")
    if target not in states:
        states[target] = frame
        queue.append(target)
        return
    merged, changed = T.merge_frames(states[target], frame, max_locals, hier)
    if changed:
        states[target] = merged
        queue.append(target)
