"""Symbolic evaluation of clinit-built tables (static JVM replay).

Protectors and obfuscators construct their constant tables in ``<clinit>``:
string pools, int/long constant arrays, two-level lookup tables, encrypted
blobs. Running the JVM to dump them needs an environment; parsing the bytecode
with patterns breaks on every shape change. The middle road is a symbolic
stack machine over the (branch-free) init code: constants and arrays are
tracked exactly, unknown values poison only their dependents, and every
unhandled opcode is reported instead of guessed.

Exact for the shapes such init code emits: primitive/String/object array
construction (``newarray``/``anewarray``/``multianewarray`` + element stores),
boxed-primitive autoboxing (``valueOf`` is passed through), wide
(0xC4-prefixed) local-variable access, and static helper calls whose
semantics the caller supplies via ``hooks``. Branches and loops are outside
the model — they surface in ``unknown_ops`` rather than producing silently
wrong tables.

Public surface:

- ``walk_init(cf, insns, hooks, raw_code)`` — symbolic walk of one method
  body; returns ``(fields, unknown_ops)`` where ``fields`` maps every
  ``putstatic`` target to its symbolic value.
- ``collect_fields(cf, method_name, hooks)`` — ``walk_init`` over a named
  method (default ``<clinit>``).
- ``rows_of`` / ``flat_of`` — interpret symbolic array values as plain
  Python lists.
- ``arg_slots`` / ``ret_kind`` — method-descriptor helpers.

Hook contract: ``hooks`` maps a static helper's simple name to a callable
``f(stack)`` that pops its arguments from and pushes its result onto the
symbolic stack. Use it to emulate protector-specific unpack routines
(e.g. ``int[] unpackStringInts(String[] chunks, int len, int key)``) in
Python without loading a single class.
"""

from __future__ import annotations

import struct

try:  # package import (jdec CLI)
    from . import bytecode as bc
    from . import classfile as cfmod
except ImportError:  # standalone
    import bytecode as bc
    import classfile as cfmod

__all__ = ["walk_init", "collect_fields", "rows_of", "flat_of",
           "expand_wide", "arg_slots", "ret_kind"]


# ---------------------------------------------------------------------------
# constant-pool readers
# ---------------------------------------------------------------------------

def _cp_class_name(cf, index: int) -> str | None:
    e = cf.cp[index]
    if e and e[0] == cfmod.C_CLASS:
        return cf.utf8(e[1][0])
    return None


def _const_int(cf, insn: "bc.Insn") -> int | None:
    """Signed value of an int-const push (iconst/bipush/sipush/ldc-int)."""
    op = insn.op
    if 0x02 <= op <= 0x08:  # iconst_m1..iconst_5
        return op - 0x03
    if op == 0x10:  # bipush (signed byte)
        v = insn.arg if insn.arg is not None else 0
        return v - 256 if v > 127 else v
    if op == 0x11:  # sipush (signed short)
        v = insn.arg if insn.arg is not None else 0
        return v - 0x10000 if v > 0x7FFF else v
    if op in (0x12, 0x13):  # ldc / ldc_w
        e = cf.cp[insn.arg]
        if e and e[0] == cfmod.C_INTEGER:
            return struct.unpack(">i", e[1][0])[0]
    return None


def _const_str(cf, insn: "bc.Insn") -> str | None:
    if insn.op in (0x12, 0x13):
        e = cf.cp[insn.arg]
        if e and e[0] == cfmod.C_STRING:
            # modified-UTF-8-exact: encrypted payloads may contain lone
            # surrogates (position-semantic; "replace" shifts every
            # subsequent char and corrupts the tail of the stream)
            return cf.utf8_strict(e[1][0])
    return None


def _const_long(cf, insn: "bc.Insn") -> int | None:
    if insn.op == 0x14:  # ldc2_w
        e = cf.cp[insn.arg]
        if e and e[0] == cfmod.C_LONG:
            return struct.unpack(">q", e[1][0])[0]
    return None


def _target_desc(cf, insn: "bc.Insn") -> tuple[str, str, str] | None:
    """(owner, name, descriptor) of an invokestatic/putstatic/getstatic."""
    if insn.op not in (0xB8, 0xB3, 0xB2):
        return None
    e = cf.cp[insn.arg]
    if not e or e[0] not in (cfmod.C_METHODREF, cfmod.C_FIELDREF):
        return None
    cls = cf.class_name(e[1][0])
    nt = cf.cp[e[1][1]]
    return cls, cf.utf8(nt[1][0]), cf.utf8(nt[1][1])


# ---------------------------------------------------------------------------
# descriptor helpers
# ---------------------------------------------------------------------------

def arg_slots(desc: str) -> int:
    """Number of operand-stack slots consumed by a descriptor's arguments
    (long/double take two)."""
    n = 0
    i = 1
    while i < len(desc) and desc[i] != ")":
        c = desc[i]
        if c in "JD":
            n += 2
            i += 1
        elif c == "L":
            n += 1
            i = desc.find(";", i) + 1
        elif c == "[":
            n += 1
            i += 1
            while i < len(desc) and desc[i] == "[":
                i += 1
            if i < len(desc) and desc[i] == "L":
                i = desc.find(";", i)
            i += 1
        elif c in "BCFISZ":
            n += 1
            i += 1
        else:
            i += 1
    return n


def ret_kind(desc: str):
    """Symbolic unknown value shaped like a descriptor's return type, or
    ``None`` for ``void``/reference returns."""
    ret = desc.split(")")[-1]
    if ret in ("I", "Z", "B", "C", "S"):
        return ("unknown", None)
    if ret == "J":
        return ("long", None)
    if ret == "F":
        return ("float", None)
    if ret == "D":
        return ("double", None)
    return None


# ---------------------------------------------------------------------------
# symbolic values
# ---------------------------------------------------------------------------
# ("int", v) ("long", v) ("float", f) ("double", d) ("str", s) ("type", desc)
# ("null", None) ("unknown", None)
# ("str_arr", [str|None]) ("int_arr", [v|None]) ("long_arr", [v|None])
# ("int2d", {idx: row})   row = ("ints"|"int_arr", [int]) once filled
# ("long2d", {idx: row})
# ("obj_arr", {idx: elem})  elem = a symbolic value tuple | None

def _sym_newarray(insn, cf, stack, raw_code: bytes = b""):
    """anewarray / newarray / multianewarray with a symbolic result.
    bytecode.py may not store the operand — read it from the raw code."""
    def u2(off: int) -> int:
        return struct.unpack_from(">H", raw_code, off)[0]

    if insn.op == 0xBD:  # anewarray <cp class>
        cnt = stack.pop() if stack else ("unknown", None)
        n = cnt[1] if cnt[0] == "int" else None
        idx = insn.arg if insn.arg is not None else u2(insn.pc + 1)
        cname = _cp_class_name(cf, idx) or "?"
        if cname == "java/lang/String":
            stack.append(("str_arr", [None] * n if n is not None else []))
        elif cname == "[I":
            stack.append(("int2d", {}))     # array of int[] rows
        elif cname == "[J":
            stack.append(("long2d", {}))
        else:
            stack.append(("obj_arr", {}))
    elif insn.op == 0xBC:  # newarray <atype>
        cnt = stack.pop() if stack else ("unknown", None)
        n = cnt[1] if cnt[0] == "int" else None
        atype = insn.arg if insn.arg is not None else raw_code[insn.pc + 1]
        if atype == 11:  # T_LONG
            stack.append(("long_arr", [None] * n if n is not None else []))
        elif atype == 10:  # T_INT
            stack.append(("int_arr", [None] * n if n is not None else []))
        else:
            stack.append(("obj_arr", {}))
    elif insn.op == 0xC5:  # multianewarray <cp class>, dims
        if stack:
            stack.pop()
        idx = insn.arg if insn.arg is not None else u2(insn.pc + 1)
        cname = _cp_class_name(cf, idx) or "?"
        if cname.startswith("[[I"):
            stack.append(("int2d", {}))
        elif cname.startswith("[[J"):
            stack.append(("long2d", {}))
        else:
            stack.append(("obj_arr", {}))


def _array_elem(arr, index) -> object:
    if isinstance(arr, tuple) and isinstance(arr[1], dict):
        idx = index[1] if index[0] == "int" else None
        return arr[1].get(idx)
    if isinstance(arr, tuple) and isinstance(arr[1], list):
        idx = index[1] if index[0] == "int" else None
        if idx is not None and 0 <= idx < len(arr[1]):
            v = arr[1][idx]
            return v if v is not None else ("unknown", None)
    return ("unknown", None)


def _store_into(arr, index, value) -> None:
    if not isinstance(arr, tuple):
        return
    kind, payload = arr
    idx = index[1] if isinstance(index, tuple) and index[0] == "int" else None
    if isinstance(payload, dict):
        payload[idx] = value
    elif isinstance(payload, list) and idx is not None and 0 <= idx < len(payload):
        payload[idx] = value[1] if isinstance(value, tuple) else value


# ---------------------------------------------------------------------------
# the walk
# ---------------------------------------------------------------------------

def expand_wide(insns: list, raw_code: bytes) -> list:
    """Expand ``wide`` (0xC4) prefixed loads/stores into plain equivalents.

    bytecode.py decodes ``wide <op>`` as Insn(op=0xC4, arg=sub-opcode); the
    u2 local-variable index sits at pc+2 and is not stored. Init bodies with
    >255 locals use wide aload/astore heavily — without this expansion the
    walk loses stack/local tracking past the first wide op.
    """
    out = []
    for ins in insns:
        if ins.op == 0xC4 and ins.arg is not None and ins.arg != 0x84:
            idx = struct.unpack_from(">H", raw_code, ins.pc + 2)[0]
            out.append(bc.Insn(pc=ins.pc, op=ins.arg, arg=idx,
                               length=ins.length))
        else:
            out.append(ins)
    return out


def _load_op(op: int) -> tuple[str, int | None] | None:
    """(kind, slot) for a long/float/double local load; slot None = use ins.arg.

    JVMS index ranges, not a guess: lload 0x16 + lload_0..3 = 0x1E-0x21,
    fload 0x17 + fload_0..3 = 0x22-0x25, dload 0x18 + dload_0..3 = 0x26-0x29.
    The old table put 0x24/0x25 (fload_2/3) in the double branch and derived
    the slot from the opcode as well, so a float load silently produced a
    double read from the wrong variable - and never reached unknown_ops.
    """
    if op in (0x16, 0x17, 0x18):
        return {0x16: "long", 0x17: "float", 0x18: "double"}[op], None
    if 0x1E <= op <= 0x21:
        return "long", op - 0x1E
    if 0x22 <= op <= 0x25:
        return "float", op - 0x22
    if 0x26 <= op <= 0x29:
        return "double", op - 0x26
    return None


def walk_init(cf, insns, hooks: dict | None = None,
              raw_code: bytes = b"") -> tuple[dict, list[str]]:
    """Symbolically evaluate one init-method body.

    Returns ``(fields, unknown_ops)``. ``fields`` maps each ``putstatic``
    target name to the symbolic value assigned (call ``rows_of``/``flat_of``
    to interpret array shapes). ``unknown_ops`` lists every construct the
    walk could not model — a non-empty list means the extracted tables are
    incomplete and must not be trusted blindly.
    """
    hooks = hooks or {}
    insns = expand_wide(insns, raw_code)
    locals_: dict[int, object] = {}
    stack: list[object] = []
    fields: dict[str, object] = {}
    unknown: list[str] = []

    for ins in insns:
        op = ins.op
        if op in (0x00, 0xC0, 0xBF):        # nop / checkcast / athrow
            continue
        elif 0x02 <= op <= 0x08:            # iconst_m1..iconst_5
            stack.append(("int", op - 0x03))
        elif op in (0x09, 0x0A):            # lconst_0/1
            stack.append(("long", op - 0x09))
        elif 0x0B <= op <= 0x0D:            # fconst_0..2
            stack.append(("float", float(op - 0x0B)))
        elif op in (0x0E, 0x0F):            # dconst_0/1
            stack.append(("double", float(op - 0x0E)))
        elif op == 0x01:                    # aconst_null
            stack.append(("null", None))
        elif op in (0x10, 0x11, 0x12, 0x13):  # bipush/sipush/ldc/ldc_w
            v = _const_int(cf, ins)
            if v is not None:
                stack.append(("int", v))
                continue
            s = _const_str(cf, ins)
            if s is not None:
                stack.append(("str", s))
                continue
            if op in (0x12, 0x13):
                e = cf.cp[ins.arg]
                if e and e[0] == cfmod.C_FLOAT:
                    stack.append(("float", struct.unpack(">f", e[1][0])[0]))
                    continue
                if e and e[0] == cfmod.C_DOUBLE:
                    stack.append(("double", struct.unpack(">d", e[1][0])[0]))
                    continue
                if e and e[0] == cfmod.C_CLASS:
                    stack.append(("type", cf.utf8(e[1][0])))
                    continue
            stack.append(("unknown", None))
        elif op == 0x14:                    # ldc2_w
            lo = _const_long(cf, ins)
            stack.append(("long", lo) if lo is not None else ("unknown", None))
        elif 0x15 <= op <= 0x35:            # loads incl. array loads
            if op == 0x15 or 0x1A <= op <= 0x1D:          # iload / iload_n
                idx = ins.arg if op == 0x15 else op - 0x1A
                stack.append(locals_.get(idx, ("unknown", None)))
            elif op in (0x16, 0x17, 0x18) or 0x1E <= op <= 0x29:  # l/f/d load
                kind, slot = _load_op(op)
                idx = ins.arg if slot is None else slot
                stack.append(locals_.get(idx, (kind, None)))
            elif op == 0x19 or 0x2A <= op <= 0x2D:        # aload / aload_n
                idx = ins.arg if op == 0x19 else op - 0x2A
                stack.append(locals_.get(idx, ("unknown", None)))
            elif 0x2E <= op <= 0x35:                      # *aload
                index = stack.pop() if stack else ("int", 0)
                arr = stack.pop() if stack else None
                stack.append(_array_elem(arr, index))
            else:
                unknown.append(f"load {op:02x}")
        elif 0x36 <= op <= 0x4E:            # stores (locals)
            if op == 0x36 or 0x3B <= op <= 0x3E:          # istore / istore_n
                idx = ins.arg if op == 0x36 else op - 0x3B
                locals_[idx] = stack.pop() if stack else ("unknown", None)
            elif op == 0x37 or 0x3F <= op <= 0x42:        # lstore / lstore_n
                idx = ins.arg if op == 0x37 else op - 0x3F
                locals_[idx] = stack.pop() if stack else ("unknown", None)
            elif op == 0x38 or 0x43 <= op <= 0x46:        # fstore / fstore_n
                idx = ins.arg if op == 0x38 else op - 0x43
                locals_[idx] = stack.pop() if stack else ("unknown", None)
            elif op == 0x39 or 0x47 <= op <= 0x4A:        # dstore / dstore_n
                idx = ins.arg if op == 0x39 else op - 0x47
                locals_[idx] = stack.pop() if stack else ("unknown", None)
            elif op == 0x3A or 0x4B <= op <= 0x4E:        # astore / astore_n
                idx = ins.arg if op == 0x3A else op - 0x4B
                locals_[idx] = stack.pop() if stack else ("unknown", None)
            else:
                unknown.append(f"store {op:02x}")
        elif 0x4F <= op <= 0x56:            # array stores
            value = stack.pop() if stack else ("unknown", None)
            index = stack.pop() if stack else ("int", 0)
            arr = stack.pop() if stack else None
            _store_into(arr, index, value)
        elif op in (0x57, 0x58):            # pop / pop2
            if stack:
                stack.pop()
            if op == 0x58 and stack:
                stack.pop()
        elif op == 0x59:                    # dup
            if stack:
                stack.append(stack[-1])
        elif op == 0x5A:                    # dup_x1
            if len(stack) >= 2:
                stack.insert(-2, stack[-1])
        elif op == 0x5B:                    # dup_x2
            if len(stack) >= 3:
                stack.insert(-3, stack[-1])
        elif op == 0x5C:                    # dup2 (two cat1 values here)
            if len(stack) >= 2:
                stack.extend([stack[-2], stack[-1]])
        elif op == 0x5D:                    # dup2_x1
            if len(stack) >= 3:
                v1, v2 = stack[-2], stack[-1]
                stack.insert(-3, v1)
                stack.insert(-3, v2)
        elif op == 0x5E:                    # swap
            if len(stack) >= 2:
                stack[-1], stack[-2] = stack[-2], stack[-1]
        elif op in (0xBD, 0xBC, 0xC5):
            _sym_newarray(ins, cf, stack, raw_code)
        elif op == 0xBE:                    # arraylength
            if stack:
                stack.pop()
            stack.append(("unknown", None))
        elif op == 0xB8:                    # invokestatic
            t = _target_desc(cf, ins)
            name = t[1] if t else "?"
            desc = t[2] if t else ""
            hook = hooks.get(name)
            if hook is not None:
                hook(stack)                 # pops args, pushes results
            elif name == "valueOf":
                pass  # boxed primitive: keep the value on the stack
            else:
                for _ in range(arg_slots(desc)):
                    if stack:
                        stack.pop()
                ret = ret_kind(desc)
                if ret is not None:
                    stack.append(ret)
        elif op == 0xB3:                    # putstatic
            t = _target_desc(cf, ins)
            value = stack.pop() if stack else None
            if t and value is not None:
                fields[t[1]] = value
        elif op == 0xB2:                    # getstatic
            stack.append(("unknown", None))
        elif op == 0xB1 or 0xAC <= op <= 0xB0:  # return / *return
            pass
        else:                               # branches etc: outside the model
            unknown.append(f"op {op:02x}")
    return fields, sorted(set(unknown))


def collect_fields(cf, method_name: str = "<clinit>",
                   hooks: dict | None = None) -> tuple[dict, list[str]] | None:
    """``walk_init`` over a named method; ``None`` when method/body absent."""
    m = None
    for cand in cf.methods:
        if cf.utf8(cand.name_index) == method_name:
            m = cand
            break
    if m is None:
        return None
    code = bc.method_code(cf, m, decode_insns=True)
    if code is None:
        return None
    return walk_init(cf, code.insns, hooks=hooks, raw_code=code.code)


# ---------------------------------------------------------------------------
# interpreting symbolic values
# ---------------------------------------------------------------------------

def rows_of(sym) -> list:
    """Two-dimensional array symbol (``int2d``/``long2d``) -> list of rows."""
    if not isinstance(sym, tuple) or not isinstance(sym[1], dict):
        return []
    out = []
    for k in sorted(sym[1]):
        row = sym[1][k]
        out.append(list(row[1]) if isinstance(row, tuple)
                   and isinstance(row[1], list) else [])
    return out


def flat_of(sym):
    """Array symbol -> plain Python list, unwrapping one symbolic level.
    Scalar symbols pass through unchanged."""
    if not isinstance(sym, tuple):
        return sym
    kind, payload = sym
    if kind in ("int", "long", "float", "double", "str", "type"):
        return payload
    if isinstance(payload, list):
        return [v[1] if isinstance(v, tuple) else v for v in payload]
    if isinstance(payload, dict):
        return [flat_of(payload[k]) for k in sorted(payload)
                if payload[k] is not None]
    if kind == "null":
        return None
    return sym
