"""Control flow de-flattening and constant arithmetic simplification.

Advanced obfuscators (ZKM, Allatori, Dash-O) apply control flow flattening:
methods are transformed into a state machine loop around a switch dispatcher,
where case blocks update a state variable and jump back to the dispatcher.
Decompilers (CFR, Vineflower, Procyon) struggle with this, emitting infinite
while loops or dozens of irreducible gotos.

This module inspects decoded bytecode instructions, identifies state machine
dispatchers, resolves case transitions, and redirects back-jumps directly to
their successor blocks, de-flattening the control flow before decompilation.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
import zipfile

from . import bytecode as BC
from . import classfile as CF
from .bytecode import (
    OP_GOTO, OP_GOTO_W, OP_TABLESWITCH, OP_LOOKUPSWITCH,
    OP_IXOR, OP_LXOR, Insn
)

# Opcodes for loading integer constants
_INT_CONST_OPS = {
    0x02: -1,  # iconst_m1
    0x03: 0,   # iconst_0
    0x04: 1,   # iconst_1
    0x05: 2,   # iconst_2
    0x06: 3,   # iconst_3
    0x07: 4,   # iconst_4
    0x08: 5,   # iconst_5
}

# Binary integer arithmetic operations for constant folding
_INT_BIN_OPS = {
    0x82: lambda a, b: a ^ b,                     # ixor
    0x60: lambda a, b: a + b,                     # iadd
    0x64: lambda a, b: a - b,                     # isub
    0x7E: lambda a, b: a & b,                     # iand
    0x80: lambda a, b: a | b,                     # ior
    0x78: lambda a, b: a << (b & 0x1F),          # ishl
    0x7A: lambda a, b: a >> (b & 0x1F),          # ishr
    0x7C: lambda a, b: (a & 0xFFFFFFFF) >> (b & 0x1F), # iushr
}


def _get_int_const(insn: Insn, code: bytes, cf: CF.ClassFile | None = None) -> int | None:
    """Extract integer constant value loaded by an instruction, if any."""
    if insn.op in _INT_CONST_OPS:
        return _INT_CONST_OPS[insn.op]
    if insn.op == 0x10 and insn.pc + 1 < len(code):  # bipush
        return struct.unpack_from(">b", code, insn.pc + 1)[0]
    if insn.op == 0x11 and insn.pc + 2 < len(code):  # sipush
        return struct.unpack_from(">h", code, insn.pc + 1)[0]
    if cf is not None:
        idx = None
        if insn.op == 0x12 and insn.pc + 1 < len(code):  # ldc
            idx = code[insn.pc + 1]
        elif insn.op == 0x13 and insn.pc + 2 < len(code):  # ldc_w
            idx = struct.unpack_from(">H", code, insn.pc + 1)[0]
        if idx is not None and 0 < idx < len(cf.cp):
            entry = cf.cp[idx]
            if entry and entry[0] == CF.C_INTEGER:
                val_data = entry[1][0] if isinstance(entry[1], list) else entry[1]
                return struct.unpack(">i", val_data)[0]
    return None


def _is_istore(insn: Insn, code: bytes) -> int | None:
    """Returns local variable index if istore instruction, else None."""
    op = insn.op
    if 0x3B <= op <= 0x3E:  # istore_0 .. istore_3
        return op - 0x3B
    if op == 0x36 and insn.pc + 1 < len(code):  # istore <index>
        return code[insn.pc + 1]
    return None


def _is_iload(insn: Insn, code: bytes) -> int | None:
    """Returns local variable index if iload instruction, else None."""
    op = insn.op
    if 0x1A <= op <= 0x1D:  # iload_0 .. iload_3
        return op - 0x1A
    if op == 0x15 and insn.pc + 1 < len(code):  # iload <index>
        return code[insn.pc + 1]
    return None


def simplify_constants(code: bytes, cf: CF.ClassFile | None = None) -> tuple[bytes, int]:
    """Peephole simplification for simple constant arithmetic like iconst + ixor."""
    try:
        insns = BC.decode(code)
    except Exception:
        return code, 0

    buf = bytearray(code)
    changes = 0

    # Look for [const A], [const B], [binop] -> fold into [bipush/sipush], [nop...]
    for i in range(len(insns) - 2):
        in1, in2, in3 = insns[i], insns[i + 1], insns[i + 2]
        if in3.op in _INT_BIN_OPS:
            v1 = _get_int_const(in1, code, cf=cf)
            v2 = _get_int_const(in2, code, cf=cf)
            if v1 is not None and v2 is not None:
                calc = _INT_BIN_OPS[in3.op]
                raw_res = calc(v1, v2)
                folded = raw_res & 0xFFFFFFFF
                s_val = folded if folded < 0x80000000 else folded - 0x100000000
                total_span = (in3.pc + in3.length) - in1.pc
                if -128 <= s_val <= 127 and total_span >= 2:
                    buf[in1.pc] = 0x10  # bipush
                    buf[in1.pc + 1] = s_val & 0xFF
                    for p in range(in1.pc + 2, in3.pc + in3.length):
                        buf[p] = 0x00  # nop
                    changes += 1
                elif -32768 <= s_val <= 32767 and total_span >= 3:
                    buf[in1.pc] = 0x11  # sipush
                    struct.pack_into(">h", buf, in1.pc + 1, s_val)
                    for p in range(in1.pc + 3, in3.pc + in3.length):
                        buf[p] = 0x00  # nop
                    changes += 1

    return bytes(buf), changes


def deflat_code(code: bytes, cf: CF.ClassFile | None = None) -> tuple[bytes, int]:
    """Identify dispatcher switch and unflatten case transitions."""
    try:
        insns = BC.decode(code)
    except Exception:
        return code, 0

    if not insns:
        return code, 0

    # 1. Run constant simplification
    code, c_changes = simplify_constants(code, cf=cf)
    try:
        insns = BC.decode(code)
    except Exception:
        return code, c_changes

    # 2. Find all candidate dispatcher switches (switches with >= 3 branch targets)
    switches = [
        (i, insn) for i, insn in enumerate(insns)
        if insn.op in (OP_TABLESWITCH, OP_LOOKUPSWITCH) and len(insn.targets) >= 3
    ]

    if not switches:
        return code, c_changes

    buf = bytearray(code)
    unflattened = 0

    for switch_idx, switch_insn in switches:
        dispatcher_pc = switch_insn.pc

        # Check if preceding instruction is an iload
        state_var = -1
        if switch_idx > 0:
            prev = insns[switch_idx - 1]
            v = _is_iload(prev, bytes(buf))
            if v is not None:
                state_var = v
                dispatcher_pc = prev.pc

        # Parse switch table: map case values to target PCs
        case_to_target: dict[int, int] = {}
        pad = (4 - (switch_insn.pc + 1) % 4) % 4
        base = switch_insn.pc + 1 + pad

        try:
            if switch_insn.op == OP_LOOKUPSWITCH:
                npairs = struct.unpack_from(">i", code, base + 4)[0]
                if npairs > 0 and base + 8 + npairs * 8 <= len(code):
                    for p in range(npairs):
                        m_val, m_off = struct.unpack_from(">ii", code, base + 8 + p * 8)
                        target = switch_insn.pc + m_off
                        case_to_target[m_val] = target
            elif switch_insn.op == OP_TABLESWITCH:
                low, high = struct.unpack_from(">ii", code, base + 4)
                count = high - low + 1
                if count > 0 and base + 12 + count * 4 <= len(code):
                    for idx in range(count):
                        m_off = struct.unpack_from(">i", code, base + 12 + idx * 4)[0]
                        target = switch_insn.pc + m_off
                        case_to_target[low + idx] = target
        except Exception:
            continue

        if len(case_to_target) < 3:
            continue

        # Filter out NOP instructions so folded constants don't break consecutive matching
        clean_insns = [insn for insn in insns if insn.op != 0]

        for i in range(len(clean_insns) - 2):
            in_c = clean_insns[i]      # const loader
            in_s = clean_insns[i + 1]  # istore
            in_g = clean_insns[i + 2]  # goto

            if not in_g.is_goto or in_g.arg is None:
                continue

            goto_dest = in_g.pc + in_g.arg
            # Jumps back to dispatcher or switch
            if goto_dest != dispatcher_pc and goto_dest != switch_insn.pc:
                continue

            store_v = _is_istore(in_s, bytes(buf))
            if store_v is None:
                continue
            if state_var != -1 and store_v != -1 and store_v != state_var:
                continue

            next_state = _get_int_const(in_c, bytes(buf), cf=cf)
            if next_state is None:
                continue

            target_pc = case_to_target.get(next_state)
            if target_pc is None or target_pc == goto_dest:
                continue

            # Redirect goto directly to successor case block
            rel_target = target_pc - in_g.pc
            if in_g.op == OP_GOTO and -32768 <= rel_target <= 32767:
                struct.pack_into(">h", buf, in_g.pc + 1, rel_target)
                unflattened += 1
            elif in_g.op == OP_GOTO_W:
                struct.pack_into(">i", buf, in_g.pc + 1, rel_target)
                unflattened += 1

    return bytes(buf), c_changes + unflattened


def deflat_class(cf: CF.ClassFile) -> int:
    """De-flatten methods in a ClassFile in place. Returns number of edits."""
    changes = 0
    for m in cf.methods:
        if not m.attrs_blob or len(m.attrs_blob) < 2:
            continue
        attrs_data = bytearray(m.attrs_blob)
        ac = struct.unpack_from(">H", attrs_data, 0)[0]
        p = 2
        method_changed = False
        for _ in range(ac):
            if p + 6 > len(attrs_data):
                break
            name_idx, attr_len = struct.unpack_from(">HI", attrs_data, p)
            attr_val_start = p + 6
            attr_val_end = attr_val_start + attr_len
            if attr_val_end > len(attrs_data):
                break
            if cf.utf8(name_idx) == "Code":
                if attr_len >= 8:
                    max_s, max_l, code_len = struct.unpack_from(">HHI", attrs_data, attr_val_start)
                    code_start = attr_val_start + 8
                    code_end = code_start + code_len
                    if code_end <= attr_val_end:
                        raw_code = bytes(attrs_data[code_start:code_end])
                        new_code, n_edits = deflat_code(raw_code, cf=cf)
                        if n_edits > 0 and len(new_code) == len(raw_code):
                            attrs_data[code_start:code_end] = new_code
                            changes += n_edits
                            method_changed = True
            p = attr_val_end
        if method_changed:
            m.attrs_blob = bytes(attrs_data)
    return changes


def deflat_jar(jar_in: Path, jar_out: Path) -> dict:
    """Rewrite flattened control flow across an entire jar."""
    stats = {"classes": 0, "methods_unflattened": 0}
    jar_out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(jar_in) as zin, zipfile.ZipFile(jar_out, "w", zipfile.ZIP_DEFLATED) as zout:
        for name in zin.namelist():
            data = zin.read(name)
            if name.endswith(".class"):
                stats["classes"] += 1
                try:
                    cf = CF.parse(data)
                    edits = deflat_class(cf)
                    if edits > 0:
                        stats["methods_unflattened"] += edits
                        data = cf.serialize()
                except Exception:
                    pass
            zout.writestr(name, data)
    return stats
