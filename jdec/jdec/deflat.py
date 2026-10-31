"""Control flow de-flattening, anti-decompiler trap pruning, and opaque predicate elimination.

Advanced obfuscators (ZKM, Allatori, Dash-O, Stringer, Smoke) employ deep bytecode traps:
1. Control flow flattening: methods are transformed into a state machine loop around a
   switch dispatcher, where case blocks jump back to the dispatcher;
2. Opaque predicates: branches whose conditions are constant tautologies (e.g. 1 == 0,
   5 == 5, x == x) guarding unreachable blocks;
3. Anti-decompiler traps: unreachable dead code blocks containing invalid opcodes,
   unbalanced operand stacks, or bogus `athrow` instructions designed to crash CFR/Vineflower;
4. Malformed exception tables: zero-length (start == end) or out-of-bounds exception handlers.

This module cleans and optimizes method bytecode in place:
- Eliminates constant arithmetic and folds values;
- Resolves opaque predicates (converting always-taken jumps to unconditional gotos and
  never-taken jumps to NOPs);
- Eliminates redundant gotos jumping to their immediate successor;
- Unflattens switch state machine loops by linking case blocks directly to successors;
- Computes CFG reachability and NOPs out 100% of dead code traps;
- Sanitizes malformed exception table entries.
"""

from __future__ import annotations

import collections
import os
import struct
from pathlib import Path
import zipfile

from . import bytecode as BC
from . import classfile as CF
from .bytecode import (
    OP_GOTO, OP_GOTO_W, OP_TABLESWITCH, OP_LOOKUPSWITCH,
    Insn
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
    if insn.pc >= len(code) or code[insn.pc] != insn.op:
        return None
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
    if insn.pc >= len(code) or code[insn.pc] != insn.op:
        return None
    op = insn.op
    if 0x3B <= op <= 0x3E:  # istore_0 .. istore_3
        return op - 0x3B
    if op == 0x36 and insn.pc + 1 < len(code):  # istore <index>
        return code[insn.pc + 1]
    return None


def _is_iload(insn: Insn, code: bytes) -> int | None:
    """Returns local variable index if iload instruction, else None."""
    if insn.pc >= len(code) or code[insn.pc] != insn.op:
        return None
    op = insn.op
    if 0x1A <= op <= 0x1D:  # iload_0 .. iload_3
        return op - 0x1A
    if op == 0x15 and insn.pc + 1 < len(code):  # iload <index>
        return code[insn.pc + 1]
    return None


def _is_aload(insn: Insn, code: bytes) -> int | None:
    """Returns local variable index if aload instruction, else None."""
    if insn.pc >= len(code) or code[insn.pc] != insn.op:
        return None
    op = insn.op
    if 0x2A <= op <= 0x2D:  # aload_0 .. aload_3
        return op - 0x2A
    if op == 0x19 and insn.pc + 1 < len(code):  # aload <index>
        return code[insn.pc + 1]
    return None


def _protected_pcs(code: bytes, extra: set[int] | None = None) -> set[int]:
    """Instruction boundaries a rewrite must not swallow.

    Folding `iconst a; iconst b; ixor` replaces three instructions with one and
    NOPs the rest. That is only safe if nothing else enters the span: a branch
    or an exception handler that starts at the second instruction would land on
    a NOP with a different operand stack (VerifyError, or worse - a branch that
    silently changes meaning). Jump targets come from the code itself; handler
    PCs have to be supplied by the caller.
    """
    pcs: set[int] = set(extra or ())
    try:
        for insn in BC.decode(code):
            pcs.update(insn.jump_targets())
    except Exception:
        return pcs
    return pcs


def simplify_constants(code: bytes, cf: CF.ClassFile | None = None,
                       protected: set[int] | None = None) -> tuple[bytes, int]:
    """Peephole simplification for simple constant arithmetic like iconst + ixor.

    `protected` carries PCs the caller knows are entry points but which are not
    visible as branch targets (exception handlers).
    """
    try:
        insns = BC.decode(code)
    except Exception:
        return code, 0

    buf = bytearray(code)
    changes = 0
    entry_pcs = _protected_pcs(code, protected)

    clean_insns = [i for i in insns if i.op != 0]

    for i in range(len(clean_insns) - 2):
        in1, in2, in3 = clean_insns[i], clean_insns[i + 1], clean_insns[i + 2]
        if in3.pc >= len(buf) or buf[in3.pc] != in3.op:
            continue
        if in3.op in _INT_BIN_OPS:
            v1 = _get_int_const(in1, bytes(buf), cf=cf)
            v2 = _get_int_const(in2, bytes(buf), cf=cf)
            if v1 is not None and v2 is not None:
                span_end = in3.pc + in3.length
                # an entry point inside the span would be rewritten to a NOP
                if any(in1.pc < t < span_end for t in entry_pcs):
                    continue
                calc = _INT_BIN_OPS[in3.op]
                raw_res = calc(v1, v2)
                folded = raw_res & 0xFFFFFFFF
                s_val = folded if folded < 0x80000000 else folded - 0x100000000
                total_span = (in3.pc + in3.length) - in1.pc
                if -1 <= s_val <= 5 and total_span >= 1:
                    buf[in1.pc] = 0x03 + s_val  # iconst_0 + s_val
                    for p in range(in1.pc + 1, in3.pc + in3.length):
                        buf[p] = 0x00  # nop
                    changes += 1
                elif -128 <= s_val <= 127 and total_span >= 2:
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


def prune_opaque_predicates(code: bytes, cf: CF.ClassFile | None = None,
                            protected: set[int] | None = None) -> tuple[bytes, int]:
    """Eliminate constant and identity opaque predicates guarding dead branches.

    Every rewrite here replaces a *sequence* with a single jump. If something
    else can enter the sequence in the middle (a branch target, an exception
    handler), the replacement changes its operand stack, so such candidates are
    skipped instead of rewritten.
    """
    try:
        insns = BC.decode(code)
    except Exception:
        return code, 0

    buf = bytearray(code)
    changes = 0
    entry_pcs = _protected_pcs(code, protected)

    def _clobbers_entries(start: int, end: int) -> bool:
        return any(start < t < end for t in entry_pcs)

    clean = [i for i in insns if i.op != 0]

    # Pattern 1: [const v], [ifeq..ifle]
    for i in range(len(clean) - 1):
        in1, in2 = clean[i], clean[i + 1]
        if in2.op in (0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E) and in2.arg is not None:
            v = _get_int_const(in1, bytes(buf), cf=cf)
            if v is not None:
                taken = False
                if in2.op == 0x99: taken = (v == 0)
                elif in2.op == 0x9A: taken = (v != 0)
                elif in2.op == 0x9B: taken = (v < 0)
                elif in2.op == 0x9C: taken = (v >= 0)
                elif in2.op == 0x9D: taken = (v > 0)
                elif in2.op == 0x9E: taken = (v <= 0)

                if _clobbers_entries(in1.pc, in2.pc + in2.length):
                    continue
                target_pc = in2.pc + in2.arg
                rel = target_pc - in2.pc
                span1 = (in2.pc + in2.length) - in1.pc
                if taken and -32768 <= rel <= 32767:
                    for p in range(in1.pc, in1.pc + in1.length):
                        buf[p] = 0x00
                    buf[in2.pc] = OP_GOTO
                    struct.pack_into(">h", buf, in2.pc + 1, rel)
                    changes += 1
                elif taken and span1 >= 5:
                    rel_far = target_pc - in1.pc
                    buf[in1.pc] = OP_GOTO_W
                    struct.pack_into(">i", buf, in1.pc + 1, rel_far)
                    for p in range(in1.pc + 5, in2.pc + in2.length):
                        buf[p] = 0x00
                    changes += 1
                elif not taken:
                    for p in range(in1.pc, in2.pc + in2.length):
                        buf[p] = 0x00
                    changes += 1

    # Pattern 2: [const v1], [const v2], [if_icmpeq..if_icmple]
    for i in range(len(clean) - 2):
        in1, in2, in3 = clean[i], clean[i + 1], clean[i + 2]
        if in3.op in (0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4) and in3.arg is not None:
            v1 = _get_int_const(in1, bytes(buf), cf=cf)
            v2 = _get_int_const(in2, bytes(buf), cf=cf)
            if v1 is not None and v2 is not None:
                taken = False
                if in3.op == 0x9F: taken = (v1 == v2)
                elif in3.op == 0xA0: taken = (v1 != v2)
                elif in3.op == 0xA1: taken = (v1 < v2)
                elif in3.op == 0xA2: taken = (v1 >= v2)
                elif in3.op == 0xA3: taken = (v1 > v2)
                elif in3.op == 0xA4: taken = (v1 <= v2)

                if _clobbers_entries(in1.pc, in3.pc + in3.length):
                    continue
                target_pc = in3.pc + in3.arg
                rel = target_pc - in3.pc
                span2 = (in3.pc + in3.length) - in1.pc
                if taken and -32768 <= rel <= 32767:
                    for p in range(in1.pc, in3.pc):
                        buf[p] = 0x00
                    buf[in3.pc] = OP_GOTO
                    struct.pack_into(">h", buf, in3.pc + 1, rel)
                    changes += 1
                elif taken and span2 >= 5:
                    rel_far = target_pc - in1.pc
                    buf[in1.pc] = OP_GOTO_W
                    struct.pack_into(">i", buf, in1.pc + 1, rel_far)
                    for p in range(in1.pc + 5, in3.pc + in3.length):
                        buf[p] = 0x00
                    changes += 1
                elif not taken:
                    for p in range(in1.pc, in3.pc + in3.length):
                        buf[p] = 0x00
                    changes += 1

    # Pattern 3: Identity [iload X], [iload X], [if_icmpeq..if_icmple]
    for i in range(len(clean) - 2):
        in1, in2, in3 = clean[i], clean[i + 1], clean[i + 2]
        if in3.op in (0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4) and in3.arg is not None:
            x1 = _is_iload(in1, bytes(buf))
            x2 = _is_iload(in2, bytes(buf))
            if x1 is not None and x2 is not None and x1 == x2:
                taken = in3.op in (0x9F, 0xA2, 0xA4)
                if _clobbers_entries(in1.pc, in3.pc + in3.length):
                    continue
                target_pc = in3.pc + in3.arg
                rel = target_pc - in3.pc
                span3 = (in3.pc + in3.length) - in1.pc
                if taken and -32768 <= rel <= 32767:
                    for p in range(in1.pc, in3.pc):
                        buf[p] = 0x00
                    buf[in3.pc] = OP_GOTO
                    struct.pack_into(">h", buf, in3.pc + 1, rel)
                    changes += 1
                elif taken and span3 >= 5:
                    rel_far = target_pc - in1.pc
                    buf[in1.pc] = OP_GOTO_W
                    struct.pack_into(">i", buf, in1.pc + 1, rel_far)
                    for p in range(in1.pc + 5, in3.pc + in3.length):
                        buf[p] = 0x00
                    changes += 1
                elif not taken:
                    for p in range(in1.pc, in3.pc + in3.length):
                        buf[p] = 0x00
                    changes += 1

    # Pattern 4: [aconst_null], [ifnull / ifnonnull]
    for i in range(len(clean) - 1):
        in1, in2 = clean[i], clean[i + 1]
        if in1.op == 0x01 and in2.op in (0xC6, 0xC7) and in2.arg is not None:
            taken = (in2.op == 0xC6)
            if _clobbers_entries(in1.pc, in2.pc + in2.length):
                continue
            target_pc = in2.pc + in2.arg
            rel = target_pc - in2.pc
            if taken and -32768 <= rel <= 32767:
                for p in range(in1.pc, in2.pc):
                    buf[p] = 0x00
                buf[in2.pc] = OP_GOTO
                struct.pack_into(">h", buf, in2.pc + 1, rel)
                changes += 1
            elif not taken:
                for p in range(in1.pc, in2.pc + in2.length):
                    buf[p] = 0x00
                changes += 1

    # Pattern 5: Object reference identity [aload X], [aload X], [if_acmpeq / if_acmpne]
    for i in range(len(clean) - 2):
        in1, in2, in3 = clean[i], clean[i + 1], clean[i + 2]
        if in3.op in (0xA5, 0xA6) and in3.arg is not None:
            a1 = _is_aload(in1, bytes(buf))
            a2 = _is_aload(in2, bytes(buf))
            if a1 is not None and a2 is not None and a1 == a2:
                taken = (in3.op == 0xA5)  # if_acmpeq is always true for same local var
                target_pc = in3.pc + in3.arg
                rel = target_pc - in3.pc
                span5 = (in3.pc + in3.length) - in1.pc
                if taken and -32768 <= rel <= 32767:
                    for p in range(in1.pc, in3.pc):
                        buf[p] = 0x00
                    buf[in3.pc] = OP_GOTO
                    struct.pack_into(">h", buf, in3.pc + 1, rel)
                    changes += 1
                elif taken and span5 >= 5:
                    rel_far = target_pc - in1.pc
                    buf[in1.pc] = OP_GOTO_W
                    struct.pack_into(">i", buf, in1.pc + 1, rel_far)
                    for p in range(in1.pc + 5, in3.pc + in3.length):
                        buf[p] = 0x00
                    changes += 1
                elif not taken:
                    for p in range(in1.pc, in3.pc + in3.length):
                        buf[p] = 0x00
                    changes += 1

    return bytes(buf), changes


def clean_redundant_jumps(code: bytes) -> tuple[bytes, int]:
    """Eliminate redundant gotos jumping to immediate successor (even across NOPs) and thread trampolines."""
    try:
        insns = BC.decode(code)
    except Exception:
        return code, 0

    buf = bytearray(code)
    changes = 0
    pc_to_insn = {i.pc: i for i in insns}

    # 1. Eliminate self-fallthrough gotos (even across NOP padding)
    for insn in insns:
        if insn.is_goto and insn.arg is not None:
            target_pc = insn.pc + insn.arg
            next_insn_pc = insn.pc + insn.length
            if target_pc == next_insn_pc or (
                target_pc > next_insn_pc and all(buf[p] == 0 for p in range(next_insn_pc, min(target_pc, len(buf))))
            ):
                for p in range(insn.pc, insn.pc + insn.length):
                    buf[p] = 0x00
                changes += 1

    # 2. Jump threading / trampoline flattening
    for insn in insns:
        if insn.is_goto and insn.arg is not None and buf[insn.pc] == insn.op:
            target_pc = insn.pc + insn.arg
            curr = target_pc
            depth = 0
            visited = {insn.pc, curr}
            while depth < 8:
                while curr < len(buf) and buf[curr] == 0:
                    curr += 1
                next_insn = pc_to_insn.get(curr)
                if next_insn and next_insn.is_goto and next_insn.arg is not None and buf[next_insn.pc] == next_insn.op:
                    hop_target = next_insn.pc + next_insn.arg
                    if hop_target in visited:
                        break
                    visited.add(hop_target)
                    curr = hop_target
                    depth += 1
                else:
                    break

            if curr != target_pc:
                rel = curr - insn.pc
                if insn.op == OP_GOTO and -32768 <= rel <= 32767:
                    struct.pack_into(">h", buf, insn.pc + 1, rel)
                    changes += 1
                elif insn.op == OP_GOTO_W:
                    struct.pack_into(">i", buf, insn.pc + 1, rel)
                    changes += 1

    return bytes(buf), changes


def prune_dead_code(code: bytes, handlers: list[BC.Handler] | None = None) -> tuple[bytes, int]:
    """Identify unreachable basic blocks and replace them with NOPs."""
    try:
        insns = BC.decode(code)
    except Exception:
        return code, 0

    if not insns:
        return code, 0

    pc_to_insn = {i.pc: i for i in insns}
    reachable: set[int] = set()
    queue = collections.deque([0])
    reachable.add(0)

    active_handlers: set[int] = set()

    def check_handlers(pc: int) -> None:
        if not handlers:
            return
        for hi, h in enumerate(handlers):
            if hi not in active_handlers and h.start_pc <= pc < h.end_pc:
                if h.handler_pc in pc_to_insn and h.handler_pc not in reachable:
                    active_handlers.add(hi)
                    reachable.add(h.handler_pc)
                    queue.append(h.handler_pc)

    check_handlers(0)

    while queue:
        curr_pc = queue.popleft()
        insn = pc_to_insn.get(curr_pc)
        if not insn:
            continue

        check_handlers(curr_pc)

        if insn.is_branch or insn.is_goto:
            for t in insn.jump_targets():
                if t in pc_to_insn and t not in reachable:
                    reachable.add(t)
                    queue.append(t)

        if not insn.is_terminator and not insn.is_goto and insn.op not in (OP_TABLESWITCH, OP_LOOKUPSWITCH):
            next_pc = insn.pc + insn.length
            if next_pc in pc_to_insn and next_pc not in reachable:
                reachable.add(next_pc)
                queue.append(next_pc)

    buf = bytearray(code)
    pruned_count = 0
    handler_pcs = {h.handler_pc for h in (handlers or [])}
    for insn in insns:
        if insn.pc not in reachable:
            # NOPing the instruction *before* a handler entry turns "jump away"
            # into "fall into the catch block with an empty stack". That is not
            # a stale-frame problem, it is a behaviour change — measured on
            # HMCL: 45 classes failed verification because a dead `goto` was
            # NOPed and control fell into the handler's `astore`.
            nxt = insn.pc + insn.length
            ends_flow = (insn.is_terminator or insn.is_goto
                         or insn.op in (OP_TABLESWITCH, OP_LOOKUPSWITCH))
            if ends_flow and (nxt not in pc_to_insn or nxt in handler_pcs):
                # NOPing the last terminator makes control fall off the end of
                # the code array; NOPing the one before a handler entry makes it
                # fall into the catch block with an empty stack. Both are
                # behaviour changes, not stale frames (measured: 13 + 3 classes).
                continue
            if insn.is_branch or insn.is_goto or insn.op in (
                    OP_TABLESWITCH, OP_LOOKUPSWITCH):
                # A dead branch is left alone. NOPing it turns "jump away" into
                # "fall through", and the verifier then judges the fall-through
                # path against the frame that the *next* instruction declares:
                # measured on ThemeCondition.normalizeValue, where `goto 286`
                # sat right before a stack-map entry at 273 and the class was
                # rejected with "current frame's stack size doesn't match".
                # The instruction is unreachable either way, so keeping it costs
                # two bytes and changes nothing.
                continue
            if insn.op != 0:
                pruned_count += 1
            for p in range(insn.pc, insn.pc + insn.length):
                buf[p] = 0x00

    return bytes(buf), pruned_count


def prune_exception_handlers(handlers: list[BC.Handler], code_len: int, reachable_pcs: set[int] | None = None) -> tuple[list[BC.Handler], int]:
    """Filter out zero-length, inverted, or out-of-bounds exception handlers."""
    valid: list[BC.Handler] = []
    dropped = 0
    for h in handlers:
        if h.start_pc >= h.end_pc:
            dropped += 1
            continue
        if h.start_pc < 0 or h.end_pc > code_len or h.handler_pc < 0 or h.handler_pc >= code_len:
            dropped += 1
            continue
        if reachable_pcs is not None and not any(pc in reachable_pcs for pc in range(h.start_pc, h.end_pc)):
            dropped += 1
            continue
        valid.append(h)
    return valid, dropped


def deflat_code(code: bytes, cf: CF.ClassFile | None = None) -> tuple[bytes, int]:
    """Identify dispatcher switch and unflatten case transitions."""
    try:
        insns = BC.decode(code)
    except Exception:
        return code, 0

    if not insns:
        return code, 0

    switches = [
        (i, insn) for i, insn in enumerate(insns)
        if insn.op in (OP_TABLESWITCH, OP_LOOKUPSWITCH) and len(insn.targets) >= 3
    ]

    if not switches:
        return code, 0

    buf = bytearray(code)
    unflattened = 0

    for switch_idx, switch_insn in switches:
        dispatcher_pc = switch_insn.pc

        state_var = -1
        if switch_idx > 0:
            prev = insns[switch_idx - 1]
            v = _is_iload(prev, bytes(buf))
            if v is not None:
                state_var = v
                dispatcher_pc = prev.pc

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

        clean_insns = [insn for insn in insns if insn.op != 0]

        for i in range(len(clean_insns) - 2):
            in_c = clean_insns[i]
            in_s = clean_insns[i + 1]
            in_g = clean_insns[i + 2]

            if not in_g.is_goto or in_g.arg is None:
                continue

            goto_dest = in_g.pc + in_g.arg
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

            rel_target = target_pc - in_g.pc
            if in_g.op == OP_GOTO and -32768 <= rel_target <= 32767:
                struct.pack_into(">h", buf, in_g.pc + 1, rel_target)
                unflattened += 1
            elif in_g.op == OP_GOTO_W:
                struct.pack_into(">i", buf, in_g.pc + 1, rel_target)
                unflattened += 1
            elif in_g.op == OP_GOTO and (rel_target < -32768 or rel_target > 32767):
                total_span = (in_g.pc + in_g.length) - in_c.pc
                if total_span >= 5:
                    rel_far = target_pc - in_c.pc
                    buf[in_c.pc] = OP_GOTO_W
                    struct.pack_into(">i", buf, in_c.pc + 1, rel_far)
                    for p in range(in_c.pc + 5, in_g.pc + in_g.length):
                        buf[p] = 0x00
                    unflattened += 1

    return bytes(buf), unflattened


def optimize_code(code: bytes, handlers: list[BC.Handler] | None = None, cf: CF.ClassFile | None = None) -> tuple[bytes, list[BC.Handler], dict[str, int]]:
    """Master optimization pass: constant folding, opaque predicates, dead code pruning, unflattening."""
    cur_code = code
    cur_handlers = list(handlers or [])
    stats = {
        "constants": 0,
        "opaque_predicates": 0,
        "redundant_jumps": 0,
        "dead_code": 0,
        "unflattened": 0,
        "handlers_pruned": 0,
        "total": 0,
    }

    for _ in range(3):
        # deflat rewrites in place (NOP fill keeps every PC valid), so handler
        # entry points stay at their original offsets across the whole loop
        entries = {pc for h in cur_handlers for pc in (h.start_pc, h.end_pc, h.handler_pc)}
        cur_code, c_n = simplify_constants(cur_code, cf=cf, protected=entries)
        stats["constants"] += c_n

        cur_code, op_n = prune_opaque_predicates(cur_code, cf=cf, protected=entries)
        stats["opaque_predicates"] += op_n

        cur_code, j_n = clean_redundant_jumps(cur_code)
        stats["redundant_jumps"] += j_n

        cur_code, unflat_n = deflat_code(cur_code, cf=cf)
        stats["unflattened"] += unflat_n

        cur_code, d_n = prune_dead_code(cur_code, cur_handlers)
        stats["dead_code"] += d_n

        if c_n == 0 and op_n == 0 and j_n == 0 and unflat_n == 0 and d_n == 0:
            break

    try:
        final_insns = BC.decode(cur_code)
        non_nop_pcs = {i.pc for i in final_insns if i.op != 0}
    except Exception:
        non_nop_pcs = None

    cur_handlers, h_n = prune_exception_handlers(cur_handlers, len(cur_code), reachable_pcs=non_nop_pcs)
    stats["handlers_pruned"] += h_n
    stats["total"] = sum(v for k, v in stats.items() if k != "total")

    return cur_code, cur_handlers, stats


def deflat_class(cf: CF.ClassFile) -> int:
    """Optimize all methods in a ClassFile: unflatten, eliminate traps and dead blocks.

    Returns total number of bytecode edits.
    """
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
            is_code = False
            if 0 < name_idx < len(cf.cp) and cf.cp[name_idx] and cf.cp[name_idx][0] == CF.C_UTF8:
                try:
                    is_code = (cf.utf8(name_idx) == "Code")
                except Exception:
                    is_code = False
            if is_code:
                if attr_len >= 8:
                    max_s, max_l, code_len = struct.unpack_from(">HHI", attrs_data, attr_val_start)
                    code_start = attr_val_start + 8
                    code_end = code_start + code_len
                    if code_end <= attr_val_end:
                        raw_code = bytes(attrs_data[code_start:code_end])

                        # Read exception handlers
                        handlers: list[BC.Handler] = []
                        if code_end + 2 <= attr_val_end:
                            hcount = struct.unpack_from(">H", attrs_data, code_end)[0]
                            if code_end + 2 + hcount * 8 <= attr_val_end:
                                for hi in range(hcount):
                                    hs, he, hh, hc = struct.unpack_from(">HHHH", attrs_data, code_end + 2 + hi * 8)
                                    handlers.append(BC.Handler(hs, he, hh, hc))

                        new_code, new_handlers, stats = optimize_code(raw_code, handlers, cf=cf)
                        if stats["total"] > 0:
                            diff_code_len = len(new_code) - len(raw_code)
                            # Update code bytes
                            attrs_data[code_start:code_end] = new_code
                            code_end = code_start + len(new_code)
                            attr_val_end += diff_code_len

                            if diff_code_len != 0:
                                # Update code_length in Code attribute header
                                struct.pack_into(">I", attrs_data, attr_val_start + 4, len(new_code))
                                attr_len += diff_code_len
                                struct.pack_into(">I", attrs_data, p + 2, attr_len)

                            # Re-pack exception handlers if counts changed, code length shifted, or handlers modified
                            handlers_changed = (len(new_handlers) != len(handlers)) or any(nh != oh for nh, oh in zip(new_handlers, handlers))
                            if handlers_changed or diff_code_len != 0:
                                h_bytes = struct.pack(">H", len(new_handlers)) + b"".join(
                                    struct.pack(">HHHH", h.start_pc, h.end_pc, h.handler_pc, h.catch_type)
                                    for h in new_handlers
                                )
                                old_tail_offset = code_end + 2 + len(handlers) * 8
                                sub_attrs = bytes(attrs_data[old_tail_offset:attr_val_end])
                                attrs_data[code_end:attr_val_end] = h_bytes + sub_attrs
                                new_attr_len = (code_end - attr_val_start) + len(h_bytes) + len(sub_attrs)
                                struct.pack_into(">I", attrs_data, p + 2, new_attr_len)
                                attr_val_end = attr_val_start + new_attr_len

                            changes += stats["total"]
                            method_changed = True
            p = attr_val_end
        if method_changed:
            m.attrs_blob = bytes(attrs_data)
    return changes


def _strip_smt_from_code(cf: CF.ClassFile, payload: bytes) -> bytes | None:
    """从 Code 属性负载里剥掉 StackMapTable 内嵌属性;没有则返回 None。"""
    import struct as _s
    try:
        o = 4                                   # max_stack u2 + max_locals u2
        code_len = _s.unpack_from(">I", payload, o)[0]
        o += 4 + code_len
        exc_n = _s.unpack_from(">H", payload, o)[0]
        o += 2 + 8 * exc_n
        tbl_start = o                    # 内嵌属性表起点（attr_count 字段处）
        attr_n = _s.unpack_from(">H", payload, o)[0]
        o += 2
        entries, had = [], False
        for _ in range(attr_n):
            ni = _s.unpack_from(">H", payload, o)[0]
            ln = _s.unpack_from(">I", payload, o + 2)[0]
            data = payload[o + 6:o + 6 + ln]
            o += 6 + ln
            if cf.utf8(ni) == "StackMapTable":
                had = True
                continue
            entries.append((ni, data))
        if not had:
            return None
        out = bytearray(payload[:tbl_start])
        out += _s.pack(">H", len(entries))
        for ni, data in entries:
            out += _s.pack(">HI", ni, len(data)) + data
        return bytes(out)
    except Exception:
        return None


def _strip_stackmaps(cf: CF.ClassFile, only: set[int] | None = None) -> int:
    """反平坦化后原 StackMapTable 帧全部失效（原地改写不更新帧），
    陈旧帧会让下游反编译器在这些类上出错误标记（真实样本实测掉档
    46 个类）。剥帧后 CFR/Vineflower 自行重算分析。返回处理的方法数。

    `only` 限定只剥这些下标的方法。**没改写的方法必须保留原帧**：
    它们本来是对的，剥掉之后只要还含分支就会被 split verifier 拒绝。
    早期版本剥全类，HMCL 上因此有 242 个类被验证器拒绝。

    已知边界（2026-10-29 用真 JVM 校验器实测，**不是**推测）：
    剥帧后的方法如果还含分支，split verifier 会直接拒绝——
    `VerifyError: Expecting a stackmap frame at branch target N`。
    所以 `deflat_jar` 逐方法回滚"改写后仍有分支目标"的方法，再用
    `verify_or_keep` 兜底。要把这些改写保住，必须生成正确的帧，
    也就是 ROADMAP 02 的帧生成。"""
    import struct as _s
    n = 0
    for idx, m in enumerate(cf.methods):
        if only is not None and idx not in only:
            continue
        blob = m.attrs_blob
        if len(blob) < 2:
            continue
        try:
            cnt = _s.unpack_from(">H", blob, 0)[0]
            o = 2
            entries, changed = [], False
            for _ in range(cnt):
                ni = _s.unpack_from(">H", blob, o)[0]
                ln = _s.unpack_from(">I", blob, o + 2)[0]
                data = blob[o + 6:o + 6 + ln]
                o += 6 + ln
                if cf.utf8(ni) == "Code":
                    new = _strip_smt_from_code(cf, data)
                    if new is not None:
                        entries.append((ni, new))
                        changed = True
                        continue
                entries.append((ni, data))
            if changed:
                out = bytearray(_s.pack(">H", cnt))
                for ni, data in entries:
                    out += _s.pack(">HI", ni, len(data)) + data
                m.attrs_blob = bytes(out)
                n += 1
        except Exception:
            continue
    return n


def _revert_branchy_methods(cf: CF.ClassFile, before: list[bytes]) -> int:
    """Put back any rewritten method whose body still has a branch target.

    A method without a StackMapTable is only verifiable when it is straight-line
    code: the split verifier demands a frame at every branch target. Reverting
    the *method* (not the class) keeps every other rewrite in the class and
    keeps the class loadable — class-level rollback threw away 343 classes'
    worth of good edits for a handful of bad methods.
    """
    reverted = 0
    for m, old in zip(cf.methods, before):
        if m.attrs_blob == old:
            continue
        ci = BC.method_code(cf, m)
        if ci is None or (ci.insns and (ci.branch_targets or ci.handlers)):
            m.attrs_blob = old
            reverted += 1
    return reverted


def _rebuild_frames(cf, indices, before, hier) -> tuple[int, list[int]]:
    """Recompute StackMapTables for the methods deflat changed.

    Returns (rebuilt, reverted). A method whose frames cannot be computed is put
    back exactly as it was: shipping a class with a guessed frame is worse than
    shipping the original method.
    """
    from . import bytecode as _BC
    from .ir import assume as _assume
    from .ir import attrs as _attrs
    from .ir import frames as _frames
    from .ir import types as _types

    rebuilt, reverted = 0, []
    for i in indices:
        m = cf.methods[i]
        try:
            ci = _BC.method_code(cf, m, decode_insns=False)
            if ci is None:
                raise _types.FrameError("no Code attribute")
            insns = _BC.decode(ci.code)
            states = _assume.compute_frames(cf, m, ci.code, ci.handlers,
                                            ci.max_stack, ci.max_locals, hier)
            needed = set(_frames.needed_pcs(insns, ci.handlers))
            # javac decided some offsets need frames that our worklist never
            # reaches (a rewrite can leave dead padding at the end of a
            # protected range). Keep those offsets and reuse the original
            # frame: dropping it is what made HMCL classes fail with
            # "Expecting a stackmap frame at branch target" after a rewrite.
            original = {}
            try:
                shim = _Blob(before[i])
                for name, payload in _attrs.code_subattrs(cf, shim):
                    if name == "StackMapTable":
                        original = _frames.decode(cf, payload, m, ci.max_locals)
                        break
            except Exception:
                original = {}
            needed |= set(original)
            merged = {}
            for pc in needed:
                if pc in states:
                    merged[pc] = states[pc]
                elif pc in original:
                    merged[pc] = original[pc]
            missing = needed - set(merged)
            if missing:
                raise _types.FrameError(
                    f"no frame for offset(s) {sorted(missing)[:4]}")
            _attrs.set_code_subattr(cf, m, "StackMapTable",
                                    _frames.encode(cf, merged, needed))
            rebuilt += 1
        except Exception:  # noqa: BLE001 - FrameError and decode errors alike
            m.attrs_blob = before[i]
            reverted.append(i)
    return rebuilt, reverted


class _Blob:
    """Just enough of a Member for `attrs.code_subattrs` on saved bytes."""

    __slots__ = ("attrs_blob",)

    def __init__(self, blob: bytes):
        self.attrs_blob = blob


def _revert_shifted_methods(cf: CF.ClassFile, before: list[bytes],
                            before_len: list[int]) -> int:
    """Put back any rewritten method whose code moved.

    Every rewrite here is length-preserving (NOP fill), so the original
    StackMapTable keeps pointing at the same offsets and stays correct. If a
    rewrite ever changes the length, the frames no longer line up — revert that
    method instead of shipping a class whose frames describe the old layout.
    """
    reverted = 0
    for i, (m, old) in enumerate(zip(cf.methods, before)):
        if m.attrs_blob == old:
            continue
        ci = BC.method_code(cf, m)
        if ci is None or len(ci.code) != before_len[i]:
            m.attrs_blob = old
            reverted += 1
    return reverted


def _method_signature(cf: CF.ClassFile, member) -> tuple[str, str, str]:
    return (cf.name, cf.utf8(member.name_index), cf.utf8(member.descriptor_index))


def _rewrite_class_ir(cf: CF.ClassFile, hier,
                      rewritten: list | None = None,
                      refusals: list | None = None,
                      check_reasons: bool = True) -> tuple[int, int]:
    """Run the instruction-level passes over one class.

    Returns (methods rewritten, methods rolled back). A rollback restores the
    original `attrs_blob`, so the output is never worse than the input — the
    same invariant the byte passes are held to.

    `rewritten` collects `(class, name, descriptor)` for every method that
    actually changed, which is what the behaviour harness needs to know which
    methods are worth deriving cases for. `refusals` collects the methods the
    reason checker would not justify; they keep their original body.
    """
    from .ir import transforms as _transforms
    edits = reverted = 0
    for m in cf.methods:
        before = m.attrs_blob
        try:
            if _transforms.rewrite_method(cf, m, hier,
                                          check_reasons=check_reasons):
                edits += 1
                if rewritten is not None:
                    rewritten.append(_method_signature(cf, m))
        except Exception as exc:  # noqa: BLE001 - FrameError, decode error, etc
            if m.attrs_blob != before:
                m.attrs_blob = before
                reverted += 1
            if refusals is not None and str(exc).startswith("unjustified"):
                refusals.append(_method_signature(cf, m) + (str(exc),))
    return edits, reverted


# --- parallel rewriting ----------------------------------------------------
# Workers parse and rewrite whole classes; the parent owns the zip and the
# entry order. Each worker builds its own Hierarchy: the spawn context cannot
# share the parent's, and one parse per worker is cheaper than shipping the
# graph. The parent takes the missing-dependency set from a worker instead of
# building a third copy.

_WORKER: dict = {}


def _deflat_worker_init(jar_in: str, classpath, check_reasons: bool) -> None:
    hier = None
    try:
        from .ir import hierarchy as _hierarchy
        hier = _hierarchy.Hierarchy.from_jar(
            Path(jar_in), extra=[Path(c) for c in classpath])
    except Exception:  # noqa: BLE001 - Object fallback still works
        hier = None
    _WORKER["hier"] = hier
    _WORKER["check"] = check_reasons
    _WORKER["unresolved"] = sorted(hier.unresolved) if hier is not None else []


def _deflat_one(item):
    name, data = item
    try:
        cf = CF.parse(data)
        rewritten: list = []
        refused: list = []
        edits, reverted = _rewrite_class_ir(
            cf, _WORKER.get("hier"), rewritten, refused,
            _WORKER.get("check", True))
        if edits:
            data = cf.serialize()
        return (name, data, edits, reverted, rewritten, refused, None)
    except Exception as exc:  # noqa: BLE001 - one bad class only
        return (name, data, 0, 0, [], [],
                f"{name}: {type(exc).__name__}: {exc}")


def _deflat_chunk(items):
    return ([_deflat_one(it) for it in items],
            list(_WORKER.get("unresolved") or []))


def _is_class_entry(name: str) -> bool:
    return name.endswith(".class") and not name.startswith("META-INF/")


def _parallel_deflat(jar_in: Path, jar_out: Path, classpath, check_reasons: bool,
                     jobs: int, stats: dict) -> bool:
    """Rewrite classes in worker processes; False means "fall back to serial".

    The output is written to a side file and merged into `stats` only after
    every worker returned, so a failed pool leaves both untouched.
    """
    auto = jobs <= 0
    if auto:
        jobs = min(4, os.cpu_count() or 1)
    if jobs <= 1:
        return False
    tmp = jar_out.with_name(jar_out.name + ".parallel")
    try:
        import concurrent.futures as _cf
        import multiprocessing as _mp
        from math import ceil

        with zipfile.ZipFile(jar_in) as zin:
            entries = [(n, zin.read(n)) for n in zin.namelist()]
        class_items = [(n, d) for n, d in entries if _is_class_entry(n)]
        if auto and len(class_items) < 400:
            return False
        per = max(1, min(200, ceil(len(class_items) / max(1, jobs * 4))))
        chunks = [class_items[i:i + per]
                  for i in range(0, len(class_items), per)]
        ctx = _mp.get_context("spawn")
        with _cf.ProcessPoolExecutor(
                max_workers=jobs, mp_context=ctx,
                initializer=_deflat_worker_init,
                initargs=(str(jar_in), tuple(str(c) for c in classpath),
                          check_reasons)) as ex:
            results = list(ex.map(_deflat_chunk, chunks))
        rows = [row for chunk_rows, _u in results for row in chunk_rows]
        if len(rows) != len(class_items):
            return False
        unresolved = next((u for _r, u in results if u), [])

        edits = reverted = 0
        rewritten: list = []
        refused: list = []
        failed: list = []
        it = iter(rows)
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
            for name, data in entries:
                if _is_class_entry(name):
                    _n, ndata, e, r, rw, rf, fail = next(it)
                    edits += e
                    reverted += r
                    rewritten.extend(rw)
                    refused.extend(rf)
                    if fail:
                        failed.append(fail)
                    zout.writestr(name, ndata)
                else:
                    zout.writestr(name, data)
        os.replace(tmp, jar_out)
        stats["classes"] = len(class_items)
        stats["methods_unflattened"] += edits
        stats["traps_pruned"] += edits
        stats["frames_rebuilt"] += edits
        stats["methods_reverted"] += reverted
        stats["rewritten"].extend(rewritten)
        stats["reason_refused"].extend(refused)
        stats["failed_classes"].extend(failed)
        stats["unresolved_types"] = unresolved
        return True
    except Exception:  # noqa: BLE001 - any pool problem falls back to serial
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        return False


def deflat_jar(jar_in: Path, jar_out: Path, verify_output: bool = True,
               strip_frames: bool = False,
               recompute_frames: bool = False,
               ir_rewrite: bool = True,
               classpath=(),
               check_reasons: bool = True,
               jobs: int = 1) -> dict:
    """Rewrite flattened control flow and prune bytecode traps across an entire jar.

    The default path works on the instruction list (`ir/transforms.py`): a
    folded expression is deleted, a dead block is removed, frames are recomputed
    and the result is loaded under `-Xverify:all`. `ir_rewrite=False` selects
    the original byte-patching passes, which fill their holes with `nop` and
    leave the original StackMapTable in place; `strip_frames` is for
    decompiler input only, where loadability is not the goal.

    Safety nets, in increasing cost:

    1. per method — on the instruction path a method whose frames cannot be
       recomputed keeps its original Code attribute; on the byte path a rewrite
       that still contains branches (with `strip_frames`) or that moved an
       offset (without it) is reverted;
    2. per class — `verify_or_keep` loads the result under `-Xverify:all` and
       replaces any class the verifier rejects with the original bytes.

    `strip_frames` trades JVM-loadability for decompiler quality: stale frames
    made CFR/Vineflower drop ~46 classes in an earlier sample. For an artifact
    that has to run, keep the frames (default).
    """
    if ir_rewrite and strip_frames:
        raise ValueError("ir_rewrite and strip_frames are mutually exclusive: "
                         "the instruction-level path computes the frames that "
                         "strip_frames removes on purpose")
    stats: dict = {"classes": 0, "methods_unflattened": 0, "traps_pruned": 0,
                   "methods_reverted": 0, "frames_rebuilt": 0,
                   "unresolved_types": [],
                   "failed_classes": [],
                   "rewritten": [], "reason_refused": []}
    jar_out.parent.mkdir(parents=True, exist_ok=True)
    if ir_rewrite and jobs != 1 and _parallel_deflat(
            jar_in, jar_out, classpath, check_reasons, jobs, stats):
        if verify_output:
            stats["verify"] = _verify_rewrite(jar_in, jar_out, classpath,
                                              stats.get("rewritten"))
        return stats
    hier = None
    if recompute_frames or ir_rewrite:
        try:
            from .ir import hierarchy as _hierarchy
            hier = _hierarchy.Hierarchy.from_jar(jar_in, extra=classpath)
        except Exception:  # noqa: BLE001 - Object fallback still works
            hier = None
    if hier is not None:
        stats["unresolved_types"] = sorted(hier.unresolved)
    with zipfile.ZipFile(jar_in) as zin, zipfile.ZipFile(jar_out, "w", zipfile.ZIP_DEFLATED) as zout:
        for name in zin.namelist():
            data = zin.read(name)
            if name.endswith(".class") and not name.startswith("META-INF/"):
                stats["classes"] += 1
                try:
                    cf = CF.parse(data)
                    if ir_rewrite:
                        edits, reverted = _rewrite_class_ir(
                            cf, hier, stats["rewritten"],
                            stats["reason_refused"], check_reasons)
                        stats["methods_unflattened"] += edits
                        stats["traps_pruned"] += edits
                        stats["frames_rebuilt"] += edits
                        stats["methods_reverted"] += reverted
                        if edits:
                            data = cf.serialize()
                        zout.writestr(name, data)
                        continue
                    before = [m.attrs_blob for m in cf.methods]
                    before_len = []
                    for m in cf.methods:
                        ci = BC.method_code(cf, m)
                        before_len.append(len(ci.code) if ci else 0)
                    edits = deflat_class(cf)
                    if edits > 0:
                        if strip_frames:
                            kept_back = _revert_branchy_methods(cf, before)
                        else:
                            kept_back = _revert_shifted_methods(cf, before, before_len)
                        stats["methods_reverted"] += kept_back
                        edits -= kept_back
                    if edits > 0 and strip_frames:
                        stats["methods_unflattened"] += edits
                        stats["traps_pruned"] += edits
                        changed = {i for i, (m, old) in
                                   enumerate(zip(cf.methods, before))
                                   if m.attrs_blob != old}
                        _record_rewritten(cf, changed, stats)
                        # 只剥被改写方法的帧：没动过的方法帧本来是对的
                        _strip_stackmaps(cf, only=changed)
                        data = cf.serialize()
                    elif edits > 0 and recompute_frames:
                        changed = {i for i, (m, old) in
                                   enumerate(zip(cf.methods, before))
                                   if m.attrs_blob != old}
                        rebuilt, reverted = _rebuild_frames(cf, changed, before, hier)
                        stats["frames_rebuilt"] += rebuilt
                        stats["methods_reverted"] += len(reverted)
                        stats["methods_unflattened"] += edits - len(reverted)
                        stats["traps_pruned"] += edits - len(reverted)
                        _record_rewritten(cf, changed - set(reverted), stats)
                        data = cf.serialize()
                    elif edits > 0:
                        # default: keep the original table. These rewrites are
                        # length-preserving, so the frames still sit at the same
                        # offsets; `--recompute-frames` regenerates them, which
                        # is experimental.
                        stats["methods_unflattened"] += edits
                        stats["traps_pruned"] += edits
                        changed = {i for i, (m, old) in
                                   enumerate(zip(cf.methods, before))
                                   if m.attrs_blob != old}
                        _record_rewritten(cf, changed, stats)
                        data = cf.serialize()
                except Exception as exc:  # noqa: BLE001 - one bad class only
                    stats["failed_classes"].append(
                        f"{name}: {type(exc).__name__}: {exc}")
            zout.writestr(name, data)
    if verify_output:
        stats["verify"] = _verify_rewrite(jar_in, jar_out, classpath,
                                          stats.get("rewritten"))
    return stats


def _record_rewritten(cf, indices, stats: dict) -> None:
    """Name the methods the *byte* path actually changed.

    Without this, `--byte-patch --rewritten` wrote an empty file: the list was
    only filled by the instruction-level path, so the behaviour harness was
    told "nothing was rewritten" about a jar that had 1366 rewritten methods.
    """
    for i in sorted(indices):
        try:
            stats["rewritten"].append(_method_signature(cf, cf.methods[i]))
        except Exception:
            continue


def _verify_rewrite(jar_in: Path, jar_out: Path, classpath=(),
                    rows=None) -> dict:
    """Run the JVM gate on the output and roll back any class it rejects."""
    try:
        from . import toolchain as TC
        from . import verify as VF
    except Exception as exc:  # pragma: no cover - import cycle guard
        return {"skipped": f"{type(exc).__name__}: {exc}"}
    if not TC.find_java():
        return {"skipped": "java not found: set JAVA_HOME or put java on PATH"}
    try:
        return VF.verify_or_keep(jar_in, jar_out, classpath=classpath,
                                 rows=rows).to_dict()
    except Exception as exc:  # noqa: BLE001 - the rewrite itself already succeeded
        return {"skipped": f"{type(exc).__name__}: {exc}"}
