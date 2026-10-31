"""Rewrites that change the code array's length.

`deflat`'s original passes patch raw bytes in place and fill the holes with
`nop`. That keeps every offset where it was — which is why the original
StackMapTable usually survives — but it also means a method never gets shorter,
and a decompiler reading it walks through a corridor of `nop`s.

The passes here work on the instruction list instead: a folded expression is
*deleted*, a dead block is *removed*, and `assemble()` re-lays the method out.
The price is that every offset moves, so frames must be recomputed — that is
`rewrite_method`'s job, and anything it cannot do it reverts instead of
shipping a method it cannot prove loadable.

The rewrite rules are the same ones `deflat` applies, because a migration that
quietly does less is not a migration:

    [iconst a][iconst b][iadd]        -> [iconst a+b]
    [const v][ifeq L]                 -> [goto L]   or   (nothing)
    [iconst a][iconst b][if_icmp..]   -> [goto L]   or   (nothing)
    [iload x][iload x][if_icmp..]     -> [goto L]   or   (nothing)
    [aload x][aload x][if_acmp..]     -> [goto L]   or   (nothing)
    [aconst_null][ifnull/ifnonnull]   -> [goto L]   or   (nothing)
    [goto L] where L is the next pc  -> (nothing)
    unreachable instructions         -> (nothing)

One deliberate difference from the byte passes: pattern 5 in the original had no
"is anything jumping into the middle of this sequence" check, so a branch into
the middle of `[aload][aload][if_acmp]` could be silently broken. Here deletion
is checked against every surviving branch, so that case is refused.
"""

from __future__ import annotations

import bisect

from .. import bytecode as BC
from .. import classfile as CF
from . import assemble as ASM
from . import attrs as AT
from . import assume as AS
from . import frames as FR
from .types import FrameError

MAX_ROUNDS = 4096

_ICONST = {0x02: -1, 0x03: 0, 0x04: 1, 0x05: 2, 0x06: 3, 0x07: 4, 0x08: 5}

_INT_BIN = {
    0x60: lambda a, b: a + b,                       # iadd
    0x64: lambda a, b: a - b,                       # isub
    0x68: lambda a, b: a * b,                       # imul
    0x7E: lambda a, b: a & b,                       # iand
    0x80: lambda a, b: a | b,                       # ior
    0x82: lambda a, b: a ^ b,                       # ixor
    0x78: lambda a, b: a << (b & 0x1F),             # ishl
    0x7A: lambda a, b: a >> (b & 0x1F),             # ishr
    0x7C: lambda a, b: (a & 0xFFFFFFFF) >> (b & 0x1F),  # iushr
}

_IF_ICMP = {0x9F: lambda a, b: a == b, 0xA0: lambda a, b: a != b,
            0xA1: lambda a, b: a < b, 0xA2: lambda a, b: a >= b,
            0xA3: lambda a, b: a > b, 0xA4: lambda a, b: a <= b}
# if_icmp<cond> is always taken when the same local is compared to itself
_IF_ICMP_SELF = {0x9F, 0xA2, 0xA4}

_IF_UNARY = {0x99: lambda v: v == 0, 0x9A: lambda v: v != 0,
             0x9B: lambda v: v < 0, 0x9C: lambda v: v >= 0,
             0x9D: lambda v: v > 0, 0x9E: lambda v: v <= 0}

OP_GOTO = 0xA7
OP_GOTO_W = 0xC8


# --------------------------------------------------------------------------
# instruction helpers (the byte passes read a byte array; these read `Insn`)
# --------------------------------------------------------------------------

def int_const(insn, cf=None) -> int | None:
    """The int an instruction pushes, or None."""
    op = insn.op
    if op in _ICONST:
        return _ICONST[op]
    if op == 0x10 and insn.arg is not None:            # bipush
        return insn.arg - 0x100 if insn.arg > 0x7F else insn.arg
    if op == 0x11 and insn.arg is not None:            # sipush
        return insn.arg - 0x10000 if insn.arg > 0x7FFF else insn.arg
    if cf is not None and op in (0x12, 0x13) and insn.arg is not None:
        idx = insn.arg
        if 0 < idx < len(cf.cp):
            entry = cf.cp[idx]
            if entry and entry[0] == CF.C_INTEGER:
                raw = entry[1][0] if isinstance(entry[1], (list, tuple)) else entry[1]
                if isinstance(raw, bytes) and len(raw) == 4:
                    return int.from_bytes(raw, "big", signed=True)
    return None


def local_index(insn, op_lo: int, op_hi: int, wide_op: int) -> int | None:
    """Index of an `xload_n` / `xload n` instruction, or None."""
    op = insn.op
    if op_lo <= op <= op_hi:
        return op - op_lo
    if op == wide_op and insn.arg is not None:
        return insn.arg
    return None


def _iload(insn):
    return local_index(insn, 0x1A, 0x1D, 0x15)


def _aload(insn):
    return local_index(insn, 0x2A, 0x2D, 0x19)


def _const_insn(pc: int, value: int):
    """Smallest instruction that pushes `value` (int range only)."""
    if -1 <= value <= 5:
        return BC.Insn(pc=pc, op=0x03 + value, length=1)
    if -128 <= value <= 127:
        return BC.Insn(pc=pc, op=0x10, arg=value & 0xFF, length=2)
    if -32768 <= value <= 32767:
        return BC.Insn(pc=pc, op=0x11, arg=value & 0xFFFF, length=3)
    raise FrameError(f"{value} needs a constant pool entry")


def _goto(pc: int, target: int):
    """A jump to `target`, wide when the original distance would not fit s16.

    Deletion only ever removes bytes, so a distance measured in the input
    coordinate system is an upper bound for the output one.
    """
    rel = target - pc
    if -32768 <= rel <= 32767:
        return BC.Insn(pc=pc, op=OP_GOTO, arg=rel, length=3)
    return BC.Insn(pc=pc, op=OP_GOTO_W, arg=rel, length=5)


# --------------------------------------------------------------------------
# the passes
# --------------------------------------------------------------------------

def _refused(fn, *args) -> bool:
    """True when the edit was refused (a branch still needs the instruction).

    A refusal is a fact about this candidate, not about the method: the caller
    moves on to the next one. Letting it escape would abandon a whole method
    because one of a hundred predicates happened to be a branch target.
    """
    try:
        fn(*args)
    except FrameError:
        return True
    return False


def _iter_rounds(prog, apply):
    """Run `apply` to a fixpoint, re-decoding after every successful edit.

    Positions are identity keys during a round, so a pass must not look at
    instruction identity after it edited something — it restarts instead.
    """
    total = 0
    for _ in range(MAX_ROUNDS):
        if not apply(prog):
            return total
        total += 1
    return total


def fold_constants(prog, cf=None) -> int:
    """[const a][const b][iadd] -> [const a+b]."""
    def one(p) -> bool:
        insns = p.insns
        for i in range(len(insns) - 2):
            a, b, op = insns[i], insns[i + 1], insns[i + 2]
            calc = _INT_BIN.get(op.op)
            if calc is None:
                continue
            v1, v2 = int_const(a, cf), int_const(b, cf)
            if v1 is None or v2 is None:
                continue
            raw = calc(v1, v2) & 0xFFFFFFFF
            value = raw if raw < 0x80000000 else raw - 0x100000000
            if not -32768 <= value <= 32767:
                continue
            folded = _const_insn(op.pc, value)
            if _refused(p.remove, {a.pc, b.pc}):
                continue
            p.replace(op.pc, [folded])
            return True
        return False
    return _iter_rounds(prog, one)


def _replace_pair(p, first, branch, target: int, taken: bool) -> bool:
    """Shared tail of every predicate rule: jump, or fall through."""
    if not taken:
        return not _refused(p.remove, {i.pc for i in first} | {branch.pc})
    if _refused(p.remove, {i.pc for i in first}):
        return False
    p.replace(branch.pc, [_goto(branch.pc, target)])
    return True


def prune_predicates(prog, cf=None) -> int:
    """Constant and identity predicates guarding a branch that never varies."""
    def one(p) -> bool:
        insns = p.insns
        n = len(insns)

        # [const v][ifeq..ifle]
        for i in range(n - 1):
            a, br = insns[i], insns[i + 1]
            test = _IF_UNARY.get(br.op)
            if test is None or br.arg is None:
                continue
            v = int_const(a, cf)
            if v is None:
                continue
            if _replace_pair(p, [a], br, br.pc + br.arg, test(v)):
                return True

        # [const a][const b][if_icmp*]
        for i in range(n - 2):
            a, b, br = insns[i], insns[i + 1], insns[i + 2]
            test = _IF_ICMP.get(br.op)
            if test is None or br.arg is None:
                continue
            v1, v2 = int_const(a, cf), int_const(b, cf)
            if v1 is None or v2 is None:
                continue
            if _replace_pair(p, [a, b], br, br.pc + br.arg, test(v1, v2)):
                return True

        # [iload x][iload x][if_icmp*]
        for i in range(n - 2):
            a, b, br = insns[i], insns[i + 1], insns[i + 2]
            test = _IF_ICMP.get(br.op)
            if test is None or br.arg is None:
                continue
            x1, x2 = _iload(a), _iload(b)
            if x1 is None or x1 != x2:
                continue
            if _replace_pair(p, [a, b], br, br.pc + br.arg, br.op in _IF_ICMP_SELF):
                return True

        # [aload x][aload x][if_acmp*]
        for i in range(n - 2):
            a, b, br = insns[i], insns[i + 1], insns[i + 2]
            if br.op not in (0xA5, 0xA6) or br.arg is None:
                continue
            x1, x2 = _aload(a), _aload(b)
            if x1 is None or x1 != x2:
                continue
            if _replace_pair(p, [a, b], br, br.pc + br.arg, br.op == 0xA5):
                return True

        # [aconst_null][ifnull / ifnonnull]
        for i in range(n - 1):
            a, br = insns[i], insns[i + 1]
            if a.op != 0x01 or br.op not in (0xC6, 0xC7) or br.arg is None:
                continue
            if _replace_pair(p, [a], br, br.pc + br.arg, br.op == 0xC6):
                return True

        return False
    return _iter_rounds(prog, one)


def drop_redundant_goto(prog) -> int:
    """[goto L] where L is the next surviving instruction."""
    def one(p) -> bool:
        insns = p.insns
        for i, ins in enumerate(insns[:-1]):
            if ins.op not in (OP_GOTO, OP_GOTO_W) or ins.arg is None:
                continue
            if ins.pc + ins.arg == insns[i + 1].pc:
                if not _refused(p.remove, {ins.pc}):
                    return True
                continue
        return False
    return _iter_rounds(prog, one)


def reachable_pcs(insns, handlers, code_len: int = 0) -> set[int]:
    """Every instruction the verifier would reach: entry, branches, handlers.

    Adjacency is by *list order*, not by `pc + length`: once an instruction has
    been deleted the old pcs no longer tile the array, and arithmetic on them
    silently reports the rest of the method as unreachable.
    """
    index = {ins.pc: i for i, ins in enumerate(insns)}
    if not insns:
        return set()
    seen: set[int] = set()
    # entry is the first surviving instruction, which is not pc 0 any more
    # once an earlier one has been deleted
    work = [insns[0].pc] + [h.handler_pc for h in handlers]
    while work:
        pc = work.pop()
        while pc in index and pc not in seen:
            seen.add(pc)
            i = index[pc]
            ins = insns[i]
            if ins.is_branch or ins.targets:
                work.extend(ins.jump_targets())
            # `Insn.is_terminator` covers return/athrow/ret only. A goto and a
            # switch also have no fall-through, and treating them as if they did
            # keeps a whole dead region alive — measured: it left a `goto` after
            # a `goto` in place, and HotSpot demands a frame for that block
            # start, which no analysis can produce for dead code.
            if (ins.is_terminator or ins.is_goto
                    or ins.op in (0xAA, 0xAB) or i + 1 >= len(insns)):
                break
            pc = insns[i + 1].pc
    return seen


def thread_jumps(prog) -> int:
    """[goto A] where A is itself [goto B] -> [goto B].

    Only jumps are bypassed, and a jump never changes the operand stack, so the
    destination's frame still applies. Cycles are left alone.
    """
    by_pc = {ins.pc: ins for ins in prog.insns}
    changed = 0
    for ins in prog.insns:
        if ins.op not in (OP_GOTO, OP_GOTO_W) or ins.arg is None:
            continue
        target = ins.pc + ins.arg
        seen = {ins.pc, target}
        for _ in range(8):
            nxt = by_pc.get(target)
            if nxt is None or nxt.op not in (OP_GOTO, OP_GOTO_W) or nxt.arg is None:
                break
            hop = nxt.pc + nxt.arg
            if hop in seen:
                break
            seen.add(hop)
            target = hop
        if target == ins.pc + ins.arg:
            continue
        ins.arg = target - ins.pc
        if ins.op == OP_GOTO and not -32768 <= ins.arg <= 32767:
            ins.op, ins.length = OP_GOTO_W, 5
        changed += 1
    return changed


def _istore(insn):
    return local_index(insn, 0x3B, 0x3E, 0x36)


def _case_map(switch) -> dict:
    """key -> target for a decoded tableswitch / lookupswitch."""
    if switch.op == 0xAA:                       # tableswitch
        low = switch.switch_low
        if low is None:
            return {}
        return {low + i: t for i, t in enumerate(switch.targets[1:])}
    return {k: t for k, t in zip(switch.switch_keys, switch.targets[1:])}


def _retarget(insn, target: int) -> None:
    insn.arg = target - insn.pc
    if insn.op == OP_GOTO and not -32768 <= insn.arg <= 32767:
        insn.op, insn.length = OP_GOTO_W, 5
    elif insn.op == OP_GOTO_W:
        insn.length = 5


def unflatten_dispatchers(prog, cf=None) -> int:
    """Retarget `[const s][istore state][goto top]` straight at the case body.

    This is the pass that actually does something on an obfuscated jar: the
    switch near the top is a state machine, and every transition can jump
    directly to the block that handles the state it just stored. Once they all
    do, the dispatcher has no predecessors and `drop_dead_code` deletes it —
    which is the whole point, and something the NOP-filling version could only
    approximate.
    """
    total = 0
    for _ in range(8):
        found = 0
        insns = prog.insns
        for idx, sw in enumerate(insns):
            if sw.op not in (0xAA, 0xAB) or len(sw.targets) < 3:
                continue
            cases = _case_map(sw)
            if len(cases) < 3:
                continue
            dispatcher = sw.pc
            state_var = -1
            if idx > 0:
                v = _iload(insns[idx - 1])
                if v is not None:
                    state_var = v
                    dispatcher = insns[idx - 1].pc
            for i in range(len(insns) - 2):
                c, st, jump = insns[i], insns[i + 1], insns[i + 2]
                if jump.op not in (OP_GOTO, OP_GOTO_W) or jump.arg is None:
                    continue
                dest = jump.pc + jump.arg
                if dest != dispatcher and dest != sw.pc:
                    continue
                slot = _istore(st)
                if slot is None:
                    continue
                if state_var != -1 and slot != state_var:
                    continue
                value = int_const(c, cf)
                if value is None:
                    continue
                target = cases.get(value)
                if target is None or target == dest:
                    continue
                _retarget(jump, target)
                found += 1
        total += found
        if not found:
            break
    return total


def drop_dead_code(prog, code_len: int = 0, handlers=None) -> int:
    """Remove instructions nothing can reach, then handlers with no live range.

    A block that touches an exception-table boundary is kept whole: shortening
    a protected range would need the table rewritten, and a half-shrunk range is
    worse than an unreachable instruction.
    """
    if not prog.insns:
        return 0
    live = reachable_pcs(prog.insns, prog.handlers)
    pcs = sorted(i.pc for i in prog.insns)
    kept = []
    for h in prog.handlers:
        if h.handler_pc not in pcs:
            continue
        # any live instruction inside [start, end) keeps the handler alive
        lo = bisect.bisect_left(pcs, h.start_pc)
        hi = bisect.bisect_left(pcs, h.end_pc)
        if any(pcs[k] in live for k in range(lo, hi)):
            kept.append(h)
    if len(kept) != len(prog.handlers):
        prog.handlers = kept
        live = reachable_pcs(prog.insns, kept)

    # `end_pc` is exclusive, so the instruction sitting on it is not protected:
    # deleting it only shortens a range over code that never ran. `start_pc` and
    # `handler_pc` are entries — those stay.
    fenced: set[int] = set()
    for h in prog.handlers:
        fenced.update((h.start_pc, h.handler_pc))
    doomed = set()
    for ins in prog.insns:
        if ins.pc in live or ins.pc in fenced:
            continue
        if set(range(ins.pc, ins.pc + ins.length)) & fenced:
            continue
        doomed.add(ins.pc)
    if not doomed:
        return 0
    try:
        prog.remove(doomed)
    except FrameError:
        return 0
    return 1


def optimize(prog, cf=None) -> dict:
    """Run the whole pipeline. Returns per-pass rewrite counts."""
    counts = {"unflattened": 0, "folded": 0, "predicates": 0, "gotos": 0,
              "threaded": 0, "dead": 0}
    for _ in range(8):                    # passes feed each other
        before = sum(counts.values())
        counts["unflattened"] += unflatten_dispatchers(prog, cf)
        counts["folded"] += fold_constants(prog, cf)
        counts["predicates"] += prune_predicates(prog, cf)
        counts["gotos"] += drop_redundant_goto(prog)
        counts["threaded"] += thread_jumps(prog)
        counts["dead"] += drop_dead_code(prog)
        if sum(counts.values()) == before:
            break
    counts["total"] = sum(counts.values())
    return counts


# --------------------------------------------------------------------------
# driver: rewrite one method, or leave it alone
# --------------------------------------------------------------------------

def rewrite_method(cf, member, hier=None) -> int:
    """Optimise one method in place; returns the number of rewrites.

    Raises `FrameError` if the result cannot be shown loadable — the caller
    restores the original `attrs_blob`. Every failure mode ends in "keep the
    original", never in "ship something unverified".
    """
    ci = BC.method_code(cf, member, decode_insns=False)
    if ci is None or not ci.code:
        return 0
    prog = ASM.Program.parse(ci.code, ci.handlers)
    counts = optimize(prog, cf)
    if not counts["total"]:
        return 0

    code, handlers = prog.assemble()
    if len(code) > 0xFFFF:
        raise FrameError(f"rewritten method is {len(code)} bytes")
    if not code:
        raise FrameError("rewrite emptied the method")

    states = AS.compute_frames(cf, member, code, handlers,
                               ci.max_stack, ci.max_locals, hier)
    need = FR.needed_pcs(BC.decode(code), handlers)
    missing = {p for p in need if p not in states}
    if missing:
        raise FrameError(f"no frame for branch target(s) {sorted(missing)[:4]}")

    AT.replace_code(cf, member, code, handlers, ci.max_stack, ci.max_locals)
    AT.remap_debug(cf, member, prog.last_pc_map, len(ci.code), len(code))
    AT.set_code_subattr(cf, member, "StackMapTable",
                        FR.encode(cf, states, need, member, ci.max_locals))
    return counts["total"]
