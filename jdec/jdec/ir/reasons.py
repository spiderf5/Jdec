"""Independent replay of the rewrite journal.

`ir/transforms.py` edits a method for semantic reasons; this module is the
counterweight. It takes the *original* bytes plus the journal the edits left
behind, replays every edit on a private shadow, re-derives each rule's
precondition from those bytes, and compares the result with what the rewrite
claims it produced.

Two properties make this worth having:

* it never calls the optimizing passes. Reusing `optimize()` to check
  `optimize()` would only prove that the bug is deterministic;
* `unflatten` is checked *more strictly* than the pass itself: the switch
  selector's slot must be explicit, and no branch may land inside the
  `const; istore; goto` triple. Both are real miscompile paths that
  `-Xverify:all` cannot see, because the frames stay self-consistent.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .. import bytecode as BC
from .. import classfile as CF
from . import assemble as ASM
from .types import FrameError

OP_GOTO = 0xA7
OP_GOTO_W = 0xC8
OP_TABLESWITCH = 0xAA
OP_LOOKUPSWITCH = 0xAB

_ICONST = {0x02: -1, 0x03: 0, 0x04: 1, 0x05: 2, 0x06: 3, 0x07: 4, 0x08: 5}
_INT_BIN = {
    0x60: lambda a, b: a + b, 0x64: lambda a, b: a - b,
    0x68: lambda a, b: a * b, 0x7E: lambda a, b: a & b,
    0x80: lambda a, b: a | b, 0x82: lambda a, b: a ^ b,
    0x78: lambda a, b: a << (b & 0x1F), 0x7A: lambda a, b: a >> (b & 0x1F),
    0x7C: lambda a, b: (a & 0xFFFFFFFF) >> (b & 0x1F),
}
_IF_ICMP = {0x9F: lambda a, b: a == b, 0xA0: lambda a, b: a != b,
            0xA1: lambda a, b: a < b, 0xA2: lambda a, b: a >= b,
            0xA3: lambda a, b: a > b, 0xA4: lambda a, b: a <= b}
_IF_UNARY = {0x99: lambda v: v == 0, 0x9A: lambda v: v != 0,
             0x9B: lambda v: v < 0, 0x9C: lambda v: v >= 0,
             0x9D: lambda v: v > 0, 0x9E: lambda v: v <= 0}


@dataclass(frozen=True)
class Violation:
    kind: str
    detail: str
    edit_index: int = -1

    def describe(self) -> str:
        where = "" if self.edit_index < 0 else f" (edit #{self.edit_index})"
        return f"{self.kind}: {self.detail}{where}"


@dataclass
class MethodAudit:
    cls: str
    method: str
    descriptor: str
    before_code: bytes = b""
    after_code: bytes | None = None
    edits: int = 0
    violations: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.violations

    def describe(self) -> str:
        head = f"{self.cls}.{self.method}{self.descriptor}"
        if self.ok:
            return f"{head}: {self.edits} edit(s), justified"
        return f"{head}: " + "; ".join(v.describe() for v in self.violations[:3])


# --- small helpers, deliberately local to this module -----------------------

def _const_value(cf, snap: ASM.InsnSnap):
    op = snap.op
    if op in _ICONST:
        return _ICONST[op]
    if op == 0x10 and snap.arg is not None:
        return snap.arg - 0x100 if snap.arg > 0x7F else snap.arg
    if op == 0x11 and snap.arg is not None:
        return snap.arg - 0x10000 if snap.arg > 0x7FFF else snap.arg
    if cf is not None and op in (0x12, 0x13) and snap.arg is not None:
        idx = snap.arg
        if 0 < idx < len(cf.cp):
            entry = cf.cp[idx]
            if entry and entry[0] == CF.C_INTEGER:
                raw = entry[1][0] if isinstance(entry[1], (list, tuple)) else entry[1]
                if isinstance(raw, bytes) and len(raw) == 4:
                    return int.from_bytes(raw, "big", signed=True)
    return None


def _load_slot(snap: ASM.InsnSnap):
    op = snap.op
    if 0x15 <= op <= 0x19:
        return snap.arg
    if 0x1A <= op <= 0x2D:
        return (op - 0x1A) if op <= 0x1D else (op - 0x1E) if op <= 0x21 else \
               (op - 0x22) if op <= 0x25 else (op - 0x26) if op <= 0x29 else \
               (op - 0x2A)
    return None


def _store_slot(snap: ASM.InsnSnap):
    op = snap.op
    if 0x36 <= op <= 0x3A:
        return snap.arg
    if 0x3B <= op <= 0x4E:
        return (op - 0x3B) % 4
    return None


def _case_map(snap: ASM.InsnSnap) -> dict:
    if snap.op == OP_TABLESWITCH:
        if snap.switch_low is None:
            return {}
        return {snap.switch_low + i: t
                for i, t in enumerate(snap.targets[1:])}
    return {k: t for k, t in zip(snap.switch_keys, snap.targets[1:])}


def _reachable(insns: list[ASM.InsnSnap], handlers) -> set[int]:
    """Reachability from entry plus live handler entries (list-order based)."""
    index = {s.pc: i for i, s in enumerate(insns)}
    if not insns:
        return set()
    seen: set[int] = set()
    work = [insns[0].pc] + [h.handler_pc for h in handlers]
    while work:
        pc = work.pop()
        while pc in index and pc not in seen:
            seen.add(pc)
            i = index[pc]
            snap = insns[i]
            if snap.op in (OP_TABLESWITCH, OP_LOOKUPSWITCH) or (
                    snap.arg is not None and 0x99 <= snap.op <= 0xA8):
                if snap.targets:
                    work.extend(snap.targets)
                elif 0x99 <= snap.op <= 0xA8:
                    work.append(snap.pc + snap.arg)
            terminal = (snap.op in (0xA9, 0xBF) or 0xAC <= snap.op <= 0xB1
                        or snap.op in (OP_GOTO, OP_GOTO_W)
                        or snap.op in (OP_TABLESWITCH, OP_LOOKUPSWITCH))
            if terminal or i + 1 >= len(insns):
                break
            pc = insns[i + 1].pc
    return seen


def _insn_from_snap(snap: ASM.InsnSnap) -> BC.Insn:
    return BC.Insn(pc=snap.pc, op=snap.op, arg=snap.arg, arg2=snap.arg2,
                   length=snap.length, targets=list(snap.targets),
                   switch_low=snap.switch_low, switch_keys=list(snap.switch_keys),
                   pad=snap.pad, raw=snap.raw)


def _handlers_from(snapshots) -> list:
    return [BC.Handler(s.start_pc, s.end_pc, s.handler_pc, s.catch_type)
            for s in snapshots]


def _snap_of(ins) -> ASM.InsnSnap:
    return ASM.InsnSnap.of(ins)


def _by_pc(insns) -> dict[int, ASM.InsnSnap]:
    return {s.pc: s for s in insns}


def _handlers_equal(a, b) -> bool:
    return [(h.start_pc, h.end_pc, h.handler_pc, h.catch_type) for h in a] == \
           [(h.start_pc, h.end_pc, h.handler_pc, h.catch_type) for h in b]


# --- the checker ------------------------------------------------------------

def replay(original_code: bytes, original_handlers, journal,
           expected_code: bytes, expected_handlers, cf=None) -> list[Violation]:
    """Replay `journal` on a private shadow and re-derive every rule."""
    out: list[Violation] = []

    def bad(kind, detail, idx=-1):
        out.append(Violation(kind, detail, idx))

    shadow = ASM.Program.parse(original_code, original_handlers)
    groups: list[list[ASM.Edit]] = []
    for edit in journal:
        if edit.group and groups and groups[-1][0].group == edit.group:
            groups[-1].append(edit)
        else:
            groups.append([edit])

    for gi, group in enumerate(groups):
        start = tuple(_snap_of(i) for i in shadow.insns)
        start_handlers = list(shadow.handlers)
        start_by_pc = _by_pc(start)
        kind = group[0].kind

        # every recorded "before" must exist, byte for byte, before the edit
        for ei, edit in enumerate(group):
            for snap in edit.before:
                current = start_by_pc.get(snap.pc) if ei == 0 else next(
                    (ASM.InsnSnap.of(i) for i in shadow.insns if i.pc == snap.pc),
                    None)
                if current != snap:
                    bad(kind, f"edit {ei}: pc {snap.pc} does not match the "
                              f"recorded before-state", gi)
                    break

        for edit in group:
            pcs = [s.pc for s in edit.before]
            try:
                if kind in ("thread", "unflatten"):
                    shadow.retarget(pcs[0], edit.evidence["target"], kind=kind)
                elif kind == "dead_handlers":
                    shadow.set_handlers(
                        _handlers_from(edit.handlers_after), kind=kind)
                elif edit.after:
                    shadow.replace(pcs[0], [_insn_from_snap(s)
                                            for s in edit.after])
                else:
                    shadow.remove(set(pcs))
            except FrameError as exc:
                bad(kind, f"replay refused the edit: {exc}", gi)

        end = tuple(_snap_of(i) for i in shadow.insns)
        end_by_pc = _by_pc(end)

        # every recorded "after" must now exist exactly
        for edit in group:
            for snap in edit.after:
                if end_by_pc.get(snap.pc) != snap:
                    bad(kind, f"pc {snap.pc} is not the recorded after-state", gi)

        check = _CHECKS.get(kind, _check_structural)
        check(kind, group, start, end, start_handlers, list(shadow.handlers),
              cf, bad, gi)

    # nothing may change without a journal entry, and the product must match
    try:
        code, handlers = shadow.assemble()
    except FrameError as exc:
        out.append(Violation("assemble", str(exc)))
        return out
    if code != expected_code:
        out.append(Violation("assemble", "replayed bytes differ from the "
                                           "produced method"))
    elif not _handlers_equal(handlers, expected_handlers):
        out.append(Violation("assemble", "replayed exception table differs"))
    return out


def _check_structural(kind, group, start, end, sh, eh, cf, bad, gi):
    """Edits with no extra rule: the byte-level replay above is the check."""


def _check_fold(kind, group, start, end, sh, eh, cf, bad, gi):
    before = [s for e in group for s in e.before]
    if len(before) != 3:
        bad(kind, "fold must touch exactly three instructions", gi)
        return
    a, b, op = before
    ev = group[0].evidence
    v1, v2 = _const_value(cf, a), _const_value(cf, b)
    calc = _INT_BIN.get(op.op)
    if v1 is None or v2 is None or calc is None:
        bad(kind, "folded window is not two int constants and a binop", gi)
        return
    raw = calc(v1, v2) & 0xFFFFFFFF
    value = raw if raw < 0x80000000 else raw - 0x100000000
    if value != ev.get("result"):
        bad(kind, "recorded result does not match the JVM int semantics", gi)
    produced = end_by_pc_safe(end, op.pc)
    if produced is None or _const_value(cf, produced) != value:
        bad(kind, "replacement is not the folded constant", gi)


def end_by_pc_safe(end, pc):
    return _by_pc(end).get(pc)


def _check_predicate(kind, group, start, end, sh, eh, cf, bad, gi):
    before = [s for e in group for s in e.before]
    branch = before[-1]
    taken = bool(group[0].evidence.get("taken"))
    target = group[0].evidence.get("target")
    decided = None
    if branch.op in _IF_UNARY and len(before) == 2:
        v = _const_value(cf, before[0])
        decided = None if v is None else _IF_UNARY[branch.op](v)
    elif branch.op in _IF_ICMP and len(before) == 3:
        v1, v2 = _const_value(cf, before[0]), _const_value(cf, before[1])
        decided = None if None in (v1, v2) else _IF_ICMP[branch.op](v1, v2)
    elif branch.op in _IF_ICMP and len(before) == 2:
        x1, x2 = _load_slot(before[0]), _load_slot(before[1])
        if x1 is not None and x1 == x2:
            decided = branch.op in (0x9F, 0xA2, 0xA4)
    elif branch.op in (0xC6, 0xC7) and len(before) == 2 \
            and before[0].op == 0x01:
        decided = branch.op == 0xC6
    elif branch.op in (0xA5, 0xA6) and len(before) == 2:
        x1, x2 = _load_slot(before[0]), _load_slot(before[1])
        if x1 is not None and x1 == x2:
            decided = branch.op == 0xA5
    if decided is None:
        bad(kind, "predicate shape is not a constant or same-local test", gi)
        return
    if decided != taken:
        bad(kind, "recorded branch direction contradicts the predicate", gi)
        return
    produced = end_by_pc_safe(end, branch.pc)
    if taken:
        if produced is None or produced.op not in (OP_GOTO, OP_GOTO_W) \
                or produced.pc + produced.arg != target:
            bad(kind, "taken predicate must keep a goto to the same target", gi)
    elif produced is not None:
        bad(kind, "not-taken predicate must remove the branch", gi)


def _check_goto(kind, group, start, end, sh, eh, cf, bad, gi):
    snap = group[0].before[0]
    start_by_pc = _by_pc(start)
    idx = next((i for i, s in enumerate(start) if s.pc == snap.pc), None)
    if idx is None or idx + 1 >= len(start):
        bad(kind, "redundant goto has no following instruction", gi)
        return
    if snap.pc + (snap.arg or 0) != start[idx + 1].pc:
        bad(kind, "goto target is not the next instruction", gi)
        return
    incoming = [s.pc for s in start
                if s.pc != snap.pc and snap.pc in _branch_targets(s)]
    if incoming:
        bad(kind, f"goto is still a branch target of {incoming[:3]}", gi)
    if end_by_pc_safe(end, snap.pc) is not None:
        bad(kind, "redundant goto survived the edit", gi)


def _branch_targets(snap: ASM.InsnSnap) -> set[int]:
    if snap.op in (OP_TABLESWITCH, OP_LOOKUPSWITCH):
        return set(snap.targets)
    if snap.arg is not None and 0x99 <= snap.op <= 0xA8:
        return {snap.pc + snap.arg}
    return set()


def _check_thread(kind, group, start, end, sh, eh, cf, bad, gi):
    ev = group[0].evidence
    start_by_pc = _by_pc(start)
    snap = start_by_pc.get(group[0].before[0].pc)
    if snap is None or snap.op not in (OP_GOTO, OP_GOTO_W):
        bad(kind, "threaded instruction is not a goto", gi)
        return
    chain = list(ev.get("chain") or [])
    if len(set(chain)) != len(chain) or not chain or chain[0] != snap.pc:
        bad(kind, "threading walked a cycle", gi)
        return
    cur = snap.pc + (snap.arg or 0)
    if cur != chain[1]:
        bad(kind, "chain does not start at the goto target", gi)
        return
    for hop in chain[2:]:
        nxt = start_by_pc.get(cur)
        if nxt is None or nxt.op not in (OP_GOTO, OP_GOTO_W):
            bad(kind, f"chain hop {cur} is not an unconditional goto", gi)
            return
        if nxt.pc + nxt.arg != hop:
            bad(kind, "chain does not match the original bytes", gi)
            return
        cur = hop
    if cur != ev.get("target"):
        bad(kind, "final target does not match the goto chain", gi)
    produced = end_by_pc_safe(end, snap.pc)
    if produced is None or produced.pc + (produced.arg or 0) != ev.get("target"):
        bad(kind, "retargeted goto does not reach the recorded target", gi)


def _check_dead(kind, group, start, end, sh, eh, cf, bad, gi):
    ev = group[0].evidence
    doomed = set(ev.get("doomed") or [])
    live = set(ev.get("live") or [])
    start_by_pc = _by_pc(start)
    reachable = _reachable(start, sh)
    for pc in doomed:
        if pc not in start_by_pc:
            bad(kind, f"doomed pc {pc} is not an instruction", gi)
        elif pc in live:
            bad(kind, f"doomed pc {pc} was reachable", gi)
        elif pc in reachable:
            bad(kind, f"replay reaches doomed pc {pc}", gi)
    for pc in doomed:
        if end_by_pc_safe(end, pc) is not None:
            bad(kind, f"doomed pc {pc} survived", gi)


def _check_dead_handlers(kind, group, start, end, sh, eh, cf, bad, gi):
    live = set(group[0].evidence.get("live") or [])
    removed = []
    for h in sh:
        pcs = sorted(s.pc for s in start if h.start_pc <= s.pc < h.end_pc)
        if not any(pcs[k] in live for k in range(len(pcs))):
            removed.append(h)
    if len(removed) != len(sh) - len(eh):
        bad(kind, "handler pruning does not match the live ranges", gi)


def _check_unflatten(kind, group, start, end, sh, eh, cf, bad, gi):
    ev = group[0].evidence
    start_by_pc = _by_pc(start)
    slot = ev.get("state_slot")
    if slot is None or slot < 0:
        bad(kind, "state slot is unknown: the pass guessed", gi)
        return
    sw = start_by_pc.get(ev.get("switch_pc"))
    if sw is None or sw.op not in (OP_TABLESWITCH, OP_LOOKUPSWITCH):
        bad(kind, "switch is missing from the original bytes", gi)
        return
    idx = next((i for i, s in enumerate(start) if s.pc == sw.pc), None)
    if idx is None or idx == 0:
        bad(kind, "switch has no preceding selector load", gi)
        return
    selector = start[idx - 1]
    if _load_slot(selector) != slot:
        bad(kind, f"switch reads slot {_load_slot(selector)}, the triple "
                  f"writes {slot}", gi)
        return
    cases = _case_map(sw)
    if len(cases) < 3:
        bad(kind, "switch has fewer than three cases", gi)
        return
    c = start_by_pc.get(ev.get("const_pc"))
    st = start_by_pc.get(ev.get("store_pc"))
    jump = start_by_pc.get(group[0].before[0].pc)
    if c is None or st is None or jump is None:
        bad(kind, "const/istore/goto triple is missing", gi)
        return
    order = sorted([(c.pc, "c"), (st.pc, "st"), (jump.pc, "jump")])
    if [name for _pc, name in order] != ["c", "st", "jump"]:
        bad(kind, "triple is not in const, istore, goto order", gi)
        return
    idx_c = next(i for i, s in enumerate(start) if s.pc == c.pc)
    if [s.pc for s in start[idx_c:idx_c + 3]] != [c.pc, st.pc, jump.pc]:
        bad(kind, "triple is not three adjacent instructions", gi)
        return
    if _store_slot(st) != slot:
        bad(kind, "istore writes a different slot than the switch reads", gi)
        return
    value = _const_value(cf, c)
    if value is None or value != ev.get("value"):
        bad(kind, "stored value is not the recorded constant", gi)
        return
    if cases.get(value) != ev.get("case_target"):
        bad(kind, "case table does not map the stored value to the target", gi)
        return
    for s in start:
        if s.pc in (st.pc, jump.pc):
            continue
        hits = _branch_targets(s) & {st.pc, jump.pc}
        if hits:
            bad(kind, f"pc {s.pc} branches into the state triple at "
                      f"{sorted(hits)}", gi)
            return
    produced = end_by_pc_safe(end, jump.pc)
    if produced is None or produced.pc + (produced.arg or 0) \
            != ev.get("case_target"):
        bad(kind, "retargeted transition does not reach the case", gi)


_CHECKS = {
    "fold": _check_fold,
    "predicate": _check_predicate,
    "goto": _check_goto,
    "thread": _check_thread,
    "dead": _check_dead,
    "dead_handlers": _check_dead_handlers,
    "unflatten": _check_unflatten,
}


# --- entry points -----------------------------------------------------------

def audit_method(cf, member, hier=None) -> MethodAudit:
    """Optimize one method, then replay its journal. Never mutates `member`."""
    from . import transforms as TR          # local: transforms imports nothing here

    ci = BC.method_code(cf, member, decode_insns=False)
    name = cf.utf8(member.name_index)
    desc = cf.utf8(member.descriptor_index)
    audit = MethodAudit(cf.name, name, desc)
    if ci is None or not ci.code:
        return audit
    audit.before_code = bytes(ci.code)
    prog = ASM.Program.parse(ci.code, ci.handlers)
    counts = TR.optimize(prog, cf)
    audit.edits = counts.get("total", 0)
    if not counts.get("total"):
        return audit
    code, handlers = prog.assemble()
    audit.after_code = code
    audit.violations = replay(prog.original_code, prog.original_handlers,
                              prog.journal, code, handlers, cf=cf)
    return audit
