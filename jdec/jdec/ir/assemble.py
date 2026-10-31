"""Instruction-level edits that change the code array's length.

`bytecode.encode` can already re-lay out a fixed instruction list; this module
adds the two operations that actually change lengths — delete and insert — plus
the exception-table remapping that has to happen with them.

Why it exists: every rewrite in `deflat` is length-preserving (NOP fill), which
is why the original StackMapTable usually survives. As soon as an instruction is
deleted or added, all offsets move, and frames MUST be recomputed. That is the
point of this layer: `assemble()` hands back a method whose frames are known to
be stale, and the caller is expected to run `assume.compute_frames` +
`frames.encode` before writing it into a class.

Deletion is deliberately strict: if a branch or an exception-table boundary
points into the removed range, `assemble()` raises instead of silently
retargeting. Silently picking a new target is how a deobfuscator changes
behaviour while the JVM still accepts the class.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .. import bytecode as BC
from .types import FrameError


@dataclass(frozen=True)
class Label:
    """A jump target that survives editing.

    Branch offsets are relative and the layout is only known at `assemble()`, so
    hand-computing an `arg` is how you end up pointing one instruction past the
    block you meant to reach. A label is just an id; `mark()` binds it to an
    instruction and the insert helpers turn it into the right offset.
    """

    id: int


@dataclass(frozen=True)
class InsnSnap:
    """An immutable instruction, including switch and `wide` payloads."""

    pc: int
    op: int
    arg: int | None
    arg2: int | None
    length: int
    targets: tuple = ()
    switch_low: int | None = None
    switch_keys: tuple = ()
    pad: bytes = b""
    raw: bytes = b""

    @classmethod
    def of(cls, ins) -> "InsnSnap":
        return cls(ins.pc, ins.op, ins.arg, ins.arg2, ins.length,
                   tuple(ins.targets), ins.switch_low, tuple(ins.switch_keys),
                   ins.pad, ins.raw)


@dataclass(frozen=True)
class Edit:
    """One structural edit. `group` ties a remove+replace into one rule."""

    group: int
    kind: str
    before: tuple[InsnSnap, ...]
    after: tuple[InsnSnap, ...]
    evidence: dict
    handlers_after: tuple = ()


@dataclass
class Program:
    """A method body as a mutable instruction list.

    Instruction `pc` values stay in the *original* coordinate system; they are
    only used as identity keys. Positions in the output come from `assemble()`.
    """

    insns: list = field(default_factory=list)
    handlers: list = field(default_factory=list)
    original_length: int = 0
    #: the exact input, needed because Insn is mutable and a shallow copy is not
    #: a snapshot once thread_jumps/retarget starts changing operands
    original_code: bytes = b""
    original_handlers: list = field(default_factory=list)
    #: chronological edits; ir/reasons.py independently replays these
    journal: list[Edit] = field(default_factory=list)
    #: filled by `assemble()`: original pc -> new pc, for debug-info remapping
    last_pc_map: dict = field(default_factory=dict)
    #: labels; only meaningful until `assemble()` turns them into offsets
    marks: dict = field(default_factory=dict)
    #: next synthetic identity, always above every pc in the input
    _next_id: int = 0
    _reason_seq: int = 0
    _pending_reason: tuple | None = None

    @classmethod
    def parse(cls, code: bytes, handlers=None) -> "Program":
        insns = BC.decode(code)
        return cls(insns=insns, handlers=list(handlers or []),
                   original_length=len(code), original_code=bytes(code),
                   original_handlers=list(handlers or []),
                   _next_id=max((i.pc for i in insns), default=0) + 1)

    # ---- rewrite evidence -------------------------------------------
    def note(self, kind: str, **evidence) -> int:
        """Attach a high-level rule to the following low-level edits.

        A fold is a remove followed by a replace; both edits share one group,
        so the checker can validate the rule as a whole instead of pretending
        the two halves are unrelated rewrites.
        """
        self._reason_seq += 1
        self._pending_reason = (self._reason_seq, kind, dict(evidence))
        return self._reason_seq

    def _take_reason(self, fallback: str) -> tuple[int, str, dict]:
        """Read the pending note without consuming it.

        One rule may issue several low-level edits (a fold removes two
        instructions and replaces a third); they all belong to the same group.
        A *failed* edit drops the note instead, so it cannot leak onto an
        unrelated rewrite.
        """
        if self._pending_reason is None:
            return 0, fallback, {}
        group, kind, evidence = self._pending_reason
        return group, kind, evidence

    def _drop_reason(self) -> None:
        self._pending_reason = None

    def _record(self, reason, before: list, after: list) -> None:
        group, kind, evidence = reason
        self.journal.append(Edit(
            group, kind,
            tuple(InsnSnap.of(i) for i in before),
            tuple(InsnSnap.of(i) for i in after), evidence,
            tuple(self.handlers)))

    # ---- labels -----------------------------------------------------
    def new_label(self) -> "Label":
        return Label(self._next_id + len(self.marks))

    def mark(self, pc: int, label: "Label") -> None:
        """Bind `label` to the instruction at `pc`."""
        if not any(i.pc == pc for i in self.insns):
            raise FrameError(f"cannot mark {pc}: not an instruction boundary")
        self.marks[label.id] = pc

    def _target_pc(self, label: "Label") -> int:
        if label.id not in self.marks:
            raise FrameError(f"label {label.id} was never marked")
        return self.marks[label.id]

    def _fresh(self) -> int:
        value = self._next_id
        self._next_id += 1
        return value

    # ---- edits ------------------------------------------------------
    def index_of(self, pc: int) -> int:
        for i, ins in enumerate(self.insns):
            if ins.pc == pc:
                return i
        raise FrameError(f"{pc} is not an instruction boundary")

    def delete(self, start_pc: int, end_pc: int) -> int:
        """Remove every instruction whose pc is in [start_pc, end_pc)."""
        doomed = {ins.pc for ins in self.insns if start_pc <= ins.pc < end_pc}
        if not doomed:
            return 0
        self.remove(doomed)
        return len(doomed)

    def remove(self, doomed: set) -> None:
        """Remove an explicit set of instruction pcs.

        Checked against the instructions that **survive**: a dead block may
        branch to another dead block, and removing them as one set is exactly
        the case `delete` cannot express.
        """
        reason = self._take_reason("remove")
        doomed = {pc for pc in doomed if any(i.pc == pc for i in self.insns)}
        if not doomed:
            return
        try:
            for ins in self.insns:
                if ins.pc in doomed:
                    continue
                for target in ins.jump_targets():
                    if target in doomed:
                        raise FrameError(
                            f"{ins.pc} branches into the deleted range "
                            f"({target})")
            for h in self.handlers:
                for boundary in (h.start_pc, h.handler_pc):
                    if boundary in doomed:
                        raise FrameError(
                            f"exception-table boundary {boundary} is inside "
                            f"the deleted range")
        except FrameError:
            self._drop_reason()
            raise
        before = [i for i in self.insns if i.pc in doomed]
        self.insns = [i for i in self.insns if i.pc not in doomed]
        self._record(reason, before, [])

    def replace(self, pc: int, new_insns: list) -> None:
        """Replace one instruction with a sequence (may be empty or longer)."""
        reason = self._take_reason("replace")
        i = self.index_of(pc)
        if not new_insns:
            self.delete(pc, pc + self.insns[i].length)
            return
        # The first replacement keeps the original pc (a branch may target it),
        # the rest get fresh identities: sharing one pc made `pc_map` keep only
        # the last of them, so a jump to that position landed *inside* the
        # replacement instead of at its start.
        before = [self.insns[i]]
        for k, ins in enumerate(new_insns):
            ins.pc = pc if k == 0 else self._fresh()
        self.insns[i:i + 1] = new_insns
        self._record(reason, before, new_insns)

    def insert_after(self, pc: int, new_insns: list) -> None:
        """Insert instructions; they get fresh identities."""
        reason = self._take_reason("insert")
        i = self.index_of(pc)
        anchor = [self.insns[i]]
        for ins in new_insns:
            ins.pc = self._fresh()
        self.insns[i + 1:i + 1] = new_insns
        self._record(reason, anchor, new_insns)

    def insert_before(self, pc: int, new_insns: list) -> None:
        reason = self._take_reason("insert")
        i = self.index_of(pc)
        anchor = [self.insns[i]]
        for ins in new_insns:
            ins.pc = self._fresh()
        self.insns[i:i] = new_insns
        self._record(reason, anchor, new_insns)

    def retarget(self, pc: int, new_target: int, *, kind: str,
                 **evidence) -> None:
        """Change a branch target and record the semantic justification."""
        ins = self.insns[self.index_of(pc)]
        before = [InsnSnap.of(ins)]
        ins.arg = new_target - ins.pc
        if ins.op == 0xA7 and not -32768 <= ins.arg <= 32767:
            ins.op, ins.length = 0xC8, 5
        elif ins.op == 0xC8:
            ins.length = 5
        self._record((0, kind, evidence), before, [ins])

    def set_handlers(self, handlers: list, *, kind: str, **evidence) -> None:
        group, name, pending = self._take_reason(kind)
        merged = dict(pending)
        merged.update(evidence)
        self.handlers = list(handlers)
        self._record((group or 0, name or kind, merged), [], [])

    def insert_branch(self, pc: int, op: int, label: "Label", *,
                      before: bool = True):
        """Insert a branch to `label` next to `pc`; returns the new instruction."""
        target = self._target_pc(label)
        ins = BC.Insn(pc=self._fresh(), op=op, arg=0, length=3)
        ins.arg = target - ins.pc          # relative to its own identity
        i = self.index_of(pc)
        self.insns.insert(i if before else i + 1, ins)
        return ins

    # ---- reassembly -------------------------------------------------
    def assemble(self) -> tuple[bytes, list]:
        """Re-lay out, re-encode, and remap the exception table.

        The returned frames (if any were in the input) are stale by definition:
        offsets moved. Recompute them before writing the method back.
        """
        if not self.insns:
            raise FrameError("cannot assemble an empty method")
        positions, _sizes = BC.layout(self.insns)
        # setdefault, not a plain comprehension: if two instructions ever share
        # a pc, the *first* is the one a branch means
        pc_map: dict = {}
        for ins, pos in zip(self.insns, positions):
            pc_map.setdefault(ins.pc, pos)
        self.last_pc_map = pc_map
        code = BC.encode(self.insns, pc_map)

        def remap(pc: int, *, is_end: bool) -> int:
            if pc in pc_map:
                return pc_map[pc]
            if is_end:
                # `end_pc` is exclusive. If the instruction that used to sit
                # there was removed (it is dead code beyond the last live
                # instruction of the range, or the tail of the method), the
                # range still has to end at the same *place* — so round up to
                # the first surviving instruction, not down.
                for ins, pos in zip(self.insns, positions):
                    if ins.pc >= pc:
                        return pos
                return len(code)
            raise FrameError(f"offset {pc} is no longer an instruction boundary")

        handlers = [BC.Handler(remap(h.start_pc, is_end=False),
                               remap(h.end_pc, is_end=True),
                               remap(h.handler_pc, is_end=False),
                               h.catch_type)
                    for h in self.handlers]
        return code, handlers
