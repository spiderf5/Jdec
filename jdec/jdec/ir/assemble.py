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


@dataclass
class Program:
    """A method body as a mutable instruction list.

    Instruction `pc` values stay in the *original* coordinate system; they are
    only used as identity keys. Positions in the output come from `assemble()`.
    """

    insns: list = field(default_factory=list)
    handlers: list = field(default_factory=list)
    original_length: int = 0
    #: filled by `assemble()`: original pc -> new pc, for debug-info remapping
    last_pc_map: dict = field(default_factory=dict)

    @classmethod
    def parse(cls, code: bytes, handlers=None) -> "Program":
        insns = BC.decode(code)
        return cls(insns=insns, handlers=list(handlers or []),
                   original_length=len(code))

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
        doomed = {pc for pc in doomed if any(i.pc == pc for i in self.insns)}
        if not doomed:
            return
        for ins in self.insns:
            if ins.pc in doomed:
                continue
            for target in ins.jump_targets():
                if target in doomed:
                    raise FrameError(
                        f"{ins.pc} branches into the deleted range ({target})")
        for h in self.handlers:
            for boundary in (h.start_pc, h.handler_pc):
                if boundary in doomed:
                    raise FrameError(
                        f"exception-table boundary {boundary} is inside the "
                        f"deleted range")
        self.insns = [i for i in self.insns if i.pc not in doomed]

    def replace(self, pc: int, new_insns: list) -> None:
        """Replace one instruction with a sequence (may be empty or longer)."""
        i = self.index_of(pc)
        if not new_insns:
            self.delete(pc, pc + self.insns[i].length)
            return
        for ins in new_insns:
            ins.pc = pc
        self.insns[i:i + 1] = new_insns

    def insert_after(self, pc: int, new_insns: list) -> None:
        """Insert instructions; they get synthetic identity pcs."""
        i = self.index_of(pc)
        base = max((x.pc for x in self.insns), default=0) + 1
        for k, ins in enumerate(new_insns):
            ins.pc = base + k
        self.insns[i + 1:i + 1] = new_insns

    # ---- reassembly -------------------------------------------------
    def assemble(self) -> tuple[bytes, list]:
        """Re-lay out, re-encode, and remap the exception table.

        The returned frames (if any were in the input) are stale by definition:
        offsets moved. Recompute them before writing the method back.
        """
        if not self.insns:
            raise FrameError("cannot assemble an empty method")
        positions, _sizes = BC.layout(self.insns)
        pc_map = {ins.pc: pos for ins, pos in zip(self.insns, positions)}
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
