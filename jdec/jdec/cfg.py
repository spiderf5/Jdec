"""Control Flow Graph (CFG) analysis, basic block partitioning, and instruction reassembly.

Provides:
- BasicBlock: nodes representing linear instruction sequences with single entry and exit;
- CFG: directed graph of basic blocks with predecessor/successor edges and exception handlers;
- build_cfg: constructs CFG from raw bytecode and exception tables;
- compute_reachability: traverses CFG from entry to find reachable blocks;
- prune_unreachable: strips unreachable blocks and invalid exception handlers from CFG;
- assemble_cfg: reassembles CFG into linear bytecode, breaking equal-length NOP constraints,
  automatically widening 16-bit branches (goto -> goto_w, inverted conditionals + goto_w)
  to support far jumps exceeding 32KB, and updating exception tables;
- rebuild_stack_map_table: reconstructs a valid StackMapTable attribute for code targets.
"""

from __future__ import annotations

import collections
import struct
from dataclasses import dataclass, field

from . import bytecode as BC
from . import classfile as CF
from .bytecode import (
    OP_GOTO, OP_GOTO_W, OP_TABLESWITCH, OP_LOOKUPSWITCH,
    Insn, Handler
)

# Branch condition inversion mapping for far conditional jumps
_INVERT_BRANCH = {
    0x99: 0x9A, 0x9A: 0x99,  # ifeq <-> ifne
    0x9B: 0x9C, 0x9C: 0x9B,  # iflt <-> ifge
    0x9D: 0x9E, 0x9E: 0x9D,  # ifgt <-> ifle
    0x9F: 0xA0, 0xA0: 0x9F,  # if_icmpeq <-> if_icmpne
    0xA1: 0xA2, 0xA2: 0xA1,  # if_icmplt <-> if_icmpge
    0xA3: 0xA4, 0xA4: 0xA3,  # if_icmpgt <-> if_icmple
    0xA5: 0xA6, 0xA6: 0xA5,  # if_acmpeq <-> if_acmpne
    0xC6: 0xC7, 0xC7: 0xC6,  # ifnull <-> ifnonnull
}


@dataclass
class BasicBlock:
    id: int
    start_pc: int
    end_pc: int
    insns: list[Insn] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)
    is_handler_target: bool = False

    @property
    def is_empty(self) -> bool:
        return len(self.insns) == 0

    @property
    def terminator(self) -> Insn | None:
        return self.insns[-1] if self.insns else None


@dataclass
class CFG:
    blocks: dict[int, BasicBlock] = field(default_factory=dict)
    entry_id: int = 0
    handlers: list[Handler] = field(default_factory=list)
    orig_code: bytes = b""

    def get_block(self, block_id: int) -> BasicBlock | None:
        return self.blocks.get(block_id)


def build_cfg(code: bytes, handlers: list[Handler] | None = None) -> CFG:
    """Construct a Control Flow Graph from bytecode and optional exception handlers."""
    handlers = list(handlers or [])
    try:
        insns = BC.decode(code)
    except Exception:
        return CFG(orig_code=code, handlers=handlers)

    if not insns:
        return CFG(orig_code=code, handlers=handlers)

    pc_to_insn = {i.pc: i for i in insns}

    # Identify leader PCs
    leaders: set[int] = {0}
    for insn in insns:
        for t in insn.jump_targets():
            if t in pc_to_insn or t == len(code):
                leaders.add(t)
        if insn.is_branch or insn.is_goto or insn.is_terminator or insn.op in (OP_TABLESWITCH, OP_LOOKUPSWITCH):
            next_pc = insn.pc + insn.length
            if next_pc in pc_to_insn or next_pc == len(code):
                leaders.add(next_pc)

    for h in handlers:
        if h.handler_pc in pc_to_insn:
            leaders.add(h.handler_pc)
        if h.start_pc in pc_to_insn:
            leaders.add(h.start_pc)
        if h.end_pc in pc_to_insn:
            leaders.add(h.end_pc)

    sorted_leaders = sorted(l for l in leaders if l < len(code))
    leader_set = set(sorted_leaders)

    blocks: dict[int, BasicBlock] = {}
    current_block: BasicBlock | None = None
    block_id_counter = 0
    pc_to_block_id: dict[int, int] = {}

    for insn in insns:
        if insn.pc in leader_set or current_block is None:
            bid = block_id_counter
            block_id_counter += 1
            current_block = BasicBlock(id=bid, start_pc=insn.pc, end_pc=insn.pc + insn.length)
            blocks[bid] = current_block

        current_block.insns.append(insn)
        current_block.end_pc = insn.pc + insn.length
        pc_to_block_id[insn.pc] = current_block.id

    handler_target_pcs = {h.handler_pc for h in handlers}
    for bid, block in blocks.items():
        if block.start_pc in handler_target_pcs:
            block.is_handler_target = True

    # Connect edges
    for bid, block in blocks.items():
        if not block.insns:
            continue
        term = block.insns[-1]

        if term.is_goto:
            for t in term.jump_targets():
                tgt_bid = pc_to_block_id.get(t)
                if tgt_bid is not None and tgt_bid not in block.successors:
                    block.successors.append(tgt_bid)
        elif term.is_branch:
            for t in term.jump_targets():
                tgt_bid = pc_to_block_id.get(t)
                if tgt_bid is not None and tgt_bid not in block.successors:
                    block.successors.append(tgt_bid)
            next_pc = term.pc + term.length
            tgt_bid = pc_to_block_id.get(next_pc)
            if tgt_bid is not None and tgt_bid not in block.successors:
                block.successors.append(tgt_bid)
        elif term.op in (OP_TABLESWITCH, OP_LOOKUPSWITCH):
            for t in term.jump_targets():
                tgt_bid = pc_to_block_id.get(t)
                if tgt_bid is not None and tgt_bid not in block.successors:
                    block.successors.append(tgt_bid)
        elif not term.is_terminator:
            next_pc = term.pc + term.length
            tgt_bid = pc_to_block_id.get(next_pc)
            if tgt_bid is not None and tgt_bid not in block.successors:
                block.successors.append(tgt_bid)

        for h in handlers:
            if h.start_pc <= block.start_pc < h.end_pc:
                h_bid = pc_to_block_id.get(h.handler_pc)
                if h_bid is not None and h_bid not in block.successors:
                    block.successors.append(h_bid)

    for bid, block in blocks.items():
        for succ_bid in block.successors:
            if succ_bid in blocks and bid not in blocks[succ_bid].predecessors:
                blocks[succ_bid].predecessors.append(bid)

    return CFG(blocks=blocks, entry_id=0, handlers=handlers, orig_code=code)


def compute_reachability(cfg: CFG) -> tuple[set[int], set[int]]:
    """Compute reachable block IDs and instruction PCs from method entry."""
    if not cfg.blocks:
        return set(), set()

    reachable_blocks: set[int] = set()
    queue = collections.deque([cfg.entry_id])
    reachable_blocks.add(cfg.entry_id)

    covered_handlers_active: set[int] = set()

    def check_handlers_for_block(blk: BasicBlock) -> None:
        for hi, h in enumerate(cfg.handlers):
            if hi not in covered_handlers_active and (h.start_pc <= blk.start_pc < h.end_pc):
                covered_handlers_active.add(hi)
                for obid, oblk in cfg.blocks.items():
                    if oblk.start_pc == h.handler_pc and obid not in reachable_blocks:
                        reachable_blocks.add(obid)
                        queue.append(obid)

    if cfg.entry_id in cfg.blocks:
        check_handlers_for_block(cfg.blocks[cfg.entry_id])

    while queue:
        bid = queue.popleft()
        blk = cfg.blocks.get(bid)
        if not blk:
            continue
        check_handlers_for_block(blk)
        for succ_id in blk.successors:
            if succ_id in cfg.blocks and succ_id not in reachable_blocks:
                reachable_blocks.add(succ_id)
                queue.append(succ_id)

    reachable_pcs: set[int] = set()
    for bid in reachable_blocks:
        blk = cfg.blocks[bid]
        for insn in blk.insns:
            for p in range(insn.pc, insn.pc + insn.length):
                reachable_pcs.add(p)

    return reachable_blocks, reachable_pcs


def prune_unreachable(cfg: CFG) -> int:
    """Prune unreachable blocks from CFG and clean dead exception handlers."""
    reachable_blocks, _ = compute_reachability(cfg)
    dead_bids = [bid for bid in cfg.blocks if bid not in reachable_blocks]
    for bid in dead_bids:
        del cfg.blocks[bid]

    for blk in cfg.blocks.values():
        blk.successors = [s for s in blk.successors if s in cfg.blocks]
        blk.predecessors = [p for p in blk.predecessors if p in cfg.blocks]

    valid_handlers = []
    for h in cfg.handlers:
        any_covered = any(blk.start_pc >= h.start_pc and blk.end_pc <= h.end_pc for blk in cfg.blocks.values())
        handler_alive = any(blk.start_pc == h.handler_pc for blk in cfg.blocks.values())
        if any_covered and handler_alive:
            valid_handlers.append(h)
    cfg.handlers = valid_handlers
    return len(dead_bids)


def assemble_cfg(cfg: CFG, allow_widening: bool = True) -> tuple[bytes, list[Handler], dict[str, int]]:
    """Assemble CFG into linear bytecode with branch widening and relaxation.

    Supports:
    - Relaxation loop for relative branch offsets;
    - Automatic widening of 16-bit branches (goto -> goto_w, inverted if + goto_w)
      for far jumps exceeding 32KB;
    - Dynamic re-alignment of tableswitch and lookupswitch 4-byte padding;
    - Accurate re-mapping of exception handler ranges.
    """
    stats = {"widened_goto": 0, "widened_if": 0, "blocks": len(cfg.blocks)}
    if not cfg.blocks:
        return cfg.orig_code, cfg.handlers, stats

    sorted_bids = sorted(cfg.blocks.keys(), key=lambda b: cfg.blocks[b].start_pc)
    orig_code = cfg.orig_code

    # Build initial instruction representation per block
    orig_pc_to_bid: dict[int, int] = {}
    for bid, blk in cfg.blocks.items():
        orig_pc_to_bid[blk.start_pc] = bid

    # Relaxation state
    insn_states: dict[tuple[int, int], dict[str, Any]] = {}
    for bid in sorted_bids:
        blk = cfg.blocks[bid]
        for ii, insn in enumerate(blk.insns):
            insn_states[(bid, ii)] = {
                "insn": insn,
                "op": insn.op,
                "length": insn.length,
                "widened": False,
                "inv_op": None,
            }

    # Iterative relaxation loop
    for _pass in range(10):
        changed = False
        cur_pc = 0
        block_new_starts: dict[int, int] = {}

        for bid in sorted_bids:
            block_new_starts[bid] = cur_pc
            blk = cfg.blocks[bid]
            for ii, insn in enumerate(blk.insns):
                st = insn_states[(bid, ii)]
                st["new_pc"] = cur_pc

                if st["op"] in (OP_TABLESWITCH, OP_LOOKUPSWITCH):
                    pad = (4 - ((cur_pc + 1) % 4)) % 4
                    base = insn.pc + 1 + (4 - ((insn.pc + 1) % 4)) % 4
                    table_payload_len = insn.length - (1 + (4 - ((insn.pc + 1) % 4)) % 4)
                    new_len = 1 + pad + table_payload_len
                    if st["length"] != new_len:
                        st["length"] = new_len
                        changed = True

                cur_pc += st["length"]

        # Check branch spans
        for bid in sorted_bids:
            blk = cfg.blocks[bid]
            for ii, insn in enumerate(blk.insns):
                st = insn_states[(bid, ii)]
                targets = insn.jump_targets()
                if not targets or not (insn.is_branch or insn.is_goto):
                    continue

                tgt_pc = targets[0]
                tgt_bid = orig_pc_to_bid.get(tgt_pc)
                if tgt_bid is None:
                    for b, bblk in cfg.blocks.items():
                        if bblk.start_pc <= tgt_pc <= bblk.end_pc:
                            tgt_bid = b
                            break

                if tgt_bid is not None and tgt_bid in block_new_starts:
                    tgt_new_pc = block_new_starts[tgt_bid]
                else:
                    tgt_new_pc = tgt_pc

                rel = tgt_new_pc - st["new_pc"]

                if (rel < -32768 or rel > 32767) and allow_widening:
                    if st["op"] == OP_GOTO and not st["widened"]:
                        st["op"] = OP_GOTO_W
                        st["length"] = 5
                        st["widened"] = True
                        stats["widened_goto"] += 1
                        changed = True
                    elif st["op"] in _INVERT_BRANCH and not st["widened"]:
                        st["inv_op"] = _INVERT_BRANCH[st["op"]]
                        st["length"] = 8  # 3 bytes inverted if + 5 bytes goto_w
                        st["widened"] = True
                        stats["widened_if"] += 1
                        changed = True

        if not changed:
            break

    # Pre-calculate final block positions once relaxation is settled.
    # This guarantees that forward jumps and switch targets are always known.
    final_block_starts: dict[int, int] = {}
    cur_p = 0
    for bid in sorted_bids:
        final_block_starts[bid] = cur_p
        blk = cfg.blocks[bid]
        for ii, _insn in enumerate(blk.insns):
            cur_p += insn_states[(bid, ii)]["length"]
    final_total_len = cur_p

    def resolve_dest(orig_target_pc: int) -> int:
        if orig_target_pc >= len(orig_code):
            return final_total_len
        tgt_b = orig_pc_to_bid.get(orig_target_pc)
        if tgt_b is not None and tgt_b in final_block_starts:
            return final_block_starts[tgt_b]
        for b, bblk in cfg.blocks.items():
            if bblk.start_pc <= orig_target_pc < bblk.end_pc and b in final_block_starts:
                return final_block_starts[b] + (orig_target_pc - bblk.start_pc)
        return orig_target_pc

    # Assemble bytes
    out_buf = bytearray()

    for bid in sorted_bids:
        blk = cfg.blocks[bid]
        for ii, insn in enumerate(blk.insns):
            st = insn_states[(bid, ii)]
            insn_pc = len(out_buf)

            if st["op"] in (OP_TABLESWITCH, OP_LOOKUPSWITCH):
                pad = (4 - ((insn_pc + 1) % 4)) % 4
                out_buf.append(st["op"])
                out_buf.extend(b"\x00" * pad)
                old_pad = (4 - ((insn.pc + 1) % 4)) % 4
                old_base = insn.pc + 1 + old_pad

                if st["op"] == OP_LOOKUPSWITCH:
                    default_off = struct.unpack_from(">i", orig_code, old_base)[0]
                    dest_pc = resolve_dest(insn.pc + default_off)
                    new_def_off = dest_pc - insn_pc
                    npairs = struct.unpack_from(">i", orig_code, old_base + 4)[0]
                    out_buf.extend(struct.pack(">ii", new_def_off, npairs))
                    for p in range(npairs):
                        m_val, m_off = struct.unpack_from(">ii", orig_code, old_base + 8 + p * 8)
                        case_dest = resolve_dest(insn.pc + m_off)
                        new_off = case_dest - insn_pc
                        out_buf.extend(struct.pack(">ii", m_val, new_off))
                else:  # TABLESWITCH
                    default_off, low, high = struct.unpack_from(">iii", orig_code, old_base)
                    dest_pc = resolve_dest(insn.pc + default_off)
                    new_def_off = dest_pc - insn_pc
                    out_buf.extend(struct.pack(">iii", new_def_off, low, high))
                    count = high - low + 1
                    for idx in range(count):
                        m_off = struct.unpack_from(">i", orig_code, old_base + 12 + idx * 4)[0]
                        case_dest = resolve_dest(insn.pc + m_off)
                        new_off = case_dest - insn_pc
                        out_buf.extend(struct.pack(">i", new_off))

            elif st.get("inv_op") is not None:
                # Far conditional: inverted if +8, goto_w target
                tgt_pc = insn.jump_targets()[0]
                target_dest = resolve_dest(tgt_pc)
                # 1. Inverted if jumping 8 bytes forward (skipping the 5-byte goto_w)
                out_buf.append(st["inv_op"])
                out_buf.extend(struct.pack(">h", 8))
                # 2. goto_w to target
                goto_w_pc = len(out_buf)
                out_buf.append(OP_GOTO_W)
                rel = target_dest - goto_w_pc
                out_buf.extend(struct.pack(">i", rel))

            elif st["op"] == OP_GOTO_W:
                tgt_pc = insn.jump_targets()[0]
                target_dest = resolve_dest(tgt_pc)
                rel = target_dest - insn_pc
                out_buf.append(OP_GOTO_W)
                out_buf.extend(struct.pack(">i", rel))

            elif insn.is_branch or insn.is_goto:
                tgt_pc = insn.jump_targets()[0]
                target_dest = resolve_dest(tgt_pc)
                rel = target_dest - insn_pc
                if (rel < -32768 or rel > 32767) and st["op"] == OP_GOTO:
                    out_buf.append(OP_GOTO_W)
                    out_buf.extend(struct.pack(">i", rel))
                else:
                    out_buf.append(st["op"])
                    out_buf.extend(struct.pack(">h", rel))

            else:
                out_buf.extend(orig_code[insn.pc:insn.pc + insn.length])

    # Re-map exception handlers
    final_handlers: list[Handler] = []
    code_total_len = len(out_buf)
    for h in cfg.handlers:
        new_start = resolve_dest(h.start_pc)
        new_end = code_total_len if h.end_pc >= len(orig_code) else resolve_dest(h.end_pc)
        new_handler = resolve_dest(h.handler_pc)

        if new_start < new_end and new_handler < code_total_len:
            final_handlers.append(Handler(new_start, new_end, new_handler, h.catch_type))

    return bytes(out_buf), final_handlers, stats


def rebuild_stack_map_table(
    cf: CF.ClassFile | None,
    code: bytes,
    branch_targets: set[int] | None = None,
    handlers: list[Handler] | None = None,
) -> bytes:
    """Structurally well-formed frames for branch targets — NOT verifier-proof.

    Every non-handler target is emitted as `same_frame`, which asserts the
    locals are unchanged from the previous frame; a real rewrite (far-jump
    widening, devirtualisation) routinely violates that. A `finally` handler
    (catch_type 0) needs the implicit `java/lang/Throwable` frame, which
    cannot be expressed without adding a constant-pool Class entry.

    A table a JVM actually accepts requires type inference over the rewritten
    body — ROADMAP phase 02 ("类型 IR"), not a side effect of reassembly.
    Until then this helper exists for structural assertions in tests; do not
    ship its output inside a class that must pass `-Xverify`.
    """
    if branch_targets is None:
        try:
            insns = BC.decode(code)
            branch_targets = set()
            for i in insns:
                branch_targets.update(i.jump_targets())
        except Exception:
            branch_targets = set()

    handler_targets: dict[int, int] = {}
    if handlers:
        for h in handlers:
            handler_targets[h.handler_pc] = h.catch_type
            branch_targets.add(h.handler_pc)

    sorted_targets = sorted(t for t in branch_targets if 0 < t < len(code))
    if not sorted_targets:
        return struct.pack(">H", 0)

    frames = bytearray()
    prev_pc = -1
    for target_pc in sorted_targets:
        offset_delta = target_pc if prev_pc == -1 else target_pc - prev_pc - 1
        is_handler = target_pc in handler_targets

        if is_handler:
            catch_type = handler_targets[target_pc]
            # 0 is not a valid cp index: a finally handler's frame needs
            # java/lang/Throwable, which this helper cannot add (see docstring).
            cpool_idx = catch_type if (cf and 0 < catch_type < len(cf.cp)) else 0
            vtype = struct.pack(">BH", 7, cpool_idx)
            if 0 <= offset_delta <= 63:
                frames.append(64 + offset_delta)
                frames.extend(vtype)
            else:
                frames.append(247)  # same_locals_1_stack_item_frame_extended
                frames.extend(struct.pack(">H", max(0, offset_delta)))
                frames.extend(vtype)
        else:
            if 0 <= offset_delta <= 63:
                frames.append(offset_delta)
            else:
                frames.append(251)  # same_frame_extended
                frames.extend(struct.pack(">H", max(0, offset_delta)))
        prev_pc = target_pc

    payload = struct.pack(">H", len(sorted_targets)) + bytes(frames)
    return payload
