"""bvmw_devirt — BytecodeVM static devirtualizer (bytecode-level).

Pipeline (all from the jar, no decompiler needed):

  1. discover VM sets: classes named `...BytecodeVM$N$CodePool` (+ VM main
     class), or structurally (static [[I fields + unpackStringInts).
  2. extract the per-VM obfuscation profile from bytecode: mixSeed /
     mixRoundA..C / mixMulA..B (CodePool.mix(IIII)I shape), saltArray
     (arrayMix), and the VM-main salts (dispatchKey / layoutValue / stateKey /
     blockValue / resolveConstant / findExceptionHandler), plus the
     layoutSlots[9] physical-column permutation.
  3. unpack the CodePool streams via a symbolic stack walk of codePoolInit$N
     (unpackStringInts char-pair chunks + unpackInts long pairs + CONSTANTS).
  4. decode each protected method: block stream -> stateKey chain ->
     layout columns (pc / original_pc / next_pc / operand start+count /
     constant mask / block index) -> opcodes (two-stage xor + opcode map) ->
     operands -> EncodedConstant payloads -> exception handlers.
  5. lift to JVM-semantics disassembly:
       - REGISTER_OP plans carry the *pre-mutation* Opcs ordinal in operand 0
       - DATA_FLOW_REGION nodes carry it too; node order is rebuilt by
         topological sort over the dependency bitmask (+stackDelta check)
       - POLYMORPHIC/FSM mutated opcodes are calibrated against the original
         jar via LAYOUT_ORIGINAL_PC join (protected/original fixture pair);
         unknown mutated values are reported as opc<N> (UNK).
  6. verify: decoded original_pc sequence vs the original jar's Code
     attribute (pc + normalized opcode names).

Key static fact (source-verified): on the honest path frame.integrityKey ==
0 (expectedCapability ^ integrityCapability == 0), so syncState's xor is a
no-op and the Integrity VM / shards / STATE_WORD are skipped entirely. The
decoder warns if featureFlags or integrity-derived values look unexpected.

`Polymorphic Shard 0..N` classes are dispatch handler shards (SHARD_SIZE=32),
not integrity shards — they never participate in decoding.

Ground truth protocol for the extractor:
  - mix() semantics: fixtures/mix_java.tsv (1048 Java MixProbe vectors)
  - chunk keys / stream shapes: the codePoolInit$N bytecode itself
  - known constants (e.g. set0 methodKey 0xc2f47ad9, flags 0x1f) re-derived
    from the chunks; the legacy bvmw_disasm_set*.txt hex dumps are NOT usable
    as value ground truth (their transform is unidentifiable) — only their
    stream-size table is kept as a sanity reference.
"""

from __future__ import annotations

import itertools
import json
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

try:  # package import (jdec CLI)
    from . import bytecode as bc
    from . import classfile as cfmod
except ImportError:  # standalone
    import bytecode as bc
    import classfile as cfmod

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF


def _i32(x: int) -> int:
    x &= M32
    return x - 0x1_0000_0000 if x >= 0x8000_0000 else x


def _i64(x: int) -> int:
    x &= M64
    return x - 0x1_0000_0000_0000_0000 if x >= 0x8000_0000_0000_0000 else x


def _ushr(x: int, k: int) -> int:
    return (x & M32) >> k


def _rotl(x: int, k: int) -> int:
    x &= M32
    k &= 31
    return _i32(((x << k) & M32) | (x >> (32 - k))) if k else _i32(x)


# ---------------------------------------------------------------------------
# profile
# ---------------------------------------------------------------------------

@dataclass
class VMProfile:
    mix_seed: int
    mix_round_a: int
    mix_round_b: int
    mix_round_c: int
    mix_mul_a: int
    mix_mul_b: int
    salt_layout: int
    salt_opcode: int
    salt_opcode_map: int
    salt_operand: int
    salt_constant: int
    salt_handler: int
    salt_array: int
    salt_string: int
    salt_state: int
    salt_block: int
    dispatch_salt: int
    layout_slots: list[int]  # logical 0..8 -> physical column

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["layout_slots"] = list(self.layout_slots)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "VMProfile":
        return cls(**d)


def mix(prof: VMProfile, key: int, a: int, b: int, c: int) -> int:
    """CodePool.mix / VMObfProfile.mix — Java int semantics throughout.
    NOTE: python's + binds tighter than >>, and Java's n>>>2 applies only to
    n — explicit grouping is mandatory (0/1048 without it, Java-truth
    calibrated)."""
    x = _i32(key ^ prof.mix_seed)
    x = _i32(x ^ _i32(_i32(_i32(a + prof.mix_round_a) + _i32(x << 6)) + _ushr(x, 2)))
    x = _i32(x ^ _i32(_i32(_i32(b + prof.mix_round_b) + _i32(x << 6)) + _ushr(x, 2)))
    x = _i32(x ^ _i32(_i32(_i32(c + prof.mix_round_c) + _i32(x << 6)) + _ushr(x, 2)))
    x = _i32(x ^ _ushr(x, 16))
    x = _i32(x * prof.mix_mul_a)
    x = _i32(x ^ _ushr(x, 15))
    x = _i32(x * prof.mix_mul_b)
    x = _i32(x ^ _ushr(x, 16))
    return x


def array_mix(prof, key, idx) -> int:
    return mix(prof, key, idx, prof.salt_array, 0)


def unpack_string_ints(prof, chunks: list[str], length: int, key: int) -> list[int]:
    """CodePool.unpackStringInts — char pairs -> int ^ arrayMix(key, i)."""
    flat: list[str] = []
    for s in chunks:
        flat.extend(s)
    out: list[int] = []
    i = 0
    while i + 1 < len(flat) and len(out) < length:
        val = (ord(flat[i]) << 16) | ord(flat[i + 1])
        out.append(_i32(val ^ array_mix(prof, key, len(out))))
        i += 2
    while len(out) < length:
        out.append(0)
    return out[:length]


def unpack_ints(prof, packed: list[int], length: int, key: int) -> list[int]:
    """CodePool.unpackInts([JII)[I — hi/lo halves of each long ^ arrayMix."""
    out: list[int] = []
    p = 0
    while p < len(packed) and len(out) < length:
        word = packed[p] & M64
        out.append(_i32(_i32(word >> 32) ^ array_mix(prof, key, len(out))))
        if len(out) < length:
            out.append(_i32(_i32(word & M32) ^ array_mix(prof, key, len(out))))
        p += 1
    while len(out) < length:
        out.append(0)
    return out[:length]


def layout_mix(prof, key, sk, slot, phys) -> int:
    return mix(prof, key ^ sk, slot, phys, prof.salt_layout)


def state_mix(prof, key, slot) -> int:
    return mix(prof, key, slot, prof.salt_state, 0)


def chained_state_mix(prof, key, prev_sk, slot, block_idx) -> int:
    return mix(prof, key ^ prev_sk, slot, block_idx, prof.salt_state)


def block_mix(prof, key, block_idx, fld) -> int:
    return mix(prof, key, block_idx, fld, prof.salt_block)


def opcode_mix(prof, key, sk, vpc, slot) -> int:
    return mix(prof, key ^ sk, vpc, slot, prof.salt_opcode)


def opcode_map_mix(prof, key, virt) -> int:
    return mix(prof, key, virt, prof.salt_opcode_map, 0)


def operand_mix(prof, key, sk, dopcode, vpc, op_idx, pos) -> int:
    return mix(prof, (key ^ sk) ^ dopcode, vpc, op_idx, prof.salt_operand ^ pos)


def constant_mix(prof, key, sk, dopcode, vpc, op_idx) -> int:
    return mix(prof, (key ^ sk) ^ dopcode, vpc, op_idx, prof.salt_constant)


def constant_state_mix(prof, key, sk, vpc, block_idx, slot, dopcode) -> int:
    path = mix(prof, key ^ sk, vpc, block_idx, prof.salt_constant)
    return mix(prof, path, slot, dopcode, prof.salt_string)


def constant_state_mix_secondary(prof, key, sk, vpc, block_idx, slot, dopcode) -> int:
    path = mix(prof, sk ^ prof.salt_array, key, dopcode, vpc)
    return mix(prof, path, block_idx, slot, prof.salt_opcode_map)


def constant_selector(prof, primary, secondary, nonce_a, nonce_b) -> int:
    return mix(prof, primary ^ nonce_a, secondary, nonce_b, prof.salt_handler)


def constant_selector_secondary(prof, primary, secondary, nonce_a, nonce_b) -> int:
    return mix(prof, secondary ^ nonce_b, primary, nonce_a, prof.salt_block)


def constant_stream(prof, primary, secondary, nonce_a, nonce_b, index) -> int:
    left = mix(prof, primary ^ nonce_a, secondary, index, prof.salt_constant)
    right = mix(prof, secondary ^ nonce_b, primary, index, prof.salt_array)
    return _i32(left ^ _rotl(right, (nonce_a + index) & 31))


def handler_mix(prof, key, handler_slot, fld) -> int:
    return mix(prof, key, handler_slot, fld, prof.salt_handler)


# ---------------------------------------------------------------------------
# class loading + insn helpers
# ---------------------------------------------------------------------------

def load_classes(path: Path) -> dict[str, "cfmod.ClassFile"]:
    """jar / class file / directory -> {internal name: ClassFile}."""
    out: dict[str, cfmod.ClassFile] = {}
    if path.is_dir():
        for p in sorted(path.rglob("*.class")):
            data = p.read_bytes()
            c = cfmod.parse(data)
            out.setdefault(c.name, c)
        return out
    data = path.read_bytes()
    if data[:2] == b"PK":
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if n.endswith(".class"):
                    try:
                        c = cfmod.parse(z.read(n))
                    except cfmod.ClassFormatError:
                        continue
                    out.setdefault(c.name, c)
        return out
    c = cfmod.parse(data)
    out[c.name] = c
    return out


def _member(cf, name: str, desc: str | None = None):
    for m in cf.methods:
        if cf.utf8(m.name_index) == name and \
                (desc is None or cf.utf8(m.descriptor_index) == desc):
            return m
    return None


def _code(cf, member) -> "bc.CodeInfo | None":
    return bc.method_code(cf, member, decode_insns=True)


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
    return None


def _int_pushes(cf, insns: list["bc.Insn"]) -> list[tuple[int, int]]:
    """(insn index, value) for every int-const push, in order."""
    out = []
    for i, ins in enumerate(insns):
        v = _const_int(cf, ins)
        if v is not None:
            out.append((i, v))
    return out


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
# profile extraction (structural, keyed by generated method shapes)
# ---------------------------------------------------------------------------

def _extract_pool_mix(cf) -> tuple[int, int, int, int, int, int]:
    """mixSeed, mixRoundA..C, mixMulA..B from the CodePool mix(IIII)I body."""
    m = _member(cf, "mix", "(IIII)I")
    if m is None:  # structural fallback: the only (IIII)I static
        for cand in cf.methods:
            if cf.utf8(cand.descriptor_index) == "(IIII)I":
                m = cand
                break
    if m is None:
        raise ValueError("CodePool mix(IIII)I not found")
    code = _code(cf, m)
    insns = code.insns
    pushes = _int_pushes(cf, insns)
    if not pushes:
        raise ValueError("mix(): no int constants")
    mix_seed = pushes[0][1]
    # round constants follow the iload of params 1/2/3 (a, b, c)
    rounds: list[int] = []
    for param_op in (0x1B, 0x1C, 0x1D):  # iload_1..iload_3
        for i, ins in enumerate(insns):
            if ins.op == param_op:
                for pi, pv in pushes:
                    if pi > i:
                        rounds.append(pv)
                        break
                break
    if len(rounds) != 3:
        raise ValueError(f"mix(): expected 3 round constants, got {rounds}")
    muls: list[int] = []
    for i, ins in enumerate(insns):
        if ins.op == 0x68:  # imul
            prev = [v for pi, v in pushes if pi < i]
            if prev:
                muls.append(prev[-1])
    if len(muls) < 2:
        raise ValueError("mix(): imul constants not found")
    return mix_seed, rounds[0], rounds[1], rounds[2], muls[0], muls[1]


def _ldc_ints(cf, insns: list["bc.Insn"]) -> list[int]:
    """Only cp-INTEGER pushes (the generated salts are always LDC-sized)."""
    out = []
    for ins in insns:
        if ins.op in (0x12, 0x13):
            e = cf.cp[ins.arg]
            if e and e[0] == cfmod.C_INTEGER:
                out.append(struct.unpack(">i", e[1][0])[0])
    return out


def _extract_pool_salt_array(cf) -> int:
    m = _member(cf, "arrayMix", "(II)I")
    if m is None:
        for cand in cf.methods:
            if cf.utf8(cand.descriptor_index) == "(II)I":
                m = cand
                break
    if m is None:
        raise ValueError("CodePool arrayMix(II)I not found")
    code = _code(cf, m)
    vals = _ldc_ints(cf, code.insns)
    if not vals:
        raise ValueError("arrayMix(): no salt constant")
    return vals[0]


def _extract_main_salts(cf_main) -> dict[str, int]:
    salts: dict[str, int] = {}
    # dispatchKey: mix(dispatchSalt, opcode, saltOpcode, 0)
    m = _member(cf_main, "dispatchKey", "(I)I")
    if m is not None:
        vals = _ldc_ints(cf_main, _code(cf_main, m).insns)
        if len(vals) >= 2:
            salts["dispatch_salt"] = vals[0]
            salts["salt_opcode"] = vals[1]
    # layoutValue: mix(key^sk, slot, phys, saltLayout)
    m = _member(cf_main, "layoutValue")
    if m is not None:
        vals = _ldc_ints(cf_main, _code(cf_main, m).insns)
        if vals:
            salts.setdefault("salt_layout", vals[-1])
    # stateKey: mix(key, slot, saltState, 0)
    m = _member(cf_main, "stateKey")
    if m is not None:
        vals = _ldc_ints(cf_main, _code(cf_main, m).insns)
        if vals:
            salts.setdefault("salt_state", vals[0])
    # blockValue: mix(key, blockIdx, field, saltBlock)
    m = _member(cf_main, "blockValue")
    if m is not None:
        vals = _ldc_ints(cf_main, _code(cf_main, m).insns)
        if vals:
            salts.setdefault("salt_block", vals[0])
    # resolveConstant ldc order: saltConstant, saltString, saltArray,
    # saltOpcodeMap, saltHandler, saltBlock (constantStateMix/Secondary/
    # Selector/SelectorSecondary/Stream bodies, VMObfProfile.java:155-194)
    m = _member(cf_main, "resolveConstant")
    if m is not None:
        vals = _ldc_ints(cf_main, _code(cf_main, m).insns)
        uniq: list[int] = []
        for v in vals:
            if v not in uniq:
                uniq.append(v)
        names = ["salt_constant", "salt_string", "salt_array",
                 "salt_opcode_map", "salt_handler", "salt_block"]
        for n, v in zip(names, uniq):
            salts.setdefault(n, v)
    # findExceptionHandler: handlerMix d-arg = saltHandler
    m = _member(cf_main, "findExceptionHandler")
    if m is not None:
        vals = _ldc_ints(cf_main, _code(cf_main, m).insns)
        if vals:
            salts.setdefault("salt_handler", vals[0])
    # saltOperand has no dedicated accessor: on SELF_MODIFYING layouts the
    # operand decode is inlined into superInstructionChunk$N with the
    # signature shape  ldc saltOperand; iload pos; ixor; invokestatic mix
    # (the only mix call whose 4th argument is an ixor).
    if "salt_operand" not in salts:
        v = _extract_salt_operand(cf_main)
        if v is not None:
            salts["salt_operand"] = v
    return salts


def _extract_salt_operand(cf_main) -> int | None:
    """ldc V; ...ixor...; invokestatic mix(IIII)I within a few slots -> V."""
    for m in cf_main.methods:
        code = _code(cf_main, m)
        if code is None:
            continue
        insns = code.insns
        for i, ins in enumerate(insns):
            if ins.op not in (0x12, 0x13):
                continue
            e = cf_main.cp[ins.arg]
            if not e or e[0] != cfmod.C_INTEGER:
                continue
            v = struct.unpack(">i", e[1][0])[0]
            saw_xor = False
            for j in range(i + 1, min(i + 6, len(insns))):
                if insns[j].op == 0x82:
                    saw_xor = True
                if insns[j].op == 0xB8:
                    if saw_xor:
                        t = _target_desc(cf_main, insns[j])
                        if t and t[1] == "mix":
                            return v
                    break
    return None


def _extract_state_key_column(cf_main) -> int:
    """Physical STATE_KEY column: stateKey() reads layoutStream[slot*9 + K]
    as `bipush 9; imul; <const K>; iadd; iaload`."""
    m = _member(cf_main, "stateKey")
    if m is None:
        raise ValueError("stateKey method not found")
    insns = _code(cf_main, m).insns
    for i, ins in enumerate(insns):
        if ins.op == 0x68 and i >= 1 and insns[i - 1].op == 0x10 \
                and insns[i - 1].arg == 9:  # bipush 9; imul
            for j in range(i + 1, min(i + 4, len(insns))):
                v = _const_int(cf_main, insns[j])
                if v is not None:
                    return v
    raise ValueError("STATE_KEY physical column not found in stateKey()")


def _pushed_const(cf, insn: "bc.Insn") -> int | None:
    """Constant value pushed by iconst/bipush/sipush/ldc, else None."""
    if insn is None:
        return None
    if insn.op == 0x02:                      # iconst_m1
        return -1
    if 0x03 <= insn.op <= 0x08:              # iconst_0..5
        return insn.op - 0x03
    if insn.op in (0x10, 0x11):              # bipush / sipush
        return insn.arg
    return _const_int(cf, insn)


def _extract_layout_anchors(cf_main) -> dict[str, int]:
    """Baked-in layout column constants from the VM main class.

    Verified semantics (jar bytecode, case bodies):
      stateKey()               reads the STATE_KEY column directly
      syncState()              layoutValue(..., K, sk) -> frame.blockIndex
      resolveConstant()        layoutValue(..., K, ...) on the VPC column
      instructionIndexInBlock  matches the dispatch token against the VPC
                               and ORIGINAL_PC columns (two layoutValue
                               calls): dispatch may locate a slot either
                               by its vpc token or by its original pc.
                               The true NEXT column has no layoutValue
                               call site and stays in the searched set.
    """
    anchors: dict[str, int] = {"state_key": _extract_state_key_column(cf_main)}
    lv_hits: dict[str, list[int]] = {}
    for m in cf_main.methods:
        name = cf_main.utf8(m.name_index)
        code = _code(cf_main, m)
        if code is None:
            continue
        insns = code.insns
        for i, ins in enumerate(insns):
            if ins.op != 0xB8:               # invokestatic
                continue
            t = _target_desc(cf_main, ins)
            if not t or t[1] != "layoutValue":
                continue
            # args: prog(aload) idx(iload) K(const) sk(iload/getfield);
            # walk back over the pushes collecting constants
            consts: list[int] = []
            j, steps = i - 1, 0
            while j >= 0 and steps < 6 and len(consts) < 2:
                k = _pushed_const(cf_main, insns[j])
                if k is not None:
                    consts.append(k)
                j -= 1
                steps += 1
            if consts:
                lv_hits.setdefault(name, []).append(consts[0])
    if lv_hits.get("syncState"):
        anchors["block_index"] = lv_hits["syncState"][0]
    if lv_hits.get("resolveConstant"):
        anchors["pc"] = lv_hits["resolveConstant"][0]
    for k in lv_hits.get("instructionIndexInBlock", []):
        if k != anchors.get("pc") and "original_pc" not in anchors:
            anchors["original_pc"] = k
    return anchors


def solve_layout_slots(cf_main, prof: VMProfile, pool: PoolData) -> list[int]:
    """Recover the 9-column physical permutation.

    Four columns are pinned by bytecode anchors (see
    _extract_layout_anchors): state_key, block_index, pc (vpc token) and
    original_pc (instructionIndexInBlock matches the dispatch token
    against both).  The dispatch vpc is an arbitrary int token
    (POLYMORPHIC variants replicate slots), so legacy constraints like
    "pc is a permutation of 0..n" were wrong.  The remaining five
    columns (next_pc / operand_start / operand_count / constant_mask /
    branch_selector) are resolved by a small permutation search with
    structural checks:
      - every NEXT token lands in the VPC domain or -1
      - operand windows [ostart, ostart+ocount) stay inside the stream
      - constant_mask fits under operand_count
    branch_selector is the unconstrained leftover: structurally
    indistinguishable from next_pc only if branch tokens happened to
    fall in the VPC domain; stage 2 calibrates against the original
    jar's Code attribute if ever ambiguous.
    """
    key = pool.single["METHOD_KEYS"][0]
    operand_stream = pool.streams["OPERAND_STREAMS"][0]
    layout = pool.streams["LAYOUT_STREAMS"][0]
    block_stream = pool.streams["BLOCK_STREAMS"][0]
    n_slots = len(pool.streams["OPCODE_STREAMS"][0])
    operand_len = len(operand_stream)

    blocks = []
    for b in range(len(block_stream) // 4):
        row4 = block_stream[b * 4:b * 4 + 4]
        blocks.append([row4[f] if key == 0
                       else _i32(row4[f] ^ block_mix(prof, key, b, f))
                       for f in range(4)])
    span = [-1] * n_slots
    for b, (_bpc, _borig, first, count) in enumerate(blocks):
        if first < 0 or count <= 0 or first + count > n_slots:
            raise ValueError(f"block {b} span out of range: {blocks[b]}")
        for s in range(first, first + count):
            span[s] = b

    anchors = _extract_layout_anchors(cf_main)
    k_sk = anchors["state_key"]

    # stateKey chain per slot (uses the STATE_KEY column)
    sks: dict[int, int] = {}
    for b, (_bpc, _borig, first, count) in enumerate(blocks):
        prev = 0
        for s in range(first, first + count):
            raw = layout[s * 9 + k_sk]
            if key == 0:
                sk = raw
            elif s == first:
                sk = _i32(raw ^ state_mix(prof, key, s))
            else:
                sk = _i32(raw ^ chained_state_mix(prof, key, prev, s, b))
            sks[s] = sk
            prev = sk

    # precomputed per-(slot, column) keystream
    mixret = {s: {p: 0 if key == 0 else _i32(
                  layout_mix(prof, key, sks[s], s, p)) for p in range(9)}
              for s in range(n_slots)}

    def dec(s: int, phys: int) -> int:
        return layout[s * 9 + phys] ^ mixret[s][phys]

    k_blk = anchors.get("block_index")
    k_pc = anchors.get("pc")
    k_org = anchors.get("original_pc")
    if k_blk is None or k_pc is None or k_org is None:
        # anchors incomplete (unexpected shape) — fall back to identity
        import sys as _sys
        print(f"[bvmw] layout anchors incomplete {anchors}; identity fallback",
              file=_sys.stderr)
        return list(range(9))

    pc_vals = {dec(s, k_pc) for s in range(n_slots)}
    nxt_allowed = pc_vals | {-1}

    pinned = {k_sk, k_blk, k_pc, k_org}
    if len(pinned) != 4:
        import sys as _sys
        print(f"[bvmw] layout anchors collide {anchors}; identity fallback",
              file=_sys.stderr)
        return list(range(9))
    rest = [p for p in range(9) if p not in pinned]
    sols = []
    for perm in itertools.permutations(rest):
        p_nxt, p_ost, p_ocn, p_cms, p_bsel = perm
        ok = True
        max_ocn = 0
        for s in range(n_slots):
            if dec(s, p_nxt) not in nxt_allowed:
                ok = False; break
            ost, ocn = dec(s, p_ost), dec(s, p_ocn)
            if ost < 0 or ocn < 0 or ost + ocn > operand_len:
                ok = False; break
            max_ocn = max(max_ocn, ocn)
            cms = dec(s, p_cms)
            if cms < 0 or (ocn < 32 and (cms >> ocn) != 0):
                ok = False; break
        if ok:
            sols.append((max_ocn, perm))
    if not sols:
        raise ValueError("layout slot permutation not solvable")
    # ostart/ocount swap ambiguity: the true ocount column holds small
    # per-instruction operand counts while ostart spans the whole stream,
    # so prefer the assignment with the smallest max operand count.
    sols.sort(key=lambda t: (t[0], t[1]))
    p_nxt, p_ost, p_ocn, p_cms, p_bsel = sols[0][1]
    # logical: 0=pc 1=original_pc 2=next_pc 3=ostart 4=ocount 5=cmask
    #          6=state_key 7=block_index 8=branch_selector
    slots = [0] * 9
    slots[0], slots[1] = k_pc, k_org
    slots[2], slots[3], slots[4] = p_nxt, p_ost, p_ocn
    slots[5], slots[6], slots[7] = p_cms, k_sk, k_blk
    slots[8] = p_bsel
    return slots


def extract_profile(pool_cf, main_cf) -> VMProfile:
    seed, ra, rb, rc, ma, mb = _extract_pool_mix(pool_cf)
    salts = _extract_main_salts(main_cf)
    salts.setdefault("salt_array", _extract_pool_salt_array(pool_cf))
    missing = [n for n in ("salt_layout", "salt_opcode", "salt_opcode_map",
                           "salt_operand", "salt_constant", "salt_handler",
                           "salt_array", "salt_string", "salt_state",
                           "salt_block", "dispatch_salt") if n not in salts]
    if missing:
        raise ValueError(f"profile salts missing: {missing}")
    return VMProfile(
        mix_seed=seed, mix_round_a=ra, mix_round_b=rb, mix_round_c=rc,
        mix_mul_a=ma, mix_mul_b=mb,
        salt_layout=salts["salt_layout"], salt_opcode=salts["salt_opcode"],
        salt_opcode_map=salts["salt_opcode_map"],
        salt_operand=salts["salt_operand"], salt_constant=salts["salt_constant"],
        salt_handler=salts["salt_handler"], salt_array=salts["salt_array"],
        salt_string=salts["salt_string"], salt_state=salts["salt_state"],
        salt_block=salts["salt_block"], dispatch_salt=salts["dispatch_salt"],
        layout_slots=list(range(9)))  # solved later by solve_layout_slots


# ---------------------------------------------------------------------------
# CodePool stream extraction (symbolic stack walk of codePoolInit$N)
# ---------------------------------------------------------------------------

@dataclass
class PoolData:
    streams: dict[str, list[list[int]]] = field(default_factory=dict)
    constants: list[list] = field(default_factory=list)  # per method row
    # element forms: ("encoded", [[int]-variants]) / ("str", s) / ("int", v) /
    # ("long", v) / ("float", f) / ("double", d) / ("type", desc) / None
    single: dict[str, list[int]] = field(default_factory=dict)
    unknown_ops: list[str] = field(default_factory=list)


def _cp_class_name(cf, index: int) -> str | None:
    e = cf.cp[index]
    if e and e[0] == cfmod.C_CLASS:
        return cf.utf8(e[1][0])
    return None


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


def extract_pool(pool_cf) -> PoolData:
    """Walk codePoolInit$0..9 and rebuild every stream row."""
    data = PoolData()
    for m in pool_cf.methods:
        name = pool_cf.utf8(m.name_index)
        if not name.startswith("codePoolInit$"):
            continue
        code = _code(pool_cf, m)
        if code is None:
            continue
        _walk_pool_init(pool_cf, code.insns, data, code.code)
    return data


# symbolic stack values: ("int", v) ("long", v) ("float", f) ("double", d)
# ("str", s) ("type", desc) ("null", None) ("unknown", None)
# ("str_arr", [str|None]) ("int_arr", [v|None]) ("long_arr", [v|None])
# ("int2d", {idx: row})  row = ("ints", [int]) once unpacked
# ("long2d", {idx: row})
# ("obj_arr", {idx: elem})  elem = ("str"|"int"|"long"|"float"|"double"|
#                                   "type"|"encoded"|"ints", payload) | None

def _expand_wide(insns: list, raw_code: bytes) -> list:
    """Expand wide (0xC4) load/store into equivalent plain insns.

    bytecode.py decodes `wide <op>` as Insn(op=0xC4, arg=sub-opcode); the
    u2 local-variable index sits at pc+2 and is not stored.  codePoolInit$
    bodies with >255 locals use wide aload/astore heavily — without this
    expansion the walk loses stack/local tracking past the first wide op.
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


def _walk_pool_init(cf, insns, data: PoolData, raw_code: bytes = b"") -> None:
    prof = _current_profile
    if prof is None:
        raise RuntimeError("profile must be set before pool unpacking")
    insns = _expand_wide(insns, raw_code)
    locals_: dict[int, object] = {}
    stack: list[object] = []
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
            elif op in (0x16, 0x1E, 0x1F):                # lload / lload_n
                idx = ins.arg if op == 0x16 else op - 0x1E
                stack.append(locals_.get(idx, ("long", None)))
            elif op in (0x17, 0x22, 0x23):                # fload / fload_n
                idx = ins.arg if op == 0x17 else op - 0x22
                stack.append(locals_.get(idx, ("float", None)))
            elif op in (0x18, 0x24, 0x25):                # dload / dload_n
                idx = ins.arg if op == 0x18 else op - 0x24
                stack.append(locals_.get(idx, ("double", None)))
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
            if name == "unpackStringInts" and desc.endswith("[I"):
                key = stack.pop() if stack else ("int", 0)
                length = stack.pop() if stack else ("int", 0)
                arr = stack.pop() if stack else None
                payload = arr[1] if isinstance(arr, tuple) else None
                strs = []
                for e in (payload or []):
                    if isinstance(e, str):
                        strs.append(e)
                    elif isinstance(e, tuple) and e[0] == "str":
                        strs.append(e[1])
                    else:
                        strs.append(None)
                vals = unpack_string_ints(prof, [s for s in strs if s],
                                          length[1] if length[0] == "int" else 0,
                                          key[1] if key[0] == "int" else 0)
                stack.append(("ints", vals))
            elif name == "unpackInts" and desc.endswith("[I"):
                key = stack.pop() if stack else ("int", 0)
                length = stack.pop() if stack else ("int", 0)
                arr = stack.pop() if stack else None
                payload = arr[1] if isinstance(arr, tuple) else None
                longs = []
                for e in (payload or []):
                    if isinstance(e, tuple) and e[0] == "long":
                        longs.append(e[1])
                    elif isinstance(e, int):
                        longs.append(e)
                    else:
                        longs.append(0)
                vals = unpack_ints(prof, longs,
                                   length[1] if length[0] == "int" else 0,
                                   key[1] if key[0] == "int" else 0)
                stack.append(("ints", vals))
            elif name == "valueOf":
                pass  # boxed primitive: keep the value on the stack
            else:
                for _ in range(_arg_slots(desc)):
                    if stack:
                        stack.pop()
                ret = _ret_kind(desc)
                if ret is not None:
                    stack.append(ret)
        elif op == 0xB3:                    # putstatic
            t = _target_desc(cf, ins)
            value = stack.pop() if stack else None
            if t and value is not None:
                _assign_field(data, t[1], value)
        elif op == 0xB2:                    # getstatic
            stack.append(("unknown", None))
        elif op == 0xB1 or 0xAC <= op <= 0xB0:  # return / *return
            pass
        else:                               # branches etc: not in init shapes
            unknown.append(f"op {op:02x}")
    if unknown:
        for u in sorted(set(unknown)):
            if u not in data.unknown_ops:
                data.unknown_ops.append(u)


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


def _assign_field(data: PoolData, field_name: str, value) -> None:
    kind, payload = value
    if kind == "int2d":
        rows: list[list[int]] = []
        for k in sorted(payload):
            row = payload[k]
            rows.append(row[1] if isinstance(row, tuple) and row[0] == "ints"
                        else [])
        data.streams[field_name] = rows
    elif kind == "ints":
        data.single[field_name] = list(payload)
    elif kind == "obj_arr":
        def _const_row(entry):
            # entry is either a nested obj_arr (one method's row of
            # constants — CONSTANTS = Object[rows][], row[i] = Object[n]
            # of constants) or a direct constant payload
            if isinstance(entry, tuple) and entry[0] == "obj_arr":
                return [_resolve_const_elem(entry[1][k])
                        for k in sorted(entry[1])]
            return _resolve_const_elem(entry)
        data.constants = [_const_row(payload[k]) for k in sorted(payload)]
    elif kind == "int_arr":
        vals = []
        it = (payload[k] for k in sorted(payload)) if isinstance(payload, dict) \
            else payload
        for v in it:
            vals.append(v if isinstance(v, int) else 0)
        data.single[field_name] = vals
    else:
        data.single[f"__unassigned_{field_name}__"] = []
        data.single[f"__unassigned_{field_name}__"] = repr(value)[:120]


def _resolve_const_elem(value):
    if value is None:
        return None
    kind, payload = value
    if kind == "int2d":
        variants = []
        for k in sorted(payload):
            row = payload[k]
            variants.append(row[1] if isinstance(row, tuple)
                            and row[0] == "ints" else [])
        return ("encoded", variants)
    if kind == "ints":
        return ("ints", list(payload))
    if kind in ("str", "int", "long", "float", "double", "type"):
        return (kind, payload)
    if kind == "null":
        return None
    return ("unknown", repr(value)[:80])


def _arg_slots(desc: str) -> int:
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


def _ret_kind(desc: str):
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


# profile used during pool unpacking (set by the caller)
_current_profile: VMProfile | None = None


# ---------------------------------------------------------------------------
# VM set discovery + bridges
# ---------------------------------------------------------------------------

@dataclass
class VMSet:
    index: int
    pool_name: str
    main_name: str
    profile: VMProfile
    pool: PoolData
    main_cf: object = None


def discover_vm_sets(classes: dict) -> list[VMSet]:
    sets = []
    for name, cf in classes.items():
        if "$CodePool" in name and "Integrity" not in name:
            base = name.rsplit("$CodePool", 1)[0]
            try:
                n = int(base.rsplit("$", 1)[-1])
            except ValueError:
                continue
            main_cf = classes.get(base)
            if main_cf is None:
                continue
            global _current_profile
            _current_profile = None
            prof = extract_profile(cf, main_cf)
            _current_profile = prof
            pool = extract_pool(cf)
            try:
                prof.layout_slots = solve_layout_slots(main_cf, prof, pool)
            except ValueError as e:
                import sys as _sys
                print(f"[bvmw] layout slot solve failed for {name}: {e}; "
                      f"falling back to identity", file=_sys.stderr)
                prof.layout_slots = list(range(9))
            sets.append(VMSet(index=n, pool_name=name, main_name=base,
                              profile=prof, pool=pool, main_cf=main_cf))
    sets.sort(key=lambda s: s.index)
    _current_profile = None
    return sets


def scan_bridges(classes: dict) -> list[tuple[str, str, int]]:
    """(class, method, vm_set) for calls into BytecodeVM$N$Integrity entries."""
    out = []
    for name, cf in classes.items():
        if "BytecodeVM$" in name:
            continue
        for m in cf.methods:
            code = _code(cf, m)
            if code is None:
                continue
            for ins in code.insns:
                t = _target_desc(cf, ins)
                if t and "$Integrity" in t[0] and t[1].startswith("$vm$integrityEntry"):
                    try:
                        n = int(t[0].rsplit("$", 2)[-2])
                    except ValueError:
                        continue
                    out.append((name, cf.utf8(m.name_index), n))
    return out


# ---------------------------------------------------------------------------
# method decoding
# ---------------------------------------------------------------------------

@dataclass
class VMMethodDecoded:
    set_index: int
    row: int
    method_key: int
    feature_flags: int
    blocks: list[list[int]]        # raw decoded [start_pc, orig_start, first_slot, count]
    slots: list[dict]              # per slot decoded fields
    handlers: list[list[int]]      # [start_pc, end_pc, handler_pc, type_idx]
    constants: list                # decoded python values (or None)
    warnings: list[str] = field(default_factory=list)


LAYOUT_FIELDS = ["pc", "original_pc", "next_pc", "operand_start",
                 "operand_count", "constant_mask", "_state_key",
                 "block_index", "branch_selector"]


def decode_method(vs: VMSet, row: int) -> VMMethodDecoded:
    prof = vs.profile
    pool = vs.pool
    key = pool.single["METHOD_KEYS"][row]
    flags = pool.single["FEATURE_FLAGS"][row]
    opcode_stream = pool.streams["OPCODE_STREAMS"][row]
    operand_stream = pool.streams["OPERAND_STREAMS"][row]
    layout = pool.streams["LAYOUT_STREAMS"][row]
    block_stream = pool.streams["BLOCK_STREAMS"][row]
    opcode_map = pool.streams["OPCODE_MAPS"][row]
    handlers_field = pool.streams.get("EXCEPTION_HANDLERS", [])
    handler_stream = handlers_field[row] if row < len(handlers_field) else []
    constants_row = pool.constants[row] if pool.constants else []

    warnings: list[str] = []
    if key == 0:
        warnings.append("methodKey==0: codePool protection off — decode is pass-through")

    # blocks
    blocks = []
    for b in range(len(block_stream) // 4):
        row4 = block_stream[b * 4:b * 4 + 4]
        vals = [row4[f] if key == 0 else _i32(row4[f] ^ block_mix(prof, key, b, f))
                for f in range(4)]
        blocks.append(vals)

    # stateKey chain per block, then per-slot layout decode
    phys_sk = prof.layout_slots[6]
    n_slots = len(opcode_stream)
    sk_by_slot: dict[int, int] = {}
    block_of: dict[int, int] = {}
    for b, (bpc, borig, first, count) in enumerate(blocks):
        prev = 0
        for s in range(first, first + count):
            raw = layout[s * 9 + phys_sk]
            if key == 0:
                sk = raw
            elif s == first:
                sk = _i32(raw ^ state_mix(prof, key, s))
            else:
                sk = _i32(raw ^ chained_state_mix(prof, key, prev, s, b))
            sk_by_slot[s] = sk
            block_of[s] = b
            prev = sk

    slots: list[dict] = []
    for s in range(n_slots):
        sk = sk_by_slot.get(s, 0)
        rec: dict[str, object] = {"slot": s, "state_key": sk,
                                  "block": block_of.get(s)}
        for logical, fname in enumerate(LAYOUT_FIELDS):
            if fname == "_state_key":
                continue
            phys = prof.layout_slots[logical]
            raw = layout[s * 9 + phys]
            rec[fname] = raw if key == 0 else \
                _i32(raw ^ layout_mix(prof, key, sk, s, phys))
        # opcodes
        v = opcode_stream[s]
        if key != 0 and (flags & 1):
            v = _i32(v ^ opcode_mix(prof, key, sk, rec["pc"], s))
        if 0 <= v < len(opcode_map):
            mapped = opcode_map[v]
            if key != 0 and (flags & 1):
                mapped = _i32(mapped ^ opcode_map_mix(prof, key, v))
        else:
            warnings.append(f"slot {s}: virtual opcode {v} out of map range")
            mapped = -1
        rec["virtual_opcode"] = v
        rec["dispatch_opcode"] = mapped
        # operands
        ops = []
        start, count = rec["operand_start"], rec["operand_count"]
        mask = rec["constant_mask"]
        for i in range(count):
            pos = start + i
            if pos >= len(operand_stream):
                warnings.append(f"slot {s}: operand {i} out of stream")
                ops.append(None)
                continue
            val = operand_stream[pos]
            if key != 0 and (flags & 2):
                val = _i32(val ^ operand_mix(prof, key, sk, mapped, rec["pc"],
                                             i, pos))
            if key != 0 and (flags & 4) and mask and (mask & (1 << i)):
                val = _i32(val ^ constant_mix(prof, key, sk, mapped, rec["pc"], i))
            ops.append(val)
        rec["operands"] = ops
        slots.append(rec)

    # exception handlers
    handlers = []
    for h in range(len(handler_stream) // 4):
        row4 = handler_stream[h * 4:h * 4 + 4]
        vals = [row4[f] if key == 0 else _i32(row4[f] ^ handler_mix(prof, key, h, f))
                for f in range(4)]
        handlers.append(vals)

    # constants (dynamic decrypt via selector match)
    decoded_consts = _decode_constants(vs, row, slots, constants_row, warnings)

    return VMMethodDecoded(set_index=vs.index, row=row, method_key=key,
                           feature_flags=flags, blocks=blocks, slots=slots,
                           handlers=handlers, constants=decoded_consts,
                           warnings=warnings)


def _decode_constants(vs: VMSet, row: int, slots, constants_row, warnings):
    prof = vs.profile
    key = vs.pool.single["METHOD_KEYS"][row]
    out: list = [None] * len(constants_row)
    if not constants_row:
        return out
    # candidate bindings: every (slot) + the default binding
    candidates: list[tuple[int, int]] = []
    for rec in slots:
        p = constant_state_mix(prof, key, rec["state_key"], rec["pc"],
                               rec["block"], rec["slot"], rec["dispatch_opcode"])
        s2 = constant_state_mix_secondary(prof, key, rec["state_key"],
                                          rec["pc"], rec["block"],
                                          rec["slot"], rec["dispatch_opcode"])
        candidates.append((p, s2))
    candidates.append((constant_state_mix(prof, key, 0, 0, -1, -1, 0),
                       constant_state_mix_secondary(prof, key, 0, 0, -1, -1, 0)))
    unmatched = 0
    for ci, elem in enumerate(constants_row):
        if elem is None:
            continue
        if elem[0] != "encoded":
            out[ci] = elem[1] if elem[0] in ("str", "int", "long", "type") \
                else elem
            continue
        decoded = None
        for (p, s2) in candidates:
            for var in elem[1]:
                if len(var) < 5:
                    continue
                na, nb, sel, selsec = var[0], var[1], var[2], var[3]
                if constant_selector(prof, p, s2, na, nb) == sel and \
                        constant_selector_secondary(prof, p, s2, na, nb) == selsec:
                    payload = [var[4 + i] ^ constant_stream(prof, p, s2, na, nb, i)
                               for i in range(len(var) - 4)]
                    decoded = _decode_payload(payload)
                    break
            if decoded is not None:
                break
        if decoded is None:
            unmatched += 1
        out[ci] = decoded
    if unmatched:
        warnings.append(f"{unmatched} constants unmatched (no valid binding)")
    return out


def _decode_payload(payload: list[int]):
    tag = payload[0]
    body = payload[1:]
    if tag == 1:  # String
        return "".join(chr(c & 0xFFFF) for c in body)
    if tag == 2:
        return _i32(body[0])
    if tag == 3:
        return _i64((body[0] << 32) | (body[1] & M32))
    if tag == 4:
        return struct.unpack(">f", struct.pack(">i", body[0]))[0]
    if tag == 5:
        return struct.unpack(">d", struct.pack(">ii", body[0], body[1]))[0]
    if tag == 6:
        return ("type", "".join(chr(c & 0xFFFF) for c in body))
    return ("tag?", tag, body)
