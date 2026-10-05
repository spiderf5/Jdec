"""bvmw_devirt — BytecodeVM virtual-program extractor (prototype).

Input:  CFR-decompiled source dir of a BytecodeVM-protected jar
        (jdec decompile <jar> -o <dir>), plus the VMOpcode enum names from
        the BytecodeVM source (study/BytecodeVM/.../enums/VMOpcode.java).

What it does (prototype scope, corpus = fixtures/dec):
  1. reimplement CodePool.mix() with Java int semantics (32-bit wrap)
  2. unpack the packed CJK strings: OPCODE/OPERAND/LAYOUT/BLOCK streams,
     METHOD_KEYS, OPCODE_MAPS, MAX_LOCALS/MAX_STACK/FEATURE_FLAGS
  3. apply OPCODE_MAPS to the opcode streams and emit a first-cut
     disassembly of every virtual method (VMOpcode names)

NOT done yet (next steps): operand/layout semantics per opcode, CONSTANTS
decoding, super-instruction recipe expansion, full lift to Java.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

M32 = 0xFFFFFFFF


def _i32(x: int) -> int:
    x &= M32
    return x - 0x100000000 if x >= 0x80000000 else x


def mix(n: int, n2: int, n3: int, n4: int) -> int:
    """CodePool.mix — Java int semantics throughout."""
    n5 = n ^ 0x31001553
    n5 = _i32(n5 ^ _i32(n2 + -1679048790 + _i32((n5 << 6) & M32) + (n5 & M32) >> 2))
    n5 = _i32(n5 ^ _i32(n3 + 1424382671 + _i32((n5 << 6) & M32) + (n5 & M32) >> 2))
    n5 = _i32(n5 ^ _i32(n4 + 333759693 + _i32((n5 << 6) & M32) + (n5 & M32) >> 2))
    n5 = _i32(n5 ^ (n5 & M32) >> 16)
    n5 = _i32(n5 * 1861620505)
    n5 = _i32(n5 ^ (n5 & M32) >> 15)
    n5 = _i32(n5 * 1321811161)
    n5 = _i32(n5 ^ (n5 & M32) >> 16)
    return n5


def array_mix(seed: int, idx: int) -> int:
    return mix(seed, idx, 1756755566, 0)


def unpack_string_ints(strings: list[str], length: int, seed: int) -> list[int]:
    """CodePool.unpackStringInts — char pairs -> int, XOR arrayMix(seed, i)."""
    out: list[int] = []
    flat: list[str] = []
    for s in strings:
        flat.extend(s)
    i = 0
    while i + 1 < len(flat) and len(out) < length:
        val = (ord(flat[i]) << 16) | ord(flat[i + 1])
        out.append(_i32(val ^ array_mix(seed, len(out))))
        i += 2
    while len(out) < length:
        out.append(0)
    return out[:length]


def vmopcode_names(source_file: Path) -> list[str]:
    """Extract VMOpcode enum constant names (declaration order = ordinal)."""
    names = []
    for line in source_file.read_text(encoding="utf-8").splitlines():
        m = re.match(r"\s*([A-Z_0-9]+)\s*\(", line)
        if m:
            names.append(m.group(1))
    return names


def _java_unescape(s: str) -> str:
    """CFR java string literal -> raw chars."""
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "u":
                out.append(chr(int(s[i + 2:i + 6], 16)))
                i += 6
                continue
            mapping = {"n": "\n", "t": "\t", "r": "\r", "b": "\b",
                       "f": "\f", '"': '"', "'": "'", "\\": "\\"}
            out.append(mapping.get(n, n))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def parse_code_pool(java_file: Path):
    """Regex-extract the codePoolInit$N blocks from decompiled CodePool.java
    (corpus-specific: matches CFR output shape)."""
    text = java_file.read_text(encoding="utf-8")
    streams: dict[str, dict[int, list[int]]] = {}
    for block in re.finditer(
            r"private static void (codePoolInit\$\d+)\(\) \{(.*?)\n    \}", text,
            re.S):
        _name, body = block.group(1), block.group(2)
        target = re.search(r"(\w+) = nArray;", body)
        if not target:
            continue
        field = target.group(1)
        out_idx = 0
        literals: dict[str, list[str]] = {}
        for lit in re.finditer(
                r'String\[\] (\w+) = new String\[\]\{(.*?)\};', body):
            var = lit.group(1)
            literals[var] = [_java_unescape(x) for x in
                             re.findall(r'"((?:[^"\\]|\\.)*)"', lit.group(2))]
        longs: dict[str, list[int]] = {}
        for lit in re.finditer(
                r'long\[\] (\w+) = new long\[\]\{(.*?)\};', body):
            longs[lit.group(1)] = [int(x.strip().rstrip("Ll"), 0) & M32
                                   for x in lit.group(2).split(",") if x.strip()]
        for call in re.finditer(
                r'unpackStringInts\((\w+), (\d+), (-?\d+)\);', body):
            var, length, seed = call.group(1), int(call.group(2)), int(call.group(3))
            strs = literals.get(var, [])
            streams.setdefault(field, {})[out_idx] = \
                unpack_string_ints(strs, length, seed)
            out_idx += 1
        for call in re.finditer(
                r'unpackInts\((\w+), (\d+), (-?\d+)\);', body):
            var, length, seed = call.group(1), int(call.group(2)), int(call.group(3))
            vals = longs.get(var, [])
            pairs: list[int] = []
            for k in range(0, len(vals), 2):
                hi = vals[k]
                lo = vals[k + 1] if k + 1 < len(vals) else 0
                pairs.append(_i32((hi << 32) | lo))
                if len(pairs) < length and k + 1 < len(vals):
                    pairs.append(_i32(lo))
                if len(pairs) >= length:
                    break
            streams.setdefault(field, {})[out_idx] = pairs[:length]
            out_idx += 1
    return streams


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("decompiled_dir", help="CFR output dir of the protected jar")
    ap.add_argument("--vmopcode", required=True,
                    help="path to enums/VMOpcode.java from the BytecodeVM source")
    ap.add_argument("--set", default="0",
                    help="VM set index to dump (BytecodeVM$N$CodePool)")
    ap.add_argument("-o", "--out", default="bvmw_disasm.txt")
    args = ap.parse_args()

    src_dir = Path(args.decompiled_dir)
    pool_file = src_dir / "BytecodeVM" / f"BytecodeVM${args.set}$CodePool.java"
    if not pool_file.exists():
        print(f"not found: {pool_file}")
        return 2

    streams = parse_code_pool(pool_file)
    names = vmopcode_names(Path(args.vmopcode))

    with open(args.out, "w", encoding="utf-8") as f:
        for field, sets in sorted(streams.items()):
            f.write(f"== {field} ==\n")
            for idx, vals in sorted(sets.items()):
                f.write(f"-- set {idx}: {len(vals)} ints\n")
                f.write("  " + " ".join(
                    f"{v & M32:08x}" for v in vals[:32]) + (" ..." if len(vals) > 32 else "") + "\n")

        opstreams = streams.get("OPCODE_STREAMS", {})
        opmaps = streams.get("OPCODE_MAPS", {})
        for idx, ops in sorted(opstreams.items()):
            mapping = opmaps.get(idx)
            f.write(f"\n== virtual method {idx}: {len(ops)} vops ==\n")
            for i, op in enumerate(ops):
                op &= M32
                # opcode map: virtual byte -> real VMOpcode ordinal; the
                # exact application direction still needs verification —
                # emit both raw and mapped candidates
                mapped = None
                if mapping and op < len(mapping):
                    mapped = mapping[op] & M32
                raw_name = names[op] if op < len(names) else f"?{op}"
                map_name = names[mapped] if (mapped is not None
                                             and mapped < len(names)) else \
                    (f"?{mapped}" if mapped is not None else "-")
                f.write(f"  {i:4d}: raw={op:3d} ({raw_name})"
                        f"  mapped={mapped} ({map_name})\n")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
