"""Diagnose the block-2/3 puzzle: is BLOCK_STREAMS wrong at the extraction
layer (walk vs runtime dump) or at the decryption layer (block_mix)?"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from jdec import bvmw_devirt as dv
from compare_dump import parse_dump, DUMP, JAR

def first_diff(a: list[int], b: list[int]) -> int:
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    return -1 if len(a) == len(b) else min(len(a), len(b))

def main() -> int:
    dump = parse_dump(DUMP)
    classes = dv.load_classes(JAR)

    for idx in range(4):
        pool_name = f"BytecodeVM/BytecodeVM${idx}$CodePool"
        base = pool_name.rsplit("$CodePool", 1)[0]
        pool_cf, main_cf = classes[pool_name], classes[base]
        prof = dv.extract_profile(pool_cf, main_cf)
        dv._current_profile = prof          # bypass discover_vm_sets
        pool = dv.extract_pool(pool_cf)
        dv._current_profile = None

        want = dump[str(idx)]["BLOCK_STREAMS"]
        got = pool.streams.get("BLOCK_STREAMS")
        print(f"\n=== set{idx} BLOCK_STREAMS: got {len(got)} rows, "
              f"want {len(want)} rows")
        for r in range(min(len(got), len(want))):
            g, w = got[r], want[r]
            if g == w:
                print(f"  row {r}: IDENTICAL ({len(g)} ints)")
                continue
            d = first_diff(g, w)
            print(f"  row {r}: DIFF from int {d}  (len {len(g)} vs {len(w)})")
            lo, hi = max(0, d - 2), min(len(g), d + 4)
            for k in range(lo, hi):
                mark_g = " <" if k == d else ""
                print(f"    [{k}] got {g[k]:>12} (0x{g[k] & 0xffffffff:08x})"
                      f"   want {w[k]:>12} "
                      f"(0x{w[k] & 0xffffffff:08x}){mark_g}")
        if len(got) != len(want):
            for r in range(min(len(got), len(want)), max(len(got), len(want))):
                src = got if r < len(got) else want
                tag = "got " if r < len(got) else "want"
                print(f"  extra {tag}row {r}: "
                      f"{[f'0x{x & 0xffffffff:08x}' for x in src[:8]]} ...")
    return 0

if __name__ == "__main__":
    sys.exit(main())
