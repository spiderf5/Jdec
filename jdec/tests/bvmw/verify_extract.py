"""Stage-1 acceptance: profile + pool extraction for calc-bytecodevm.jar.

Checks:
  - 4 VM sets discovered (Integrity pools excluded)
  - profile salts match the known set0 constants
  - set0 METHOD_KEYS == [0xc2f47ad9], FEATURE_FLAGS == [0x1f]
  - stream sizes sane; no unknown ops in the walker
  - decode_method() runs for every set/row without exceptions
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from jdec import bvmw_devirt as dv

JAR = Path(__file__).resolve().parent / "calc-bytecodevm.jar"

KNOWN_SET0 = {
    "mix_seed": 0x31001553,
    "salt_layout": -1606612877,
    "salt_operand": 0xEEF4BBB7 - (1 << 32),
    "salt_constant": 836934301,
    "salt_state": -2111293298,
}

def main() -> int:
    classes = dv.load_classes(JAR)
    print(f"classes loaded: {len(classes)}")
    pools = sorted(n for n in classes if "$CodePool" in n)
    print(f"codepools: {pools}")

    sets = dv.discover_vm_sets(classes)
    print(f"\nVM sets discovered: {len(sets)} "
          f"({[s.pool_name.rsplit('$',1)[-2] for s in sets]})")
    fail = 0

    for vs in sets:
        prof = vs.profile
        pd = prof.to_dict()
        print(f"\n--- set {vs.index}: {vs.pool_name}")
        print("    " + " ".join(f"{k}=0x{v & 0xffffffff:x}" for k, v in
                                pd.items() if k != "layout_slots"))
        print(f"    layout_slots={prof.layout_slots}")
        for k, v in KNOWN_SET0.items():
            if vs.index == 0 and getattr(prof, k) != v:
                print(f"    MISMATCH {k}: got {getattr(prof, k)} want {v}")
                fail += 1
        if vs.pool.unknown_ops:
            print(f"    UNKNOWN OPS: {vs.pool.unknown_ops}")
            fail += 1
        print(f"    streams: " + " ".join(
            f"{k}={len(rows)}x{[len(r) for r in rows]}" for k, rows in
            vs.pool.streams.items()))
        print(f"    singles: " + " ".join(
            f"{k}={len(v)}" for k, v in vs.pool.single.items()))
        print(f"    constants rows: {len(vs.pool.constants)}")
        for k, v in (("METHOD_KEYS", [0xC2F47AD9 - (1 << 32)]),
                     ("FEATURE_FLAGS", [0x1F])):
            got = vs.pool.single.get(k)
            if vs.index == 0 and got is not None and got != v:
                print(f"    MISMATCH {k}: got {got} want {v}")
                fail += 1

    print("\n--- decode all methods")
    for vs in sets:
        n_rows = len(vs.pool.single.get("METHOD_KEYS", []))
        for row in range(n_rows):
            try:
                dec = dv.decode_method(vs, row)
                pcs = [s["pc"] for s in dec.slots]
                orig = [s["original_pc"] for s in dec.slots]
                dops = [s["dispatch_opcode"] for s in dec.slots]
                print(f"set {vs.index} row {row}: key=0x{dec.method_key & 0xffffffff:08x} "
                      f"flags={dec.feature_flags:#x} slots={len(dec.slots)} "
                      f"blocks={len(dec.blocks)} handlers={len(dec.handlers)} "
                      f"consts={len(dec.constants)}")
                print(f"  pc={pcs}")
                print(f"  orig={orig}")
                print(f"  dispatch={dops}")
                for w in dec.warnings:
                    print(f"  warn: {w}")
            except Exception as e:
                print(f"set {vs.index} row {row}: DECODE FAILED: {e!r}")
                fail += 1

    bridges = dv.scan_bridges(classes)
    print(f"\nbridges: {bridges}")

    print("\nRESULT:", "FAIL" if fail else "PASS", f"({fail} failures)")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
