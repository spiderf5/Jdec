"""Stage-1 golden comparison: extracted pool vs runtime FieldDump.

Parses codepool_runtime_dump.txt (JDK8 reflection dump of the four
BytecodeVM$N$CodePool classes after clinit) and compares every field,
int by int, against the bytecode-level extraction (bvmw_devirt).

Field mapping (dump -> PoolData):
  OPCODE_STREAMS / OPERAND_STREAMS / LAYOUT_STREAMS / BLOCK_STREAMS /
  EXCEPTION_HANDLERS / OPCODE_MAPS          -> pool.streams[name]
  CONSTANTS [m][c] = variants[v] = int[]    -> pool.constants[m][c]
      ("encoded", variants)                 -> variants (list identity)
  METHOD_KEYS / FEATURE_FLAGS / MAX_LOCALS /
  MAX_STACK                                 -> pool.single[name]
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from jdec import bvmw_devirt as dv

HERE = Path(__file__).resolve().parent
JAR = HERE / "calc-bytecodevm.jar"
DUMP = HERE / "codepool_runtime_dump.txt"

STREAM_FIELDS = ("OPCODE_STREAMS", "OPERAND_STREAMS", "LAYOUT_STREAMS",
                 "BLOCK_STREAMS", "EXCEPTION_HANDLERS", "OPCODE_MAPS")
SINGLE_FIELDS = ("METHOD_KEYS", "FEATURE_FLAGS", "MAX_LOCALS", "MAX_STACK")


def parse_dump(path: Path) -> dict[str, dict[str, object]]:
    """-> {"0": {FIELD: python object}, ...} keyed by set index digit."""
    sections: dict[str, dict[str, object]] = {}
    cur: dict[str, object] | None = None
    cur_idx = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("==== "):
            # BytecodeVM.BytecodeVM$<idx>$CodePool
            parts = line.split("$")
            cur_idx = parts[1] if len(parts) >= 3 else "?"
            cur = sections.setdefault(cur_idx, {})
            continue
        if cur is None or "=" not in line:
            continue
        name, _, rhs = line.strip().partition(" = ")
        if name == "INSTANCE" or not name.isupper():
            continue
        try:
            cur[name] = ast.literal_eval(rhs)
        except (ValueError, SyntaxError):
            cur[name] = ("__unparsed__", rhs[:80])
    return sections


def norm_constants(ours: list) -> list:
    """PoolData.constants row -> [[[int...]] per variant] or ('OTHER', repr)."""
    out = []
    for elem in ours:
        if isinstance(elem, tuple) and elem[0] == "encoded" \
                and isinstance(elem[1], list):
            out.append(elem[1])
        elif elem is None:
            out.append(None)
        else:
            out.append(("OTHER", elem[0], repr(elem[1])[:60]))
    return out


def compare(name: str, got, want, fails: list) -> bool:
    if got == want:
        return True
    if isinstance(want, list) and isinstance(got, list) \
            and len(got) == len(want):
        for i, (g, w) in enumerate(zip(got, want)):
            compare(f"{name}[{i}]", g, w, fails)
    else:
        fails.append(f"{name}: got {repr(got)[:100]} want {repr(want)[:100]}")
    return False


def main() -> int:
    dump = parse_dump(DUMP)
    print(f"dump sections: {sorted(dump)}  fields/section: "
          f"{[len(v) for v in dump.values()]}")

    classes = dv.load_classes(JAR)
    sets = dv.discover_vm_sets(classes)
    by_idx = {s.index: s for s in sets}
    print(f"vm sets: {[(s.index, s.pool_name) for s in sets]}")

    fails: list[str] = []
    for idx in sorted(dump):
        want_fields = dump[idx]
        vs = by_idx.get(int(idx)) if idx.isdigit() else None
        if vs is None:
            fails.append(f"set {idx}: no matching VMSet")
            continue
        pool = vs.pool
        for field in STREAM_FIELDS:
            if field not in want_fields:
                continue
            got = pool.streams.get(field)
            if got is None:
                fails.append(f"set {idx} {field}: missing from extraction")
                continue
            n0 = len(fails)
            compare(f"set{idx}.{field}", got, want_fields[field], fails)
            status = "ok" if len(fails) == n0 else "DIFF"
            rows = f"{len(got)}x{[len(r) for r in got]}"
            print(f"  set{idx} {field:<20} {status}  {rows}")
        for field in SINGLE_FIELDS:
            if field not in want_fields:
                continue
            got = pool.single.get(field)
            if got is None:
                fails.append(f"set {idx} {field}: missing from extraction")
                continue
            n0 = len(fails)
            compare(f"set{idx}.{field}", got, want_fields[field], fails)
            status = "ok" if len(fails) == n0 else "DIFF"
            print(f"  set{idx} {field:<20} {status}  {got}")
        if "CONSTANTS" in want_fields:
            want_rows = want_fields["CONSTANTS"]
            got_rows = [norm_constants(r) for r in pool.constants]
            n0 = len(fails)
            if len(got_rows) != len(want_rows):
                fails.append(f"set{idx}.CONSTANTS: {len(got_rows)} rows "
                             f"want {len(want_rows)}")
            else:
                for m, (g, w) in enumerate(zip(got_rows, want_rows)):
                    compare(f"set{idx}.CONSTANTS[{m}]", g, w, fails)
            status = "ok" if len(fails) == n0 else "DIFF"
            print(f"  set{idx} {'CONSTANTS':<20} {status}  "
                  f"rows={len(got_rows)}")

    print()
    if fails:
        print(f"RESULT: FAIL ({len(fails)} diffs)")
        for f in fails[:40]:
            print("  " + f)
        return 1
    print("RESULT: PASS — extraction matches runtime FieldDump on all fields")
    return 0


if __name__ == "__main__":
    sys.exit(main())
