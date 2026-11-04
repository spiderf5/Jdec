"""nativedb — build & query an analysis bundle for a dumped native library.

The "IDA+MCP" discipline adapted to jdec: bind the LLM to a structured,
queryable store of ground truth instead of guessing.

Build:  python jdec.py nativedb <lib.dll> --build <outdir>
        -> <outdir>/nativedb.json (exports, JNI descriptors, strings,
           optional Ghidra C sources if present in <outdir>/*_decompiled)
Query:  python jdec.py nativedb <outdir> --search <kw>     # grep the bundle
        python jdec.py nativedb <outdir> --strings          # dump strings
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import native_scan as NS


def build(lib_path: Path, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    tri = NS.triage_raw(lib_path, out_dir)
    db = {
        "library": lib_path.name,
        "format": tri.libs[0].format if tri.libs else "?",
        "size": tri.libs[0].size if tri.libs else 0,
        "exports": tri.libs[0].exports if tri.libs else [],
        "jni_exports": tri.libs[0].jni_exports if tri.libs else [],
        "dynamic_methods": [
            {"desc": m.get("descriptor", ""), "origin": m.get("origin", "")}
            for m in (tri.libs[0].dynamic_methods if tri.libs else [])
        ],
        "strings": tri.libs[0].strings if tri.libs else [],
        "decompiled_c": [],
    }
    # Ghidra 产物（若同目录存在 *_decompiled/src/*.c 则并入）
    for c_file in sorted(out_dir.glob("*_decompiled/src/*.c")):
        db["decompiled_c"].append({
            "file": c_file.name,
            "text": c_file.read_text(encoding="utf-8", errors="replace"),
        })
    db_path = out_dir / "nativedb.json"
    db_path.write_text(json.dumps(db, ensure_ascii=False, indent=1),
                       encoding="utf-8")
    print(f"built {db_path}: exports={len(db['exports'])} "
          f"strings={len(db['strings'])} c_files={len(db['decompiled_c'])}")
    return db_path


def query(db_path: Path, search: str | None, show_strings: bool) -> int:
    db = json.loads(db_path.read_text(encoding="utf-8"))
    if show_strings:
        for s in db["strings"]:
            print(s)
        return 0
    if search is None:
        print(json.dumps({k: v for k, v in db.items() if k != "strings"
                          and k != "decompiled_c"},
                         ensure_ascii=False, indent=1)[:4000])
        return 0
    kw = search.lower()
    hits = 0
    for s in db["strings"]:
        if kw in s.lower():
            print(f"[string] {s}")
            hits += 1
    for sym in db["exports"]:
        if kw in sym.lower():
            print(f"[export] {sym}")
            hits += 1
    for m in db["dynamic_methods"]:
        if kw in m["desc"].lower():
            print(f"[jni-desc] {m['desc']} ({m['origin']})")
            hits += 1
    for c in db["decompiled_c"]:
        for i, line in enumerate(c["text"].splitlines()):
            if kw in line.lower():
                print(f"[{c['file']}:{i + 1}] {line.strip()[:160]}")
                hits += 1
    print(f"-- {hits} hit(s) for '{search}'")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="nativedb")
    ap.add_argument("input")
    ap.add_argument("--build", dest="build", metavar="OUTDIR")
    ap.add_argument("--search", default=None)
    ap.add_argument("--strings", action="store_true")
    args = ap.parse_args(argv)
    inp = Path(args.input)
    if args.build:
        build(inp, Path(args.build))
        return 0
    db_path = inp if inp.name == "nativedb.json" else inp / "nativedb.json"
    if not db_path.exists():
        print(f"no nativedb.json under {inp} — run with --build first")
        return 2
    return query(db_path, args.search, args.strings)
