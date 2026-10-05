"""Flatten BytecodeVM$-nested class names to single-level names.

BytecodeVM$0$PoolRecord -> BVM0_PoolRecord
BytecodeVM$0            -> BVM0
Also renames the source files. String literals may reference old names —
acceptable for the instrumented-trace use case (documented caveat).
"""
import re
import pathlib
import sys

root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "vf_src")

rename_map = {}


def new_name(stem: str) -> str:
    m = re.fullmatch(r"BytecodeVM\$(\d+)\$(.+)", stem)
    if m:
        return f"BVM{m.group(1)}_{m.group(2)}"
    m = re.fullmatch(r"BytecodeVM\$(\d+)", stem)
    if m:
        return f"BVM{m.group(1)}"
    return stem


files = list(root.rglob("*.java"))
for p in files:
    old_stem = p.stem
    new_stem = new_name(old_stem)
    if new_stem != old_stem:
        rename_map[old_stem] = new_stem

# content rewrite: longest old names first (avoid prefix collisions)
for old in sorted(rename_map, key=len, reverse=True):
    new = rename_map[old]
    pass  # applied below via regex on all files

def apply_content(s: str) -> str:
    for old in sorted(rename_map, key=len, reverse=True):
        s = s.replace(old, rename_map[old])
    return s

renamed_files = 0
content_files = 0
for p in files:
    s = p.read_text(encoding="utf-8")
    s2 = apply_content(s)
    stem = p.stem
    new_stem = rename_map.get(stem, stem)
    if s2 != s:
        p.write_text(s2, encoding="utf-8")
        content_files += 1
    if new_stem != stem:
        p.rename(p.with_name(new_stem + ".java"))
        renamed_files += 1
print(f"files renamed: {renamed_files}, contents rewritten: {content_files}")
for old, new in sorted(rename_map.items())[:6]:
    print(" ", old, "->", new)
