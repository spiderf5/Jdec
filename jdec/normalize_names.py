"""Normalize dotted nested-class references in the Vineflower tree.

For every class file name containing '$' (e.g. BytecodeVM$0$Integrity$VM$Polymorphic$Handler),
build a pattern where each '$' matches either '$' or '.', and rewrite occurrences
to the canonical '$' form. Idempotent.
"""
import re
import pathlib
import sys

root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "vf_src")

names = [p.stem for p in (root / "BytecodeVM").glob("*.java")]
multi = [n for n in names if "$" in n]
print("classes with $:", len(multi))

pats = []
for n in multi:
    segs = n.split("$")
    pats.append((n, re.compile(r"\b" + r"[.$]".join(re.escape(seg) for seg in segs) + r"\b")))

fixed = 0
for p in root.rglob("*.java"):
    s = p.read_text(encoding="utf-8")
    orig = s
    for n, pat in pats:
        s = pat.sub(n, s)
    if s != orig:
        p.write_text(s, encoding="utf-8")
        fixed += 1
print("normalized files:", fixed)
