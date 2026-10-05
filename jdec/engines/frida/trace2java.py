"""trace2java — turn a jnitrace TSV into per-segment pseudo-Java.

Input: --jni-out TSV from dump_mappings.py (tid \t fn \t args...)
Optional: --markers harness stdout (lines "===ENTER cls.method===" /
"===EXIT cls.method===") to segment the trace per method invocation.

Output: a readable pseudo-Java listing per thread/segment. JNI skeleton ops
map to Java semantics 1:1 for the native-obfuscator family (JNIC / MyJ2C /
radioegor146 / PhantomShield), because their C is generator-translated
bytecode: every class/field/method/string access goes through JNIEnv.
"""

from __future__ import annotations

import argparse
from collections import OrderedDict


def load_ops(path: str):
    ops = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 2:
                continue
            tid, fn = parts[0], parts[1]
            args = parts[2:]
            ops.append((tid, fn, args))
    return ops


def op_to_java(fn: str, args: list[str]) -> str:
    if fn == "FindClass":
        return f'Class.forName("{args[0].replace("/", ".")}")'
    if fn in ("GetMethodID", "GetStaticMethodID"):
        name, sig = (args + ["?", "?"])[:2]
        return f'// method: {name} {sig}'
    if fn in ("GetFieldID", "GetStaticFieldID"):
        name, sig = (args + ["?", "?"])[:2]
        return f'// field: {name} {sig}'
    if fn == "NewStringUTF":
        return f'const-string "{args[0]}"'
    if fn == "GetStringUTFChars":
        return f'// read string: "{args[0]}"'
    return f"// {fn} {args}"


def segment(ops, markers):
    """Split ops by ENTER/EXIT markers when available; else by thread."""
    if not markers:
        by_thread: "OrderedDict[str, list]" = OrderedDict()
        for tid, fn, args in ops:
            by_thread.setdefault(tid, []).append((fn, args))
        return [(f"thread {tid}", items) for tid, items in by_thread.items()]
    # marker-driven: markers file lines are matched by order of appearance
    segs = []
    current = None
    buf = []
    marker_lines = [l.rstrip("\n") for l in open(markers, encoding="utf-8")]
    idx = 0
    for tid, fn, args in ops:
        # interleave: markers are text lines, ops are JNI rows; v1 assumes
        # the harness logged markers to the same stdout stream that was
        # interleaved into the trace by the wrapper — approximate by order
        while idx < len(marker_lines) and marker_lines[idx].startswith("==="):
            line = marker_lines[idx]
            idx += 1
            if line.startswith("===ENTER") and current:
                segs.append((current, buf))
                buf = []
            if line.startswith("===ENTER"):
                current = line[len("===ENTER "):].strip()
        if fn == "FindClass" or True:
            buf.append((fn, args))
    if current and buf:
        segs.append((current, buf))
    return segs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("trace", help="jni TSV from dump_mappings.py --jni-out")
    ap.add_argument("--markers", help="harness stdout with ===ENTER/===EXIT lines")
    ap.add_argument("-o", "--out", default="pseudo_java.txt")
    args = ap.parse_args()

    ops = load_ops(args.trace)
    segs = segment(ops, args.markers)

    with open(args.out, "w", encoding="utf-8") as f:
        for title, items in segs:
            f.write(f"=== {title} ({len(items)} ops) ===\n")
            counts: "OrderedDict[str, int]" = OrderedDict()
            for fn, a in items:
                line = op_to_java(fn, a)
                f.write(f"  {line}\n")
                counts[fn] = counts.get(fn, 0) + 1
            f.write("  -- summary: " +
                    ", ".join(f"{k} x{v}" for k, v in counts.items()) + "\n\n")
    print(f"wrote {args.out} ({len(segs)} segments, {len(ops)} ops)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
