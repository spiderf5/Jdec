#!/usr/bin/env python3
"""Reproducible behaviour-union benchmark for the rewrite base.

The headline coverage numbers in docs/README.md were measured on corpora that
cannot ship with the repository (an authorised HMCL launcher and two user
provided jars). This script gives anyone a one-command, self-contained number
instead: it compiles a generated fixture from source, derives cases for every
method, and runs the same ``behave --engine both`` gate.

Two comparisons are made:

  * identity (original vs original)  - measures how many methods the two
    engines can actually judge, and must report zero differences;
  * negative control (original vs a mutant with one changed constant) - must
    report a difference. A harness that always says "same" is worthless, so
    this is part of the verdict, not an optional extra.

To reproduce an external corpus instead, pass --original / --rewritten / --from
(and --cp as many times as needed). See docs/REPRODUCE.md for the exact
HMCL 3.15.2 / 411-method / JavaFX classpath recipe behind the 83.0% figure.

The builtin number is NOT a substitute for that corpus: it is a small,
deterministic regression baseline for the gate itself.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

JAVA_SOURCE = """\
package bench;

public final class Core {
    public static int add(int a, int b) { return a + b; }
    public static long mul(long a, long b) { return a * b; }
    public static boolean both(boolean a, boolean b) { return a && b; }
    public static int fold(int n) {
        int s = 0;
        for (int i = 0; i < n; i++) { s += i; }
        return s;
    }
    public static int branch(int x) { return x > 0 ? x * 2 : -x; }
    public static String tag(String s) { return "v:" + s; }
    public static int sum(int[] a) {
        int s = 0;
        for (int v : a) { s += v; }
        return s;
    }
    public static int opaque(int x) { return (x ^ 0x5a) & 0xff; }
    public static double ratio(double a, double b) { return b == 0.0 ? 0.0 : a / b; }
    public static int clamp(int x, int lo, int hi) {
        return x < lo ? lo : (x > hi ? hi : x);
    }
    public static String join(String a, String b) { return a + "/" + b; }
    public static char pick(String s, int i) { return s.charAt(i % s.length()); }
    public static int positive(int x) { return x < 0 ? -x : x; }
}
"""

_MUTANT_MARK = "return a + b;"
assert JAVA_SOURCE.count(_MUTANT_MARK) == 1
JAVA_MUTANT = JAVA_SOURCE.replace(_MUTANT_MARK, "return a + b + 1;", 1)

_UNION = re.compile(r"union\s+: (\d+)/(\d+) judged by either engine")
_UNION_VALUE = re.compile(r"union value\s+: (\d+)/(\d+)")
_DIFF = re.compile(r"^diff\s+: (\d+)\s*$", re.MULTILINE)


def find_javac() -> str | None:
    exe = shutil.which("javac")
    if exe:
        return exe
    home = os.environ.get("JAVA_HOME")
    if home:
        name = "javac.exe" if os.name == "nt" else "javac"
        cand = Path(home) / "bin" / name
        if cand.is_file():
            return str(cand)
    return None


def compile_fixture(source: str, work: Path, tag: str) -> Path:
    """Compile one Java source into a jar. No external build tool needed."""
    javac = find_javac()
    if javac is None:
        raise RuntimeError("javac not found: set JAVA_HOME or put javac on PATH")
    src_dir = work / tag / "src" / "bench"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "Core.java").write_text(source, encoding="utf-8")
    classes = work / tag / "classes"
    classes.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [javac, "--release", "8", "-encoding", "UTF-8", "-d", str(classes),
         str(src_dir / "Core.java")],
        capture_output=True, text=True, errors="replace", timeout=180)
    if proc.returncode != 0:
        raise RuntimeError(f"javac failed: {(proc.stderr or proc.stdout)[-800:]}")
    jar = work / f"{tag}.jar"
    with zipfile.ZipFile(jar, "w", zipfile.ZIP_DEFLATED) as zout:
        for cls in sorted(classes.rglob("*.class")):
            zout.write(cls, cls.relative_to(classes).as_posix())
    return jar


def method_rows(jar: Path) -> list[str]:
    """A rewritten list covering every real method in the fixture."""
    from jdec import classfile as CF
    rows: list[str] = []
    with zipfile.ZipFile(jar) as zin:
        for name in sorted(zin.namelist()):
            if not name.endswith(".class"):
                continue
            cf = CF.parse(zin.read(name))
            cls = name[:-len(".class")]
            for member in cf.methods:
                mname = cf.utf8(member.name_index)
                if mname in ("<init>", "<clinit>"):
                    continue
                desc = cf.utf8(member.descriptor_index)
                rows.append("\t".join((cls, mname, desc)))
    return rows


def run_gate(original: Path, rewritten: Path, rows_file: Path,
             cp: list[str]) -> dict:
    from jdec import cli as CL
    cmd = ["behave", str(original), str(rewritten), "--derive",
           "--from", str(rows_file), "--execute", "--engine", "both",
           "--union-gate", "0"]
    for entry in cp:
        cmd += ["--cp", entry]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = CL.main(cmd)
    text = buf.getvalue()
    union = _UNION.search(text)
    value = _UNION_VALUE.search(text)
    diff = _DIFF.search(text)
    return {
        "command": "jdec " + " ".join(cmd),
        "exit_code": rc,
        "union_judged": int(union.group(1)) if union else None,
        "union_total": int(union.group(2)) if union else None,
        "union_value": int(value.group(1)) if value else None,
        "diffs": int(diff.group(1)) if diff else None,
        "stdout": text,
    }


def environment() -> dict:
    from jdec import sandbox as SBX
    env: dict = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "java_major": None,
        "isolation_backend": None,
        "git": None,
    }
    try:
        env["java_major"] = SBX.java_major()
        env["isolation_backend"] = SBX.plan().backend
    except Exception as exc:  # noqa: BLE001 - report, do not hide
        env["java_error"] = str(exc)
    try:
        proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                              capture_output=True, text=True, timeout=15)
        if proc.returncode == 0:
            env["git"] = proc.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return env


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--original", type=Path, default=None,
                   help="original jar (default: the generated fixture)")
    p.add_argument("--rewritten", type=Path, default=None,
                   help="rewritten jar (default: same as --original)")
    p.add_argument("--from", dest="rows", type=Path, default=None,
                   help="rewritten method list, three tab-separated columns")
    p.add_argument("--cp", action="append", default=[], metavar="PATH",
                   help="extra classpath entry (repeatable); part of the "
                        "measurement, see docs/REPRODUCE.md")
    p.add_argument("--json", type=Path, default=None, help="write the full report here")
    p.add_argument("--workdir", type=Path, default=None,
                   help="keep the generated fixture in this directory")
    args = p.parse_args(argv)

    external = args.original is not None
    if external and args.rows is None:
        p.error("--from is required with --original (the method list is part of the recipe)")

    keep = None
    if args.workdir is not None:
        args.workdir.mkdir(parents=True, exist_ok=True)
        work = args.workdir
    else:
        keep = tempfile.TemporaryDirectory(prefix="jdec_bench_")
        work = Path(keep.name)

    try:
        if external:
            original = args.original.resolve()
            rewritten = (args.rewritten or args.original).resolve()
            rows_file = args.rows.resolve()
            mode = "external"
            methods = sum(1 for _ in rows_file.read_text(
                encoding="utf-8").splitlines() if _.strip())
        else:
            original = compile_fixture(JAVA_SOURCE, work, "base")
            rewritten = original
            mutant = compile_fixture(JAVA_MUTANT, work, "mutant")
            rows = method_rows(original)
            if not rows:
                raise RuntimeError("the generated fixture has no methods")
            rows_file = work / "rewritten.tsv"
            rows_file.write_text("\n".join(rows) + "\n", encoding="utf-8")
            methods = len(rows)
            mode = "builtin"

        report: dict = {
            "schema": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": mode,
            "environment": environment(),
            "methods": methods,
            "classpath": [str(Path(c).resolve()) for c in args.cp],
            "note": ("The builtin fixture is a deterministic gate regression, "
                     "not a replacement for the 411-method HMCL corpus. "
                     "docs/REPRODUCE.md records that recipe and the 83.0% / "
                     "90% decision."),
        }
        identity = run_gate(original, rewritten, rows_file, args.cp)
        report["comparison"] = identity
        verdict_ok = (identity["exit_code"] == 0
                      and identity["diffs"] == 0
                      and bool(identity["union_judged"]))

        if not external:
            negative = run_gate(original, mutant, rows_file, args.cp)
            detected = negative["exit_code"] == 1 and bool(negative["diffs"])
            report["negative_control"] = negative
            report["negative_control_detected"] = detected
            verdict_ok = verdict_ok and detected

        report["verdict"] = "PASS" if verdict_ok else "FAIL"
        report["source_sha256"] = (hashlib.sha256(JAVA_SOURCE.encode("utf-8"))
                                   .hexdigest() if not external else None)

        if args.json:
            args.json.parent.mkdir(parents=True, exist_ok=True)
            args.json.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                                 encoding="utf-8")

        union = identity["union_judged"]
        total = identity["union_total"]
        pct = (100.0 * union / total) if union is not None and total else 0.0
        print(f"mode      : {mode}")
        print(f"methods   : {methods}")
        print(f"backend   : {report['environment']['isolation_backend']} "
              f"(JDK {report['environment']['java_major']})")
        print(f"union     : {union}/{total} judged by either engine -> {pct:.1f}%")
        print(f"union val : {identity['union_value']}")
        print(f"diffs     : {identity['diffs']} (identity comparison)")
        if not external:
            print(f"neg. ctrl : {'DIFF detected' if report['negative_control_detected'] else 'NOT DETECTED'}")
        print(f"verdict   : {report['verdict']}")
        if args.json:
            print(f"report    : {args.json}")
        return 0 if verdict_ok else 1
    except Exception as exc:  # noqa: BLE001 - a benchmark must report, not traceback
        print(f"benchmark failed: {type(exc).__name__}: {exc}")
        return 2
    finally:
        if keep is not None:
            keep.cleanup()


if __name__ == "__main__":
    sys.exit(main())
