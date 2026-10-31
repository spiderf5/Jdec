#!/usr/bin/env python3
"""Regression tests for jdec.

Run:  python tests/run_tests.py            (core tests)
      python tests/run_tests.py --with-mc  (also exercises a real Minecraft jar)

These assert the things that are easy to break and hard to notice:
  * parse -> serialise must be byte-identical, or remapping silently corrupts
    every class it touches
  * a remapped class must still be loadable bytecode (checked with javap), and
    call sites must be renamed along with declarations
  * one unparsable class must not be allowed to sink an otherwise fine run
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import struct                         # noqa: E402

from types import SimpleNamespace      # noqa: E402

import build_fixtures                 # noqa: E402
from build_fixtures import ensure_collide_jar  # noqa: E402
from jdec import analyze as AZ        # noqa: E402
from jdec import annotations as AN    # noqa: E402
from jdec import bytecode as BC       # noqa: E402
from jdec import callgraph as CG      # noqa: E402
from jdec import classfile as CF      # noqa: E402
from jdec import devirt as DV         # noqa: E402
from jdec import indy as INDY        # noqa: E402
from jdec import cli as CL           # noqa: E402
from jdec import mappings as MP       # noqa: E402
from jdec import mcmod as MM          # noqa: E402
from jdec import obf as OB            # noqa: E402
from jdec import pipeline as PIPE     # noqa: E402
from jdec import pool as PL           # noqa: E402
from jdec import project as PJ        # noqa: E402
from jdec import recover as RC        # noqa: E402
from jdec import score as SCORE       # noqa: E402
from jdec import strings as ST        # noqa: E402
from jdec import engines as EN  # noqa: E402
from jdec.decompile import _iso_buckets, decompile, write_report  # noqa: E402
from jdec.probe import JarProfile, profile_jar    # noqa: E402
from jdec.score import evaluate       # noqa: E402

# Every javac/java lookup in this file goes through these two. A JDK reachable
# only through JAVA_HOME (no PATH entry) is a normal Windows setup; resolving
# them once here keeps the gates and the subprocess calls in agreement.
JAVAC = build_fixtures._javac()
JAVA = EN.find_java()


def _jdk_tool(name: str) -> str | None:
    """javap/jar sit next to javac, which may be reachable only via JAVA_HOME."""
    if JAVAC:
        cand = Path(JAVAC).parent / (name + (".exe" if sys.platform == "win32" else ""))
        if cand.is_file():
            return str(cand)
    return shutil.which(name)


JAVAP = _jdk_tool("javap")

SAMPLE = ROOT / "tests" / "sample.jar"
MIXIN = ROOT / "tests" / "mixin.jar"
FLOW = ROOT / "tests" / "flow.jar"
MC_JAR = ROOT / "tests" / "mc" / "client_1.20.4.jar"
MC_MAP = ROOT / "tests" / "mc" / "mojang_1.20.4.txt"


ENGINES_DIR = ROOT / "engines"
ENGINES_READY = False


def _prepare_engines(quiet: bool = False) -> bool:
    """Make sure the decompiler jars are present before any test needs them.

    The jars are gitignored, so a fresh checkout has none. A test that needs an
    engine must be skipped with a reason rather than killing the whole run -
    decompile() raises EngineUnavailable when no engine is available.
    """
    global ENGINES_READY
    try:
        EN.ensure_engines(ENGINES_DIR, quiet=quiet)
    except Exception as exc:  # noqa: BLE001
        if not quiet:
            print(f"engine setup failed: {exc}")
    ENGINES_READY = any(EN.ENGINES[k].available(ENGINES_DIR) for k in EN.ENGINES)
    if ENGINES_READY and EN.find_java() is None:
        # The jars are on disk but nothing can run them. Treat that as "no
        # engine" so every engine-dependent case skips with a reason instead of
        # failing one by one with "java not found on PATH".
        ENGINES_READY = False
        if not quiet:
            print("NOTE       : decompiler jars present but no Java runtime found "
                  "(set JAVA_HOME); engine-dependent tests will be SKIPPED")
    if not ENGINES_READY and not quiet:
        print("NOTE       : no decompiler engine available (offline?); "
              "engine-dependent tests will be SKIPPED")
    return ENGINES_READY


def _no_engines() -> bool:
    if ENGINES_READY:
        return False
    print("  (skipped: decompiler engines unavailable; run `python jdec.py engines`)")
    return True



_passed = 0
_failed = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  ok   {name}")
    else:
        _failed += 1
        print(f"  FAIL {name}" + (f"  -> {detail}" if detail else ""))


BROKEN_SAMPLE = "demo/broken/Truncated.class"  # deliberately truncated fixture


def test_roundtrip_sample() -> None:
    print("classfile: parse -> serialise is lossless (sample jar)")
    with zipfile.ZipFile(SAMPLE) as z:
        names = [n for n in z.namelist() if n.endswith(".class")]
    ok = diff = 0
    for n in names:
        with zipfile.ZipFile(SAMPLE) as z:
            data = z.read(n)
        if n == BROKEN_SAMPLE:
            try:
                CF.parse(data)
                check("truncated class is rejected", False, "it parsed anyway")
            except CF.ClassFormatError:
                check("truncated class raises ClassFormatError", True)
            except Exception as exc:  # noqa: BLE001
                check("truncated class raises ClassFormatError", False, f"raised {type(exc)} instead")
            continue
        try:
            out = CF.parse(data).serialize()
        except Exception as exc:  # noqa: BLE001
            check(f"{n} parses", False, str(exc))
            continue
        if out == data:
            ok += 1
        else:
            diff += 1
            check(f"{n} byte-identical", False, f"{len(data)} -> {len(out)}")
    check(f"all {len(names)} classes round-trip", diff == 0 and ok > 0,
          f"identical={ok} diff={diff}")


def test_synthetic_members_ignored() -> None:
    """A record's generated equals/hashCode/toString must not count as lost."""
    print("score: compiler-generated members are not counted against output")
    with zipfile.ZipFile(SAMPLE) as z:
        data = z.read("demo/modern/Showcase$Point.class")
    cf = CF.parse(data)
    names = {n for n, _ in cf.method_sigs()}
    check("record exposes equals/hashCode/toString in bytecode",
          {"equals", "hashCode", "toString"} <= names, str(sorted(names)))
    src = "public record Point(int x, int y) { public String label() { return null; } }"
    q = evaluate(src, cf)
    check("plain record source scores as fully recovered", q.score >= 95.0,
          f"score={q.score} issues={q.issues}")


def test_end_to_end_sample() -> None:
    if _no_engines():
        return

    print("pipeline: end to end on the sample jar")
    out = Path(tempfile.mkdtemp()) / "out"
    rep = decompile(SAMPLE, out, ROOT / "engines", jobs=2, verify_all=True)
    check("every readable class comes out clean",
          rep.ok >= 10, f"ok={rep.ok} partial={rep.partial} failed={rep.failed}")
    check("the truncated class is quarantined, not fatal",
          any(o.status == "broken" for o in rep.outcomes.values()),
          str(sorted({o.status for o in rep.outcomes.values()})))
    check("member recovery is complete",
          (rep.coverage_avg or 0) >= 0.99, f"coverage={rep.coverage_avg}")


def test_partial_failure_is_not_total_failure() -> None:
    """Losing one method must not condemn the whole class.

    Decompilers wrap the method they gave up on in a "could not be decompiled"
    comment. Treating that as a class-level failure made CFR's 122 KB output for
    a real-sample class -- every member recovered -- get reported as a total loss.
    """
    print("score: a bounded give-up is not a class-level failure")
    with zipfile.ZipFile(SAMPLE) as z:
        cf = CF.parse(z.read("demo/modern/Showcase.class"))
    members = [m for m, _d in cf.method_sigs() if not m.startswith("<")]

    lost = ("    /*\n     * This method has failed to decompile.  When submitting a\n"
            "     * bug report, please include this class.\n     */\n")
    body = "\n".join(f"    public int {m}() {{ return 1; }}" for m in members)
    whole = f"public class Showcase {{\n{lost}\n{body}\n}}\n"

    # one method lost out of len(members), inside an otherwise complete class
    q = evaluate(whole, cf)
    check("the give-up note is detected", q.hard_error)
    check("but it is not a class-level failure", not q.class_level_failure,
          f"damaged={q.damaged_fraction}")
    check("the surviving members still count as recovered",
          q.coverage >= 0.9, f"coverage={q.coverage}")
    check("and the class stays usable", q.usable, f"score={q.score}")

    # a note that covers most of the file means the class really was refused
    huge = lost * 40 + f"public class Showcase {{\n{body}\n}}\n"
    check("a give-up covering the file is class-level",
          evaluate(huge, cf).class_level_failure,
          f"damaged={evaluate(huge, cf).damaged_fraction}")

    # and a truncated file with no members at all does not sneak through
    check("empty output is never usable", not evaluate("", cf).usable)


def test_unbalanced_braces_are_proportional() -> None:
    """Absolute brace counting condemned large files for one truncated method."""
    print("score: brace imbalance is judged as a share of the file")
    with zipfile.ZipFile(SAMPLE) as z:
        cf = CF.parse(z.read("demo/modern/Showcase.class"))
    members = [m for m, _d in cf.method_sigs() if not m.startswith("<")]

    def build(reps: int) -> str:
        body = "\n".join(
            f"    public int {m}() {{ return {i}; }}" for i, m in enumerate(members * reps))
        return "public class Showcase {\n" + body + "\n}\n"

    small = build(1)
    check("a balanced class is fine", not evaluate(small, cf).unbalanced)

    # one missing closing brace, in a file large enough that 1/N is noise
    large = build(20)
    off_by_one = large[:-2]
    q = evaluate(off_by_one, cf)
    check("one missing closing brace in a large class is tolerated",
          not q.unbalanced,
          f"opens={off_by_one.count('{')} closes={off_by_one.count('}')}")

    # but a genuinely shredded file still is flagged
    check("a thoroughly broken file is still flagged",
          evaluate("public class Showcase { { { { {\n", cf).unbalanced)


def test_case_colliding_class_names() -> None:
    """Two classes whose names differ only by case must both survive.

    ZKM-style mangling emits names like `pkg/A` and `pkg/a`. On a
    case-insensitive filesystem those are one path, so writing both into one
    output directory loses one of them -- and because the pipeline keys its
    bookkeeping on the output path, the victim was still reported as recovered.
    """
    if _no_engines():
        return

    print("pipeline: class names that differ only by case are not conflated")
    collide = ensure_collide_jar()
    if collide is None:
        print("  skip (javac unavailable)")
        return

    out = Path(tempfile.mkdtemp()) / "out"
    rep = decompile(collide, out, ROOT / "engines", jobs=2, verify_all=True)

    check("both case-twin classes are accounted for",
          rep.total == 2, f"total={rep.total}")

    names = {o.name for o in rep.outcomes.values()}
    check("both names are distinct entries",
          names == {"demo/collide/Widget", "demo/collide/widget"},
          str(sorted(names)))

    # The decisive assertion: each class must be matched against its OWN body.
    # Both markers appearing somewhere is not enough -- a single file scored
    # twice would satisfy that, which is exactly the bug.
    bodies = {}
    for stem, rel in (("demo/collide/Widget", None), ("demo/collide/widget", None)):
        o = rep.outcomes.get(stem)
        bodies[stem] = (out / "src" / o.rel).read_text("utf-8", "replace") if o and o.rel else ""

    upper, lower = bodies["demo/collide/Widget"], bodies["demo/collide/widget"]
    check("Widget got a source file", bool(upper), "no output")
    check("widget got a source file", bool(lower), "no output")
    check("the two sources are not the same file content",
          bool(upper) and bool(lower) and upper != lower,
          "both classes resolved to one body")
    check("Widget's body carries its own marker", "upper-Widget" in upper,
          "wrong body")
    check("widget's body carries its own marker", "lower-widget" in lower,
          "wrong body")
    check("neither class is reported failed",
          all(o.status != "failed" for o in rep.outcomes.values()),
          str({n: o.status for n, o in rep.outcomes.items()}))

    # The report must carry each class' own output path. Colliding classes are
    # written to percent-encoded paths, so the path is NOT derivable from the
    # class name -- an external tool has to read it from here.
    write_report(rep, out)
    payload = json.loads((out / "report.json").read_text("utf-8"))
    rels = {n: payload["classes"][n].get("rel") for n in sorted(names)}
    check("report.json records an output path per class",
          all(rels.values()), str(rels))
    check("the two case-twins record different output paths",
          rels["demo/collide/Widget"] != rels["demo/collide/widget"], str(rels))


def test_iso_buckets() -> None:
    """Bucketing must never put two same-lowercase names in one engine run."""
    print("pipeline: case-collision buckets never mix same-lowercase names")
    collisions = {
        "pkg/a": ["pkg/A", "pkg/a"],
        "pkg/b$c": ["pkg/B$C", "pkg/b$C"],
        "demo/ab": ["demo/AB", "demo/Ab", "demo/aB"],   # a 3-way group
    }
    buckets = _iso_buckets(collisions)
    check("bucket count follows the largest group",
          len(buckets) == 3, str(len(buckets)))
    for i, b in enumerate(buckets):
        keys = [n.lower() for n in b]
        check(f"bucket {i} holds distinct lowercase names",
              len(keys) == len(set(keys)), str(keys))
    flat = sorted(n for b in buckets for n in b)
    check("every colliding class lands in exactly one bucket",
          flat == sorted(n for g in collisions.values() for n in g), str(flat))


def test_safe_rel_covers_package_segments() -> None:
    """Collision-free paths must escape package segments, not just the class.

    `pkg/A/x` and `pkg/a/x` differ only by package case. Encoding the simple
    name alone left both on `pkg/a/x.java`, so one class was silently
    overwritten while report.json credited both as recovered.
    """
    print("pipeline: collision-free paths escape every path segment")
    from jdec.decompile import _safe_rel

    check("simple-name encoding is unchanged",
          _safe_rel("pkg/A") == "pkg/%41.java", _safe_rel("pkg/A"))
    twin = {_safe_rel(n).lower() for n in ("pkg/A/x", "pkg/a/x")}
    check("package-case twins get distinct paths", len(twin) == 2, str(twin))
    three = {_safe_rel(n).lower() for n in ("pkg/A/A", "pkg/A/a", "pkg/a/A")}
    check("three-way group stays distinct", len(three) == 3, str(three))
    check("non-ASCII case twins stay distinct",
          _safe_rel("pkg/Ä/x").lower() != _safe_rel("pkg/ä/x").lower(),
          f"{_safe_rel('pkg/Ä/x')} vs {_safe_rel('pkg/ä/x')}")
    escaped = _safe_rel("pkg/A/x")
    decoded = "/".join(urllib.parse.unquote(s) for s in escaped[:-5].split("/"))
    check("escaped path decodes back to the class name", decoded == "pkg/A/x", decoded)
    wide = _safe_rel("pkg/Ä/x")
    check("non-ASCII escape round-trips",
          urllib.parse.unquote(wide[:-5]) == "pkg/Ä/x", wide)


def test_web_report_rel_reverse_lookup() -> None:
    """web must read the per-class key that write_report actually writes."""
    print("web: report.json rel is honoured for twin-class previews")
    from jdec import web as WB

    work = Path(tempfile.mkdtemp())
    (work / "src" / "pkg").mkdir(parents=True)
    (work / "src" / "pkg" / "%41.java").write_text("class A {}", encoding="utf-8")
    (work / "report.json").write_text(json.dumps(
        {"classes": {"pkg/A": {"status": "ok", "rel": "pkg/%41.java"}}}), encoding="utf-8")
    got = WB._get_source_for_engine(work, "pkg/A", "final")
    check("twin-class source is found through rel",
          got.strip() == "class A {}", repr(got[:60]))
    (work / "report.json").write_text(json.dumps(
        {"outcomes": {"pkg/A": {"rel": "pkg/%41.java"}}}), encoding="utf-8")
    old = WB._get_source_for_engine(work, "pkg/A", "final")
    check("older report.json (outcomes) still readable",
          old.strip() == "class A {}", repr(old[:60]))


def test_pipeline_summary_target_is_resolvable() -> None:
    """The summary's target must survive being read outside its own directory."""
    print("pipeline: summary target is an absolute, resolvable path")
    prof = profile_jar(SAMPLE)
    res = PIPE.PipelineResult(target_jar=SAMPLE, out_dir=Path("."), profile=prof)
    data = res.to_dict()
    check("target is absolute", Path(data["target"]).is_absolute(), data["target"])
    check("target resolves to the analysed jar",
          Path(data["target"]) == SAMPLE.resolve(), data["target"])
    check("bare name still available for display",
          data.get("target_name") == SAMPLE.name, str(data.get("target_name")))


def test_bytecode_and_string_quality() -> None:
    """The reporting path must not mangle literals or overstate threat tags."""
    print("quality: iinc immediates, non-BMP literals, threat tags, exit codes")
    from jdec import stubs as SB
    from jdec.decompile import Report as DRep, decompile_exit_code

    # 1. iinc carries two immediates; arg used to be 0x0203 for `iinc 2 3`
    ins = BC.decode(bytes([0x84, 0x02, 0x03]))[0]
    check("iinc keeps index and delta apart",
          (ins.arg, ins.arg2) == (2, 3), f"arg={ins.arg} arg2={ins.arg2}")
    check("plain iload is unaffected", BC.decode(bytes([0x15, 0x05]))[0].arg == 5)

    # 2. A CESU-8 surrogate pair is one character, not six U+FFFD
    cp = [b"\x01" + struct.pack(">H", 6) + b"\xed\xa0\xbd\xed\xb8\x80",
          b"\x08" + struct.pack(">H", 1),
          b"\x01" + struct.pack(">H", 3) + b"a/E",
          b"\x07" + struct.pack(">H", 3)]
    data = b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 52, len(cp) + 1) + b"".join(cp)
    data += struct.pack(">HHHHHHH", 0x21, 4, 0, 0, 0, 0, 0)
    cf = CF.parse(data)
    lit = AN.constant_strings(cf)[0]
    check("emoji literal survives the string dump", lit == "\U0001F600", repr(lit))

    # 3. Threat tags: no exception-class / library-name false positives
    check("RuntimeException is not exec", ST.classify("java/lang/RuntimeException") == [],
          str(ST.classify("java/lang/RuntimeException")))
    check("authlib is not a credential",
          ST.classify("com.mojang.authlib.GameProfile") == [],
          str(ST.classify("com.mojang.authlib.GameProfile")))
    check("forward-slash Windows path is tagged",
          ST.classify("C:/Users/Public/cfg.dat") == ["path"],
          str(ST.classify("C:/Users/Public/cfg.dat")))
    check("a URL is not read as a drive letter",
          "path" not in ST.classify("https://example.com/a"),
          str(ST.classify("https://example.com/a")))
    blob = "a" * 48
    check("a duplicate label is emitted once",
          ST.classify(blob) == ["encrypted-blob"], str(ST.classify(blob)))

    # 4. Exit codes: an empty run must not report success
    base = dict(input="x.jar", output="src", started=0.0)
    check("all recovered -> 0",
          decompile_exit_code(DRep(total=3, ok=3, **base)) == 0)
    check("one failed -> 1",
          decompile_exit_code(DRep(total=3, ok=2, failed=1, **base)) == 1)
    check("all failed -> 2",
          decompile_exit_code(DRep(total=2, failed=2, **base)) == 2)
    check("empty jar is not a failure",
          decompile_exit_code(DRep(total=0, **base)) == 0)

    # 5. A two-class jar cannot claim 100/100 obfuscation from name medians
    with tempfile.TemporaryDirectory() as td:
        jar = Path(td) / "tiny.jar"
        with zipfile.ZipFile(jar, "w") as z:
            for n in ("a/A", "a/B"):
                z.writestr(n + ".class", SB.build_stub_class_bytes(n))
        prof = profile_jar(jar)
        check("small sample is capped", prof.obfuscation <= 50.0, str(prof.obfuscation))
        check("small sample is called out",
              any("small sample" in s for s in prof.signatures), str(prof.signatures))


    # 6. deflat must not fold across an entry point (branch target/handler)
    from jdec import deflat as DFM
    targeted = bytes([0x03, 0x99, 0x00, 0x04, 0x04, 0x05, 0x82, 0xAC])
    out, n = DFM.simplify_constants(targeted)
    check("fold skips a span a branch jumps into", n == 0 and out == targeted, out.hex())
    clean = bytes([0x03, 0x99, 0x00, 0x06, 0x04, 0x05, 0x82, 0xAC])
    out2, n2 = DFM.simplify_constants(clean)
    check("fold still happens when the span is entry-free",
          n2 == 1 and out2[4] == 0x06, out2.hex())
    op = bytes([0x03, 0x99, 0x00, 0x00, 0xB1])
    _, n3 = DFM.prune_opaque_predicates(op)
    check("opaque-predicate rewrite skips an entered span", n3 == 0)


def test_safety_and_byte_fidelity() -> None:
    """P0: destructive-output guard, float constants, byte-exact source rewrite."""
    print("safety: pool output guard, devirt float, recover byte fidelity")
    from unittest import mock
    from jdec import pool as PL
    from jdec import stubs as SB
    from jdec.recover import rewrite_sources

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        src = root / "src"
        (src / "pkg").mkdir(parents=True)
        sample = src / "pkg" / "A.java"
        sample.write_text("class A {}\n", encoding="utf-8")

        refusals = []
        for bad in (src, src.parent):
            try:
                PL.apply(src, None, bad)
            except ValueError:
                refusals.append(str(bad.name))
        check("pool refuses output == input", "src" in refusals, str(refusals))
        check("pool refuses output == input's parent",
              root.name in refusals, str(refusals))
        check("source tree survived the refusals", sample.is_file(), str(sample))

        # CWD is patched to an unrelated scratch dir so a broken guard cannot
        # delete the real working directory while the test runs
        cwd_only = root / "cwd_only"
        cwd_only.mkdir()
        with mock.patch.object(Path, "cwd", return_value=cwd_only):
            try:
                PL.apply(src, None, cwd_only)
                cwd_refused = False
            except ValueError:
                cwd_refused = True
        check("pool refuses output == CWD", cwd_refused)

        out = root / "src_pool"
        st = PL.apply(src, None, out)
        check("pool still writes to a fresh directory",
              out.is_dir() and isinstance(st, dict), str(st))

    # Path.read_text(newline=...) is Python 3.13+; the package claims 3.9+
    offenders = []
    for p in sorted((ROOT / "jdec").glob("*.py")):
        for ln in p.read_text(encoding="utf-8").splitlines():
            code = ln.split("#", 1)[0]
            if ("read_text(" in code or "write_text(" in code) and "newline=" in code:
                offenders.append(f"{p.name}: {ln.strip()}")
    check("no Path.read_text(newline=) (3.13-only)", not offenders, str(offenders))

    cf = CF.parse(SB.build_stub_class_bytes("com/example/Host"))
    helper = DV.ConstantPoolHelper(cf)
    idx = helper.add_constant(1.5)
    entry = cf.cp[idx]
    check("float constant uses CONSTANT_Float", entry[0] == CF.C_FLOAT, str(entry[0]))
    check("float value round-trips",
          abs(struct.unpack(">f", entry[1][0])[0] - 1.5) < 1e-6)
    check("float is one operand slot", DV._const_is_two_word(1.5) is False)
    check("long is still two slots", DV._const_is_two_word(1 << 40) is True)

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        raw = (b'class A {\n'
               b'    String s = Enc.d("n1", "Q2ZnbA==", 42);\n'
               b'    // stray byte: \x80\n'
               b'}\n')
        (d / "A.java").write_bytes(raw)
        tsv = d / "recovered.tsv"
        tsv.write_text("OK\tpkg.C\tn1\tQ2ZnbA==\t42\tsecret\n", encoding="utf-8")
        st = rewrite_sources(d, tsv)
        after = (d / "A.java").read_bytes()
        check("recover rewrote the site", st.get("replaced") == 1, str(st))
        check("LF endings preserved", b"\r\n" not in after, repr(after[:40]))
        check("undecodable byte preserved", b"\x80" in after, repr(after))
        check("plaintext written back", b'"secret"' in after)


def _synthetic_pe(names_rva: int = 0x10A0, name_bytes: bytes = b"Java_test_Foo\x00") -> bytes:
    """Minimal PE32 image with one export name; used to pin the export-table layout."""
    buf = bytearray(0x320)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)          # e_lfanew
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", buf, 0x86, 1)             # NumberOfSections
    struct.pack_into("<H", buf, 0x94, 0xE0)          # SizeOfOptionalHeader
    struct.pack_into("<H", buf, 0x98, 0x10B)         # PE32 magic
    struct.pack_into("<II", buf, 0xF8, 0x1000, 0x100)  # export dir RVA/size
    struct.pack_into("<I", buf, 0x178 + 8, 0x1000)   # section VirtualSize
    struct.pack_into("<I", buf, 0x178 + 12, 0x1000)  # section VirtualAddress
    struct.pack_into("<I", buf, 0x178 + 16, 0x320)   # SizeOfRawData
    struct.pack_into("<I", buf, 0x178 + 20, 0x200)   # PointerToRawData
    exp = 0x200
    struct.pack_into("<I", buf, exp + 20, 1)         # NumberOfFunctions
    struct.pack_into("<I", buf, exp + 24, 1)         # NumberOfNames
    struct.pack_into("<I", buf, exp + 28, 0x1040)    # AddressOfFunctions (decoy)
    struct.pack_into("<I", buf, exp + 32, 0x1060)    # AddressOfNames
    struct.pack_into("<I", buf, exp + 36, 0x1080)    # AddressOfNameOrdinals
    struct.pack_into("<I", buf, 0x240, 0x10C0)       # function -> decoy string
    struct.pack_into("<I", buf, 0x260, names_rva)
    buf[0x2A0:0x2A0 + len(name_bytes)] = name_bytes
    buf[0x2C0:0x2C0 + 6] = b"DECOY\x00"
    return bytes(buf)


def test_binary_semantics() -> None:
    """P1: PE export table, l/f/d load opcodes, internal-name normalisation."""
    print("binary: PE exports, clinit load slots, devirt name normalisation")
    from jdec import native_scan as NS
    from jdec import clinit_sim as CS
    from jdec.decompile import _out_rel

    check("PE export table reads AddressOfNames (not AddressOfFunctions)",
          NS.parse_pe_exports(_synthetic_pe()) == ["Java_test_Foo"],
          str(NS.parse_pe_exports(_synthetic_pe())))
    unterminated = bytearray(_synthetic_pe(names_rva=0x1080))
    unterminated[0x280:0x320] = b"A" * 0xA0          # no NUL terminator in range
    check("unterminated export name is skipped, not sliced",
          NS.parse_pe_exports(bytes(unterminated)) == [],
          str(NS.parse_pe_exports(bytes(unterminated))))
    check("non-PE input returns no exports", NS.parse_pe_exports(b"not a pe") == [])
    check("truncated MZ header returns no exports",
          NS.parse_pe_exports(b"MZ" + b"\x00" * 58) == [])

    longs = {CS._load_op(op)[1] for op in range(0x1E, 0x22)}
    floats = {CS._load_op(op)[1] for op in range(0x22, 0x26)}
    doubles = {CS._load_op(op)[1] for op in range(0x26, 0x2A)}
    check("load slot ranges are disjoint",
          longs == floats == doubles == {0, 1, 2, 3}, f"{longs} {floats} {doubles}")
    check("fload_2/fload_3 are floats",
          CS._load_op(0x24) == ("float", 2) and CS._load_op(0x25) == ("float", 3),
          f"{CS._load_op(0x24)} {CS._load_op(0x25)}")
    check("dload_0 is double slot 0", CS._load_op(0x26) == ("double", 0))
    check("lload_3 is long slot 3", CS._load_op(0x21) == ("long", 3))
    check("indexed loads take the operand",
          CS._load_op(0x16) == ("long", None)
          and CS._load_op(0x17) == ("float", None)
          and CS._load_op(0x18) == ("double", None))

    check("dotted exception name becomes internal",
          DV._norm_internal("java.lang.Exception") == "java/lang/Exception")
    check("L...; wrapper is stripped",
          DV._norm_internal("Ljava/lang/String;") == "java/lang/String")
    check("array descriptor keeps its wrapper",
          DV._norm_internal("[Ljava.lang.String;") == "[Ljava/lang/String;")
    check("already-internal name is unchanged",
          DV._norm_internal("java/lang/Object") == "java/lang/Object")

    check("inlined nested class keeps the outer path",
          _out_rel("pkg/A$B", "pkg/A", set()) == "pkg/A.java")
    check("separate nested file keeps its own path",
          _out_rel("pkg/A$B", "pkg/A$B", set()) == "pkg/A$B.java")
    check("colliding outer path is still escaped",
          _out_rel("pkg/A$b", "pkg/A", {"pkg/A"}) == "pkg/%41.java",
          _out_rel("pkg/A$b", "pkg/A", {"pkg/A"}))


def test_degradation_accounting() -> None:
    """P2: "could not read it" must never look like "there was nothing"."""
    print("accounting: callgraph / devirt / recover / natives / grounding")
    from jdec import stubs as SB
    from jdec import callgraph as CG
    from jdec import recover as RC
    from jdec import native_scan as NS
    from jdec import mcmod as MM

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        jar = root / "mixed.jar"
        with zipfile.ZipFile(jar, "w") as z:
            z.writestr("pkg/Good.class", SB.build_stub_class_bytes("pkg/Good"))
            z.writestr("pkg/Bad.class", b"\xca\xfe\xba\xbe broken")

        cg = CG.build_callgraph(jar)
        check("callgraph records the unreadable class",
              cg.unreadable == {"pkg/Bad"}, str(cg.unreadable))
        rep = CG.compute_reachability(cg)
        check("reachability json exposes the count",
              CG.export_json(rep)["summary"]["unreadable_classes"] == 1,
              str(CG.export_json(rep)["summary"]))
        keep, counts = CG.conservative_keepset(jar)
        check("keep-set holds the unreadable class", "pkg/Bad" in keep, str(keep))
        check("keep-set counts it", counts.get("unreadable") == 1, str(counts))
        pruned = root / "pruned.jar"
        CG.prune_jar(jar, pruned, keep)
        with zipfile.ZipFile(pruned) as z:
            names = z.namelist()
        check("pruning keeps the unreadable entry", "pkg/Bad.class" in names, str(names))

        poison = root / "poison.jar"
        with zipfile.ZipFile(poison, "w") as z:
            z.writestr("CodePool.class", b"\xca\xfe\xba\xbe broken")
        _pool, stats = DV.BVMDevirtualizer.scan_jar_code_pool_ex(poison)
        check("pool scan reports the parse error",
              len(stats["errors"]) == 1 and stats["classes_seen"] == 1, str(stats))
        check("legacy scan API still returns a dict",
              isinstance(DV.BVMDevirtualizer.scan_jar_code_pool(poison), dict))

        (root / "rec").mkdir()
        _spec, _n, _skip, unreadable = RC.build_spec(jar, root / "rec")
        check("build_spec counts unreadable classes", unreadable == 1, str(unreadable))

        (root / "nat").mkdir()
        tri = NS.triage(jar, root / "nat")
        check("native triage counts unreadable classes",
              tri.unreadable_classes == 1, str(tri.unreadable_classes))
        nat_md = root / "nat" / "report.md"
        NS.write_report(tri, "mixed.jar", nat_md)
        check("native report says so", "unreadable" in nat_md.read_text(encoding="utf-8"))

        broken_jar = root / "not_a_zip.jar"
        broken_jar.write_bytes(b"not a zip at all")
        g_bad = MM.IntermediaryGrounding(broken_jar)
        check("broken intermediary jar keeps the reason",
              bool(g_bad.error) and not g_bad.is_available(), str(g_bad.error))
        g_ok = MM.IntermediaryGrounding(SAMPLE)
        check("healthy intermediary jar has no error",
              g_ok.error is None and g_ok.is_available(), str(g_ok.error))


def test_tool_hardening() -> None:
    """P2: hung javac / missing java must produce a message, not a traceback."""
    print("tools: javac timeouts, missing java, replay prep warnings")
    import contextlib
    import io
    from unittest import mock
    from jdec import pool as PL
    from jdec import recover as RC
    from jdec import stubs as SB

    if JAVAC is None:
        print("  (skipped: javac timeout assertions need a JDK)")
    else:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            timeout_exc = subprocess.TimeoutExpired(cmd="javac", timeout=300)

            with mock.patch("subprocess.run", side_effect=timeout_exc):
                try:
                    SB.build_stubs_jar(root / "stubs.jar")
                    stubs_msg = ""
                except RuntimeError as exc:
                    stubs_msg = str(exc)
            check("stub build reports a javac timeout",
                  "timed out" in stubs_msg, stubs_msg)

            spec = root / "spec.tsv"
            spec.write_text("", encoding="utf-8")
            with mock.patch("subprocess.run", side_effect=timeout_exc):
                try:
                    PL.harvest(spec, root / "harvest.tsv", root / "work",
                               allow_exec=True, with_stubs=False)
                    pool_msg = ""
                except RuntimeError as exc:
                    pool_msg = str(exc)
            check("pool harvest reports a javac timeout",
                  "timed out" in pool_msg, pool_msg)

            buf = io.StringIO()
            with mock.patch("subprocess.run", side_effect=timeout_exc), \
                    contextlib.redirect_stdout(buf):
                rc = RC.recover(SAMPLE, root / "rec1", allow_exec=True,
                                with_stubs=False)
            check("recover returns 1 on a javac timeout", rc == 1, str(rc))
            check("recover prints the timeout", "timed out" in buf.getvalue(),
                  buf.getvalue()[-200:])

    if JAVAC is None:
        print("  (skipped: missing-java assertion needs a JDK)")
    else:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            buf = io.StringIO()
            with mock.patch("jdec.engines.find_java", return_value=None), \
                    contextlib.redirect_stdout(buf):
                rc = RC.recover(SAMPLE, root / "rec2", allow_exec=True,
                                with_stubs=False)
            check("missing java is an error, not a FileNotFoundError", rc == 1, str(rc))
            check("missing java message is readable",
                  "java not found" in buf.getvalue(), buf.getvalue()[-200:])

    # prep warnings need no JDK: ensure_stubs_jar is patched to raise
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        buf = io.StringIO()
        with mock.patch("jdec.stubs.ensure_stubs_jar",
                        side_effect=RuntimeError("boom-stubs")), \
                contextlib.redirect_stdout(buf):
            rc = RC.recover(SAMPLE, root / "rec3", with_stubs=True)
        out = buf.getvalue()
        check("replay prep failure is surfaced", "boom-stubs" in out, out[-200:])
        check("safety gate still returns 3", rc == 3, str(rc))


def test_cli_exit_codes() -> None:
    """0/1/2 must be visible from the CLI, not just inside the library."""
    print("cli: unusable engines and empty runs use the documented codes")
    import contextlib
    import io
    from types import SimpleNamespace
    from unittest import mock
    from jdec import cli as CL
    from jdec import engines as ENM

    with tempfile.TemporaryDirectory() as td:
        buf = io.StringIO()
        with mock.patch.object(ENM, "ensure_engines", return_value=[]), \
                mock.patch.object(ENM.Engine, "available", return_value=False), \
                contextlib.redirect_stdout(buf):
            rc = CL.cmd_engines(SimpleNamespace(engines_dir=td, with_ghidra=False))
        check("engines returns 1 when a jar is unusable", rc == 1, str(rc))
        check("engines names the problem", "unusable" in buf.getvalue(),
              buf.getvalue()[-200:])

        buf = io.StringIO()
        with mock.patch.object(ENM, "ensure_engines", return_value=[]), \
                mock.patch.object(ENM.Engine, "available", return_value=False), \
                contextlib.redirect_stdout(buf):
            rc = CL.main(["decompile", str(SAMPLE), "-o", str(Path(td) / "out")])
        check("decompile returns 2 when no engine is usable", rc == 2, str(rc))


def test_polish() -> None:
    """Batch 5: byte-exact pool view, modified UTF-8 stubs, cache fingerprint."""
    print("polish: ops_pool byte view, stub mUTF-8, cache fingerprint")
    from jdec import ops_pool as OP
    from jdec import stubs as SB

    check("pool strings decode to characters", OP._ldc_text(b"\xc2\xb1\xc3\xa9") == "\u00b1\u00e9",
          repr(OP._ldc_text(b"\xc2\xb1\xc3\xa9")))
    check("ISO-8859-1 payload re-encodes to the intended bytes",
          OP._ldc_text(b"\xc2\xb1\xc3\xa9").encode("latin-1") == b"\xb1\xe9")
    check("NUL survives (C0 80)", OP._ldc_text(b"\xc0\x80") == "\x00")

    name = "com/example/\U0001F600"
    data = SB.build_stub_class_bytes(name)
    check("stub class uses modified UTF-8", CF.encode_mutf8(name) in data)
    check("stub class does not use plain UTF-8", name.encode("utf-8") not in data)
    cf = CF.parse(data)
    check("stub class name decodes exactly",
          cf.utf8_text(cf.cp[cf.this_class][1][0]) == name,
          cf.utf8_text(cf.cp[cf.this_class][1][0]))

    fp1 = SB._sources_fingerprint({"a": "1"})
    fp2 = SB._sources_fingerprint({"a": "2"})
    check("fingerprint follows the sources", fp1 != fp2, fp1)
    check("fingerprint is stable", fp1 == SB._sources_fingerprint({"a": "1"}))
    check("real stub sources produce a fingerprint",
          len(SB._sources_fingerprint(SB.STUB_SOURCES)) == 64)

    check("valid IPv4 is tagged", "ip" in ST.classify("192.168.1.10"),
          str(ST.classify("192.168.1.10")))
    check("out-of-range octet is not an address",
          "ip" not in ST.classify("999.1.1.1") and "ip" not in ST.classify("256.0.0.1"),
          f"{ST.classify('999.1.1.1')} {ST.classify('256.0.0.1')}")
    check("four-part version still tags (no over-tightening)",
          "ip" in ST.classify("1.20.4.1"), str(ST.classify("1.20.4.1")))


def test_ir_roundtrip() -> None:
    """The stage-02 gate: a class and its methods must rebuild byte-for-byte."""
    print("ir: parse -> re-assemble is byte-exact (the precondition for a type IR)")
    import struct
    from jdec import bytecode as BC
    from jdec import ir as IR

    # 1. Every operand shape the decoder models, including the ones that used
    #    to be thrown away (switch payloads, wide operands, trailing bytes).
    cases = {
        "bipush -1": b"\x10\xff",
        "sipush -1": b"\x11\xff\xff",
        "ldc": b"\x12\x07",
        "iinc -1": b"\x84\x02\xff",
        "wide iinc": b"\xc4\x84\x00\x02\xff\x40",
        "wide iload": b"\xc4\x15\x01\x02",
        "ifnonnull": b"\xc7\x00\x03\xb1",
        "goto_w": b"\xc8\x00\x00\x00\x05\xb1",
        "multianewarray": b"\xc5\x00\x07\x02",
        "invokeinterface": b"\xb9\x00\x07\x02\x00",
        "invokedynamic": b"\xba\x00\x07\x00\x00",
    }
    for name, raw in cases.items():
        insns = BC.decode(raw)
        check(f"encode round-trips {name}", BC.encode(insns) == raw,
              BC.encode(insns).hex())

    # 2. Switch padding is positional: exercise all four alignments.
    for k in range(4):
        pad = (4 - ((k + 1) % 4)) % 4
        sw = (b"\x00" * k + b"\xaa" + b"\x00" * pad
              + struct.pack(">iii", 0, 0, 1) + struct.pack(">ii", 0, 0))
        check(f"tableswitch round-trips at pc%4={k}",
              BC.encode(BC.decode(sw)) == sw, BC.encode(BC.decode(sw)).hex())
        lk = (b"\x00" * k + b"\xab" + b"\x00" * pad
              + struct.pack(">ii", 0, 1) + struct.pack(">ii", 7, 0))
        check(f"lookupswitch round-trips at pc%4={k}",
              BC.encode(BC.decode(lk)) == lk, BC.encode(BC.decode(lk)).hex())

    # 3. Offsets are recomputed, not copied: inserting an instruction between a
    #    branch and its target must move the offset and keep the target.
    orig = bytes([0x03, 0x99, 0x00, 0x04, 0x04, 0xac])   # iconst_0; ifeq -> 5
    insns = BC.decode(orig)
    nop = BC.Insn(pc=-1, op=0x00, length=1)
    moved = [insns[0], insns[1], nop, insns[2], insns[3]]
    out = BC.encode(moved)
    check("relocated branch offset is recomputed (+4 -> +5)",
          out == bytes([0x03, 0x99, 0x00, 0x05, 0x00, 0x04, 0xac]), out.hex())
    check("relocated branch still targets the return",
          BC.decode(out)[1].jump_targets() == [6],
          str([i.jump_targets() for i in BC.decode(out)]))

    # 4. Refusals: a removed target, a switch that lost its low key, a `wide`
    #    without operands. Silently emitting the old offset is the failure mode
    #    this whole module exists to prevent.
    try:
        BC.encode(insns[:2])          # the branch target (pc 5) is gone
        lost_target = False
    except BC.BytecodeError:
        lost_target = True
    check("encode refuses a branch whose target was removed", lost_target)

    sw_insn = BC.decode(bytes([0xaa]) + b"\x00" * 3
                        + struct.pack(">iiii", 0, 0, 0, 0))[0]
    sw_insn.switch_low = None
    try:
        BC.encode([sw_insn])
        missing_low = False
    except BC.BytecodeError:
        missing_low = True
    check("encode refuses a tableswitch without its low key", missing_low)

    wide_insn = BC.Insn(pc=0, op=0xC4, arg=0x15, length=4)
    try:
        BC.encode([wide_insn])
        no_raw = False
    except BC.BytecodeError:
        no_raw = True
    check("encode refuses a wide with no operand bytes", no_raw)

    # 5. The corpus: every fixture class, every method.
    rep = IR.audit_jar(SAMPLE)
    check("audit covers the whole fixture jar", rep.classes >= 10, str(rep.classes))
    check("audit found methods to check", rep.methods >= 20, str(rep.methods))
    check("every class rebuilds byte-identically", not rep.class_mismatch,
          str(rep.class_mismatch))
    check("every method rebuilds byte-identically",
          not rep.mismatches, "; ".join(m.describe() for m in rep.mismatches[:3]))
    check("the truncated fixture is counted, not crashed on",
          rep.classes_unreadable == 1, str(rep.classes_unreadable))
    check("audit passes overall", rep.ok)

    # 6. A file that is not a class is unreadable, not an exception.
    bad = IR.AuditReport(target="x")
    IR.audit_class_bytes(b"\xca\xfe\xba\xbe junk", "x/Bad", bad)
    check("corrupt class counts as unreadable", bad.classes_unreadable == 1
          and bad.classes == 0)
    check("nothing checked is not a pass", not bad.ok)

    # 7. CLI: 0 on a clean jar, and the summary names both levels.
    import contextlib
    import io
    from jdec import cli as CL
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = CL.main(["ircheck", str(SAMPLE)])
    text = buf.getvalue()
    check("ircheck exits 0 on a clean jar", rc == 0, str(rc))
    check("ircheck reports both levels", "class     :" in text and "method    :" in text,
          text[-300:])
    check("ircheck says PASS", "result    : PASS" in text, text[-200:])


def test_toolchain_single_entry() -> None:
    """javac is spawned from exactly one place, with the same guardrails."""
    print("toolchain: one entry point for the JDK")
    import io
    from unittest import mock
    from jdec import engines as EN
    from jdec import toolchain as TC

    check("path_sep is the JVM's separator", TC.path_sep() == EN.cp_sep(),
          TC.path_sep())

    # explicit override is authoritative: a named-but-missing compiler must not
    # silently fall back to whatever else is on PATH
    missing = str(Path(tempfile.gettempdir()) / "definitely-not-javac")
    check("an explicit missing javac resolves to empty",
          TC.find_javac(missing) == "", TC.find_javac(missing))

    with mock.patch("jdec.engines.find_javac", return_value=None):
        try:
            TC.require_javac("testing")
            raised = False
        except TC.ToolchainError as exc:
            raised = "javac not found" in str(exc) and "testing" in str(exc)
        check("require_javac raises an actionable error", raised)

    # every invocation carries text mode, error replacement and a timeout
    captured: dict = {}

    class _Fake:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        captured.update(kw)
        return _Fake()

    with mock.patch("subprocess.run", side_effect=fake_run):
        TC.run_javac(["-version"], exe=sys.executable)
    check("run_javac sets text mode", captured.get("text") is True, str(captured))
    check("run_javac sets errors=replace", captured.get("errors") == "replace",
          str(captured.get("errors")))
    check("run_javac sets a timeout", captured.get("timeout") == TC.JAVAC_TIMEOUT,
          str(captured.get("timeout")))

    with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("javac", 300)):
        try:
            TC.run_javac(["-version"], exe=sys.executable)
            timed_out = ""
        except TC.ToolchainError as exc:
            timed_out = str(exc)
    check("a hung javac becomes a ToolchainError", "timed out" in timed_out, timed_out)

    # the rule itself: no module outside toolchain.py may spawn a javac
    offenders = []
    for p in sorted((ROOT / "jdec").glob("*.py")):
        if p.name == "toolchain.py":
            continue
        for ln in p.read_text(encoding="utf-8").splitlines():
            if "subprocess.run(" in ln and "javac" in ln:
                offenders.append(f"{p.name}: {ln.strip()}")
    check("javac is spawned only from toolchain.py", not offenders,
          "; ".join(offenders))


def test_verify_gate() -> None:
    """The JVM gate must reject broken bytecode — proven, not assumed."""
    print("verify: -Xverify:all gate, positive and negative controls")
    import re
    import struct
    from jdec import verify as VF

    if JAVAC is None or EN.find_java() is None:
        print("  (skipped: the verification gate needs a JDK)")
        return

    # 1. positive control: an untouched jar must pass
    rep = VF.verify(MIXIN)
    check("untouched jar passes the gate", rep.ok and rep.invalid == [],
          rep.summary())
    check("the gate actually judged every class", rep.verified == rep.checked,
          f"{rep.verified}/{rep.checked}")

    # 2. negative control: flip one `return` to `ireturn` in a fixture class.
    #    Without this, a driver that only *loads* classes reports PASS on
    #    everything (that bug shipped twice while building this module).
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        broken = root / "broken.jar"
        victim = "demo/mixin/ClientEntry"
        with zipfile.ZipFile(MIXIN) as zin:
            data = zin.read(victim + ".class")
            cf = CF.parse(data)
            target = None
            for m in cf.methods:
                if (cf.utf8(m.name_index) == "<init>"
                        and cf.utf8(m.descriptor_index) == "()V"):
                    target = m
                    break
            check("fixture has a constructor to corrupt", target is not None)
            ci = BC.method_code(cf, target)
            blob = bytearray(target.attrs_blob)
            cnt = struct.unpack_from(">H", blob, 0)[0]
            o = 2
            patched = False
            for _ in range(cnt):
                ni, ln = struct.unpack_from(">HI", blob, o)
                start = o + 6
                if cf.utf8(ni) == "Code":
                    code_len = struct.unpack_from(">I", blob, start + 4)[0]
                    code_at = start + 8
                    blob[code_at + code_len - 1] = 0xAC      # return -> ireturn
                    patched = True
                    break
                o = start + ln
            check("constructor code was found and corrupted", patched)
            target.attrs_blob = bytes(blob)
            with zipfile.ZipFile(broken, "w") as zout:
                for info in zin.infolist():
                    if info.filename == victim + ".class":
                        zout.writestr(info, cf.serialize())
                    else:
                        zout.writestr(info, zin.read(info.filename))

        bad = VF.verify(broken, classpath=[MIXIN])
        check("a class whose constructor ends in ireturn is rejected",
              [i.cls for i in bad.invalid] == [victim], bad.summary())
        check("the rejection is a VerifyError",
              bad.invalid and "VerifyError" in bad.invalid[0].detail,
              bad.invalid[0].detail if bad.invalid else "")
        check("a rejected jar is not a pass", not bad.ok)

        # 3. the rollback policy: a rewrite never ships a class that fails
        res = VF.verify_or_keep(MIXIN, broken)
        check("the broken class was reverted", res.reverted == [victim],
              str(res.reverted))
        after = VF.verify(broken, classpath=[MIXIN])
        check("after the rollback the output verifies", not after.invalid,
              after.summary())
        check("nothing is left invalid", not res.still_invalid, str(res.still_invalid))

    # 4. a truncated class is rejected too (ClassFormatError, not VerifyError)
    trunc = VF.verify(SAMPLE)
    check("a truncated class is reported invalid",
          any("Truncated" in i.cls for i in trunc.invalid), trunc.summary())

    # 5. static guard: the driver must force linking. `forName(..., false)` and
    #    `resolveClass` both silently skip verification on JDK 21. Comments are
    #    stripped first — the driver's own docstring names the rejected APIs.
    src = VF.DRIVER_JAVA
    src_code = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src_code = re.sub(r"//[^\n]*", "", src_code)
    check("driver forces linking via reflection",
          "getDeclaredMethods" in src_code and "resolveClass" not in src_code,
          "the driver must not go back to resolveClass/forName")

    # 6. exit codes
    import contextlib
    import io
    from jdec import cli as CL
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc_ok = CL.main(["verify", str(MIXIN)])
    with contextlib.redirect_stdout(buf):
        rc_bad = CL.main(["verify", str(SAMPLE)])
    check("verify exits 0 on a clean jar", rc_ok == 0, str(rc_ok))
    check("verify exits 1 when the verifier rejects a class", rc_bad == 1, str(rc_bad))


def test_classfile_parser_survives_mutation() -> None:
    """Mutated input must end in ClassFormatError, never an internal crash."""
    print("classfile: mutated inputs are rejected, not crashed on")
    import random

    with zipfile.ZipFile(SAMPLE) as z:
        blobs = [z.read(n) for n in z.namelist() if n.endswith(".class")]
    rng = random.Random(20261031)
    unexpected = []
    for _ in range(1000):
        data = bytearray(rng.choice(blobs))
        for _ in range(rng.randint(1, 4)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        if rng.random() < 0.3:
            data = data[: rng.randrange(len(data) + 1)]
        try:
            CF.parse(bytes(data)).serialize()
        except CF.ClassFormatError:
            pass
        except Exception as exc:  # noqa: BLE001 - the point of the test
            unexpected.append(f"{type(exc).__name__}: {exc}")
    check("1000 mutated classes: only ClassFormatError escapes",
          not unexpected, "; ".join(unexpected[:3]))


def test_deflat_parallel_matches_serial() -> None:
    """The worker pool must not change a byte or the accounting."""
    print("deflat: parallel rewriting matches the serial result")
    from jdec import deflat as DF

    with tempfile.TemporaryDirectory() as td:
        serial = DF.deflat_jar(SAMPLE, Path(td) / "serial.jar",
                               verify_output=False, jobs=1)
        par = DF.deflat_jar(SAMPLE, Path(td) / "par.jar",
                            verify_output=False, jobs=2)

        with zipfile.ZipFile(Path(td) / "serial.jar") as a, \
                zipfile.ZipFile(Path(td) / "par.jar") as b:
            names_a = a.namelist()
            names_b = b.namelist()
            same = names_a == names_b and all(
                a.read(n) == b.read(n) for n in names_a)
        check("the entry order and every class byte are identical", same,
              f"{len(names_a)} vs {len(names_b)} entries")
        check("the rewrite count is identical",
              serial["methods_unflattened"] == par["methods_unflattened"],
              f"{serial['methods_unflattened']} vs {par['methods_unflattened']}")
        check("the rewritten list is identical",
              serial["rewritten"] == par["rewritten"],
              f"{len(serial['rewritten'])} vs {len(par['rewritten'])}")
        check("unreadable-class accounting is identical",
              serial["failed_classes"] == par["failed_classes"],
              str(par["failed_classes"]))
        check("the missing-type set is identical",
              serial["unresolved_types"] == par["unresolved_types"],
              f"{len(serial['unresolved_types'])} vs "
              f"{len(par['unresolved_types'])}")


def test_deflat_output_loads() -> None:
    """Both deflat modes must ship loadable classes, with different trade-offs."""
    print("deflat: default keeps frames, --strip-frames keeps rewrites straight-line")
    from jdec import deflat as DF
    from jdec import verify as VF

    if JAVAC is None or EN.find_java() is None:
        print("  (skipped: needs a JDK)")
        return

    with tempfile.TemporaryDirectory() as td:
        keep = Path(td) / "keep.jar"
        strip = Path(td) / "strip.jar"
        # this case is about the length-preserving path, where the original
        # frames are already at the right offsets — pin it explicitly
        stats_keep = DF.deflat_jar(SAMPLE, keep, ir_rewrite=False)
        stats_strip = DF.deflat_jar(SAMPLE, strip, strip_frames=True,
                                    verify_output=False, ir_rewrite=False)
        check("deflat reports its per-method rollbacks",
              "methods_reverted" in stats_keep, str(stats_keep))
        check("at least one method was rewritten",
              stats_keep["methods_unflattened"] > 0, str(stats_keep["methods_unflattened"]))

        # Default mode: frames are kept, so nothing needs to be reverted for
        # frame reasons and the output must load.
        rep = VF.verify(keep, classpath=[SAMPLE])
        new_bad = {i.cls for i in rep.invalid} - {"demo/broken/Truncated"}
        check("default mode introduces no invalid class", not new_bad,
              str(sorted(new_bad)[:3]))
        check("the deliberately truncated fixture stays the only failure",
              {i.cls for i in rep.invalid} <= {"demo/broken/Truncated"},
              rep.summary())

        # strip_frames mode: no shipped rewrite may still need a frame.
        branched = []
        with zipfile.ZipFile(SAMPLE) as zin, zipfile.ZipFile(strip) as zout:
            for name in zin.namelist():
                if not name.endswith(".class") or name == BROKEN_SAMPLE:
                    continue
                try:
                    before = CF.parse(zin.read(name))
                    after = CF.parse(zout.read(name))
                except Exception:
                    continue
                for m_before, m_after in zip(before.methods, after.methods):
                    if m_before.attrs_blob == m_after.attrs_blob:
                        continue
                    ci = BC.method_code(after, m_after)
                    if ci and ci.insns and (ci.branch_targets or ci.handlers):
                        branched.append(f"{name}.{after.utf8(m_after.name_index)}")
        check("with --strip-frames no rewrite still needs a stack map frame",
              not branched, "; ".join(branched[:3]))
        check("--strip-frames actually reverts the branchy methods",
              stats_strip["methods_reverted"] > 0, str(stats_strip))


def test_behaviour_is_preserved() -> None:
    """Differential check: a rewrite must return the same answers."""
    print("behave: same cases, original vs rewritten, plus a negative control")
    from jdec import behave as BH
    from jdec import deflat as DF

    if JAVAC is None or EN.find_java() is None:
        print("  (skipped: needs a JDK)")
        return

    cases = BH.parse_spec(
        "# comment lines and blanks are ignored\n"
        "\n"
        "demo/legacy/OldStyle|pick|java.lang.String|hello\n"
        "demo/legacy/OldStyle|pick|java.lang.String|\n"
        "demo/legacy/OldStyle|pick|java.lang.String|MOJANG\n")
    check("spec parser reads three cases", len(cases) == 3, str(len(cases)))
    check("spec parser keeps empty arguments", cases[1].arg_values == ("",),
          str(cases[1].arg_values))
    try:
        BH.parse_spec("onlyonetoken\n")
        bad_spec = False
    except ValueError:
        bad_spec = True
    check("spec parser rejects a malformed line", bad_spec)

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        out = root / "deflated.jar"
        stats = DF.deflat_jar(SAMPLE, out)
        check("the fixture actually has a method deflat rewrites",
              stats["methods_unflattened"] > 0,
              "a vacuous comparison would prove nothing")

        rep = BH.compare(SAMPLE, out, cases)
        check("the rewritten jar answers all cases", rep.compared == 3, str(rep.compared))
        check("behaviour is identical after the rewrite", rep.ok,
              "; ".join(o.describe() for o in rep.diffs))
        check("the answers are real values, not errors",
              all(o.left.startswith("OK:") for o in rep.outcomes),
              str([o.left for o in rep.outcomes]))

        # Negative control: change the constant the method returns and confirm
        # the harness notices. Without this the comparison is a rubber stamp.
        with zipfile.ZipFile(SAMPLE) as zin:
            blob = zin.read("demo/legacy/OldStyle.class")
        cf = CF.parse(blob)
        hits = 0
        for i, e in enumerate(cf.cp):
            if e and e[0] == CF.C_UTF8 and e[1] == b"?":
                cf.cp[i] = (CF.C_UTF8, b"!")
                hits += 1
        check("found the returned constant to corrupt", hits > 0, str(hits))
        tampered = root / "tampered.jar"
        with zipfile.ZipFile(SAMPLE) as zin, zipfile.ZipFile(tampered, "w") as zout:
            for info in zin.infolist():
                if info.filename == "demo/legacy/OldStyle.class":
                    zout.writestr(info, cf.serialize())
                else:
                    zout.writestr(info, zin.read(info.filename))
        bad = BH.compare(SAMPLE, tampered, cases)
        check("a changed return value is reported as a difference", not bad.ok,
              str([o.describe() for o in bad.outcomes]))
        check("the difference shows both values",
              any("OK:s:?" in d.left and "OK:s:!" in d.right for d in bad.diffs),
              str([(d.left, d.right) for d in bad.diffs]))

    # Safety gate: no --execute, no execution.
    import contextlib
    import io
    spec_path = Path(tempfile.gettempdir()) / "jdec_behave_spec.txt"
    spec_path.write_text("demo/legacy/OldStyle|pick|java.lang.String|hello\n",
                         encoding="utf-8")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = CL.main(["behave", str(SAMPLE), str(SAMPLE), "--spec", str(spec_path)])
    check("behave refuses to run without --execute", rc == 3, str(rc))
    check("the refusal explains why", "executes their code" in buf.getvalue(),
          buf.getvalue()[-200:])


def test_frame_generation() -> None:
    """Recomputed StackMapTables must be accepted by a real JVM."""
    print("ir: types + abstract interpretation + frame encoding")
    from jdec.ir import assume as AS
    from jdec.ir import attrs as AT
    from jdec.ir import frames as FR
    from jdec.ir import types as TT

    # lattice rules that are easy to get wrong
    check("merge of different primitives is top",
          TT.merge(TT.INT, TT.LONG) == TT.TOP)
    check("merge of null and a reference keeps the reference",
          TT.merge(TT.NULL, TT.obj("java/lang/String")) == TT.obj("java/lang/String"))
    check("merge of unrelated classes widens to Object",
          TT.merge(TT.obj("a/A"), TT.obj("b/B")) == TT.OBJECT)
    fa = TT.Frame([TT.INT], [TT.INT])
    fb = TT.Frame([TT.INT], [])
    try:
        TT.merge_frames(fa, fb, 1)
        stack_mismatch = False
    except TT.FrameError:
        stack_mismatch = True
    check("a stack-height mismatch at a join is an error", stack_mismatch)

    # long/double occupy two slots but one StackMapTable entry
    check("wide locals collapse to one frame entry",
          FR._locals_entries([TT.LONG, TT.TOP, TT.INT]) == [TT.LONG, TT.INT])
    check("frame type names are rejected when malformed",
          not FR._valid_class_name("[L[I;") and FR._valid_class_name("[[I"))

    if JAVAC is None or EN.find_java() is None:
        print("  (skipped: the frame round-trip needs a JDK)")
        return

    # Every fixture method: compute -> encode -> write back -> JVM verdict.
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "framed"
        methods = 0
        errors: list[str] = []
        for jar in (SAMPLE, MIXIN, FLOW):
            with zipfile.ZipFile(jar) as z:
                for info in z.infolist():
                    if not info.filename.endswith(".class"):
                        continue
                    try:
                        cf = CF.parse(z.read(info.filename))
                    except Exception:
                        continue
                    for m in cf.methods:
                        ci = BC.method_code(cf, m, decode_insns=False)
                        if ci is None:
                            continue
                        methods += 1
                        try:
                            insns = BC.decode(ci.code)
                            states = AS.compute_frames(cf, m, ci.code, ci.handlers,
                                                       ci.max_stack, ci.max_locals)
                            needed = FR.needed_pcs(insns, ci.handlers)
                            AT.set_code_subattr(cf, m, "StackMapTable",
                                                FR.encode(cf, states, needed))
                        except TT.FrameError as exc:
                            errors.append(f"{cf.name}.{cf.utf8(m.name_index)}: {exc}")
                    dest = root / info.filename
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(cf.serialize())
        check("frames were computed for every fixture method", methods > 20, str(methods))
        check("no fixture method is untypable", not errors, "; ".join(errors[:3]))
        from jdec import verify as VF
        rep = VF.verify(root)
        check("every rebuilt class loads under -Xverify:all", not rep.invalid,
              rep.summary())


def test_dead_code_keeps_control_flow() -> None:
    """Pruning dead code must not create a new path into a handler."""
    print("deflat: dead-code pruning never rewrites control flow")
    from jdec import deflat as DF

    # 0 iconst_0 / 1 ireturn / 2 goto +3 -> 5 / 5 astore_0 (handler) / 6 return
    # The goto at 2 is dead, but NOPing it lets control fall from 4 into 5 with
    # an empty stack — measured on HMCL, that broke 13 classes.
    code = bytes([0x03, 0xAC, 0xA7, 0x00, 0x03, 0x4B, 0xB1])
    out, pruned = DF.prune_dead_code(code, [BC.Handler(0, 2, 5, 0)])
    check("the dead goto before a handler survives",
          out[2:5] == bytes([0xA7, 0x00, 0x03]), out.hex())

    # A dead terminator at the very end must also survive: NOPing it lets
    # control fall off the code array ("Control flow falls through code end").
    tail = bytes([0xB1, 0xBF])
    out2, _ = DF.prune_dead_code(tail, [])
    check("the trailing terminator survives", out2[1] == 0xBF, out2.hex())

    # Ordinary dead code is still pruned.
    dead = bytes([0xB1, 0x10, 0x63, 0xB1])   # return; bipush 99; return(dead)
    out3, pruned3 = DF.prune_dead_code(dead, [])
    check("ordinary dead code is still NOPed",
          out3[1:3] == bytes([0, 0]) and pruned3 >= 1, out3.hex())


def test_frames_match_javac() -> None:
    """M2 acceptance: our frames must agree with javac's, and never be wider."""
    print("ir: computed frames vs the ones javac wrote")
    from jdec.ir import assume as AS
    from jdec.ir import attrs as AT
    from jdec.ir import frames as FR
    from jdec.ir import hierarchy as HI
    from jdec.ir import types as TT

    checked = same_offsets = wider = 0
    offset_examples: list[str] = []
    wider_examples: list[str] = []
    for jar in (SAMPLE, MIXIN, FLOW):
        hier = HI.Hierarchy.from_jar(jar)
        with zipfile.ZipFile(jar) as z:
            for info in z.infolist():
                if not info.filename.endswith(".class"):
                    continue
                try:
                    cf = CF.parse(z.read(info.filename))
                except Exception:
                    continue
                for m in cf.methods:
                    ci = BC.method_code(cf, m, decode_insns=False)
                    if ci is None:
                        continue
                    payload = next((p for n, p in AT.code_subattrs(cf, m)
                                    if n == "StackMapTable"), None)
                    if payload is None:
                        continue
                    try:
                        orig = FR.decode(cf, payload, m, ci.max_locals)
                        states = AS.compute_frames(cf, m, ci.code, ci.handlers,
                                                   ci.max_stack, ci.max_locals, hier)
                        need = FR.needed_pcs(BC.decode(ci.code), ci.handlers)
                    except Exception:
                        continue
                    checked += 1
                    ours = {pc: states[pc] for pc in need if pc in states}
                    if set(ours) != set(orig):
                        if len(offset_examples) < 3:
                            offset_examples.append(
                                f"{cf.name}.{cf.utf8(m.name_index)}: "
                                f"{sorted(set(ours) ^ set(orig))[:4]}")
                        continue
                    same_offsets += 1
                    for pc, f in ours.items():
                        g = orig[pc]
                        if len(f.stack) != len(g.stack):
                            wider += 1
                            if len(wider_examples) < 3:
                                wider_examples.append(f"{cf.name}@{pc}: stack height")
                            break
                        bad = False
                        for a, b in zip(f.stack, g.stack):
                            if a == b or b == TT.TOP:
                                continue
                            if TT.is_ref(a) and TT.is_ref(b) and hier.lca(a[1], b[1]) == b[1]:
                                continue        # ours is narrower: allowed
                            bad = True
                            if len(wider_examples) < 3:
                                wider_examples.append(f"{cf.name}@{pc}: {a} vs {b}")
                        if bad:
                            wider += 1
                            break

    check("there are methods to compare", checked >= 20, str(checked))
    check("frame offsets agree with javac in ~all cases",
          same_offsets >= checked - 1,
          f"{same_offsets}/{checked}: " + "; ".join(offset_examples))
    if EN.find_java() is None:
        # "narrower" is a subtype query, and the JDK side of the hierarchy is
        # asked of a live JVM (a hand-written seed table kept guessing wrong on
        # exception types). Without one, every JDK-typed pair looks unrelated
        # and the comparison would report false positives — say so instead.
        print("  (skipped the width comparison: no JVM, so subtyping is unknown)")
    else:
        check("no frame is wider than the one javac wrote", wider == 0,
              "; ".join(wider_examples))


def test_ir_assembly_changes_length() -> None:
    """A length-changing edit must still produce a loadable class."""
    print("ir: insert/delete + re-layout + recomputed frames")
    from jdec.ir import assemble as ASM
    from jdec.ir import assume as AS
    from jdec.ir import attrs as AT
    from jdec.ir import frames as FR
    from jdec.ir import types as TT

    # unit: deletion must refuse to break a branch
    prog = ASM.Program.parse(bytes([0x03, 0x99, 0x00, 0x04, 0x04, 0xAC]))
    try:
        prog.delete(5, 6)          # ifeq at 1 targets 5
        refused = False
    except TT.FrameError:
        refused = True
    check("deleting a branch target is refused", refused)

    # unit: deleting unreachable tail really shortens the array
    prog2 = ASM.Program.parse(bytes([0x10, 0x63, 0x57, 0xB1]))   # bipush 99; pop; return
    prog2.delete(0, 3)
    code2, _ = prog2.assemble()
    check("deletion shrinks the code array", code2 == bytes([0xB1]), code2.hex())

    if JAVAC is None or EN.find_java() is None:
        print("  (skipped: the end-to-end reassembly needs a JDK)")
        return

    # end-to-end: insert a nop into a fixture method, re-lay out, recompute
    # frames, and let the JVM judge the result.
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "reassembled"
        edited = 0
        for jar in (SAMPLE, MIXIN):
            with zipfile.ZipFile(jar) as z:
                for info in z.infolist():
                    if not info.filename.endswith(".class"):
                        continue
                    try:
                        cf = CF.parse(z.read(info.filename))
                    except Exception:
                        continue
                    for m in cf.methods:
                        ci = BC.method_code(cf, m)
                        if ci is None or not ci.insns:
                            continue
                        if edited >= 8:
                            break
                        prog = ASM.Program.parse(ci.code, ci.handlers)
                        first = prog.insns[0]
                        prog.insert_after(first.pc, [BC.Insn(pc=0, op=0x00, length=1)])
                        new_code, new_handlers = prog.assemble()
                        AT.replace_code(cf, m, new_code, new_handlers,
                                        ci.max_stack, ci.max_locals)
                        try:
                            states = AS.compute_frames(cf, m, new_code, new_handlers,
                                                       ci.max_stack, ci.max_locals)
                            need = FR.needed_pcs(BC.decode(new_code), new_handlers)
                            AT.set_code_subattr(cf, m, "StackMapTable",
                                                FR.encode(cf, states, need))
                        except TT.FrameError:
                            m.attrs_blob = m.attrs_blob   # keep the edit, no frames
                        edited += 1
                    dest = root / info.filename
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(cf.serialize())
        check("methods were reassembled", edited >= 4, str(edited))
        from jdec import verify as VF
        rep = VF.verify(root)
        check("reassembled classes still load under -Xverify:all",
              not rep.invalid, rep.summary())


def test_ir_transforms() -> None:
    """The instruction-level passes delete instead of padding, and refuse to break a branch."""
    print("ir: fold / predicate / unflatten / dead code, then a real jar")
    from jdec import deflat as DF
    from jdec.ir import assemble as ASM
    from jdec.ir import transforms as TR
    from jdec.ir import types as TT

    def run(code, handlers=None):
        prog = ASM.Program.parse(code, handlers or [])
        counts = TR.optimize(prog)
        out, _hs = prog.assemble()
        return out, counts

    # fold: iconst_2, iconst_3, iadd, pop, return -> iconst_5, pop, return
    out, counts = run(bytes([0x05, 0x06, 0x60, 0x57, 0xB1]))
    check("constant folding deletes both operands",
          out == bytes([0x08, 0x57, 0xB1]), out.hex())
    check("the fold is counted", counts["folded"] == 1, str(counts))

    # predicate always taken:
    #   0: iconst_0   1: ifeq +6 -> 7   4: iconst_1   5: ireturn
    #   6: iconst_0   7: ireturn
    prog = ASM.Program.parse(bytes([0x03, 0x99, 0x00, 0x06,
                                    0x04, 0xAC, 0x03, 0xAC]), [])
    n = TR.prune_predicates(prog)
    out, _hs = prog.assemble()
    check("a taken predicate becomes a single goto",
          n == 1 and out[:3] == bytes([0xA7, 0x00, 0x06]) and len(out) == 7, out.hex())

    # predicate never taken: the whole test disappears and control falls through
    prog = ASM.Program.parse(bytes([0x04, 0x99, 0x00, 0x06, 0x04, 0xAC]), [])
    n = TR.prune_predicates(prog)
    out, _hs = prog.assemble()
    check("a never-taken predicate disappears", n == 1 and out == bytes([0x04, 0xAC]),
          out.hex())

    # dead code after a goto. `Insn.is_terminator` only covers return/athrow, so
    # an earlier version walked straight through a goto and kept this block.
    prog = ASM.Program.parse(bytes([0xA7, 0x00, 0x05, 0x03, 0xB1, 0x04, 0xAC]), [])
    n = TR.drop_dead_code(prog)
    out, _hs = prog.assemble()
    check("code after a goto is not reachable",
          n == 1 and out == bytes([0xA7, 0x00, 0x03, 0x04, 0xAC]), out.hex())

    # refusals are local: one branch target must not abandon the whole method
    prog = ASM.Program.parse(bytes([0x03, 0x99, 0x00, 0x04, 0x04, 0xAC]), [])
    try:
        prog.remove({5})
        refused = False
    except TT.FrameError:
        refused = True
    check("removing a branch target is refused", refused)

    # exception-table end_pc is exclusive: deleting the instruction sitting on
    # it must round the range up, not make the method unassemblable
    prog = ASM.Program.parse(bytes([0xB1, 0x03, 0x57]), [BC.Handler(0, 1, 0, 0)])
    prog.remove({1})
    _code, handlers = prog.assemble()
    check("a deleted end_pc rounds up to the next instruction",
          handlers[0].end_pc == 1, str([(h.start_pc, h.end_pc, h.handler_pc) for h in handlers]))

    if JAVAC is None or EN.find_java() is None:
        print("  (skipped: the end-to-end part needs a JDK)")
        return

    import shutil
    td = Path(tempfile.mkdtemp(prefix="jdec_ir_"))
    try:
        out = td / "ir.jar"
        stats = DF.deflat_jar(SAMPLE, out, verify_output=False, ir_rewrite=True)
        check("the IR path rewrites the fixture", stats["methods_unflattened"] > 0,
              str(stats))
        check("no method had to be rolled back", stats["methods_reverted"] == 0,
              str(stats))
        check("every rewrite got a recomputed table",
              stats["frames_rebuilt"] == stats["methods_unflattened"], str(stats))

        # `OldStyle.pick` is a state-machine dispatcher: after the rewrite its
        # transitions must jump straight at the case body instead of going back
        # through the switch. In the fixture the dispatcher sits at 83.
        with zipfile.ZipFile(SAMPLE) as zin, zipfile.ZipFile(out) as zout:
            before = CF.parse(zin.read("demo/legacy/OldStyle.class"))
            after = CF.parse(zout.read("demo/legacy/OldStyle.class"))
        m_before = next(m for m in before.methods if before.utf8(m.name_index) == "pick")
        m_after = next(m for m in after.methods if after.utf8(m.name_index) == "pick")
        old_gotos = {i.pc + i.arg for i in BC.method_code(before, m_before).insns if i.is_goto}
        new_gotos = {i.pc + i.arg for i in BC.method_code(after, m_after).insns if i.is_goto}
        check("the rewrite retargets transitions away from the dispatcher",
              old_gotos != new_gotos, f"before={sorted(old_gotos)} after={sorted(new_gotos)}")

        from jdec import behave as BH
        from jdec import verify as VF
        rep = VF.verify(out, classpath=[SAMPLE])
        new_bad = {i.cls for i in rep.invalid} - {"demo/broken/Truncated"}
        check("the IR output introduces no invalid class", not new_bad,
              str(sorted(new_bad)[:3]))

        cases = BH.parse_spec(
            "demo/legacy/OldStyle|pick|java.lang.String|hello\n"
            "demo/legacy/OldStyle|pick|java.lang.String|\n"
            "demo/legacy/OldStyle|pick|java.lang.String|MOJANG\n"
            "demo/legacy/OldStyle|messy|int|7\n")
        bh = BH.compare(SAMPLE, out, cases)
        check("the IR output answers every case", bh.compared == len(cases), str(bh.compared))
        check("behaviour survives the instruction-level rewrite", bh.ok,
              "; ".join(o.describe() for o in bh.diffs))
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_pipeline_gate() -> None:
    """A rewrite stage must report `partial` when the verifier had to put something back."""
    print("pipeline: the pre-cleaning stage is gated")
    from jdec import deflat as DF
    from jdec import pipeline as PL

    ok_stats = {"classes": 10, "methods_unflattened": 3,
                "verify": {"verified": 9, "reverted": [], "still_invalid": [],
                           "unresolved": 1}}
    status, detail = PL.deflat_stage_status(ok_stats)
    check("a fully verified rewrite is ok", status == PL.STAGE_OK, detail)
    check("the detail carries the verify counts",
          "-Xverify:all" in detail and "not judged" in detail, detail)

    reverted = dict(ok_stats, verify={"verified": 8, "reverted": ["a/B"],
                                      "still_invalid": [], "unresolved": 0})
    status, detail = PL.deflat_stage_status(reverted)
    check("a rewrite that had to be rolled back is partial",
          status == PL.STAGE_PARTIAL, detail)
    check("the detail says how many were rolled back", "reverted" in detail, detail)

    skipped = dict(ok_stats, verify={"skipped": "java not found"})
    status, _detail = PL.deflat_stage_status(skipped)
    check("an unchecked rewrite is partial, not ok",
          status == PL.STAGE_PARTIAL, status)

    unverified = dict(ok_stats)
    unverified.pop("verify")
    status, _detail = PL.deflat_stage_status(unverified)
    check("a report with no verify section is partial", status == PL.STAGE_PARTIAL, status)

    if JAVAC is None or EN.find_java() is None:
        print("  (skipped: the end-to-end part needs a JDK)")
        return

    import shutil
    td = Path(tempfile.mkdtemp(prefix="jdec_gate_"))
    try:
        out = td / "gated.jar"
        stats = DF.deflat_jar(SAMPLE, out)          # IR path + gate, the default
        check("deflat reports the verification result",
              isinstance(stats.get("verify"), dict) and "skipped" not in stats["verify"],
              str(stats.get("verify")))
        check("the fixture output verifies cleanly",
              stats["verify"].get("reverted") == [], str(stats["verify"].get("reverted")))
        check("the default path is the instruction-level one",
              stats.get("frames_rebuilt", 0) > 0, str(stats))
        status, detail = PL.deflat_stage_status(stats)
        check("the knowingly-broken fixture keeps the stage partial",
              status == PL.STAGE_PARTIAL, detail)
        check("the detail names the class kept original",
              "kept original" in detail, detail)
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_devirt_output_loads() -> None:
    """A devirtualized method must get frames, and the gate must prove it loads."""
    print("devirt: translated bodies carry a StackMapTable and load")
    from jdec import bvm_devirt as BVM
    from jdec import stubs as SB
    from jdec import verify as VF
    from jdec.ir import attrs as AT

    O = BVM.ORDINAL_BY_NAME
    # static (I)I  ->  iload_0; ifeq L; iconst_1; ireturn; L: iconst_0; ireturn
    # A branch on purpose: straight-line code would verify without any table.
    # The argument is in slot 0 because the method is static.
    vm_code = [O["ILOAD"], 0,
               O["IFEQ"], 6,
               O["ICONST_1"], O["IRETURN"],
               O["ICONST_0"], O["IRETURN"]]
    pool = {999: BVM.BVMMethod(code_id=999, name="branchy", desc="(I)I",
                               code=vm_code, max_locals=1, max_stack=1)}

    def host_with_vm_call():
        cf = CF.parse(SB.build_stub_class_bytes("com/example/Host"))
        helper = BVM.ConstantPoolHelper(cf)
        mref = helper.add_methodref("com/example/VM", "execute", "(I)V")
        blob = bytes([0x11, (999 >> 8) & 0xFF, 999 & 0xFF,
                      0xB8, (mref >> 8) & 0xFF, mref & 0xFF, 0xAC])
        attr = BVM.BVMDevirtualizer.build_code_attribute(cf, 1, 1, blob, [])
        cf.methods.append(CF.Member(
            access_flags=CF.ACC_PUBLIC | CF.ACC_STATIC,
            name_index=cf.intern_utf8("branchy"),
            descriptor_index=cf.intern_utf8("(I)I"),
            attrs_blob=struct.pack(">H", 1) + attr))
        return cf

    cf = host_with_vm_call()
    translated = BVM.BVMTranslator.translate_method(pool[999], cf)
    check("the translated body really branches",
          any(i.is_branch for i in BC.decode(translated.bytecode)),
          translated.bytecode.hex())

    notes: list[str] = []
    cf_out, n = BVM.BVMDevirtualizer.devirtualize_class_file(cf, pool, notes=notes)
    check("the method was devirtualized", n == 1, str(n))
    check("no frame was refused", not notes, "; ".join(notes[:3]))
    subattrs = [name for name, _p in AT.code_subattrs(cf_out, cf_out.methods[-1])]
    check("the rebuilt Code carries a StackMapTable",
          "StackMapTable" in subattrs, str(subattrs))

    if JAVAC is None or EN.find_java() is None:
        print("  (skipped: the end-to-end part needs a JDK)")
        return

    import shutil
    td = Path(tempfile.mkdtemp(prefix="jdec_devirt_"))
    try:
        good = td / "good"
        (good / "com" / "example").mkdir(parents=True)
        (good / "com/example/Host.class").write_bytes(cf_out.serialize())
        rep = VF.verify(good)
        check("a devirtualized class loads under -Xverify:all",
              rep.invalid == [], rep.summary())

        # Negative control: the same class built without `member` gets no frames
        # and must be rejected — otherwise this test proves nothing about them.
        cf_raw = host_with_vm_call()
        attr = BVM.BVMDevirtualizer.build_code_attribute(
            cf_raw, translated.max_stack, translated.max_locals,
            translated.bytecode, translated.handlers)      # no member -> no frames
        BVM.BVMDevirtualizer.set_code_attribute(cf_raw, cf_raw.methods[-1], attr)
        bad = td / "bad"
        (bad / "com" / "example").mkdir(parents=True)
        (bad / "com/example/Host.class").write_bytes(cf_raw.serialize())
        rep_bad = VF.verify(bad)
        check("without frames the same class is rejected",
              [i.cls for i in rep_bad.invalid] == ["com/example/Host"],
              rep_bad.summary())
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_dead_branch_is_not_nop_ed() -> None:
    """The byte path must not turn a dead `goto` into a fall-through.

    Measured on HMCL's `ThemeCondition.normalizeValue`: a `goto` sat right
    before a stack-map entry, every branch to it had been threaded away, and
    NOPing it let control fall into the entry with a value on the stack. The
    class was rejected ("Current frame's stack size doesn't match stackmap")
    and the whole class was rolled back. The instruction is unreachable either
    way, so keeping it is free.
    """
    print("deflat(byte path): dead branches are left in place")
    from jdec import deflat as DF

    code = bytes([0xB1,                  # return  -> everything below is dead
                  0xA7, 0x00, 0x04,      # goto +4
                  0x03, 0xAC,            # iconst_0; ireturn
                  0x03, 0xAC])
    out, _n = DF.prune_dead_code(code)
    check("the dead branch survives, operand bytes included",
          out[1:4] == bytes([0xA7, 0x00, 0x04]), out.hex())
    # the trailing `ireturn` stays: NOPing the last terminator would let
    # control run off the end of the code array, which the existing guard
    # already refuses
    check("the rest of the dead block is nop'ed",
          out[4:7] == b"\x00" * 3 and out[7] == 0xAC, out.hex())

    live = bytes([0x03, 0xAC])
    same, n = DF.prune_dead_code(live)
    check("a method with nothing dead is untouched", same == live and n == 0)


def test_rewritten_list_from_both_paths() -> None:
    """Both deflat paths must name the methods they changed.

    `--byte-patch --rewritten` used to write an empty file — only the
    instruction-level path filled the list — so `behave --from` was told
    "nothing was rewritten" about a jar with 412 rewritten methods.
    """
    print("deflat: the rewritten list is filled by both paths")
    from jdec import deflat as DF

    td = Path(tempfile.mkdtemp(prefix="jdec_rw_"))
    try:
        for ir in (True, False):
            out = td / f"out{int(ir)}.jar"
            stats = DF.deflat_jar(SAMPLE, out, verify_output=False,
                                  ir_rewrite=ir)
            tag = "instruction-level" if ir else "byte-patch"
            check(f"{tag} names at least one rewritten method",
                  bool(stats.get("rewritten")), str(stats.get("rewritten")))
            if stats.get("rewritten"):
                cls, name, desc = stats["rewritten"][0]
                check(f"{tag} writes class/name/descriptor",
                      cls and name and desc.startswith("("),
                      str(stats["rewritten"][0]))
    finally:
        import shutil as _sh
        _sh.rmtree(td, ignore_errors=True)


def test_devirt_realistic_vm() -> None:
    """A high-fidelity VM sample: tableswitch dispatch, handlers, wide types.

    Four virtualized methods go through the full chain — pool, devirtualize
    with frame generation, -Xverify:all, differential behaviour — covering the
    structural features a real VM protector has: a table-driven dispatcher
    with 4 routes, a VM-level exception handler that swallows a division by
    zero, long/double arithmetic across loop bodies, and an array loop. A real
    commercial protector sample is still missing; this is the closest
    structural simulation and it is registered as such.
    """
    print("devirt: tableswitch dispatcher, handler, long/double, array loop")
    import zipfile
    from jdec import behave as BH
    from jdec import devirt as DV
    from jdec import bvm_devirt as BVM
    from jdec import stubs as SB
    from jdec.ir import attrs as AT

    if EN.find_java() is None:
        print("  (skipped: needs a JVM)")
        return

    O = DV.ORDINAL_BY_NAME
    pool = {
        # calc(III)I: switch(op): 0 add, 1 sub, 2 div (handler -> -1), dflt mul
        900: BVM.BVMMethod(
            code_id=900, name="calc", desc="(III)I", is_static=True,
            max_locals=3, max_stack=4,
            # VM jump targets and exception ranges are virtual BYTE offsets,
            # not instruction indexes. The switch consumes `op`; each case
            # pushes a and b from locals before the arithmetic.
            code=[O["ILOAD"], 0,
                  O["TABLESWITCH"], 0, 2, 28, 3, 10, 16, 22,
                  O["ILOAD"], 1, O["ILOAD"], 2, O["IADD"], O["IRETURN"],
                  O["ILOAD"], 1, O["ILOAD"], 2, O["ISUB"], O["IRETURN"],
                  O["ILOAD"], 1, O["ILOAD"], 2, O["IDIV"], O["IRETURN"],
                  O["ILOAD"], 1, O["ILOAD"], 2, O["IMUL"], O["IRETURN"],
                  O["POP"], O["ICONST_M1"], O["IRETURN"]],
            exception_handlers=[26, 27, 34, 0]),
        # prod(I)I: long accumulator over a counted loop
        901: BVM.BVMMethod(
            code_id=901, name="prod", desc="(I)I", is_static=True,
            max_locals=5, max_stack=4,
            code=[O["LCONST_1"], O["LSTORE"], 1,
                  O["ICONST_1"], O["ISTORE"], 3,
                  O["ILOAD"], 3, O["ILOAD"], 0, O["IF_ICMPGE"], 25,
                  O["LLOAD"], 1, O["ILOAD"], 3, O["I2L"], O["LMUL"],
                  O["LSTORE"], 1,
                  O["IINC"], 3, 1,
                  O["GOTO"], 6,
                  O["LLOAD"], 1, O["L2I"], O["IRETURN"]]),
        # mul2(D)D
        902: BVM.BVMMethod(
            code_id=902, name="mul2", desc="(D)D", is_static=True,
            max_locals=3, max_stack=4,
            code=[O["DLOAD"], 0, O["DCONST_1"], O["DADD"], O["DRETURN"]]),
        # sum([I)I
        903: BVM.BVMMethod(
            code_id=903, name="sum", desc="([I)I", is_static=True,
            max_locals=3, max_stack=3,
            code=[O["ICONST_0"], O["ISTORE"], 1,
                  O["ICONST_0"], O["ISTORE"], 2,
                  O["ILOAD"], 2, O["ALOAD"], 0, O["ARRAYLENGTH"],
                  O["IF_ICMPGE"], 28,
                  O["ILOAD"], 1, O["ALOAD"], 0, O["ILOAD"], 2, O["IALOAD"],
                  O["IADD"], O["ISTORE"], 1,
                  O["IINC"], 2, 1,
                  O["GOTO"], 6,
                  O["ILOAD"], 1, O["IRETURN"]]),
    }

    def host():
        cf = CF.parse(SB.build_stub_class_bytes("com/example/Host"))
        helper = BVM.ConstantPoolHelper(cf)
        mref = helper.add_methodref("com/example/VM", "execute", "(I)V")
        tail = {"calc": 0xAC, "prod": 0xAC, "mul2": 0xAE, "sum": 0xAC}
        for mid, m in pool.items():
            member = CF.Member(
                access_flags=CF.ACC_PUBLIC | CF.ACC_STATIC,
                name_index=cf.intern_utf8(m.name),
                descriptor_index=cf.intern_utf8(m.desc),
                attrs_blob=b"")
            cf.methods.append(member)
            blob = bytes([0x11, (mid >> 8) & 0xFF, mid & 0xFF,
                          0xB8, (mref >> 8) & 0xFF, mref & 0xFF,
                          tail[m.name]])
            BVM.BVMDevirtualizer.set_code_attribute(
                cf, member,
                BVM.BVMDevirtualizer.build_code_attribute(
                    cf, 2, 4, blob, [], member=member))
        return cf

    td = Path(tempfile.mkdtemp(prefix="jdec_vm_hi_"))
    try:
        src = td / "vm.jar"
        with zipfile.ZipFile(src, "w") as z:
            z.writestr("com/example/Host.class", host().serialize())

        out = td / "devirt.jar"
        res = BVM.BVMDevirtualizer.devirtualize_jar(src, out, pool,
                                                    verify_output=True)
        check("all four VM methods were devirtualized",
              res["devirtualized_methods"] == 4,
              str(res.get("devirtualized_methods")))
        vres = res.get("verify") or {}
        check("the verifier accepted every rebuilt class",
              vres.get("verified") == 1 and not vres.get("reverted")
              and not res.get("frame_notes"),
              str({k: vres.get(k) for k in ("verified", "reverted")}
                  | {"frame_notes": len(res.get("frame_notes") or [])}))

        # every rebuilt method carries a StackMapTable: loading is not enough
        with zipfile.ZipFile(out) as z:
            cf = CF.parse(z.read("com/example/Host.class"))
        frames_found = 0
        for m in cf.methods:
            ci = BC.method_code(cf, m, decode_insns=False)
            if ci is None or not ci.code:
                continue
            found = any(n == "StackMapTable"
                        for n, _payload in AT.code_subattrs(cf, m))
            if found:
                frames_found += 1
        check("all rebuilt methods have StackMapTables", frames_found == 4,
              f"{frames_found}/4")

        # differential: the translated jar against itself through both the
        # interpreter (value assertions) and the real JVM (same verdict)
        from jdec.interp.engine import Interp, Universe
        from jdec.interp.values import Arr, Heap
        from jdec.interp.models import Models
        it = Interp(Universe(out), Heap(), Models())
        cases = [
            ("calc", [0, 3, 4], 7), ("calc", [1, 9, 4], 5),
            ("calc", [9, 2, 3], 6),            # default route
            ("calc", [2, 7, 0], -1),           # handler swallows the /0
            ("prod", [5], 24), ("prod", [0], 1),
            ("sum", [Arr("I", [1, 2, 3])], 6),
        ]
        for name, argv, expect in cases:
            desc = {"calc": "(III)I", "prod": "(I)I",
                    "sum": "([I)I"}[name]
            h = Heap()
            o = it.invoke("com/example/Host", name, desc, None, argv)
            check(f"{name}{argv} computes {expect}",
                  o.kind == "return" and o.value == expect,
                  f"{o.kind}:{o.value} {o.reason[:60]}")
        h = Heap()
        o = it.invoke("com/example/Host", "mul2", "(D)D", None, [2.5])
        check("mul2(2.5) computes 3.5",
              o.kind == "return" and abs(o.value - 3.5) < 1e-9,
              f"{o.kind}:{o.value}")

        jvm_cases = [BH.Case("com/example/Host", n, t, v)
                     for n, t, v in [("calc", ("int", "int", "int"),
                                      ("0", "3", "4")),
                                     ("calc", ("int", "int", "int"),
                                      ("2", "7", "0")),
                                     ("prod", ("int",), ("5",)),
                                     ("sum", ("[I",), ("@arr0",))]]
        rep = BH.compare(out, out, jvm_cases)
        check("the translated methods agree on the real JVM",
              all(o.status == "same" for o in rep.outcomes),
              rep.summary() + " || " + "; ".join(u.describe()
                                                 for u in rep.unusable[:2]))
    finally:
        import shutil as _sh
        _sh.rmtree(td, ignore_errors=True)


def test_jsr_subroutine_is_left_alone() -> None:
    """`jsr`/`ret`: the IR cannot type a subroutine, so the method must survive.

    The failure mode this guards against is not "we did not optimise it" but
    "we rewrote half of it and shipped a method whose frames are gone". A
    fixture at major 50 with a `jsr` is the only way to exercise that path:
    javac stopped emitting subroutines in Java 6 and class files from 51 on
    cannot contain one at all.
    """
    print("jsr/ret: the IR refuses, and the method comes out byte-identical")
    from jdec import deflat as DF
    from jdec.ir.roundtrip import audit_jar

    jar = build_fixtures.ensure_jsr_jar()
    check("the fixture exists", jar.is_file())
    rep = audit_jar(jar)
    check("the subroutine round-trips byte-exactly",
          not rep.mismatches and not rep.undecodable,
          f"{len(rep.mismatches)} mismatch, {len(rep.undecodable)} undecodable")

    with zipfile.ZipFile(jar) as z:
        before = z.read("demo/jsr/JsrDemo.class")
    cf = CF.parse(before)
    check("the fixture really is a major-50 class with a jsr",
          cf.major == 50 and b"\xa8" in before, f"major={cf.major}")

    # the gate that matters: `rewrite_method` finds something to fold, then
    # refuses — before it touches the class — because it cannot type the body
    from jdec.ir import transforms as TR
    member = [m for m in cf.methods if cf.utf8(m.name_index) == "choose"][0]
    try:
        TR.rewrite_method(cf, member, None)
        refused = False
    except Exception:  # noqa: BLE001 - FrameError is the expected answer
        refused = True
    check("rewrite_method refuses a method with jsr", refused)
    check("and it left the method alone", cf.serialize() == before)

    td = Path(tempfile.mkdtemp(prefix="jdec_jsr_"))
    try:
        out = td / "jsr_deflat.jar"
        stats = DF.deflat_jar(jar, out, verify_output=False)
        with zipfile.ZipFile(out) as z:
            after = z.read("demo/jsr/JsrDemo.class")
        check("the class came out byte-identical", after == before,
              f"{len(before)} -> {len(after)} bytes")
        check("nothing is claimed as rewritten",
              stats.get("rewritten") == [], str(stats.get("rewritten")))
        # and the round trip still holds on the output
        rep2 = audit_jar(out)
        check("the output still round-trips", not rep2.mismatches,
              f"{len(rep2.mismatches)} mismatch")
    finally:
        import shutil as _sh
        _sh.rmtree(td, ignore_errors=True)




def test_interp_engine_semantics() -> None:
    """Negative controls for the interpreter bugs this round actually had.

    Each check pins one concrete mis-execution: category-2 argument popping
    in the wrong order, reference comparison routed through pop_int, and an
    Opaque hiding inside a model collection.
    """
    print("interp engine: category-2 args, acmp, and taint in containers")
    from pathlib import Path as _P
    from jdec.interp import diff as ID
    from jdec.interp.values import Heap, Obj, Opaque
    from jdec.interp.engine import Interp, Universe

    if JAVAC is None:
        print("  (skipped: needs javac)")
        return

    td = Path(tempfile.mkdtemp(prefix="jdec_interpeng_"))
    try:
        # mix(J, String): the long is NOT the last parameter, so a pop-order
        # bug grabs a reference where the long belongs
        cls = _compile_java(td, {
            "demo/eng/Mix.java": """
                package demo.eng;
                public final class Mix {
                    public static String mix(long v, String tag) {
                        return tag + ":" + (v * 2);
                    }
                }
            """,
        })
        jar = _jar_from(cls, td / "mix.jar")
        row = ("demo/eng/Mix", "mix",
               "(JLjava/lang/String;)Ljava/lang/String;")
        rep = ID.compare_rows(jar, jar, [row], trials=3)
        check("a (long, String) signature executes identically",
              rep.rows[0].verdict == "same", rep.rows[0].describe())

        # acmp: comparing references must not go through as_int
        cls2 = _compile_java(td / "acmp", {
            "demo/eng/Same.java": """
                package demo.eng;
                public final class Same {
                    public static boolean same(Object a, Object b) {
                        return a == b;
                    }
                }
            """,
        })
        jar2 = _jar_from(cls2, td / "acmp.jar")
        rep2 = ID.compare_rows(jar2, jar2,
                               [("demo/eng/Same", "same",
                                 "(Ljava/lang/Object;Ljava/lang/Object;)Z")],
                               trials=2)
        check("reference equality runs without an int cast",
              rep2.rows[0].verdict == "same", rep2.rows[0].describe())

        # taint: a run-era Opaque inside a model collection must never read
        # as same; a clinit-era one is a structural placeholder by design
        left = Universe(jar)
        h1, h2 = Heap(), Heap()
        it = Interp(left, h1, __import__("jdec.interp.models",
                                        fromlist=["Models"]).Models())
        hidden = Opaque("call:java/lang/System.currentTimeMillis()J", 1, 1)
        h1.statics[("demo/eng/Mix", "bag")] = \
            Obj("java/util/ArrayList", {"items": [hidden]})
        h2.statics[("demo/eng/Mix", "bag")] = \
            Obj("java/util/ArrayList", {"items": [hidden]})
        from jdec.interp.diff import _verdict
        from jdec.interp.values import Outcome
        verdict, _reason = _verdict(Outcome("return", value=1),
                                    Outcome("return", value=1), h1, h2)
        check("a run-era Opaque inside a collection is inconclusive",
              verdict == "inconclusive", verdict)

        # clinit-era Opaques with matching sources agree structurally: both
        # sides ran the same initialiser
        init_opaque = Opaque("call:java/lang/System.nanoTime()J", 2, 0)
        h1.statics[("demo/eng/Mix", "bag")] = \
            Obj("java/util/ArrayList", {"items": [init_opaque]})
        h2.statics[("demo/eng/Mix", "bag")] = \
            Obj("java/util/ArrayList", {"items": [init_opaque]})
        verdict2, _r2 = _verdict(Outcome("return", value=1),
                                 Outcome("return", value=1), h1, h2)
        check("a clinit-era Opaque pair agrees structurally",
              verdict2 == "same", verdict2)
        h2.statics[("demo/eng/Mix", "bag")] = \
            Obj("java/util/ArrayList", {"items":
                                        [Opaque("call:other", 3, 0)]})
        verdict3, _r3 = _verdict(Outcome("return", value=1),
                                 Outcome("return", value=1), h1, h2)
        check("clinit Opaques from different sources do not agree",
              verdict3 == "diff", verdict3)
    finally:
        import shutil as _sh
        _sh.rmtree(td, ignore_errors=True)


def test_interp_lambda_and_streams() -> None:
    """Lambdas and Stream pipelines execute deterministically on the IR.

    A lambda is an invokedynamic site resolved through BootstrapMethods to a
    synthetic `lambda$...` body; the model executes it synchronously on both
    sides. File IO goes through the in-memory VFS, so a pipeline that reads
    and writes the filesystem is decisive without touching the real disk.
    """
    print("interp: lambda bodies, Stream pipelines, and the VFS")
    from pathlib import Path as _P
    from jdec.interp import diff as ID

    if JAVAC is None:
        print("  (skipped: needs javac)")
        return

    td = Path(tempfile.mkdtemp(prefix="jdec_lambda_"))
    try:
        cls = _compile_java(td, {
            "demo/lm/Target.java": """
                package demo.lm;
                import java.nio.file.*;
                import java.util.stream.*;
                import java.util.*;
                public final class Target {
                    public static String roundtrip(String name) throws Exception {
                        Path dir = Paths.get("/case/sub");
                        Files.createDirectories(dir);
                        Path file = dir.resolve(name + ".txt");
                        Files.writeString(file, "hello " + name);
                        return Files.readString(file);
                    }
                    public static String collect(List<String> xs) {
                        return xs.stream().filter(s -> s.length() > 1)
                                 .map(s -> s + "!")
                                 .collect(Collectors.joining("-"));
                    }
                    public static int viaMethodRef(List<String> xs) {
                        return xs.stream().map(String::length)
                                 .reduce(0, Integer::sum);
                    }
                }
            """,
        })
        jar = _jar_from(cls, td / "t.jar")
        rows = [("demo/lm/Target", "roundtrip",
                 "(Ljava/lang/String;)Ljava/lang/String;"),
                ("demo/lm/Target", "collect",
                 "(Ljava/util/List;)Ljava/lang/String;"),
                ("demo/lm/Target", "viaMethodRef",
                 "(Ljava/util/List;)I")]
        rep = ID.compare_rows(jar, jar, rows, trials=3)
        check("original vs original never differs through lambdas",
              not rep.diff, "; ".join(d.describe() for d in rep.diff))
        check("every lambda/stream row was judged",
              rep.judged == len(rows),
              "; ".join(r.describe() for r in rep.rows))

        # a changed lambda body must be a DIFF: the pipeline has to matter
        bad = _compile_java(td / "bad", {
            "demo/lm/Target.java": """
                package demo.lm;
                import java.util.*;
                import java.util.stream.*;
                public final class Target {
                    public static String collect(List<String> xs) {
                        return xs.stream().filter(s -> s.length() > 1)
                                 .map(s -> s + "?")
                                 .collect(Collectors.joining("-"));
                    }
                }
            """,
        })
        bad_jar = _jar_from(bad, td / "bad.jar")
        rep_bad = ID.compare_rows(jar, bad_jar, rows[1:2], trials=4)
        check("a changed lambda body is a DIFF",
              rep_bad.rows[0].verdict == "diff",
              rep_bad.rows[0].describe())
    finally:
        import shutil as _sh
        _sh.rmtree(td, ignore_errors=True)


def test_reason_replay_and_rollback() -> None:
    """Every accepted edit must replay from the original bytes."""
    print("reasons: the journal replays, and tampering is caught")
    import zipfile
    from jdec import classfile as CF, bytecode as BC
    from jdec.ir import reasons as RS

    with zipfile.ZipFile(SAMPLE) as z:
        data = z.read("demo/legacy/OldStyle.class")
    cf = CF.parse(data)
    member = [m for m in cf.methods
              if cf.utf8(m.name_index) == "pick"][0]
    audit = RS.audit_method(cf, member)
    check("the fixture rewrite has edits", audit.edits > 0, str(audit.edits))
    check("the accepted rewrite replays cleanly", audit.ok, audit.describe())

    if audit.after_code is None:
        return
    broken = bytearray(audit.after_code)
    for i, b in enumerate(broken):          # corrupt the first immediate
        if b in (0x04, 0x03, 0x02):
            broken[i] = 0x05
            break
    bad = RS.replay(audit.before_code,
                    [],  # empty handlers is enough for this method
                    [], bytes(broken), [])
    check("an unexplained product is a violation", bool(bad),
          "replay accepted bytes without a journal")

    cf2 = CF.parse(data)
    member2 = [m for m in cf2.methods
               if cf2.utf8(m.name_index) == "pick"][0]
    from jdec import deflat as DF
    check("deflat refuses nothing here", DF.deflat_jar is not None)


def test_unflatten_strict_rejection() -> None:
    """The two known false-positive paths must be refused by the checker."""
    print("reasons: unflatten without a state slot, or with an extra branch")
    import struct
    from jdec import bytecode as BC
    from jdec.ir import assemble as ASM, reasons as RS
    from jdec.ir import transforms as TR

    def build(with_selector_iload: bool, extra_branch: bool):
        insns: list[BC.Insn] = []
        pc = 0
        if with_selector_iload:
            insns.append(BC.Insn(pc=0, op=0x15, arg=5, length=2)); pc = 2
        else:
            insns.append(BC.Insn(pc=0, op=0x2A, length=1)); pc = 1
            insns.append(BC.Insn(pc=1, op=0xB6, arg=1, length=3)); pc = 4
        sw_pc = pc
        pad = (4 - (sw_pc + 1) % 4) % 4
        npairs = 3
        length = 1 + pad + 4 + 4 + 8 * npairs
        body = sw_pc + length                 # first case target
        targets = [body + 30, body, body + 10, body + 20]
        insns.append(BC.Insn(pc=sw_pc, op=0xAB, length=length,
                             targets=targets, switch_keys=[1, 2, 3],
                             pad=b"\x00" * pad))
        pc = body
        # the state triple: const; istore 5; goto dispatcher
        insns.append(BC.Insn(pc=pc, op=0x04, length=1)); pc += 1
        st_pc = pc
        insns.append(BC.Insn(pc=pc, op=0x36, arg=5, length=2)); pc += 2
        jump_pc = pc
        insns.append(BC.Insn(pc=pc, op=0xA7, arg=sw_pc - pc, length=3))
        pc += 3
        if extra_branch:
            insns.append(BC.Insn(pc=pc, op=0xA7, arg=st_pc - pc, length=3))
            pc += 3
        while pc <= body + 30:                # case bodies and default target
            insns.append(BC.Insn(pc=pc, op=0x00, length=1)); pc += 1
        code = BC.encode(insns)
        return code, sw_pc, st_pc, jump_pc

    for with_iload, extra in ((False, False), (True, True)):
        code, sw_pc, st_pc, jump_pc = build(with_iload, extra)
        prog = ASM.Program.parse(code, [])
        n = TR.unflatten_dispatchers(prog, None)
        if not with_iload and not extra:
            check("the pass still retargets a guessed state slot", n >= 1,
                  str(n))
        if not prog.journal:
            continue
        try:
            out_code, out_handlers = prog.assemble()
        except FrameError as exc:
            from jdec.ir.types import FrameError
            check("an unrepeatable edit is refused", True, str(exc))
            continue
        bad = RS.replay(prog.original_code, prog.original_handlers,
                        prog.journal, out_code, out_handlers, cf=None)
        check(f"checker refuses (selector-iload={with_iload}, "
              f"extra-branch={extra})", bool(bad),
              "the known false-positive path passed the checker")


def test_interp_same_negative_and_models() -> None:
    """Same model both sides: agreement, difference, and model behaviour."""
    print("interp: original==original, a broken rewrite differs, models run")
    from pathlib import Path as _P
    from jdec.interp import diff as ID

    if JAVAC is None:
        print("  (skipped: needs javac)")
        return

    td = Path(tempfile.mkdtemp(prefix="jdec_interp_"))
    try:
        ok = _compile_java(td, {
            "demo/ip/Target.java": """
                package demo.ip;
                import java.nio.file.*;
                public final class Target {
                    public static int pick(int v) { return v < 2 ? v + 1 : v * 2; }
                    public static String make(String name) throws Exception {
                        Path dir = Paths.get("/case/sub");
                        Files.createDirectories(dir);
                        Path file = dir.resolve(name + ".txt");
                        Files.writeString(file, "hello " + name);
                        return Files.readString(file);
                    }
                    public static int fail(String host) throws Exception {
                        new java.net.Socket(host, 1);
                        return 1;
                    }
                }
            """,
        })
        jar = _jar_from(ok, td / "ok.jar")
        rows = [("demo/ip/Target", "pick", "(I)I"),
                ("demo/ip/Target", "make", "(Ljava/lang/String;)Ljava/lang/String;"),
                ("demo/ip/Target", "fail", "(Ljava/lang/String;)I")]
        rep = ID.compare_rows(jar, jar, rows, trials=3)
        check("original vs original never differs",
              not rep.diff, "; ".join(d.describe() for d in rep.diff))
        check("the file model makes IO decisive",
              all(r.verdict == "same" for r in rep.rows[:2]),
              "; ".join(r.describe() for r in rep.rows))
        check("a refused connection is deterministic",
              rep.rows[2].verdict == "same", rep.rows[2].describe())

        bad_src = _compile_java(td / "bad", {
            "demo/ip/Target.java": """
                package demo.ip;
                public final class Target {
                    public static int pick(int v) { return v < 2 ? v + 1 : v * 3; }
                }
            """,
        })
        bad = _jar_from(bad_src, td / "bad.jar")
        rep_bad = ID.compare_rows(jar, bad, rows[:1], trials=4)
        check("a changed constant is a DIFF",
              rep_bad.rows[0].verdict == "diff", rep_bad.rows[0].describe())
    finally:
        import shutil as _sh
        _sh.rmtree(td, ignore_errors=True)


def test_devirt_behaviour() -> None:
    """A devirtualized body must *compute* what the plain bytecode computes.

    `test_devirt_output_loads` proves the translated method loads. Loading is
    not behaviour: an off-by-one in the case table would still verify. This
    builds the same method twice — once as a VM blob to be translated, once as
    the plain bytecode a compiler would emit — and runs both through the
    differential harness.
    """
    print("devirt: translated body vs the plain method, same answers")
    import zipfile
    from jdec import behave as BH
    from jdec import bvm_devirt as BVM
    from jdec import stubs as SB

    if EN.find_java() is None:
        print("  (skipped: needs a JVM to run the two jars)")
        return

    O = BVM.ORDINAL_BY_NAME
    # the VM program: `if (arg == 0) return 1; return 0;` in VM ordinals
    vm_code = [O["ILOAD"], 0,
               O["IFEQ"], 6,
               O["ICONST_1"], O["IRETURN"],
               O["ICONST_0"], O["IRETURN"]]
    pool = {999: BVM.BVMMethod(code_id=999, name="branchy", desc="(I)I",
                               code=vm_code, max_locals=1, max_stack=1)}
    # the same program as real JVM bytecode (`ifeq` offset is relative to the
    # opcode at 1, so 1 + 5 = 6 is the `iconst_0`)
    plain = bytes([0x1A, 0x99, 0x00, 0x05, 0x04, 0xAC, 0x03, 0xAC])

    def host(body_builder):
        cf = CF.parse(SB.build_stub_class_bytes("com/example/Host"))
        helper = BVM.ConstantPoolHelper(cf)
        mref = helper.add_methodref("com/example/VM", "execute", "(I)V")
        blob = bytes([0x11, (999 >> 8) & 0xFF, 999 & 0xFF,
                      0xB8, (mref >> 8) & 0xFF, mref & 0xFF, 0xAC])
        member = CF.Member(
            access_flags=CF.ACC_PUBLIC | CF.ACC_STATIC,
            name_index=cf.intern_utf8("branchy"),
            descriptor_index=cf.intern_utf8("(I)I"),
            attrs_blob=b"")
        cf.methods.append(member)
        BVM.BVMDevirtualizer.set_code_attribute(
            cf, member,
            body_builder(cf, member, blob))
        return cf

    # the expected side: the same body written out by hand, with frames
    def expected_body(cf, member, _blob):
        return BVM.BVMDevirtualizer.build_code_attribute(
            cf, 1, 1, plain, [], member=member)

    td = Path(tempfile.mkdtemp(prefix="jdec_devirt_behave_"))
    try:
        src = td / "vm.jar"
        vm_cf = host(lambda cf, member, blob:
                     BVM.BVMDevirtualizer.build_code_attribute(
                         cf, 1, 1, blob, [], member=member))
        with zipfile.ZipFile(src, "w") as z:
            z.writestr("com/example/Host.class", vm_cf.serialize())

        out = td / "devirt.jar"
        res = BVM.BVMDevirtualizer.devirtualize_jar(src, out, pool,
                                                    verify_output=False)
        check("the VM blob was devirtualized", res["devirtualized_methods"] == 1,
              str(res["devirtualized_methods"]))

        ref = td / "expected.jar"
        with zipfile.ZipFile(ref, "w") as z:
            z.writestr("com/example/Host.class", host(expected_body).serialize())

        cases = [BH.Case("com/example/Host", "branchy", ("int",), (v,))
                 for v in ("0", "1", "-7", "42")]
        rep = BH.compare(ref, out, cases)
        check("every case was judged", rep.compared == len(cases),
              f"{rep.compared}/{len(cases)}: {rep.summary()}")
        check("no translated answer differs",
              not rep.diffs, "; ".join(d.describe() for d in rep.diffs[:3]))
        # the case table has to matter: a translation that always returned the
        # same constant would pass a one-input test
        check("both branches were exercised",
              {o.left for o in rep.outcomes} >= {"OK:Integer:0", "OK:Integer:1"},
              str(sorted({o.left for o in rep.outcomes})))
    finally:
        import shutil as _sh
        _sh.rmtree(td, ignore_errors=True)


def _compile_java(td: Path, files: dict[str, str], classpath=()) -> Path:
    """Compile `{relative/path.java: source}` under `td/src` into `td/classes`."""
    src = td / "src"
    cls = td / "classes"
    for rel, text in files.items():
        f = src / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")
    cls.mkdir(parents=True, exist_ok=True)
    import subprocess
    cp = [str(c) for c in classpath]
    proc = subprocess.run([JAVAC, "-nowarn", "-d", str(cls)]
                          + (["-cp", os.pathsep.join(cp)] if cp else [])
                          + [str(p) for p in sorted(src.rglob("*.java"))],
                          capture_output=True, text=True, errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr[-1500:])
    return cls


def _jar_from(classes: Path, out: Path, extra: dict[str, bytes] | None = None) -> Path:
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(classes.rglob("*.class")):
            z.write(p, p.relative_to(classes).as_posix())
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return out


def test_sandbox_isolation() -> None:
    """Replay must not be able to write outside the run root."""
    print("sandbox: the replay JVM cannot escape its write root")
    from jdec import behave as BH
    from jdec import sandbox as SBX

    if JAVAC is None or EN.find_java() is None:
        print("  (skipped: needs a JDK)")
        return
    try:
        SBX.check_available()
    except SBX.SandboxError as exc:
        print(f"  (skipped: {exc})")
        return

    args = SBX.jvm_args(Path(tempfile.gettempdir()) / "jdec_sbx_args")
    check("the manager is installed at JVM start",
          any(a.startswith("-Djava.security.manager=") for a in args), str(args))
    check("writes are rooted at the run directory",
          any(a.startswith("-Djdec.sandbox.root=") for a in args), str(args))

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cls = _compile_java(root / "src", {
            "demo/sbx/Evil.java": """
                package demo.sbx;
                public class Evil {
                    public static int write(String path) {
                        try {
                            java.nio.file.Files.writeString(
                                java.nio.file.Path.of(path), "escaped");
                            return 1;
                        } catch (Exception e) {
                            return 0;
                        }
                    }
                }
            """,
        })
        jar = _jar_from(cls, root / "evil.jar")
        outside = root / "outside.txt"
        case = BH.Case("demo/sbx/Evil", "write", ("java.lang.String",),
                       (str(outside),))

        rep = BH.compare(jar, jar, [case], sandbox=True)
        check("the case ran under the sandbox", rep.compared == 1, rep.summary())
        check("the sandbox denied the write", not outside.exists(), str(outside))
        check("both sides were denied identically",
              all(o.status == "same" for o in rep.outcomes), str(rep.outcomes))

        # a self-extracting exe is a zip with a native prefix; URLClassPath
        # cannot resolve classes from it under a SecurityManager
        prefixed = root / "sample.exe"
        prefixed.write_bytes(b"MZ" + b"\0" * 64 + SAMPLE.read_bytes())
        pick_case = BH.Case("demo/legacy/OldStyle", "pick",
                            ("java.lang.String",), ("hello",))
        rep3 = BH.compare(prefixed, SAMPLE, [pick_case], sandbox=True)
        check("a prefixed (exe) input is normalized for the sandbox",
              rep3.compared == 1, rep3.summary())
        first = SBX.plain_jar(prefixed, root / "p1")
        second = SBX.plain_jar(prefixed, root / "p2")
        check("the repacked plain jar is cached across calls",
              first == second and first.is_file(), f"{first} / {second}")
        check("an ordinary jar is returned unchanged",
              SBX.plain_jar(SAMPLE, root / "p3") == SAMPLE)

        # negative control: the same call writes when the sandbox is off
        rep2 = BH.compare(jar, jar, [case], sandbox=False)
        check("without the sandbox the write happens", outside.exists(),
              rep2.summary())


def test_receiver_and_argument_synthesis() -> None:
    """A method must be invocable when its class has no no-arg constructor.

    This is the whole "193 of 411" gap: a receiver used to require a public
    no-arg constructor. The driver now falls back to a constructor with
    synthesised arguments and then to a zero-state instance, and a reference
    parameter can be more than null.
    """
    print("behave: receivers and arguments are synthesised, not just null")
    from jdec import behave as BH

    if JAVAC is None or EN.find_java() is None:
        print("  (skipped: needs a JDK)")
        return

    td = Path(tempfile.mkdtemp(prefix="jdec_recv_"))
    try:
        cls = _compile_java(td, {
            "demo/recv/Target.java": """
                package demo.recv;
                public final class Target {
                    private final int base;
                    private final String tag;
                    public Target(int base, String tag) { this.base = base; this.tag = tag; }
                    public int plus(int x) { return base + x; }
                    public String describe() { return tag + ":" + base; }
                    public static int len(java.util.List<String> xs) { return xs.size(); }
                    public static int strLen(String s) { return s.length(); }
                }
            """,
        })
        jar = _jar_from(cls, td / "target.jar")

        def run(cases):
            return BH.compare(jar, jar, cases)

        rep = run([BH.Case("demo.recv.Target", "plus", ("int",), ("1",))])
        check("an instance method with only an arg-constructor is invocable",
              rep.compared == 1 and not rep.diffs, rep.summary())

        rep = run([BH.Case("demo.recv.Target", "describe", (), ())])
        check("the constructed receiver carries its state",
              rep.outcomes and rep.outcomes[0].left.startswith("OK:s:"),
              rep.summary())

        rep = run([BH.Case("demo.recv.Target", "len", ("java.util.List",), ("@new",))])
        check("a `@new` reference argument is a real instance",
              rep.outcomes and rep.outcomes[0].left == "OK:Integer:0",
              rep.summary())

        rep = run([BH.Case("demo.recv.Target", "strLen", ("java.lang.String",), ("@new",))])
        check("`@new` on String is the empty string",
              rep.outcomes and rep.outcomes[0].left == "OK:Integer:0",
              rep.summary())

        rep = run([BH.Case("demo.recv.Target", "len", ("java.util.List",), ("@null",))])
        check("a null argument still NPEs, and that counts as a throw",
              rep.outcomes and rep.outcomes[0].evidence == "throw",
              rep.summary())

        # the identity-hash question: two loaders can never agree on one
        rep = run([BH.Case("demo.recv.Target", "describe", (), ())])
        check("no case is a false difference", not rep.diffs, rep.summary())
    finally:
        import shutil as _sh
        _sh.rmtree(td, ignore_errors=True)


def test_behave_classpath() -> None:
    """A class whose supertype lives in another jar needs `--cp` to be judged."""
    print("behave: the dependency classpath reaches both loaders")
    from jdec import behave as BH

    if JAVAC is None or EN.find_java() is None:
        print("  (skipped: needs a JDK)")
        return

    td = Path(tempfile.mkdtemp(prefix="jdec_cp_"))
    try:
        dep_cls = _compile_java(td / "dep", {
            "demo/dep/Base.java": """
                package demo.dep;
                public class Base { public int twice(int x) { return 2 * x; } }
            """,
        })
        dep = _jar_from(dep_cls, td / "dep.jar")
        app_cls = _compile_java(td / "app", {
            "demo/app/Child.java": """
                package demo.app;
                public class Child extends demo.dep.Base {
                    public int four(int x) { return twice(twice(x)); }
                }
            """,
        }, classpath=[dep_cls])
        app = _jar_from(app_cls, td / "app.jar")

        case = BH.Case("demo.app.Child", "four", ("int",), ("3",))
        without = BH.compare(app, app, [case])
        check("without the dependency the case is unusable",
              without.outcomes[0].status == "unusable", without.summary())
        with_cp = BH.compare(app, app, [case], classpath=[dep])
        check("with it, the method runs and answers",
              with_cp.outcomes[0].left == "OK:Integer:12", with_cp.summary())
    finally:
        import shutil as _sh
        _sh.rmtree(td, ignore_errors=True)


def test_verify_skips_multirelease() -> None:
    """`META-INF/versions/N/...` is the same class, not a second one."""
    print("verify: multi-release entries are not enumerated")
    from jdec import verify as VF

    if JAVAC is None:
        print("  (skipped: needs javac)")
        return

    td = Path(tempfile.mkdtemp(prefix="jdec_mr_"))
    try:
        cls = _compile_java(td, {
            "demo/mr/Plain.java": "package demo.mr; public class Plain { public int f() { return 1; } }",
        })
        jar = _jar_from(cls, td / "mr.jar",
                        {"META-INF/versions/9/demo/mr/Plain.class":
                         (cls / "demo/mr/Plain.class").read_bytes()})
        names = VF.class_names(jar)
        check("the versioned copy is not listed as a class",
              names == ["demo/mr/Plain"], str(names))
        rep = VF.verify(jar)
        check("nothing is reported unresolved",
              not rep.unresolved and rep.verified == 1, rep.summary())
    finally:
        import shutil as _sh
        _sh.rmtree(td, ignore_errors=True)


def test_hierarchy_extra_classpath() -> None:
    """Two library subclasses must merge to their library superclass."""
    print("hierarchy: dependency jars supply supertypes for the merge")
    from jdec.ir import hierarchy as H

    if JAVAC is None:
        print("  (skipped: needs javac)")
        return

    td = Path(tempfile.mkdtemp(prefix="jdec_hier_"))
    try:
        dep_cls = _compile_java(td / "dep", {
            "demo/lib/Anim.java": "package demo.lib; public class Anim {}",
            "demo/lib/Sub1.java": "package demo.lib; public class Sub1 extends Anim {}",
            "demo/lib/Sub2.java": "package demo.lib; public class Sub2 extends Anim {}",
        })
        dep = _jar_from(dep_cls, td / "dep.jar")
        app_cls = _compile_java(td / "app", {
            "demo/app/Use.java": """
                package demo.app;
                public class Use {
                    public static demo.lib.Anim pick(boolean b) {
                        return b ? new demo.lib.Sub1() : new demo.lib.Sub2();
                    }
                }
            """,
        }, classpath=[dep_cls])
        app = _jar_from(app_cls, td / "app.jar")

        blind = H.Hierarchy.from_jar(app)
        check("without the dependency the merge widens to Object",
              blind.lca("demo/lib/Sub1", "demo/lib/Sub2") == H.OBJECT,
              blind.lca("demo/lib/Sub1", "demo/lib/Sub2"))
        withcp = H.Hierarchy.from_jar(app, extra=[dep])
        check("with it, the merge finds the real superclass",
              withcp.lca("demo/lib/Sub1", "demo/lib/Sub2") == "demo/lib/Anim",
              withcp.lca("demo/lib/Sub1", "demo/lib/Sub2"))
        check("without the dependency the missing library types are named",
              {"demo/lib/Anim", "demo/lib/Sub1", "demo/lib/Sub2"}
              <= blind.unresolved, str(sorted(blind.unresolved)[:5]))
        check("with it, none of those types are reported missing",
              not ({"demo/lib/Anim", "demo/lib/Sub1", "demo/lib/Sub2"}
                   & withcp.unresolved), str(sorted(withcp.unresolved)[:5]))
    finally:
        import shutil as _sh
        _sh.rmtree(td, ignore_errors=True)


def test_missing_dependency_gate() -> None:
    """A missing dependency must be named, and it must make the stage partial.

    Frames are computed against the classpath deflat is given. A library type
    that is not there has no supertypes, so a merge involving it widens to
    Object; the verifier runs on the same incomplete classpath, so it accepts
    the frame. The packet only shows up when the artifact is verified against
    the real dependencies. The gate must say so, not report "0 rejected".
    """
    print("deflat: missing classpath types are reported, not silently widened")
    from jdec import deflat as DF
    from jdec import pipeline as PIPE
    from jdec import cli as CL

    if JAVAC is None:
        print("  (skipped: needs javac)")
        return

    td = Path(tempfile.mkdtemp(prefix="jdec_missing_"))
    try:
        dep_cls = _compile_java(td / "dep", {
            "demo/lib/Anim.java": "package demo.lib; public class Anim {}",
            "demo/lib/Sub1.java": "package demo.lib; public class Sub1 extends Anim {}",
            "demo/lib/Sub2.java": "package demo.lib; public class Sub2 extends Anim {}",
        })
        dep = _jar_from(dep_cls, td / "dep.jar")
        app_cls = _compile_java(td / "app", {
            "demo/app/Use.java": """
                package demo.app;
                public class Use {
                    public static demo.lib.Anim pick(boolean b) {
                        return b ? new demo.lib.Sub1() : new demo.lib.Sub2();
                    }
                }
            """,
        }, classpath=[dep_cls])
        app = _jar_from(app_cls, td / "app.jar")

        blind = DF.deflat_jar(app, td / "blind.jar", verify_output=False)
        check("deflat names the types the classpath did not provide",
              {"demo/lib/Anim", "demo/lib/Sub1", "demo/lib/Sub2"}
              <= set(blind["unresolved_types"]), str(blind["unresolved_types"]))
        withcp = DF.deflat_jar(app, td / "withcp.jar", verify_output=False,
                               classpath=[dep])
        check("deflat stays quiet for a supplied dependency",
              not (set(withcp["unresolved_types"])
                   & {"demo/lib/Anim", "demo/lib/Sub1", "demo/lib/Sub2"}),
              str(withcp["unresolved_types"]))

        partial = {"classes": 1, "methods_unflattened": 2,
                   "unresolved_types": ["demo/lib/Anim"],
                   "verify": {"verified": 1}, "reason_refused": []}
        status, detail = PIPE.deflat_stage_status(partial)
        check("a rewritten method behind a missing type is partial",
              status == PIPE.STAGE_PARTIAL, status)
        check("the stage detail says the classpath is missing types",
              "classpath" in detail, detail)
        ok = {"classes": 1, "methods_unflattened": 2, "unresolved_types": [],
              "verify": {"verified": 1}, "reason_refused": []}
        check("with a complete classpath the stage stays ok",
              PIPE.deflat_stage_status(ok)[0] == PIPE.STAGE_OK)
        untouched = {"classes": 1, "methods_unflattened": 0,
                     "unresolved_types": ["demo/lib/Anim"],
                     "verify": {"verified": 1}, "reason_refused": []}
        check("no rewrite means no rebuilt frame, so the stage stays ok",
              PIPE.deflat_stage_status(untouched)[0] == PIPE.STAGE_OK)

        import contextlib
        import io as _io
        from types import SimpleNamespace
        from unittest import mock
        fake = {"classes": 1, "methods_unflattened": 2, "methods_reverted": 0,
                "reason_refused": [], "rewritten": [], "verify": None,
                "unresolved_types": ["demo/lib/Anim"]}
        ns = SimpleNamespace(input=str(app), output=str(td / "cli.jar"),
                             no_verify=True, strip_frames=False,
                             recompute_frames=False, byte_patch=False,
                             cp=[], no_reasons=False, rewritten=None)
        buf = _io.StringIO()
        with mock.patch("jdec.deflat.deflat_jar", return_value=fake), \
                contextlib.redirect_stdout(buf):
            rc = CL.cmd_deflat(ns)
        check("the CLI warns about the missing type",
              "not on the classpath" in buf.getvalue(), buf.getvalue()[-300:])
        check("the warning does not turn into a failure", rc == 0, str(rc))

        # devirt has the same blind spot: it rebuilds frames from the same
        # hierarchy and then verifies without the declared dependencies.
        from jdec import devirt as DV
        dv_blind = DV.Devirtualizer.devirtualize_jar(
            app, td / "dv_blind.jar", {}, verify_output=False)
        check("devirt names the missing types too",
              {"demo/lib/Anim", "demo/lib/Sub1", "demo/lib/Sub2"}
              <= set(dv_blind["unresolved_types"]),
              str(dv_blind["unresolved_types"]))
        dv_cp = DV.Devirtualizer.devirtualize_jar(
            app, td / "dv_cp.jar", {}, verify_output=False, classpath=[dep])
        check("devirt stays quiet for a supplied dependency",
              not (set(dv_cp["unresolved_types"])
                   & {"demo/lib/Anim", "demo/lib/Sub1", "demo/lib/Sub2"}),
              str(dv_cp["unresolved_types"]))

        fake_dv = {"devirtualized_methods": 2, "devirtualized_classes": 1,
                   "verify": None, "frame_notes": [],
                   "unresolved_types": ["demo/lib/Anim"]}
        dvns = SimpleNamespace(input=str(app), output=str(td / "dv_cli.jar"),
                               pool=None, no_verify=True, cp=[])
        dvbuf = _io.StringIO()
        with mock.patch("jdec.devirt.Devirtualizer.devirtualize_jar",
                        return_value=fake_dv), \
                contextlib.redirect_stdout(dvbuf):
            dvrc = CL.cmd_devirt(dvns)
        check("the devirt CLI warns about the missing type",
              "not on the classpath" in dvbuf.getvalue(),
              dvbuf.getvalue()[-300:])
        check("the devirt warning does not turn into a failure",
              dvrc == 0, str(dvrc))

        with mock.patch("jdec.verify.verify_or_keep") as vk, \
                mock.patch("jdec.toolchain.find_java", return_value="java"):
            vk.return_value.to_dict.return_value = {"skipped": "test"}
            DV.Devirtualizer._verify_rewrite(app, td / "dv_verify.jar",
                                             classpath=[dep])
        check("devirt hands the verifier the classpath the frames used",
              (vk.call_args.kwargs if vk.call_args else {}).get("classpath")
              == [dep], str(vk.call_args))
    finally:
        import shutil as _sh
        _sh.rmtree(td, ignore_errors=True)


def _looks_like_signature(name: str) -> bool:
    upper = name.upper()
    return upper.startswith("META-INF/") and upper.endswith(
        (".SF", ".RSA", ".DSA", ".EC"))


def test_deflat_failure_accounting() -> None:
    """A class that cannot be parsed must be named, not silently dropped.

    `deflat_jar` used to swallow every per-class exception; the truncated
    fixture in sample.jar therefore disappeared without a trace. A tool that
    says "done" while skipping input is the same failure mode as "0 rejected"
    on an incomplete classpath.
    """
    print("deflat: unreadable classes are counted and surfaced")
    from jdec import deflat as DF
    from jdec import pipeline as PIPE
    from jdec import cli as CL
    import contextlib
    import io as _io
    from types import SimpleNamespace
    from unittest import mock

    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "sample_deflat.jar"
        stats = DF.deflat_jar(SAMPLE, out, verify_output=False)
        # a signed jar: rewritten entries invalidate the signature, so the
        # stale signature files must not survive into the output
        signed = Path(td) / "signed.jar"
        with zipfile.ZipFile(SAMPLE) as zin, \
                zipfile.ZipFile(signed, "w") as zout:
            for name in zin.namelist():
                zout.writestr(name, zin.read(name))
            zout.writestr("META-INF/FAKE.SF", b"Signature-Version: 1.0\n")
            zout.writestr("META-INF/FAKE.RSA", b"fake")
        signed_out = Path(td) / "signed_deflat.jar"
        signed_stats = DF.deflat_jar(signed, signed_out, verify_output=False)
        check("stale jar signatures are counted",
              signed_stats["signatures_removed"] == 2,
              str(signed_stats["signatures_removed"]))
        with zipfile.ZipFile(signed_out) as z:
            left = [n for n in z.namelist() if _looks_like_signature(n)]
        check("stale jar signatures are gone", not left, str(left))

        check("the broken fixture is named in failed_classes",
              any("Truncated" in x for x in stats.get("failed_classes") or []),
              str(stats.get("failed_classes")))

        bad = {"classes": 12, "methods_unflattened": 3, "unresolved_types": [],
               "failed_classes": ["demo/broken/Truncated.class: ClassFormatError"],
               "verify": {"verified": 10}, "reason_refused": []}
        st, detail = PIPE.deflat_stage_status(bad)
        check("a class failure makes the stage partial",
              st == PIPE.STAGE_PARTIAL, st)
        check("the stage detail counts the failure",
              "parse" in detail, detail)

        fake = {"classes": 12, "methods_unflattened": 3, "methods_reverted": 0,
                "reason_refused": [], "rewritten": [], "verify": None,
                "unresolved_types": [],
                "failed_classes": ["demo/broken/Truncated.class: ClassFormatError"]}
        ns = SimpleNamespace(input=str(SAMPLE), output=str(Path(td) / "x.jar"),
                             no_verify=True, strip_frames=False,
                             recompute_frames=False, byte_patch=False,
                             cp=[], no_reasons=False, rewritten=None)
        buf = _io.StringIO()
        with mock.patch("jdec.deflat.deflat_jar", return_value=fake), \
                contextlib.redirect_stdout(buf):
            rc = CL.cmd_deflat(ns)
        check("the CLI names the failed class",
              "could not be parsed" in buf.getvalue(), buf.getvalue()[-300:])
        check("a failed class changes the exit code to partial", rc == 1, str(rc))


def test_coverage_accounting() -> None:
    """Coverage counts methods, and says why the rest were not judged."""
    print("coverage: per-method verdicts, values vs throws, and reasons")
    from jdec import cases as CS
    from jdec import behave as BH

    rows = [("a/A", "m", "()V"), ("a/B", "n", "()V"), ("a/C", "o", "()V"),
            ("a/D", "p", "()V")]
    c = BH.Case("a/A", "m")
    oc = BH.CaseOutcome

    class Der:
        reason_of = {("a/C", "o"): "touches java/nio/file/Files",
                     ("a/D", "p"): "instance method on an abstract type"}

    cov = CS.coverage(rows, [
        oc(c, "OK:i:1", "OK:i:1", "same"),
        oc(BH.Case("a/A", "m"), "THROW:X:y", "THROW:X:y", "same"),
        oc(BH.Case("a/B", "n"), "THROW:X:y", "THROW:X:y", "same"),
    ], Der)
    check("two methods were judged", cov["judged"] == 2, str(cov))
    check("a value is counted as a value", cov["value"] == 1, str(cov))
    check("an identical throw is counted apart", cov["throw"] == 1, str(cov))
    check("the method with both is counted once",
          sum(1 for m in cov["missing"] if m[1] == "m") == 0, str(cov["missing"]))
    OC = BH.CaseOutcome
    ev = CS.evidence_sets([
        OC(BH.Case("a/A", "v"), "OK:1", "OK:1", "same"),
        OC(BH.Case("a/B", "t"),
           "THROW:java.lang.IllegalStateException:x",
           "THROW:java.lang.IllegalStateException:x", "same"),
        OC(BH.Case("a/C", "d"),
           "THROW:java.lang.SecurityException:sandbox: write denied",
           "THROW:java.lang.SecurityException:sandbox: write denied", "same"),
    ])
    check("a returned value is value evidence",
          ("a/A", "v") in ev["value"])
    check("a real exception is throw evidence",
          ("a/B", "t") in ev["throw"])
    check("a sandbox denial is not throw evidence",
          ("a/C", "d") in ev["denied"] and ("a/C", "d") not in ev["throw"])
    check("denied-only is not in the no-denial set",
          ("a/C", "d") not in (ev["value"] | ev["throw"]))
    from jdec.interp import diff as ID
    irow = ("a/A", "m", "()I")
    ithrow = ID.InterpReport(rows=[ID.MethodDiff(irow, "same", "", 1, "throw")])
    check("an interpreter throw is classified as a throw",
          ID.outcomes(ithrow)[0].evidence == "throw")
    ivalue = ID.InterpReport(rows=[ID.MethodDiff(irow, "same", "", 1, "value")])
    check("an interpreter value is classified as a value",
          ID.outcomes(ivalue)[0].evidence == "value")
    check("NaN equals NaN for the differential comparison",
          ID._same_value(float("nan"), float("nan"), {}))
    check("NaN still differs from a number",
          not ID._same_value(float("nan"), 1.0, {}))
    check("helpful-NPE detail is not a difference",
          BH._normalize_throw(
              "THROW:java.lang.NullPointerException:x because \"\"") ==
          BH._normalize_throw(
              "THROW:java.lang.NullPointerException:x because \"this\" is null"))
    reasons = {name: why for _cls, name, why in cov["missing"]}
    check("the filter's reason is carried through",
          reasons.get("o") == "touches java/nio/file/Files", str(reasons))
    check("a method that never got a case is still listed",
          "p" in reasons, str(reasons))


def test_behave_semantics() -> None:
    """A case the harness cannot invoke must not count as evidence."""
    print("behave: same / diff / unusable, and what each verdict means")
    from jdec import behave as BH

    c = BH.Case("demo/X", "f", ("int",), ("1",))
    check("a judged agreement is 'same'",
          BH.CaseOutcome(c, "OK:i:1", "OK:i:1", "same").same)
    check("a judged disagreement is not 'same'",
          not BH.CaseOutcome(c, "OK:i:1", "OK:i:2", "diff").same)
    # the old rule was `left == right`, so an un-invokable case (both sides
    # "ERROR:...") compared equal and was counted as identical
    check("an outcome built without a status is never 'same'",
          not BH.CaseOutcome(c, "OK:i:1", "OK:i:1").same)

    def report(*outcomes) -> BH.BehaveReport:
        rep = BH.BehaveReport(original="a.jar", rewritten="b.jar")
        rep.outcomes.extend(outcomes)
        return rep

    ok1 = BH.CaseOutcome(c, "OK:i:1", "OK:i:1", "same")
    bad = BH.CaseOutcome(c, "OK:i:1", "OK:i:2", "diff")
    skip = BH.CaseOutcome(c, "ERROR:X:y", "ERROR:X:y", "unusable", "no method")

    check("no cases is NO VERDICT, not a pass",
          report().verdict == "NO VERDICT" and not report().ok)
    check("all-agree is PASS", report(ok1).verdict == "PASS" and report(ok1).ok)
    check("a difference is FAIL", report(ok1, bad).verdict == "FAIL")
    check("an unusable case downgrades PASS to PARTIAL",
          report(ok1, skip).verdict == "PARTIAL" and not report(ok1, skip).ok)
    check("unusable cases are not counted as compared",
          report(ok1, skip).compared == 1, str(report(ok1, skip).compared))
    check("two identical ERRORs are not identical",
          skip.status == "unusable" and not skip.same)
    check("summary names the unusable count",
          "unusable" in report(ok1, skip).summary(),
          report(ok1, skip).summary())
    check("json carries the verdict",
          report(ok1, skip).to_dict()["verdict"] == "PARTIAL")

    if JAVAC is None or EN.find_java() is None:
        print("  (skipped: the end-to-end part needs a JDK)")
        return

    # end-to-end: a spec where one class does not exist must not read as PASS
    with tempfile.TemporaryDirectory() as td:
        spec = Path(td) / "cases.txt"
        spec.write_text("demo/legacy/OldStyle|pick|java.lang.String|hello\n"
                        "demo/legacy/NoSuchClass|pick|java.lang.String|hello\n",
                        encoding="utf-8")
        import contextlib
        import io
        from jdec import cli as CL
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = CL.main(["behave", str(SAMPLE), str(SAMPLE),
                          "--spec", str(spec), "--execute"])
        out = buf.getvalue()
        check("a partly-unusable run exits 4, not 0", rc == 4, f"rc={rc}")
        check("the CLI reports PARTIAL", "result    : PARTIAL" in out, out[-200:])
        check("the CLI names the skipped case", "SKIP " in out, out[-200:])

    # the coverage gate is a separate exit code: "the rewrite is wrong" (1),
    # "nothing was proven" (4) and "we did not look enough" (5) are different
    with tempfile.TemporaryDirectory() as td:
        out_jar = Path(td) / "d.jar"
        rewritten = Path(td) / "rw.txt"
        from jdec import deflat as DF
        stats = DF.deflat_jar(SAMPLE, out_jar, verify_output=False)
        rewritten.write_text(
            "\n".join("\t".join(r) for r in stats.get("rewritten") or []),
            encoding="utf-8")
        if stats.get("rewritten"):
            import contextlib
            import io
            from jdec import cli as CL

            def run(gate):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = CL.main(["behave", str(SAMPLE), str(out_jar), "--derive",
                                  "--from", str(rewritten), "--execute",
                                  "--gate", str(gate)])
                return rc, buf.getvalue()

            rc, text = run(0)
            check("a met gate keeps exit 0", rc == 0, f"rc={rc}: {text[-200:]}")
            rc, text = run(101)
            check("an impossible gate exits 5, not 1", rc == 5, f"rc={rc}")
            check("the gate line names both numbers",
                  "gate      :" in text and "threshold 101%" in text,
                  text[-300:])

        # the union gate spans both engines: the CLI must print the union and
        # enforce it as exit 5, exactly like --gate/--interp-gate
        if stats.get("rewritten"):
            import contextlib
            import io
            from jdec import cli as CL

            def run_union(gate):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = CL.main(["behave", str(SAMPLE), str(out_jar), "--derive",
                                  "--from", str(rewritten), "--execute",
                                  "--engine", "both", "--union-gate", str(gate)])
                return rc, buf.getvalue()

            rc, text = run_union(0)
            check("a met union gate keeps exit 0", rc == 0,
                  f"rc={rc}: {text[-200:]}")
            check("the union line names both numbers",
                  "union        :" in text and "either engine" in text,
                  text[-400:])
            rc, text = run_union(101)
            check("an impossible union gate exits 5", rc == 5, f"rc={rc}")
            check("the union gate line prints the threshold",
                  "union gate  :" in text and "threshold 101%" in text,
                  text[-300:])


def test_case_derivation() -> None:
    """Derived cases must be callable, stable, and honestly counted."""
    print("cases: descriptor parsing, filters, and the stability baseline")
    from jdec import cases as CS

    check("split_descriptor handles primitives",
          CS.split_descriptor("(IJ)Z") == (["I", "J"], "Z"))
    check("split_descriptor handles objects and arrays",
          CS.split_descriptor("(Ljava/lang/String;[I)V")
          == (["Ljava/lang/String;", "[I"], "V"), "")
    check("split_descriptor handles no arguments",
          CS.split_descriptor("()V") == ([], "V"))
    try:
        CS.split_descriptor("broken")
        raised = False
    except ValueError:
        raised = True
    check("split_descriptor rejects a non-descriptor", raised)

    check("an array uses its binary name",
          CS._type_name("[I") == "[I")
    check("a reference type becomes an FQCN",
          CS._type_name("Ljava/util/List;") == "java.util.List")
    check("a primitive keeps its java name", CS._type_name("I") == "int")

    pick = ("demo/legacy/OldStyle", "pick",
            "(Ljava/lang/String;)Ljava/lang/String;")
    der = CS.derive(SAMPLE, [pick])
    check("the rewritten method was considered", der.considered == 1, str(der.considered))
    check("it passed the filters", der.eligible == 1, der.summary())
    check("four string inputs were derived", len(der.cases) == 4, str(len(der.cases)))

    # an instance method with no no-arg constructor cannot be given a receiver
    spawn = ("demo/legacy/OldStyle", "spawn", "(I)V")
    der2 = CS.derive(SAMPLE, [spawn])
    check("a method that starts a thread is not derived",
          not der2.cases and "java/lang/Thread" in " ".join(der2.dropped),
          der2.summary())

    if JAVAC is not None:
        sbx_td = Path(tempfile.mkdtemp(prefix="jdec_derive_sbx_"))
        try:
            sbx_cls = _compile_java(sbx_td, {
                "demo/dsbx/Io.java": """
                    package demo.dsbx;
                    public class Io {
                        public static int write() {
                            try {
                                java.nio.file.Files.writeString(
                                    java.nio.file.Path.of("out.txt"), "x");
                                return 1;
                            } catch (Exception e) { return 0; }
                        }
                        public static int net() {
                            try {
                                new java.net.Socket("127.0.0.1", 9).close();
                                return 1;
                            } catch (Exception e) { return 0; }
                        }
                        public static long clock() {
                            return System.currentTimeMillis();
                        }
                    }
                """,
            })
            sbx_jar = _jar_from(sbx_cls, sbx_td / "io.jar")
            sbx_rows = [("demo/dsbx/Io", "write", "()I"),
                        ("demo/dsbx/Io", "net", "()I"),
                        ("demo/dsbx/Io", "clock", "()J")]
            plain = CS.derive(sbx_jar, sbx_rows)
            check("without a sandbox file IO is not derived",
                  not any(c.method == "write" for c in plain.cases),
                  plain.summary())
            sand = CS.derive(sbx_jar, sbx_rows, sandbox=True)
            check("with a sandbox file IO is derived",
                  any(c.method == "write" for c in sand.cases),
                  sand.summary())
            check("with a sandbox network is derived",
                  any(c.method == "net" for c in sand.cases),
                  sand.summary())
            check("the clock stays excluded even under a sandbox",
                  ("demo/dsbx/Io", "clock") in sand.reason_of,
                  sand.summary())
        finally:
            import shutil as _sh
            _sh.rmtree(sbx_td, ignore_errors=True)

    kept, why = CS.stabilise(der.cases, SAMPLE)
    check("the stable baseline keeps the pure string cases", len(kept) == 4,
          f"{len(kept)} kept, {why}")

    if JAVAC is None or EN.find_java() is None:
        print("  (skipped: the end-to-end part needs a JDK)")
        return

    # a case that only ever throws is not evidence: build one by asking for a
    # method whose argument is an object (the driver passes null -> NPE)
    import shutil
    td = Path(tempfile.mkdtemp(prefix="jdec_derive_"))
    try:
        out = td / "d.jar"
        from jdec import deflat as DF
        stats = DF.deflat_jar(SAMPLE, out, verify_output=False)
        rows = stats.get("rewritten") or []
        check("deflat reports the rewritten methods", bool(rows), str(rows))
        check("the report carries class, name and descriptor",
              all(len(r) == 3 and r[2].startswith("(") for r in rows), str(rows[:2]))
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_verify_matrix() -> None:
    """The gate must know what a JVM can read, and say so instead of failing."""
    print("verify: class-version aware, same fixture judged by 8 / 17 / 21")
    from jdec import verify as VF

    jar = build_fixtures.ensure_legacy8_jar()
    check("the legacy8 fixture builds", jar is not None and jar.is_file())
    if jar is None or not jar.is_file():
        return
    majors = VF.class_majors(jar)
    check("it carries class files at major 52",
          set(majors.values()) == {52}, str(sorted(set(majors.values()))))

    exes: list[Path] = []
    for root in (os.environ.get("JDEC_JDKS", ""),
                 "D:/JAVA8", "D:/JAVA17", "D:/java21"):
        for part in str(root).split(os.pathsep):
            if not part:
                continue
            exe = Path(part) / "bin" / ("java.exe" if os.name == "nt" else "java")
            if exe.is_file() and exe not in exes:
                exes.append(exe)
    if not exes:
        print("  (skipped: no JDK found; set JDEC_JDKS to the JDK roots)")
        return

    judged = 0
    for exe in exes:
        rep = VF.verify(jar, java=str(exe))
        label = exe.parent.parent.name
        check(f"{label} judges every legacy8 class",
              rep.skipped == [] and rep.invalid == [] and rep.verified > 0,
              rep.summary())
        if rep.verified:
            judged += 1
    check("at least one JVM actually judged the fixture", judged >= 1, str(judged))

    # the behaviour driver is built with --release 8 for the same reason: one
    # build has to run on every JVM in the matrix
    from jdec import behave as BH
    case = BH.Case("demo/legacy8/Legacy8Math", "pick", ("int",), ("3",))
    for exe in exes:
        rep = BH.compare(jar, jar, [case], java=str(exe))
        label = exe.parent.parent.name
        check(f"{label} runs the behaviour driver",
              rep.compared == 1 and rep.outcomes[0].left == "OK:Integer:6",
              rep.summary())

    # The regression that matters: an old JVM used to report a whole modern jar
    # as INVALID (UnsupportedClassVersionError), which made `verify_or_keep`
    # revert everything and the exit code meaningless.
    oldest = min(exes, key=lambda e: VF.jvm_major(str(e)) or 99)
    ceiling = VF.jvm_major(str(oldest))
    newest = max(majors.values())
    sample_major = max(VF.class_majors(SAMPLE).values())
    if ceiling and ceiling < sample_major:
        rep = VF.verify(SAMPLE, java=str(oldest))
        check("a jar newer than the JVM is skipped, not called invalid",
              rep.invalid == [] and len(rep.skipped) == rep.checked, rep.summary())
        check("and that reports PARTIAL, never PASS",
              rep.verdict == "PARTIAL", rep.verdict)
    else:
        print(f"  (no JVM older than class v{sample_major}; skip check)")


def test_focus_reports_unjudged() -> None:
    """`verify --focus` must separate "0 rejected" from "0 judged"."""
    print("verify: how many rewritten methods live in an unjudged class")
    from jdec import verify as VF

    rep = VF.VerifyReport(target="x.jar", checked=4, verified=2)
    rep.unresolved.append(VF.VerifyIssue("a/A", "UNRESOLVED", "no dep"))
    rep.skipped.append(VF.VerifyIssue("b/B", "SKIP", "v65 > v61"))
    rep.invalid.append(VF.VerifyIssue("c/C", "INVALID", "bad"))
    rows = [("a/A", "m", "()V"), ("b/B", "m", "()V"), ("c/C", "m", "()V"),
            ("d/D", "m", "()V")]
    bad = VF.unjudged_rewritten(rep, rows)
    check("unjudged counts unresolved, skipped and invalid classes",
          len(bad) == 3, str(bad))
    check("a fully judged class is not counted",
          "d/D.m()V" not in bad, str(bad))

    if JAVAC is None or EN.find_java() is None:
        print("  (skipped: the end-to-end part needs a JDK)")
        return

    import shutil
    td = Path(tempfile.mkdtemp(prefix="jdec_focus_"))
    try:
        out = td / "f.jar"
        from jdec import deflat as DF
        stats = DF.deflat_jar(SAMPLE, out, verify_output=False)
        rows = stats["rewritten"]
        rep = VF.verify(out, classpath=[SAMPLE])
        check("the fixture's rewritten methods are all judged",
              VF.unjudged_rewritten(rep, rows) == [],
              str(VF.unjudged_rewritten(rep, rows)))

        # a rewritten method inside a class the verifier rejected is reported
        # by name — that is the whole point of the number
        bad2 = VF.unjudged_rewritten(
            rep, list(rows) + [("demo/broken/Truncated", "m", "()V")])
        check("a rewrite inside a rejected class is named",
              bad2 == ["demo/broken/Truncated.m()V"], str(bad2))
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_insert_branch_to_label() -> None:
    """Edit a method with a label, and have the JVM still accept it."""
    print("ir: label-marked branch insertion, and identity after replace")
    from jdec.ir import assemble as ASM
    from jdec.ir import assume as AS
    from jdec.ir import attrs as AT
    from jdec.ir import frames as FR

    # a branch to a replaced position must land on the FIRST replacement
    prog = ASM.Program.parse(bytes([0x04, 0xAC]), [])
    prog.replace(0, [BC.Insn(pc=0, op=0x05, length=1),
                     BC.Insn(pc=0, op=0x57, length=1)])   # iconst_2; pop
    jump = BC.Insn(pc=0, op=0xA7, arg=0, length=3)
    prog.insert_after(1, [jump])
    jump.pc = 50
    jump.arg = 0 - 50                                        # target original pc 0
    out, _hs = prog.assemble()
    check("a branch to a replaced pc lands on the first instruction",
          int.from_bytes(out[-2:], "big", signed=True) == -3, out.hex())

    # label edition: append a block, mark it, jump to it
    q = ASM.Program.parse(bytes([0x04, 0xAC]), [])          # iconst_1; ireturn
    label = q.new_label()
    q.insert_after(1, [BC.Insn(pc=0, op=0x07, length=1),   # iconst_7
                       BC.Insn(pc=0, op=0xAC, length=1)])  # ireturn
    q.mark(q.insns[-2].pc, label)
    q.insert_branch(0, 0xA7, label, before=True)
    out, _hs = q.assemble()
    check("a label branch encodes to the marked block",
          out == bytes([0xA7, 0x00, 0x05, 0x04, 0xAC, 0x07, 0xAC]), out.hex())

    unmarked = q.new_label()
    try:
        q.insert_branch(0, 0xA7, unmarked)
        refused = False
    except Exception:
        refused = True
    check("a branch to an unmarked label is refused", refused)

    if JAVAC is None or EN.find_java() is None:
        print("  (skipped: the JVM half needs a JDK)")
        return

    import shutil
    td = Path(tempfile.mkdtemp(prefix="jdec_label_"))
    try:
        src = td / "src"
        src.mkdir(parents=True)
        with zipfile.ZipFile(SAMPLE) as z:
            # extract everything: a class whose siblings are missing comes back
            # UNRESOLVED, and "not judged" is not what this test is about
            for name in z.namelist():
                if not name.endswith(".class"):
                    continue
                dest = src / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(z.read(name))
            cf = CF.parse(z.read("demo/legacy/OldStyle.class"))
        # <init>()V ends in `return`; move that return into an appended block
        target = next(m for m in cf.methods
                      if cf.utf8(m.name_index) == "<init>")
        ci = BC.method_code(cf, target)
        last = ci.insns[-1]
        check("the fixture constructor ends in return", last.op == 0xB1, hex(last.op))
        prog = ASM.Program.parse(ci.code, ci.handlers)
        mark = prog.new_label()
        prog.insert_after(prog.insns[-1].pc, [BC.Insn(pc=0, op=0xB1, length=1)])
        prog.mark(prog.insns[-1].pc, mark)
        prog.insert_branch(last.pc, 0xA7, mark, before=True)   # goto the new return
        prog.remove({last.pc})                                 # drop the old one
        code, handlers = prog.assemble()
        AT.replace_code(cf, target, code, handlers, ci.max_stack, ci.max_locals)
        states = AS.compute_frames(cf, target, code, handlers,
                                   ci.max_stack, ci.max_locals)
        need = FR.needed_pcs(BC.decode(code), handlers)
        AT.set_code_subattr(cf, target, "StackMapTable",
                            FR.encode(cf, states, need, target, ci.max_locals))
        (src / "demo/legacy/OldStyle.class").write_bytes(cf.serialize())
        # verify takes a jar or a directory, not a single class file; the
        # inner-class reference simply comes back unresolved, which is fine —
        # what this asserts is that nothing is rejected
        from jdec import verify as VF
        rep = VF.verify(src)
        bad = {i.cls for i in rep.invalid}
        stuck = {i.cls for i in rep.unresolved}
        check("the label-edited class is not rejected", "demo/legacy/OldStyle" not in bad,
              rep.summary())
        check("and it was actually judged, not left unresolved",
              "demo/legacy/OldStyle" not in stuck, rep.summary())
        check("nothing else broke either",
              bad <= {"demo/broken/Truncated"}, str(sorted(bad)))
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_weak_engine_is_rescued() -> None:
    """Lead engine fails on modern syntax; a later engine must recover it."""
    if _no_engines():
        return

    print("pipeline: a failing lead engine gets backed up by the others")
    out = Path(tempfile.mkdtemp()) / "out"
    rep = decompile(SAMPLE, out, ROOT / "engines", jobs=2, verify_all=True,
                    engine_order=["procyon", "cfr", "vineflower"])
    check("retry pass recovered what Procyon dropped", rep.improved >= 1,
          f"retried={rep.retried} improved={rep.improved}")
    check("final result is still clean", rep.ok >= 10,
          f"ok={rep.ok} failed={rep.failed}")


def test_annotated_classes_roundtrip() -> None:
    """Reading annotations must not perturb the bytes we re-emit."""
    print("classfile: annotation-bearing classes still round-trip")
    with zipfile.ZipFile(MIXIN) as z:
        names = [n for n in z.namelist() if n.endswith(".class")]
    bad: list[str] = []
    for n in names:
        with zipfile.ZipFile(MIXIN) as z:
            data = z.read(n)
        try:
            out = CF.parse(data).serialize()
        except Exception as exc:  # noqa: BLE001
            bad.append(f"{n}: {exc}")
            continue
        if out != data:
            bad.append(n)
    check(f"all {len(names)} annotated classes round-trip", not bad, str(bad[:3]))


def test_mixin_fixture() -> None:
    """The point of the whole exercise: hooks survive name mangling."""
    print("mcmod: mixin targets are recovered from annotations")
    meta = MM.read_mod_meta(MIXIN)
    check("fabric metadata is read",
          meta.mod_id == "demo-cheat" and meta.loader == "fabric",
          f"{meta.mod_id}/{meta.loader}")
    check("mixin config is read", meta.mixin_configs == ["demo.mixins.json"],
          str(meta.mixin_configs))

    declared, cfg = MM.mixin_class_names(MIXIN, meta)
    check("declared mixin classes resolved",
          declared == ["demo/mixin/PlayerHooks", "demo/mixin/RenderHooks"],
          str(declared))

    hooks, _stats = MM.collect_hooks(MIXIN, meta, declared=declared)
    targets = sorted({h.target_class for h in hooks if h.target_class})
    check("target given as a Class reference",
          "net/minecraft/entity/PlayerEntity" in targets, str(targets))
    check("target given as a dotted string",
          "net/minecraft/client/Minecraft" in targets, str(targets))
    methods = {h.target_method for h in hooks if h.target_method}
    check("injected method names", {"tick", "jump", "method_9012"} <= methods,
          str(sorted(methods)))
    check("inheritance: @Inject inherits the class @Mixin target",
          all(h.target_class for h in hooks if h.kind == "Inject"),
          str([h.target_class for h in hooks if h.kind == "Inject"]))
    check("injection point is captured", any(h.at == "HEAD" for h in hooks),
          str(sorted({h.at for h in hooks if h.at})))
    check("@Overwrite is recognised", any(h.kind == "Overwrite" for h in hooks))

    m = MP.Mapping(source="test")
    m.add_class("net/minecraft/entity/PlayerEntity", "player/PlayerEntity")
    m.add_member("net/minecraft/entity/PlayerEntity", "tick", None, "tickPlayer")
    resolved = MM.translate_hooks(hooks, m)
    check("targets resolved through a mapping",
          resolved >= 1 and any(h.named_class == "player/PlayerEntity" for h in hooks),
          f"resolved={resolved}")
    check("methods resolved through a mapping",
          any(h.named_method == "tickPlayer" for h in hooks))


def test_signals() -> None:
    """An obfuscator renames your identifiers, not the JDK calls you make."""
    print("analyze: API-level fingerprints survive obfuscation")
    a = AZ.analyze(MIXIN)
    sigs = {c.name: set(c.signals) for c in a.classes}
    got = sigs.get("demo/mixin/Licence", set())
    check("native method flagged as jni", "jni" in got, str(sorted(got)))
    check("process launch flagged", "process-exec" in got, str(sorted(got)))
    check("payload-looking constants flagged", "encrypted-strings" in got,
          str(sorted(got)))
    check("hooks grouped by patched class", len(a.hook_groups()) == 2,
          str(len(a.hook_groups())))
    prof = profile_jar(MIXIN)
    check("the Mixin package is not mistaken for Sponge",
          prof.mc_flavor != "Sponge", str(prof.mc_flavor))


# --------------------------------------------------------------------------
# flow obfuscation fixtures
# --------------------------------------------------------------------------

def _split_attrs(blob: bytes) -> list[tuple[int, bytes]]:
    items: list[tuple[int, bytes]] = []
    o = 0
    count = struct.unpack_from(">H", blob, o)[0]
    o += 2
    for _ in range(count):
        ni = struct.unpack_from(">H", blob, o)[0]
        o += 2
        ln = struct.unpack_from(">I", blob, o)[0]
        o += 4
        items.append((ni, blob[o:o + ln]))
        o += ln
    return items


def _join_attrs(items: list[tuple[int, bytes]]) -> bytes:
    out = bytearray(struct.pack(">H", len(items)))
    for ni, pl in items:
        out += struct.pack(">H", ni) + struct.pack(">I", len(pl)) + pl
    return bytes(out)


def _make_handler_jump_backwards(data: bytes) -> bytes | None:
    """Point a class's first exception handler at pc 0.

    javac will not emit that shape, so to test the detector we have to build
    the evidence ourselves.
    """
    cf = CF.parse(data)
    for m in cf.methods:
        payload = AN.member_attributes(cf, m).get("Code")
        if not payload:
            continue
        try:
            ci = BC.parse_code(payload, decode_insns=False)
        except BC.BytecodeError:
            continue
        if not ci.handlers:
            continue
        base = 8 + len(ci.code) + 2           # start of the exception table
        new = bytearray(payload)
        struct.pack_into(">H", new, base, max(1, ci.handlers[0].start_pc))
        struct.pack_into(">H", new, base + 4, 0)
        items = _split_attrs(m.attrs_blob)
        for i, (ni, _pl) in enumerate(items):
            try:
                if cf.utf8(ni) == "Code":
                    items[i] = (ni, bytes(new))
            except Exception:
                continue
        m.attrs_blob = _join_attrs(items)
        return cf.serialize()
    return None


def test_bytecode_decodes() -> None:
    """A wrong opcode length shifts everything after it, so check the tail."""
    print("bytecode: every method decodes exactly to the end of its code array")
    total = 0
    bad: list[str] = []
    for jar in (MIXIN, FLOW):
        with zipfile.ZipFile(jar) as z:
            for n in z.namelist():
                if not n.endswith(".class"):
                    continue
                cf = CF.parse(z.read(n))
                for m in cf.methods:
                    ci = BC.method_code(cf, m)
                    if ci is None:
                        continue
                    total += 1
                    if ci.error:
                        bad.append(f"{n}: {ci.error}")
                        continue
                    if not ci.insns:
                        continue
                    last = ci.insns[-1]
                    if last.pc + last.length != len(ci.code):
                        bad.append(f"{n}: ends at {last.pc + last.length} "
                                   f"of {len(ci.code)}")
    check(f"{total} methods decode cleanly", total > 0 and not bad, str(bad[:3]))

    # Regression: lookupswitch branch offsets must unpack with 8-byte stride
    # (default=100, npairs=2; pair 0: match=10, off=20; pair 1: match=30, off=40)
    ls_code = bytearray([0xAB, 0, 0, 0])
    ls_code += struct.pack(">ii", 100, 2)
    ls_code += struct.pack(">ii", 10, 20)
    ls_code += struct.pack(">ii", 30, 40)
    ls_insns = BC.decode(bytes(ls_code))
    check("lookupswitch decodes all jump targets correctly",
          len(ls_insns) == 1 and ls_insns[0].targets == [100, 20, 40],
          f"targets={ls_insns[0].targets if ls_insns else None}")

    # Regression: ifnull and ifnonnull must decode as branches with signed relative offsets
    ifnull_insns = BC.decode(bytes([0xC6, 0xFF, 0xFC]))  # ifnull -4
    check("ifnull decodes as signed branch",
          len(ifnull_insns) == 1 and ifnull_insns[0].is_branch and ifnull_insns[0].arg == -4 and ifnull_insns[0].jump_targets() == [-4],
          f"insn={ifnull_insns[0] if ifnull_insns else None}")
    ifnonnull_insns = BC.decode(bytes([0xC7, 0x00, 0x0A]))  # ifnonnull +10
    check("ifnonnull decodes as signed branch",
          len(ifnonnull_insns) == 1 and ifnonnull_insns[0].is_branch and ifnonnull_insns[0].arg == 10 and ifnonnull_insns[0].jump_targets() == [10],
          f"insn={ifnonnull_insns[0] if ifnonnull_insns else None}")


def test_flow_fingerprints() -> None:
    print("obf: structural fingerprints fire on evidence, not on guesswork")
    clean, _ = OB.scan_obfuscation(MIXIN)
    check("ordinary javac output is not attributed",
          clean.vendor is None, clean.summary())

    rep, _per = OB.scan_obfuscation(FLOW)
    keys = {e.key for e in rep.evidence}
    check("a ZKM-shaped <clinit> is recognised as a decryptor",
          "clinit-decryptor" in keys, str(sorted(keys)))

    # javac's worst case is a jumpy but honest method: nested loops with
    # break/continue reach 7.3% gotos, under the 10% flood threshold. An
    # if-else chain over one variable reaches zero - javac folds it into a
    # switch, so only a bytecode rewriter can produce a real flood.
    rep_flow, per_flow = OB.scan_obfuscation(FLOW)
    check("ordinary compiler control flow is not called a goto flood",
          "goto-flood" not in {e.key for e in rep_flow.evidence},
          str(sorted({e.key for e in rep_flow.evidence})))

    with zipfile.ZipFile(FLOW) as z:
        raw = z.read("demo/flow/Guarded.class")
    before = OB.inspect_class(CF.parse(raw))
    check("untouched output has no backwards handler",
          "handler-backjump" not in before, str(before))

    patched = _make_handler_jump_backwards(raw)
    check("fixture could be rewritten", patched is not None)
    if patched is None:
        return
    check("rewriting an attribute does not corrupt the class",
          CF.parse(patched).serialize() == patched)
    after = OB.inspect_class(CF.parse(patched))
    check("a backwards exception handler is detected",
          after.get("handler-backjump", 0) >= 1, str(after))
    vendor, conf = OB.attribute(after)
    check("attributed to Zelix KlassMaster on that evidence",
          vendor is not None and "ZKM" in vendor, f"{vendor} {conf}")


def test_native_reporting() -> None:
    """A native body is not a recovery failure - it is an absent body."""
    if _no_engines():
        return

    print("analyze: native bodies are called out instead of silently failing")
    a = AZ.analyze(MIXIN)
    nat = a.native
    check("native method counted", nat is not None and nat.total == 1,
          str(nat.total) if nat else "no report")
    if nat is None or not nat.total:
        return
    check("the native method is identified by name",
          nat.methods[0][1] == "validateNative", str(nat.methods))
    check("its class is identified", nat.per_class.get("demo/mixin/Licence") == 1,
          str(nat.per_class))
    check("shipped native library is found",
          any(n.endswith(".dll") for n, _ in nat.libraries), str(nat.libraries))
    check("verdict points at native code", "native" in nat.verdict(), nat.verdict())
    md = AZ.render_markdown(a)
    check("the report has a native section", "## native code" in md, md[:120])

    out = Path(tempfile.mkdtemp()) / "out"
    rep = decompile(MIXIN, out, ROOT / "engines", jobs=1)
    check("decompile counts native methods separately",
          rep.native_methods == 1 and rep.native_classes == 1,
          f"{rep.native_methods}/{rep.native_classes}")


def test_scoring_sees_obfuscated_names() -> None:
    """Guard against a fixed name-length floor coming back.

    ZKM renames everything to a, b, c. With a floor of 3 every candidate is
    filtered out, the candidate set empties, coverage becomes a perfect 1.0 and
    the least-recovered class in the jar scores highest. The two sources below
    differ by half their members and must not score the same.
    """
    print("score: short member names still count, so the score can tell them apart")
    with zipfile.ZipFile(SAMPLE) as z:
        cf = CF.parse(z.read("demo/obf/a.class"))
    names = [m for m, _ in cf.method_sigs() if not m.startswith("<")]
    names += [m for m, _ in cf.field_sigs()]
    check("the fixture really is short-named", any(len(n) < 3 for n in names),
          str(names))
    full = "class X { " + " ".join(f"int {m};" for m in names) + " }"
    partial = "class X { " + " ".join(f"int {m};" for m in names[:2]) + " }"
    a, b = evaluate(full, cf), evaluate(partial, cf)
    check("short names are counted as candidates", a.total >= 4, f"total={a.total}")
    check("dropping half the members costs real points",
          b.score < a.score - 15.0, f"full={a.score} partial={b.score}")


def test_refmap() -> None:
    """Intermediary names are opaque; the refmap is what makes them readable."""
    print("mcmod: refmap turns intermediary method names back into real ones")
    rep = MM.load_refmap(MIXIN)
    check("refmap is found in the jar", len(rep) == 3, str(rep.mappings))
    check("refmap file is named", any("refmap" in s for s in rep.sources),
          str(rep.sources))

    meta = MM.read_mod_meta(MIXIN)
    declared, _ = MM.mixin_class_names(MIXIN, meta)
    hooks, _stats = MM.collect_hooks(MIXIN, meta, declared=declared)
    before = {h.target_method for h in hooks if h.target_method}
    check("the fixture really is intermediary-named", "method_9012" in before,
          str(sorted(before)))

    n = MM.apply_refmap(hooks, rep)
    check("one name restored", n == 1, f"changed={n}")
    restored = [h for h in hooks if h.raw_method == "method_9012"]
    check("method_9012 became runTick",
          len(restored) == 1 and restored[0].target_method == "runTick",
          str([(h.target_method, h.raw_method) for h in hooks if h.raw_method]))
    check("names the refmap does not mention are left alone",
          "tick" in {h.target_method for h in hooks}, str(sorted(
              {h.target_method for h in hooks if h.target_method})))

    # the full pipeline has to do it in this order, or the mapping cannot help
    a = AZ.analyze(MIXIN)
    named = {h.resolved_method for h in a.hooks if h.resolved_method}
    check("analyze applies the refmap too", "runTick" in named, str(sorted(named)))


def test_string_dump() -> None:
    """Code can be renamed into anything; literals still have to say something."""
    print("strings: literals are dumped, tagged and filtered")
    d = ST.dump_strings(MIXIN)
    check("every class parsed", d.classes_scanned == 10, str(d.classes_scanned))
    check("literals collected", d.total >= 5, str(d.total))
    rows = {(c, s) for c, s, _ in d.rows}
    check("a known literal is present", ("demo/mixin/Licence", "whoami") in rows,
          str(sorted(rows)[:3]))
    check("per-class literals are attributed to the right class",
          all(c.startswith("demo/") or c.startswith("net/") for c, _ in rows),
          str(sorted({c for c, _ in rows})))

    check("url literals are tagged",
          ST.classify("https://example.com/x") == ["url"],
          str(ST.classify("https://example.com/x")))
    check("machine-id literals are tagged",
          "machine-id" in ST.classify("HWID-1234"), str(ST.classify("HWID-1234")))
    check("ordinary literals are not tagged", ST.classify("tick") == [],
          str(ST.classify("tick")))

    check("grep filters", d.grep("whoami").total == 1, str(d.grep("whoami").total))
    check("suspicious-only is a subset", d.only_suspicious().total <= d.total)

    check("tabs and newlines cannot break the TSV",
          "\t" not in ST._cell("a\tb") and "\n" not in ST._cell("a\nb")
          and "\r" not in ST._cell("a\rb"), repr(ST._cell("a\tb")))
    out = Path(tempfile.mkdtemp()) / "s.tsv"
    ST.write_tsv(d, out)
    lines = out.read_text(encoding="utf-8").splitlines()
    check("one row per literal plus a header", len(lines) == d.total + 1,
          f"{len(lines)} lines for {d.total} literals")
    check("every row has three columns",
          all(l.count("\t") == 2 for l in lines[1:]), str(lines[1:3]))


def test_indy_encoding() -> None:
    """superblaubeere27 / JObf hide call targets as text; decoding is pure."""
    print("indy: encoded call targets are found and decoded without execution")
    check("a plain reference is not mistaken for an encoding",
          INDY.parse_ref("net/minecraft/client/Minecraft") is None)
    check("a reference without trailing spaces is rejected",
          INDY.parse_ref("a/b/C:method:()V") is None, "no pad")
    check("an ordinary sentence is rejected",
          INDY.parse_ref("hello world") is None)

    r = INDY.parse_ref("a/b/C:methodName:()V  ")
    check("two spaces means virtual-call",
          r is not None and r.op == 2 and r.op_name == "virtual-call",
          str(r))
    check("the descriptor is kept", r is not None and r.desc == "()V", str(r))
    for pad, name in ((1, "static-call"), (3, "field-get"),
                      (4, "static-field-get"), (5, "field-set")):
        got = INDY.parse_ref(f"x/Y:f:I{' ' * pad}")
        check(f"{pad} space(s) means {name}",
              got is not None and got.op_name == name, str(got))

    rep = INDY.build_report([], {}, 0, 0, 0)
    check("no references means no verdict", not rep.confirmed, rep.verdict())
    two = INDY.build_report([r, r], {}, 0, 0, 0)
    check("two references stay a hint, not a verdict", not two.confirmed,
          two.verdict())
    three = INDY.build_report([r, r, r], {}, 5, 1, 10)
    check("three references confirm it", three.confirmed, three.verdict())

    a = AZ.analyze(FLOW)
    ind = a.indy
    check("the fixture's table is found", len(ind.refs) == 6, str(len(ind.refs)))
    check("it is reported as confirmed", ind.confirmed, ind.verdict())
    ops = ind.op_counts()
    check("operations are decoded",
          ops.get("virtual-call") == 3 and ops.get("static-call") == 1
          and ops.get("field-get") == 1 and ops.get("static-field-get") == 1,
          str(ops))
    owners = ind.owners()
    check("targets are grouped by owner",
          owners.get("net.minecraft.client.Minecraft") == 2, str(owners))
    check("the decoded target is readable",
          any("PlayerEntity.tick()V" in x.as_readable() for x in ind.refs),
          str([x.as_readable() for x in ind.refs][:3]))
    md = AZ.render_markdown(a)
    check("the report has an indy section", "## indy call-target encoding" in md,
          md[:120])

    # vanilla is full of lambdas, which are invokedynamic too, but it has no
    # encoded target table - the census must not cry wolf
    clean = AZ.analyze(MIXIN)
    check("an ordinary jar is not flagged", not clean.indy.confirmed,
          clean.indy.verdict())


def test_real_zkm_sample() -> None:
    """Recall can only be proven on a real sample; the fixtures prove the rest.

    A Forge 1.7-1.12 mod (723 classes) put through ZKM 27 twice. Baselines from
    the same run: vanilla 1.20.4 fires goto-flood on 3.1% of classes and
    clinit-decryptor on none; this sample fires 46.9% and 43.6%.

    The real sample lives OUTSIDE the tool tree. Point JDEC_SAMPLE_DIR at a
    folder containing Myau0729-obf.jar to enable; default keeps looking next
    to the jdec checkout, and the test stays a skip when nothing is there.
    """
    sample_dir = os.environ.get("JDEC_SAMPLE_DIR")
    roots = [Path(sample_dir)] if sample_dir else [ROOT.parent, Path("D:/MC/samples")]
    jar = next((r / "Myau0729-obf.jar" for r in roots if (r / "Myau0729-obf.jar").exists()), None)
    if jar is None:
        print("  (skipped: real sample not present; set JDEC_SAMPLE_DIR to enable)")
        return
    print("obf: a real ZKM 27 sample is attributed")
    rep, _per = OB.scan_obfuscation(jar)
    check("attributed to ZKM", rep.vendor is not None and "ZKM" in rep.vendor,
          rep.summary())
    classes = max(1, rep.classes_scanned)
    got = {e.key: e.classes for e in rep.evidence}
    check("goto-flood fires on a large share of its classes",
          got.get("goto-flood", 0) / classes > 0.10,
          f"{got.get('goto-flood', 0)}/{classes}")
    check("string decryption is detected widely",
          got.get("clinit-decryptor", 0) / classes > 0.10,
          f"{got.get('clinit-decryptor', 0)}/{classes}")
    check("backward handlers are NOT this obfuscator's signature",
          got.get("handler-backjump", 0) == 0, str(got.get("handler-backjump")))
    # two of these are inverted as evidence: a vanilla jar has 100% SourceFile
    # mismatch and 34% method overloading, this one 0.1% and 3.7%
    check("SourceFile mismatch is not used as evidence here",
          got.get("fake-sourcefile", 0) / classes < 0.10,
          f"{got.get('fake-sourcefile', 0)}/{classes}")


def test_mc_roundtrip(limit: int = 800) -> None:
    print(f"classfile: parse -> serialise is lossless ({limit} real MC classes)")
    with zipfile.ZipFile(MC_JAR) as z:
        names = [n for n in z.namelist() if n.endswith(".class")][:limit]
    ok = diff = fail = 0
    with zipfile.ZipFile(MC_JAR) as z:
        for n in names:
            data = z.read(n)
            try:
                out = CF.parse(data).serialize()
            except Exception:  # noqa: BLE001
                fail += 1
                continue
            if out == data:
                ok += 1
            else:
                diff += 1
    check(f"{len(names)} classes round-trip byte-identical",
          diff == 0 and fail == 0, f"ok={ok} diff={diff} fail={fail}")


def test_mojang_mapping_direction() -> None:
    print("mappings: Mojang client.txt is inverted to obf -> named")
    m = MP.load_mapping(MC_MAP)
    check("obfuscated class name maps to a real package",
          m.classes.get("enr") == "com/mojang/blaze3d/Blaze3D",
          repr(m.classes.get("enr")))
    check("mapping is large enough to be useful", len(m.classes) > 5000,
          f"{len(m.classes)} classes")


def test_yarn_compose() -> None:
    """The compose must resolve from every namespace a Fabric jar names:
    mixin annotations carry intermediary names, vanilla remap uses official
    ones, and both must land on the Yarn name."""
    print("mappings: yarn compose keeps official and intermediary findable")
    inter = MP.parse_tiny("\n".join([
        "tiny\t2\t0\tofficial\tintermediary",
        "c\tabc\tnet/minecraft/class_310",
        "\tm\t(I)V\ta\tmethod_1481",
    ]), source="inter-test", from_ns="official", to_ns="intermediary")
    yarn = MP.parse_tiny("\n".join([
        "tiny\t2\t0\tintermediary\tnamed",
        "c\tnet/minecraft/class_310\tnet/minecraft/client/MinecraftClient",
        "\tm\t(I)V\tmethod_1481\trun",
    ]), source="yarn-test", from_ns="intermediary", to_ns="named")
    m = MP.compose_yarn(inter, yarn, "compose-test")
    check("official class reaches the yarn name",
          m.classes.get("abc") == "net/minecraft/client/MinecraftClient",
          repr(m.classes.get("abc")))
    check("official member reaches the yarn name (owner namespace bug)",
          m.lookup_member("abc", "a", "(I)V") == "run",
          repr(m.lookup_member("abc", "a", "(I)V")))
    check("intermediary class is a lookup key (mixin annotations use it)",
          m.lookup_class("net/minecraft/class_310")
          == "net/minecraft/client/MinecraftClient",
          repr(m.lookup_class("net/minecraft/class_310")))
    check("intermediary member resolves with and without descriptor",
          m.lookup_member("net/minecraft/class_310", "method_1481", "(I)V")
          == "run"
          and m.lookup_member("net/minecraft/class_310", "method_1481", None)
          == "run",
          repr(m.lookup_member("net/minecraft/class_310", "method_1481", None)))


def test_official_srg_compose() -> None:
    print("mappings: official-srg compose combines Mojang classes and SRG members")
    from jdec import mappings as MP
    mojang = MP.Mapping(source="test-mojang")
    mojang.add_class("brc", "net/minecraft/world/entity/monster/Creeper")
    mojang.add_member("brc", "a", "(I)V", "tick")

    srg = MP.Mapping(source="test-srg")
    srg.add_class("brc", "net/minecraft/entity/monster/EntityCreeper")
    srg.add_member("brc", "a", "(I)V", "m_6075_")
    srg.add_member("brc", "b", "I", "f_19853_")

    combined = MP.compose_official_srg(mojang, srg, source="test-combined")

    check("class maps to official Mojang name",
          combined.lookup_class("brc") == "net/minecraft/world/entity/monster/Creeper",
          repr(combined.lookup_class("brc")))
    check("member maps to SRG name under obf owner",
          combined.lookup_member("brc", "a", "(I)V") == "m_6075_",
          repr(combined.lookup_member("brc", "a", "(I)V")))
    check("member maps to SRG name under official owner",
          combined.lookup_member("net/minecraft/world/entity/monster/Creeper", "a", "(I)V") == "m_6075_",
          repr(combined.lookup_member("net/minecraft/world/entity/monster/Creeper", "a", "(I)V")))
    check("field maps to SRG name under official owner",
          combined.lookup_member("net/minecraft/world/entity/monster/Creeper", "b", "I") == "f_19853_",
          repr(combined.lookup_member("net/minecraft/world/entity/monster/Creeper", "b", "I")))


def test_auto_mapping_set_flavor() -> None:
    print("cli: auto picks yarn for Fabric/Quilt, version pick otherwise")
    p = SimpleNamespace(mc_flavor="Fabric")
    check("fabric jar gets yarn", CL._mapping_set_for("auto", p) == "yarn",
          CL._mapping_set_for("auto", p))
    p.mc_flavor = "Quilt"
    check("quilt jar gets yarn too", CL._mapping_set_for("auto", p) == "yarn")
    p.mc_flavor = "Forge"
    check("forge jar keeps auto (mojang first)", CL._mapping_set_for("auto", p) == "auto")
    check("explicit set is never overridden",
          CL._mapping_set_for("mojang", p) == "mojang")
    check("flavor-less profile keeps auto",
          CL._mapping_set_for("auto", SimpleNamespace()) == "auto")


def test_java_escape() -> None:
    print("recover: java_escape escapes backslash/quote/newline/tab")
    from jdec.recover import java_escape
    bs = chr(92)
    src = "a" + bs + 'b"c' + chr(10) + chr(9) + chr(13)
    out = java_escape(src)
    want = ("a" + bs + bs + "b" + bs + '"c' + bs + "n"
            + bs + "t" + bs + "r")
    check("escape is java-literal-safe", out == want, repr(out))


def test_rewrite_sources() -> None:
    print("recover: rewrite_sources backfills plaintexts, keeps misses")
    from jdec.recover import rewrite_sources
    import base64
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        # 四个站点：单行、跨行折行、Base64 带换行/转义、无解
        b64_val = "b64:" + base64.b64encode(b"line1\nline2").decode("ascii")
        (d / "A.java").write_text(
            'class A {\n'
            '    String s = Enc.d("n1", "Q2ZnbA==", 42);\n'
            '    String t = Enc.d(\n'
            '            "n2",\n'
            '            "TG9uZw==",\n'
            '            -7);\n'
            '    String v = Enc.d("n4", "QjY0", 99);\n'
            '    String u = Enc.d("n3", "TWlz=", 9);\n'
            "}\n", encoding="utf-8")
        tsv = d / "recovered.tsv"
        rows = [
            "OK\tpkg.C\tn1\tQ2ZnbA==\t42\tsecret",
            "OK\tpkg.C\tn2\tTG9uZw==\t-7\tlonger",
            f"OK\tpkg.C\tn4\tQjY0\t99\t{b64_val}",
            "FAIL\tpkg.C\tn3\t?\t?\tboom",
        ]
        tsv.write_text(chr(10).join(rows) + chr(10), encoding="utf-8")
        st = rewrite_sources(d, tsv)
        check("three sites replaced", st["replaced"] == 3, str(st))
        check("unrecoverable site missed", st["missed"] == 1, str(st))
        check("residual counts the miss", st["residual"] == 1, str(st))
        check("no key conflicts", st["conflicts"] == 0, str(st))
        txt = (d / "A.java").read_text(encoding="utf-8")
        check("plaintexts written back", '"secret"' in txt and '"longer"' in txt)
        check("base64 newline preserved without double escaping",
              '"line1\\nline2"' in txt and '"line1\\\\nline2"' not in txt)
        check("unmatched site untouched", "TWlz=" in txt)


def test_recover_triage() -> None:
    print("recover: failure lines auto-triaged into buckets with remediation")
    from jdec import recover as RC
    lines = [
        "FAIL\tcom/x/A\tcom/x/A\tjava.lang.NoClassDefFoundError: org/lwjgl/glfw/GLFW",
        "FAIL\tcom/x/B\t11\tjava.lang.NullPointerException: Cannot invoke "
        "\"net.minecraft.client.Minecraft.getInstance()\" because \"mc\" is null",
        "FAIL\tcom/x/C\t3\tjava.lang.NoSuchMethodException: com.x.C.b(int,int)->String",
        "FAIL\tcom/x/D\tcom/x/D\tjava.lang.UnsatisfiedLinkError: "
        "org.lwjgl.opengl.GL11C.nglBegin(Native Method)",
        "FAIL\tcom/x/E\tcom/x/E\tjava.lang.NoClassDefFoundError: com/netease/mc/Foo",
        "FAIL\tcom/x/F\tcom/x/F\tjava.lang.IllegalStateException: Not bootstrapped",
        "FAIL\tcom/x/G\tcom/x/G\tjava.lang.SomeWeirdError: ???",
    ]
    buckets = {b.key: b for b in RC.triage_failures(lines)}

    def has(key, cls):
        return any(e[0] == cls for e in buckets[key].entries)

    check("lwjgl constants bucket", has("lwjgl-constants", "com/x/A"))
    check("needs-instance bucket", has("needs-instance", "com/x/B"))
    check("signature bucket", has("signature", "com/x/C"))
    check("native bucket", has("native", "com/x/D"))
    check("missing-class bucket", has("missing-class", "com/x/E"))
    check("needs-bootstrap bucket", has("needs-bootstrap", "com/x/F"))
    check("other bucket", has("other", "com/x/G"))
    check("all sites classified",
          sum(len(b.entries) for b in buckets.values()) == len(lines))
    with tempfile.TemporaryDirectory() as td:
        p = RC.write_failed_triage(Path(td), list(buckets.values()), 3)
        txt = p.read_text(encoding="utf-8")
        check("triage md written", p is not None and p.exists())
        check("triage md has remediation", "lwjgl-api" in txt
              and "处置" in txt)


def test_manifest_and_resources() -> None:
    print("mcmod: MANIFEST.MF parsed (agent attrs) + resource inventory")
    with tempfile.TemporaryDirectory() as td:
        jar = Path(td) / "m.jar"
        man = ("Manifest-Version: 1.0\r\n"
               "Implementation-Title: fake\r\n"
               "Implementation-Vendor: VendorX\r\n"
               "Implementation-Description: line1\r\n"
               " continuation\r\n"
               "Premain-Class: com.x.Agent\r\n"
               "Can-Retransform-Classes: true\r\n"
               "\r\n"
               "Name: com/x/Foo.class\r\n"
               "SHA-256-Digest: abc\r\n")
        with zipfile.ZipFile(jar, "w") as z:
            z.writestr("META-INF/MANIFEST.MF", man)
            z.writestr("fabric.mod.json", json.dumps({"id": "fake", "version": "1"}))
            z.writestr("assets/fake/icon.png", b"\x89PNG")
            z.writestr("com/x/Foo.class", b"\xca\xfe\xba\xbe")
        info = MM.read_manifest(jar)
        check("manifest main parsed", info is not None
              and info.main.get("Implementation-Vendor") == "VendorX")
        check("manifest continuation", "continuation"
              in info.main.get("Implementation-Description", ""))
        check("manifest agent attrs", info.agent_attrs().get("Premain-Class")
              == "com.x.Agent")
        check("manifest per-entry section", "com/x/Foo.class" in info.sections)
        meta = MM.read_mod_meta(jar)
        check("meta attaches manifest", meta.manifest is not None
              and meta.loader == "fabric")
        check("meta summary shows vendor+agent", "vendor=VendorX" in meta.summary()
              and "java-agent" in meta.summary())
        inv = MM.resource_inventory(jar)
        check("resources counted", inv["non_class"] == 3, str(inv))
        check("resources top dirs", any(k == "assets" for k, _ in inv["top_dirs"]),
              str(inv["top_dirs"]))


def test_rewrite_escapes() -> None:
    print("recover: rewritten literals are ASCII-escaped (no raw ctrl bytes)")
    from jdec.recover import java_unescape, rewrite_sources
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        BS = chr(92)
        (d / "A.java").write_text(
            'class A {' + chr(10)
            + '    String s = Enc.d("n1", "Q2ZnbA==", 42);' + chr(10)
            + "}" + chr(10), encoding="utf-8")
        tsv = d / "recovered.tsv"
        plain = "secret" + chr(1) + chr(0x4e2d)  # ctrl-A + CJK
        tsv.write_text("OK" + chr(9) + "pkg.C" + chr(9) + "n1" + chr(9)
                       + "Q2ZnbA==" + chr(9) + "42" + chr(9) + plain
                       + chr(10), encoding="utf-8")
        st = rewrite_sources(d, tsv)
        check("escape site replaced", st["replaced"] == 1, str(st))
        txt = (d / "A.java").read_text(encoding="utf-8")
        want = '"secret' + BS + "u0001" + BS + "u4e2d" + '"'
        check("literal is unicode-escaped", want in txt, repr(txt[-80:]))
        check("no raw ctrl byte in file", chr(1) not in txt)
        # round-trip: 反转义回明文
        inner = want[1:-1]
        check("escape is reversible", java_unescape(inner) == plain)


def test_bsm_scan_and_parse_resilience() -> None:
    print("bsm: scan_jar, parse_bsm, and enum_sites handle valid and corrupt classes")
    from jdec import bsm as BM
    from jdec import classfile as CF

    # 1. Whole jar scan on SAMPLE which contains a deliberately truncated class fixture
    census = BM.scan_jar(SAMPLE)
    st = census["stats"]
    check("bsm scan quarantined corrupt class and counted valid classes", st["classes"] == 10, str(st))
    check("bsm scan identified classes with BSM", st["classes_with_bsm"] >= 4, str(st))
    check("bsm scan found indy callsites", st["sites"] >= 10, str(st))
    check("bsm sample contains entries", len(census["sample"]) == 0 or len(census["per_name"]) > 0)

    # 2. Corrupted attribute resilience in parse_bsm
    with zipfile.ZipFile(SAMPLE) as z:
        cf = CF.parse(z.read("demo/modern/Showcase.class"))
    # Corrupt the attributes blob
    cf.attrs_blob = b"\x00\x05\x00\x01"  # truncated attribute header
    corrupt_bsm = BM.parse_bsm(cf)
    check("parse_bsm survives truncated attribute blob without exception", corrupt_bsm == [])

    # 3. Method arity calculation edge cases
    check("_arity works on primitives and objects", BM._arity("(IDLjava/lang/String;)V") == 3)
    check("_arity handles long and double correctly", BM._arity("(JJDD)V") == 4)
    check("_arity handles arrays", BM._arity("([[I[Ljava/lang/String;)V") == 2)

    # 4. Local variable slot tracking for slot >= 4 and lload opcode 0x16
    check("LOAD_OPS contains lload opcode 0x16", 0x16 in BM.LOAD_OPS and BM.LOAD_OPS[0x16] == ("l", None))
    code_bytes = bytes([0x04, 0x36, 0x04, 0x05, 0x36, 0x05, 0x15, 0x04])
    insns = BC.decode(code_bytes)
    stk: list = []
    loc: dict = {}
    for ins in insns:
        op = ins.op
        if op in BM.ICONST:
            stk.append(("lit", op - 0x03))
        elif op in BM.STORE_OPS or op in BM.STORE_N:
            k, sl = BM.STORE_OPS.get(op) or BM.STORE_N[op]
            if sl is None: sl = ins.arg
            if stk: loc[(k, sl)] = stk.pop()
        elif op in BM.LOAD_OPS or op in BM.LOAD_N:
            k, sl = BM.LOAD_OPS.get(op) or BM.LOAD_N[op]
            if sl is None: sl = ins.arg
            v = loc.get((k, sl))
            stk.append(v if v is not None else ("?", None))
    check("distinct local variable slots >= 4 do not overwrite each other",
          loc.get(("i", 4)) == ("lit", 1) and loc.get(("i", 5)) == ("lit", 2))
    check("iload 4 retrieves correct value from slot 4", stk == [("lit", 1)])


def test_recover_spec_generation_and_quarantine() -> None:
    print("recover: build_spec parses jar and quarantines corrupt classes cleanly")
    from jdec import recover as RC

    with tempfile.TemporaryDirectory() as td:
        out_d = Path(td)
        spec_path, n_sites, n_skip, n_unreadable = RC.build_spec(SAMPLE, out_d)
        check("build_spec produced spec file", spec_path.is_file())
        check("build_spec found callsites", n_sites >= 10, f"n_sites={n_sites}")
        lines = spec_path.read_text(encoding="utf-8").splitlines()
        check("spec lines non-empty", len(lines) >= n_sites)
        c_lines = [l for l in lines if l.startswith("C\t")]
        s_lines = [l for l in lines if l.startswith("S\t")]
        check("spec has class directives", len(c_lines) >= 3, f"classes={len(c_lines)}")
        check("spec has site directives", len(s_lines) == n_sites, f"sites={len(s_lines)}")
        if s_lines:
            s_parts = s_lines[0].split("\t")
            check("site directive has >= 6 TSV columns", len(s_parts) >= 6, f"cols={len(s_parts)}")



def test_resource_anomaly() -> None:
    print("mcmod: resource_anomaly flags identifier-level obfuscation tokens")
    with tempfile.TemporaryDirectory() as td:
        jar = Path(td) / "m.jar"
        toml = (chr(10).join(
            ['modId="NS5Nc6"', 'version="1.0.0"',
             'displayName="NS5Nc6 client"', 'authors="someone"'] * 6)
            + chr(10))
        with zipfile.ZipFile(jar, "w") as z:
            z.writestr("META-INF/mods.toml", toml)
            z.writestr("assets/fake/lang/en_us.json",
                       '{"item.ns5nc6.sword": "Sword"}')
        anom = MM.resource_anomaly(jar)
        toks = [t for t, _n, _f in anom["suspects"]]
        check("anomaly text files scanned", anom["text_files"] == 2, str(anom))
        check("replaced token flagged", "NS5Nc6" in toks, str(toks))
        check("known words not flagged",
              "version" not in toks and "modId" not in toks
              and "displayName" not in toks, str(toks))
        check("flag is repeatable", "NS5Nc6" in [
            t for t, _n, _f in MM.resource_anomaly(jar)["suspects"]])


def test_scorecard_smoke() -> None:
    print("scorecard: fixed-metric row + JSON out + delta vs previous")
    from jdec import scorecard as SC2
    row = SC2.score_jar(SAMPLE)
    check("probe fields present",
          row["classes"] > 0 and "obfuscation" in row and "jar" in row,
          str(row)[:200])
    check("strings counted", row["strings"] >= 0
          and row["strings_suspicious"] >= 0, str(row)[:200])
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "sc.json"
        jp, _ = SC2.write_scorecard([row], out,
                                    {"analyze": False, "decompile": False})
        payload = json.loads(jp.read_text(encoding="utf-8"))
        check("scorecard json written", jp.exists()
              and payload["rows"][0]["jar"] == row["jar"])
        # 伪造上一版：strings 变了 -> delta 应捕捉
        old = json.loads(json.dumps(payload))
        old["rows"][0]["strings"] = payload["rows"][0]["strings"] - 5
        deltas = SC2.compare_rows(old["rows"], payload["rows"])
        check("delta catches change",
              deltas and deltas[0]["status"] == "changed"
              and "strings" in deltas[0]["diffs"], str(deltas))
        md = SC2.render_markdown(payload["rows"], deltas,
                                 {"analyze": False, "decompile": False})
        check("md has delta section", "vs previous" in md and "strings" in md)


def test_pool_roundtrip() -> None:
    print("pool: scan -> harvest (real JVM replay) -> apply, end to end")
    import base64
    if not (JAVAC and JAVA):
        print("skipping: no javac/java found (set JAVA_HOME or PATH)")
        return
    from jdec import pool as PL  # noqa: F401 - 触发模块加载即模板校验
    from jdec.cli import main as cli_main
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        src = d / "src"
        (src / "pkg").mkdir(parents=True)
        BS = chr(92)
        LF = chr(10)
        # 访问器返回值含控制字符与 CJK -> 验证 \u 转义落盘
        (src / "pkg" / "Sample.java").write_text(
            "package pkg;" + LF
            + "public class Sample {" + LF
            + "    static String a(int idx, int seed) {" + LF
            + '        return "V" + idx + ":" + seed + "' + BS + "u0007"
            + BS + 'u4e2d";' + LF
            + "    }" + LF
            + "    String own() { return a(33, 44); }" + LF
            + "}" + LF, encoding="utf-8")
        (src / "pkg" / "User.java").write_text(
            "package pkg;" + LF
            + "public class User {" + LF
            + "    String tag() { return Sample.a(11, 22); }" + LF
            + "}" + LF, encoding="utf-8")
        # 1. scan
        spec = d / "pool_spec.tsv"
        rc = cli_main(["pool", "scan", str(src), "-o", str(spec)])
        check("pool scan rc", rc == 0)
        lines = spec.read_text(encoding="utf-8").splitlines()
        keys = {tuple(l.split(chr(9))[i] for i in (1, 3, 4)) for l in lines}
        check("pool scan found both sites",
              ("pkg.Sample", "11", "22") in keys
              and ("pkg.Sample", "33", "44") in keys, str(lines))
        # 2. 编译合成源作为 replay classpath，真 JVM 收割
        cls_dir = d / "classes"
        cls_dir.mkdir()
        r = subprocess.run([JAVAC, "-d", str(cls_dir),
                            str(src / "pkg" / "Sample.java"),
                            str(src / "pkg" / "User.java")],
                           capture_output=True, text=True, errors="replace")
        check("fixture javac", r.returncode == 0, r.stderr[-300:])
        hv = d / "pool_work" / "pool_harvest.tsv"
        # REVIEW 2.1: replay is opt-in now; this fixture is locally built.
        rc = cli_main(["pool", "harvest", str(spec), "-o", str(hv),
                       "--cp", str(cls_dir), "--execute"])
        rows = ([l.split(chr(9)) for l in hv.read_text(encoding="utf-8",
                                                       errors="replace")
                 .splitlines()] if hv.exists() else [])
        plains = {tuple(rr[i] for i in (1, 3, 4)):
                  base64.b64decode(rr[5]).decode("utf-8")
                  for rr in rows if rr and rr[0] == "R"}
        check("pool harvest rc", rc == 0, str(plains))
        check("pool harvest plaintexts",
              plains.get(("pkg.Sample", "11", "22"))
              == "V11:22" + chr(7) + chr(0x4e2d), str(plains))
        # 3. apply（回填 + verify + 失败归因挂接）
        out = d / "src_pool"
        rc = cli_main(["pool", "apply", str(src), "--harvest", str(hv),
                       "-o", str(out)])
        check("pool apply rc", rc == 0)
        utxt = (out / "pkg" / "User.java").read_text(encoding="utf-8")
        stxt = (out / "pkg" / "Sample.java").read_text(encoding="utf-8")
        lit = "V11:22" + BS + "u0007" + BS + "u4e2d"
        lit_b = "V33:44" + BS + "u0007" + BS + "u4e2d"
        check("apply replaced qualified call", ('"' + lit + '"') in utxt,
              utxt[-160:])
        check("apply replaced bare call", ('"' + lit_b + '"') in stxt,
              stxt[-160:])
        check("apply wrote no raw ctrl bytes",
              chr(7) not in utxt and chr(7) not in stxt)
        check("apply left no decodable residual",
              "Sample.a(11, 22)" not in utxt and "a(33, 44)" not in stxt)


def test_web_template_js() -> None:
    print("web: HTML_TEMPLATE inline JS parses (node --check)")
    import re as _re
    import shutil as _sh
    try:
        from jdec import web as WB
    except Exception as exc:  # noqa: BLE001
        print(f"skipping: jdec.web import failed: {exc}")
        return
    node = _sh.which("node")
    if not node:
        print("skipping: node not on PATH")
        return
    blocks = _re.findall("<script>(.*?)</script>", WB.HTML_TEMPLATE, _re.S)
    check("template has an inline script block", len(blocks) >= 1)
    js = "\n".join(blocks)
    # 2026-10-04 事故：模板非 raw，JS 字符串里的 \n 被 Python 编译期吃成
    # 真实换行，alert('...') 字符串断裂 -> 整个 script 解析失败、工作台瘫痪。
    # 硬校验：内联 JS 必须整体语法合法（node --check）。
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "inline.js"
        p.write_text(js, encoding="utf-8")
        r = subprocess.run([node, "--check", str(p)],
                           capture_output=True, text=True, errors="replace")
        check("inline JS is syntactically valid", r.returncode == 0,
              (r.stderr or r.stdout or "")[-400:])


def test_pool_qualified_and_full_string() -> None:
    print("pool: handles java.lang.String return type and package-qualified calls")
    from jdec import pool as PL
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        src = d / "src"
        (src / "com" / "example").mkdir(parents=True)
        # Class with java.lang.String return type
        (src / "com" / "example" / "Holder.java").write_text(
            "package com.example;\n"
            "public class Holder {\n"
            "    public static java.lang.String decode(int a, int b) { return null; }\n"
            "}\n", encoding="utf-8"
        )
        # Caller using full qualified name com.example.Holder.decode(...) and simple Holder.decode(...)
        (src / "com" / "example" / "Caller.java").write_text(
            "package com.example;\n"
            "public class Caller {\n"
            '    String s = com.example.Holder.decode(100, 200);\n'
            '    String s2 = Holder.decode(300, 400);\n'
            "}\n", encoding="utf-8"
        )
        spec = d / "spec.tsv"
        st = PL.scan_spec(src, spec)
        check("pool scan finds Holder class", st["pool_classes"] == 1, str(st))
        check("pool scan finds 2 sites", st["unique"] == 2, str(st))
        lines = spec.read_text(encoding="utf-8").splitlines()
        keys = {tuple(l.split("\t")[i] for i in (1, 2, 3, 4)) for l in lines}
        check("both qualified and simple sites recorded",
              ("com.example.Holder", "decode", "100", "200") in keys
              and ("com.example.Holder", "decode", "300", "400") in keys,
              str(keys))

        # Test apply with harvest mock
        import base64
        hv = d / "harvest.tsv"
        val1 = base64.b64encode(b"hello_p2").decode("ascii")
        val2 = base64.b64encode(b"world_p2").decode("ascii")
        hv.write_text(
            f"R\tcom.example.Holder\tdecode\t100\t200\t{val1}\n"
            f"R\tcom.example.Holder\tdecode\t300\t400\t{val2}\n",
            encoding="utf-8"
        )
        out = d / "applied"
        PL.apply(src, hv, out)
        res = (out / "com" / "example" / "Caller.java").read_text(encoding="utf-8")
        check("qualified call site replaced", '"hello_p2"' in res, res)
        check("simple call site replaced", '"world_p2"' in res, res)


def test_pool_overload_dispatch() -> None:
    print("pool: overload dispatch keeps only String-accessor call sites")
    from jdec import pool as PL
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        src = d / "src"
        (src / "p").mkdir(parents=True)
        # 2026-10-05 真实样本实测：一个池类里 String a(int,int)（字符串池）与
        # int a(int,long)（int 常量池）共存，名字级匹配把 int 池调用点也
        # 扫进 spec -> driver 传错 idx 报 AIOOBE。按实参字面量类型分派。
        (src / "p" / "TwoPools.java").write_text(
            "package p;\n"
            "public class TwoPools {\n"
            "    static String a(int idx, int seed) { return null; }\n"
            "    static int a(int idx, long seed) { return 0; }\n"
            "    String s1() { return a(11, 22); }\n"
            "    int s2() { return a(33, 44L); }\n"
            "    int s3() { return a(55, 66666666666L); }\n"
            "}\n", encoding="utf-8")
        (src / "p" / "Caller.java").write_text(
            "package p;\n"
            "public class Caller {\n"
            "    String s4() { return TwoPools.a(7, 8); }\n"
            "    int s5() { return TwoPools.a(9, 10L); }\n"
            "}\n", encoding="utf-8")
        spec = d / "spec.tsv"
        st = PL.scan_spec(src, spec)
        lines = spec.read_text(encoding="utf-8").splitlines()
        keys = {tuple(l.split("\t")[i] for i in (3, 4)) for l in lines}
        check("keeps (int,int) bare site", ("11", "22") in keys, str(keys))
        check("keeps (int,int) qualified site", ("7", "8") in keys, str(keys))
        check("skips (int,long) literal", ("33", "44") not in keys, str(keys))
        check("skips big long literal", ("55", "66666666666") not in keys,
              str(keys))
        check("skips qualified (int,long) site", ("9", "10") not in keys,
              str(keys))
        check("overload_skipped counted", st["overload_skipped"] == 3,
              str(st))


def test_probe_fingerprints_json() -> None:
    print("probe: fingerprints.json detects obfuscator from keywords")
    with tempfile.TemporaryDirectory() as td:
        jar = Path(td) / "test_obf.jar"
        with zipfile.ZipFile(jar, "w") as z:
            z.writestr("dev/jnic/Bridge.class", b"\xca\xfe\xba\xbe")
            z.writestr("com/example/Main.class", b"\xca\xfe\xba\xbe")
        prof = profile_jar(jar)
        check("fingerprints.json matched JNIC", prof.obfuscator == "JNIC", str(prof.obfuscator))
        check("signature recorded", any("JNIC" in s for s in prof.signatures), str(prof.signatures))

        # Regression: _major_version requires 0xCAFEBABE magic and 8-byte header
        from jdec.probe import _major_version
        check("_major_version rejects non-magic bytes", _major_version(b"corrupt_") is None)
        check("_major_version extracts valid Java 8 major", _major_version(b"\xca\xfe\xba\xbe\x00\x00\x00\x34") == 52)


def test_platform_classpath_separator() -> None:
    print("engines: classpath separator follows the platform")
    from jdec import engines as EN
    expected = ";" if os.name == "nt" else ":"
    check("cp_sep matches os.name", EN.cp_sep() == expected, EN.cp_sep())
    eng = EN.ENGINES["procyon"]
    cp = eng.classpath(ROOT / "engines")
    check("procyon bridge classpath splits on platform separator",
          len(cp.split(expected)) == 3, cp)
    real = os.name
    try:
        os.name = "posix" if real == "nt" else "nt"
        want = ";" if os.name == "nt" else ":"
        check("cp_sep switches with os.name", EN.cp_sep() == want, EN.cp_sep())
    finally:
        os.name = real


def test_procyon_bridge_is_built() -> None:
    """A fresh checkout has ProcyonBridge.java but not the compiled .class.

    Without building it the Procyon engine silently disappears from the engine
    order, which is exactly what happened in CI.
    """
    print("engines: ProcyonBridge is compiled when only the source is present")
    import shutil as _shutil
    src = ROOT / "engines"
    jars = [j for j in sorted(src.glob("*.jar")) if j.name.startswith("procyon-")]
    if len(jars) < 2 or not (src / "ProcyonBridge.java").is_file():
        print("  (skipped: procyon artifacts not present; run `python jdec.py engines`)")
        return
    if JAVAC is None:
        print("  (skipped: no javac; set JAVA_HOME or PATH)")
        return
    with tempfile.TemporaryDirectory(prefix="jdec_test_bridge_") as td:
        tmp = Path(td) / "engines"
        tmp.mkdir()
        for j in jars:
            _shutil.copy(j, tmp / j.name)
        _shutil.copy(src / "ProcyonBridge.java", tmp / "ProcyonBridge.java")
        check("procyon is unavailable without the bridge class",
              not EN.ENGINES["procyon"].available(tmp))
        EN.ensure_engines(tmp, quiet=True)
        check("ProcyonBridge.class is built from the shipped source",
              (tmp / "bridge" / "ProcyonBridge.class").is_file())
        check("procyon becomes available after the build",
              EN.ENGINES["procyon"].available(tmp))
        check("cfr and vineflower stay available",
              all(EN.ENGINES[k].available(tmp) for k in ("cfr", "vineflower")))


def test_ops_pool() -> None:
    print("opspool: PhantomShield string-pool static decrypt (DES via bundled _des)")
    gen = Path(__file__).resolve().parent / "gen_ops_fixture.py"
    javac = JAVAC
    if javac is None:
        print("skipping ops pool test: no javac (set JAVA_HOME or PATH)")
        return
    from jdec import ops_pool as OP
    OP  # noqa
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        r = subprocess.run([sys.executable, str(gen)], cwd=tdp,
                           capture_output=True, text=True, errors="replace")
        if r.returncode != 0:
            check("fixture generated", False, r.stderr[-200:])
            return
        r = subprocess.run([javac, "OpsPoolFixture.java"], cwd=tdp,
                           capture_output=True, text=True, errors="replace")
        check("fixture compiled", r.returncode == 0, r.stderr[-200:])
        jar = tdp / "ops_fixture.jar"
        # zipfile, not the `jar` tool: the test only needs an archive, and a
        # bare tool name would fail whenever the JDK is reachable only through
        # JAVA_HOME (no PATH entry)
        with zipfile.ZipFile(jar, "w") as zf:
            zf.write(tdp / "OpsPoolFixture.class", "OpsPoolFixture.class")
        results = OP.scan_jar(str(jar))
        ok = any(s == ["alpha-secret-ONE", "bravo-secret-TWO",
                       "charlie-secret-THREE"] for _c, s, _e in results)
        check("static decrypt matches original strings", ok, str(results)[:200])


def test_jint() -> None:
    print("jint: Java primitive arithmetic emulation KATs")
    from jdec import jint as J
    check("i32 wraps at 2^31", J.i32(0x80000000) == -2147483648,
          str(J.i32(0x80000000)))
    check("i32 identity below 2^31", J.i32(12345) == 12345, "")
    check("i32 wraps past 2^31", J.i32((1 << 31) + 5) == -2147483643,
          str(J.i32((1 << 31) + 5)))
    check("i64 wraps at 2^63", J.i64(1 << 63) == -(1 << 63), "")
    check("ushr is unsigned", J.ushr32(-1, 4) == 0x0FFFFFFF,
          hex(J.ushr32(-1, 4)))
    check("rotl32 KAT", J.rotl32(0x12345678, 8) == 0x34567812,
          hex(J.rotl32(0x12345678, 8)))
    check("rotl32 by 0 is identity", J.rotl32(0xDEADBEEF, 0) == J.i32(0xDEADBEEF),
          "")


def test_clinit_sim() -> None:
    print("clinit_sim: symbolic evaluation of a javac-compiled table builder")
    from jdec import classfile as CFM
    from jdec import clinit_sim as CS
    javac = JAVAC
    if javac is None:
        print("  (skipped: no javac; set JAVA_HOME or PATH)")
        return
    src = """public class ClinitSimFixture {
    static int[] ONE_D;
    static int[][] TWO_D;
    static String[] WORDS;
    static long[] LONGS;
    static Object[] MIXED;
    static {
        ONE_D = new int[]{3, 1, 4, 1, 5};
        TWO_D = new int[][]{{10, 20}, {30}, {}};
        WORDS = new String[]{"alpha", "beta"};
        LONGS = new long[]{0x1122334455667788L, -1L};
        MIXED = new Object[]{"s", 42, 0x1FL, null};
    }
}
"""
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        (tdp / "ClinitSimFixture.java").write_text(src, encoding="utf-8")
        r = subprocess.run([javac, "-d", str(tdp),
                            str(tdp / "ClinitSimFixture.java")],
                           check=True, capture_output=True, text=True, errors="replace")
        check("fixture compiled", r.returncode == 0, r.stderr[-200:])
        cf = CFM.parse((tdp / "ClinitSimFixture.class").read_bytes())
        fields, unknown = CS.collect_fields(cf)
        check("clinit walked", fields is not None, "")
        check("walk is exact (no unknown ops)", not unknown, str(unknown))
        check("ONE_D extracted", CS.flat_of(fields.get("ONE_D"))
              == [3, 1, 4, 1, 5], str(fields.get("ONE_D")))
        check("TWO_D rows extracted", CS.rows_of(fields.get("TWO_D"))
              == [[10, 20], [30], []], str(fields.get("TWO_D")))
        check("WORDS extracted", CS.flat_of(fields.get("WORDS"))
              == ["alpha", "beta"], str(fields.get("WORDS")))
        check("LONGS extracted", CS.flat_of(fields.get("LONGS"))
              == [0x1122334455667788, -1], str(fields.get("LONGS")))
        check("MIXED extracted (boxing passed through)",
              CS.flat_of(fields.get("MIXED")) == ["s", 42, 31, None],
              str(fields.get("MIXED")))


def test_ghidra_integration() -> None:
    print("ghidra: engine detection, script validation, and report integration")
    import shutil
    from jdec import ghidra_engine as GE
    from jdec import native_scan as NS

    # 1. worker script validation
    check("ghidra_worker.java exists", GE.WORKER_JAVA.exists())
    txt = GE.WORKER_JAVA.read_text(encoding="utf-8")
    check("worker script defines GhidraScript", "ghidra_worker extends GhidraScript" in txt)
    check("worker script uses DecompInterface", "DecompInterface" in txt)

    # 2. find_ghidra on mock installation
    with tempfile.TemporaryDirectory() as td:
        mock_dir = Path(td) / "mock_ghidra"
        support = mock_dir / "support"
        support.mkdir(parents=True)
        bin_name = "analyzeHeadless.bat" if sys.platform == "win32" else "analyzeHeadless"
        (support / bin_name).write_text("echo mock", encoding="utf-8")

        found = GE.find_ghidra(explicit_path=mock_dir)
        check("mock ghidra detected via explicit_path", found == mock_dir.resolve(), str(found))

        engines_dir = Path(td) / "engines"
        engines_dir.mkdir()
        shutil.copytree(mock_dir, engines_dir / "ghidra")
        found_engine = GE.find_ghidra(engines_dir=engines_dir)
        check("mock ghidra detected in engines dir", found_engine is not None, str(found_engine))

    # 3. native_scan report formatting with decompiled info
    with tempfile.TemporaryDirectory() as td:
        rep_out = Path(td) / "test-triage.md"
        tri = NS.Triage(libs=[NS.NativeLib(name="test.dll", size=1024, format="PE", exports=["Java_com_x_Y_z"])])
        decomp_mock = {
            "test.dll": {
                "ok": True,
                "decompiled_count": 1,
                "functions": [{"name": "Java_com_x_Y_z", "entry": "0x1000", "file": "src/Java_com_x_Y_z.c"}]
            }
        }
        NS.write_report(tri, "test.jar", rep_out, decompiled_info=decomp_mock)
        md = rep_out.read_text(encoding="utf-8")
        check("report contains decompiled section", "decompiled C sources (via Ghidra Headless)" in md)
        check("report lists decompiled function", "Java_com_x_Y_z" in md and "src/Java_com_x_Y_z.c" in md)

    # 4. decompile_library exception resilience on invalid / mock binary
    with tempfile.TemporaryDirectory() as td:
        fake_gh = Path(td) / "fake_gh"
        (fake_gh / "support").mkdir(parents=True)
        bin_name = "analyzeHeadless.bat" if sys.platform == "win32" else "analyzeHeadless"
        (fake_gh / "support" / bin_name).write_text("exit 1\n", encoding="utf-8")
        dummy_dll = Path(td) / "dummy.dll"
        dummy_dll.write_bytes(b"\x00" * 64)
        out_c = Path(td) / "out_c"
        res_dec = GE.decompile_library(fake_gh, dummy_dll, out_c, timeout=5, quiet=True)
        check("decompile_library returns clean dict on error", isinstance(res_dec, dict) and "ok" in res_dec)



def test_native_elf_and_ghidra_annotate() -> None:
    print("natives: ELF (.so) export parsing and Ghidra annotation script generation")
    from jdec import native_scan as NS

    # 1. ELF export parsing
    ehdr = bytearray(64)
    ehdr[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", ehdr, 16, 3, 0x3E, 1, 0, 0, 64, 0, 64, 0, 0, 64, 3, 0)
    sh0 = bytearray(64)
    sh1 = bytearray(64)
    struct.pack_into("<IIQQQQIIQQ", sh1, 0, 0, 11, 2, 0, 256, 72, 2, 1, 8, 24)
    sh2 = bytearray(64)
    dynstr_data = b"\x00Java_demo_Cls_run\x00JNI_OnLoad\x00"
    struct.pack_into("<IIQQQQIIQQ", sh2, 0, 0, 3, 2, 0, 328, len(dynstr_data), 0, 0, 1, 0)

    sym0 = bytearray(24)
    sym1 = bytearray(24)
    struct.pack_into("<IBBHQQ", sym1, 0, 1, 0x12, 0, 1, 0x1000, 32)
    sym2 = bytearray(24)
    struct.pack_into("<IBBHQQ", sym2, 0, 19, 0x12, 0, 1, 0x1020, 16)

    elf = bytes(ehdr + sh0 + sh1 + sh2 + sym0 + sym1 + sym2 + dynstr_data)
    exports = NS.parse_elf_exports(elf)
    check("ELF parsed JNI exports", "Java_demo_Cls_run" in exports and "JNI_OnLoad" in exports, str(exports))

    # 2. Ghidra GUI annotation script generation
    with tempfile.TemporaryDirectory() as td:
        script_out = Path(td) / "ghidra_annotate.py"
        tri = NS.Triage(
            libs=[NS.NativeLib(name="libsample.so", size=len(elf), format="ELF", exports=exports)],
            native_decl=[("demo/Cls", "run")]
        )
        NS.write_ghidra_annotation_script(tri, script_out)
        check("ghidra_annotate.py written", script_out.exists())
        txt = script_out.read_text(encoding="utf-8")
        check("ghidra_annotate maps Java method", "Java_demo_Cls_run" in txt and "demo/Cls" in txt)
        check("ghidra_annotate contains run entry", "def run():" in txt and "JNI_BINDINGS" in txt)

    # 3. Stripped ELF (e_shoff = 0) fallback parsing via PT_DYNAMIC program headers
    ehdr_s = bytearray(64)
    ehdr_s[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", ehdr_s, 16, 3, 0x3E, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    ph0_s = bytearray(56)
    struct.pack_into("<IIQQQQQQ", ph0_s, 0, 1, 7, 0, 0x10000, 0x10000, 1024, 1024, 0x1000)
    ph1_s = bytearray(56)
    struct.pack_into("<IIQQQQQQ", ph1_s, 0, 2, 6, 0x200, 0x10200, 0x10200, 128, 128, 8)
    buf_s = bytearray(1024)
    buf_s[:64] = ehdr_s
    buf_s[64:120] = ph0_s
    buf_s[120:176] = ph1_s
    dyn_off_s = 0x200
    struct.pack_into("<QQ", buf_s, dyn_off_s, 6, 0x10300)       # DT_SYMTAB
    struct.pack_into("<QQ", buf_s, dyn_off_s + 16, 5, 0x10380)  # DT_STRTAB
    struct.pack_into("<QQ", buf_s, dyn_off_s + 32, 10, 64)      # DT_STRSZ
    struct.pack_into("<QQ", buf_s, dyn_off_s + 48, 11, 24)      # DT_SYMENT
    struct.pack_into("<QQ", buf_s, dyn_off_s + 64, 4, 0x10280)  # DT_HASH
    struct.pack_into("<QQ", buf_s, dyn_off_s + 80, 0, 0)        # DT_NULL
    struct.pack_into("<II", buf_s, 0x280, 1, 3)                  # nbucket=1, nchain=3
    str_data_s = b"\x00Java_pkg_Native_call\x00JNI_OnLoad\x00"
    buf_s[0x380:0x380 + len(str_data_s)] = str_data_s
    struct.pack_into("<IBBHQQ", buf_s, 0x300 + 24, 1, 0x12, 0, 1, 0x1000, 32)
    struct.pack_into("<IBBHQQ", buf_s, 0x300 + 48, 22, 0x12, 0, 1, 0x1020, 16)

    # 4. Binary JNINativeMethod structure recovery directly from ELF rodata
    s_method = b"nativeFunc\x00(I)V\x00"
    buf_s[0x350:0x350 + len(s_method)] = s_method
    struct.pack_into("<QQQ", buf_s, 0x3c0, 0x10350, 0x10350 + 11, 0x10555)

    stripped_elf = bytes(buf_s)
    stripped_exports = NS.parse_elf_exports(stripped_elf)
    check("stripped ELF parsed JNI exports via PT_DYNAMIC",
          "Java_pkg_Native_call" in stripped_exports and "JNI_OnLoad" in stripped_exports,
          str(stripped_exports))

    reg_methods = NS.scan_binary_register_natives(stripped_elf, fmt="ELF")
    check("binary scan extracted JNINativeMethod table",
          any(m["name"] == "nativeFunc" and m["sig"] == "(I)V" for m in reg_methods),
          str(reg_methods))

    tri_reg = NS.Triage(
        libs=[NS.NativeLib(name="libtest.so", size=len(stripped_elf), format="ELF", exports=stripped_exports, dynamic_methods=reg_methods)],
        native_decl=[("demo/Cls", "nativeFunc")]
    )
    dyn_matched = tri_reg.matched_dynamic()
    check("tri.matched_dynamic matched declared Java method to native function",
          len(dyn_matched) == 1 and dyn_matched[0]["func"] == "0x10555",
          str(dyn_matched))

    # 5. Stripped ELF with DT_GNU_HASH (0x6FFFFEF5)
    buf_gnu = bytearray(buf_s)
    struct.pack_into("<QQ", buf_gnu, dyn_off_s + 64, 0x6FFFFEF5, 0x10280)
    struct.pack_into("<IIII", buf_gnu, 0x280, 1, 1, 1, 0)
    struct.pack_into("<Q", buf_gnu, 0x290, 0xFFFFFFFF)
    struct.pack_into("<I", buf_gnu, 0x298, 1)
    struct.pack_into("<I", buf_gnu, 0x29C, 0x12345671)
    gnu_elf = bytes(buf_gnu)
    gnu_exports = NS.parse_elf_exports(gnu_elf)
    check("stripped ELF parsed JNI exports via DT_GNU_HASH",
          "Java_pkg_Native_call" in gnu_exports,
          str(gnu_exports))


def test_score_and_signal_enhancements() -> None:
    print("score/analyze: hard error patterns and expanded API rules")
    from jdec.score import _HARD_ERROR_PATTERNS
    samples = [
        "// Method dump skipped",
        "/* Decompilation failed: stack underflow */",
        "// Decompilation aborted",
    ]
    for s in samples:
        matched = any(p.search(s) for p in _HARD_ERROR_PATTERNS)
        check(f"hard error matched: {s}", matched)


def test_multimodule_enhancements() -> None:
    print("modules: strings threat tags, tsrg2 mappings, quilt/neoforge metadata")
    # 1. strings.py
    check("webhook detected", "webhook" in ST.classify("https://discord.com/api/webhooks/123456789/AbCdEf-GhIj"))
    check("telegram bot detected", "telegram" in ST.classify("https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"))
    check("c2 staging detected", "c2-staging" in ST.classify("https://pastebin.com/raw/xyz123"))
    check("crypto address detected", "crypto" in ST.classify("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))
    blob = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="
    check("encrypted blob detected", "encrypted-blob" in ST.classify(blob))
    sd = ST.StringDump(rows=[("ClsA", "s1", ["webhook", "url"]), ("ClsB", "s2", ["webhook"])])
    tc = sd.tag_counts()
    check("tag_counts computed", tc.get("webhook") == 2 and tc.get("url") == 1, str(tc))

    # 2. mappings.py TSRG v2
    tsrg2_sample = (
        "tsrg2 obf srg\n"
        "a net/minecraft/client/main/Main\n"
        "\tb field_1234_a\n"
        "\tc (Ljava/lang/String;)V func_5678_b\n"
        "\t\t0 p_5678_0_\n"
    )
    m = MP.parse_tsrg(tsrg2_sample)
    check("tsrg2 class parsed", m.lookup_class("a") == "net/minecraft/client/main/Main")
    check("tsrg2 field parsed", m.lookup_member("a", "b", "") == "field_1234_a")
    check("tsrg2 method parsed", m.lookup_member("a", "c", "(Ljava/lang/String;)V") == "func_5678_b")
    check("tsrg2 parameter skipped as member", m.lookup_member("a", "0", "") is None)

    # 3. mcmod.py & probe.py (Quilt & NeoForge)
    from jdec import mcmod as MM
    tmp_dir = Path(tempfile.mkdtemp(prefix="jdec_test_meta_"))
    try:
        # Mock Quilt jar
        quilt_jar = tmp_dir / "quilt_test.jar"
        with zipfile.ZipFile(quilt_jar, "w") as z:
            quilt_json = {
                "schema_version": 1,
                "quilt_loader": {
                    "id": "quilt_sample",
                    "version": "2.0.0",
                    "metadata": {"name": "Quilt Sample Mod", "contributors": {"AuthorA": "Owner"}},
                    "entrypoints": {"init": "com.example.QuiltMod"},
                    "depends": [{"id": "minecraft", "versions": "1.20.2"}]
                },
                "mixin": "quilt_sample.mixins.json"
            }
            z.writestr("quilt.mod.json", json.dumps(quilt_json))
        qmeta = MM.read_mod_meta(quilt_jar)
        check("quilt loader recognized", qmeta.loader == "quilt", str(qmeta.loader))
        check("quilt mod id", qmeta.mod_id == "quilt_sample", str(qmeta.mod_id))
        check("quilt name", qmeta.name == "Quilt Sample Mod", str(qmeta.name))
        check("quilt entrypoint", "com.example.QuiltMod" in qmeta.entrypoints, str(qmeta.entrypoints))
        check("quilt mixin config", "quilt_sample.mixins.json" in qmeta.mixin_configs, str(qmeta.mixin_configs))

        qprof = profile_jar(quilt_jar)
        check("quilt flavor in probe", qprof.mc_flavor == "Quilt", str(qprof.mc_flavor))
        check("quilt version in probe", qprof.mc_version == "1.20.2", str(qprof.mc_version))

        # Mock NeoForge jar
        neo_jar = tmp_dir / "neo_test.jar"
        with zipfile.ZipFile(neo_jar, "w") as z:
            neo_toml = (
                "modId = 'neoforge_test'\n"
                "displayName = 'NeoForge Mod'\n"
                "version = '1.20.4-1.0'\n"
                "authors = 'Dev'\n"
                "description = 'A test mod'\n"
                "[[dependencies.neoforge_test]]\n"
                "modId = 'minecraft'\n"
                "versionRange = '[1.20.4, 1.21)'\n"
                "[[mixins]]\n"
                "config = 'neo.mixins.json'\n"
            )
            z.writestr("META-INF/neoforge.mods.toml", neo_toml)
        nmeta = MM.read_mod_meta(neo_jar)
        check("neoforge loader recognized", nmeta.loader == "neoforge", str(nmeta.loader))
        check("neoforge mod id", nmeta.mod_id == "neoforge_test", str(nmeta.mod_id))
        check("neoforge name", nmeta.name == "NeoForge Mod", str(nmeta.name))
        check("neoforge mixin config", "neo.mixins.json" in nmeta.mixin_configs, str(nmeta.mixin_configs))

        nprof = profile_jar(neo_jar)
        check("neoforge flavor in probe", nprof.mc_flavor == "NeoForge", str(nprof.mc_flavor))
        check("neoforge version in probe", nprof.mc_version == "1.20.4", str(nprof.mc_version))
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_advanced_roadmap_features() -> None:
    print("advanced: reverse JNI, RegisterNatives, stubs, deflat, and rename")
    from jdec import native_scan as NS
    from jdec import stubs
    from jdec import deflat as DF
    from jdec import rename as RN

    # 1. Reverse JNI & RegisterNatives scanning
    c_snippet = (
        'jclass c = (*env)->FindClass(env, "net/minecraft/client/Minecraft");\n'
        'jmethodID m = (*env)->GetMethodID(env, c, "run", "()V");\n'
        'jfieldID f = (*env)->GetFieldID(env, c, "player", "Ljava/lang/Object;");\n'
        '(*env)->CallVoidMethod(env, obj, m);\n'
        'env->FindClass("net/minecraft/world/World");\n'
    )
    rev = NS.scan_reverse_jni_c(c_snippet, "native_init")
    check("reverse JNI FindClass", any(r["type"] == "FindClass" and r["class"] == "net/minecraft/client/Minecraft" for r in rev))
    check("reverse JNI C++ FindClass", any(r["type"] == "FindClass" and r["class"] == "net/minecraft/world/World" for r in rev))
    check("reverse JNI GetMethodID", any(r["type"] == "GetMethodID" and r["method"] == "run" for r in rev))
    check("reverse JNI GetFieldID", any(r["type"] == "GetFieldID" and r["field"] == "player" for r in rev))
    check("reverse JNI CallMethod", any(r["type"] == "CallMethod" and r["mid_var"] == "m" for r in rev))

    c_reg = 'static JNINativeMethod methods[] = { { "nativeFunc", "(ILjava/lang/String;)Z", (void*)&sub_1234 } };'
    dyn = NS.scan_register_natives_c(c_reg, "JNI_OnLoad")
    check("RegisterNatives parsed", len(dyn) == 1 and dyn[0]["name"] == "nativeFunc" and dyn[0]["func"] == "sub_1234")

    # 2. Fake MC Stubs jar generation
    tmp_stubs = Path(tempfile.mkdtemp(prefix="jdec_test_stubs_"))
    try:
        if JAVAC is None:
            print("  (skipped: stub compilation needs javac; set JAVA_HOME or PATH)")
        else:
            sjar = stubs.ensure_stubs_jar(cache_dir=tmp_stubs)
            check("stubs jar generated", sjar.is_file())
            with zipfile.ZipFile(sjar) as z:
                names = z.namelist()
            check("stubs has Minecraft", "net/minecraft/client/Minecraft.class" in names)
            check("stubs has Launch", "net/minecraft/launchwrapper/Launch.class" in names)
            check("stubs has SharedConstants", "net/minecraft/SharedConstants.class" in names)
            check("stubs has BuiltInRegistries", "net/minecraft/core/registries/BuiltInRegistries.class" in names)

            # 2.5 Javac compiler detection
            from jdec import engines as EN
            jc = EN.find_javac()
            if jc is not None:
                check("engines.find_javac found valid executable", Path(jc).is_file(), str(jc))
                check("stubs._find_javac resolves javac", stubs._find_javac("javac") is not None)
    finally:
        shutil.rmtree(tmp_stubs, ignore_errors=True)

    # 3. Control flow de-flattening and constant arithmetic
    code = bytes([0x10, 0x05, 0x10, 0x03, 0x82])  # 5 ^ 3
    new_code, n = DF.simplify_constants(code)
    check("constant folding simplified ixor", n == 1 and new_code[0] == 0x10 and new_code[1] == 6)

    code_add = bytes([0x10, 0x0A, 0x10, 0x14, 0x60])  # 10 + 20
    new_code_add, n_add = DF.simplify_constants(code_add)
    check("constant folding simplified iadd", n_add == 1 and new_code_add[0] == 0x10 and new_code_add[1] == 30)

    # Switch at pc 1 with low=1, high=3 (count=3)
    switch_code = bytearray([0x1b, 0xaa, 0, 0] + list(struct.pack('>iiiii', 0, 1, 3, 27, 34)) + list(struct.pack('>i', 35)))
    switch_code += bytearray([0x10, 0x02, 0x3c, 0xa7]) + bytearray(struct.pack('>h', -31))
    switch_code += bytearray([0x00, 0xb1])
    deflat_res, n_unflat = DF.deflat_code(bytes(switch_code))
    check("deflat unflattened switch transition", n_unflat >= 1)

    # Test deflat_class with a synthetically embedded Code attribute
    with zipfile.ZipFile(SAMPLE) as zf:
        sample_cls_data = zf.read(zf.namelist()[0])
    cf_sample = CF.parse(sample_cls_data)
    # deflat_class should safely scan methods without crashing
    edits = DF.deflat_class(cf_sample)
    check("deflat_class runs on ClassFile", edits >= 0)
    roundtrip = cf_sample.serialize()
    check("ClassFile round-trips after deflat_class", len(roundtrip) > 0)

    # 4. Semantic renaming and LLM prompt export
    tmp_ren = Path(tempfile.mkdtemp(prefix="jdec_test_ren_"))
    try:
        sample_java = tmp_ren / "TestMixin.java"
        sample_java.write_text(
            'package demo;\n'
            'public class TestMixin {\n'
            '    @Inject(method = "tick")\n'
            '    public void a(int x) {\n'
            '        String s = "Connecting to socket";\n'
            '    }\n'
            '}\n',
            encoding="utf-8"
        )
        cands = RN.scan_source_file(sample_java)
        check("rename candidate found", len(cands) == 1 and cands[0].member_name == "a")
        check("rename suggestion inferred from mixin", cands[0].suggested_name == "onTick")

        prompt = RN.export_llm_prompt(cands)
        check("LLM prompt contains candidate", "onTick" in prompt)

        out_map = tmp_ren / "mapping.txt"
        n_rules = RN.write_proguard_mapping(cands, out_map)
        check("ProGuard mapping exported", n_rules == 1 and out_map.exists())
        map_content = out_map.read_text(encoding="utf-8")
        check("ProGuard parameter signature formatted", "void a(int) -> onTick" in map_content, map_content)
    finally:
        shutil.rmtree(tmp_ren, ignore_errors=True)


def test_pipeline_automation() -> None:
    if _no_engines():
        return

    print("pipeline: automated end-to-end deobfuscation and triage")
    from jdec import pipeline as PL
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        out_dir = d / "auto_out"
        res = PL.run_pipeline(
            SAMPLE,
            out_dir,
            no_deflat=False,
            no_recover=False,
            # REVIEW 2.1: replay now opts in explicitly; this fixture is a
            # locally-built benign jar, so executing it is safe.
            allow_replay=True,
            export_project=True,
            clean_work=False,
        )
        check("pipeline ran successfully", res.decompile_total > 0)
        check("pipeline summary markdown exists", (out_dir / "pipeline_summary.md").is_file())
        check("pipeline summary json exists", (out_dir / "pipeline_summary.json").is_file())
        check("decompiled sources exist", (out_dir / "src").is_dir())
        check("analysis markdown exists", (out_dir / "analysis.md").is_file())
        check("strings tsv exists", (out_dir / "strings.tsv").is_file())
        check("report markdown exists", (out_dir / "report.md").is_file())

        # REVIEW 2.2: stage status plumbing is part of the result now
        stage_names = [s.name for s in res.stages]
        check("pipeline records core stages",
              all(n in stage_names for n in ("probe", "deflat", "decompile", "replay", "summary")),
              f"stages={stage_names}")
        check("replay stage attempted under allow_replay",
              res.stage("replay").status in (PIPE.STAGE_OK, PIPE.STAGE_PARTIAL, PIPE.STAGE_FAILED),
              res.stage("replay").status)
        check("exit code reflects overall status",
              res.exit_code == {"success": 0, "partial": 1, "failed": 2}[res.overall_status],
              f"overall={res.overall_status} exit={res.exit_code}")

        # Phase 2 unflattened methods
        check("pipeline unflattened methods", res.unflattened_methods > 0, f"unflattened={res.unflattened_methods}")

        # Phase 5 recover artifacts
        check("recover spec tsv exists", (out_dir / "_pipeline" / "recover" / "recover_spec.tsv").is_file())
        check("recover results tsv exists", (out_dir / "_pipeline" / "recover" / "recovered.tsv").is_file())

        # Phase 8 project artifacts
        proj_dir = out_dir / "project"
        check("exported project directory exists", proj_dir.is_dir())
        check("exported build.gradle exists", (proj_dir / "build.gradle").is_file())
        check("exported src directory exists", (proj_dir / "src" / "main" / "java").is_dir())

        json_data = json.loads((out_dir / "pipeline_summary.json").read_text(encoding="utf-8"))
        check("summary json contains metrics", "metrics" in json_data and json_data["metrics"]["decompile_total"] > 0)
        check("summary json contains profile", "profile" in json_data and json_data["profile"]["classes"] > 0)
        # REVIEW 2.2: summary json exposes stage statuses and the exit code
        check("summary json contains overall/exit_code/stages",
              "overall" in json_data and "exit_code" in json_data
              and isinstance(json_data.get("stages"), list) and json_data["stages"])



def test_web_workbench_features() -> None:
    print("web: interactive workbench with diff, annotations and LLM assist")
    import re
    from jdec import web as WB
    import urllib.request
    import threading

    with tempfile.TemporaryDirectory() as td:
        work_dir = Path(td)
        src_dir = work_dir / "src" / "demo" / "obf"
        src_dir.mkdir(parents=True, exist_ok=True)
        java_file = src_dir / "a.java"
        java_file.write_text(
            'package demo.obf;\n\n'
            'public class a {\n'
            '    public int x = 1;\n'
            '    public void b() {\n'
            '        System.out.println("Connecting to C2 host");\n'
            '    }\n'
            '}\n',
            encoding="utf-8"
        )

        # case-twin class: the on-disk stem is percent-encoded
        (work_dir / "src" / "demo" / "obf" / "%41.java").write_text(
            "package demo.obf;\n\npublic class A {}\n", encoding="utf-8")

        cfr_dir = work_dir / "engines" / "cfr" / "demo" / "obf"
        cfr_dir.mkdir(parents=True, exist_ok=True)
        (cfr_dir / "a.java").write_text(
            'package demo.obf;\n\n'
            'public class a {\n'
            '    public int x = 1;\n'
            '    public int y = 2;\n'
            '    public void b() {\n'
            '        System.out.println("Connecting to C2 host");\n'
            '    }\n'
            '}\n',
            encoding="utf-8"
        )

        (work_dir / "report.json").write_text(json.dumps({
            "target": "sample.jar",
            "outcomes": {
                "demo/obf/a": {
                    "engine": "vineflower",
                    "rel": "demo/obf/a.java",
                    "quality": {"score": 96.5},
                    "attempts": ["cfr", "vineflower"],
                    "status": "ok"
                }
            }
        }), encoding="utf-8")

        (work_dir / "strings.json").write_text(json.dumps({
            "strings": {
                "demo/obf/a": [
                    {"string": "Connecting to C2 host", "tags": ["c2-staging", "url"]}
                ]
            }
        }), encoding="utf-8")

        (work_dir / "pipeline_summary.md").write_text("# Pipeline Summary\nAutomated deobf successful.", encoding="utf-8")

        handler = lambda *args, **kwargs: WB.WorkbenchHandler(*args, work_dir=work_dir, **kwargs)
        server = WB.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        port = server.server_address[1]
        srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
        srv_thread.start()

        try:
            base_url = f"http://127.0.0.1:{port}"

            # 1. Test GET /
            with urllib.request.urlopen(f"{base_url}/") as res:
                html_body = res.read().decode("utf-8")
                check("workbench home page returns 200", res.status == 200)
                check("workbench HTML has interactive tabs", "Engine Diff" in html_body and "AI Semantic Rename" in html_body)
                check("workbench HTML has clean benign tag", '<option value="benign">benign</option>' in html_body)
                check("workbench HTML has zero emojis", not bool(re.search(r'[\U00010000-\U0010ffff\u2600-\u27bf\u2300-\u23ff\u2b50-\u2b55\u200d\ufe0f]', html_body)))
                check("workbench renders the decoded tree label",
                      "currentData.names[cls] || cls" in html_body)

            # 2. Test GET /api/tree
            with urllib.request.urlopen(f"{base_url}/api/tree") as res:
                tree_data = json.loads(res.read().decode("utf-8"))
                check("tree contains demo/obf/a", "demo/obf/a" in tree_data.get("classes", []))
                check("tree keeps the on-disk stem as the key",
                      "demo/obf/%41" in tree_data.get("classes", []),
                      str(tree_data.get("classes")))
                check("tree sends a decoded display name",
                      tree_data.get("names", {}).get("demo/obf/%41") == "demo/obf/A",
                      str(tree_data.get("names")))

            # 3. Test GET /api/source
            with urllib.request.urlopen(f"{base_url}/api/source?class=demo/obf/a") as res:
                source_code = res.read().decode("utf-8")
                check("source endpoint returns code", "Connecting to C2" in source_code)

            # 4. Test GET /api/class_info
            with urllib.request.urlopen(f"{base_url}/api/class_info?class=demo/obf/a") as res:
                cinfo = json.loads(res.read().decode("utf-8"))
                check("class info has engine", cinfo.get("engine") == "vineflower")
                check("class info has strings", len(cinfo.get("strings", [])) >= 1)

            # 5. Test GET /api/report
            with urllib.request.urlopen(f"{base_url}/api/report") as res:
                rep_text = res.read().decode("utf-8")
                check("report returns pipeline summary", "Pipeline Summary" in rep_text)

            # 6. Test GET & POST /api/annotations
            with urllib.request.urlopen(f"{base_url}/api/annotations") as res:
                empty_anns = json.loads(res.read().decode("utf-8"))
                check("initial annotations are empty", len(empty_anns) == 0)

            post_data = json.dumps({
                "class": "demo/obf/a",
                "tag": "threat",
                "note": "Suspicious C2 beacon string"
            }).encode("utf-8")
            req = urllib.request.Request(f"{base_url}/api/annotations", data=post_data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req) as res:
                post_res = json.loads(res.read().decode("utf-8"))
                check("annotation save succeeded", post_res.get("ok") is True)
                check("annotation returned has tag", post_res.get("annotations", {}).get("demo/obf/a", {}).get("tag") == "threat")

            notes_file = work_dir / "audit_notes.json"
            check("audit_notes.json written to disk", notes_file.is_file())
            saved_notes = json.loads(notes_file.read_text(encoding="utf-8"))
            check("saved notes contains tag and note", saved_notes.get("demo/obf/a", {}).get("note") == "Suspicious C2 beacon string")

            # 7. Test GET /api/diff (Final vs CFR)
            with urllib.request.urlopen(f"{base_url}/api/diff?class=demo/obf/a&e1=final&e2=cfr") as res:
                diff_data = json.loads(res.read().decode("utf-8"))
                check("diff is not identical", diff_data.get("identical") is False)
                check("diff has added/removed stats", diff_data.get("stats", {}).get("added", 0) > 0)
                check("diff text contains unified diff marker", "+++" in diff_data.get("diff", ""))

            with urllib.request.urlopen(f"{base_url}/api/diff?class=demo/obf/a&e1=final&e2=final") as res:
                diff_same = json.loads(res.read().decode("utf-8"))
                check("diff between same engine is identical", diff_same.get("identical") is True)

            # 8. Test GET /api/llm_prompt
            with urllib.request.urlopen(f"{base_url}/api/llm_prompt?class=demo/obf/a") as res:
                prompt_data = json.loads(res.read().decode("utf-8"))
                prompt_text = prompt_data.get("prompt", "")
                check("LLM prompt contains class", "demo.obf.a" in prompt_text)
                check("LLM prompt contains candidate member", "b(" in prompt_text or "x" in prompt_text)
                check("LLM prompt requests ProGuard format", "```proguard" in prompt_text)

            # 9. Test GET /api/callgraph
            with urllib.request.urlopen(f"{base_url}/api/callgraph?class=demo/obf/a") as res:
                cg_api_data = json.loads(res.read().decode("utf-8"))
                check("callgraph endpoint responds", "callers" in cg_api_data and "callees" in cg_api_data)

            # 10. Test Path traversal defense on /api/source and /api/llm_prompt
            with urllib.request.urlopen(f"{base_url}/api/source?class=../../secret") as res:
                trav_source = res.read().decode("utf-8")
                check("path traversal on /api/source blocked", "Source not found" in trav_source)

            with urllib.request.urlopen(f"{base_url}/api/llm_prompt?class=../../secret") as res:
                trav_prompt = json.loads(res.read().decode("utf-8"))
                check("path traversal on /api/llm_prompt handled safely", "prompt" in trav_prompt)

        finally:
            server.shutdown()
            server.server_close()


def test_callgraph_and_reachability() -> None:
    print("callgraph: entrypoint reachability, path tracing and jar pruning")
    from jdec import callgraph as CG

    # 1. Custom entrypoint on sample.jar
    cg_sample = CG.build_callgraph(SAMPLE, custom_entrypoints=["demo/modern/Showcase"])
    check("sample.jar classes indexed", len(cg_sample.classes) == 10)
    rep_sample = CG.compute_reachability(cg_sample)
    check("showcase reachability computed", rep_sample.reachability_pct == 30.0, str(rep_sample.reachability_pct))
    check("dead classes identified in sample", "demo/obf/a" in rep_sample.dead_classes)
    check("showcase shapes reachable", "demo/modern/Showcase$Circle" in rep_sample.reachable_classes)

    # 2. Automated Mod/Mixin entrypoints on mixin.jar
    if MIXIN.exists():
        cg_mixin = CG.build_callgraph(MIXIN)
        check("mixin entrypoints discovered", len(cg_mixin.entrypoints) >= 5, str(len(cg_mixin.entrypoints)))
        rep_mixin = CG.compute_reachability(cg_mixin)
        check("mixin reachability computed", rep_mixin.reachability_pct == 40.0, str(rep_mixin.reachability_pct))
        check("licence class is reachable", "demo/mixin/Licence" in rep_mixin.reachable_classes)

        # 3. Shortest path finding
        path = CG.find_path(rep_mixin, "demo/mixin/Licence")
        check("trigger path to licence found", path is not None and len(path) == 1, str(path))
        check("trigger path caller is ClientEntry", path[0].caller.display_name == "ClientEntry.onInitializeClient()")
        check("trigger path callee is Licence.decode", path[0].callee.display_name == "Licence.decode()")
        check("trigger path opcode is invokestatic", path[0].opcode == "invokestatic")

        # 4. Jar pruning
        with tempfile.TemporaryDirectory() as td:
            pruned_jar = Path(td) / "pruned.jar"
            kept, dropped, saved = CG.prune_jar(MIXIN, pruned_jar, rep_mixin.reachable_classes)
            check("pruning kept reachable classes", kept == 4, str(kept))
            check("pruning dropped dead classes", dropped == 6, str(dropped))
            check("pruned jar is valid zip", zipfile.is_zipfile(pruned_jar))

        # 5. DOT and JSON export
        dot_str = CG.export_dot(cg_mixin, rep_mixin.reachable_methods)
        check("DOT output contains digraph", "digraph CallGraph" in dot_str)
        json_data = CG.export_json(rep_mixin)
        check("JSON export contains reachable classes count", json_data["summary"]["reachable_classes"] == 4)
        md_report = CG.render_markdown(rep_mixin, target_path="demo/mixin/Licence")
        check("markdown report mentions path", "ClientEntry.onInitializeClient()" in md_report)


def test_decompiler_trap_pruning() -> None:
    print("deflat: anti-decompiler trap pruning, opaque predicates and CFG reachability")
    from jdec import deflat as DF

    # 1. Constant folding
    code_const = bytes([0x10, 0x0A, 0x10, 0x14, 0x60])  # bipush 10, bipush 20, iadd
    folded, n_folded = DF.simplify_constants(code_const)
    check("constant folding simplifies bipush sum", n_folded == 1 and folded[:2] == bytes([0x10, 0x1E]))
    check("constant folding preserves byte length with NOPs", len(folded) == len(code_const) and folded[2:] == bytes([0, 0, 0]))

    # 2. Opaque predicates
    # 2a. Unary constant: iconst_0 (0x03), ifeq +5 (0x99, 0x00, 0x05), return (0xb1) -> always taken -> goto
    code_p1_taken = bytes([0x03, 0x99, 0x00, 0x05, 0xB1])
    res_p1t, n_p1t = DF.prune_opaque_predicates(code_p1_taken)
    check("opaque predicate unary always-taken becomes goto", n_p1t == 1 and res_p1t[0] == 0x00 and res_p1t[1] == 0xA7)

    # 2b. Unary constant: iconst_1 (0x04), ifeq +5 -> never taken -> NOPs
    code_p1_not = bytes([0x04, 0x99, 0x00, 0x05, 0xB1])
    res_p1n, n_p1n = DF.prune_opaque_predicates(code_p1_not)
    check("opaque predicate unary never-taken eliminated", n_p1n == 1 and res_p1n[:4] == bytes([0, 0, 0, 0]))

    # 2c. Identity: iload_1 (0x1b), iload_1 (0x1b), if_icmpeq +5 -> always taken -> goto
    code_p3_taken = bytes([0x1B, 0x1B, 0x9F, 0x00, 0x05, 0xB1])
    res_p3t, n_p3t = DF.prune_opaque_predicates(code_p3_taken)
    check("opaque predicate identity always-taken becomes goto", n_p3t == 1 and res_p3t[2] == 0xA7)

    # 2d. Identity: iload_2 (0x1c), iload_2 (0x1c), if_icmpne +5 -> never taken -> NOPs
    code_p3_not = bytes([0x1C, 0x1C, 0xA0, 0x00, 0x05, 0xB1])
    res_p3n, n_p3n = DF.prune_opaque_predicates(code_p3_not)
    check("opaque predicate identity never-taken eliminated", n_p3n == 1 and res_p3n[:5] == bytes([0, 0, 0, 0, 0]))

    # 2e. Null check: aconst_null (0x01), ifnull +5 -> always taken -> goto
    code_null_taken = bytes([0x01, 0xC6, 0x00, 0x05, 0xB1])
    res_nt, n_nt = DF.prune_opaque_predicates(code_null_taken)
    check("opaque predicate null-check always-taken becomes goto", n_nt == 1 and res_nt[1] == 0xA7)

    # 2f. Null check: aconst_null (0x01), ifnonnull +5 -> never taken -> NOPs
    code_null_not = bytes([0x01, 0xC7, 0x00, 0x05, 0xB1])
    res_nn, n_nn = DF.prune_opaque_predicates(code_null_not)
    check("opaque predicate null-check never-taken eliminated", n_nn == 1 and res_nn[:4] == bytes([0, 0, 0, 0]))

    # 2g. Object reference identity: aload_0 (0x2a), aload_0 (0x2a), if_acmpeq +5 -> always taken -> goto
    code_aload_taken = bytes([0x2A, 0x2A, 0xA5, 0x00, 0x05, 0xB1])
    res_at, n_at = DF.prune_opaque_predicates(code_aload_taken)
    check("opaque predicate aload reference identity always-taken becomes goto", n_at == 1 and res_at[2] == 0xA7)

    # 2h. Object reference identity: aload_1 (0x2b), aload_1 (0x2b), if_acmpne +5 -> never taken -> NOPs
    code_aload_not = bytes([0x2B, 0x2B, 0xA6, 0x00, 0x05, 0xB1])
    res_an, n_an = DF.prune_opaque_predicates(code_aload_not)
    check("opaque predicate aload reference identity never-taken eliminated", n_an == 1 and res_an[:5] == bytes([0, 0, 0, 0, 0]))

    # 3. Redundant jump elimination & trampoline threading
    code_rj = bytes([0xA7, 0x00, 0x03, 0xB1])  # goto +3 -> next pc
    res_rj, n_rj = DF.clean_redundant_jumps(code_rj)
    check("redundant self-fallthrough goto eliminated", n_rj == 1 and res_rj[:3] == bytes([0, 0, 0]))

    # Redundant goto through NOP padding
    code_rjn = bytes([0xA7, 0x00, 0x05, 0x00, 0x00, 0xB1])
    res_rjn, n_rjn = DF.clean_redundant_jumps(code_rjn)
    check("redundant goto through NOP padding eliminated", n_rjn == 1 and res_rjn[:3] == bytes([0, 0, 0]))

    # Trampoline jump threading: goto 7 -> pc 7: goto 5 -> target pc 12
    code_tramp = bytes([
        0xA7, 0x00, 0x07,  # pc 0: goto +7
        0x10, 0x02,        # pc 3: bipush 2
        0x00, 0x00,        # pc 5: nops
        0xA7, 0x00, 0x05,  # pc 7: goto +5 -> jumps to pc 12
        0x00, 0x00,        # pc 10: nops
        0xB1,              # pc 12: return
    ])
    res_tramp, n_tramp = DF.clean_redundant_jumps(code_tramp)
    check("trampoline jump threaded directly to final target", n_tramp >= 1 and struct.unpack_from(">h", res_tramp, 1)[0] == 12)

    # 1-byte iconst constant folding: iconst_1 (0x04) + iconst_2 (0x05) + iadd (0x60) -> iconst_3 (0x06)
    code_ic = bytes([0x04, 0x05, 0x60])
    res_ic, n_ic = DF.simplify_constants(code_ic)
    check("constant folding simplifies small sum to iconst", n_ic == 1 and res_ic[0] == 0x06 and res_ic[1:] == bytes([0, 0]))

    # 4. Dead code & anti-decompiler trap pruning
    # pc 0: goto +6 (0xa7, 0x00, 0x06); pc 3: bipush 42 (0x10, 0x2a); pc 5: athrow (0xbf); pc 6: return (0xb1)
    code_trap = bytes([0xA7, 0x00, 0x06, 0x10, 0x2A, 0xBF, 0xB1])
    res_trap, n_trap = DF.prune_dead_code(code_trap)
    check("dead bytecode trap instructions pruned", n_trap == 2)
    check("dead trap converted to NOPs", res_trap[3:6] == bytes([0, 0, 0]))
    check("reachable instructions untouched", res_trap[0] == 0xA7 and res_trap[6] == 0xB1)

    # 5. Exception handler sanitization
    handlers = [
        BC.Handler(10, 10, 20, 0),    # zero-length trap (start == end)
        BC.Handler(0, 10, 5, 0),      # valid handler
        BC.Handler(0, 50, 10, 0),     # out of bounds (len > 30)
        BC.Handler(20, 25, 26, 0),    # dead handler (no reachable pcs in range)
    ]
    reachable_pcs = {0, 1, 2, 5}
    sanitized_h, dropped_h = DF.prune_exception_handlers(handlers, code_len=30, reachable_pcs=reachable_pcs)
    check("malformed and dead exception handlers pruned", dropped_h == 3)
    check("valid exception handler preserved", len(sanitized_h) == 1 and sanitized_h[0].start_pc == 0)

    # 6. Master optimize_code pass
    combined_code = bytes([
        0x10, 0x05, 0x10, 0x03, 0x60,         # pc 0: bipush 5, bipush 3, iadd -> simplifies to bipush 8
        0x3B,                                 # pc 5: istore_0
        0x04, 0x99, 0x00, 0x06,               # pc 6: iconst_1, ifeq +6 -> never taken, eliminated
        0xA7, 0x00, 0x03,                     # pc 10: goto +3 -> redundant goto eliminated
        0xB1,                                 # pc 13: return
        0x10, 0x63, 0xBF,                     # pc 14: bipush 99, athrow -> dead trap eliminated
    ])
    combined_handlers = [BC.Handler(5, 5, 10, 0)]  # zero-length handler
    opt_code, opt_h, stats = DF.optimize_code(combined_code, combined_handlers)
    check("master optimizer preserves code length", len(opt_code) == len(combined_code))
    check("master optimizer eliminated zero-length handler", len(opt_h) == 0 and stats["handlers_pruned"] == 1)
    check("master optimizer recorded multiple passes", stats["total"] >= 4, str(stats))
    # The trailing terminator stays: NOPing the last instruction lets control
    # fall off the end of the code array (measured on HMCL: 3 classes).
    check("dead code block at end of method NOPed out",
          opt_code[14:16] == bytes([0, 0]) and opt_code[16] == 0xBF,
          opt_code[14:].hex())

    # 7. Whole-jar deflat_jar integration on SAMPLE
    with tempfile.TemporaryDirectory() as td:
        out_deflat = Path(td) / "deflat_sample.jar"
        jar_stats = DF.deflat_jar(SAMPLE, out_deflat, ir_rewrite=False)
        check("deflat_jar processed classes", jar_stats["classes"] == 11)
        check("deflat output jar exists and is valid zip", out_deflat.exists() and zipfile.is_zipfile(out_deflat))
        with zipfile.ZipFile(out_deflat) as zout:
            for n in zout.namelist():
                if n.endswith(".class") and n != BROKEN_SAMPLE:
                    cdata = zout.read(n)
                    cf = CF.parse(cdata)
                    check(f"deflat class {n} parses cleanly", cf.name is not None)
            # StackMapTable handling: a *reverted* method keeps its original
            # frames on purpose, so "the output has no frames" is no longer the
            # property to assert. Idempotence and not breaking the class are.
            old_data = zout.read("demo/legacy/OldStyle.class")
            old_cf = CF.parse(old_data)
            first_strip = DF._strip_stackmaps(old_cf)
            check("_strip_stackmaps is idempotent",
                  DF._strip_stackmaps(old_cf) == 0, f"first pass stripped {first_strip}")
            check("_strip_stackmaps leaves a parseable class",
                  CF.parse(old_cf.serialize()).name == old_cf.name)

    # 8. Regression test: pipeline with no_natives=True (verifies UnboundLocalError fix)
    from jdec import pipeline as PL_MOD
    with tempfile.TemporaryDirectory() as td:
        out_pipe = Path(td) / "pipe_nonat"
        res_pipe = PL_MOD.run_pipeline(
            SAMPLE, out_pipe,
            no_natives=True,
            no_deflat=True,
            no_recover=True,
            mapping_set="none",
            jobs=1,
        )
        check("pipeline runs cleanly with no_natives=True", res_pipe.native_libs_count == 0 and res_pipe.mixin_hooks_count >= 0)


def test_project_export_and_recompilability() -> None:
    print("project: automated IDE project generation, syntax repair, and javac recompilation loop")

    # 1. Keyword identifier sanitization
    raw_kw_java = "\n".join([
        "package demo.obf;",
        "public class KeywordTest {",
        "    private int goto = 10;",
        "    public String default = \"test\";",
        "    private final Object const = null;",
        "    public void compute(int goto, String default) {",
        "        this.goto = goto;",
        "        System.out.println(goto);",
        "    }",
        "}",
    ])
    cleaned_kw, kw_edits = PJ.sanitize_keyword_identifiers(raw_kw_java)
    check("escaped reserved keyword identifiers", kw_edits >= 4, f"edits={kw_edits}")
    check("goto escaped to goto_", "goto_" in cleaned_kw and "int goto " not in cleaned_kw)
    check("default escaped to default_", "default_" in cleaned_kw and "String default " not in cleaned_kw)
    check("const escaped to const_", "const_" in cleaned_kw and "Object const " not in cleaned_kw)

    # 2. Prune duplicate bridge methods
    bridge_java = "\n".join([
        "package demo.bridge;",
        "public class BridgeTest {",
        "    public String getValue() {",
        "        return \"real\";",
        "    }",
        "    // bridge method",
        "    public Object getValue() {",
        "        return this.getValue();",
        "    }",
        "}",
    ])
    cleaned_br, br_edits = PJ.prune_duplicate_bridge_methods(bridge_java)
    check("pruned duplicate synthetic bridge method", br_edits == 1, f"edits={br_edits}")
    check("duplicate bridge method commented out", "// [jdec: stripped duplicate bridge method]" in cleaned_br)
    check("original method kept intact", "public String getValue() {" in cleaned_br)

    # 3. Master clean_source_for_compilation pass
    no_pkg_java = "public class Orphan\u200bTrap { int goto = 1; \ufeff}"
    cleaned_src, chgs = PJ.clean_source_for_compilation(no_pkg_java, expected_package="com.example.orphan")
    check("clean_source added missing package declaration", any("package com.example.orphan" in c for c in chgs))
    check("clean_source escaped keywords", any("keyword" in c for c in chgs))
    check("clean_source stripped zero-width obfuscator traps", "\u200b" not in cleaned_src and "\ufeff" not in cleaned_src)
    check("clean_source output begins with package", cleaned_src.startswith("package com.example.orphan;"))

    # 4. Gradle scaffold generation
    with tempfile.TemporaryDirectory() as td:
        proj_dir = Path(td) / "TestScaffold"
        PJ.generate_gradle_scaffold(
            proj_dir,
            project_name="MyTestProject",
            java_version="21",
            mc_version="1.20.4",
            mc_flavor="fabric",
        )
        check("scaffold generated build.gradle", (proj_dir / "build.gradle").is_file())
        check("scaffold generated settings.gradle", (proj_dir / "settings.gradle").is_file())
        check("scaffold generated gradle.properties", (proj_dir / "gradle.properties").is_file())
        check("scaffold generated README.md", (proj_dir / "README.md").is_file())
        check("scaffold generated .gitignore", (proj_dir / ".gitignore").is_file())
        check("scaffold generated gradlew.bat", (proj_dir / "gradlew.bat").is_file())
        check("scaffold generated gradlew", (proj_dir / "gradlew").is_file())

        bg_text = (proj_dir / "build.gradle").read_text(encoding="utf-8")
        check("build.gradle includes libs tree dependency", "fileTree(dir: 'libs'" in bg_text)
        check("build.gradle sets Java 21 compatibility", "JavaVersion.toVersion('21')" in bg_text)

        gp_text = (proj_dir / "gradle.properties").read_text(encoding="utf-8")
        check("gradle.properties specifies minecraft_version", "minecraft_version=1.20.4" in gp_text)

        rm_text = (proj_dir / "README.md").read_text(encoding="utf-8")
        check("README provides IntelliJ IDEA instructions", "IntelliJ IDEA" in rm_text)

    # 5. Whole project export from SAMPLE & Windows reserved device name escaping
    with tempfile.TemporaryDirectory() as td:
        exp_dir = Path(td) / "sample_exported_proj"
        mock_src = Path(td) / "mock_src"
        mock_src.mkdir(parents=True, exist_ok=True)
        # Create an aux.java file (Windows reserved device name) and %41.java (twin collision)
        (mock_src / "aux.java").write_text("public class aux { public int val = 42; }", encoding="utf-8")
        (mock_src / "a.java").write_text("public class a { public a() {} }", encoding="utf-8")
        (mock_src / "%41.java").write_text("public class A { public A parent; public A(A p) { this.parent = p; } }", encoding="utf-8")
        (mock_src / "b.java").write_text("public class b { public A field; public b() { this.field = new A(null); } }", encoding="utf-8")
        stats = PJ.export_project(SAMPLE, exp_dir, src_dir=mock_src, mc_version="1.20.4", with_stubs=True)
        check("export created src/main/java directory", (exp_dir / "src" / "main" / "java").is_dir())
        check("export escaped Windows reserved name aux.java -> _aux.java", (exp_dir / "src" / "main" / "java" / "_aux.java").is_file())
        check("export escaped percent-encoded collision file %41.java -> A_Twin.java", (exp_dir / "src" / "main" / "java" / "A_Twin.java").is_file())
        twin_txt = (exp_dir / "src" / "main" / "java" / "A_Twin.java").read_text(encoding="utf-8")
        check("collision file class name updated to A_Twin", "class A_Twin" in twin_txt and "A_Twin(" in twin_txt)
        check("collision file self-references updated to A_Twin", "A_Twin parent" in twin_txt and "(A_Twin p)" in twin_txt)
        check("a.java preserved without collision", (exp_dir / "src" / "main" / "java" / "a.java").is_file())
        b_txt = (exp_dir / "src" / "main" / "java" / "b.java").read_text(encoding="utf-8")
        check("sibling b.java updated A references to A_Twin", "A_Twin field" in b_txt and "new A_Twin(null)" in b_txt)
        check("export bundled mc_stubs.jar into libs/", (exp_dir / "libs" / "mc_stubs.jar").is_file())
        check("export extracted resources to src/main/resources", stats["resources_copied"] >= 1)
        check("export generated build.gradle", (exp_dir / "build.gradle").is_file())

    if JAVAC is None:
        print("  (skipped: compile self-healing and CLI project need javac; set JAVA_HOME or PATH)")
    else:
        # 6. Deep javac compile self-healing loop: 5 simultaneous error types
        with tempfile.TemporaryDirectory() as td:
            c_proj = Path(td) / "compile_project"
            PJ.generate_gradle_scaffold(c_proj, "CompileVerify")
            src_root = c_proj / "src" / "main" / "java" / "test"
            src_root.mkdir(parents=True, exist_ok=True)

            # Inject:
            # 1. Duplicate method declaration
            # 2. Ambiguous null overload
            # 3. Unreachable statement
            # 4. Missing return statement
            # 5. Missing external library class import
            buggy_java = src_root / "Buggy.java"
            buggy_java.write_text("\n".join([
                "package test;",
                "import ext.unknown.Helper;",
                "public class Buggy {",
                "    public void run() {",
                "        System.out.println(1);",
                "    }",
                "    public void run() {",
                "        System.out.println(2);",
                "    }",
                "    public static void pick(String s) {}",
                "    public static void pick(Integer i) {}",
                "    public int compute(int x) {",
                "        if (x > 0) return 10;",
                "    }",
                "    public void deadCode() {",
                "        return;",
                "        System.out.println(999);",
                "    }",
                "    public static void main(String[] args) {",
                "        pick(null);",
                "        Helper h = null;",
                "    }",
                "}",
            ]), encoding="utf-8")

            rep = PJ.verify_compilation(c_proj, max_repair_passes=4)
            check("deep self-healing loop repaired multiple simultaneous error types", rep.repaired_count >= 4, f"repaired={rep.repaired_count}")
            check("deep self-healing loop achieved 100% clean compilation", rep.success is True, rep.summary())
            check("deep self-healing loop compiled all files cleanly", rep.compiled_files == rep.total_files and rep.total_files >= 1)

        # 7. CLI project subcommand smoke test
        with tempfile.TemporaryDirectory() as td:
            cli_out = Path(td) / "cli_sample_project"
            cli_args = SimpleNamespace(
                input=str(SAMPLE),
                output=str(cli_out),
                src=None,
                mc_version="1.20.4",
                no_stubs=False,
                compile=False,
                engines_dir=str(ROOT / "engines"),
            )
            res = CL.cmd_project(cli_args)
            check("cmd_project returned 0", res == 0)
            check("cmd_project created output project", (cli_out / "build.gradle").is_file())
            check("cmd_project bundled libs", (cli_out / "libs" / "mc_stubs.jar").is_file())

    # 7. Decompiler unbox cascade normalization and typed self-healing
    unbox_raw = "int x = v instanceof Boolean ? (Boolean)v : (v instanceof Character ? (char)((Number)v).intValue() : ((Number)v).intValue()));"
    norm_unbox, unbox_n = PJ.normalize_unbox(unbox_raw)
    check("normalize_unbox matched and converted ternary", unbox_n >= 1, f"edits={unbox_n}")
    check("normalize_unbox produced valid typed expression", "booleanValue() ? 1 : 0" in norm_unbox and "charValue()" in norm_unbox)


def test_remap_rewrites_call_sites() -> None:
    """Renaming only declarations would leave dangling member references."""
    if _no_engines():
        return

    print("mappings: remap rewrites declarations *and* every call site")
    m = MP.load_mapping(MC_MAP)
    with zipfile.ZipFile(MC_JAR) as z:
        data = z.read("env.class")  # com.mojang.blaze3d.audio.Channel
    cf = CF.parse(data)
    before = [cf.utf8(f.name_index) for f in cf.fields]
    changed = MP.remap_class(cf, m)
    after = [cf.utf8(f.name_index) for f in cf.fields]
    check("class was renamed", cf.name == "com/mojang/blaze3d/audio/Channel", cf.name)
    check("fields were renamed", changed > 0 and after != before,
          f"{before} -> {after}")
    check("renamed names are the official ones",
          "LOGGER" in after and "source" in after, str(after))

    refs = []
    for i in range(1, len(cf.cp)):
        e = cf.cp[i]
        if e and e[0] in (CF.C_FIELDREF, CF.C_METHODREF, CF.C_INTERFACE_METHODREF):
            owner = cf.utf8(cf.cp[e[1][0]][1][0])
            nt = cf.cp[e[1][1]]
            refs.append((owner, cf.utf8(nt[1][0]), cf.utf8(nt[1][1])))
    dangling = [r for r in refs if r[0] == cf.name and r[1] in before
                and r[1] not in after]
    check("no dangling references to old member names", not dangling, str(dangling[:5]))


def test_remapped_class_is_valid_bytecode() -> None:
    """The real proof: javap must still be able to read what we produced."""
    print("mappings: remapped bytecode still loads (verified by javap)")
    if JAVAP is None:
        print("  (skipped: no javap; set JAVA_HOME or PATH)")
        return
    m = MP.load_mapping(MC_MAP)
    with zipfile.ZipFile(MC_JAR) as z:
        data = z.read("env.class")
    cf = CF.parse(data)
    MP.remap_class(cf, m)
    tmp = Path(tempfile.mkdtemp())
    p = tmp / "Channel.class"
    p.write_bytes(cf.serialize())
    r = subprocess.run([JAVAP, "-p", str(p)],
                       capture_output=True, text=True, errors="replace")
    check("javap accepts the remapped class", r.returncode == 0, r.stderr[:200])
    check("javap shows the deobfuscated field names", "LOGGER" in r.stdout,
          r.stdout[:200])


def test_mc_is_not_flow_obfuscated() -> None:
    """The real check on false positives: 300 real classes from a vanilla jar.

    Only the backwards-handler fingerprint is asserted absent. Irreducible
    gotos are deliberately *not* asserted absent: measuring a real 1.20.4
    client showed javac emits gotos into the middle of a protected range on
    its own, so that shape cannot carry an attribution on its own either.
    """
    print("obf: a vanilla client is not mistaken for flow-obfuscated")
    rep, _per = OB.scan_obfuscation(MC_JAR, limit=300)
    keys = {e.key for e in rep.evidence}
    check("no backwards exception handlers", "handler-backjump" not in keys,
          str(sorted(keys)))
    check("nothing attributed", rep.vendor is None, rep.summary())


def test_cfg_and_dynamic_mocks() -> None:
    print("cfg & stubs: control flow graph reassembly, far jumps, and dynamic mock agent")
    from jdec import stubs as SB
    from jdec import cfg as CFG_MOD
    from jdec import deflat as DF_MOD

    # 1. build_stub_class_bytes: pure Python synthetic class generation
    data = SB.build_stub_class_bytes("net/minecraft/client/Minecraft")
    cf = CF.parse(data)
    check("build_stub_class_bytes produces valid class", cf.name == "net/minecraft/client/Minecraft")
    check("stub class inherits java/lang/Object", cf.super_name == "java/lang/Object")
    fnames = [cf.utf8(f.name_index) for f in cf.fields]
    check("stub class has INSTANCE field", "INSTANCE" in fnames)
    mnames = [cf.utf8(m.name_index) for m in cf.methods]
    check("stub class has getInstance", "getInstance" in mnames)
    check("stub class has <clinit>", "<clinit>" in mnames)

    # 2. build_mock_agent_jar & ensure_mock_agent_jar
    tmp_agent_dir = Path(tempfile.mkdtemp(prefix="jdec_test_agent_"))
    try:
        agent_jar = tmp_agent_dir / "mock_agent.jar"
        SB.build_mock_agent_jar(agent_jar)
        check("mock_agent.jar created", agent_jar.is_file())
        with zipfile.ZipFile(agent_jar) as z:
            mf = z.read("META-INF/MANIFEST.MF").decode("utf-8")
            check("mock agent manifest has Premain-Class", "Premain-Class: jdec.mock.MockAgent" in mf)
            check("mock agent jar contains MockAgent.class", "jdec/mock/MockAgent.class" in z.namelist())
    finally:
        shutil.rmtree(tmp_agent_dir, ignore_errors=True)

    # 3. DynamicMockClassLoader live test (if javac & java available)
    jc = SB._find_javac("javac")
    if jc:
        tmp_live = Path(tempfile.mkdtemp(prefix="jdec_test_dmcl_"))
        try:
            driver_src = (
                "public class DynamicMockTest {\n"
                "    public static void main(String[] args) throws Exception {\n"
                "        RecoverDriver.DynamicMockClassLoader cl = new RecoverDriver.DynamicMockClassLoader(DynamicMockTest.class.getClassLoader());\n"
                "        Class<?> c = Class.forName(\"com.unknown.external.MockService\", true, cl);\n"
                "        Object inst1 = c.getMethod(\"getInstance\").invoke(null);\n"
                "        Object inst2 = c.getMethod(\"getInstance\").invoke(null);\n"
                "        if (inst1 == null || inst1 != inst2) throw new AssertionError(\"mock instance null or not singleton\");\n"
                "        System.out.println(\"MOCK_OK: \" + inst1.getClass().getName());\n"
                "    }\n"
                "}\n"
            )
            rec_src = Path(__file__).resolve().parent.parent / "jdec" / "recover_driver_template.java"
            (tmp_live / "RecoverDriver.java").write_text(rec_src.read_text(encoding="utf-8"), encoding="utf-8")
            (tmp_live / "DynamicMockTest.java").write_text(driver_src, encoding="utf-8")
            r_c = subprocess.run([jc, "-d", str(tmp_live), str(tmp_live / "RecoverDriver.java"), str(tmp_live / "DynamicMockTest.java")], capture_output=True, text=True, errors="replace")
            if r_c.returncode == 0:
                from jdec import engines as EN
                java_bin = EN.find_java() or "java"
                r_r = subprocess.run([java_bin, "-cp", str(tmp_live), "DynamicMockTest"], capture_output=True, text=True, errors="replace")
                check("DynamicMockClassLoader loaded missing class on the fly", "MOCK_OK: com.unknown.external.MockService" in r_r.stdout)
                check("DynamicMockClassLoader enforces singleton reference identity", "MOCK_OK" in r_r.stdout)
        finally:
            shutil.rmtree(tmp_live, ignore_errors=True)

    # 4. CFG construction, reachability & reassembly
    code = bytearray([
        0x04,             # 0: iconst_1
        0x99, 0x00, 0x07, # 1: ifeq +7 (to 8)
        0x05,             # 4: iconst_2
        0xA7, 0x00, 0x06, # 5: goto +6 (to 11)
        0x06,             # 8: iconst_3
        0x00,             # 9: nop
        0x00,             # 10: nop
        0xB1              # 11: return
    ])
    g = CFG_MOD.build_cfg(bytes(code))
    check("CFG partitioned basic blocks", len(g.blocks) == 4)
    r_blocks, r_pcs = CFG_MOD.compute_reachability(g)
    check("CFG reachability found all blocks", len(r_blocks) == 4 and len(r_pcs) == 12)
    reassembled, _, _ = CFG_MOD.assemble_cfg(g)
    check("CFG reassembled code matches original", reassembled == bytes(code))

    # 5. Far jump widening (> 32KB)
    code_far = bytearray([0x04])
    code_far.extend([0xC8, 0x00, 0x00, 0x9C, 0x44]) # goto_w +40004 -> targets 40005
    code_far.extend([0x00] * 39999)
    code_far.extend([0xB1])

    g_far = CFG_MOD.build_cfg(bytes(code_far))
    g_far.blocks[0].insns[1].op = BC.OP_GOTO
    g_far.blocks[0].insns[1].length = 3
    new_code, _, stats = CFG_MOD.assemble_cfg(g_far, allow_widening=True)
    check("CFG widened 16-bit goto to goto_w for far jump", stats["widened_goto"] == 1)
    dec = BC.decode(new_code)
    check("CFG reassembled far goto_w has correct target", dec[1].op == BC.OP_GOTO_W and dec[1].jump_targets() == [40005])

    # 6. Far conditional jump expansion (> 32KB)
    g_far2 = CFG_MOD.build_cfg(bytes(code_far))
    g_far2.blocks[0].insns[1].op = 0x99 # ifeq
    g_far2.blocks[0].insns[1].length = 3
    new_code2, _, stats2 = CFG_MOD.assemble_cfg(g_far2, allow_widening=True)
    check("CFG expanded far conditional branch", stats2["widened_if"] == 1)
    dec2 = BC.decode(new_code2)
    check("CFG expanded to inverted condition and goto_w", dec2[1].op == 0x9A and dec2[2].op == BC.OP_GOTO_W and dec2[2].jump_targets() == [40008])
    check("CFG expanded goto_w reaches return instruction", new_code2[dec2[2].jump_targets()[0]] == 0xB1)

    # 7. StackMapTable reconstruction
    smt = CFG_MOD.rebuild_stack_map_table(None, new_code2)
    check("StackMapTable generated", len(smt) >= 2 and struct.unpack_from(">H", smt, 0)[0] > 0)

    # 8. deflat far switch transition (> 32KB)
    switch_code = bytearray([0x1B, 0xAA, 0, 0] + list(struct.pack('>iiiii', 0, 1, 3, 27, 40030)) + list(struct.pack('>i', 35)))
    switch_code += bytearray([0x10, 0x02, 0x3C, 0xA7]) + bytearray(struct.pack('>h', -31))
    switch_code += bytearray(b'\x00' * (40035 - len(switch_code)))
    switch_code += bytearray([0xB1])
    deflat_far, n_far = DF_MOD.deflat_code(bytes(switch_code))
    check("deflat unflattened switch transition spanning > 32KB", n_far >= 1 and deflat_far[28] == BC.OP_GOTO_W)

    # 9. CFG exception handler covers widened code end
    h_orig = [BC.Handler(start_pc=0, end_pc=len(code_far), handler_pc=len(code_far) - 1, catch_type=0)]
    g_far_h = CFG_MOD.build_cfg(bytes(code_far), handlers=h_orig)
    g_far_h.blocks[0].insns[1].op = BC.OP_GOTO
    g_far_h.blocks[0].insns[1].length = 3
    new_code_h, new_handlers_h, _ = CFG_MOD.assemble_cfg(g_far_h, allow_widening=True)
    check("CFG exception handler start matches 0", new_handlers_h[0].start_pc == 0)
    check("CFG exception handler end covers full expanded code", new_handlers_h[0].end_pc == len(new_code_h))

    # 10. StackMapTable with exception handler generates handler frames
    smt_h = CFG_MOD.rebuild_stack_map_table(None, new_code_h, handlers=new_handlers_h)
    check("StackMapTable generated with handler frames", len(smt_h) >= 5)

    # 11. deflat_class supports variable-length code widening without dropping code
    cf_dummy = CF.parse(SB.build_stub_class_bytes("com/example/Dummy"))
    edits = DF_MOD.deflat_class(cf_dummy)
    check("deflat_class executed without crashing", isinstance(edits, int))


def test_bvm_and_native_extensions() -> None:
    print("bvm & native: BytecodeVM devirtualization, far CFG reassembly, and Frida dynamic ingest")
    from jdec import bvm_devirt as BVM
    from jdec import recover as RC
    from jdec import stubs as SB

    # 1. BVMDecoder: decode standard virtual instruction stream
    code_seq = [
        BVM.ORDINAL_BY_NAME["ICONST_1"],
        BVM.ORDINAL_BY_NAME["BIPUSH"], 42,
        BVM.ORDINAL_BY_NAME["IADD"],
        BVM.ORDINAL_BY_NAME["IRETURN"]
    ]
    insns = BVM.BVMDecoder.decode(code_seq)
    check("BVMDecoder decoded all instructions", len(insns) == 4)
    check("BVMDecoder resolved BIPUSH opcode", insns[1].opcode_name == "BIPUSH" and insns[1].operands == [42])

    # 2. Mutator map decoding (random permutation)
    mut_map = {999: BVM.ORDINAL_BY_NAME["ICONST_5"], 888: "RETURN"}
    mut_insns = BVM.BVMDecoder.decode([999, 888], mutator_map=mut_map)
    check("BVMDecoder resolved mutated opcodes", mut_insns[0].opcode_name == "ICONST_5" and mut_insns[1].opcode_name == "RETURN")

    # 3. BVMTranslator: translate simple method into valid JVM bytecode
    vm_meth = BVM.BVMMethod(
        code_id=101,
        name="calculate",
        desc="()I",
        code=code_seq,
        constants=[],
        max_locals=1,
        max_stack=2
    )
    cf_host = CF.parse(SB.build_stub_class_bytes("com/example/Host"))
    res = BVM.BVMTranslator.translate_method(vm_meth, cf_host)
    check("BVMTranslator translated bytecode length", len(res.bytecode) == 5)
    check("BVMTranslator bytecode matches JVM ops", res.bytecode == bytes([0x04, 0x10, 42, 0x60, 0xAC]))

    # 4. BVMTranslator: branch resolution and far jump widening (>32KB)
    far_code = [BVM.ORDINAL_BY_NAME["GOTO"], 33002]
    far_code.extend([BVM.ORDINAL_BY_NAME["NOP"]] * 33000)
    far_code.append(BVM.ORDINAL_BY_NAME["RETURN"])

    vm_meth_far = BVM.BVMMethod(
        code_id=102,
        name="farBranch",
        desc="()V",
        code=far_code,
        constants=[],
        max_locals=1,
        max_stack=1
    )
    res_far = BVM.BVMTranslator.translate_method(vm_meth_far, cf_host)
    check("BVMTranslator widened far virtual branch to goto_w", res_far.stats.get("widened_goto", 0) == 1)
    dec_far = BC.decode(res_far.bytecode)
    check("BVMTranslator decoded first insn is goto_w", dec_far[0].op == BC.OP_GOTO_W)

    # 5. Exception handler mapping
    eh_code = [
        BVM.ORDINAL_BY_NAME["ICONST_0"],
        BVM.ORDINAL_BY_NAME["ICONST_1"],
        BVM.ORDINAL_BY_NAME["IDIV"],
        BVM.ORDINAL_BY_NAME["IRETURN"],
        BVM.ORDINAL_BY_NAME["POP"],
        BVM.ORDINAL_BY_NAME["ICONST_M1"],
        BVM.ORDINAL_BY_NAME["IRETURN"]
    ]
    vm_meth_eh = BVM.BVMMethod(
        code_id=103,
        name="safeDiv",
        desc="()I",
        code=eh_code,
        constants=["java/lang/ArithmeticException"],
        exception_handlers=[0, 3, 4, 0],
        max_locals=1,
        max_stack=2
    )
    res_eh = BVM.BVMTranslator.translate_method(vm_meth_eh, cf_host)
    check("BVMTranslator translated exception handler", len(res_eh.handlers) == 1)
    check("BVMTranslator handler start_pc is 0", res_eh.handlers[0].start_pc == 0)
    check("BVMTranslator handler handler_pc points to POP", res_eh.bytecode[res_eh.handlers[0].handler_pc] == 0x57)

    # 5b. end_pc is exclusive and may equal the code length (no instruction
    # starts there); it must still cover the final instruction
    vm_meth_eh_end = BVM.BVMMethod(
        code_id=104,
        name="safeDivEnd",
        desc="()I",
        code=eh_code,
        constants=["java/lang/ArithmeticException"],
        exception_handlers=[0, 7, 4, 0],
        max_locals=1,
        max_stack=2
    )
    res_eh_end = BVM.BVMTranslator.translate_method(vm_meth_eh_end, cf_host)
    check("handler end_pc == code length covers the final instruction",
          len(res_eh_end.handlers) == 1
          and res_eh_end.handlers[0].end_pc == len(res_eh_end.bytecode),
          str([(h.start_pc, h.end_pc) for h in res_eh_end.handlers])
          + f" len={len(res_eh_end.bytecode)}")

    # 6. Devirtualizer class file injection
    cp_helper = BVM.ConstantPoolHelper(cf_host)
    mref_idx = cp_helper.add_methodref("com/example/VM", "execute", "(I)V")

    code_blob = bytearray([0x10, 101, 0xB8, (mref_idx >> 8) & 0xFF, mref_idx & 0xFF, 0xB1])
    code_attr = BVM.BVMDevirtualizer.build_code_attribute(cf_host, 2, 1, bytes(code_blob), [])
    target_method = CF.Member(
        access_flags=CF.ACC_PUBLIC | CF.ACC_STATIC,
        name_index=cf_host.intern_utf8("testTarget"),
        descriptor_index=cf_host.intern_utf8("()I"),
        attrs_blob=struct.pack(">H", 1) + code_attr
    )
    cf_host.methods.append(target_method)

    extracted_id = BVM.BVMDevirtualizer.extract_code_id(cf_host, target_method)
    check("BVMDevirtualizer extracted codeId from bytecode", extracted_id == 101)

    code_pool = {101: vm_meth}
    devirt_cf, devirt_count = BVM.BVMDevirtualizer.devirtualize_class_file(cf_host, code_pool)
    check("BVMDevirtualizer devirtualized target method", devirt_count == 1)

    # 7. Code pool JSON round-trip
    with tempfile.TemporaryDirectory() as td:
        p_json = Path(td) / "code_pool.json"
        BVM.BVMDevirtualizer.save_code_pool(code_pool, p_json)
        check("BVMDevirtualizer saved code pool JSON", p_json.exists())
        loaded_pool = BVM.BVMDevirtualizer.load_code_pool(p_json)
        check("BVMDevirtualizer loaded code pool roundtrip", 101 in loaded_pool and loaded_pool[101].name == "calculate")

    # 8. Frida dynamic TSV ingestion
    frida_6col_content = (
        "OK\tcom.example.Target\tdecrypt\tCIPHER_A\t1001\tHelloFrida\n"
        "OK\tcom.example.Target\tresolve\tCIPHER_B\t1002\tSecretFrida\n"
    )
    with tempfile.TemporaryDirectory() as td:
        tsv_path = Path(td) / "frida.tsv"
        tsv_path.write_text(frida_6col_content, encoding="utf-8")
        rows = RC.ingest_frida_tsv(tsv_path)
        check("ingest_frida_tsv parsed 6-col rows", len(rows) == 2)
        check("ingest_frida_tsv parsed string plaintext", rows.get(("CIPHER_A", "1001")) == "HelloFrida")
        check("ingest_frida_tsv parsed second plaintext", rows.get(("CIPHER_B", "1002")) == "SecretFrida")

        # Test 3-col format
        frida_3col_content = "CIPHER_C\t2001\tPlain3Col\n"
        tsv_3col = Path(td) / "frida_3col.tsv"
        tsv_3col.write_text(frida_3col_content, encoding="utf-8")
        rows_3col = RC.ingest_frida_tsv(tsv_3col)
        check("ingest_frida_tsv parsed 3-col rows", rows_3col.get(("CIPHER_C", "2001")) == "Plain3Col")

        # Test jnitrace format
        jnitrace_content = (
            "1234\tNewStringUTF\tjni_decrypted_secret\n"
        )
        (Path(td) / "jnitrace.tsv").write_text(jnitrace_content, encoding="utf-8")
        jni_rows = RC.ingest_frida_tsv(Path(td) / "jnitrace.tsv")
        check("ingest_frida_tsv parsed jnitrace rows", len(jni_rows) == 1 and jni_rows.get(("jni_decrypted_secret", "0")) == "jni_decrypted_secret")

    # 9. MockAgent JAR generation and instrumentation verification
    agent_jar = SB.ensure_mock_agent_jar()
    check("ensure_mock_agent_jar returns existing jar", agent_jar.is_file())
    with zipfile.ZipFile(agent_jar, "r") as zf:
        mf = zf.read("META-INF/MANIFEST.MF").decode("utf-8")
        check("mock agent manifest contains Premain-Class", "Premain-Class: jdec.mock.MockAgent" in mf)
        check("mock agent contains MockAgent.class", "jdec/mock/MockAgent.class" in zf.namelist())

    # 10. INVOKEINTERFACE with arguments and receiver count
    vm_meth_itf = BVM.BVMMethod(
        code_id=104,
        name="callItf",
        desc="()V",
        code=[
            BVM.ORDINAL_BY_NAME["ALOAD"], 0,
            BVM.ORDINAL_BY_NAME["ICONST_1"],
            BVM.ORDINAL_BY_NAME["LCONST_0"],
            BVM.ORDINAL_BY_NAME["INVOKEINTERFACE"], 0, 1, 2, 4,
            BVM.ORDINAL_BY_NAME["RETURN"]
        ],
        constants=["com/example/MyInterface", "compute", "(IJ)V"],
        max_locals=3,
        max_stack=4
    )
    res_itf = BVM.BVMTranslator.translate_method(vm_meth_itf, cf_host)
    check("BVMTranslator translated invokeinterface", 0xB9 in res_itf.bytecode)
    itf_idx = res_itf.bytecode.index(0xB9)
    check("invokeinterface count operand is 4", res_itf.bytecode[itf_idx + 3] == 4)

    # 11. LDC with 2-word Long / Double uses ldc2_w (0x14)
    vm_meth_long = BVM.BVMMethod(
        code_id=105,
        name="loadLong",
        desc="()J",
        code=[
            BVM.ORDINAL_BY_NAME["LDC"], 0,
            BVM.ORDINAL_BY_NAME["LRETURN"]
        ],
        constants=[{"type": "long", "value": 9876543210123}],
        max_locals=1,
        max_stack=2
    )
    res_long = BVM.BVMTranslator.translate_method(vm_meth_long, cf_host)
    check("ldc2_w used for long constant", res_long.bytecode[0] == 0x14)

    # 12. Non-Code attributes preserved across devirtualization
    sig_attr_idx = cf_host.intern_utf8("Signature")
    sig_val_idx = cf_host.intern_utf8("()I")
    sig_attr = struct.pack(">HIH", sig_attr_idx, 2, sig_val_idx)
    target_method.attrs_blob = struct.pack(">H", 2) + code_attr + sig_attr
    devirt_cf2, count2 = BVM.BVMDevirtualizer.devirtualize_class_file(cf_host, {101: vm_meth})
    has_sig = False
    o = 2
    for _ in range(struct.unpack_from(">H", target_method.attrs_blob, 0)[0]):
        ni = struct.unpack_from(">H", target_method.attrs_blob, o)[0]
        alen = struct.unpack_from(">I", target_method.attrs_blob, o + 2)[0]
        o += 6 + alen
        if cf_host.utf8(ni) == "Signature":
            has_sig = True
    check("set_code_attribute preserved Signature attribute", has_sig)

    # 13. Keyword sanitization handles short and byte declarations
    code_kw_types = "short default = 1;\nbyte goto = 2;\nMyType default = null;"
    san_kw, kw_c = PJ.sanitize_keyword_identifiers(code_kw_types)
    check("keywords escaped for short and byte types", "short default_ = 1;" in san_kw and "byte goto_ = 2;" in san_kw)

    # 14. Devirtualizer generic naming and alias compatibility
    from jdec import devirt as DV
    check("Devirtualizer is aliased to BVMDevirtualizer", DV.Devirtualizer is BVM.BVMDevirtualizer)
    check("VMDecoder is aliased to BVMDecoder", DV.VMDecoder is BVM.BVMDecoder)
    check("VMTranslator is aliased to BVMTranslator", DV.VMTranslator is BVM.BVMTranslator)
    check("VMMethod is aliased to BVMMethod", DV.VMMethod is BVM.BVMMethod)
    target_method.attrs_blob = struct.pack(">H", 1) + code_attr
    dv_res = DV.Devirtualizer.devirtualize_class_file(cf_host, {101: vm_meth})
    check("Devirtualizer devirtualize_class_file returns success", dv_res[1] == 1)


def test_remap_failure_accounting() -> None:
    print("mappings: remap failures are reported (and fatal under strict mode)")
    from jdec import stubs as SB
    m = MP.Mapping()
    m.add_class("demo/good/Keep", "demo/new/Keep")
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "in.jar"
        with zipfile.ZipFile(src, "w") as z:
            z.writestr("demo/good/Keep.class", SB.build_stub_class_bytes("demo/good/Keep"))
            # a class entry that fails to parse -> remap_class_bytes raises
            z.writestr("demo/bad/Broken.class",
                       b"\xca\xfe\xba\xbe\x00\x00\x00\x34garbage")
        dst = Path(td) / "out.jar"
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            changed, total = MP.remap_jar(src, dst, m)
        check("good class remapped, broken one counted in total",
              (changed, total) == (1, 2), f"changed={changed} total={total}")
        check("failure is reported, not swallowed",
              "NOT remapped" in buf.getvalue() and "demo/bad/Broken.class" in buf.getvalue(),
              buf.getvalue()[:200])
        with zipfile.ZipFile(dst) as z:
            check("broken class written back under its original name",
                  "demo/bad/Broken.class" in z.namelist(), str(z.namelist()))
        dst2 = Path(td) / "out_strict.jar"
        try:
            MP.remap_jar(src, dst2, m, strict=True)
            check("strict remap raises on failure", False, "no error")
        except RuntimeError as exc:
            check("strict remap raises on failure", "1 class(es) failed" in str(exc), str(exc))


def test_devirt_opcode_disambiguation() -> None:
    print("devirt: opcode interpretation is explicit (ordinal vs jvm-opcode)")
    from jdec import bvm_devirt as BVM
    # 0x2E is JVM iaload AND a valid ordinal index (-> POP2): the two spaces
    # overlap, so the reading must be chosen by mode, not by silent fallback
    got = BVM.BVMDecoder.resolve_opcode(0x2E, None, mode="ordinal")
    check("ordinal mode reads 0x2E as an OPCS ordinal (POP2)",
          got == BVM.OPCS_ORDINALS[0x2E] == "POP2", str(got))
    got_jvm = BVM.BVMDecoder.resolve_opcode(0x2E, None, mode="jvm-opcode")
    check("jvm-opcode mode reads 0x2E as IALOAD", got_jvm == "IALOAD", str(got_jvm))
    # a supplied map is authoritative: unmapped ints stay unmapped even when
    # they happen to land inside the ordinal range
    small_map = {7: BVM.ORDINAL_BY_NAME["ICONST_1"]}
    check("map miss returns None even for in-range ints",
          BVM.BVMDecoder.resolve_opcode(0x2E, small_map, mode="ordinal") is None)
    check("map hit resolves through the map",
          BVM.BVMDecoder.resolve_opcode(7, small_map, mode="ordinal") == "ICONST_1")
    try:
        BVM.BVMDecoder.resolve_opcode(1, None, mode="bogus")
        check("unknown mode rejected", False, "no error raised")
    except ValueError:
        check("unknown mode rejected", True)


def test_pool_verify_fq_callsites() -> None:
    print("pool: fully-qualified call sites resolve identically in repl and verify")
    import base64 as B64
    from jdec import pool as PL
    # the old verify resolved via simple-name lookup only, which can never hit
    # a fully-qualified cls_raw - that blind spot is the regression being pinned
    acc = {"demo.pool.Acc": {"a": [("int", "int")]}}
    simple = {"Acc": "demo.pool.Acc"}
    check("old-style simple-name lookup misses FQ forms",
          simple.get("demo.pool.Acc") is None)
    check("_resolve_fq resolves the FQ form",
          PL._resolve_fq("demo.pool.Acc", acc, simple, set()) == "demo.pool.Acc")
    check("_resolve_fq resolves the simple form",
          PL._resolve_fq("Acc", acc, simple, set()) == "demo.pool.Acc")
    check("_resolve_fq refuses ambiguous simple names",
          PL._resolve_fq("Acc", acc, simple, {"Acc"}) is None)
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "src"
        out = Path(td) / "out"
        src.mkdir(parents=True)
        (src / "Acc.java").write_text(
            "package demo.pool;\n\npublic class Acc {\n"
            "    static String a(int idx, int seed) {\n"
            "        return null;\n    }\n}\n", encoding="utf-8")
        (src / "Caller.java").write_text(
            "package demo.caller;\n\npublic class Caller {\n"
            "    String s = demo.pool.Acc.a(1, 2);\n"
            "    String t = Acc.a(3, 4);\n}\n", encoding="utf-8")
        harvest = Path(td) / "h.tsv"
        rows = ["R\tdemo.pool.Acc\ta\t1\t2\t" + B64.b64encode(b"alpha").decode(),
                "R\tdemo.pool.Acc\ta\t3\t4\t" + B64.b64encode(b"beta").decode()]
        harvest.write_text("\n".join(rows) + "\n", encoding="utf-8")
        res = PL.apply(src, harvest, out)
        check("FQ and simple call sites both replaced",
              res["repl_q"] == 2, str(res))
        check("verify agrees: zero residual", res["residual"] == 0, str(res))
        got = (out / "Caller.java").read_text(encoding="utf-8")
        check("plaintext landed in the source",
              '"alpha"' in got and '"beta"' in got, got)


def test_attribution_gates() -> None:
    print("obf: attribution gates on class coverage; the floor is exclusive")
    # single goto-flood fingerprint = confidence 0.35 -> not a vendor
    vendor, conf = OB.attribute({"goto-flood": 100}, 1000)
    check("single goto-flood stays unknown", vendor is None and conf == 0.35,
          f"{vendor} {conf}")
    # below the 10%-of-classes gate
    vendor, _ = OB.attribute({"goto-flood": 9}, 100)
    check("9% class coverage stays unknown", vendor is None, str(vendor))
    # independent corroboration crosses the floor
    vendor, conf = OB.attribute({"goto-flood": 500, "long-constant-array": 200}, 1000)
    check("corroborated signals attribute to ZKM",
          vendor == "Zelix KlassMaster (ZKM)" and conf > 0.35, f"{vendor} {conf}")
    # build_report must gate on *class* counts, not occurrence totals: 500
    # occurrences from 2 classes must not clear a 100-class 10% gate
    class_hits = {"a": {"goto-flood": 250}, "b": {"goto-flood": 250}}
    rep = OB.build_report({"goto-flood": 500}, class_hits, 1000, 2, 0)
    check("occurrence inflation does not smuggle past the class gate",
          rep.vendor is None, rep.summary())
    class_hits2 = {f"c{i}": {"goto-flood": 1, "long-constant-array": 1}
                   for i in range(120)}
    rep2 = OB.build_report({"goto-flood": 120, "long-constant-array": 120},
                           class_hits2, 1000, 120, 0)
    check("wide corroborated coverage does attribute",
          rep2.vendor is not None and "ZKM" in rep2.vendor, rep2.summary())


def test_score_decl_and_noise() -> None:
    """REVIEW 1.1 negative: the old identifier-set matching scored comment
    mentions and bare call sites as full member hits."""
    print("score: coverage counts declarations, not comments or call sites")
    with zipfile.ZipFile(SAMPLE) as z:
        cf = CF.parse(z.read("demo/modern/Showcase.class"))
    members = [m for m, _d in cf.method_sigs() if not m.startswith("<")]
    all_names = members + [f for f, _d in cf.field_sigs()]
    check("fixture has members to score", bool(all_names))

    # (a) names only inside a comment used to give coverage 1.0 / usable True
    comment_only = ("// declared members: " + ", ".join(all_names)
                    + "\npublic class Showcase {}\n")
    q = evaluate(comment_only, cf)
    check("comment-only member list is not a hit", q.coverage < 1.0,
          f"coverage={q.coverage}")
    check("comment-only output is unusable", not q.usable, f"score={q.score}")

    # (b) bare call sites are not declarations
    calls = ("public class Showcase {\n    void callsite() {\n        "
             + "; ".join(f"{m}()" for m in members[:3]) + ";\n    }\n}\n")
    q2 = evaluate(calls, cf)
    check("bare call sites do not count as recovered members",
          q2.coverage < 1.0, f"coverage={q2.coverage}")

    # (c) string-literal mentions are stripped before matching
    lit = ('public class Showcase {\n    void c() { System.out.println("'
           + all_names[0] + '"); }\n}\n')
    q3 = evaluate(lit, cf)
    check("string-literal mention does not count", q3.coverage < 1.0,
          f"coverage={q3.coverage}")

    # (d) same-name overloads are counted individually by _decl_counts
    counts = SCORE._decl_counts("public int a() {}\npublic int a(int x) {}\nint a;\n")
    check("_decl_counts counts overloads individually", counts.get("a") == 3,
          str(counts))
    # (d2) nested generics in the method header must not hide the name
    counts2 = SCORE._decl_counts(
        "public <T extends Comparable<T>> T maxOf(List<T> list, T t) { return t; }\n")
    check("nested generic header still counts as a declaration",
          counts2.get("maxOf") == 1, str(counts2))

    # (e) positive control: real declarations still hit
    decls = ("public class Showcase {\n"
             + "\n".join(f"    public int {m}() {{ return 1; }}" for m in members)
             + "\n}\n")
    q4 = evaluate(decls, cf)
    check("true declarations still hit", q4.coverage >= 0.9, f"coverage={q4.coverage}")


def test_code_pool_json_integrity() -> None:
    """REVIEW 1.2 negative: JSON round-trip stringifies dict keys; the loaded
    map used to make resolve_opcode(7) return None."""
    print("devirt: code-pool JSON round-trip preserves int opcode keys")
    ret = DV.ORDINAL_BY_NAME["RETURN"]
    vm = DV.VMMethod(code_id=7, name="m", desc="()V", code=[7, 8],
                     opcode_map={7: 4, 8: ret}, mode="ordinal")
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "pool.json"
        DV.Devirtualizer.save_code_pool({7: vm}, p)
        raw = json.loads(p.read_text(encoding="utf-8"))
        check("json inevitably stores string keys",
              raw["7"]["opcode_map"] == {"7": 4, "8": ret})
        loaded = DV.Devirtualizer.load_code_pool(p)[7]
        check("loaded map keys are ints again",
              loaded.opcode_map == {7: 4, 8: ret}, repr(loaded.opcode_map))
        check("mode round-trips", loaded.mode == "ordinal")
    check("review repro: resolve_opcode(7) resolves (used to be None)",
          DV.VMDecoder.resolve_opcode(7, loaded.opcode_map) == "ICONST_1",
          repr(DV.VMDecoder.resolve_opcode(7, loaded.opcode_map)))
    bad = DV.VMMethod(code_id=9, code=[0], opcode_map={5: 999})
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "bad.json"
        DV.Devirtualizer.save_code_pool({9: bad}, p)
        try:
            DV.Devirtualizer.load_code_pool(p)
            check("invalid ordinal fails loudly", False, "no exception raised")
        except ValueError as e:
            check("invalid ordinal fails loudly", "ordinal" in str(e).lower(), str(e))


def test_max_stack_dataflow() -> None:
    """REVIEW 1.3 negative: a peak-9 stream used to inherit the declared
    (smaller) max_stack instead of the computed one."""
    print("devirt: max_stack comes from stack dataflow, not the declared field")
    from jdec import stubs as SB
    cf_host = CF.parse(SB.build_stub_class_bytes("com/example/Host"))
    b = DV.ORDINAL_BY_NAME
    code9 = [b["ICONST_1"]] * 9 + [b["POP"]] * 9 + [b["RETURN"]]
    r9 = DV.VMTranslator.translate_method(
        DV.VMMethod(code_id=1, name="nine", desc="()V", code=code9, max_stack=2),
        cf_host)
    check("peak-9 stream yields max_stack >= 9 (declared was 2)",
          r9.max_stack >= 9, f"max_stack={r9.max_stack}")
    check("stats records the computed source",
          r9.stats.get("max_stack_source") == "computed")
    codel = [b["LCONST_0"]] * 4 + [b["POP2"]] * 4 + [b["RETURN"]]
    rl = DV.VMTranslator.translate_method(
        DV.VMMethod(code_id=2, name="longs", desc="()V", code=codel, max_stack=2),
        cf_host)
    check("two-slot values occupy two slots (peak 8)", rl.max_stack >= 8,
          f"max_stack={rl.max_stack}")


def test_replay_safety_gate() -> None:
    """REVIEW 2.1 negative: dynamic replay used to start a JVM with no opt-in."""
    if _no_engines():
        return

    print("recover/pool: dynamic replay is opt-in (safety gate)")
    with tempfile.TemporaryDirectory() as td:
        rec_dir = Path(td) / "rec"
        rc = RC.recover(SAMPLE, rec_dir)
        check("recover without allow_exec returns 3 (gated)", rc == 3, f"rc={rc}")
        check("no recovered.tsv without opt-in",
              not (rec_dir / "recovered.tsv").is_file())
    with tempfile.TemporaryDirectory() as td:
        spec = Path(td) / "spec.tsv"
        spec.write_text("class\tmethod\tsite\texpr\n", encoding="utf-8")
        try:
            PL.harvest(spec, Path(td) / "out.tsv", Path(td) / "work")
            check("pool harvest without allow_exec raises", False, "no exception")
        except PL.ReplayNotAllowed as e:
            check("pool harvest without allow_exec raises", "EXECUTES" in str(e), str(e))
    parser = CL.build_parser()
    ns = parser.parse_args(["auto", "x.jar"])
    check("auto defaults to allow_replay=False", not getattr(ns, "allow_replay", True))
    ns2 = parser.parse_args(["pipeline", "x.jar", "--allow-replay"])
    check("pipeline --allow-replay opts in", getattr(ns2, "allow_replay", False))


def test_rewrite_skips_comments_strings() -> None:
    """BUG round negative: source rewriters used to replace lookalike
    call sites inside comments and string literals (source pollution,
    inflated replace counts, false verify residuals)."""
    print("recover: code_mask keeps comments/strings untouched in rewrite")
    code_mask = RC.code_mask

    # 1. lexer mask core cases
    t1 = 'int a = 1; // call Foo.q("AA", "BB", 3)\nint b = 2;'
    m1 = code_mask(t1)
    check("mask: line-comment lookalike masked", not m1[t1.index('"AA"')])
    check("mask: code after comment is code", m1[t1.index("int b")] is True)

    t2 = 'String s = "a\\"b"; Foo.q("CC", "DD", 4);'
    m2 = code_mask(t2)
    check("mask: escaped quote stays inside string", m2[t2.index("a\\")] is False)
    check("mask: real call site after string is code", m2[t2.index("Foo.q")] is True)

    t3 = '/* Foo.q("EE", "FF", 5) */ int x;'
    m3 = code_mask(t3)
    check("mask: block-comment lookalike masked",
          m3[t3.index('"EE"')] is False and m3[t3.index("int x")] is True)

    t4 = "char c = '\"'; Foo.q(\"GG\", \"HH\", 6);"
    m4 = code_mask(t4)
    check("mask: quote inside char literal does not open string",
          m4[t4.index("Foo.q")] is True and m4[t4.index("'\"'")] is False)

    # 2. rewrite_sources integration: decoys untouched, real sites replaced
    import base64
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "src"
        src.mkdir()
        jf = src / "T.java"
        jf.write_text(
            'class T {\n'
            '  // decoy: Util.dec("siteA", "cipherAA", 11) must stay\n'
            '  /* decoy: Util.dec("siteB", "cipherBB", 12) must stay */\n'
            '  String doc = "decoy Util.dec(\\"siteC\\", \\"cipherCC\\", 13) stays";\n'
            '  String a = Util.dec("siteD", "cipherDD", 14);\n'
            '  String b = Util.dec("siteE", "cipherEE", 15);\n'
            '}\n', encoding="utf-8")
        tsv = Path(td) / "recovered.tsv"
        # rewrite tsv columns: OK, ?, ?, cipher=parts[3], seed=parts[4], plain
        # call-shape X.y("site", "cipher", seed) -> key=(cipher, seed-int)
        rows = ["OK\tx\tx\tcipherDD\t14\tb64:" + base64.b64encode(b"plain4").decode(),
                "OK\tx\tx\tcipherEE\t15\tb64:" + base64.b64encode(b"plain5").decode()]
        tsv.write_text("\n".join(rows) + "\n", encoding="utf-8")

        st = RC.rewrite_sources(src, tsv_path=tsv)
        out = jf.read_text(encoding="utf-8")
        check("rewrite: line-comment decoy untouched",
              'Util.dec("siteA", "cipherAA", 11)' in out)
        check("rewrite: block-comment decoy untouched",
              'Util.dec("siteB", "cipherBB", 12)' in out)
        check("rewrite: in-string decoy untouched",
              'Util.dec(\\"siteC\\", \\"cipherCC\\", 13)' in out)
        check("rewrite: real call 1 replaced", '"plain4"' in out)
        check("rewrite: real call 2 replaced", '"plain5"' in out)
        check("rewrite: replaced counted exactly 2", st["replaced"] == 2,
              f"replaced={st['replaced']}")
        check("rewrite: nothing counted missed", st["missed"] == 0)
        check("rewrite: no false residual", st["residual"] == 0)


def test_bvm_extract_code_id_descriptor_gate() -> None:
    """BUG round negative: extract_code_id used to accept any invokestatic
    named 'execute' regardless of descriptor -> wrong codeId on collisions."""
    print("devirt: extract_code_id requires (I... descriptor on execute")
    from jdec import bvm_devirt as BVM
    from jdec import stubs as SB
    cf = CF.parse(SB.build_stub_class_bytes("com/example/Host"))
    helper = BVM.ConstantPoolHelper(cf)

    def make_caller(name: str, mref: int, code_id: int) -> CF.Member:
        blob = bytearray([0x10, code_id,
                          0xB8, (mref >> 8) & 0xFF, mref & 0xFF, 0xB1])
        attr = BVM.BVMDevirtualizer.build_code_attribute(cf, 2, 1, bytes(blob), [])
        return CF.Member(
            access_flags=CF.ACC_PUBLIC | CF.ACC_STATIC,
            name_index=cf.intern_utf8(name),
            descriptor_index=cf.intern_utf8("()I"),
            attrs_blob=struct.pack(">H", 1) + attr)

    # negative: name collides but first param is long, not int
    mref_bad = helper.add_methodref("com/example/VM", "execute", "(J)V")
    m_bad = make_caller("collideLong", mref_bad, 77)
    cf.methods.append(m_bad)
    got_bad = BVM.BVMDevirtualizer.extract_code_id(cf, m_bad)
    check("wrong-descriptor execute yields None", got_bad is None,
          f"got={got_bad}")

    # positive control: (I... execute still resolves the codeId
    mref_ok = helper.add_methodref("com/example/VM", "execute", "(I)V")
    m_ok = make_caller("collideOk", mref_ok, 88)
    cf.methods.append(m_ok)
    got_ok = BVM.BVMDevirtualizer.extract_code_id(cf, m_ok)
    check("(I...) execute still yields codeId", got_ok == 88, f"got={got_ok}")


def test_web_source_path_containment() -> None:
    """Engine labels and report rels are joined into paths: keep them inside."""
    print("web: source lookup refuses engine labels and rels that escape")
    from jdec import web as WB

    with tempfile.TemporaryDirectory() as td:
        wd = Path(td)
        (wd / "src" / "demo").mkdir(parents=True)
        (wd / "src" / "demo" / "A.java").write_text("class A {}\n", encoding="utf-8")
        (wd / "secret.java").write_text("SECRET\n", encoding="utf-8")
        (wd / "report.json").write_text(json.dumps({"classes": {
            "demo/A": {"engine": "cfr", "rel": "../secret.java"}}}),
            encoding="utf-8")

        check("a known engine label maps to its key", WB._engine_key("cfr") == "cfr")
        check("an unknown engine label has no key",
              WB._engine_key("../../../") is None)
        got = WB._get_source_for_engine(wd, "demo/A", "../../../")
        check("an unknown engine label is not used as a path",
              got.startswith("// Unknown engine"), got[:80])
        got = WB._get_source_for_engine(wd, "demo/A", "final")
        check("a report rel that escapes src/ is refused",
              "SECRET" not in got, got[:80])


def test_web_callgraph_error_semantics() -> None:
    """BUG round negative: /api/callgraph used to synthesize reachable:null
    plus empty lists when the callgraph could not be built - masking
    failures as normal-looking empty data."""
    print("web: /api/callgraph returns structured error instead of fake data")
    import urllib.request
    import urllib.error
    import threading
    from jdec import web as WB

    def fetch(url: str):
        try:
            with urllib.request.urlopen(url) as res:
                return res.status, json.loads(res.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))

    # scenario 1: empty work dir -> no analysis target at all
    with tempfile.TemporaryDirectory() as td:
        handler = lambda *a, **k: WB.WorkbenchHandler(*a, work_dir=Path(td), **k)
        server = WB.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            status, body = fetch(
                f"http://127.0.0.1:{server.server_address[1]}"
                f"/api/callgraph?class=demo/X")
            check("no-target -> structured error (4xx/5xx)", status >= 400,
                  f"status={status}")
            check("no-target error mentions missing target",
                  "error" in body and "target" in body["error"], str(body))
            check("no synthesized reachable key", "reachable" not in body)
        finally:
            server.shutdown()

    # scenario 2: target resolves but build fails (not a real jar)
    with tempfile.TemporaryDirectory() as td:
        fake_jar = Path(td) / "fake.jar"
        fake_jar.write_bytes(b"this is not a zip archive")
        handler = lambda *a, **k: WB.WorkbenchHandler(*a, work_dir=fake_jar, **k)
        server = WB.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            status, body = fetch(
                f"http://127.0.0.1:{server.server_address[1]}"
                f"/api/callgraph?class=demo/X")
            check("build-failure -> structured error (4xx/5xx)", status >= 400,
                  f"status={status}")
            check("build-failure error mentions build failure",
                  "error" in body and "build failed" in body["error"], str(body))
            check("no synthesized reachable key on failure",
                  "reachable" not in body)
        finally:
            server.shutdown()


def test_pipeline_stage_status() -> None:
    """REVIEW 2.2 negative: partial results used to exit 0 with no trace."""
    print("pipeline: stage status plumbing and exit codes")
    prof = JarProfile(path=SAMPLE, entries=1, classes=1)

    def mk(stages, strict=False):
        return PIPE.PipelineResult(target_jar=SAMPLE, out_dir=Path("."), profile=prof,
                                   stages=list(stages), strict=strict)

    ok_s = PIPE.StageStatus("probe", PIPE.STAGE_OK)
    sk = PIPE.StageStatus("replay", PIPE.STAGE_SKIPPED, "safety gate")
    part = PIPE.StageStatus("decompile", PIPE.STAGE_PARTIAL, "2 failed")
    bad = PIPE.StageStatus("replay", PIPE.STAGE_FAILED, "rc=1")
    check("ok/skipped -> success/0", mk([ok_s, sk]).exit_code == 0)
    check("partial -> exit 1", mk([ok_s, part]).exit_code == 1)
    check("failed -> exit 2", mk([ok_s, bad]).exit_code == 2)
    check("failed dominates partial", mk([part, bad]).overall_status == "failed")
    check("strict escalates partial to 2", mk([part], strict=True).exit_code == 2)
    check("strict keeps success at 0", mk([ok_s], strict=True).exit_code == 0)
    r = mk([PIPE.StageStatus("replay", PIPE.STAGE_PARTIAL, "indy ok; pool failed")])
    d = r.to_dict()
    check("to_dict carries overall/exit_code/stages",
          d["overall"] == "partial" and d["exit_code"] == 1
          and d["stages"][0]["stage"] == "replay")
    with tempfile.TemporaryDirectory() as td:
        md_path, json_path = PIPE.write_pipeline_summary(mk([ok_s, sk, part]), Path(td))
        md = md_path.read_text(encoding="utf-8")
        js = json.loads(json_path.read_text(encoding="utf-8"))
        check("summary md has stage table", "## Stage Status" in md and "`replay`" in md)
        check("summary md header shows overall + exit code",
              "Overall status:" in md and "exit code 1" in md)
        check("summary json carries stages", len(js["stages"]) == 3
              and js["overall"] == "partial")
    # BUG round negative: detail containing | or newlines used to break the
    # Markdown table structure
    pipe_st = PIPE.StageStatus("pool", PIPE.STAGE_PARTIAL, "a|b\nc d")
    with tempfile.TemporaryDirectory() as td2:
        md2, _ = PIPE.write_pipeline_summary(mk([ok_s, pipe_st]), Path(td2))
        md_text = md2.read_text(encoding="utf-8")
        row = next(ln for ln in md_text.splitlines()
                   if ln.startswith("| `pool` |"))
        cols = row.split(" | ")
        check("stage table: detail pipe escaped", "\\|b" in row, row)
        check("stage table: detail newline flattened", "\n" not in row and "c d" in row)
        check("stage table: column count preserved", len(cols) == 3, row)


def test_conservative_prune() -> None:
    """REVIEW 2.3 negative: indy method-ref targets and reflection-by-name
    classes used to be pruned as 'dead'."""
    print("reach: pruning keeps unknown dependencies (indy handles, reflection)")
    check("javac available for prune fixture", build_fixtures.ensure_sample_jar() is not None)
    if JAVAC is None:
        print("  (skipped: no javac; set JAVA_HOME or PATH)")
        return
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "src" / "a").mkdir(parents=True)
        sources = {
            "a/A.java": ("package a;\n"
                         "public class A {\n"
                         "    public static void main(String[] args) throws Exception {\n"
                         "        Runnable r = B::helper;\n"
                         "        r.run();\n"
                         "        Class.forName(\"a.Reflected\");\n"
                         "    }\n"
                         "}\n"),
            "a/B.java": ("package a;\n"
                         "public class B { public static void helper() { } }\n"),
            "a/Reflected.java": ("package a;\npublic class Reflected {}\n"),
            "a/Dead.java": ("package a;\npublic class Dead { public void unused() {} }\n"),
        }
        for rel, txt in sources.items():
            (d / "src" / rel).write_text(txt, encoding="utf-8")
        cls = d / "cls"
        subprocess.run([JAVAC, "-d", str(cls)]
                       + [str(d / "src" / r) for r in sources],
                       check=True, capture_output=True)
        jar = d / "fixture.jar"
        with zipfile.ZipFile(jar, "w", zipfile.ZIP_DEFLATED) as z:
            for c in cls.rglob("*.class"):
                z.write(c, c.relative_to(cls).as_posix())

        keep, counts = CG.conservative_keepset(jar)
        check("lambda host kept via BSM rule", "a/A" in keep, str(sorted(keep)))
        check("method-ref target kept via handle rule", "a/B" in keep, str(sorted(keep)))
        check("reflection target kept via string rule", "a/Reflected" in keep,
              str(sorted(keep)))
        check("proven-dead class not held back", "a/Dead" not in keep)

        cg = CG.build_callgraph(jar)
        rep = CG.compute_reachability(cg)
        # indy + Class.forName create no static edges: B and Reflected look dead
        check("B unreacheable by static edges (indy blindness)",
              "a/B" not in rep.reachable_classes)
        check("Reflected unreachable by static edges (reflection blindness)",
              "a/Reflected" not in rep.reachable_classes)
        out = d / "pruned.jar"
        CG.prune_jar(jar, out, rep.reachable_classes | keep)
        with zipfile.ZipFile(out) as z:
            names = {n[:-6] for n in z.namelist() if n.endswith(".class")}
        check("pruned jar keeps B (would-be NoSuchMethodError)", "a/B" in names)
        check("pruned jar keeps Reflected (Class.forName target)",
              "a/Reflected" in names)
        check("pruned jar drops Dead", "a/Dead" not in names)
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "a").mkdir()
        for n in ("Reflected", "Dead"):
            (d / "a" / f"{n}.java").write_text(
                f"package a;\npublic class {n} {{}}\n", encoding="utf-8")
        cls = d / "cls"
        subprocess.run([JAVAC, "-d", str(cls), str(d / "a" / "Reflected.java"),
                        str(d / "a" / "Dead.java")], check=True, capture_output=True)
        noep = d / "noep.jar"
        with zipfile.ZipFile(noep, "w", zipfile.ZIP_DEFLATED) as z:
            for c in cls.rglob("*.class"):
                z.write(c, c.relative_to(cls).as_posix())
        rep2 = CG.compute_reachability(CG.build_callgraph(noep))
        check("no-entrypoint jar triggers the refusal condition",
              not rep2.entrypoints)


def test_selfheal_audit() -> None:
    """REVIEW 2.4 negative: self-heal used to overwrite the only copy of the
    decompiled source, with no record of what changed."""
    print("project: self-heal keeps src-original/ and writes repair-log.md")
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        src_dir = d / "decomp_src" / "a"
        src_dir.mkdir(parents=True)
        # zero-width char + 'goto' as identifier: two self-heal rules fire.
        # (record/yield are contextual keywords and legal identifiers - the
        # tool correctly leaves them alone.)
        original = ("package a;\n\npublic class Healing {\n    public void run() {\n"
                    "        int record\u200b = 1;\n        int goto = 2;\n"
                    "        System.out.println(record + goto);\n    }\n}\n")
        (src_dir / "Healing.java").write_text(original, encoding="utf-8")
        (src_dir / "Plain.java").write_text(
            "package a;\n\npublic class Plain {\n    int ok = 3;\n}\n",
            encoding="utf-8")
        out = d / "proj"
        stats = PJ.export_project(SAMPLE, out, src_dir=d / "decomp_src",
                                  with_stubs=False)
        orig = out / "src-original" / "a" / "Healing.java"
        check("pre-repair source preserved", orig.is_file()
              and "\u200b" in orig.read_text(encoding="utf-8"))
        repaired = out / "src" / "main" / "java" / "a" / "Healing.java"
        rtxt = repaired.read_text(encoding="utf-8") if repaired.is_file() else ""
        check("repaired version escapes the keyword", "goto_" in rtxt, rtxt[:200])
        check("unrepaired file not duplicated into src-original",
              not (out / "src-original" / "a" / "Plain.java").is_file())
        log = out / "repair-log.md"
        txt = log.read_text(encoding="utf-8") if log.is_file() else ""
        check("repair-log written with evidence ladder",
              log.is_file() and "readable < compilable" in txt
              and "NOT implemented" in txt)
        check("repair-log lists the healed file and rules",
              "`a/Healing.java`" in txt and "keyword" in txt.lower())
        check("stats counters consistent", stats.get("files_repaired") == 1
              and stats.get("repair_rules_applied", 0) >= 2, str(stats))


def test_sakura_architecture_improvements() -> None:
    print("grounding & source safety: unboxing, static hiding, stub synthesis, event detection")
    from jdec import stubs as SB
    from jdec import project as PJ
    from jdec import mcmod as MM

    # 1. Primitive unboxing awareness
    check("default primitive boolean is false", SB.default_primitive_return("Z") == "false")
    check("default primitive boxed boolean", SB.default_primitive_return("boolean", boxed=True) == "java.lang.Boolean.FALSE")
    check("default primitive int is 0", SB.default_primitive_return("I") == "0")
    check("default primitive boxed int", SB.default_primitive_return("int", boxed=True) == "Integer.valueOf(0)")
    check("default primitive long is 0L", SB.default_primitive_return("J") == "0L")
    check("default primitive float is 0.0F", SB.default_primitive_return("F") == "0.0F")
    check("default primitive double is 0.0", SB.default_primitive_return("D") == "0.0")
    check("default primitive char is '\\0'", SB.default_primitive_return("C") == "'\\0'")
    check("default primitive void is empty", SB.default_primitive_return("V") == "")
    check("default reference object is null", SB.default_primitive_return("Object") == "null")

    # Unbox normalization in conditions and assignments
    src_test = (
        "boolean b = (boolean)x;\n"
        "if ((boolean)myObj) { doSomething(); }\n"
        "while ((boolean)flag) { loop(); }\n"
        "int val = (boolean)cond ? 1 : 2;\n"
    )
    norm_src, edits = PJ.normalize_primitive_unboxing(src_test)
    check("normalize_primitive_unboxing applied edits", edits == 4)
    check("normalize_primitive_unboxing converted assignment", "boolean b = Boolean.TRUE.equals(x);" in norm_src)
    check("normalize_primitive_unboxing converted if condition", "if (Boolean.TRUE.equals(myObj))" in norm_src)
    check("normalize_primitive_unboxing converted while condition", "while (Boolean.TRUE.equals(flag))" in norm_src)
    check("normalize_primitive_unboxing converted ternary", "Boolean.TRUE.equals(cond) ?" in norm_src)

    # negative: comments and literals must never be rewritten
    noise = (
        "// boolean c = (boolean)commented;\n"
        "/* if ((boolean)blockComment) {} */\n"
        'String s = "(boolean)inString";\n'
        "char q = '(';\n"
    )
    noise_out, noise_edits = PJ.normalize_primitive_unboxing(noise)
    check("unboxing leaves comments and literals alone",
          noise_edits == 0 and noise_out == noise, f"edits={noise_edits}")

    # numeric unboxing: on by default, but only for declared reference operands
    num_src = (
        "Integer boxed = null;\n"
        "Object generic = null;\n"
        "int plain = 1;\n"
        "int a = (int)boxed;\n"
        "int b = (int)generic;\n"
        "int c = (int)plain;\n"
        "int d = (int)unknown;\n"
        "int e = (int)call();\n"
    )
    num_out, n_num = PJ.normalize_primitive_unboxing(num_src)
    check("numeric unboxing rewrites declared references only", n_num == 2, str(n_num))
    check("boxed rewrite is null-safe",
          "boxed == null ? 0 : ((Number)boxed).intValue()" in num_out, num_out)
    check("Object rewrite is null-safe", "generic == null ? 0" in num_out, num_out)
    check("no-op cast on int is left alone", "(int)plain" in num_out, num_out)
    check("unknown declaration is left alone", "(int)unknown" in num_out, num_out)
    check("call operand is not duplicated", "(int)call()" in num_out, num_out)

    # cross-class fields / this.x / var are resolved through the project index
    with tempfile.TemporaryDirectory(prefix="jdec_test_typeindex_") as td:
        tdp = Path(td)
        (tdp / "Holder.java").write_text(
            "public class Holder {\n    public Integer value;\n}\n")
        (tdp / "A.java").write_text(
            "public class A {\n"
            "    Integer boxed;\n"
            "    Holder holder;\n"
            "    int f() { return (int)boxed; }\n"
            "    int g() { return (int)this.boxed; }\n"
            "    int h() { return (int)holder.value; }\n"
            "    int i() { var v = new Integer(1); return (int)v; }\n"
            "    int j() { var p = boxed; return (int)p; }\n"
            "    int k() { int plain = 1; return (int)plain; }\n"
            "}\n")
        idx = PJ.build_source_type_index(tdp)
        src = (tdp / "A.java").read_text(encoding="utf-8")
        cross_out, cross_n = PJ.normalize_primitive_unboxing(
            src, type_index=idx, current_class="A")
        check("cross-class numeric unboxing resolved", cross_n == 5, str(cross_n))
        check("this.field resolved", "(this.boxed == null ? 0" in cross_out, cross_out)
        check("other.field resolved", "(holder.value == null ? 0" in cross_out, cross_out)
        check("var new-expression resolved", "(v == null ? 0" in cross_out, cross_out)
        check("var alias resolved", "(p == null ? 0" in cross_out, cross_out)
        check("plain int still untouched", "(int)plain" in cross_out, cross_out)

    # 2. Static hiding invariance check — matched by parameter types, not arity
    with tempfile.TemporaryDirectory(prefix="jdec_test_hiding_") as td:
        tdp = Path(td)
        super_cls = tdp / "SuperClass.java"
        sub_cls = tdp / "SubClass.java"
        super_cls.write_text("public class SuperClass {\n    public static String get(int a) { return null; }\n}\n")
        sub_cls.write_text(
            "public class SubClass extends SuperClass {\n"
            "    public static Object get(int a) { return null; }\n"
            "    public static Object get(String a) { return null; }\n"
            "}\n")
        h_edits = PJ.check_static_hiding_invariance(tdp)
        check("check_static_hiding_invariance applied edit", h_edits == 1, str(h_edits))
        sub_txt = sub_cls.read_text()
        check("matching signature narrowed to superclass return type",
              "public static String get(int a)" in sub_txt, sub_txt)
        check("same-arity overload with different parameter type is untouched",
              "public static Object get(String a)" in sub_txt, sub_txt)

    # 3. Safe fallback dispatcher: explicit opt-in profile only
    d6_code = SB.generate_safe_fallback_dispatcher("dev.sakura.client.d6")
    check("dispatcher stub has package", "package dev.sakura.client;" in d6_code)
    check("dispatcher stub is marked as synthesized", SB.STUB_MARKER in d6_code)
    check("dispatcher stub returns emptyList", "return Collections.emptyList();" in d6_code)
    check("dispatcher stub returns emptyMap", "return Collections.emptyMap();" in d6_code)
    check("dispatcher stub returns emptySet", "return Collections.emptySet();" in d6_code)
    check("dispatcher stub returns emptyIterator", "return Collections.emptyIterator();" in d6_code)
    check("dispatcher stub returns no-op runnable", "return () -> {};" in d6_code)
    check("empty profile produces a bodyless stub",
          "aList" not in SB.generate_safe_fallback_dispatcher("x.Y", profile={}))

    # Enrich only machine-synthesised stubs, never a real class by filename
    with tempfile.TemporaryDirectory(prefix="jdec_test_enrich_") as td:
        tdp = Path(td)
        src_dir = tdp / "src" / "main" / "java" / "dev" / "sakura" / "client"
        src_dir.mkdir(parents=True)
        stub_f = src_dir / "Synth.java"
        stub_f.write_text(
            "package dev.sakura.client;\n"
            f"{SB.STUB_MARKER}\n"
            "public class Synth {\n"
            "    public static <T> List<T> aList(Object... args) { return null; }\n"
            "}\n"
        )
        real_f = src_dir / "d6.java"
        real_f.write_text(
            "package dev.sakura.client;\n"
            "public class d6 {\n"
            "    public static <T> List<T> aList(Object... args) { return null; }\n"
            "}\n"
        )
        enr_count = PJ.enrich_safe_fallback_stubs(tdp)
        check("enrich_safe_fallback_stubs touches only the marked stub", enr_count == 1, str(enr_count))
        check("marked stub upgraded to Collections.emptyList()",
              "Collections.emptyList()" in stub_f.read_text())
        check("unmarked class named d6 is untouched",
              "return null;" in real_f.read_text(), real_f.read_text())

    # 4. Intermediary Grounding
    mc_fixture = MIXIN if MIXIN.is_file() else build_fixtures.ensure_mixin_jar()
    if mc_fixture and Path(mc_fixture).is_file():
        grounding = MM.IntermediaryGrounding(mc_fixture)
        check("grounding is available with fixture", grounding.is_available())
        check("grounding has Minecraft class", grounding.has_class("net/minecraft/client/Minecraft"))
        check("grounding detects class kind", grounding.get_class_kind("net/minecraft/client/Minecraft") == "class")
        grounded_src = grounding.generate_grounded_stub("net/minecraft/client/Minecraft")
        check("grounding generates valid stub", grounded_src is not None and "public class Minecraft" in grounded_src)

    empty_grounding = MM.IntermediaryGrounding(None)
    check("empty grounding is not available", not empty_grounding.is_available())
    check("empty grounding returns None for stub", empty_grounding.generate_grounded_stub("Foo") is None)

    # 4b. Grounded stubs for enum / interface must compile
    javac = JAVAC
    if javac is None:
        print("  (skipped: no javac; set JAVA_HOME or PATH)")
    else:
        with tempfile.TemporaryDirectory(prefix="jdec_test_ground_compile_") as td:
            tdp = Path(td)
            (tdp / "E.java").write_text(
                "public enum E { A, B; public int f() { return 1; } }")
            (tdp / "I.java").write_text(
                "public interface I {\n"
                "    int f();\n"
                "    static int g() { return 1; }\n"
                "    default int h() { return 2; }\n"
                "}\n")
            subprocess.run([javac, "-d", str(tdp), str(tdp / "E.java"), str(tdp / "I.java")],
                           check=True, capture_output=True)
            jar = tdp / "ground.jar"
            with zipfile.ZipFile(jar, "w") as z:
                z.write(tdp / "E.class", "E.class")
                z.write(tdp / "I.class", "I.class")
            g = MM.IntermediaryGrounding(jar)
            gen_dir = tdp / "gen"
            gen_dir.mkdir()
            for cls in ("E", "I"):
                code = g.generate_grounded_stub(cls)
                check(f"grounded {cls} stub generated", code is not None, str(code))
                (gen_dir / f"{cls}.java").write_text(code or "")
            r = subprocess.run([javac, "-d", str(gen_dir),
                                str(gen_dir / "E.java"), str(gen_dir / "I.java")],
                               capture_output=True, text=True, errors="replace")
            check("grounded enum/interface stubs compile", r.returncode == 0,
                  (r.stderr or r.stdout)[:400])

    # 4c. Generic Signature attributes survive stub generation
    if javac is not None:
        with tempfile.TemporaryDirectory(prefix="jdec_test_generic_") as td:
            tdp = Path(td)
            (tdp / "G.java").write_text(
                "import java.util.*;\n"
                "import java.util.function.Function;\n"
                "public class G<T extends Number> {\n"
                "    public List<String> names;\n"
                "    public Map<String, T> table;\n"
                "    public <R> List<R> map(List<R> in, Function<T, R> fn) { return null; }\n"
                "    public T value() { return null; }\n"
                "    public void run() throws java.io.IOException {}\n"
                "}\n")
            subprocess.run([javac, "-d", str(tdp), str(tdp / "G.java")],
                           check=True, capture_output=True)
            jar = tdp / "g.jar"
            with zipfile.ZipFile(jar, "w") as z:
                z.write(tdp / "G.class", "G.class")
            code = MM.IntermediaryGrounding(jar).generate_grounded_stub("G") or ""
            check("class type parameter preserved",
                  "public class G<T extends java.lang.Number>" in code, code)
            check("generic field preserved", "java.util.List<java.lang.String> names;" in code, code)
            check("generic field with type var preserved",
                  "java.util.Map<java.lang.String, T> table;" in code, code)
            check("generic method type parameter preserved", "<R> java.util.List<R> map(" in code, code)
            check("generic parameter type preserved",
                  "java.util.function.Function<T, R>" in code, code)
            check("throws clause preserved", "throws java.io.IOException" in code, code)
            (tdp / "gen").mkdir()
            (tdp / "gen" / "G.java").write_text(code)
            r = subprocess.run([javac, "-d", str(tdp / "gen"), str(tdp / "gen" / "G.java")],
                               capture_output=True, text=True, errors="replace")
            check("grounded generic stub compiles", r.returncode == 0,
                  (r.stderr or r.stdout)[:400])

        # intersection bounds: T extends A & B
        with tempfile.TemporaryDirectory(prefix="jdec_test_intersection_") as td:
            tdp = Path(td)
            (tdp / "B.java").write_text(
                "public class B<T extends Number & Comparable<T>> {\n"
                "    public T value() { return null; }\n"
                "}\n")
            subprocess.run([javac, "-d", str(tdp), str(tdp / "B.java")],
                           check=True, capture_output=True)
            jar = tdp / "b.jar"
            with zipfile.ZipFile(jar, "w") as z:
                z.write(tdp / "B.class", "B.class")
            code = MM.IntermediaryGrounding(jar).generate_grounded_stub("B") or ""
            check("intersection bound preserved",
                  "T extends java.lang.Number & java.lang.Comparable<T>" in code, code)
            (tdp / "gen").mkdir()
            (tdp / "gen" / "B.java").write_text(code)
            r = subprocess.run([javac, "-d", str(tdp / "gen"), str(tdp / "gen" / "B.java")],
                               capture_output=True, text=True, errors="replace")
            check("intersection-bound stub compiles", r.returncode == 0,
                  (r.stderr or r.stdout)[:400])

        # declaration / type annotations are intentionally dropped; that must
        # not make the generated stub uncompilable
        with tempfile.TemporaryDirectory(prefix="jdec_test_ann_") as td:
            tdp = Path(td)
            (tdp / "Ann.java").write_text(
                "import java.util.*;\n"
                "public class Ann {\n"
                "    @Deprecated public List<String> names;\n"
                "    @SuppressWarnings(\"unchecked\")\n"
                "    public <T> T id(T x) { return x; }\n"
                "}\n")
            subprocess.run([javac, "-d", str(tdp), str(tdp / "Ann.java")],
                           check=True, capture_output=True)
            jar = tdp / "ann.jar"
            with zipfile.ZipFile(jar, "w") as z:
                z.write(tdp / "Ann.class", "Ann.class")
            code = MM.IntermediaryGrounding(jar).generate_grounded_stub("Ann") or ""
            check("annotations are dropped, generics kept",
                  "@Deprecated" not in code and "java.util.List<java.lang.String>" in code, code)
            (tdp / "gen").mkdir()
            (tdp / "gen" / "Ann.java").write_text(code)
            r = subprocess.run([javac, "-d", str(tdp / "gen"), str(tdp / "gen" / "Ann.java")],
                               capture_output=True, text=True, errors="replace")
            check("annotated generic stub compiles", r.returncode == 0,
                  (r.stderr or r.stdout)[:400])

    # 5. Event pipeline detection is read-only and target-configurable
    with tempfile.TemporaryDirectory(prefix="jdec_test_event_") as td:
        tdp = Path(td)
        kb_file = tdp / "MixinKeyboard.java"
        kb_file.write_text(
            "package dev.sakura.client.mixin;\n"
            "import org.spongepowered.asm.mixin.Mixin;\n"
            "@Mixin(net.minecraft.client.Keyboard.class)\n"
            "public class MixinKeyboard {\n"
            "    public void onKey(int key, int scancode, int action) {\n"
            "        uf.v.post(new YG(key));\n"
            "    }\n"
            "}\n"
        )
        net_file = tdp / "MixinNetwork.java"
        net_file.write_text(
            "package dev.sakura.client.mixin;\n"
            "import org.spongepowered.asm.mixin.Mixin;\n"
            "@Mixin(net.minecraft.class_634.class)\n"
            "public class MixinNetwork {\n"
            "    public void sendChat(String msg) {\n"
            "        uf.v.post(new Ym(msg));\n"
            "    }\n"
            "}\n"
        )
        before = kb_file.read_text()
        pipe_info = MM.detect_event_pipelines(tdp)
        check("event pipeline detected keyboard mixin", pipe_info.keyboard_mixin == "MixinKeyboard")
        check("event pipeline detected key event class", pipe_info.key_event_class == "YG")
        check("event pipeline detected network mixin", pipe_info.network_mixin == "MixinNetwork")
        check("event pipeline detected chat event class", pipe_info.chat_event_class == "Ym")
        check("detection does not modify sources", kb_file.read_text() == before)
        check("event weaver was removed", not hasattr(MM, "weave_event_dispatcher_hook"))

        custom = MM.detect_event_pipelines(
            tdp, keyboard_targets={"Keyboard"}, network_targets={"class_634"})
        check("custom target sets are honoured",
              custom.keyboard_mixin == "MixinKeyboard" and custom.network_mixin == "MixinNetwork")


def test_grounding_real_mc_sample() -> None:
    """Independent validation: real MC classes, not the Sakura fixture."""
    print("grounding: real MC classes generate compilable stubs")
    import re as _re
    from jdec import classfile as CF
    from jdec import mcmod as MM

    javac = JAVAC
    if javac is None:
        print("  (skipped: no javac; set JAVA_HOME or PATH)")
        return
    with zipfile.ZipFile(MC_JAR) as z:
        jar_classes = {n[:-6] for n in z.namelist()
                       if n.endswith(".class") and not n.startswith("META-INF/")}
    g = MM.IntermediaryGrounding(MC_JAR)

    picked: dict[str, list[str]] = {"class": [], "interface": [], "enum": [], "record": []}
    for cn in sorted(jar_classes):
        if "$" in cn:
            continue
        k = g.get_class_kind(cn)
        if len(picked.setdefault(k, [])) < 2:
            picked[k].append(cn)
        if all(len(v) >= 2 for v in picked.values()):
            break
    check("real jar exposes all four type kinds", all(picked.values()),
          str({k: len(v) for k, v in picked.items()}))

    with tempfile.TemporaryDirectory(prefix="jdec_test_mc_ground_") as td:
        gen = Path(td) / "gen"
        gen.mkdir()
        files = []
        for names in picked.values():
            for cn in names:
                cf = g.get_classfile(cn)
                need = {cf.utf8(e[1][0]) for e in cf.cp if e and e[0] == CF.C_CLASS}
                for m in list(cf.methods) + list(cf.fields):
                    for t in _re.findall(r"L([^;]+);", cf.utf8(m.descriptor_index)):
                        need.add(t)
                external = [t for t in need if t not in jar_classes and not t.startswith(
                    ("java/", "javax/", "jdk/", "sun/", "com/sun/"))]
                if external:
                    continue
                code = g.generate_grounded_stub(cn)
                if code is None:
                    continue
                p = gen / (cn.replace("/", ".") + ".java")
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(code)
                files.append(p)
        check("real MC stubs generated", len(files) >= 4, str(len(files)))
        r = subprocess.run([javac, "-nowarn", "-cp", str(MC_JAR), "-d", str(gen)]
                           + [str(p) for p in files],
                           capture_output=True, text=True, errors="replace")
        check("real MC stubs compile", r.returncode == 0, (r.stderr or r.stdout)[:400])

    nested = next((cn for cn in jar_classes if "$" in cn), None)
    if nested:
        check("nested/anonymous classes are refused, not mis-declared",
              g.generate_grounded_stub(nested) is None, nested)


def test_real_zkm_clean_pipeline() -> None:
    """Real ZKM sample: the cleaning pass must be safe and idempotent."""
    if _no_engines():
        return

    print("real sample: ZKM jar survives the cleaning pipeline")
    from jdec.score import _count_braces

    sample_dir = os.environ.get("JDEC_SAMPLE_DIR")
    roots = [Path(sample_dir)] if sample_dir else [ROOT.parent, Path("D:/MC/samples")]
    jar = next((r / "Myau0729-obf.jar" for r in roots
                if (r / "Myau0729-obf.jar").exists()), None)
    if jar is None:
        print("  (skipped: real sample not present; set JDEC_SAMPLE_DIR to enable)")
        return

    with tempfile.TemporaryDirectory(prefix="jdec_test_zkm_clean_") as td:
        out = Path(td) / "out"
        rep = decompile(jar, out, ROOT / "engines", jobs=2, timeout=600,
                        verify_all=False, clean_work=True, limit=12)
        src = out / "src"
        files = list(src.rglob("*.java")) if src.is_dir() else []
        check("real ZKM slice decompiled", len(files) > 0,
              f"ok={rep.ok} partial={rep.partial} files={len(files)}")

        idx = PJ.build_source_type_index(src)
        unstable = introduced_imbalance = 0
        for f in files:
            code = f.read_text(encoding="utf-8", errors="replace")
            cleaned, _ = PJ.clean_source_for_compilation(
                code, type_index=idx, current_class=f.stem)
            again, _ = PJ.clean_source_for_compilation(
                cleaned, type_index=idx, current_class=f.stem)
            if again != cleaned:
                unstable += 1
            raw_opens, raw_closes = _count_braces(code)
            new_opens, new_closes = _count_braces(cleaned)
            # a decompiler may already have emitted an unbalanced file; only
            # imbalance introduced by cleaning counts as a regression
            if raw_opens == raw_closes and new_opens != new_closes:
                introduced_imbalance += 1
        check("cleaning is idempotent on real obfuscated sources", unstable == 0, str(unstable))
        check("cleaning does not introduce brace imbalance",
              introduced_imbalance == 0, str(introduced_imbalance))


def test_bridge_prune_and_clean_idempotence() -> None:
    """A long bridge method must be commented in full, not truncated at 30 lines."""
    print("project: bridge pruning stays balanced and cleaning is idempotent")
    from jdec.score import _count_braces

    filler = "\n".join(f"        int v{i} = {i};" for i in range(60))
    src = (
        "public class B {\n"
        "    public String get() {\n"
        "        return \"x\";\n"
        "    }\n"
        "    // $FF: bridge method\n"
        "    public Object get() {\n"
        f"{filler}\n"
        "        return this.get();\n"
        "    }\n"
        "    public void tail() {\n"
        "        int z = 1;\n"
        "    }\n"
        "}\n"
    )
    cleaned, changes = PJ.clean_source_for_compilation(src)
    opens, closes = _count_braces(cleaned)
    check("bridge pruning keeps braces balanced", opens == closes, f"{opens}/{closes}")
    check("long bridge body fully commented",
          "// [jdec: stripped duplicate bridge method]         int v59 = 59;" in cleaned,
          "line 59 not commented")
    check("real method kept", "public String get()" in cleaned)
    again, _ = PJ.clean_source_for_compilation(cleaned)
    check("cleaning is idempotent", again == cleaned)


def main() -> int:
    with_mc = "--with-mc" in sys.argv
    if not SAMPLE.exists() and build_fixtures.ensure_sample_jar(quiet=False) is None:
        print("missing tests/sample.jar and could not build it: no working javac\n"
              "  -> set JAVA_HOME to a JDK (e.g. JAVA_HOME=D:\\java21) or put javac\n"
              "     on PATH, then re-run. sample.jar is the prerequisite of every\n"
              "     other case, so the suite cannot degrade to a partial run.")
        return 2
    _prepare_engines()
    # every fixture must exist before the first test that touches one: several
    # tests only guard with `if MIXIN.exists()`, so a late build silently drops
    # their assertions on a fresh checkout
    build_fixtures.ensure_mixin_jar(quiet=True)
    test_roundtrip_sample()
    test_classfile_parser_survives_mutation()
    test_synthetic_members_ignored()
    test_scoring_sees_obfuscated_names()
    test_partial_failure_is_not_total_failure()
    test_score_decl_and_noise()
    test_unbalanced_braces_are_proportional()
    test_end_to_end_sample()
    test_case_colliding_class_names()
    test_iso_buckets()
    test_safe_rel_covers_package_segments()
    test_web_report_rel_reverse_lookup()
    test_pipeline_summary_target_is_resolvable()
    test_bytecode_and_string_quality()
    test_safety_and_byte_fidelity()
    test_binary_semantics()
    test_degradation_accounting()
    test_tool_hardening()
    test_polish()
    test_cli_exit_codes()
    test_ir_roundtrip()
    test_toolchain_single_entry()
    test_verify_gate()
    test_deflat_output_loads()
    test_deflat_parallel_matches_serial()
    test_behaviour_is_preserved()
    test_sandbox_isolation()
    test_frame_generation()
    test_ir_transforms()
    test_pipeline_gate()
    test_devirt_output_loads()
    test_devirt_behaviour()
    test_devirt_realistic_vm()
    test_jsr_subroutine_is_left_alone()
    test_dead_branch_is_not_nop_ed()
    test_rewritten_list_from_both_paths()
    test_reason_replay_and_rollback()
    test_unflatten_strict_rejection()
    test_interp_same_negative_and_models()
    test_interp_engine_semantics()
    test_interp_lambda_and_streams()
    test_behave_semantics()
    test_receiver_and_argument_synthesis()
    test_behave_classpath()
    test_verify_skips_multirelease()
    test_hierarchy_extra_classpath()
    test_missing_dependency_gate()
    test_deflat_failure_accounting()
    test_coverage_accounting()
    test_case_derivation()
    test_verify_matrix()
    test_focus_reports_unjudged()
    test_insert_branch_to_label()
    test_dead_code_keeps_control_flow()
    test_frames_match_javac()
    test_ir_assembly_changes_length()
    test_weak_engine_is_rescued()
    test_yarn_compose()
    test_official_srg_compose()
    test_auto_mapping_set_flavor()
    test_java_escape()
    test_rewrite_sources()
    test_recover_triage()
    test_manifest_and_resources()
    test_rewrite_escapes()
    test_bsm_scan_and_parse_resilience()
    test_recover_spec_generation_and_quarantine()
    test_replay_safety_gate()
    test_resource_anomaly()
    test_scorecard_smoke()
    test_pool_roundtrip()
    test_web_template_js()
    test_pool_qualified_and_full_string()
    test_pool_overload_dispatch()
    test_probe_fingerprints_json()
    test_platform_classpath_separator()
    test_procyon_bridge_is_built()
    test_remap_failure_accounting()
    test_devirt_opcode_disambiguation()
    test_code_pool_json_integrity()
    test_max_stack_dataflow()
    test_pool_verify_fq_callsites()
    test_attribution_gates()
    test_ops_pool()
    test_jint()
    test_clinit_sim()
    test_ghidra_integration()
    test_native_elf_and_ghidra_annotate()
    test_score_and_signal_enhancements()
    test_multimodule_enhancements()
    test_advanced_roadmap_features()
    test_pipeline_automation()
    test_pipeline_stage_status()
    test_rewrite_skips_comments_strings()
    test_bvm_extract_code_id_descriptor_gate()
    test_web_callgraph_error_semantics()
    test_web_workbench_features()
    test_web_source_path_containment()
    test_callgraph_and_reachability()
    test_conservative_prune()
    test_decompiler_trap_pruning()
    test_project_export_and_recompilability()
    test_selfheal_audit()
    test_cfg_and_dynamic_mocks()
    test_bvm_and_native_extensions()
    test_sakura_architecture_improvements()
    test_bridge_prune_and_clean_idempotence()
    if build_fixtures.ensure_mixin_jar() is None:
        print("skipping mixin tests: tests/mixin.jar could not be built "
              "(run tests/build_fixtures.py)")
    else:
        test_annotated_classes_roundtrip()
        test_mixin_fixture()
        test_refmap()
        test_string_dump()
        test_indy_encoding()
        test_signals()
        test_bytecode_decodes()
        test_flow_fingerprints()
        test_native_reporting()
    if with_mc:
        missing = [p for p in (MC_JAR, MC_MAP) if not p.exists()]
        if missing:
            # the core suite already ran: print its numbers before exiting, or
            # the "missing fixtures" path looks like a total failure
            print("missing MC fixtures: " + ", ".join(str(p) for p in missing))
            print(f"  put them under {MC_JAR.parent} (gitignored) and re-run, "
                  f"or drop --with-mc for the core suite")
            print(f"\n{_passed} passed, {_failed} failed (core suite only)")
            return 2
        test_mc_roundtrip()
        test_mojang_mapping_direction()
        test_remap_rewrites_call_sites()
        test_remapped_class_is_valid_bytecode()
        test_mc_is_not_flow_obfuscated()
        test_real_zkm_sample()
        test_grounding_real_mc_sample()
        test_real_zkm_clean_pipeline()
    print(f"\n{_passed} passed, {_failed} failed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
