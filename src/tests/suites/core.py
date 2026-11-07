"""Decompile pipeline, scoring, output layout and CLI exit codes.

The first block: every later suite assumes the fixture jars and a working
engine cache, which `main` prepares before this module runs."""

from __future__ import annotations

import re

from harness import (  # noqa: F401
    AN, BC, BROKEN_SAMPLE, CF, CG, CL, DV, ENGINES_DIR, JAVAC, MM, PIPE, PL,
    Path, RC, ROOT, SAMPLE, SCORE, ST, SimpleNamespace, _iso_buckets,
    _no_engines, _synthetic_pe, check, decompile, ensure_collide_jar,
    evaluate, json, profile_jar, struct, subprocess, tempfile, urllib,
    write_report, zipfile,
)


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

    # (f) annotation members with `default` values are declarations too
    ann = ("public @interface A {\n"
           "    int x() default 0;\n"
           '    String s() default "x";\n'
           "    int[] a() default {};\n"
           "    int plain();\n"
           "}\n")
    ann_counts = SCORE._decl_counts(ann)
    check("annotation members with defaults count as declarations",
          all(ann_counts.get(n) == 1 for n in ("x", "s", "a", "plain")),
          str(ann_counts))
    # (g) type-use annotations sit between modifiers and the return type
    type_use = SCORE._decl_counts(
        "protected @Nullable String handleArgumentType(String x) { return x; }\n"
        "public @Range(from=0L, to=255L) int red();\n"
        "public @Nullable Item item;\n")
    check("type-use annotations still count as declarations",
          type_use.get("handleArgumentType") == 1 and type_use.get("red") == 1
          and type_use.get("item") == 1, str(type_use))
    # (h) enum constants with anonymous bodies
    enum_counts = SCORE._decl_counts(
        "public enum E {\n    A { void f() {} },\n    B(1),\n"
        "    @Deprecated C;\n    void g() {}\n}\n")
    check("enum constants with bodies count",
          all(enum_counts.get(n, 0) >= 1 for n in ("A", "B", "C")),
          str(enum_counts))

    # (e) positive control: real declarations still hit
    decls = ("public class Showcase {\n"
             + "\n".join(f"    public int {m}() {{ return 1; }}" for m in members)
             + "\n}\n")
    q4 = evaluate(decls, cf)
    check("true declarations still hit", q4.coverage >= 0.9, f"coverage={q4.coverage}")


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


def test_end_to_end_sample() -> None:
    if _no_engines():
        return

    print("pipeline: end to end on the sample jar")
    out = Path(tempfile.mkdtemp()) / "out"
    rep = decompile(SAMPLE, out, ENGINES_DIR, jobs=2, verify_all=True)
    check("every readable class comes out clean",
          rep.ok >= 10, f"ok={rep.ok} partial={rep.partial} failed={rep.failed}")
    check("the truncated class is quarantined, not fatal",
          any(o.status == "broken" for o in rep.outcomes.values()),
          str(sorted({o.status for o in rep.outcomes.values()})))
    check("member recovery is complete",
          (rep.coverage_avg or 0) >= 0.99, f"coverage={rep.coverage_avg}")


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
    rep = decompile(collide, out, ENGINES_DIR, jobs=2, verify_all=True)

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



def test_readme_doc_links() -> None:
    """The overview must actually lead a reader to the long manual and roadmap.

    The root README is what both GitHub and PyPI render, so its links are the
    only path to `docs/`. They once used `blob/main` while the default branch
    was `master`: all five links 404'd and the documents looked absent even
    though they were committed. `HEAD` follows the default branch, so renaming
    it cannot break them again. This check is offline and needs no network.
    """
    print("readme: docs links resolve")
    repo = ROOT.parent
    text = (repo / "README.md").read_text(encoding="utf-8")
    links = re.findall(
        r"https://github\.com/spiderf5/Jdec/blob/([^/]+)/([^\s)]+)", text)
    check("the overview links into docs/", len(links) >= 5, str(len(links)))
    bad_ref = sorted({ref for ref, _ in links if ref != "HEAD"})
    check("docs links follow the default branch via HEAD",
          not bad_ref, ", ".join(bad_ref))
    missing = [rel for _, rel in links if not (repo / rel).is_file()]
    check("every linked document is committed", not missing,
          ", ".join(missing))
