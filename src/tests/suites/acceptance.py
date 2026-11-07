"""The 04 layers: support matrix, acceptance harness, indy payloads,
probe phases and native-library facts."""

from __future__ import annotations

from harness import (  # noqa: F401
    CF, CL, Path, ROOT, ST, check, json, tempfile, zipfile,
)


def test_support_matrix_per_corpus_gate() -> None:
    """One corpus with a zero must not be hidden by another corpus's count."""
    print("support matrix: per-corpus rules and report hygiene")
    import io
    import contextlib
    import support_matrix as SM

    spec = SM.MECHANISMS[0]
    original = SM._capture
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        a, b = root / "a.bin", root / "b.bin"
        a.write_bytes(b"MZ" + b"x" * 100)
        b.write_bytes(b"PK" + b"x" * 100)

        calls = {"n": 0}

        def one_corpus_is_zero(argv):
            calls["n"] += 1
            n = "411" if calls["n"] == 1 else "0"
            return 0, (f"deflat     : {n} method(s) rewritten\n"
                       "verify     : 3693 class(es) pass\n")

        SM._capture = one_corpus_is_zero
        try:
            bad = SM.run_mechanism(spec, {"hmcl": a, "neo": b}, root, [])
        finally:
            SM._capture = original
        check("a zero on one corpus fails the mechanism",
              bad["verdict"] == "FAIL", bad["verdict"])
        check("the per-corpus numbers are both recorded",
              bad["per_corpus"]["hmcl"]["metrics"]["rewritten"] == 411
              and bad["per_corpus"]["neo"]["metrics"]["rewritten"] == 0,
              str(bad["per_corpus"]))
        check("the aggregate report number is unchanged",
              bad["metrics"]["rewritten"] == 411, str(bad["metrics"]))
        check("rules are evaluated once", len(bad["rules"]) == len(spec.rules))

        out = root / "nested" / "selfcheck.json"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = SM.main(["--selfcheck", "--json", str(out)])
        check("--selfcheck --json creates its parent", out.is_file() and rc == 0,
              str(rc))
        data = json.loads(out.read_text(encoding="utf-8"))
        check("the selfcheck report declares its scope",
              data["stage_04_threshold_met"] is False)

    check("pair_equal without a slash is rejected",
          SM.Rule("pair_equal", "nonsense").holds({}, [0]) is False)
    check("contains with an empty needle is rejected",
          SM.Rule("contains", "x", equals="").holds({"x": "anything"}, [0])
          is False)
    check("min against a text value is rejected",
          SM.Rule("min", "x", 1).holds({"x": "411"}, [0]) is False)
    check("all_zero_rc on an empty result is False",
          SM.Rule("all_zero_rc").holds({}, []) is False)

    # ROOT here is src/, while support_matrix.ROOT is the repository root.
    # Only the acceptance report is versioned. The diagnostic report was
    # committed twice and went stale both times: it is evidence for whatever
    # code state produced it, so it is written on demand instead.
    committed = SM.ROOT / "docs" / "SUPPORT_MATRIX_REPORT.json"
    check("the diagnostic layer ships no committed report",
          not committed.is_file(), str(committed))
    check("the acceptance report is the one under version control",
          (SM.ROOT / "docs" / "STAGE04_REPORT.json").is_file())


def test_benchmark_report_hygiene() -> None:
    """The committed benchmark report must not leak local paths."""
    print("benchmark: report hygiene and argument validation")
    import io
    import contextlib
    import benchmark as BM

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        out = root / "report.json"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = BM.main(["--json", str(out)])
        check("the builtin benchmark still passes", rc == 0, str(rc))
        data = json.loads(out.read_text(encoding="utf-8"))
        blob = json.dumps(data, ensure_ascii=False)
        check("no local absolute path leaks into the report",
              not any(n in blob for n in ("AppData", "Users", "D:/MC")),
              data["comparison"]["command"][:120])
        check("the command still records the gate",
              "--engine both" in data["comparison"]["command"])
        check("classpath entries are basenames",
              all("/" not in c and "\\" not in c
                  for c in data["classpath"]), str(data["classpath"]))
        check("the report uses LF endings", b"\r" not in out.read_bytes())
        check("builtin mode reports a real negative control",
              data["negative_control_detected"] is True)

        # External mode: the control is explicitly marked as skipped.
        rows = root / "rows.tsv"
        rows.write_text("a/A\tm\t(I)V\n", encoding="utf-8")
        ext = root / "ext.json"
        with contextlib.redirect_stdout(io.StringIO()):
            BM.main(["--original", str(root / "a.jar"), "--from", str(rows),
                     "--json", str(ext)])
        if ext.is_file():
            d = json.loads(ext.read_text(encoding="utf-8"))
            check("external mode marks its negative control as skipped",
                  d["negative_control"] is None
                  and d["negative_control_detected"] is None
                  and "skipped" in d["negative_control_note"],
                  str(d.get("negative_control_detected")))

    # A half-specified external recipe must not silently run the builtin one.
    buf = io.StringIO()
    try:
        with contextlib.redirect_stderr(buf):
            BM.main(["--rewritten", "x.jar"])
        check("half-specified external mode is rejected", False, "no error")
    except SystemExit as exc:
        check("half-specified external mode is rejected", exc.code == 2,
              str(exc.code))


def test_stage04_acceptance_harness() -> None:
    """The 04 acceptance layer: independent goldens and per-mechanism controls."""
    print("stage 04: acceptance evidence and corrected fingerprints")
    import io
    import inspect
    import contextlib
    import goldens as G
    import stage04 as S
    from jdec import strings as ST

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = S.selfcheck()
    check("the acceptance selfcheck passes", rc == 0, buf.getvalue()[:200])
    check("eight mechanism acceptance specs are registered",
          len(S.SPECS) == 8, str(len(S.SPECS)))
    check("every spec declares support, boundary and its own negative control",
          all(x["support"] and x["not_covered"] and x["negative"]
              for x in S.SPECS))

    flow = ROOT / "tests" / "flow.jar"   # ROOT here is src/
    check("the independent class reader parses method names",
          "dispatch" in G.methods_of(flow, "demo/flow/GotoFlood"))
    check("independent class count matches the zip directory",
          G.jar_facts(flow)["class_count"] == G.zip_facts(flow)["class_count"])
    check("an internal class name is not an encrypted blob",
          "encrypted-blob" not in ST.classify(
              "org/spongepowered/asm/lib/tree/AbstractInsnNode"))

    # Two fingerprints were producing false positives on real corpora.
    fp = json.loads((ROOT.parent / "src/jdec/fingerprints.json")
                    .read_text(encoding="utf-8"))
    zkm = next(x for x in fp["obfuscators"]
               if x["name"] == "ZKM 27 enhanced 字符串加密（DES）")
    sentinel = next(x for x in fp["obfuscators"] if x["name"] == "Sentinel")
    check("ZKM 27 needs two exclusive markers",
          zkm.get("min_keywords", 1) >= 2
          and all("ivparameterspec" not in k.lower() for k in zkm["keywords"]))
    check("Sentinel is research-only, never an automatic attribution",
          sentinel.get("auto_attribute") is False)
    twin = (ROOT.parent / "java-deobf/scripts/fingerprints.json").read_bytes()
    check("the skill fingerprint twin is byte-identical",
          twin == (ROOT.parent / "src/jdec/fingerprints.json").read_bytes())

    # The two control-flow shapes must stay separated. Without a fixture for
    # each direction the pass silently treated javac output as obfuscation.
    import zipfile as _zf
    from jdec import bytecode as _BC
    from jdec import classfile as _CF
    from jdec.ir import assemble as _ASM
    from jdec.ir import transforms as _TR

    def _kinds_of(cls_name: str, method: str) -> dict:
        with _zf.ZipFile(ROOT / "tests" / "shapes.jar") as z:
            cf = _CF.parse(z.read(cls_name + ".class"))
        member = next(x for x in cf.methods
                      if cf.utf8(x.name_index) == method)
        code = _BC.method_code(cf, member, decode_insns=False)
        prog = _ASM.Program.parse(code.code, code.handlers)
        return _TR.optimize(prog, cf)

    flat = _kinds_of("demo/shapes/Flattened", "run")
    ssw = _kinds_of("demo/shapes/StringSwitch", "pick")
    check("a real flattened dispatcher is classified as unflatten",
          flat.get("unflattened", 0) > 0 and flat.get("switch", 0) == 0, str(flat))
    check("a javac switch(String) is classified as switch",
          ssw.get("switch", 0) > 0 and ssw.get("unflattened", 0) == 0, str(ssw))

    report = ROOT.parent / "docs" / "STAGE04_REPORT.json"
    if report.is_file():
        data = json.loads(report.read_text(encoding="utf-8"))
        check("the committed acceptance report matches the registry",
              data["total"] == len(S.SPECS)
              and [m["id"] for m in data["mechanisms"]]
              == [x["id"] for x in S.SPECS], str(data.get("total")))
        check("every mechanism passed its cross-checks",
              all(m["verdict"] == "PASS" for m in data["mechanisms"]),
              str([m["id"] for m in data["mechanisms"]
                   if m["verdict"] != "PASS"]))
        check("every mechanism has golden facts and its own negative metrics",
              all(m["golden"] and "negative_metrics" in m
                  for m in data["mechanisms"]))
        check("the negative corpus is publicly reproducible",
              "junit:junit:4.13.2" in str(data["corpus_sources"]))
        check("the runner reports facts without certifying the threshold",
              data.get("stage_04_threshold_decision")
              == "recorded in docs/ROADMAP.md"
              and data.get("mechanism_regressions_pass") is True
              and len(data.get("boundaries", [])) >= 3,
              str(data.get("boundaries"))[:200])
        check("every check is classified and the counts add up",
              data.get("check_breakdown", {}).get("a", 0) > 0
              and sum(data["check_breakdown"].values())
              == sum(len(m["checks"]) for m in data["mechanisms"]),
              str(data.get("check_breakdown")))
        check("the check registry covers exactly the eight specs",
              set(S._CHECKS) == {x["id"] for x in S.SPECS}
              and all(callable(fn) for fn in S._CHECKS.values()),
              str(sorted(S._CHECKS)))
        check("_checks is a dispatcher, not a monolith",
              len(inspect.getsource(S._checks).splitlines()) < 45,
              f"{len(inspect.getsource(S._checks).splitlines())} lines")
        m3 = next(m for m in data["mechanisms"] if m["id"] == "M3")
        check("M3 accounts for every indy site",
              m3["metrics"].get("lambda", 0) + m3["metrics"].get("concat", 0)
              + m3["metrics"].get("record", 0)
              + m3["metrics"].get("unresolved", -1)
              == m3["metrics"].get("sites", -2) > 0,
              str(m3["metrics"]))
        check("M3 recovered a payload for every site on this corpus",
              m3["metrics"].get("payload") == m3["metrics"].get("sites")
              and m3["metrics"].get("unresolved") == 0, str(m3["metrics"]))
        m1 = next(m for m in data["mechanisms"] if m["id"] == "M1")
        check("M1 records that folding and opaque predicates did not fire",
              m1["metrics"].get("folded") == 0
              and m1["metrics"].get("predicates") == 0,
              str(m1["metrics"]))
        check("M1 separates javac switch from obfuscator flattening",
              m1["metrics"].get("switch", 0) > 0
              and m1["metrics"].get("unflatten_methods") == 0,
              str(m1["metrics"]))


def test_indy_payload_resolution() -> None:
    """Every bootstrap payload must be recovered, counted, or reported absent."""
    print("indy: bootstrap payloads are recovered against the constant pool")
    import io
    import re
    import contextlib
    import goldens as G
    from jdec import bsm as BM
    from jdec import cli as CL

    jar = ROOT / "tests" / "sample.jar"   # ROOT here is src/
    golden = G.bsm_facts(jar)
    check("the independent parser sees the bootstrap entries",
          golden["entries"] > 0
          and golden["entries"] == sum(golden["owners"].values()),
          f"entries={golden['entries']} owners={golden['owners']}")
    check("the independent parser collects static payloads",
          "x;y" in golden["payloads"] and "p\x01:\x01" in golden["payloads"],
          str(golden["payloads"]))
    vanilla = {"java/lang/invoke/LambdaMetafactory",
               "java/lang/invoke/StringConcatFactory",
               "java/lang/runtime/ObjectMethods"}
    check("the independent parser resolves every vanilla owner it found",
          vanilla <= set(golden["owners"]), str(golden["owners"]))

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = CL.main(["indy", str(jar), "--resolve"])
    text = buf.getvalue()
    check("indy --resolve exits 0", rc == 0, str(rc))

    def grab(label: str) -> int:
        m = re.search(rf"(?m)^{label}\s+: (\d+)", text)
        return int(m.group(1)) if m else -1

    sites = grab("indy sites")
    payload = grab("payload recovered")
    unresolved = grab("unresolved")
    kinds = grab("lambda targets") + grab("concat templates") + grab(
        "record components")
    check("the four counts partition the sites",
          sites > 0 and kinds + unresolved == sites and payload == kinds,
          f"sites={sites} payload={payload} kinds={kinds} "
          f"unresolved={unresolved}")
    # A bootstrap with no readable constant (SwitchBootstraps, only emitted by
    # a javac new enough to lower pattern switches) must be counted as
    # unresolved rather than guessed. Absent that lowering there is nothing to
    # leave unresolved, so the assertion follows the fixture.
    if "java/lang/runtime/SwitchBootstraps" in golden["owners"]:
        check("a bootstrap without constants is reported, not guessed",
              unresolved == 1, f"unresolved={unresolved}")
    else:
        check("nothing is unresolved when every bootstrap carries a constant",
              unresolved == 0, f"unresolved={unresolved}")
    check("the owner histogram reaches stdout",
          all(f"{owner}=" in text for owner in golden["owners"]),
          text[-220:])

    # Value level: every recovered string must exist in the constant pool.
    recovered: set[str] = set()
    import zipfile
    from jdec import classfile as CF
    with zipfile.ZipFile(jar) as z:
        for info in z.infolist():
            if not info.filename.endswith(".class"):
                continue
            try:
                cf = CF.parse(z.read(info))
            except Exception:      # noqa: BLE001 - sample.jar ships a truncated class
                continue
            for site in BM.enum_sites(cf):
                concat = BM.resolve_concat(site)
                if concat:
                    recovered.add(concat["recipe"])
                record = BM.resolve_record(site)
                if record:
                    recovered.add(";".join(record["components"]))
    check("every recovered payload is a real constant-pool string",
          bool(recovered) and recovered <= set(golden["payloads"]),
          f"{len(recovered)} recovered, "
          f"{sorted(recovered - set(golden['payloads']))[:2]} invented")

    # Unit level: the three recipe shapes, including the defensive branches.
    def concat_site(recipe: str, consts: list[str]) -> BM.IndySite:
        return BM.IndySite(
            cls="a/B", method="m", name="makeConcatWithConstants",
            desc="(ILjava/lang/String;)Ljava/lang/String;",
            bsm=BM.BsmEntry(index=0, kind=6, owner=BM.CONCAT_OWNER,
                            name="makeConcatWithConstants", desc="()V",
                            args=[("lit", recipe)] + [("lit", c) for c in consts]))

    out = BM.resolve_concat(concat_site("id=\x01, n=\x02", ["x"]))
    check("a concat recipe becomes a readable template",
          out["template"] == "id={}, n={c}", out["template"])
    check("the concat constants are recovered", out["constant_parts"] == ["x"],
          str(out["constant_parts"]))
    check("the concat argument count is counted", out["arguments"] == 1,
          str(out["arguments"]))
    odd = BM.resolve_concat(concat_site("no placeholder", ["x"]))
    check("a constant with no \\u0002 placeholder is dropped, not invented",
          odd["constant_parts"] == [], str(odd["constant_parts"]))
    check("a non-concat owner is not treated as a concat",
          BM.resolve_concat(BM.IndySite(
              cls="a/B", method="m", name="n", desc="()V",
              bsm=BM.BsmEntry(index=0, kind=6, owner="custom/Boot",
                              name="b", desc="()V", args=[]))) is None)

    def record_site(names, getters=()) -> BM.IndySite:
        return BM.IndySite(
            cls="a/R", method="toString", name="toString", desc="()V",
            bsm=BM.BsmEntry(index=0, kind=6, owner=BM.RECORD_OWNER,
                            name="bootstrap", desc="()V",
                            args=[("cls", "a/R"), names] + list(getters)))

    rec = BM.resolve_record(record_site(("lit", "x;y"), [
        ("mh", {"kind": 1, "owner": "a/R", "name": "x", "desc": "I"})]))
    check("record component names are recovered", rec["components"] == ["x", "y"],
          str(rec["components"]))
    check("record getters keep their descriptors",
          rec["getters"] == [{"name": "x", "desc": "I"}], str(rec["getters"]))
    empty = BM.resolve_record(record_site(("lit", "")))
    check("a zero-component record resolves to an empty list",
          empty["components"] == [], str(empty))
    check("a dynamic component list is refused rather than emptied",
          BM.resolve_record(record_site(("?", None))) is None)
    check("resolve_site tags the lambda family",
          BM.resolve_site(concat_site("a\x01", []))["kind"] == "concat")


def test_probe_profile_phases() -> None:
    """The four extracted profile phases must keep their measured behaviour."""
    print("probe: container, minecraft, version, naming and attribution phases")
    from jdec import probe as PR

    sample = ROOT / "tests" / "sample.jar"   # ROOT here is src/
    prof = PR.profile_jar(sample)
    check("container facts are counted",
          prof.entries == 12 and prof.classes == 11 and prof.resources == 1,
          f"{prof.entries}/{prof.classes}/{prof.resources}")
    check("bytecode versions are grouped per release",
          len(prof.java_versions) == 1
          and sum(prof.java_versions.values()) == prof.classes
          and all(k.isdigit() for k in prof.java_versions),
          str(prof.java_versions))
    check("the name-shape score is computed, not defaulted",
          abs(prof.obfuscation - 42.4) < 0.05, str(prof.obfuscation))
    check("top packages are ranked by class count",
          prof.top_packages[:1] == [("demo/modern", 5)], str(prof.top_packages[:2]))
    check("structural fingerprints come from the sampler",
          "goto-flood" in prof.structural, str(prof.structural))
    check("a plain jar is not claimed to be Minecraft", prof.is_minecraft is False)

    # mixin.jar ships fabric.mod.json, which is the only marker that sets the
    # flavour for a mod jar (a mod does not shade the loader's own packages).
    mixin = PR.profile_jar(ROOT / "tests" / "mixin.jar")
    check("fabric.mod.json sets the Minecraft flavour",
          mixin.is_minecraft is True and mixin.mc_flavor == "Fabric",
          f"{mixin.is_minecraft}/{mixin.mc_flavor}")

    # A two-class jar gets a capped score and says so, rather than reporting
    # 100/100 off a median over two names.
    tiny = PR.profile_jar(ROOT / "tests" / "collide.jar")
    check("a tiny sample caps the score at 50 and explains why",
          tiny.obfuscation <= 50.0
          and any("small sample" in s for s in tiny.signatures),
          f"{tiny.obfuscation} {tiny.signatures}")

    check("the score helper returns 0 for an empty sample",
          PR._name_shape_score([], [], 0, 0) == 0.0)


def test_native_libs_and_rva() -> None:
    """JNI libraries in a separate artifact, and the RVA span that hid them."""
    print("natives: external `natives` artifact and section span")
    import io
    import contextlib
    import zipfile
    from jdec import native_scan as NS
    from jdec import cli as CL

    # The bug: the span was max(VirtualSize, 1 MiB), so an RVA in the second
    # section resolved against the first one. lwjgl64.dll reported 6218 bogus
    # exports instead of 2386 and JNI matching saw 53 names instead of 2383.
    sections = [(0x1000, 0x200, 0x400), (0x2000, 0x200, 0x600)]
    check("an RVA in the second section is not resolved against the first",
          NS._rva_to_offset(sections, 0x2100) == 0x700,
          str(NS._rva_to_offset(sections, 0x2100)))
    check("an RVA past every section resolves to nothing",
          NS._rva_to_offset(sections, 0x9000) is None)
    check("a zero VirtualSize keeps the generous fallback",
          NS._rva_to_offset([(0x1000, 0, 0x400)], 0x1500) == 0x900,
          str(NS._rva_to_offset([(0x1000, 0, 0x400)], 0x1500)))

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        jar = root / "app.jar"
        with zipfile.ZipFile(jar, "w") as z:
            z.writestr("a/B.class", b"\xca\xfe\xba\xbe" + b"\0" * 60)
        extra = root / "app-natives.jar"
        with zipfile.ZipFile(extra, "w") as z:
            z.writestr("native/x64/fake.dll", b"MZ" + b"\0" * 200)
            z.writestr("native/x86/fake.dll", b"MZ" + b"\0" * 200)

        out = root / "out"
        tri = NS.triage(jar, out)
        check("the main jar ships no library", tri.libs == [], str(tri.libs))
        NS.add_libs(tri, [extra], out)
        check("libraries from a separate artifact are added", len(tri.libs) == 2,
              str([lib.name for lib in tri.libs]))
        check("each library records the artifact it came from",
              {lib.source for lib in tri.libs} == {"app-natives.jar"},
              str([lib.source for lib in tri.libs]))
        check("two architectures with the same basename are both kept",
              len({lib.rel for lib in tri.libs}) == 2,
              str([lib.rel for lib in tri.libs]))
        check("a directory of raw libraries is accepted too",
              len(NS._external_libs([out], out)) == 2,
              str([p.name for p in out.iterdir()][:4]))

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = CL.main(["natives", str(jar), "-o", str(root / "cli"),
                          "--libs-jar", str(extra)])
        text = buf.getvalue()
        check("natives --libs-jar exits 0", rc == 0, str(rc))
        check("natives reports the external artifact",
              "external  : 2 lib(s) from 1 separate artifact(s)" in text,
              text[:300])

    ns = CL.build_parser().parse_args(
        ["natives", "a.jar", "--libs-jar", "n1.jar", "--libs-jar", "n2.jar",
         "--libs-dir", "libs"])
    check("--libs-jar is repeatable and --libs-dir parses",
          ns.libs_jar == ["n1.jar", "n2.jar"] and ns.libs_dir == "libs",
          str(ns))


def test_nativedb_bundle() -> None:
    """The native analysis bundle had no regression at all until now."""
    print("nativedb: build/query round-trip with a hit and a miss")
    import contextlib
    import io
    from jdec import nativedb as ND

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        lib = root / "probe.dll"
        lib.write_bytes(b"MZ" + b"\x00" * 4094)
        db_path = ND.build(lib, root / "db")
        check("a bundle is written", db_path.is_file(), str(db_path))
        data = json.loads(db_path.read_text(encoding="utf-8"))
        check("the bundle names its library", data.get("library") == "probe.dll",
              str(data)[:200])
        check("the bundle carries every structured field",
              all(k in data for k in ("exports", "jni_exports", "dynamic_methods",
                                      "strings", "decompiled_c")),
              str(sorted(data)))
        data["strings"] = ["JDEC_MARKER_TOKEN"]
        db_path.write_text(json.dumps(data), encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ND.query(db_path, "jdec_marker_token", False)
        check("a known string is found case-insensitively",
              "[string] JDEC_MARKER_TOKEN" in buf.getvalue(), buf.getvalue()[:200])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ND.query(db_path, "definitely-absent-9f3a", False)
        check("an absent keyword reports zero hits",
              "-- 0 hit(s)" in buf.getvalue(), buf.getvalue()[:200])


def test_support_matrix_selfcheck() -> None:
    """The 04 mechanism registry must keep its negative controls honest."""
    print("support matrix: in-repo negative controls")
    import io
    import contextlib
    import support_matrix as SM

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = SM.main(["--selfcheck"])
    check("the support matrix selfcheck passes", rc == 0, buf.getvalue()[:200])
    check("all eight mechanisms are registered", len(SM.MECHANISMS) == 8,
          str(len(SM.MECHANISMS)))
    check("every mechanism declares a support item and its boundary",
          all(m.support and m.not_covered and m.rules for m in SM.MECHANISMS))
    check("every mechanism names at least one real corpus",
          all(m.corpora and set(m.corpora) <= {"hmcl", "neo"}
              for m in SM.MECHANISMS))

