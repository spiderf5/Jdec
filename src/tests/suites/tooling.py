"""Pool, probe, engine bridge, Ghidra, jint/clinit and pipeline automation."""

from __future__ import annotations

from harness import (  # noqa: F401
    CF, DV, EN, ENGINES_DIR, JAVA, JAVAC, JarProfile, MM, MP, OB, PIPE, PL,
    Path, RC, SAMPLE, ST, _no_engines, check, json, os, profile_jar, shutil,
    struct, subprocess, sys, tempfile, zipfile,
)


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
    cp = eng.classpath(ENGINES_DIR)
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
    src = ENGINES_DIR
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
    from jdec import devirt as BVM
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


def test_ops_pool() -> None:
    print("opspool: PhantomShield string-pool static decrypt (DES via bundled _des)")
    gen = Path(__file__).resolve().parent.parent / "gen_ops_fixture.py"
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


def test_ghidra_mappings_normalization() -> None:
    print("ghidra: frida regnatives TSV normalized to the address-table contract")
    from jdec import ghidra_engine as GE

    six = (
        "com/example/Target\tdecrypt\t(Ljava/lang/String;)Ljava/lang/String;"
        "\t0x7ffb1234\t0x7ffb0000\tmod.dll\n"
        "com/example/Target\tresolve\t()V\t0x7ffb5678\t0x7ffb0000\tmod.dll\n"
    )
    rows = [ln.split("\t") for ln in GE.normalize_mappings(six).strip().splitlines()]
    check("6-column TSV becomes 3-column rows", len(rows) == 2
          and all(len(r) == 3 for r in rows), str(rows))
    check("name carries class and method",
          rows[0][0] == "com/example/Target.decrypt", rows[0][0])
    check("ptr taken from column 4", rows[0][1] == "0x7ffb1234", rows[0][1])
    check("runtime base taken from column 5", rows[0][2] == "0x7ffb0000", rows[0][2])

    four = GE.normalize_mappings(
        "com/example/Target\tdecrypt\t()V\t0x1234\n").strip().split("\t")
    check("4-column TSV gets a '-' base", four[2] == "-", str(four))

    three = "Java_com_x_Y_z\t0x1234\t0x1000\n"
    check("already-normalized 3-column table passes through",
          GE.normalize_mappings(three).strip() == three.strip())
    check("comment and blank lines are ignored",
          GE.normalize_mappings("# note\n\n" + three).strip() == three.strip())

    bad = "com/example/Target\tdecrypt\t()V\tnot-a-pointer\t0x1000\tmod.dll\n"
    try:
        GE.normalize_mappings(bad)
        check("undecodable mapping row raises instead of being dropped", False)
    except ValueError as exc:
        check("undecodable mapping row raises instead of being dropped", True)
        check("error names the offending line", "line 1" in str(exc), str(exc))

    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "bad.tsv"
        src.write_text(bad, encoding="utf-8")
        fake_gh = Path(td) / "fake_gh"
        (fake_gh / "support").mkdir(parents=True)
        res = GE.decompile_library(fake_gh, Path(td) / "x.dll",
                                   Path(td) / "out", mappings_tsv=src, quiet=True)
        check("decompile_library surfaces a bad TSV instead of a silent empty result",
              res.get("ok") is False and "invalid --mappings TSV" in res.get("error", ""),
              str(res))
        check("failed normalization leaves no filter input behind",
              not (Path(td) / "out" / "_filter_symbols.txt").exists())


def test_mappings_hardening() -> None:
    print("ghidra: normalization rejects everything the Java worker would reject")
    from jdec import ghidra_engine as GE

    for tok in ("+1", "-1", "1_000", "0x0x1", "0x", "g", "12 34"):
        check(f"Python-only hex rejected: {tok!r}", not GE._is_hex_token(tok))
    for tok in ("0x1A", "0X1a", "  0x1234  ", "deadBEEF"):
        check(f"Java-parseable hex accepted: {tok!r}", GE._is_hex_token(tok))

    canon = GE.normalize_mappings("Java_x\t0X1a\t0X1000\n").strip()
    check("uppercase 0X prefix is canonicalized before reaching the worker",
          canon == "Java_x\t0x1a\t0x1000", canon)
    check("no 0X prefix survives normalization", "0X" not in canon)

    header =("cls\tmethod\tsig\tptr\tbase\tmodule\n"
              "com/x/T\tm\t()V\t0x1000\t0x10000000\tmod.dll\n")
    expected = "com/x/T.m\t0x1000\t0x10000000"
    check("header row skipped without poisoning the table",
          GE.normalize_mappings(header).strip() == expected,
          GE.normalize_mappings(header))
    check("BOM stripped from the first column",
          GE.normalize_mappings("\ufeff" + header).strip() == expected)

    for bad in ("\tmethod\t()V\t0x1000\t0x1\tm\n",
                "com/x/T\tm\t()V\t+1\t0x1\tm\n",
                "Java_x\t0x1234\t+1\n"):
        try:
            GE.normalize_mappings(bad)
            check(f"invalid row raises: {bad[:18]!r}", False)
        except ValueError:
            check(f"invalid row raises: {bad[:18]!r}", True)

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        src, dst = d / "in.tsv", d / "out.tsv"
        src.write_text("\ufeff# comment\n" + header
                       + "\ncom/x/T\tn\t()V\t0x2000\t0x10000000\tmod.dll\n",
                       encoding="utf-8")
        count = GE.normalize_mappings_file(src, dst)
        streamed = dst.read_text(encoding="utf-8")
        check("streamed normalization matches the in-memory one",
              count == 2 and streamed
              == GE.normalize_mappings(src.read_text(encoding="utf-8-sig")),
              streamed)
        check("streamed output carries no BOM", not streamed.startswith("\ufeff"))


def test_stage04_lwjgl_fetch_hardening() -> None:
    print("stage04: LWJGL fetch is atomic and self-heals corrupt leftovers")
    import io
    from unittest import mock
    from jdec import stage04 as S4

    check("report keeps a single string url",
          isinstance(S4.LWJGL_ARTIFACTS[0][2][0], str),
          str(type(S4.LWJGL_ARTIFACTS[0][2])))
    check("multiple download sources remain available",
          all(len(art[2]) >= 2 for art in S4.LWJGL_ARTIFACTS))

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.close()
            return False

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / S4.LWJGL_ARTIFACTS[0][1]).write_bytes(b"truncated-download")
        calls: list[int] = []

        def _open(*a, **k):
            calls.append(1)
            return _Resp(b"PK\x03\x04fake")

        with mock.patch.object(S4.urllib.request, "urlopen", side_effect=_open):
            main, natives = S4.fetch_lwjgl(d)
        check("corrupt leftover is replaced by a valid jar",
              main.read_bytes().startswith(b"PK")
              and natives.read_bytes().startswith(b"PK"))
        check("no .part files leak", not list(d.glob("*.part")))
        check("both artifacts fetched exactly once", len(calls) == 2, str(calls))
        with mock.patch.object(
                S4.urllib.request, "urlopen",
                side_effect=AssertionError("unexpected download")):
            again, _ = S4.fetch_lwjgl(d)
        check("valid cache is reused without downloading",
              len(calls) == 2 and again == main, str(calls))

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / S4.LWJGL_ARTIFACTS[0][1]).mkdir()
        try:
            S4.fetch_lwjgl(d)
            check("same-name directory is reported, not crashed", False)
        except RuntimeError as exc:
            check("same-name directory is reported, not crashed",
                  "directory" in str(exc), str(exc))


def test_trace2java_dead_condition() -> None:
    print("frida: trace2java segment keeps its v1 output without the dead branch")
    import importlib.util
    src = Path(__file__).resolve().parents[3] / "engines" / "frida" / "trace2java.py"
    spec = importlib.util.spec_from_file_location("jdec_trace2java", src)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    check("trace2java has no dead or-True branch",
          "or True" not in src.read_text(encoding="utf-8"))

    with tempfile.TemporaryDirectory() as td:
        markers = Path(td) / "markers.txt"
        markers.write_text("===ENTER a.B.c\n===ENTER a.B.d\n", encoding="utf-8")
        ops = [("1", "FindClass", ["com/x/Y"]),
               ("1", "NewStringUTF", ["hello"]),
               ("1", "GetMethodID", ["m", "()V"])]
        segs = mod.segment(ops, str(markers))
        expected = [("a.B.c", []),
                    ("a.B.d", [(fn, args) for _, fn, args in ops])]
        check("segment output byte-for-byte unchanged after cleanup",
              segs == expected, str(segs))


def test_ghidra_headless_smoke() -> None:
    print("ghidra: real headless smoke on a public PE (opt-in)")
    if os.environ.get("JDEC_GHIDRA_SMOKE") != "1":
        print("  skipped: set JDEC_GHIDRA_SMOKE=1 and GHIDRA_HOME to run")
        return
    from jdec import ghidra_engine as GE
    gh = GE.find_ghidra()
    if gh is None:
        print("  skipped: no Ghidra installation found")
        return
    natives_dir = os.environ.get("JDEC_NATIVES_DIR")
    if not natives_dir:
        print("  skipped: set JDEC_NATIVES_DIR to the LWJGL natives dir")
        return
    natives = Path(natives_dir)
    jars = sorted(natives.glob("*natives-windows*.jar"))
    if not jars:
        print("  skipped: LWJGL natives jar not fetched yet")
        return

    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        with zipfile.ZipFile(jars[0]) as archive:
            dlls = [n for n in archive.namelist() if n.lower().endswith(".dll")]
            if not dlls:
                print("  skipped: natives jar contains no PE")
                return
            dll = work / "public.dll"
            dll.write_bytes(archive.read(dlls[0]))
        tsv = work / "mappings.tsv"
        tsv.write_text(
            "org/lwjgl/DefaultWidget\tnCreate\t()V\t0x10001000\t0x10000000\tpublic.dll\n",
            encoding="utf-8")
        out = work / "out"
        res = GE.decompile_library(gh, dll, out, mappings_tsv=tsv,
                                   timeout=600, quiet=True)
        # Without this the three checks below only prove the Python-side
        # normalization and would all pass even if headless never ran.
        check("headless run actually completed", res.get("ok") is True,
              str(res)[:200])

        written = out / "_addr_mappings.tsv"
        rows = [ln.split("\t") for ln in written.read_text(
            encoding="utf-8").strip().splitlines()]
        check("worker received a 3-column address table",
              len(rows) == 1 and len(rows[0]) == 3, str(rows))
        check("worker received ptr/base from the Frida columns",
              rows[0][1] == "0x10001000" and rows[0][2] == "0x10000000", str(rows))
        if res.get("ok"):
            check("headless run log written", (out / "_ghidra_run.log").is_file())
        check("worker rejected zero mapping lines",
              res.get("bad_mapping_lines", 0) == 0,
              str(res.get("bad_mapping_lines")))
        summary = out / "decompiled_summary.json"
        if summary.is_file():
            data = json.loads(summary.read_text(encoding="utf-8"))
            check("summary records the bad-line counter",
                  "bad_mapping_lines" in data, str(sorted(data)))


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
    import base64
    blob = base64.b64encode(bytes(range(64))).decode()
    check("encrypted blob detected", "encrypted-blob" in ST.classify(blob))
    # A base64 string that decodes to plain printable text is encoded text,
    # not ciphertext. The old pattern tagged these (and long FQCNs) as blobs.
    printable = ("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw"
                 "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=")
    check("base64-encoded printable text is not an encrypted blob",
          "encrypted-blob" not in ST.classify(printable))
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
    from jdec import devirt as BVM
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

