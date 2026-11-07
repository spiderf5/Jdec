"""Mappings, string recovery, triage and the scorecard baseline."""

from __future__ import annotations

from harness import (  # noqa: F401
    BC, CF, CL, MM, MP, PL, Path, RC, SAMPLE, SimpleNamespace, _no_engines,
    check, json, tempfile, zipfile,
)


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
    ns3 = parser.parse_args(["auto", "x.jar", "--no-sandbox"])
    check("auto can opt out of replay isolation", getattr(ns3, "no_sandbox", False))
    ns4 = parser.parse_args(["pipeline", "x.jar", "--no-sandbox"])
    check("pipeline can opt out of replay isolation", getattr(ns4, "no_sandbox", False))
    ns5 = parser.parse_args(["auto", "x.jar"])
    check("auto keeps isolation on by default", not getattr(ns5, "no_sandbox", True))


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

