"""Containment, project export, Mixin/Forge metadata and the Minecraft
fixtures (the latter only run with --with-mc)."""

from __future__ import annotations

from harness import (  # noqa: F401
    AN, AZ, BC, BROKEN_SAMPLE, CF, CG, CL, ClassOutcome, DV, EN, ENGINES_DIR,
    FLOW, INDY, JAVA, JAVAC, JAVAP, MC_JAR, MC_MAP, MIXIN, MM, MP, OB, PJ,
    Path, RC, ROOT, SAMPLE, ST, SimpleNamespace,
    _make_handler_jump_backwards, _no_engines, _owns_file,
    _scan_error_markers, build_fixtures, check, decompile, evaluate, json,
    os, profile_jar, shutil, struct, subprocess, sys, tempfile, urllib,
    zipfile,
)


def test_export_rejects_escaping_resources() -> None:
    """A hostile jar entry must not write outside src/main/resources.

    The jar under analysis is the untrusted input; `..` in an entry name used
    to be joined straight onto the destination, so exporting a malicious sample
    could drop files anywhere the user could write.
    """
    print("project: jar entries that escape the resources tree are refused")
    import zipfile as _zip

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        jar = root / "evil.jar"
        with _zip.ZipFile(jar, "w") as z:
            z.writestr("assets/ok.txt", "fine")
            z.writestr("../escaped.txt", "pwned")
            z.writestr("../../../../escaped_deep.txt", "pwned")

        out = root / "proj"
        stats = PJ.export_project(jar, out, with_stubs=False)
        res = out / "src" / "main" / "resources"
        check("a safe resource is still extracted",
              (res / "assets" / "ok.txt").is_file())
        check("only the safe entry is copied",
              stats.get("resources_copied") == 1, str(stats))
        check("escaping entries are counted, not silently dropped",
              stats.get("resources_skipped") == 2, str(stats))
        leaked = sorted(str(p.relative_to(root)) for p in root.rglob("escaped*"))
        check("nothing escaped the project tree", leaked == [], str(leaked))


def test_native_extract_keeps_same_basename() -> None:
    """Two libraries sharing a basename must both survive extraction.

    `win/x64/lwjgl.dll` and `win/x86/lwjgl.dll` used to be written to the same
    path, so the report described one file while the directory held the other.
    """
    print("natives: same-named libraries for different arches do not overwrite")
    from jdec import native_scan as NS

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        jar = root / "mod.jar"
        with zipfile.ZipFile(jar, "w") as z:
            z.writestr("native/windows/x64/lwjgl.dll", b"x64-payload")
            z.writestr("native/windows/x86/lwjgl.dll", b"x86-payload")
        out = root / "nat"
        tri = NS.triage(jar, out, collect_decl=False)
        rels = sorted(lib.rel for lib in tri.libs)
        check("both libraries are reported", len(tri.libs) == 2, str(rels))
        check("each has its own on-disk path", len(set(rels)) == 2, str(rels))
        check("the architecture directory is preserved",
              all(r.startswith("native/windows/") for r in rels), str(rels))
        payloads = {(out / r).read_bytes() for r in rels}
        check("no payload was overwritten",
              payloads == {b"x64-payload", b"x86-payload"}, str(payloads))


def test_stub_bundle_failure_is_visible() -> None:
    """A failed stub build must not be reported as a bundled library.

    The fallback writes the .java sources into mc_stubs.jar; that jar cannot
    satisfy javac (it has no .class entries), so counting it as "bundled" turns
    every unresolved vanilla symbol into a mystery for the user.
    """
    print("project: failed stub compile is reported, not counted as bundled")
    import zipfile as _zip
    from unittest import mock
    from jdec import stubs as SB

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        jar = root / "plain.jar"
        with _zip.ZipFile(jar, "w") as z:
            z.writestr("a/B.class", b"\xca\xfe\xba\xbe")  # unparsable on purpose
        out = root / "proj"
        with mock.patch.object(SB, "build_stubs_jar",
                               side_effect=RuntimeError("javac unavailable")):
            stats = PJ.export_project(jar, out, with_stubs=True)
        check("failed stub build is not counted as bundled",
              stats["stubs_bundled"] == 0, str(stats))
        check("failed stub build is reported as sources-only",
              stats["stubs_sources_only"] == 1, str(stats))
        stub_jar = out / "libs" / "mc_stubs.jar"
        check("sources-only jar still exists for inspection", stub_jar.is_file())
        with _zip.ZipFile(stub_jar) as z:
            names = z.namelist()
        check("sources-only jar contains sources, not classes",
              bool(names) and all(n.endswith(".java") for n in names),
              str(names[:3]))


def test_web_cross_site_guard() -> None:
    """Mutating workbench endpoints refuse browser requests from another origin.

    `/api/export_project` is a GET with side effects and `/api/annotations` is a
    plain POST; both are reachable from any page the user has open, so a missing
    origin check is a drive-by write, not a theoretical concern.
    """
    print("web: cross-site requests cannot mutate the workbench")
    import threading
    import urllib.error
    import urllib.request
    from jdec import web as WB

    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        (work / "report.json").write_text(
            json.dumps({"outcomes": {}}), encoding="utf-8")
        handler = lambda *a, **k: WB.WorkbenchHandler(*a, work_dir=work, **k)
        server = WB.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{port}"

        def status(request) -> int:
            try:
                with urllib.request.urlopen(request, timeout=10) as resp:
                    return resp.status
            except urllib.error.HTTPError as exc:
                return exc.code

        body = json.dumps({"class": "a/B", "tag": "threat"}).encode()
        try:
            hostile = urllib.request.Request(
                base + "/api/annotations", data=body, method="POST",
                headers={"Origin": "https://evil.example",
                         "Content-Type": "application/json"})
            check("cross-origin POST is refused", status(hostile) == 403)
            check("refused POST did not write notes",
                  not (work / "audit_notes.json").exists())

            plain = urllib.request.Request(
                base + "/api/annotations", data=body, method="POST",
                headers={"Content-Type": "application/json"})
            check("same-origin POST still works", status(plain) == 200)
            check("same-origin POST wrote notes",
                  (work / "audit_notes.json").is_file())

            export = urllib.request.Request(
                base + "/api/export_project",
                headers={"Sec-Fetch-Site": "cross-site"})
            check("cross-site export is refused", status(export) == 403)
            check("refused export created no project",
                  not (work / "project").exists())

            read_only = urllib.request.Request(
                base + "/api/tree", headers={"Sec-Fetch-Site": "cross-site"})
            check("cross-site read-only API is refused too",
                  status(read_only) == 403)
        finally:
            server.shutdown()
            server.server_close()


def test_cli_json_and_version() -> None:
    """The two P0 regressions: reach --json writes, --version exists."""
    print("cli: reach --json and --version are real entry points")
    from jdec import toolchain as TC
    check("source checkout keeps the repo engines dir",
          TC.default_engines_dir().name == "engines",
          str(TC.default_engines_dir()))
    ver = subprocess.run([sys.executable, "-m", "jdec", "--version"],
                         cwd=ROOT, capture_output=True, text=True, timeout=60)
    check("--version exits 0", ver.returncode == 0, ver.stderr[-200:])
    from jdec import __version__ as pkg_version
    check("--version prints the package version", pkg_version in ver.stdout,
          ver.stdout)
    out = Path(tempfile.mkdtemp(prefix="jdec_reach_json_")) / "reach.json"
    try:
        r = subprocess.run(
            [sys.executable, "-m", "jdec", "reach", str(SAMPLE),
             "--json", str(out)],
            cwd=ROOT, capture_output=True, text=True, timeout=180)
        check("reach --json exits 0", r.returncode == 0, r.stderr[-300:])
        check("reach --json writes a file", out.is_file())
        if out.is_file():
            data = json.loads(out.read_text(encoding="utf-8"))
            check("reach --json contains a summary",
                  isinstance(data.get("summary"), dict), str(data)[:200])
    finally:
        shutil.rmtree(out.parent, ignore_errors=True)


def test_review_2026_11_01() -> None:
    """Findings of the 2026-11-01 review: hostile bytecode, gate verdicts,
    scoring noise that a class named `IO` or an ordinary `"internal error"`
    string used to trigger."""
    print("review 2026-11-01: truncated bytecode, ircheck verdict, scoring noise")

    # -- 1. a cut instruction is a decode error, not an IndexError -----------
    for blob in (b"\x10", b"\x11\x00", b"\xb2\x00"):
        try:
            BC.decode(blob)
            msg = "no error"
        except BC.BytecodeError as exc:
            msg = str(exc)
        except Exception as exc:  # noqa: BLE001 - this used to be IndexError
            msg = f"{type(exc).__name__}: {exc}"
        check(f"decode({blob!r}) reports a bytecode error",
              "truncated instruction" in msg, msg)

    # -- 2. ircheck: PASS is not the same as "looked at everything" ---------
    from jdec import ir as IR
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        with zipfile.ZipFile(SAMPLE) as z:
            entry = next(n for n in z.namelist() if n.endswith(".class"))
            data = bytearray(z.read(entry))
        cf = CF.parse(bytes(data))
        patched = False
        for m in cf.methods:
            payload = AN.member_attributes(cf, m).get("Code")
            if not payload:
                continue
            clen = struct.unpack_from(">I", payload, 4)[0]
            at = bytes(data).find(payload[8:8 + clen])
            if at < 0 or clen < 2:
                continue
            data[at + clen - 1] = 0x10      # bipush with no operand: truncated
            patched = True
            break
        broken = root / "broken.jar"
        with zipfile.ZipFile(broken, "w") as z:
            z.writestr(entry, bytes(data))
        rep = IR.audit_path(broken)
        check("a truncated method is undecodable, not a crash",
              patched and rep.methods_undecodable == 1,
              f"patched={patched} undecodable={rep.methods_undecodable}")
        check("the audit still passes as far as it looked", rep.ok,
              str(rep.class_mismatch) + str(rep.mismatches))
        check("but it does not claim full coverage", not rep.full_coverage)
        check("the summary says PARTIAL", "PARTIAL" in rep.summary(), rep.summary())

        ns = SimpleNamespace(input=str(broken), json=None, limit=10,
                             allow_undecodable=False)
        check("ircheck exits 3 when something was never checked",
              CL.cmd_ircheck(ns) == 3)
        ns.allow_undecodable = True
        check("--allow-undecodable restores exit 0", CL.cmd_ircheck(ns) == 0)

    # -- 3. scoring: a short class name is still a class name ---------------
    if JAVAC is None:
        print("  (skipped: scoring assertions need javac)")
    else:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "src" / "demo").mkdir(parents=True)
            java = root / "src" / "demo" / "IO.java"
            java.write_text(
                "package demo;\n"
                "public class IO {\n"
                "    private int bufferSize;\n"
                "    public int readChunk(int requestedCount) {\n"
                "        return requestedCount + bufferSize;\n"
                "    }\n"
                "}\n", encoding="utf-8")
            subprocess.run([JAVAC, "-d", str(root / "cls"), str(java)],
                           check=True, capture_output=True)
            cf = CF.parse((root / "cls" / "demo" / "IO.class").read_bytes())
            perfect = (
                "package demo;\n"
                "public class IO {\n"
                "    private int bufferSize;\n"
                "    public int readChunk(int requestedCount) {\n"
                "        return requestedCount + bufferSize;\n"
                "    }\n"
                "}\n")
            q = evaluate(perfect, cf)
            check("a perfect recovery of class IO scores 100", q.score == 100.0,
                  f"score={q.score} issues={q.issues}")
            check("no class-name issue is invented",
                  not any("class name" in i for i in q.issues), str(q.issues))

            # a line-comment give-up note counts, and costs only its own line
            q2 = evaluate("// $FF: Couldn't be decompiled\n" + perfect, cf)
            check("a // $FF note is detected as a give-up", q2.hard_error)
            # one comment line over a ~200-character file is ~16%: the point is
            # that the span is the comment and not the whole file
            check("it is measured as the comment, not the file",
                  0.0 < q2.damaged_fraction < 0.35, str(q2.damaged_fraction))
            check("one lost line is not a class-level failure",
                  not q2.class_level_failure)
            check("the report does not print 0% damage",
                  all("(0%" not in i for i in q2.issues), str(q2.issues))

            # -- 4. an ordinary message is not an engine give-up -------------
            out = root / "out"
            (out / "demo").mkdir(parents=True)
            handler = out / "demo" / "Handler.java"
            handler.write_text(
                "package demo;\n"
                "public class Handler {\n"
                "    public void fail() {\n"
                "        throw new IllegalStateException(\"internal error\");\n"
                "    }\n"
                "}\n", encoding="utf-8")
            outs = {"demo/Handler": ClassOutcome(name="demo/Handler",
                                                 rel="demo/Handler.java",
                                                 status="ok")}
            flagged = _scan_error_markers(out, ["demo/Handler"], outs)
            check("a string literal is not a verdict on the class",
                  flagged == [] and outs["demo/Handler"].status == "ok",
                  f"{flagged} {outs['demo/Handler'].status}")
            handler.write_text("// $FF: Couldn't be decompiled\n"
                               "public class Handler {}\n", encoding="utf-8")
            flagged = _scan_error_markers(out, ["demo/Handler"], outs)
            check("a comment note still sends the class for a second opinion",
                  flagged == ["demo/Handler"], str(flagged))

            # -- 5. pass 2 does not overwrite another class' file ------------
            dest = out / "demo" / "A.java"
            dest.write_text("public class A {}\n", encoding="utf-8")
            outer = ClassOutcome(name="demo/A", rel="demo/A.java", status="ok")
            check("the outer class owns its file",
                  _owns_file(outer, "demo/A.java", dest))
            check("a class that produced nothing owns nothing",
                  not _owns_file(ClassOutcome(name="demo/A", status="missing"),
                                 "demo/A.java", dest))

    # -- 6. the sandbox: deep reflection is a driver-only privilege ---------
    from jdec import sandbox as SB
    try:
        SB.check_available()
        sandbox_ok = SB.plan().backend == SB.MANAGER
        why = "" if sandbox_ok else "no SecurityManager backend on this JDK"
    except Exception as exc:  # noqa: BLE001 - no usable JVM
        sandbox_ok = False
        why = str(exc)
    if not sandbox_ok or JAVAC is None:
        print(f"  (skipped: sandbox assertions need JDK 9-23 + javac: {why})")
    else:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "src" / "probe").mkdir(parents=True)
            (root / "src" / "probe" / "Deep.java").write_text(
                "package probe;\n"
                "import java.lang.reflect.Field;\n"
                "public class Deep {\n"
                "    private int secret = 1;\n"
                "    public static void main(String[] a) throws Exception {\n"
                "        Field f = Deep.class.getDeclaredField(\"secret\");\n"
                "        try { f.setAccessible(true); System.out.println(\"ALLOWED\"); }\n"
                "        catch (SecurityException e) { System.out.println(\"DENIED\"); }\n"
                "    }\n"
                "}\n", encoding="utf-8")
            subprocess.run([JAVAC, "-d", str(root / "cls"),
                            str(root / "src" / "probe" / "Deep.java")],
                           check=True, capture_output=True)
            cp = os.pathsep.join([str(SB.classpath_entry()), str(root / "cls")])

            def run(drivers):
                cmd = [JAVA, *SB.jvm_args(root / "sandbox", drivers=drivers),
                       "-cp", cp, "probe.Deep"]
                p = subprocess.run(cmd, capture_output=True, text=True,
                                   errors="replace", timeout=120)
                return p.stdout.strip()

            check("target code cannot setAccessible its way to Unsafe",
                  "DENIED" in run(()))
            check("a driver frame still can", "ALLOWED" in run(("probe.Deep",)))


def test_container_classification() -> None:
    print("container: every reader classifies the input the same way")
    from jdec import container as CT
    from jdec.ir import roundtrip as RT

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        # A self-extracting installer is an MZ stub with the jar appended. The
        # zip reader finds it, but only if the command asks the magic bytes
        # instead of the file suffix.
        sfx = d / "installer.exe"
        sfx.write_bytes(b"MZ" + b"\x90" * 4094 + SAMPLE.read_bytes())

        check("a jar is a zip by magic", CT.kind_of(SAMPLE) == CT.KIND_ZIP)
        check("an MZ stub with a zip payload is a zip too",
              CT.kind_of(sfx) == CT.KIND_ZIP, CT.describe(sfx))
        cls = next((ROOT / "tests" / "build").rglob("*.class"))
        check("a class file is a class", CT.kind_of(cls) == CT.KIND_CLASS)
        check("a directory is a directory", CT.kind_of(d) == CT.KIND_DIR)

        junk = d / "notes.txt"
        junk.write_bytes(b"not a container\n")
        check("a text file is unknown", CT.kind_of(junk) == CT.KIND_UNKNOWN)
        try:
            CT.read_classes(junk)
            check("reading an unknown container is an error", False)
        except CT.ContainerError as exc:
            check("reading an unknown container is an error", True)
            check("...and the message says what it is",
                  "first bytes" in str(exc), str(exc))

        direct = CT.read_classes(SAMPLE)
        stubbed = CT.read_classes(sfx)
        check("the stub does not change the class set",
              set(direct) == set(stubbed),
              f"{len(direct)} vs {len(stubbed)}")

        # META-INF/versions is an alternative to the base class, not a second
        # class; counting it produced NoClassDefFoundError (wrong name) before.
        mr = d / "multirelease.jar"
        one_name, one_bytes = next(iter(direct.items()))
        with zipfile.ZipFile(mr, "w") as z:
            z.writestr(one_name + ".class", one_bytes)
            z.writestr("META-INF/versions/9/" + one_name + ".class", one_bytes)
        check("multi-release copies are not counted as classes",
              set(CT.read_classes(mr)) == {one_name})

        a = RT.audit_path(SAMPLE)
        b = RT.audit_path(sfx)
        check("ircheck audits an installer instead of refusing it",
              b.classes == a.classes and b.classes > 0,
              f"{b.classes} vs {a.classes}")
        check("...and reaches the same byte-exactness verdict", b.ok == a.ok)

        cg_direct = CG.build_callgraph(SAMPLE)
        cg_stub = CG.build_callgraph(sfx)
        check("the call graph sees the same classes through the stub",
              len(cg_direct.classes) == len(cg_stub.classes) > 0,
              f"{len(cg_direct.classes)} vs {len(cg_stub.classes)}")


def test_corrupt_container_is_a_verdict() -> None:
    print("container: a damaged archive is a verdict, not a traceback")
    import contextlib
    import io

    from jdec import cli as CL

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        data = SAMPLE.read_bytes()
        trunc = d / "truncated.jar"
        # Half a jar: the central directory is gone, so every reader that
        # asks zipfile a question gets BadZipFile. The exit code has to stay
        # 2 - Python's default 1 would read as "partial success".
        trunc.write_bytes(data[: len(data) // 2])
        for cmd in ("probe", "reach", "ircheck", "strings", "analyze"):
            extra = ["-o", str(d / "strings_out")] if cmd == "strings" else []
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(buf):
                rc = CL.main([cmd, str(trunc)] + extra)
            text = buf.getvalue()
            check(f"{cmd}: truncated archive exits 2", rc == 2, f"rc={rc} {text[-160:]}")
            check(f"{cmd}: ...says the input cannot be read",
                  "cannot read" in text, text[-160:])
            check(f"{cmd}: ...and does not print a traceback",
                  "Traceback" not in text, text[-200:])


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
                engines_dir=str(ENGINES_DIR),
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
              and "--evidence" in txt)
        check("default export produces no evidence.md",
              not (out / "evidence.md").is_file())
        check("repair-log lists the healed file and rules",
              "`a/Healing.java`" in txt and "keyword" in txt.lower())
        check("stats counters consistent", stats.get("files_repaired") == 1
              and stats.get("repair_rules_applied", 0) >= 2, str(stats))


def test_evidence_ladder_optional() -> None:
    print("project: --evidence is opt-in, authorized and failure-tolerant")
    from jdec import cli_args as CA
    from jdec import cli_commands as CC
    from jdec import project as PJ

    def _args(mode="jvm", **over):
        base = dict(evidence=mode, evidence_from=None, execute=False,
                    no_sandbox=False, evidence_timeout=900)
        base.update(over)
        return SimpleNamespace(**base)

    def _failed_rep():
        return SimpleNamespace(success=False, classes_dir=None)

    parser = CA.build_parser()
    default_args = parser.parse_args(["project", "x.jar"])
    check("--evidence defaults to none",
          getattr(default_args, "evidence", None) == "none",
          str(getattr(default_args, "evidence", None)))
    check("--execute defaults to false", default_args.execute is False)
    jvm_args = parser.parse_args(["project", "x.jar", "--compile",
                                  "--evidence", "jvm"])
    check("--evidence jvm parses", jvm_args.evidence == "jvm")
    behave_args = parser.parse_args(["project", "x.jar", "--evidence", "behave",
                                     "--evidence-from", "cases.txt"])
    check("--evidence-from parses", behave_args.evidence_from == "cases.txt")
    exec_args = parser.parse_args(["project", "x.jar", "--evidence", "behave",
                                   "--execute", "--no-sandbox",
                                   "--evidence-timeout", "120"])
    check("execute / no-sandbox / timeout parse",
          exec_args.execute is True and exec_args.no_sandbox is True
          and exec_args.evidence_timeout == 120)

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        CC._run_evidence(_args(), d / "x.jar", d, _failed_rep(), "jvm")
        ev = (d / "evidence.md").read_text(encoding="utf-8")
        check("failed compile reports partial, never a higher level",
              "evidence_level: **partial**" in ev and "Why not higher" in ev,
              ev[:200])

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        CC._run_evidence(_args("behave"), d / "x.jar", d,
                         SimpleNamespace(success=True, classes_dir=None),
                         "behave")
        ev = (d / "evidence.md").read_text(encoding="utf-8")
        check("behave without --execute refuses to run any check",
              "--execute" in ev and "## JVM verification" not in ev
              and "evidence_level: **partial**" in ev, ev[:250])

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "evidence.md").mkdir()  # write_text raises IsADirectoryError
        CC._run_evidence(_args(), d / "x.jar", d, _failed_rep(), "jvm")
        check("unwritable evidence.md degrades to a warning",
              (d / "evidence.md").is_dir())

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        log = d / "repair-log.md"
        log.write_text("# audit\n", encoding="utf-8")
        for _ in range(2):
            CC._run_evidence(_args(), d / "x.jar", d, _failed_rep(), "jvm")
        check("repair-log evidence marker is idempotent",
              log.read_text(encoding="utf-8").count("Measured evidence level:") == 1,
              log.read_text(encoding="utf-8"))

    if not JAVAC:
        print("  skipped javac-dependent checks: no JDK")
        return
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        src = d / "proj" / "src" / "main" / "java"
        src.mkdir(parents=True)
        (src / "Plain.java").write_text(
            "public class Plain { public static int add(int a, int b) "
            "{ return a + b; } }\n", encoding="utf-8")
        plain = PJ.verify_compilation(d / "proj")
        check("default compile still discards classes",
              plain.success and plain.classes_dir is None,
              str(plain.classes_dir))
        out = d / "classes"
        out.mkdir(parents=True, exist_ok=True)
        (out / "Stale.class").write_bytes(b"old")
        kept = PJ.verify_compilation(d / "proj", classes_out=out)
        check("classes_out retains compiled classes",
              kept.success and kept.classes_dir == out
              and (out / "Plain.class").is_file(),
              str(kept.classes_dir))
        check("classes_out clears stale classes and non-class files",
              not (out / "Stale.class").exists()
              and all(p.suffix == ".class" for p in out.rglob("*") if p.is_file()),
              str([p.name for p in out.rglob("*")]))


def test_evidence_compare_classpath_excludes_original() -> None:
    print("project: behaviour comparison never loads the original jar on both sides")
    from unittest import mock
    from jdec import cli_commands as CC

    class _Report:
        def to_dict(self):
            return {"verdict": "PASS", "checked": 1, "invalid": [],
                    "unresolved": [], "diffs": []}

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        classes = d / "classes"
        classes.mkdir()
        (classes / "A.class").write_bytes(b"\xca\xfe\xba\xbe")
        libs = d / "libs"
        libs.mkdir()
        lib = libs / "dep.jar"
        lib.write_bytes(b"PK\x03\x04")
        raw = d / "target.jar"
        raw.write_bytes(b"PK\x03\x04")
        spec = d / "cases.txt"
        spec.write_text("A\tm\t|\t\n", encoding="utf-8")
        args = SimpleNamespace(evidence="behave", evidence_from=str(spec),
                               execute=True, no_sandbox=False,
                               evidence_timeout=60)
        rep = SimpleNamespace(success=True, classes_dir=classes)
        with mock.patch("jdec.verify.verify", return_value=_Report()) as mv, \
                mock.patch("jdec.behave.parse_spec", return_value=[object()]), \
                mock.patch("jdec.behave.compare", return_value=_Report()) as mc:
            CC._run_evidence(args, raw, d, rep, "behave")

        check("verify may resolve supertypes from the original jar",
              raw in mv.call_args.kwargs.get("classpath", ()),
              str(mv.call_args.kwargs.get("classpath")))
        compare_cp = mc.call_args.kwargs.get("classpath", ())
        check("compare does NOT put the original jar on either loader",
              raw not in compare_cp, str(compare_cp))
        check("compare still sees the bundled libraries",
              lib in compare_cp, str(compare_cp))
        ev = (d / "evidence.md").read_text(encoding="utf-8")
        check("mocked happy path reaches behaviour-parity",
              "behaviour-parity" in ev, ev[:200])


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
            agent_cf = CF.parse(z.read("jdec/mock/MockAgent.class"))
        agent_sigs = set(agent_cf.method_sigs())
        agent_desc = "(Ljava/lang/String;Ljava/lang/instrument/Instrumentation;)V"
        check("mock agent exposes premain", ("premain", agent_desc) in agent_sigs,
              str(sorted(agent_sigs)))
        check("mock agent exposes agentmain", ("agentmain", agent_desc) in agent_sigs,
              str(sorted(agent_sigs)))
    finally:
        shutil.rmtree(tmp_agent_dir, ignore_errors=True)

    # a cached stub with a matching old fingerprint must be rebuilt, not trusted
    bad_dir = Path(tempfile.mkdtemp(prefix="jdec_test_bad_agent_"))
    try:
        bad_jar = bad_dir / "mock_agent.jar"
        with zipfile.ZipFile(bad_jar, "w") as z:
            z.writestr("jdec/mock/MockAgent.class",
                       SB.build_stub_class_bytes("jdec/mock/MockAgent"))
        old_fp = SB._sources_fingerprint(
            {"__mock_agent__": SB.MOCK_AGENT_JAVA,
             "__builder__": str(SB._BUILD_VERSION)})
        bad_jar.with_name(bad_jar.name + ".sha256").write_text(
            old_fp, encoding="utf-8")
        rebuilt = SB.ensure_mock_agent_jar(bad_dir)
        with zipfile.ZipFile(rebuilt) as z:
            rebuilt_cf = CF.parse(z.read("jdec/mock/MockAgent.class"))
        rebuilt_sigs = set(rebuilt_cf.method_sigs())
        want_desc = "(Ljava/lang/String;Ljava/lang/instrument/Instrumentation;)V"
        check("cache validation rebuilds a stub masquerading as an agent",
              ("premain", want_desc) in rebuilt_sigs
              and ("agentmain", want_desc) in rebuilt_sigs,
              str(sorted(rebuilt_sigs)))
    finally:
        shutil.rmtree(bad_dir, ignore_errors=True)

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
            rec_src = Path(__file__).resolve().parents[2] / "jdec" / "recover_driver_template.java"
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
    from jdec import devirt as BVM
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
        agent_cf2 = CF.parse(zf.read("jdec/mock/MockAgent.class"))
    agent_sigs2 = set(agent_cf2.method_sigs())
    agent_desc2 = "(Ljava/lang/String;Ljava/lang/instrument/Instrumentation;)V"
    check("cached mock agent exposes premain", ("premain", agent_desc2) in agent_sigs2)
    check("cached mock agent exposes agentmain", ("agentmain", agent_desc2) in agent_sigs2)

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
    rep = decompile(MIXIN, out, ENGINES_DIR, jobs=1)
    check("decompile counts native methods separately",
          rep.native_methods == 1 and rep.native_classes == 1,
          f"{rep.native_methods}/{rep.native_classes}")


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
        rep = decompile(jar, out, ENGINES_DIR, jobs=2, timeout=600,
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

