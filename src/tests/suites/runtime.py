"""Isolation, replay, engine installation and the reproducible gate."""

from __future__ import annotations

from harness import (  # noqa: F401
    CL, EN, ENGINES_DIR, JAVAC, Path, SAMPLE, _compile_java, _jar_from,
    check, json, os, shutil, subprocess, tempfile, zipfile,
)


def test_sandbox_isolation() -> None:
    """Replay must not be able to write outside the run root."""
    print("sandbox: the replay JVM cannot escape its write root")
    from jdec import behave as BH
    from jdec import sandbox as SBX

    if JAVAC is None or EN.find_java() is None:
        print("  (skipped: needs a JDK)")
        return
    try:
        if SBX.plan().backend != SBX.MANAGER:
            print("  (skipped: no SecurityManager backend on this JDK)")
            return
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


def test_isolation_backends() -> None:
    """Losing the SecurityManager must degrade, not disable, replay isolation."""
    print("sandbox: the Java manager is optional, the process layer is not")
    from jdec import sandbox as SBX

    if EN.find_java() is None:
        print("  (skipped: needs a JDK)")
        return
    real_major = SBX.java_major
    try:
        SBX.java_major = lambda java=None: 24
        SBX.check_available()
        chosen = SBX.plan()
        check("JDK 24 selects the process backend",
              chosen.backend == SBX.PROCESS, str(chosen))
        args = SBX.jvm_args(Path(tempfile.gettempdir()) / "jdec_sbx_plan")
        check("no SecurityManager is installed on JDK 24",
              not any(a.startswith("-Djava.security.manager=") for a in args),
              str(args))
        check("the work root is still pinned",
              any(a.startswith("-Djdec.sandbox.root=") for a in args), str(args))
        check("no manager classpath is added", SBX.classpath_entry() is None)
        try:
            SBX.plan(backend="manager")
            check("an explicit manager backend is refused on JDK 24", False,
                  "no error raised")
        except SBX.SandboxError:
            check("an explicit manager backend is refused on JDK 24", True)
    finally:
        SBX.java_major = real_major

    env = SBX.child_env({
        "PATH": "/bin", "JAVA_HOME": "/jdk", "SYSTEMROOT": "C:\\Windows",
        "GITHUB_TOKEN": "secret", "AWS_SECRET_ACCESS_KEY": "secret",
        "JAVA_TOOL_OPTIONS": "-Xmx1m", "HTTPS_PROXY": "http://proxy",
        "MY_APP_TOKEN": "secret", "TZ": "UTC",
    })
    check("credentials and JVM-injection vars do not reach the replay JVM",
          not any(k in env for k in (
              "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "MY_APP_TOKEN",
              "JAVA_TOOL_OPTIONS", "HTTPS_PROXY")), str(sorted(env)))
    check("the JVM can still start",
          env.get("PATH") == "/bin" and env.get("JAVA_HOME") == "/jdk"
          and env.get("SYSTEMROOT") == "C:\\Windows", str(env))
    check("unrelated variables survive", env.get("TZ") == "UTC", str(env))
    check("the process backend is not a manager backend",
          SBX.PROCESS != SBX.MANAGER)


def test_benchmark_is_reproducible() -> None:
    """The generated benchmark must stay a usable, honest gate."""
    print("benchmark: a generated fixture keeps the union gate reproducible")
    import contextlib
    import io
    import benchmark

    if JAVAC is None:
        print("  (skipped: needs a JDK)")
        return
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "report.json"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = benchmark.main(["--json", str(out)])
        check("the generated benchmark passes", rc == 0, f"rc={rc}")
        if not out.is_file():
            check("a report is written", False, "no report")
            return
        data = json.loads(out.read_text(encoding="utf-8"))
        comp = data["comparison"]
        check("every generated method is judged",
              comp["union_judged"] == data["methods"], str(comp)[:200])
        check("identity comparison reports no differences",
              comp["diffs"] == 0, str(comp)[:200])
        check("the negative control catches a changed constant",
              data.get("negative_control_detected") is True,
              str(data.get("negative_control", {}))[:200])
        check("the report names the isolation backend",
              data["environment"]["isolation_backend"] in ("manager", "process"),
              str(data["environment"]))
        check("the report records the exact command",
              "--engine both" in comp["command"], comp["command"][:200])


def test_offline_engine_bundle() -> None:
    """An offline engine bundle is verifiable and never reaches the network."""
    print("engines: an offline bundle verifies without downloading")
    import shutil
    from jdec import cli as CL
    from jdec import engines as EN

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        empty = root / "empty"
        rep = EN.verify_bundle(empty)
        check("an empty bundle is not OK", rep["ok"] is False, str(rep))
        check("every pinned jar is reported missing",
              len(rep["files"]) == 4
              and all(v == "missing" for v in rep["files"].values()), str(rep))

        out = root / "offline"
        missing = EN.ensure_engines(out, offline=True, quiet=True)
        check("offline mode reports all three engines missing",
              len(missing) == 3, str(missing))
        check("offline mode downloads nothing",
              not list(out.glob("*.jar")), str(list(out.iterdir())))

        if all((ENGINES_DIR / n).is_file() for n in EN._SHA1):
            good = root / "good"
            good.mkdir()
            for name in EN._SHA1:
                shutil.copy2(ENGINES_DIR / name, good / name)
            good_report = EN.verify_bundle(good)
            check("a real bundle verifies", good_report["ok"] is True,
                  str(good_report))
            bad = root / "bad"
            shutil.copytree(good, bad)
            first = next(iter(EN._SHA1))
            with (bad / first).open("ab") as fh:
                fh.write(b"x")
            bad_report = EN.verify_bundle(bad)
            check("a tampered jar fails verification",
                  bad_report["files"][first] == "mismatch", str(bad_report))
        else:
            print("  (skipped: real engine jars not present)")

    old = os.environ.get("JDEC_MAVEN_MIRROR")
    os.environ["JDEC_MAVEN_MIRROR"] = "https://mirror.invalid/m2/"
    try:
        check("JDEC_MAVEN_MIRROR is applied",
              EN.maven_base() == "https://mirror.invalid/m2", EN.maven_base())
    finally:
        if old is None:
            os.environ.pop("JDEC_MAVEN_MIRROR", None)
        else:
            os.environ["JDEC_MAVEN_MIRROR"] = old

    ns = CL.build_parser().parse_args(
        ["engines", "--offline", "--from-dir", "bundle", "--verify-only",
         "--json", "r.json", "--mirror", "https://m.invalid/m2"])
    check("offline flags parse",
          ns.offline and ns.verify_only and ns.from_dir == "bundle"
          and ns.json == "r.json" and ns.mirror == "https://m.invalid/m2",
          str(ns))


def test_union_denominator_guard() -> None:
    """Widening derivation must not quietly change the 411-method denominator."""
    print("behave: the union denominator stays the --from method list")
    import inspect
    from jdec import cases as CS
    from jdec import cli_commands as CC

    rows = [("a/A", "m", "(I)V"), ("a/A", "m", "(J)V"), ("a/B", "n", "()V")]
    cov = CS.coverage(rows, [])
    check("coverage dedupes overloads by (class, method)",
          cov["total"] == 2, str(cov))
    src = inspect.getsource(CC.cmd_behave)
    check("the union denominator still comes from interp rows",
          "(r.row[0], r.row[1]) for r in interp_rep.rows" in src)
    check("the gate still compares against the requested threshold",
          "pct + 1e-9 < args.union_gate" in src)
    check("MAX_ARITY widens derivation only", CS.MAX_ARITY == 10,
          str(CS.MAX_ARITY))


def test_replay_timeout_cleanup() -> None:
    """A timed-out replay must never kill the caller or leak a child."""
    print("sandbox: timeout cleanup is confined to the replay process")
    import subprocess
    from unittest.mock import MagicMock, patch
    from jdec import sandbox as SBX

    def timed_out_proc():
        proc = MagicMock()
        proc.communicate.side_effect = [
            subprocess.TimeoutExpired("java", 1), ("", "")]
        proc.pid = 12345
        proc.returncode = 0
        return proc

    # POSIX + harden=False: the child shares OUR process group, so killpg
    # would SIGKILL the caller. Only proc.kill() is allowed.
    proc = timed_out_proc()
    with patch.object(SBX.subprocess, "Popen", return_value=proc), \
         patch.object(SBX.os, "name", "posix"), \
         patch.object(SBX.os, "getpgid", return_value=999, create=True), \
         patch.object(SBX.os, "killpg", create=True) as killpg:
        r = SBX.run_replay(["java"], 1, harden=False, text=True)
    check("a timeout is reported", r.timed_out is True)
    check("harden=False never kills a process group", killpg.call_count == 0,
          str(killpg.call_args_list))
    check("the child is still killed", proc.kill.call_count >= 1)
    check("text mode keeps a str stdout", isinstance(r.stdout, str),
          type(r.stdout).__name__)

    # The terminating command itself failing must not crash the replay.
    proc = timed_out_proc()
    with patch.object(SBX.subprocess, "Popen", return_value=proc), \
         patch.object(SBX.os, "name", "nt"), \
         patch.object(SBX.subprocess, "run",
                      side_effect=OSError("taskkill missing")):
        try:
            r = SBX.run_replay(["java"], 1, harden=True)
            check("a failed terminator still returns a result",
                  r.timed_out is True, str(r))
        except Exception as exc:
            check("a failed terminator still returns a result", False,
                  f"{type(exc).__name__}: {exc}")

    # harden=True keeps the process-group kill (the original behaviour).
    proc = timed_out_proc()
    with patch.object(SBX.subprocess, "Popen", return_value=proc), \
         patch.object(SBX.os, "name", "posix"), \
         patch.object(SBX.os, "getpgid", return_value=54321, create=True), \
         patch.object(SBX.os, "killpg", create=True) as killpg:
        SBX.run_replay(["java"], 1, harden=True)
    check("harden=True still kills the child's group",
          killpg.call_count == 1, str(killpg.call_args_list))

    # A second communicate timeout must reap the child and close the pipes.
    proc = MagicMock()
    proc.communicate.side_effect = [subprocess.TimeoutExpired("java", 1),
                                   subprocess.TimeoutExpired("java", 30)]
    proc.pid = 12345
    proc.returncode = 0
    with patch.object(SBX.subprocess, "Popen", return_value=proc), \
         patch.object(SBX.os, "name", "nt"):
        r = SBX.run_replay(["java"], 1, harden=True, text=True)
    check("a stuck child is reaped", proc.kill.call_count >= 1
          and proc.wait.call_count >= 1,
          f"kill={proc.kill.call_count} wait={proc.wait.call_count}")
    check("pipes are closed", proc.stdout.close.called and
          proc.stderr.close.called)
    check("empty timeout output matches text mode",
          isinstance(r.stdout, str) and isinstance(r.stderr, str))


def test_engine_install_safety() -> None:
    """A failed replacement must not delete the jar it cannot replace."""
    print("engines: replacement is prepared before the old jar is touched")
    import io
    import shutil
    import zipfile
    import contextlib
    from unittest.mock import patch
    from jdec import engines as EN

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)

        def make_jar(path: Path) -> None:
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            with path.open("ab") as fh:
                fh.write(b"0" * 20000)

        offline_dir = root / "offline"
        offline_dir.mkdir()
        jar = offline_dir / "cfr-0.152.jar"
        make_jar(jar)
        with contextlib.redirect_stdout(io.StringIO()):
            missing = EN.ensure_engines(offline_dir, want=["cfr"],
                                        offline=True, quiet=True)
        check("offline with no source keeps the existing jar", jar.is_file())
        check("offline with no source reports the engine missing",
              missing == ["cfr"], str(missing))
        check("no temp file is left behind",
              not list(offline_dir.glob("*.jdec-tmp")))

        online_dir = root / "online"
        online_dir.mkdir()
        jar2 = online_dir / "cfr-0.152.jar"
        make_jar(jar2)
        with patch("urllib.request.urlopen", side_effect=OSError("offline")), \
             patch.object(EN, "ensure_procyon_bridge", return_value=True):
            with contextlib.redirect_stdout(io.StringIO()):
                missing = EN.ensure_engines(online_dir, want=["cfr"], quiet=True)
        check("a failed download keeps the existing jar", jar2.is_file())
        check("a failed download is reported", missing == ["cfr"], str(missing))

        # A verified offline source still installs, atomically.
        bundle = root / "bundle"
        bundle.mkdir()
        for name in EN._SHA1:
            src = ENGINES_DIR / name
            if src.is_file():
                shutil.copy2(src, bundle / name)
        if (bundle / "cfr-0.152.jar").is_file():
            target = root / "target"
            with contextlib.redirect_stdout(io.StringIO()):
                missing = EN.ensure_engines(
                    target, want=["cfr"], offline=True, quiet=True,
                    source_dir=bundle)
            check("a verified offline source installs cleanly",
                  missing == [], str(missing))
            check("the installed jar matches the pinned sha1",
                  EN._intact(target / "cfr-0.152.jar",
                             EN._SHA1["cfr-0.152.jar"]))

        # Streamed digest must equal the whole-buffer digest.
        probe = root / "probe.bin"
        probe.write_bytes(b"jdec" * 4096)
        check("streamed sha1 matches the whole-buffer sha1",
              EN._sha1_file(probe) == EN._sha1(probe.read_bytes()))

        # The bridge short-circuit now points at the path javac writes to.
        bridge = root / "bridge"
        bridge.mkdir()
        (bridge / "ProcyonBridge.class").write_bytes(b"x")
        with patch.object(EN, "find_javac") as javac:
            check("an existing bridge skips javac",
                  EN.ensure_procyon_bridge(root, quiet=True) is True)
            check("javac is not started", javac.call_count == 0)


def test_engines_cli_consistency() -> None:
    """Flags that promise 'local only' / 'install' must keep that promise."""
    print("engines: CLI flag combinations and exit codes")
    import io
    import contextlib
    import types
    from unittest.mock import patch
    from jdec import cli_commands as CC
    from jdec import engines as EN

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)

        def ns(**kw):
            base = dict(engines_dir=str(root / "eng"), offline=False,
                        from_dir=None, verify_only=False, json=None,
                        mirror=None, with_ghidra=False)
            base.update(kw)
            return types.SimpleNamespace(**base)

        fake_eng = {k: types.SimpleNamespace(label=k, available=lambda d: True)
                    for k in ("cfr", "vineflower", "procyon")}
        with patch.object(CC.GE, "find_ghidra", return_value=None), \
             patch.object(CC.GE, "download_ghidra") as download:
            with contextlib.redirect_stdout(io.StringIO()):
                rc = CC.cmd_engines(ns(verify_only=True, with_ghidra=True))
            check("--verify-only refuses --with-ghidra", rc == 2, str(rc))
            check("--verify-only never downloads Ghidra",
                  download.call_count == 0)

        with patch.object(CC.GE, "find_ghidra", return_value=None), \
             patch.object(CC.GE, "download_ghidra",
                          side_effect=RuntimeError("network down")), \
             patch.object(EN, "ensure_engines", return_value=[]), \
             patch.object(EN, "ENGINES", fake_eng):
            with contextlib.redirect_stdout(io.StringIO()):
                rc = CC.cmd_engines(ns(with_ghidra=True))
            check("a failed Ghidra download is not a success", rc == 1, str(rc))

        (root / "bundle").mkdir()
        with patch("urllib.request.urlopen") as urlopen, \
             patch.object(EN, "ensure_procyon_bridge", return_value=True):
            with contextlib.redirect_stdout(io.StringIO()):
                CC.cmd_engines(ns(from_dir=str(root / "bundle")))
            check("--from-dir alone never touches the network",
                  urlopen.call_count == 0, str(urlopen.call_count))

        with patch.object(EN, "ensure_engines", return_value=["cfr"]), \
             patch.object(EN, "ENGINES", fake_eng), \
             patch.object(CC.GE, "find_ghidra", return_value=None):
            with contextlib.redirect_stdout(io.StringIO()):
                rc = CC.cmd_engines(ns())
            check("a failed fetch is reflected in the exit code",
                  rc == 1, str(rc))

        report = root / "nested" / "deep" / "engines.json"
        with patch.object(EN, "ensure_engines", return_value=[]), \
             patch.object(EN, "ENGINES", fake_eng), \
             patch.object(CC.GE, "find_ghidra", return_value=None):
            with contextlib.redirect_stdout(io.StringIO()):
                CC.cmd_engines(ns(json=str(report)))
        check("--json creates its parent directories", report.is_file())
        check("the report is valid JSON",
              isinstance(json.loads(report.read_text(encoding="utf-8")), dict))
        check("the report uses LF endings",
              b"\r" not in report.read_bytes())

