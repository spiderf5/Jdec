"""The rewrite base: IR round-trip, the verify gate and both de-flat engines."""

from __future__ import annotations

from harness import (  # noqa: F401
    BC, BROKEN_SAMPLE, CF, CL, EN, FLOW, JAVAC, MIXIN, Path, ROOT, SAMPLE,
    SHAPES, check, struct, subprocess, sys, tempfile, zipfile,
)


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

    # 7. CLI: "clean" and "not everything was checked" are different verdicts.
    #    SAMPLE ships a deliberately truncated class, so a gate that answers 0
    #    for it is lying about what it looked at.
    import contextlib
    import io
    from jdec import cli as CL
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = CL.main(["ircheck", str(SAMPLE)])
    text = buf.getvalue()
    check("ircheck does not call a jar with an unreadable class clean",
          rc == 3, str(rc))
    check("ircheck reports both levels", "class     :" in text and "method    :" in text,
          text[-300:])
    check("the verdict says PARTIAL", "result    : PARTIAL" in text, text[-200:])
    check("the exit reason names what was skipped", "exit 3:" in text and
          "unreadable" in text, text[-300:])

    # the parseable classes on their own are a clean jar: exit 0, PASS
    clean = Path(tempfile.mkdtemp()) / "clean.jar"
    with zipfile.ZipFile(SAMPLE) as zin, zipfile.ZipFile(clean, "w") as zout:
        for name in zin.namelist():
            if not name.endswith(".class"):
                continue
            try:
                CF.parse(zin.read(name))
            except Exception:
                continue
            zout.writestr(name, zin.read(name))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = CL.main(["ircheck", str(clean)])
    text = buf.getvalue()
    check("ircheck exits 0 when every class could be checked", rc == 0, str(rc))
    check("ircheck says PASS there", "result    : PASS" in text, text[-200:])


def test_toolchain_single_entry() -> None:
    """javac is spawned from exactly one place, with the same guardrails."""
    print("toolchain: one entry point for the JDK")
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
            BC.method_code(cf, target)
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


def test_deflat_paths_agree() -> None:
    """The instruction path must cover every method the byte path rewrites.

    `deflat` still ships two engines: the instruction-list rewrite (default)
    and the length-preserving byte patch (`--byte-patch`, and the only path
    that can `--strip-frames`). Their rules are meant to be the same, so the
    migration is only honest if the new engine is a superset of the old one on
    the same input. A method the byte path rewrites but the instruction path
    leaves alone means coverage was lost silently.
    """
    print("deflat: instruction path is a superset of the byte path")
    from jdec import deflat as DF

    if JAVAC is None or EN.find_java() is None:
        print("  (skipped: needs a JDK)")
        return

    # `shapes` is built for exactly this: a flattened dispatcher and a
    # javac switch(String). `flow` is the negative side — both engines decline
    # it, so it can only prove they decline together.
    for label, fixture, expect_rewrite in (("shapes", SHAPES, True),
                                           ("flow", FLOW, False)):
        if not fixture.is_file():
            check(f"{label}: fixture exists for the parity check", False,
                  str(fixture))
            continue
        with tempfile.TemporaryDirectory() as td:
            out_ir = Path(td) / "ir.jar"
            out_raw = Path(td) / "raw.jar"
            ir = DF.deflat_jar(fixture, out_ir, verify_output=False)
            raw = DF.deflat_jar(fixture, out_raw, verify_output=False,
                                ir_rewrite=False)
        ir_set = {tuple(x) for x in ir["rewritten"]}
        raw_set = {tuple(x) for x in raw["rewritten"]}
        only_raw = sorted(raw_set - ir_set)
        if expect_rewrite:
            check(f"{label}: both engines rewrite something",
                  bool(ir_set) and bool(raw_set),
                  f"ir={len(ir_set)} byte={len(raw_set)}")
        check(f"{label}: no method is left to the byte path alone",
              not only_raw, "; ".join(".".join(x[:2]) for x in only_raw[:3]))


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

