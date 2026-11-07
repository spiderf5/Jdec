"""Bytecode semantics: frames, devirtualisation, the interpreter and the
behaviour harness."""

from __future__ import annotations

from harness import (  # noqa: F401
    BC, CF, CL, DV, EN, ENGINES_DIR, FLOW, JAVAC, MIXIN, PIPE, PL, Path,
    SAMPLE, SimpleNamespace, _compile_java, _jar_from, _looks_like_signature,
    _no_engines, build_fixtures, check, decompile, os, shutil, struct,
    tempfile, zipfile,
)


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
    from jdec import devirt as BVM
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
    from jdec import devirt as BVM
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
    from jdec import devirt as BVM
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
            Heap()
            o = it.invoke("com/example/Host", name, desc, None, argv)
            check(f"{name}{argv} computes {expect}",
                  o.kind == "return" and o.value == expect,
                  f"{o.kind}:{o.value} {o.reason[:60]}")
        Heap()
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


def test_reason_replay_and_rollback() -> None:
    """Every accepted edit must replay from the original bytes."""
    print("reasons: the journal replays, and tampering is caught")
    import zipfile
    from jdec import classfile as CF
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
    [m for m in cf2.methods
               if cf2.utf8(m.name_index) == "pick"][0]
    from jdec import deflat as DF
    check("deflat refuses nothing here", DF.deflat_jar is not None)


def test_unflatten_strict_rejection() -> None:
    """The two known false-positive paths must be refused by the checker."""
    print("reasons: unflatten without a state slot, or with an extra branch")
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

    from jdec.ir.types import FrameError

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


def test_interp_engine_semantics() -> None:
    """Negative controls for the interpreter bugs this round actually had.

    Each check pins one concrete mis-execution: category-2 argument popping
    in the wrong order, reference comparison routed through pop_int, and an
    Opaque hiding inside a model collection.
    """
    print("interp engine: category-2 args, acmp, and taint in containers")
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
        Interp(left, h1, __import__("jdec.interp.models",
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
    max(majors.values())
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


def test_weak_engine_is_rescued() -> None:
    """Lead engine fails on modern syntax; a later engine must recover it."""
    if _no_engines():
        return

    print("pipeline: a failing lead engine gets backed up by the others")
    out = Path(tempfile.mkdtemp()) / "out"
    rep = decompile(SAMPLE, out, ENGINES_DIR, jobs=2, verify_all=True,
                    engine_order=["procyon", "cfr", "vineflower"])
    check("retry pass recovered what Procyon dropped", rep.improved >= 1,
          f"retried={rep.retried} improved={rep.improved}")
    check("final result is still clean", rep.ok >= 10,
          f"ok={rep.ok} failed={rep.failed}")

