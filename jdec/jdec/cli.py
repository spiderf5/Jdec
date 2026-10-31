"""Command line entry point."""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

from . import analyze as AZ
from . import bsm as BM
from . import classfile as CF
from . import engines as EN
from . import ghidra_engine as GE
from . import mappings as MP
from . import native_scan as NS
from . import pool as PL
from . import scorecard as SC
from . import strings as ST
from .decompile import EngineUnavailable, decompile, decompile_exit_code, write_report
from .probe import profile_jar
from .recover import recover as do_recover
from .recover import rewrite_sources as do_rewrite_sources

HERE = Path(__file__).resolve().parent
DEFAULT_ENGINES_DIR = HERE.parent / "engines"


def _dir_to_jar(src: Path, dest: Path) -> Path:
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(src.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(src).as_posix())
    return dest


def cmd_probe(args: argparse.Namespace) -> int:
    p = Path(args.input)
    if not p.exists():
        print(f"no such file: {p}")
        return 2
    tmp_root: Path | None = None
    if p.is_dir():
        tmp_root = Path(tempfile.mkdtemp(prefix="jdec_probe_"))
        p = _dir_to_jar(p, tmp_root / "packed.jar")
    try:
        prof = profile_jar(p)
    finally:
        # the packed jar is a throwaway copy of the input; never leak it
        if tmp_root is not None:
            shutil.rmtree(tmp_root, ignore_errors=True)
    print(prof.summary())
    return 0



def cmd_reasons(args: argparse.Namespace) -> int:
    """Audit the rewrite journal: every accepted edit must replay."""
    import zipfile
    from . import bytecode as BC
    from .ir import reasons as RS

    original = Path(args.original)
    rewritten = Path(args.rewritten) if args.rewritten else None
    for path in (original, rewritten):
        if path is not None and not path.exists():
            print(f"no such file: {path}")
            return 2
    rw_names: set[str] = set()
    rw_bytes: dict[str, bytes] = {}
    if rewritten is not None:
        with zipfile.ZipFile(rewritten) as z:
            for info in z.infolist():
                if info.filename.endswith(".class") \
                        and not info.filename.startswith("META-INF/"):
                    rw_names.add(info.filename)
                    rw_bytes[info.filename] = z.read(info.filename)

    audits: list = []
    with zipfile.ZipFile(original) as z:
        names = [i.filename for i in z.infolist()
                 if i.filename.endswith(".class")
                 and not i.filename.startswith("META-INF/")]
        for name in sorted(names):
            try:
                cf = CF.parse(z.read(name))
            except Exception:
                continue
            for member in cf.methods:
                try:
                    audits.append(RS.audit_method(cf, member))
                except Exception as exc:  # noqa: BLE001 - reported, not fatal
                    audits.append(RS.MethodAudit(
                        cf.name, cf.utf8(member.name_index),
                        cf.utf8(member.descriptor_index)))
                    audits[-1].violations.append(
                        RS.Violation("audit", f"could not audit: {exc}"))
    candidates = [a for a in audits if a.edits]
    bad = [a for a in audits if a.violations]
    mismatched = []
    if rewritten is not None:
        for a in candidates:
            if a.violations or a.after_code is None:
                continue
            entry = a.cls + ".class"
            if entry not in rw_names:
                mismatched.append(f"{a.cls}: missing from the rewritten jar")
                continue
            rw_cf = CF.parse(rw_bytes[entry])
            rw_method = next((m for m in rw_cf.methods
                              if rw_cf.utf8(m.name_index) == a.method
                              and rw_cf.utf8(m.descriptor_index) == a.descriptor),
                             None)
            if rw_method is None:
                mismatched.append(f"{a.cls}.{a.method}: missing in the rewrite")
                continue
            ci = BC.method_code(rw_cf, rw_method, decode_insns=False)
            code = ci.code if ci else b""
            if code != a.after_code:
                mismatched.append(f"{a.cls}.{a.method}: rewritten bytes are not "
                                  f"the audited derivation")
    print(f"audited   : {len(audits)} method(s), {len(candidates)} with edits")
    print(f"justified : {len(candidates) - len(bad)} of {len(candidates)} "
          f"candidate(s) replay cleanly")
    if bad:
        print(f"violations: {len(bad)}")
        for a in bad[:args.limit]:
            print(f"  {a.describe()}")
        if len(bad) > args.limit:
            print(f"  ... and {len(bad) - args.limit} more")
    if rewritten is not None:
        print(f"pair      : {len(mismatched)} rewritten method(s) not explained "
              f"by the journal")
        for line in mismatched[:args.limit]:
            print(f"  {line}")
        if len(mismatched) > args.limit:
            print(f"  ... and {len(mismatched) - args.limit} more")
    if args.json:
        import json
        payload = {
            "audited": len(audits),
            "candidates": len(candidates),
            "violations": [v.describe() for a in bad for v in a.violations],
            "unexplained": mismatched,
        }
        Path(args.json).write_text(json.dumps(payload, ensure_ascii=False,
                                              indent=2), encoding="utf-8")
        print(f"json      : {args.json}")
    if not audits:
        print("exit 2: nothing was audited")
        return 2
    return 0 if not bad and not mismatched else 1


def cmd_ircheck(args: argparse.Namespace) -> int:
    """Gate for the IR layer: parse -> re-assemble -> compare bytes."""
    from . import ir as IR

    p = Path(args.input)
    if not p.exists():
        print(f"no such file: {p}")
        return 2
    try:
        rep = IR.audit_path(p)
    except (zipfile.BadZipFile, OSError) as exc:
        print(f"cannot read {p}: {exc}")
        return 2
    print(rep.summary())
    limit = args.limit or 10
    shown = 0
    for name in rep.class_mismatch[:limit]:
        print(f"  class  {name}")
        shown += 1
    for mm in rep.mismatches[:max(0, limit - shown)]:
        print(f"  method {mm.describe()}")
    extra = (len(rep.class_mismatch) + len(rep.mismatches)) - limit
    if extra > 0:
        print(f"  ... and {extra} more (--limit to see more, --json for all)")
    if rep.undecodable:
        print(f"  note: {len(rep.undecodable)} method(s) not covered, "
              f"first: {rep.undecodable[0]}")
    if args.json:
        rep.write_json(Path(args.json))
        print(f"json      : {args.json}")
    if rep.classes == 0:
        print("exit 2: nothing was checked")
        return 2
    return 0 if rep.ok else 1


def cmd_verify(args: argparse.Namespace) -> int:
    """JVM gate: does every class load under -Xverify:all?"""
    from . import verify as VF

    p = Path(args.input)
    if not p.exists():
        print(f"no such file: {p}")
        return 2
    cp = list(args.cp or ())
    if getattr(args, "siblings", False):
        for sib in sorted(p.parent.glob("*.jar")):
            if sib.resolve() != p.resolve() and str(sib) not in cp:
                cp.append(str(sib))
    try:
        rep = VF.verify(p, classpath=cp, limit=args.limit,
                        java=getattr(args, "java", None),
                        timeout=getattr(args, "timeout", None) or 900)
    except Exception as exc:  # noqa: BLE001 - reported, not retried
        print(str(exc))
        return 2
    print(rep.summary())
    limit = args.show or 10
    if getattr(args, "focus", None):
        try:
            rows = _read_rewritten(args.focus)
        except (OSError, ValueError) as exc:
            print(f"cannot read rewritten list: {exc}")
            return 2
        bad = VF.unjudged_rewritten(rep, rows)
        print(f"rewritten : {len(rows)} method(s); {len(bad)} in a class that "
              f"was not judged")
        for line in bad[:limit]:
            print(f"  UNJUDGED {line}")
        if len(bad) > limit:
            print(f"  ... and {len(bad) - limit} more")
    for group in (rep.invalid, rep.unresolved, rep.skipped, rep.errors):
        for issue in group[:limit]:
            print(f"  {issue.describe()}")
        if len(group) > limit:
            print(f"  ... and {len(group) - limit} more")
    if rep.driver_output.strip() and not rep.verified:
        print(f"  driver: {rep.driver_output.strip()[-400:]}")
    if args.json:
        rep.write_json(Path(args.json))
        print(f"json      : {args.json}")
    if not rep.checked:
        print("exit 2: no class was checked")
        return 2
    if rep.invalid:
        return 1
    if rep.unresolved and not args.allow_unresolved:
        # the gate could not judge these: not a pass
        print(f"note: {len(rep.unresolved)} class(es) were never judged "
              f"(missing dependencies); pass --allow-unresolved to accept that")
        return 1
    if rep.skipped and not getattr(args, "allow_skipped", False):
        print(f"note: {len(rep.skipped)} class(es) are newer than this JVM and "
              f"were never read; pass --allow-skipped to accept that, or use a "
              f"newer JDK")
        return 1
    if rep.errors:
        return 1
    return 0


def cmd_behave(args: argparse.Namespace) -> int:
    """Differential behaviour: same cases, two jars, same answers."""
    from . import behave as BH

    orig, rewritten = Path(args.original), Path(args.rewritten)
    for p in (orig, rewritten):
        if not p.exists():
            print(f"no such file: {p}")
            return 2
    if not args.execute:
        print("refusing to run: this invokes methods from the target jars, which "
              "executes their code (static initialisers included). "
              "Pass --execute to allow it.")
        return 3
    engine = getattr(args, "engine", "jvm") or "jvm"
    sandbox = not getattr(args, "no_sandbox", False)
    cases: list = []
    if args.spec:
        try:
            cases = BH.parse_spec(Path(args.spec).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"cannot read spec: {exc}")
            return 2
        if not cases:
            print("spec contains no cases")
            return 2

    rows = None
    der = None
    if args.derive:
        from . import cases as CS
        if args.from_file:
            try:
                rows = _read_rewritten(args.from_file)
            except (OSError, ValueError) as exc:
                print(f"cannot read rewritten list: {exc}")
                return 2
        der = CS.derive(orig, rows, per_param=args.per_param,
                        sandbox=sandbox)
        note = (" [sandbox: confined IO/network methods are included]"
                if sandbox else "")
        print(f"derive    : {der.summary()}{note}")
        for ex in der.examples:
            print(f"  - {ex}")
        cases = cases + der.cases
        if args.stable and cases:
            try:
                kept, why = CS.stabilise(cases, orig, classpath=args.cp or (),
                                         sandbox=sandbox)
            except Exception as exc:  # noqa: BLE001 - reported, not retried
                print(str(exc))
                return 2
            print(f"stable    : {why['kept']} kept "
                  f"({why['kept'] - why['throws']} returned a value, "
                  f"{why['throws']} threw the same exception both runs), "
                  f"{why['unstable']} dropped (the original disagreed with "
                  f"itself)")
            cases = kept
        if not cases and engine != "interp":
            print("no case survived derivation: nothing was compared, so there "
                  "is no verdict on behaviour")
            return 4

    diffs: list[str] = []
    gate_failed = False
    rep = None
    if engine in ("jvm", "both"):
        try:
            rep = BH.compare(orig, rewritten, cases, classpath=args.cp or (),
                     sandbox=sandbox)
        except Exception as exc:  # noqa: BLE001 - reported, not retried
            print(str(exc))
            return 2
        print(rep.summary())
        diffs += [d.describe() for d in rep.diffs]
        if args.derive:
            cov = CS.coverage(rows, rep.outcomes, der,
                              kept=cases if args.stable else None)
            line = (f"coverage  : {cov['judged']}/{cov['total']} method(s) judged "
                    f"({cov['value']} returned a value, {cov['throw']} threw the "
                    f"same exception)")
            if cov["total"]:
                line += f" -> {100.0 * cov['judged'] / cov['total']:.1f}%"
            print(line)
            if cov["missing"]:
                import collections as _c
                hist = _c.Counter(why for _cls, _n, why in cov["missing"])
                print(f"uncovered : {len(cov['missing'])} method(s), by reason:")
                for why, n in hist.most_common(12):
                    print(f"  {n:4d}  {why}")
                if len(hist) > 12:
                    print(f"  ... and {len(hist) - 12} more reason(s)")
                for cls, name, why in cov["missing"][:args.show]:
                    print(f"  UNCOVERED {cls}.{name}: {why}")
            if args.gate is not None:
                base = der.eligible or 0
                pct = (100.0 * cov["judged"] / base) if base else 0.0
                print(f"gate      : {cov['judged']}/{base} invokable method(s) = "
                      f"{pct:.1f}% (threshold {args.gate:.0f}%)")
                gate_failed = gate_failed or pct + 1e-9 < args.gate
        for d in rep.diffs[:args.show]:
            print(f"  DIFF {d.describe()}")
        if len(rep.diffs) > args.show:
            print(f"  ... and {len(rep.diffs) - args.show} more")
        if rep.unusable:
            for u in rep.unusable[:args.show]:
                print(f"  SKIP {u.describe()}")
            if len(rep.unusable) > args.show:
                print(f"  ... and {len(rep.unusable) - args.show} more")

    interp_rep = None
    if engine in ("interp", "both"):
        from .interp import diff as ID
        if not rows:
            print("interp    : needs --from (the rewritten-method list); "
                  "there is nothing to execute")
            return 2
        interp_rep = ID.compare_rows(orig, rewritten, rows,
                                     trials=args.trials)
        print(interp_rep.summary())
        diffs += [d.describe() for d in interp_rep.diff]
        cov_i = CS.coverage(rows, ID.outcomes(interp_rep))
        line = (f"interp    : {cov_i['judged']}/{cov_i['total']} method(s) judged "
                f"-> {100.0 * cov_i['judged'] / cov_i['total']:.1f}%"
                if cov_i["total"] else "interp    : nothing to compare")
        print(line)
        if cov_i["missing"]:
            import collections as _c
            hist = _c.Counter(why for _cls, _n, why in cov_i["missing"])
            print(f"inconcl.  : {len(cov_i['missing'])} method(s), by reason:")
            for why, n in hist.most_common(12):
                print(f"  {n:4d}  {why}")
            if len(hist) > 12:
                print(f"  ... and {len(hist) - 12} more reason(s)")
        if args.interp_gate is not None and cov_i["total"]:
            pct = 100.0 * cov_i["judged"] / cov_i["total"]
            print(f"interp gate: {cov_i['judged']}/{cov_i['total']} method(s) = "
                  f"{pct:.1f}% (threshold {args.interp_gate:.0f}%)")
            gate_failed = gate_failed or pct + 1e-9 < args.interp_gate
        for d in interp_rep.diff[:args.show]:
            print(f"  DIFF {d.describe()}")
        if len(interp_rep.diff) > args.show:
            print(f"  ... and {len(interp_rep.diff) - args.show} more")

    # the union of both engines is the headline coverage number: a method
    # counts once when either harness could judge it (the JVM harness reaches
    # what reflection can call, the interpreter what its models cover — the
    # two sets overlap only partly)
    union_failed = False
    if rep is not None and interp_rep is not None:
        jvm_keys = {(o.case.cls, o.case.method) for o in rep.outcomes
                    if o.status in ("same", "diff")}
        interp_keys = {(r.row[0], r.row[1]) for r in interp_rep.rows
                       if r.verdict in ("same", "diff")}
        total = len({(r.row[0], r.row[1]) for r in interp_rep.rows}) \
            if rows else len(jvm_keys | interp_keys)
        union = len(jvm_keys | interp_keys)
        line = f"union     : {union}/{total} method(s) judged by either engine"
        if total:
            pct = 100.0 * union / total
            line += f" -> {pct:.1f}%"
        print(line)
        if args.union_gate is not None and total:
            print(f"union gate: {union}/{total} = {pct:.1f}% "
                  f"(threshold {args.union_gate:.0f}%)")
            union_failed = pct + 1e-9 < args.union_gate

    if args.json and rep is not None:
        rep.write_json(Path(args.json))
        print(f"json      : {args.json}")
    # 0 = proven identical, 1 = proven different, 4 = nothing was proven,
    # 5 = a coverage gate was not met. "the rewrite is wrong" (1), "the harness
    # missed" (4) and "the harness did not look enough" (5) stay distinct.
    if diffs:
        return 1
    if rep is not None and rep.verdict in ("PARTIAL", "NO VERDICT"):
        return 4
    judged_any = (rep is not None and rep.compared) or \
        (interp_rep is not None and interp_rep.judged)
    if not judged_any:
        return 4
    return 5 if (gate_failed or union_failed) else 0


def cmd_engines(args: argparse.Namespace) -> int:
    d = Path(args.engines_dir)
    if getattr(args, "with_ghidra", False):
        gh = GE.find_ghidra(engines_dir=d)
        if not gh:
            print("Ghidra not found in engines directory; downloading ...")
            try:
                GE.download_ghidra(d)
            except Exception as exc:
                print(f"Failed to download Ghidra: {exc}")
        else:
            print(f"Ghidra is already present at: {gh}")
    missing = EN.ensure_engines(d)
    print(f"engines dir: {d}")
    unavailable = []
    for key, eng in EN.ENGINES.items():
        ok = eng.available(d)
        print(f"  {eng.label:<24} {'available' if ok else 'MISSING'}")
        if not ok:
            unavailable.append(eng.label)
    gh = GE.find_ghidra(engines_dir=d)
    gh_status = f"available ({gh.name})" if gh else "MISSING (pass --with-ghidra to download)"
    print(f"  {'Ghidra Headless':<24} {gh_status}")
    if missing:
        print(f"could not fetch: {', '.join(missing)}")
    if unavailable:
        # A failed ProcyonBridge compile lands here (no javac): the jar is
        # there but the engine is not usable, so this must not report success.
        print(f"unusable: {', '.join(unavailable)} "
              "(Procyon needs javac to build its bridge)")
        return 1
    return 0


def _resolve_input(path: Path) -> tuple[Path, Path | None]:
    """Return (jar_path, temp_dir_or_None)."""
    if path.is_file():
        return path, None
    tmp = Path(tempfile.mkdtemp(prefix="jdec_pack_"))
    return _dir_to_jar(path, tmp / "packed.jar"), tmp


def cmd_decompile(args: argparse.Namespace) -> int:
    raw = Path(args.input)
    if not raw.exists():
        print(f"no such file: {raw}")
        return 2
    # Fail before downloading anything: without a JVM every engine returns
    # "java not found", every class ends up failed, and the run used to exit 0.
    if EN.find_java() is None:
        print("no Java runtime found: set JAVA_HOME to a JDK (e.g. D:\\java21) "
              "or put java on PATH")
        return 2
    engines_dir = Path(args.engines_dir)
    missing = EN.ensure_engines(engines_dir, quiet=True)
    usable = [k for k in EN.ENGINES if EN.ENGINES[k].available(engines_dir)]
    if not usable:
        print("no engines present; fetching ...")
        EN.ensure_engines(engines_dir)
        usable = [k for k in EN.ENGINES if EN.ENGINES[k].available(engines_dir)]
    if not usable:
        # same bucket as "nothing recovered": the environment cannot run, which
        # the README documents as exit 2
        print("no decompiler engines available, aborting")
        return 2
    if missing:
        print(f"note: unavailable engines: {', '.join(missing)}")

    input_path, tmp = _resolve_input(raw)
    out_dir = Path(args.output) if args.output else raw.parent / (raw.stem + "_decompiled")

    jar_for_work = input_path
    tmp2: Path | None = None
    try:
        prof = profile_jar(input_path)

        want_deobf = args.mapping_set != "none" and (
            args.deobf or args.mappings is not None
            or (args.mapping_set != "none" and prof.is_minecraft and prof.obfuscation >= 50)
        )
        if want_deobf:
            version = args.mc_version or prof.mc_version
            if args.mappings:
                mp_path = Path(args.mappings)
                print(f"[0/5] loading mappings from {mp_path.name} ...")
                mapping = MP.load_mapping(mp_path, invert=not args.no_invert)
            else:
                if not version:
                    print("[0/5] ! this looks like obfuscated Minecraft, but the version is "
                          "unknown; pass --mc-version or --mappings")
                    mapping = None
                else:
                    try:
                        print(f"[0/5] fetching {args.mapping_set} mappings for {version} ...")
                        cache = out_dir.parent / ".jdec_mappings"
                        mapping = MP.auto_fetch(version, _mapping_set_for(args.mapping_set, prof), cache)
                    except Exception as exc:  # noqa: BLE001
                        print(f"[0/5] ! mapping fetch failed: {exc}")
                        print("      continuing without deobfuscation "
                              "(pass --mappings FILE to supply one)")
                        mapping = None
            if mapping is not None:
                print(f"      {mapping.describe()}")
                remapped = out_dir.parent / f"{raw.stem}_deobf.jar"
                remapped.parent.mkdir(parents=True, exist_ok=True)
                changed, total = MP.remap_jar(input_path, remapped, mapping,
                                              strict=args.strict_remap)
                print(f"      remapped {changed}/{total} classes -> {remapped.name}")
                jar_for_work = remapped
                tmp2 = remapped.parent

        rep = decompile(
            jar_for_work, out_dir, engines_dir,
            engine_order=[e.strip() for e in args.engine.split(",")] if args.engine else None,
            jobs=args.jobs, memory=args.memory, timeout=args.timeout,
            verify_all=args.verify_all, resume=args.resume, keep_work=args.keep_work,
            clean_work=args.clean_work,
            limit=args.limit,
        )
        write_report(rep, out_dir)
        print()
        print(f"classes   : {rep.total}")
        print(f"recovered : {rep.ok} clean, {rep.partial} partial, "
              f"{rep.failed + rep.missing} failed")
        print(f"retried   : {rep.retried} (improved {rep.improved})")
        if rep.coverage_avg is not None:
            print(f"recovery  : {rep.coverage_avg * 100:.1f}% member name-hit rate "
                  f"(declared members found in output)")
        print(f"elapsed   : {rep.elapsed:.1f}s")
        print(f"source    : {out_dir / 'src'}")
        print(f"report    : {out_dir / 'report.md'}")
        # Same 0/1/2 vocabulary as the pipeline: a run that recovered nothing
        # must not look like a success to a script or a CI step.
        code = decompile_exit_code(rep)
        if code == 2:
            print("exit 2: nothing was recovered")
        elif code == 1:
            print(f"exit 1: {rep.failed + rep.missing} class(es) failed, "
                  f"{rep.partial} partial")
        return code
    except EngineUnavailable as exc:
        print(str(exc))
        return 2
    finally:
        if tmp and not args.keep_work:
            shutil.rmtree(tmp, ignore_errors=True)


def _mapping_set_for(kind: str, prof) -> str:
    """Fabric/Quilt jars reference the game by Yarn intermediary names
    (class_310 / method_1234), which no Mojang mapping knows — auto must
    pick yarn there. Every other loader keeps auto's version-based pick."""
    if kind == "auto" and getattr(prof, "mc_flavor", None) in ("Fabric", "Quilt"):
        return "yarn"
    return kind


def _load_mapping(args, prof, out_dir: Path):
    """Mapping for translating hook targets. Returns (mapping, description)."""
    if args.mappings:
        p = Path(args.mappings)
        return MP.load_mapping(p, invert=not args.no_invert), p.name
    version = args.mc_version or prof.mc_version
    if args.mapping_set == "none" or not version:
        return None, None
    cache = Path(args.output).parent / ".jdec_mappings" if args.output else \
        out_dir.parent / ".jdec_mappings"
    try:
        m = MP.auto_fetch(version, _mapping_set_for(args.mapping_set, prof), cache)
        return m, m.describe()
    except Exception as exc:  # noqa: BLE001
        print(f"! mapping fetch failed: {exc}")
        return None, None


def cmd_analyze(args: argparse.Namespace) -> int:
    raw = Path(args.input)
    if not raw.exists():
        print(f"no such file: {raw}")
        return 2
    out_dir = Path(args.output) if args.output else raw.parent / (raw.stem + "_analysis")
    prof = profile_jar(raw)
    mapping, desc = _load_mapping(args, prof, out_dir)
    if mapping is not None:
        print(f"mapping: {desc}")
    a = AZ.analyze(raw, mapping=mapping, mapping_desc=desc, limit=args.limit)
    md, js = AZ.write_analysis(a, out_dir)
    AZ.print_summary(a)
    print()
    print(f"report: {md}")
    print(f"json  : {js}")
    return 0


def cmd_ops_pool(args: argparse.Namespace) -> int:
    """Decrypt PhantomShield-family string pools statically (no JVM)."""
    from . import ops_pool as OP

    raw = Path(args.input)
    if not raw.exists():
        print(f"no such file: {raw}")
        return 2
    out_path = Path(args.output) if args.output else raw.parent / (raw.stem + "_ops_pool.tsv")
    results = OP.scan_jar(str(raw))
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("class\tstrings\n")
        for cls, strings, _entry in results:
            f.write(f"{cls}\t" + "\t".join(strings) + "\n")
    total = sum(len(s) for _c, s, _e in results)
    print(f"classes with OPS pools: {len(results)}  strings: {total}")
    print(f"output: {out_path}")
    return 0 if results else 1


def cmd_strings(args: argparse.Namespace) -> int:
    raw = Path(args.input)
    if not raw.exists():
        print(f"no such file: {raw}")
        return 2
    out_dir = Path(args.output) if args.output else raw.parent / (raw.stem + "_strings")
    d = ST.dump_strings(raw, limit=args.limit, min_len=args.min_len)
    scanned, total = d.classes_scanned, d.total
    if args.suspicious:
        d = d.only_suspicious()
    if args.grep:
        d = d.grep(args.grep)
    tsv = ST.write_tsv(d, out_dir / "strings.tsv")
    js = ST.write_json(d, out_dir / "strings.json")
    print(f"scanned    : {scanned} classes ({d.unreadable} unreadable)")
    print(f"strings    : {total} total, {d.total} written")
    tagged = sum(1 for r in d.rows if r[2])
    if tagged:
        counts = d.tag_counts()
        summary = ", ".join(f"{k}: {v}" for k, v in list(counts.items())[:6])
        print(f"tagged     : {tagged} literal(s) ({summary})")
    print(f"tsv        : {tsv}")
    print(f"json       : {js}")
    return 0


def cmd_natives(args: argparse.Namespace) -> int:
    raw = Path(args.input)
    if not raw.exists():
        print(f"no such file: {raw}")
        return 2
    out_dir = Path(args.output) if args.output else raw.parent / (raw.stem + "_natives")
    is_zip = raw.read_bytes()[:2] == b"PK"
    if is_zip:
        tri = NS.triage(raw, out_dir, collect_decl=not args.no_decl)
    else:
        # raw PE/ELF file (e.g. a DLL dumped by engines/frida payload dump)
        tri = NS.triage_raw(raw, out_dir)

    decompiled_info = None
    if getattr(args, "decompile", False):
        engines_dir = Path(args.engines_dir) if hasattr(args, "engines_dir") else DEFAULT_ENGINES_DIR
        gh = GE.find_ghidra(explicit_path=args.ghidra, engines_dir=engines_dir)
        if not gh and getattr(args, "fetch_ghidra", False):
            print("Ghidra not found; fetching Ghidra Headless into engines/ghidra ...")
            try:
                gh = GE.download_ghidra(engines_dir)
            except Exception as e:
                print(f"Failed to download Ghidra: {e}")
        if gh:
            print(f"ghidra engine: {gh}")
            decompiled_info = NS.decompile_libs(
                tri, out_dir, gh,
                mappings_tsv=Path(args.mappings_tsv) if getattr(args, 'mappings_tsv', None) else None)
            total_decomp = sum(d.get("decompiled_count", 0) for d in decompiled_info.values())
            print(f"decompiled   : {total_decomp} JNI function(s) exported to C pseudo-code")
        else:
            print("note         : Ghidra Headless not found. Native C decompilation skipped.")
            print("               To download and set up Ghidra automatically, run:")
            print("                 python jdec.py engines --with-ghidra")
            print("               Or run with --fetch-ghidra / specify path via --ghidra <PATH>.")

    report = out_dir / "native-triage.md"
    NS.write_report(tri, raw.name, report, decompiled_info=decompiled_info)
    print(f"libs      : {len(tri.libs)} extracted -> {out_dir}")
    for lib in tri.libs:
        extra = f"  ({lib.error})" if lib.error else ""
        print(f"  {lib.name}  {lib.size / 1048576:.1f} MB  {lib.format}"
              f"  exports={len(lib.exports)} jni={len(lib.jni_exports)}{extra}")
    print(f"declared  : {len(tri.native_decl)} native methods "
          f"in {len({c for c, _ in tri.native_decl})} classes (java side)")
    print(f"static    : {len(tri.matched_static())} JNI exports matched 1:1; "
          f"the rest need RegisterNatives analysis (see report)")
    print(f"report    : {report}")
    return 0


def cmd_indy(args: argparse.Namespace) -> int:
    raw = Path(args.input)
    if not raw.exists():
        print(f"no such file: {raw}")
        return 2
    result = BM.scan_jar(raw, limit=args.sample)
    st = result["stats"]
    print(f"classes            : {st['classes']}")
    print(f"with BootstrapMethods: {st['classes_with_bsm']} "
          f"({st['bsm_total']} bootstrap entries)")
    print(f"with indy sites    : {st['classes_with_sites']}")
    print(f"indy sites         : {st['sites']}")
    if result["per_owner"]:
        print("bootstrap owners (top):")
        for owner, n in sorted(result["per_owner"].items(),
                               key=lambda kv: -kv[1])[:8]:
            print(f"  {n:6d}  {owner}")
    if result["per_name"]:
        names = ", ".join(f"{k!r}x{n}" for k, n in
                          sorted(result["per_name"].items(),
                                 key=lambda kv: -kv[1])[:14])
        print(f"site names: {names}")
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        import json
        payload = {"stats": st,
                   "per_owner": result["per_owner"],
                   "per_name": result["per_name"],
                   "sample": [{"cls": c, "sites": [
                       {"method": s.method, "name": s.name, "desc": s.desc,
                        "bsm": ({"owner": s.bsm.owner, "name": s.bsm.name,
                                 "kind": s.bsm.kind}
                                if s.bsm else None),
                        "dynargs": repr(s.dynargs)} for s in sites]}
                       for c, sites in result["sample"]]}
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=1),
                       encoding="utf-8")
        print(f"details  : {out}")
    return 0


def cmd_recover(args: argparse.Namespace) -> int:
    raw = Path(args.input)
    from_frida = Path(args.from_frida) if getattr(args, "from_frida", None) else None
    if not raw.exists():
        if from_frida and args.rewrite_src:
            st = do_rewrite_sources(Path(args.rewrite_src), from_frida=from_frida)
            print(f"rewrite   : {st['replaced']} call(s) replaced in {st['files']} "
                  f"file(s), {st['missed']} missed, {st['residual']} residual, "
                  f"map={st['map_size']} conflicts={st['conflicts']}")
            print(f"rewritten : {args.rewrite_src}")
            return 0
        print(f"no such file: {raw}")
        return 2
    out_dir = Path(args.output) if args.output else raw.parent / (raw.stem + "_recovered")
    rc = do_recover(raw, out_dir, cp=args.cp, java=args.java,
                    limit=args.limit, stop_on_error=args.stop_on_error,
                    cp_file=args.cp_file, timeout=args.timeout,
                    with_stubs=getattr(args, "with_stubs", True),
                    from_frida=from_frida,
                    allow_exec=getattr(args, "execute", False),
                    sandbox=not getattr(args, "no_sandbox", False))
    tsv = out_dir / "recovered.tsv"
    if args.rewrite_src:
        if not Path(args.rewrite_src).is_dir():
            print(f"rewrite-src: no such dir: {args.rewrite_src}")
            return 2
        if not tsv.exists() and not from_frida:
            print("rewrite-src: no recovered.tsv produced; nothing to rewrite")
            return 1
        st = do_rewrite_sources(Path(args.rewrite_src), tsv, from_frida=from_frida)
        print(f"rewrite   : {st['replaced']} call(s) replaced in {st['files']} "
              f"file(s), {st['missed']} missed, {st['residual']} residual, "
              f"map={st['map_size']} conflicts={st['conflicts']}")
        print(f"rewritten : {args.rewrite_src}")
    return rc


def cmd_pool(args: argparse.Namespace) -> int:
    a = args.action
    if a == "scan":
        src = Path(args.input)
        if not src.is_dir():
            print(f"no such dir: {src}")
            return 2
        out = Path(args.output) if args.output else \
            src.parent / "pool_work" / "pool_spec.tsv"
        st = PL.scan_spec(src, out)
        print(f"scanned   : {st['files']} files, {st['pool_classes']} pool "
              f"classes, {st['accessors']} accessor(s), {st['sig_bad']} "
              f"shape-mismatch candidate(s)")
        extra = (f", {st['overload_skipped']} overload-mismatch skipped"
                 if st["overload_skipped"] else "")
        print(f"call sites: {st['sites']} ({st['unique']} unique, in "
              f"{st['files_with_sites']} files{extra})")
        if st["ambiguous_simple_names"]:
            print(f"ambiguous : {', '.join(st['ambiguous_simple_names'])} "
                  f"(same simple name in several packages - qualified sites "
                  f"skipped)")
        print(f"spec      : {out}")
        return 0 if st["unique"] else 1
    if a == "harvest":
        spec = Path(args.input)
        if not spec.is_file():
            print(f"no such file: {spec}")
            return 2
        if not getattr(args, "execute", False):
            print("NOTICE    : pool harvest runs the replay JVM, which EXECUTES "
                  "code from the target jar.")
            print("            Default is refused (no sandbox). Pass --execute "
                  "to run it anyway.")
            return 3
        out_tsv = Path(args.output) if args.output else \
            spec.parent / "pool_harvest.tsv"
        try:
            st = PL.harvest(spec, out_tsv, spec.parent, cp=args.cp,
                            cp_file=args.cp_file, java=args.java,
                            timeout=args.timeout,
                            with_stubs=getattr(args, "with_stubs", True),
                            allow_exec=True,
                            sandbox=not getattr(args, "no_sandbox", False))
        except Exception as exc:  # noqa: BLE001 - reported, not retried
            print(str(exc))
            return 1
        if st["timed_out"]:
            print(f"WARNING   : driver killed at {args.timeout}s timeout "
                  f"(partial output kept; rerun with --timeout N)")
        print(f"harvest   : {st['ok']} ok, {st['err']} err -> {out_tsv}")
        if st["buckets"]:
            print("fail triage: " + " ".join(
                f"{b.key}={len(b.entries)}" for b in st["buckets"])
                + (f" -> {st['triage'].name}" if st["triage"] else ""))
        return 0 if st["ok"] else 1
    # apply
    src = Path(args.input)
    if not src.is_dir():
        print(f"no such dir: {src}")
        return 2
    from_frida = Path(args.from_frida) if getattr(args, "from_frida", None) else None
    if not args.harvest and not from_frida:
        print("apply needs --harvest <pool_harvest.tsv> or --from-frida <tsv>")
        return 2
    hv = Path(args.harvest) if args.harvest else None
    if hv and not hv.is_file():
        print(f"no such file: {hv}")
        return 2
    out = Path(args.output) if args.output else src.parent / (src.name + "_pool")
    st = PL.apply(src, hv, out, from_frida=from_frida)
    print(f"rewrite   : {st['replaced']} call(s) replaced "
          f"({st['repl_q']} qualified + {st['repl_bare']} bare), "
          f"{st['missed']} missed, {st['unique_plain']} unique plaintexts")
    print(f"verify    : residual={st['residual']} (decodable sites left)")
    if st["buckets"]:
        print("fail triage: " + " ".join(
            f"{b.key}={len(b.entries)}" for b in st["buckets"])
            + (f" -> {st['triage'].name}" if st["triage"] else ""))
    print(f"rewritten : {out}")
    return 0 if st["replaced"] else 1


def cmd_scorecard(args: argparse.Namespace) -> int:
    jars = SC.collect_jars(args.input)
    if not jars:
        print("no jars found in input(s)")
        return 2
    flags = {"analyze": args.analyze, "decompile": args.decompile}
    rows = []
    for j in jars:
        print(f"scoring: {j.name} ...")
        rows.append(SC.score_jar(j, do_analyze=args.analyze,
                                 do_decompile=args.decompile,
                                 engines_dir=Path(args.engines_dir),
                                 timeout=args.timeout))
        r = rows[-1]
        print(f"  classes={r['classes']} obf={r['obfuscation']} "
              f"strings={r['strings']} susp={r['strings_suspicious']} "
              f"({r['elapsed_s']}s)")
    out = Path(args.output) if args.output else Path("scorecard.json")
    compare = Path(args.compare) if args.compare else None
    jp, deltas = SC.write_scorecard(rows, out, flags, compare)
    md = jp.with_suffix(".md")
    md.write_text(SC.render_markdown(rows, deltas, flags), encoding="utf-8")
    print(f"scorecard : {jp}")
    print(f"markdown  : {md}")
    if deltas:
        changed = sum(1 for d in deltas if d["status"] in ("changed", "new"))
        print(f"compare   : {changed}/{len(deltas)} row(s) changed/new "
              f"vs {compare.name}")
    return 0


def cmd_web(args: argparse.Namespace) -> int:
    from . import web
    p = Path(args.input)
    if not p.exists():
        print(f"no such file or directory: {p}")
        return 2
    web.start_server(p, port=args.port, open_browser=not args.no_browser)
    return 0


def cmd_rename(args: argparse.Namespace) -> int:
    from . import rename
    p = Path(args.input)
    if not p.exists():
        print(f"no such file or directory: {p}")
        return 2
    candidates = rename.scan_source_tree(p) if p.is_dir() else rename.scan_source_file(p)
    print(f"scanned   : {len(candidates)} candidate obfuscated member(s)")
    if getattr(args, "prompt_out", None):
        prompt = rename.export_llm_prompt(candidates, limit=args.limit)
        Path(args.prompt_out).write_text(prompt, encoding="utf-8")
        print(f"prompt    : exported LLM prompt to {args.prompt_out}")
    if args.output:
        n = rename.write_proguard_mapping(candidates, Path(args.output))
        print(f"mapping   : {n} heuristic rule(s) written to {args.output}")
    return 0


def _write_rewritten(path, rows) -> None:
    """`class<TAB>method<TAB>descriptor` — what `behave --from` reads back."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(
        "".join(f"{c}\t{n}\t{d}\n" for c, n, d in rows), encoding="utf-8")


def _read_rewritten(path) -> list[tuple[str, str, str]]:
    rows = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            raise ValueError(f"bad rewritten line: {line!r} (want class<TAB>name<TAB>desc)")
        rows.append((parts[0], parts[1], parts[2]))
    return rows


def _print_verify(v) -> None:
    """One line for a `verify` report; nothing at all when there is none."""
    if not v:
        return
    if v.get("skipped"):
        print(f"verify    : skipped ({v['skipped']})")
        return
    line = f"verify    : {v.get('verified', 0)} class(es) pass -Xverify:all"
    if v.get("reverted"):
        line += f", {len(v['reverted'])} reverted (their rewrite did not load)"
    if v.get("still_invalid"):
        line += f", {len(v['still_invalid'])} were already invalid in the input"
    if v.get("unresolved"):
        line += f", {v['unresolved']} not judged (missing deps)"
    print(line)


def cmd_deflat(args: argparse.Namespace) -> int:
    from . import deflat
    p = Path(args.input)
    if not p.is_file():
        print(f"no such file: {p}")
        return 2
    out = Path(args.output) if args.output else p.with_name(p.stem + "_deflat" + p.suffix)
    # The instruction-level path is the default: it deletes what the byte
    # passes could only NOP, and it computes the StackMapTable instead of
    # inheriting one. `--byte-patch` keeps the old behaviour for comparison;
    # `--strip-frames` is a decompiler input, where neither applies.
    ir = not (args.byte_patch or args.strip_frames)
    stats = deflat.deflat_jar(p, out, verify_output=not args.no_verify,
                              strip_frames=args.strip_frames,
                              recompute_frames=args.recompute_frames,
                              ir_rewrite=ir, classpath=args.cp or (),
                              check_reasons=not args.no_reasons,
                              jobs=getattr(args, "jobs", 1) or 0)
    if stats.get("frames_rebuilt"):
        print(f"frames    : {stats['frames_rebuilt']} rewritten method(s) got a "
              f"recomputed StackMapTable")
    print(f"deflat    : {stats['methods_unflattened']} method(s) rewritten across "
          f"{stats['classes']} class(es)"
          + (f" ({stats['methods_reverted']} kept original)"
             if stats.get("methods_reverted") else ""))
    if args.no_reasons:
        print("reasons   : skipped (--no-reasons); the rewrites are not justified")
    else:
        refused = stats.get("reason_refused") or []
        if refused:
            print(f"reasons   : {len(refused)} method(s) kept original; first: "
                  f"{refused[0][0]}.{refused[0][1]} — {refused[0][3].split(': ', 1)[-1]}")
        else:
            print("reasons   : every accepted rewrite has a replayable derivation")
    print(f"output    : {out}")
    if getattr(args, "rewritten", None):
        _write_rewritten(args.rewritten, stats.get("rewritten") or [])
        print(f"rewritten : {len(stats.get('rewritten') or [])} method(s) -> "
              f"{args.rewritten}")
    v = stats.get("verify")
    _print_verify(v)
    missing = stats.get("unresolved_types") or []
    if missing and stats["methods_unflattened"]:
        sample = ", ".join(missing[:4])
        if len(missing) > 4:
            sample += f" (+{len(missing) - 4} more)"
        print(f"warning   : {len(missing)} type(s) referenced by the target are "
              f"not on the classpath ({sample}); frames that merge them widen "
              f"to java/lang/Object, so \"0 rejected\" is conditional. Re-run "
              f"with --cp <deps> and verify again.")
    if v and v.get("unjudged_rewritten"):
        print(f"warning   : {v['unjudged_rewritten']} rewritten method(s) live in "
              f"a class the verifier could not load, so they were never judged. "
              f"Pass --cp with the jar's dependencies; without them \"0 rejected\" "
              f"is conditional.")
    if stats["methods_unflattened"]:
        if ir:
            print("note      : instruction-level rewrite: folded expressions and "
                  "dead blocks are deleted, not NOP-filled, so the code array "
                  "gets shorter. Methods whose frames could not be recomputed "
                  "kept their original body.")
        elif args.strip_frames:
            print("note      : frames stripped on purpose (decompiler input). A "
                  "rewritten method that still has branches is reverted, because "
                  "the split verifier needs a frame at every branch target.")
        elif args.recompute_frames:
            print("note      : StackMapTables were recomputed (full_frame) and "
                  "keep every offset javac required. This path still reverts more "
                  "classes than the default.")
        else:
            print("note      : StackMapTables kept as they were. These rewrites "
                  "are length-preserving, so the frames still describe the right "
                  "offsets; the verifier above loaded every class.")
    if stats.get("signatures_removed"):
        print(f"note      : removed {stats['signatures_removed']} jar signature "
              f"file(s); rewritten entries no longer match the original signature")
    failed = stats.get("failed_classes") or []
    if failed:
        print(f"warning   : {len(failed)} class(es) could not be parsed or "
              f"rewritten and were written back unchanged; first: {failed[0]}")
    if (v and v.get("reverted")) or failed:
        return 1
    return 0


def cmd_devirt(args: argparse.Namespace) -> int:
    from . import devirt as DV
    p = Path(args.input)
    if not p.exists():
        print(f"no such file: {p}")
        return 2

    out = Path(args.output) if args.output else p.with_name(p.stem + "_devirt" + p.suffix)
    frame_notes: list[str] = []
    code_pool: dict[int, DV.VMMethod] = {}
    if getattr(args, "pool", None):
        pool_p = Path(args.pool)
        if pool_p.exists():
            code_pool = DV.Devirtualizer.load_code_pool(pool_p)
        else:
            print(f"pool file not found: {pool_p}")
            return 2

    if p.suffix.lower() == ".jar":
        res = DV.Devirtualizer.devirtualize_jar(
            p, out, code_pool, verify_output=not getattr(args, "no_verify", False),
            classpath=getattr(args, "cp", None) or ())
        print(f"devirt     : {res['devirtualized_methods']} method(s) in "
              f"{res['devirtualized_classes']} class(es) devirtualized")
        print(f"output     : {out}")
        _print_verify(res.get("verify"))
        missing = res.get("unresolved_types") or []
        if missing and res.get("devirtualized_methods"):
            sample = ", ".join(missing[:4])
            if len(missing) > 4:
                sample += f" (+{len(missing) - 4} more)"
            print(f"warning   : {len(missing)} type(s) referenced by the "
                  f"target are not on the classpath ({sample}); rebuilt "
                  f"frames that merge them widen to java/lang/Object, so "
                  f"\"0 rejected\" is conditional. Re-run with --cp <deps> "
                  f"and verify again.")
        if res.get("frame_notes"):
            print(f"frames     : {len(res['frame_notes'])} rebuilt method(s) could "
                  f"not be given a StackMapTable; the classes were kept only "
                  f"because the verifier accepts them, and the gate reverted the "
                  f"rest")
        return 1 if (res.get("verify") or {}).get("reverted") else 0
    elif p.suffix.lower() == ".class":
        cf = CF.parse(p.read_bytes())
        cf, count = DV.Devirtualizer.devirtualize_class_file(
            cf, code_pool, notes=frame_notes)
        out.write_bytes(cf.serialize())
        print(f"devirt     : {count} method(s) devirtualized -> {out}")
        if count:
            # a single class file has no "other version" to fall back to, so the
            # only honest thing left is to say what state it is in
            print(f"frames     : {len(frame_notes)} method(s) without a "
                  f"StackMapTable" if frame_notes
                  else "frames     : every rebuilt method got a StackMapTable")
        return 0
    else:
        print(f"unsupported format: {p.suffix}")
        return 2


cmd_bvm = cmd_devirt  # backward-compatibility alias


def cmd_auto(args: argparse.Namespace) -> int:
    from . import pipeline
    raw = Path(args.input)
    if not raw.exists():
        print(f"no such file or directory: {raw}")
        return 2

    input_path, tmp = _resolve_input(raw)
    out_dir = Path(args.output) if args.output else raw.parent / (raw.stem + "_auto")
    engines_dir = Path(args.engines_dir)

    try:
        res = pipeline.run_pipeline(
            target=input_path,
            out_dir=out_dir,
            engines_dir=engines_dir,
            mc_version=args.mc_version,
            mapping_set=args.mapping_set,
            mappings_file=Path(args.mappings) if args.mappings else None,
            no_deflat=args.no_deflat,
            no_recover=args.no_recover,
            allow_replay=getattr(args, "allow_replay", False),
            strict=getattr(args, "strict", False),
            with_stubs=getattr(args, "with_stubs", True),
            no_natives=args.no_natives,
            no_analyze=args.no_analyze,
            jobs=args.jobs,
            timeout=args.timeout,
            verify_all=args.verify_all,
            launch_web=args.web,
            web_port=args.port,
            clean_work=args.clean_work,
            export_project=getattr(args, "export_project", False),
            compile_verify=getattr(args, "compile", False),
            cp=getattr(args, "cp", "") or "",
            cp_file=Path(args.cp_file) if getattr(args, "cp_file", None) else None,
        )
        return res.exit_code
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)


def cmd_reach(args: argparse.Namespace) -> int:
    from . import callgraph
    raw = Path(args.input)
    if not raw.exists():
        print(f"no such file or directory: {raw}")
        return 2

    custom_eps = [e.strip() for e in args.entrypoints.split(",")] if getattr(args, "entrypoints", None) else None
    print(f"analyzing call graph: {raw.name} ...")
    cg = callgraph.build_callgraph(raw, custom_entrypoints=custom_eps)
    rep = callgraph.compute_reachability(cg)

    print(f"classes      : {rep.total_classes} total -> {len(rep.reachable_classes)} reachable ({rep.reachability_pct}%), {len(rep.dead_classes)} suspected unused ({rep.dead_classes_pct}%)")
    print(f"methods      : {rep.total_methods} declared -> {len(rep.reachable_methods)} reachable, {len(rep.dead_methods)} dead")
    print(f"entrypoints  : {len(rep.entrypoints)} discovered")
    for ep in rep.entrypoints[:6]:
        print(f"  [{ep.kind}] {ep.method.display_name} - {ep.description}")
    if len(rep.entrypoints) > 6:
        print(f"  ... and {len(rep.entrypoints) - 6} more")

    target = getattr(args, "target", None)
    if target:
        path_edges = callgraph.find_path(rep, target)
        print(f"\ntrigger path to '{target}':")
        if path_edges:
            for i, edge in enumerate(path_edges, 1):
                print(f"  {i}. {edge.caller.display_name} --({edge.opcode})--> {edge.callee.display_name}")
        else:
            print(f"  ! Target '{target}' is unreachable from any discovered entrypoint.")

    prune_out = getattr(args, "prune", None)
    if prune_out and raw.is_file():
        # REVIEW 2.3: no entrypoints -> reachability is empty by construction;
        # pruning would delete the whole jar. Refuse, stay report-only.
        if not rep.entrypoints:
            print("\nprune       : REFUSED - no entrypoints discovered "
                  "(no mod metadata, manifest main, or user -e list).")
            print("  Reachability cannot distinguish dead code from unknown "
                  "entry paths; pruning is disabled. The report above is the output.")
        else:
            # Unknown-dependency channels (indy method handles, reflection by
            # name) are invisible to the call graph: keep them conservatively.
            keep_conservative, keep_counts = callgraph.conservative_keepset(raw)
            held_back = keep_conservative - rep.reachable_classes
            prune_set = rep.reachable_classes | keep_conservative
            p_out = Path(prune_out)
            kept, dropped, saved = callgraph.prune_jar(raw, p_out, prune_set)
            print(f"\npruned jar   : {p_out}")
            print(f"  kept {kept} class(es) ({len(rep.reachable_classes)} reachable + "
                  f"{len(held_back)} conservatively held back), "
                  f"dropped {dropped} suspected-unused class(es), saved {saved // 1024} KB")
            if held_back:
                print(f"  hold-back reasons: bootstrap/indy={keep_counts['bsm']}, "
                      f"method-handle targets={keep_counts['handle']}, "
                      f"reflection-by-name={keep_counts['reflect']}")
            if keep_counts.get("unreadable"):
                print(f"  unreadable      : {keep_counts['unreadable']} class(es) "
                      f"kept as-is (parse failure is not proof of being unused)")
            print("  WARNING: this is a 'suspected unused classes' cut, NOT a "
                  "verified slim jar - lambda/reflection/behaviour equivalence "
                  "is not guaranteed. Prefer the reachability report for decisions.")

    dot_out = getattr(args, "dot", None)
    if dot_out:
        d_out = Path(dot_out)
        d_out.parent.mkdir(parents=True, exist_ok=True)
        dot_str = callgraph.export_dot(cg, rep.reachable_methods)
        d_out.write_text(dot_str, encoding="utf-8")
        print(f"graphviz dot : {d_out}")

    json_out = getattr(args, "json", None)
    if json_out:
        j_out = Path(json_out)
        j_out.parent.mkdir(parents=True, exist_ok=True)
        j_data = callgraph.export_json(rep)
        j_out.write_text(json.dumps(j_data, indent=2), encoding="utf-8")
        print(f"json export  : {j_out}")

    if args.output:
        md_out = Path(args.output)
        md_out.parent.mkdir(parents=True, exist_ok=True)
        md_content = callgraph.render_markdown(rep, target_path=target)
        md_out.write_text(md_content, encoding="utf-8")
        print(f"report       : {md_out}")

    return 0


def cmd_project(args: argparse.Namespace) -> int:
    raw = Path(args.input)
    if not raw.exists():
        print(f"no such file or directory: {raw}")
        return 2

    out_dir = Path(args.output) if args.output else raw.parent / (raw.stem + "_project")
    src_dir = Path(args.src) if getattr(args, "src", None) else None
    tmp_decomp: Path | None = None

    # If src_dir not specified, look for candidate decompiled directories
    if src_dir is None:
        cand1 = raw.parent / (raw.stem + "_out") / "src"
        cand2 = raw.parent / (raw.stem + "_auto") / "src"
        cand3 = raw.parent / "src"
        if cand1.is_dir():
            src_dir = cand1
        elif cand2.is_dir():
            src_dir = cand2
        elif cand3.is_dir():
            src_dir = cand3
        else:
            print("note: source directory not specified; running multi-engine decompilation first ...")
            from . import decompile as DC
            tmp_decomp = Path(tempfile.mkdtemp(prefix="jdec_decomp_for_proj_"))
            rep = DC.decompile(raw, tmp_decomp, engines_dir=Path(args.engines_dir))
            DC.write_report(rep, tmp_decomp)
            src_dir = tmp_decomp / "src"

    try:
        _do_project_export(args, raw, out_dir, src_dir)
    finally:
        # the transient decompilation tree exists only to feed the export;
        # it holds thousands of intermediate files, so never leak it
        if tmp_decomp is not None:
            shutil.rmtree(tmp_decomp, ignore_errors=True)
    return 0


def _do_project_export(args: argparse.Namespace, raw: Path, out_dir: Path,
                       src_dir: Path) -> None:
    from . import project
    print(f"project export: {raw.name} -> {out_dir}")
    stats = project.export_project(
        source_jar=raw,
        out_dir=out_dir,
        src_dir=src_dir,
        mc_version=getattr(args, "mc_version", None),
        with_stubs=not getattr(args, "no_stubs", False),
        intermediary_jar=getattr(args, "intermediary_jar", None),
    )
    print(f"  java sources   : {stats['java_files']} file(s) ({stats['files_repaired']} repaired for recompilation)")
    print(f"  resources      : {stats['resources_copied']} file(s) extracted")
    print(f"  stubs bundled  : {stats['stubs_bundled']} mock library(ies)")
    print(f"  scaffold       : build.gradle, settings.gradle, gradle.properties, README.md")

    if getattr(args, "compile", False):
        print("\nrunning javac verification loop ...")
        rep = project.verify_compilation(
            out_dir,
            intermediary_jar=getattr(args, "intermediary_jar", None),
        )
        print(rep.summary())
        if not rep.success and rep.issues:
            print(f"  remaining compilation issues ({len(rep.issues)}):")
            for iss in rep.issues[:5]:
                print(f"    - {iss.file_path.name}:{iss.line_number}: {iss.message}")

    print(f"\nProject is ready! Open with IntelliJ IDEA: File -> Open -> {out_dir / 'build.gradle'}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="jdec",
        description="multi-engine Java decompiler with bytecode-verified output selection",
    )
    p.add_argument("--engines-dir", default=str(DEFAULT_ENGINES_DIR),
                   help="where decompiler jars live")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("probe", help="fingerprint a jar without decompiling")
    sp.add_argument("input")
    sp.set_defaults(func=cmd_probe)

    si = sub.add_parser(
        "ircheck",
        help="byte-exactness gate: parse -> re-assemble -> compare (IR precondition)")
    si.add_argument("input", help="jar, .class file, or a directory of classes")
    si.add_argument("--json", default=None, help="write the full report as JSON")
    si.add_argument("--limit", type=int, default=10,
                    help="show at most N mismatches (default 10)")
    si.set_defaults(func=cmd_ircheck)

    sr = sub.add_parser(
        "reasons",
        help="audit the rewrite journal: every accepted deflat edit must "
             "replay from the original bytes")
    sr.add_argument("original", help="the jar the rewrites started from")
    sr.add_argument("rewritten", nargs="?", default=None,
                    help="optional: also prove every rewritten method is the "
                         "audited derivation")
    sr.add_argument("--json", default=None, help="write the full report as JSON")
    sr.add_argument("--limit", type=int, default=10,
                    help="show at most N problems (default 10)")
    sr.set_defaults(func=cmd_reasons)

    sv = sub.add_parser(
        "verify",
        help="JVM gate: load every class under -Xverify:all "
             "(proves a rewrite did not break the frames)")
    sv.add_argument("input", help="jar or directory of .class files")
    sv.add_argument("--cp", action="append", default=[],
                    help="extra classpath entry (repeatable); pass the original "
                         "jar when verifying a rewritten one")
    sv.add_argument("--limit", type=int, default=0,
                    help="only check the first N classes")
    sv.add_argument("--show", type=int, default=10,
                    help="show at most N problems per bucket")
    sv.add_argument("--java", default=None,
                    help="java executable to verify with (default: JAVA_HOME); "
                         "classes newer than that JVM are reported SKIP, not INVALID")
    sv.add_argument("--timeout", type=int, default=900)
    sv.add_argument("--focus", default=None,
                    help="rewritten-methods file (from `deflat --rewritten`); "
                         "reports how many of them sit in a class that was not judged")
    sv.add_argument("--siblings", action="store_true",
                    help="also put every other *.jar in the target's directory on "
                         "the classpath (one-shot experiment; can shadow the real deps)")
    sv.add_argument("--allow-skipped", action="store_true",
                    help="treat classes newer than this JVM as acceptable")
    sv.add_argument("--json", default=None, help="write the full report as JSON")
    sv.add_argument("--allow-unresolved", action="store_true",
                    help="classes whose dependencies are missing were not judged; "
                         "without this flag they make the run fail")
    sv.set_defaults(func=cmd_verify)

    sb = sub.add_parser(
        "behave",
        help="differential behaviour: run the same cases against two jars "
             "and compare (executes target code; needs --execute)")
    sb.add_argument("original", help="the jar you started from")
    sb.add_argument("rewritten", help="the jar a rewrite produced")
    sb.add_argument("--spec", default=None,
                    help="cases file, one per line: class|method|argTypes|argValues "
                         "(types: int,long,boolean,double,float,short,byte,char,FQCN)")
    sb.add_argument("--derive", action="store_true",
                    help="derive cases from the jar itself: every method whose "
                         "parameters can be synthesised (primitives, String, "
                         "arrays, objects), arity <= 8")
    sb.add_argument("--from", dest="from_file", default=None,
                    help="with --derive: only these methods, as written by "
                         "`deflat --rewritten` (class<TAB>name<TAB>descriptor)")
    sb.add_argument("--per-param", type=int, default=4,
                    help="how many inputs per parameter (default 4)")
    sb.add_argument("--no-stable", dest="stable", action="store_false",
                    help="skip the self-consistency baseline (two runs of the "
                         "original are compared to drop non-deterministic cases)")
    sb.add_argument("--execute", action="store_true",
                    help="required: this runs methods from the target jars")
    sb.add_argument("--no-sandbox", dest="no_sandbox",
                    action="store_true",
                    help="run the replay JVM without the Java sandbox: "
                         "writes outside the work dir, network, exec, "
                         "native libraries and System.exit then become "
                         "allowed (unsafe on untrusted jars)")
    sb.add_argument("--cp", action="append", default=None, metavar="PATH",
                    help="extra classpath entry the target needs to load "
                         "(repeatable). Without it every case in a class whose "
                         "supertype lives elsewhere is unusable")
    sb.add_argument("--engine", choices=["jvm", "interp", "both"], default="jvm",
                    help="jvm: reflective differential; interp: the in-memory "
                         "interpreter; both: run and cross-check")
    sb.add_argument("--trials", type=int, default=4,
                    help="interp: deterministic input vectors per method")
    sb.add_argument("--interp-gate", type=float, default=None, metavar="PCT",
                    help="fail (exit 5) when fewer than PCT%% of ALL rewritten "
                         "methods got a conclusive interp verdict")
    sb.add_argument("--union-gate", type=float, default=None, metavar="PCT",
                    help="fail (exit 5) when fewer than PCT%% of ALL rewritten "
                         "methods were judged by either engine (only with "
                         "--engine both)")
    sb.add_argument("--gate", type=float, default=None, metavar="PCT",
                    help="fail (exit 5) when fewer than PCT%% of the invokable "
                         "methods got a verdict")
    sb.add_argument("--show", type=int, default=10)
    sb.add_argument("--json", default=None)
    sb.set_defaults(func=cmd_behave)

    se = sub.add_parser("engines", help="download / check decompiler engines")
    se.add_argument("--with-ghidra", action="store_true",
                    help="download and prepare Ghidra Headless native engine into engines/ghidra")
    se.set_defaults(func=cmd_engines)

    ss = sub.add_parser("strings",
                        help="dump string constants (survives most obfuscation)")
    ss.add_argument("input")
    ss.add_argument("-o", "--output", default=None)
    ss.add_argument("--grep", default=None,
                    help="only literals containing this text (case-insensitive)")
    ss.add_argument("--suspicious", action="store_true",
                    help="only literals that look like url / ip / path / "
                         "credential / exec / machine-id")
    ss.add_argument("--min-len", type=int, default=1,
                    help="skip literals shorter than this")
    ss.add_argument("--limit", type=int, default=0,
                    help="only scan the first N classes")
    ss.set_defaults(func=cmd_strings)

    sa = sub.add_parser("analyze",
                        help="report what a Minecraft jar hooks into (no decompiling)")
    sa.add_argument("input")
    sa.add_argument("-o", "--output", default=None)
    sa.add_argument("--mc-version", default=None, help="Minecraft version, e.g. 1.20.4")
    sa.add_argument("--mappings", default=None, help="mapping file (proguard/tiny/tsrg)")
    sa.add_argument("--mapping-set", default="auto",
                    choices=["auto", "mojang", "yarn", "mcp", "official-srg", "forge-srg", "none"])
    sa.add_argument("--no-invert", action="store_true",
                    help="mapping file is already obf -> named")
    sa.add_argument("--limit", type=int, default=0,
                    help="only scan the first N classes for signals")
    sa.set_defaults(func=cmd_analyze)

    sd = sub.add_parser("decompile", help="decompile a jar or class directory")
    sd.add_argument("input")
    sd.add_argument("-o", "--output", default=None)
    sd.add_argument("-e", "--engine", default=None,
                    help="comma separated engine order, e.g. cfr,vineflower,procyon")
    sd.add_argument("-j", "--jobs", type=int, default=0, help="parallel JVMs (default: auto)")
    sd.add_argument("--memory", default="2g", help="heap per JVM, e.g. 4g")
    sd.add_argument("--timeout", type=int, default=1800, help="per-chunk timeout in seconds")
    sd.add_argument("--verify-all", action="store_true",
                    help="score every class against its bytecode (slower, full report)")
    sd.add_argument("--resume", action="store_true", help="reuse existing work in the output dir")
    sd.add_argument("--keep-work", action="store_true",
                    help="kept for compatibility; intermediate files are kept "
                         "by default now")
    sd.add_argument("--clean-work", action="store_true",
                    help="delete the intermediate work directory when done "
                         "(it can hold thousands of files, so this is opt-in)")
    sd.add_argument("--deobf", action="store_true",
                    help="force deobfuscation attempt (auto-enabled for obfuscated Minecraft)")
    sd.add_argument("--mc-version", default=None, help="Minecraft version, e.g. 1.20.4")
    sd.add_argument("--mappings", default=None, help="mapping file (proguard/tiny/tsrg)")
    sd.add_argument("--mapping-set", default="auto",
                    choices=["auto", "mojang", "yarn", "mcp", "official-srg", "forge-srg", "none"],
                    help="which mapping source to fetch")
    sd.add_argument("--limit", type=int, default=0,
                    help="only decompile the first N classes (quick trial run)")
    sd.add_argument("--no-invert", action="store_true",
                    help="mapping file is already obf -> named (do not invert proguard)")
    sd.add_argument("--strict-remap", action="store_true",
                    help="fail the run instead of writing back classes that "
                         "could not be remapped (default: warn loudly)")
    sd.set_defaults(func=cmd_decompile)

    snv = sub.add_parser("natives",
                         help="extract shipped native libs and read their PE "
                              "export tables (triage for Ghidra/IDA)")
    snv.add_argument("input")
    snv.add_argument("-o", "--output", default=None,
                     help="output dir for extracted libs + report")
    snv.add_argument("--no-decl", action="store_true",
                     help="skip scanning java-side native declarations")
    snv.add_argument("--decompile", action="store_true",
                     help="decompile extracted native libraries to C pseudo-code using Ghidra Headless")
    snv.add_argument("--ghidra", default=None,
                     help="path to Ghidra installation directory (or set GHIDRA_HOME)")
    snv.add_argument("--fetch-ghidra", action="store_true",
                     help="automatically download Ghidra into engines/ghidra if not present")
    snv.add_argument("--mappings", default=None, dest="mappings_tsv",
                     help="frida regnatives TSV (cls, method, sig, ptr, [base, module]) - "
                          "enables address-table mode for dynamically registered natives")
    snv.set_defaults(func=cmd_natives)

    sdb = sub.add_parser("nativedb",
                         help="build & query an analysis bundle for a dumped "
                              "native library (the IDA+MCP discipline, jdec flavor)")
    sdb.add_argument("input")
    sdb.add_argument("--build", metavar="OUTDIR")
    sdb.add_argument("--search", default=None)
    sdb.add_argument("--strings", action="store_true")
    sdb.set_defaults(func=lambda a: __import__("jdec.nativedb", fromlist=["nativedb"]).main(
        [a.input] + (["--build", a.build] if a.build else []) +
        ([ "--search", a.search] if a.search else []) +
        (["--strings"] if a.strings else [])))

    sop = sub.add_parser("opspool",
                         help="statically decrypt PhantomShield-family "
                              "string pools (DES/CBC + swp inverse, no JVM)")
    sop.add_argument("input")
    sop.add_argument("-o", "--output", default=None,
                     help="output TSV (default: <stem>_ops_pool.tsv)")
    sop.set_defaults(func=cmd_ops_pool)

    si = sub.add_parser("indy",
                        help="enumerate invokedynamic sites and BootstrapMethods")
    si.add_argument("input")
    si.add_argument("-o", "--output", default=None,
                    help="write detailed JSON (stats + sampled sites)")
    si.add_argument("--sample", type=int, default=40,
                    help="how many classes of site detail to include")
    si.set_defaults(func=cmd_indy)

    sr = sub.add_parser("recover",
                        help="self-consistent replay: decrypt indy-encrypted "
                             "strings/constants by running the target's own "
                             "bootstrap machinery (EXECUTES code from the "
                             "target jar; needs a runnable classpath and "
                             "--execute)")
    sr.add_argument("input")
    sr.add_argument("--execute", action="store_true",
                    help="run the replay JVM. WARNING: the replay EXECUTES "
                         "code from the target jar (initializers, decryptors) "
                         "with your process's permissions; a Java sandbox is "
                         "installed by default, but stubs and timeouts are "
                         "not a substitute for it. Without this flag only "
                         "the static spec is generated.")
    sr.add_argument("--no-sandbox", dest="no_sandbox",
                    action="store_true",
                    help="run the replay JVM without the Java sandbox: "
                         "writes outside the work dir, network, exec, "
                         "native libraries and System.exit then become "
                         "allowed (unsafe on untrusted jars)")
    sr.add_argument("-o", "--output", default=None, help="output dir")
    sr.add_argument("--cp", default="", help="extra classpath entries for the "
                   "replay JVM, ';'-separated on Windows (MC jars, libs, stubs)")
    sr.add_argument("--cp-file", dest="cp_file", default=None,
                    help="file containing classpath entries (one per line or "
                         "';'-joined) - use instead of --cp when long")
    sr.add_argument("--java", default="java", help="java executable to run")
    sr.add_argument("--limit", type=int, default=0,
                    help="only recover the first N classes with sites")
    sr.add_argument("--stop-on-error", action="store_true",
                    help="abort the replay JVM on first failure (debug)")
    sr.add_argument("--timeout", type=int, default=1800,
                    help="kill the replay JVM after N seconds (default 1800); "
                         "every site runs its own decryption for real, so "
                         "big samples can need well over 30 minutes")
    sr.add_argument("--rewrite-src", metavar="DIR", default=None,
                    help="rewrite recovered plaintexts into decompiled "
                         ".java sources under DIR (matches the BSM call "
                         "form Cls.method(\"site\", \"cipher\", seed)); "
                         "pair with decompile output src/")
    sr.add_argument("--from-frida", dest="from_frida", default=None,
                    help="ingest external Frida dynamic dump TSV (mappings, trace, or string dump) "
                         "for source rewriting or combining with replay")
    sr.add_argument("--no-stubs", dest="with_stubs", action="store_false", default=True,
                    help="do not inject synthetic Minecraft runtime stubs into classpath")
    sr.set_defaults(func=cmd_recover)

    sp = sub.add_parser("pool",
                        help="string-pool (non-indy) decryption via JVM "
                             "replay: scan call sites -> harvest via "
                             "reflective driver -> rewrite sources")
    sp.add_argument("action", choices=["scan", "harvest", "apply"])
    sp.add_argument("input",
                    help="scan: decompiled src dir; harvest: pool_spec.tsv; "
                         "apply: decompiled src dir")
    sp.add_argument("-o", "--output", default=None,
                    help="scan: spec path; harvest: harvest.tsv path; "
                         "apply: rewritten source tree (default <src>_pool)")
    sp.add_argument("--harvest", default=None,
                    help="apply: harvest.tsv from the harvest step")
    sp.add_argument("--from-frida", dest="from_frida", default=None,
                    help="ingest external Frida dynamic dump TSV for source rewriting")
    sp.add_argument("--cp", default="", help="extra classpath entries for "
                    "the replay JVM, ';'-separated on Windows (MC jars, "
                    "lwjgl-api, libs, stubs)")
    sp.add_argument("--cp-file", dest="cp_file", default=None,
                    help="file containing classpath entries (one per line "
                         "or ';'-joined) - use instead of --cp when long")
    sp.add_argument("--java", default="java", help="java executable to run")
    sp.add_argument("--timeout", type=int, default=3600,
                    help="kill the replay JVM after N seconds (default "
                         "3600); partial output is kept on timeout")
    sp.add_argument("--execute", action="store_true",
                    help="harvest: run the replay JVM. WARNING: the replay "
                         "EXECUTES code from the target jar with your "
                         "process's permissions; a Java sandbox is "
                         "installed by default. Required for the harvest "
                         "step.")
    sp.add_argument("--no-sandbox", dest="no_sandbox",
                    action="store_true",
                    help="run the replay JVM without the Java sandbox: "
                         "writes outside the work dir, network, exec, "
                         "native libraries and System.exit then become "
                         "allowed (unsafe on untrusted jars)")
    sp.add_argument("--no-stubs", dest="with_stubs", action="store_false", default=True,
                    help="do not inject synthetic Minecraft runtime stubs into classpath")
    sp.set_defaults(func=cmd_pool)

    ssc = sub.add_parser("scorecard",
                         help="fixed-metric regression baseline over a set "
                              "of jars (probe+strings, optional "
                              "analyze/decompile); JSON+markdown out, "
                              "--compare diffs against a previous run")
    ssc.add_argument("input", nargs="+",
                     help="jar paths and/or directories (dirs scanned for "
                          "*.jar)")
    ssc.add_argument("-o", "--output", default=None,
                     help="output JSON path (default ./scorecard.json; "
                          "a .md twin is written next to it)")
    ssc.add_argument("--analyze", action="store_true",
                     help="also run the analyze pass (hooks/notes counts)")
    ssc.add_argument("--decompile", action="store_true",
                     help="also decompile (slow; full clean/partial/failed "
                          "counts)")
    ssc.add_argument("--compare", default=None,
                     help="previous scorecard.json - adds a delta section")
    ssc.add_argument("--timeout", type=int, default=1800,
                     help="per-jar decompile timeout (decompile mode only)")
    ssc.set_defaults(func=cmd_scorecard)

    sw = sub.add_parser("web",
                        help="launch lightweight local web workbench for "
                             "interactive multi-engine review & triage")
    sw.add_argument("input", help="decompiled output directory or jar path")
    sw.add_argument("--port", type=int, default=8080, help="HTTP server port")
    sw.add_argument("--no-browser", action="store_true", help="do not auto-open browser")
    sw.set_defaults(func=cmd_web)

    sren = sub.add_parser("rename",
                          help="semantic identifier recovery & LLM prompt export")
    sren.add_argument("input", help="source directory or single .java file")
    sren.add_argument("-o", "--output", default=None,
                      help="output ProGuard mapping file with heuristic suggestions")
    sren.add_argument("--prompt-out", default=None,
                      help="export structured JSON prompt for LLM renaming")
    sren.add_argument("--limit", type=int, default=50,
                      help="maximum members to include in prompt export")
    sren.set_defaults(func=cmd_rename)

    sdef = sub.add_parser("deflat",
                          help="bytecode control flow de-flattening and constant folding")
    sdef.add_argument("input", help="target jar to de-flatten")
    sdef.add_argument("-o", "--output", default=None,
                      help="output jar path (default: <input>_deflat.jar)")
    sdef.add_argument("-j", "--jobs", type=int, default=0, metavar="N",
                      help="rewrite classes in N worker processes (default: "
                           "auto; 1 disables). The process pool is only "
                           "used for the instruction-level path")
    sdef.add_argument("--no-verify", action="store_true",
                      help="skip the -Xverify:all gate (the output is then not "
                           "guaranteed to load)")
    sdef.add_argument("--rewritten", default=None,
                      help="write the class/method/descriptor of every rewritten "
                           "method to this file (input for `behave --from`)")
    sdef.add_argument("--byte-patch", action="store_true",
                      help="use the old byte-patching passes (NOP fill, original "
                           "StackMapTable kept) instead of the instruction-level "
                           "rewrite")
    sdef.add_argument("--recompute-frames", action="store_true",
                      help="with --byte-patch: also regenerate the "
                           "StackMapTables (the instruction-level path always does)")
    sdef.add_argument("--strip-frames", action="store_true",
                      help="byte-patch, then strip the StackMapTables: for feeding "
                           "a decompiler, not for running the jar")
    sdef.add_argument("--no-reasons", action="store_true",
                      help="skip the independent replay of rewrite reasons "
                           "(diagnostics only: the pipeline then reports partial)")
    sdef.add_argument("--cp", action="append", default=None, metavar="PATH",
                      help="extra classpath entry holding the target's libraries "
                           "(repeatable). Frame generation needs the real "
                           "supertypes: without them every merge with a library "
                           "type widens to Object and the verifier rejects the "
                           "method afterwards")
    sdef.set_defaults(func=cmd_deflat)

    def _add_devirt_args(parser):
        parser.add_argument("input", help="target jar or class file to devirtualize")
        parser.add_argument("--no-verify", action="store_true",
                            help="skip the -Xverify:all gate on the output jar "
                                 "(it is then not guaranteed to load)")
        parser.add_argument("-o", "--output", default=None,
                            help="output path (default: <input>_devirt.<ext>)")
        parser.add_argument("--pool", default=None,
                            help="JSON file containing dumped virtual code pools / methods")
        parser.add_argument("--cp", action="append", default=None, metavar="PATH",
                            help="extra classpath entry holding the target's "
                                 "libraries (repeatable); see `deflat --cp`")
        parser.set_defaults(func=cmd_devirt)

    sdevirt = sub.add_parser("devirt",
                             help="devirtualize custom bytecode instruction streams to standard JVM bytecode")
    _add_devirt_args(sdevirt)

    sbvm = sub.add_parser("bvm",
                          help="alias for 'devirt' devirtualization")
    _add_devirt_args(sbvm)

    def _add_auto_args(parser):
        parser.add_argument("input", help="target jar or directory")
        parser.add_argument("-o", "--output", default=None,
                            help="output workspace directory (default: <input>_auto)")
        parser.add_argument("--mc-version", default=None, help="Minecraft version (e.g. 1.20.4, 1.8.9)")
        parser.add_argument("--mapping-set", default="auto",
                            choices=["auto", "mojang", "yarn", "mcp", "official-srg", "none"],
                            help="mapping set for deobfuscation (default: auto)")
        parser.add_argument("--mappings", default=None, help="custom mapping file (proguard/tiny/tsrg)")
        parser.add_argument("--no-deflat", action="store_true", help="skip control flow unflattening")
        parser.add_argument("--no-recover", action="store_true", help="skip dynamic replay string decryption")
        parser.add_argument("--allow-replay", action="store_true",
                            help="enable dynamic replay string decryption - EXECUTES code "
                                 "from the target jar on this machine; opt-in, default off")
        parser.add_argument("--strict", action="store_true",
                            help="CI mode: exit 2 on any stage failure or partial result "
                                 "(default exit codes: 0=success, 1=partial, 2=failed)")
        parser.add_argument("--no-stubs", dest="with_stubs", action="store_false", default=True,
                            help="do not inject synthetic Minecraft runtime stubs into replay classpath")
        parser.add_argument("--no-natives", action="store_true", help="skip native library triage")
        parser.add_argument("--no-analyze", action="store_true", help="skip behavioral analysis / Mixin scan")
        parser.add_argument("-j", "--jobs", type=int, default=0, help="parallel JVMs (0 = auto)")
        parser.add_argument("--timeout", type=int, default=1800, help="decompile timeout in seconds")
        parser.add_argument("--verify-all", action="store_true", help="verify all classes against bytecode")
        parser.add_argument("--web", action="store_true", help="launch Web Workbench on completion")
        parser.add_argument("--port", type=int, default=8080, help="Web Workbench port (default: 8080)")
        parser.add_argument("--clean-work", action="store_true", help="delete intermediate _work directory")
        parser.add_argument("--export-project", action="store_true",
                            help="export complete IDE Gradle project after pipeline")
        parser.add_argument("--compile", action="store_true",
                            help="run javac compilation verification loop after project export")
        parser.add_argument("--cp", default="",
                            help="classpath entries for replay JVM")
        parser.add_argument("--cp-file", dest="cp_file", default=None,
                            help="file with classpath entries for the replay JVM "
                                 "(remapped MC + libraries) - boosts recovery yield")
        parser.set_defaults(func=cmd_auto)

    sauto = sub.add_parser("auto",
                           help="fully automated end-to-end deobfuscation and triage pipeline")
    _add_auto_args(sauto)

    spipe = sub.add_parser("pipeline",
                           help="alias for 'auto' pipeline")
    _add_auto_args(spipe)

    def _add_reach_args(parser):
        parser.add_argument("input", help="target jar or directory")
        parser.add_argument("-e", "--entrypoints", default=None,
                            help="comma-separated custom entrypoint classes or methods (e.g. com/example/Mod:init)")
        parser.add_argument("-t", "--target", default=None,
                            help="target class or method to trace shortest execution path from entrypoints")
        parser.add_argument("--prune", default=None,
                            help="write a jar dropping SUSPECTED-unused classes only "
                                 "(conservative: keeps indy handles and reflection-by-name "
                                 "targets; not a behaviour-safe slim jar)")
        parser.add_argument("--dot", default=None,
                            help="export call graph in Graphviz DOT format")
        parser.add_argument("--json", default=None,
                            help="export reachability metrics to JSON")
        parser.add_argument("-o", "--output", default=None,
                            help="export markdown reachability audit report")
        parser.set_defaults(func=cmd_reach)

    sreach = sub.add_parser("reach",
                            help="entrypoint reachability analysis, call graph and dead code pruning")
    _add_reach_args(sreach)

    scg = sub.add_parser("callgraph",
                         help="alias for 'reach' call graph analysis")
    _add_reach_args(scg)

    def _add_project_args(parser):
        parser.add_argument("input", help="target jar to projectize")
        parser.add_argument("-o", "--output", default=None,
                            help="output project directory (default: <input>_project)")
        parser.add_argument("--src", default=None,
                            help="pre-existing decompiled source directory (default: auto-detected or decompiles)")
        parser.add_argument("--mc-version", default=None,
                            help="Minecraft version target (e.g. 1.20.4, 1.8.9)")
        parser.add_argument("--game-intermediary-jar", "--intermediary-jar", default=None,
                            dest="intermediary_jar",
                            help="path to Minecraft client-intermediary.jar for grounding symbols")
        parser.add_argument("--no-stubs", action="store_true",
                            help="skip bundling mc_stubs.jar into libs/")
        parser.add_argument("--compile", action="store_true",
                            help="run javac compilation diagnostic and auto-repair loop")
        parser.set_defaults(func=cmd_project)

    sproj = sub.add_parser("project",
                           help="export decompiled code as a complete IDE-ready Gradle project")
    _add_project_args(sproj)

    sexp = sub.add_parser("export",
                          help="alias for 'project' IDE project export")
    _add_project_args(sexp)

    return p


def main(argv: list[str] | None = None) -> int:
    if sys.platform == "win32":
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            if hasattr(sys.stderr, "reconfigure"):
                sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
