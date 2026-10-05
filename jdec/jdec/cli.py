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
from . import engines as EN
from . import ghidra_engine as GE
from . import mappings as MP
from . import native_scan as NS
from . import pool as PL
from . import scorecard as SC
from . import strings as ST
from .decompile import decompile, write_report
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
    if p.is_dir():
        tmp = Path(tempfile.mkdtemp()) / "packed.jar"
        p = _dir_to_jar(p, tmp)
    prof = profile_jar(p)
    print(prof.summary())
    return 0


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
    for key, eng in EN.ENGINES.items():
        ok = eng.available(d)
        print(f"  {eng.label:<24} {'available' if ok else 'MISSING'}")
    gh = GE.find_ghidra(engines_dir=d)
    gh_status = f"available ({gh.name})" if gh else "MISSING (pass --with-ghidra to download)"
    print(f"  {'Ghidra Headless':<24} {gh_status}")
    if missing:
        print(f"could not fetch: {', '.join(missing)}")
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
    engines_dir = Path(args.engines_dir)
    missing = EN.ensure_engines(engines_dir, quiet=True)
    usable = [k for k in EN.ENGINES if EN.ENGINES[k].available(engines_dir)]
    if not usable:
        print("no engines present; fetching ...")
        EN.ensure_engines(engines_dir)
        usable = [k for k in EN.ENGINES if EN.ENGINES[k].available(engines_dir)]
    if not usable:
        print("no decompiler engines available, aborting")
        return 1
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
                changed, total = MP.remap_jar(input_path, remapped, mapping)
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
            print(f"recovery  : {rep.coverage_avg * 100:.1f}% of members found in output")
        print(f"elapsed   : {rep.elapsed:.1f}s")
        print(f"source    : {out_dir / 'src'}")
        print(f"report    : {out_dir / 'report.md'}")
        return 0
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
    tri = NS.triage(raw, out_dir, collect_decl=not args.no_decl)

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
            decompiled_info = NS.decompile_libs(tri, out_dir, gh)
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
    if not raw.exists():
        print(f"no such file: {raw}")
        return 2
    out_dir = Path(args.output) if args.output else raw.parent / (raw.stem + "_recovered")
    rc = do_recover(raw, out_dir, cp=args.cp, java=args.java,
                    limit=args.limit, stop_on_error=args.stop_on_error,
                    cp_file=args.cp_file, timeout=args.timeout,
                    with_stubs=getattr(args, "with_stubs", True))
    tsv = out_dir / "recovered.tsv"
    if args.rewrite_src:
        if not Path(args.rewrite_src).is_dir():
            print(f"rewrite-src: no such dir: {args.rewrite_src}")
            return 2
        if not tsv.exists():
            print("rewrite-src: no recovered.tsv produced; nothing to rewrite")
            return 1
        st = do_rewrite_sources(Path(args.rewrite_src), tsv)
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
        print(f"call sites: {st['sites']} ({st['unique']} unique, in "
              f"{st['files_with_sites']} files)")
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
        out_tsv = Path(args.output) if args.output else \
            spec.parent / "pool_harvest.tsv"
        st = PL.harvest(spec, out_tsv, spec.parent, cp=args.cp,
                        cp_file=args.cp_file, java=args.java,
                        timeout=args.timeout,
                        with_stubs=getattr(args, "with_stubs", True))
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
    if not args.harvest:
        print("apply needs --harvest <pool_harvest.tsv>")
        return 2
    hv = Path(args.harvest)
    if not hv.is_file():
        print(f"no such file: {hv}")
        return 2
    out = Path(args.output) if args.output else src.parent / (src.name + "_pool")
    st = PL.apply(src, hv, out)
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


def cmd_deflat(args: argparse.Namespace) -> int:
    from . import deflat
    p = Path(args.input)
    if not p.is_file():
        print(f"no such file: {p}")
        return 2
    out = Path(args.output) if args.output else p.with_name(p.stem + "_deflat" + p.suffix)
    stats = deflat.deflat_jar(p, out)
    print(f"deflat    : {stats['methods_unflattened']} method(s) unflattened across {stats['classes']} class(es)")
    print(f"output    : {out}")
    return 0


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
        pipeline.run_pipeline(
            target=input_path,
            out_dir=out_dir,
            engines_dir=engines_dir,
            mc_version=args.mc_version,
            mapping_set=args.mapping_set,
            mappings_file=Path(args.mappings) if args.mappings else None,
            no_deflat=args.no_deflat,
            no_recover=args.no_recover,
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
        )
        return 0
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

    print(f"classes      : {rep.total_classes} total -> {len(rep.reachable_classes)} reachable ({rep.reachability_pct}%), {len(rep.dead_classes)} dead/unused ({rep.dead_classes_pct}%)")
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
        p_out = Path(prune_out)
        kept, dropped, saved = callgraph.prune_jar(raw, p_out, rep.reachable_classes)
        print(f"\npruned jar   : {p_out}")
        print(f"  kept {kept} reachable class(es), dropped {dropped} dead class(es), saved {saved // 1024} KB")

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
    from . import project
    raw = Path(args.input)
    if not raw.exists():
        print(f"no such file or directory: {raw}")
        return 2

    out_dir = Path(args.output) if args.output else raw.parent / (raw.stem + "_project")
    src_dir = Path(args.src) if getattr(args, "src", None) else None

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

    print(f"project export: {raw.name} -> {out_dir}")
    stats = project.export_project(
        source_jar=raw,
        out_dir=out_dir,
        src_dir=src_dir,
        mc_version=getattr(args, "mc_version", None),
        with_stubs=not getattr(args, "no_stubs", False),
    )
    print(f"  java sources   : {stats['java_files']} file(s) ({stats['files_repaired']} repaired for recompilation)")
    print(f"  resources      : {stats['resources_copied']} file(s) extracted")
    print(f"  stubs bundled  : {stats['stubs_bundled']} mock library(ies)")
    print(f"  scaffold       : build.gradle, settings.gradle, gradle.properties, README.md")

    if getattr(args, "compile", False):
        print("\nrunning javac verification loop ...")
        rep = project.verify_compilation(out_dir)
        print(rep.summary())
        if not rep.success and rep.issues:
            print(f"  remaining compilation issues ({len(rep.issues)}):")
            for iss in rep.issues[:5]:
                print(f"    - {iss.file_path.name}:{iss.line_number}: {iss.message}")

    print(f"\nProject is ready! Open with IntelliJ IDEA: File -> Open -> {out_dir / 'build.gradle'}")
    return 0


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
    snv.set_defaults(func=cmd_natives)

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
                             "bootstrap machinery (needs a runnable classpath)")
    sr.add_argument("input")
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
    sdef.set_defaults(func=cmd_deflat)

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
                            help="output slimmed jar containing only reachable classes")
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
