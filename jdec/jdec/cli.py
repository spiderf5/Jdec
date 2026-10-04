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
from . import mappings as MP
from . import native_scan as NS
from . import strings as ST
from .decompile import decompile, write_report
from .probe import profile_jar
from .recover import recover as do_recover

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
    missing = EN.ensure_engines(d)
    print(f"engines dir: {d}")
    for key, eng in EN.ENGINES.items():
        ok = eng.available(d)
        print(f"  {eng.label:<24} {'available' if ok else 'MISSING'}")
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
        print(f"tagged     : {tagged} literal(s) look like url / path / credential "
              f"/ exec / machine-id")
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
    report = out_dir / "native-triage.md"
    NS.write_report(tri, raw.name, report)
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
    return do_recover(raw, out_dir, cp=args.cp, java=args.java,
                      limit=args.limit, stop_on_error=args.stop_on_error,
                      cp_file=args.cp_file)


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
                    choices=["auto", "mojang", "yarn", "mcp", "none"])
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
                    choices=["auto", "mojang", "yarn", "mcp", "none"],
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
    sr.set_defaults(func=cmd_recover)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
