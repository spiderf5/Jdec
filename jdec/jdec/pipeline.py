"""Automated end-to-end deobfuscation and analysis pipeline for jdec.

Orchestrates all analysis and deobfuscation capabilities into a single flow:
Phase 1: Probe & Profiling (structure, MC version, obfuscator fingerprints)
Phase 2: Bytecode Pre-cleaning (CFG de-flattening & constant folding)
Phase 3: Symbol Remapping (Mojang / Yarn / MCP / TSRG2 / Official-SRG)
Phase 4: Multi-Engine Decompilation & Verification Scoring
Phase 5: Dynamic Replay Decryption (BSM indy & string-pool with mc_stubs)
Phase 6: Native Triage & Reverse JNI Call Graph
Phase 7: Behavioral Analysis (Mixin hooks, refmap, threat signals, strings)
Phase 8: Master Executive Report & Web Workbench Launch
"""

from __future__ import annotations

import json
import shutil
import sys
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import analyze as AZ
from . import bsm as BM
from . import decompile as DC
from . import deflat as DF
from . import engines as EN
from . import mappings as MP
from . import native_scan as NS
from . import pool as PL
from . import probe as PB
from . import recover as RC
from . import strings as ST
from . import web as WB


@dataclass
class PipelineResult:
    target_jar: Path
    out_dir: Path
    profile: PB.JarProfile
    unflattened_methods: int = 0
    remapped_classes: int = 0
    mapping_name: str | None = None
    decompile_total: int = 0
    decompile_ok: int = 0
    decompile_partial: int = 0
    decompile_failed: int = 0
    coverage_avg: float | None = None
    indy_recovered: int = 0
    pool_recovered: int = 0
    native_libs_count: int = 0
    native_methods_count: int = 0
    reverse_jni_calls: int = 0
    dynamic_registered_jni: int = 0
    mixin_hooks_count: int = 0
    patched_classes_count: int = 0
    threat_strings_count: int = 0
    signal_classes_count: int = 0
    elapsed_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "target": str(self.target_jar.name),
            "out_dir": str(self.out_dir),
            "profile": {
                "classes": self.profile.classes,
                "obfuscation": self.profile.obfuscation,
                "obfuscator": self.profile.obfuscator,
                "minecraft": self.profile.is_minecraft,
                "mc_flavor": self.profile.mc_flavor,
                "mc_version": self.profile.mc_version,
                "signatures": self.profile.signatures,
            },
            "metrics": {
                "unflattened_methods": self.unflattened_methods,
                "remapped_classes": self.remapped_classes,
                "mapping": self.mapping_name,
                "decompile_total": self.decompile_total,
                "decompile_ok": self.decompile_ok,
                "decompile_partial": self.decompile_partial,
                "decompile_failed": self.decompile_failed,
                "coverage_avg": self.coverage_avg,
                "indy_recovered": self.indy_recovered,
                "pool_recovered": self.pool_recovered,
                "native_libs": self.native_libs_count,
                "native_methods": self.native_methods_count,
                "reverse_jni_calls": self.reverse_jni_calls,
                "dynamic_registered_jni": self.dynamic_registered_jni,
                "mixin_hooks": self.mixin_hooks_count,
                "patched_classes": self.patched_classes_count,
                "threat_strings": self.threat_strings_count,
                "signal_classes": self.signal_classes_count,
                "elapsed_seconds": round(self.elapsed_seconds, 2),
            }
        }


def _mapping_set_for(declared: str, prof: PB.JarProfile) -> str:
    if declared != "auto":
        return declared
    flavor = prof.mc_flavor or ""
    if flavor == "Fabric" or flavor == "Quilt":
        return "yarn"
    if flavor == "Forge" or flavor == "NeoForge":
        v = prof.mc_version or ""
        try:
            parts = [int(p) for p in v.split(".") if p.isdigit()]
            if len(parts) >= 2 and (parts[0] > 1 or parts[1] >= 16):
                return "official-srg"
        except Exception:
            pass
        return "mcp"
    return "mojang"


def write_pipeline_summary(res: PipelineResult, out_dir: Path) -> tuple[Path, Path]:
    """Generate Markdown and JSON executive summary reports."""
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / "pipeline_summary.md"
    json_path = out_dir / "pipeline_summary.json"

    # Write JSON
    json_path.write_text(json.dumps(res.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

    # Write Markdown
    cov_str = f"{res.coverage_avg * 100:.1f}%" if res.coverage_avg is not None else "N/A"
    mc_desc = f"{res.profile.mc_flavor or 'Unknown'} {res.profile.mc_version or ''}".strip()
    if not mc_desc:
        mc_desc = "Not detected / Non-Minecraft"

    md_lines = [
        f"# jdec Pipeline Executive Summary: `{res.target_jar.name}`",
        "",
        "> [!NOTE]",
        f"> Automated pipeline execution finished in **{res.elapsed_seconds:.2f}s**.",
        "",
        "## Target Fingerprint",
        f"- **File**: `{res.target_jar.name}` ({res.profile.classes} classes, {res.profile.entries} total entries)",
        f"- **Obfuscation Score**: **{res.profile.obfuscation}/100**",
        f"- **Identified Obfuscator**: `{res.profile.obfuscator or 'None / Unknown'}`",
        f"- **Minecraft Environment**: `{mc_desc}`",
    ]

    if res.profile.signatures:
        md_lines.append(f"- **Structural Signatures**: {', '.join(f'`{s}`' for s in res.profile.signatures)}")

    md_lines.extend([
        "",
        "## Pipeline Outcomes & Quality Metrics",
        "",
        "| Stage | Metric | Result |",
        "| :--- | :--- | :--- |",
        f"| **CFG De-flattening** | Unflattened Method Transitions | **{res.unflattened_methods}** |",
        f"| **Symbol Remapping** | Remapped Classes | **{res.remapped_classes}** ({res.mapping_name or 'None'}) |",
        f"| **Decompilation** | Clean / Partial / Failed | **{res.decompile_ok}** / {res.decompile_partial} / {res.decompile_failed} |",
        f"| **Ground-Truth Verification**| Member Signature Recovery | **{cov_str}** |",
        f"| **String Decryption** | Indy + Pool Plaintexts Recovered | **{res.indy_recovered + res.pool_recovered}** ({res.indy_recovered} indy, {res.pool_recovered} pool) |",
        f"| **Native Code Triage** | Shipped Libs / Methods / Rev JNI | **{res.native_libs_count}** libs, **{res.native_methods_count}** methods, **{res.reverse_jni_calls}** reverse calls |",
        f"| **Game Hooks** | Mixin Injections / Patched Classes | **{res.mixin_hooks_count}** hooks across **{res.patched_classes_count}** classes |",
        f"| **High-Risk Signals** | Threat-Tagged Strings / Signal Classes| **{res.threat_strings_count}** strings, **{res.signal_classes_count}** classes |",
        "",
        "## Generated Workspace Artifacts",
        "- `src/` — Clean, decompiled Java source code with decrypted plaintexts substituted.",
        "- `report.md` / `report.json` — Per-class decompiler engine selection and member coverage score.",
        "- `analysis.md` / `analysis.json` — In-depth Mixin hook analysis and high-risk capability signals.",
        "- `strings.tsv` / `strings.json` — All string literals with security tags (webhook, C2, IP, crypto).",
    ])

    if res.native_libs_count > 0:
        md_lines.append("- `native-triage.md` / `natives/ghidra_annotate.py` — Native library analysis and Ghidra script.")

    md_lines.append("")
    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    return md_path, json_path


def run_pipeline(
    target: Path,
    out_dir: Path,
    engines_dir: Path | None = None,
    mc_version: str | None = None,
    mapping_set: str = "auto",
    mappings_file: Path | None = None,
    no_deflat: bool = False,
    no_recover: bool = False,
    with_stubs: bool = True,
    no_natives: bool = False,
    no_analyze: bool = False,
    jobs: int = 0,
    timeout: int = 1800,
    verify_all: bool = False,
    launch_web: bool = False,
    web_port: int = 8080,
    clean_work: bool = False,
    export_project: bool = False,
    compile_verify: bool = False,
) -> PipelineResult:
    """Execute end-to-end deobfuscation and triage pipeline."""
    t0 = time.time()
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir = out_dir / "_pipeline"
    work_dir.mkdir(parents=True, exist_ok=True)

    if engines_dir is None:
        engines_dir = Path(__file__).resolve().parent.parent / "engines"
    EN.ensure_engines(engines_dir, quiet=True)

    print(f"=== jdec Automated Pipeline ===")
    print(f"target  : {target}")
    print(f"output  : {out_dir}")
    print()

    # Phase 1: Probe
    print("[1/7] Probing & profiling target ...")
    prof = PB.profile_jar(target)
    print(f"      entries={prof.entries}, classes={prof.classes}, "
          f"obf={prof.obfuscation}/100 ({prof.obfuscator or 'Unknown'})")
    if prof.is_minecraft:
        print(f"      minecraft: {prof.mc_flavor} {prof.mc_version or 'unknown version'}")

    current_jar = target
    unflattened_count = 0

    # Phase 2: Bytecode Pre-cleaning (CFG De-flattening)
    if not no_deflat:
        print("[2/7] Bytecode pre-cleaning (CFG de-flattening & constant folding) ...")
        preclean_jar = work_dir / "precleaned.jar"
        try:
            stats = DF.deflat_jar(current_jar, preclean_jar)
            unflattened_count = stats.get("methods_unflattened", 0)
            if unflattened_count > 0:
                print(f"      unflattened {unflattened_count} method(s) across {stats.get('classes', 0)} class(es)")
                current_jar = preclean_jar
            else:
                print("      no flattened switch dispatchers detected")
        except Exception as exc:
            print(f"      ! de-flattening skipped: {exc}")

    # Phase 3: Minecraft Symbol Remapping
    remapped_count = 0
    mapping_obj = None
    mapping_desc = None
    want_deobf = mapping_set != "none" and (
        mappings_file is not None or (prof.is_minecraft and prof.obfuscation >= 40)
    )

    if want_deobf:
        version = mc_version or prof.mc_version
        if mappings_file:
            print(f"[3/7] Loading custom mappings from {mappings_file.name} ...")
            mapping_obj = MP.load_mapping(mappings_file)
            mapping_desc = mappings_file.name
        elif version:
            try:
                resolved_set = _mapping_set_for(mapping_set, prof)
                print(f"[3/7] Auto-fetching {resolved_set} mappings for {version} ...")
                cache = out_dir.parent / ".jdec_mappings"
                mapping_obj = MP.auto_fetch(version, resolved_set, cache)
                mapping_desc = mapping_obj.describe() if mapping_obj else None
            except Exception as exc:
                print(f"      ! mapping fetch failed: {exc}")
                mapping_obj = None
        else:
            print("[3/7] ! Minecraft version unknown; skipping symbol remapping")

        if mapping_obj is not None:
            remapped_jar = work_dir / "remapped.jar"
            try:
                remapped_count, total = MP.remap_jar(current_jar, remapped_jar, mapping_obj)
                print(f"      remapped {remapped_count}/{total} classes -> remapped.jar")
                if remapped_count > 0:
                    current_jar = remapped_jar
            except Exception as exc:
                print(f"      ! remapping failed: {exc}")
    else:
        print("[3/7] Symbol remapping: skipped (not needed or disabled)")

    # Phase 4: Multi-Engine Decompilation & Verification
    print("[4/7] Multi-engine decompilation with bytecode verification ...")
    src_dir = out_dir / "src"
    rep = DC.decompile(
        current_jar, out_dir, engines_dir=engines_dir,
        jobs=jobs, timeout=timeout, verify_all=verify_all,
        clean_work=False, limit=0
    )
    DC.write_report(rep, out_dir)
    print(f"      results: {rep.ok} clean, {rep.partial} partial, {rep.failed + rep.missing} failed")
    if rep.coverage_avg is not None:
        print(f"      member recovery coverage: {rep.coverage_avg * 100:.1f}%")

    # Phase 5: Dynamic Decryption Replay (BSM Indy + Pool Recovery)
    indy_recovered = 0
    pool_recovered = 0
    if not no_recover:
        print("[5/7] Dynamic JVM replay string decryption ...")
        # 1. BSM Indy
        try:
            census = BM.census_jar(current_jar)
            if census.sites > 0:
                print(f"      inspecting {census.sites} indy callsite(s) across {census.classes_with_sites} class(es) ...")
                rec_dir = work_dir / "recover"
                rc_code = RC.recover(current_jar, rec_dir, timeout=120, with_stubs=with_stubs)
                rec_tsv = rec_dir / "recovered.tsv"
                if rec_tsv.is_file():
                    st_rw = RC.rewrite_sources(src_dir, rec_tsv)
                    indy_recovered = st_rw.get("replaced", 0)
                    if indy_recovered > 0:
                        print(f"      indy: {indy_recovered} callsite(s) decrypted and rewritten")
        except Exception as exc:
            print(f"      ! indy decryption skipped: {exc}")

        # 2. String Pool
        try:
            st_scan = PL.scan(src_dir)
            if st_scan.get("accessors", 0) > 0 and st_scan.get("unique", 0) > 0:
                print(f"      inspecting {st_scan['unique']} pool site(s) across {st_scan['pool_classes']} accessor class(es) ...")
                pool_dir = work_dir / "pool"
                harvest_tsv = pool_dir / "pool_harvest.tsv"
                PL.harvest(st_scan["spec"], harvest_tsv, pool_dir, timeout=120, with_stubs=with_stubs)
                if harvest_tsv.is_file():
                    tmp_pool = work_dir / "src_pool"
                    st_apply = PL.apply(src_dir, harvest_tsv, tmp_pool)
                    pool_recovered = st_apply.get("replaced", 0)
                    if pool_recovered > 0:
                        shutil.rmtree(src_dir, ignore_errors=True)
                        shutil.copytree(tmp_pool, src_dir)
                        shutil.rmtree(tmp_pool, ignore_errors=True)
                        print(f"      pool: {pool_recovered} callsite(s) decrypted and rewritten")
        except Exception as exc:
            print(f"      ! pool decryption skipped: {exc}")
    else:
        print("[5/7] Dynamic replay string decryption: disabled")

    # Phase 6: Native Triage & Behavioral Analysis
    nat_libs_count = 0
    nat_methods_count = 0
    rev_jni_count = 0
    dyn_jni_count = 0

    if not no_natives:
        print("[6/7] Native library & behavioral triage ...")
        try:
            nat_dir = out_dir / "natives"
            tri = NS.triage(current_jar, nat_dir, collect_decl=True)
            if tri.libs or tri.native_decl:
                NS.write_report(tri, current_jar.name, out_dir / "native-triage.md")
                NS.write_ghidra_annotation_script(tri, nat_dir / "ghidra_annotate.py")
                nat_libs_count = len(tri.libs)
                nat_methods_count = len(tri.native_decl)
                rev_jni_count = sum(len(l.reverse_jni) for l in tri.libs)
                dyn_jni_count = sum(len(l.dynamic_methods) for l in tri.libs)
                print(f"      native: {nat_libs_count} library(ies), {nat_methods_count} native method(s), "
                      f"{rev_jni_count} reverse JNI call(s)")
            else:
                print("      native: no native binaries found")
        except Exception as exc:
            print(f"      ! native triage failed: {exc}")
    else:
        print("[6/7] Native library triage: disabled")

    # Behavioral analysis (Mixin hooks & threat signals)
    hooks_count = 0
    patched_cls_count = 0
    signals_count = 0
    threat_count = 0

    if not no_analyze:
        try:
            a = AZ.analyze(current_jar, mapping=mapping_obj, mapping_desc=mapping_desc)
            AZ.write_analysis(a, out_dir)
            hooks_count = len(a.hooks)
            patched_cls_count = len(a.hook_groups())
            signals_count = len(a.classes)
            print(f"      analysis: {hooks_count} Mixin hook(s) across {patched_cls_count} class(es), "
                  f"{signals_count} high-risk signal class(es)")
        except Exception as exc:
            print(f"      ! analysis failed: {exc}")

        try:
            d = ST.dump_strings(current_jar)
            ST.write_tsv(d, out_dir / "strings.tsv")
            ST.write_json(d, out_dir / "strings.json")
            tc = d.tag_counts()
            threat_count = sum(tc.values())
            print(f"      strings: {d.total} literal(s) dumped, {threat_count} threat-tagged")
        except Exception as exc:
            print(f"      ! strings dump failed: {exc}")
    else:
        print("      behavioral analysis: disabled")

    # Phase 7: Master Executive Summary Report
    print("[7/7] Generating pipeline summary ...")
    elapsed = time.time() - t0
    res = PipelineResult(
        target_jar=target,
        out_dir=out_dir,
        profile=prof,
        unflattened_methods=unflattened_count,
        remapped_classes=remapped_count,
        mapping_name=mapping_desc,
        decompile_total=rep.total,
        decompile_ok=rep.ok,
        decompile_partial=rep.partial,
        decompile_failed=rep.failed + rep.missing,
        coverage_avg=rep.coverage_avg,
        indy_recovered=indy_recovered,
        pool_recovered=pool_recovered,
        native_libs_count=nat_libs_count,
        native_methods_count=nat_methods_count,
        reverse_jni_calls=rev_jni_count,
        dynamic_registered_jni=dyn_jni_count,
        mixin_hooks_count=hooks_count,
        patched_classes_count=patched_cls_count,
        threat_strings_count=threat_count,
        signal_classes_count=signals_count,
        elapsed_seconds=elapsed,
    )
    md_sum, json_sum = write_pipeline_summary(res, out_dir)
    print(f"      summary: {md_sum}")
    print(f"      json   : {json_sum}")
    print(f"=== Pipeline finished in {elapsed:.2f}s ===")

    # Phase 8: Automated IDE Project Export
    if export_project:
        print("\n[8/8] Exporting complete IDE Gradle project ...")
        from . import project as PJ
        proj_dir = out_dir / "project"
        p_stats = PJ.export_project(
            source_jar=target,
            out_dir=proj_dir,
            src_dir=out_dir / "src",
            mc_version=prof.mc_version,
            with_stubs=True,
        )
        print(f"      project: {proj_dir} ({p_stats['java_files']} sources, {p_stats['files_repaired']} repaired)")
        if compile_verify:
            print("      running javac compilation verification ...")
            c_rep = PJ.verify_compilation(proj_dir)
            print(f"      {c_rep.summary()}")

    if clean_work:
        shutil.rmtree(work_dir, ignore_errors=True)

    if launch_web:
        print()
        print("Launching Web Workbench ...")
        WB.start_server(out_dir, port=web_port, open_browser=True)

    return res
