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

# Stage status vocabulary (REVIEW 2.2): a stage is one of exactly these.
STAGE_OK = "ok"
STAGE_PARTIAL = "partial"
STAGE_SKIPPED = "skipped"
STAGE_FAILED = "failed"

_EXIT_CODES = {"success": 0, "partial": 1, "failed": 2}


@dataclass
class StageStatus:
    """Outcome of one pipeline stage: 成功/部分成功/跳过/失败 + 原因."""
    name: str
    status: str = STAGE_SKIPPED
    detail: str = ""

    def to_dict(self) -> dict:
        return {"stage": self.name, "status": self.status, "detail": self.detail}


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
    stages: list[StageStatus] = field(default_factory=list)
    strict: bool = False

    def stage(self, name: str) -> StageStatus:
        for s in self.stages:
            if s.name == name:
                return s
        raise KeyError(f"unknown stage: {name}")

    @property
    def overall_status(self) -> str:
        statuses = [s.status for s in self.stages]
        if any(s == STAGE_FAILED for s in statuses):
            return "failed"
        if any(s == STAGE_PARTIAL for s in statuses):
            return "partial"
        return "success"

    @property
    def exit_code(self) -> int:
        """0 = all stages ok/skipped, 1 = partial results, 2 = stage failure.

        With strict=True any non-success outcome escalates to 2 (CI mode).
        """
        code = _EXIT_CODES[self.overall_status]
        if self.strict and code != 0:
            return 2
        return code

    def to_dict(self) -> dict:
        return {
            # absolute path, not the bare file name: consumers (the web
            # workbench, external tooling) resolve it to rebuild the call
            # graph, and `Path("client.jar")` only exists if the process
            # happens to run inside the jar's directory.
            "target": str(self.target_jar.resolve()),
            "target_name": self.target_jar.name,
            "out_dir": str(self.out_dir),
            "overall": self.overall_status,
            "exit_code": self.exit_code,
            "stages": [s.to_dict() for s in self.stages],
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


def _split_cp(cp: str) -> list[str]:
    """`a.jar;b.jar` -> the two entries, ignoring blanks."""
    if not cp:
        return []
    sep = ";" if (";" in cp and ":" not in cp.replace("\\", "")) else ":"
    out = []
    for part in cp.split(sep):
        part = part.strip()
        if part:
            out.append(part)
    return out


def deflat_stage_status(stats: dict) -> tuple[str, str]:
    """(status, detail) for the pre-cleaning stage, from deflat's own report.

    Two things must survive into the summary: how much of the rewrite took, and
    whether the bytecode we hand to every later stage was actually loaded by a
    JVM. A rewrite the verifier had to put back, or one nobody checked, is
    `partial` — the artifact is usable, the rewrite is not complete, and saying
    "ok" would erase the difference.
    """
    n = stats.get("methods_unflattened", 0)
    classes = stats.get("classes", 0)
    v = stats.get("verify") or {}
    head = f"unflattened {n} method(s) in {classes} class(es)"
    if v.get("skipped"):
        return STAGE_PARTIAL, f"{head}; verify skipped: {v['skipped']}"
    if not v:
        return STAGE_PARTIAL, f"{head}; output not verified"
    bits = [f"{v.get('verified', 0)} pass -Xverify:all"]
    if v.get("reverted"):
        bits.append(f"{len(v['reverted'])} reverted")
    if v.get("still_invalid"):
        bits.append(f"{len(v['still_invalid'])} invalid in the input")
    if v.get("unresolved"):
        bits.append(f"{v['unresolved']} not judged (missing deps)")
    refused = stats.get("reason_refused") or []
    if refused:
        bits.append(f"{len(refused)} rewrite(s) kept original: no replayable "
                    f"derivation")
    status = STAGE_PARTIAL if (v.get("reverted") or refused) else STAGE_OK
    return status, f"{head}; " + ", ".join(bits)


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
        f"> Overall status: **{res.overall_status.upper()}** (exit code {res.exit_code}"
        + (", strict mode" if res.strict else "") + ").",
        "",
    ]

    if res.stages:
        md_lines.extend([
            "## Stage Status",
            "",
            "| Stage | Status | Detail |",
            "| :--- | :--- | :--- |",
        ])
        for s in res.stages:
            # detail 是自由文本（可能含路径、异常摘要）：| 和换行会破坏
            # Markdown 表格结构，先压平
            detail = (s.detail or "—").replace("|", "\\|")
            detail = " ".join(detail.split())
            md_lines.append(f"| `{s.name}` | **{s.status}** | {detail} |")
        md_lines.append("")

    md_lines.extend([
        "## Target Fingerprint",
        f"- **File**: `{res.target_jar.name}` ({res.profile.classes} classes, {res.profile.entries} total entries)",
        f"- **Obfuscation Score**: **{res.profile.obfuscation}/100**",
        f"- **Identified Obfuscator**: `{res.profile.obfuscator or 'None / Unknown'}`",
        f"- **Minecraft Environment**: `{mc_desc}`",
    ])

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
        f"| **Ground-Truth Verification**| Member Name-Hit Rate | **{cov_str}** |",
        f"| **String Decryption** | Indy + Pool Plaintexts Recovered | **{res.indy_recovered + res.pool_recovered}** ({res.indy_recovered} indy, {res.pool_recovered} pool) |",
        f"| **Native Code Triage** | Shipped Libs / Methods / Rev JNI | **{res.native_libs_count}** libs, **{res.native_methods_count}** methods, **{res.reverse_jni_calls}** reverse calls |",
        f"| **Game Hooks** | Mixin Injections / Patched Classes | **{res.mixin_hooks_count}** hooks across **{res.patched_classes_count}** classes |",
        f"| **High-Risk Signals** | Threat-Tagged Strings / Signal Classes| **{res.threat_strings_count}** strings, **{res.signal_classes_count}** classes |",
        "",
        "## Generated Workspace Artifacts",
        "- `src/` — Clean, decompiled Java source code with decrypted plaintexts substituted.",
        "- `report.md` / `report.json` — Per-class decompiler engine selection and member name-hit score.",
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
    cp: str = "",
    cp_file: Path | None = None,
    allow_replay: bool = False,
    strict: bool = False,
) -> PipelineResult:
    """Execute end-to-end deobfuscation and triage pipeline."""
    t0 = time.time()
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir = out_dir / "_pipeline"
    work_dir.mkdir(parents=True, exist_ok=True)
    stages: list[StageStatus] = []

    def record(name: str, status: str, detail: str = "") -> StageStatus:
        st = StageStatus(name=name, status=status, detail=detail)
        stages.append(st)
        return st

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
    record("probe", STAGE_OK,
           f"{prof.classes} classes, obf={prof.obfuscation}/100 "
           f"({prof.obfuscator or 'Unknown'})")
    print(f"      entries={prof.entries}, classes={prof.classes}, "
          f"obf={prof.obfuscation}/100 ({prof.obfuscator or 'Unknown'})")
    if prof.is_minecraft:
        print(f"      minecraft: {prof.mc_flavor} {prof.mc_version or 'unknown version'}")

    current_jar = target
    original_jar = target      # Phase 5 的重放要和 classpath 同命名空间:
    unflattened_count = 0      # 用户提供的 cp 对应原始 jar 的命名空间

    # Phase 2: Bytecode Pre-cleaning (CFG De-flattening)
    if not no_deflat:
        print("[2/7] Bytecode pre-cleaning (CFG de-flattening & constant folding) ...")
        preclean_jar = work_dir / "precleaned.jar"
        try:
            # The rewrite produces the artifact every later stage reads, so it
            # is gated here rather than at the end: frames are recomputed, the
            # result is loaded under -Xverify:all, and any class the verifier
            # rejects is put back byte for byte. Frames used to be stripped on
            # purpose (stale ones made CFR drop classes); they are no longer
            # stale, so stripping would only make the file unloadable for
            # nothing.
            # 用户的 cp 里放着这个 jar 依赖的库(如 JavaFX)。帧合并需要真实
            # 父类,否则每次与库类型相遇都会退化成 Object,验证器随后拒绝。
            stats = DF.deflat_jar(current_jar, preclean_jar,
                                  classpath=_split_cp(cp))
            unflattened_count = stats.get("methods_unflattened", 0)
            status, detail = deflat_stage_status(stats)
            v_note = detail.split("; ", 1)[1] if "; " in detail else ""
            if unflattened_count > 0:
                print(f"      unflattened {unflattened_count} method(s) across {stats.get('classes', 0)} class(es); {v_note}")
                # 有类被验证器拒绝并回退 -> 阶段是 partial，不是 ok：
                # 产物可用，但改写没有全量生效，这个区别必须留在报告里
                record("deflat", status, detail)
                # 不直接切 current_jar:反平坦化对某些目标(如 CFR 本就能
                # 结构化的 ZKM goto 洪水)是净伤害。原 jar 先正常反编译,
                # Phase 4 末尾按 clean 数对比决定是否采用 deflatted 版。
            else:
                print(f"      no flattened switch dispatchers detected{v_note}")
                record("deflat", STAGE_OK, f"no flattened switch dispatchers detected{v_note}")
        except Exception as exc:
            print(f"      ! de-flattening skipped: {exc}")
            record("deflat", STAGE_FAILED, f"de-flattening error: {exc}")
    else:
        record("deflat", STAGE_SKIPPED, "disabled (--no-deflat)")

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
            try:
                mapping_obj = MP.load_mapping(mappings_file)
                mapping_desc = mappings_file.name
            except Exception as exc:
                print(f"      ! mapping load failed: {exc}")
                record("remap", STAGE_FAILED, f"mapping load failed: {exc}")
        elif version:
            try:
                resolved_set = _mapping_set_for(mapping_set, prof)
                print(f"[3/7] Auto-fetching {resolved_set} mappings for {version} ...")
                cache = out_dir.parent / ".jdec_mappings"
                mapping_obj = MP.auto_fetch(version, resolved_set, cache)
                mapping_desc = mapping_obj.describe() if mapping_obj else None
            except Exception as exc:
                print(f"      ! mapping fetch failed: {exc}")
                record("remap", STAGE_FAILED, f"mapping fetch failed: {exc}")
                mapping_obj = None
        else:
            print("[3/7] ! Minecraft version unknown; skipping symbol remapping")
            record("remap", STAGE_SKIPPED, "minecraft version unknown")

        if mapping_obj is not None:
            remapped_jar = work_dir / "remapped.jar"
            try:
                remapped_count, total = MP.remap_jar(current_jar, remapped_jar, mapping_obj)
                print(f"      remapped {remapped_count}/{total} classes -> remapped.jar")
                record("remap", STAGE_OK, f"remapped {remapped_count}/{total} classes ({mapping_desc or 'custom'})")
                if remapped_count > 0:
                    current_jar = remapped_jar
            except Exception as exc:
                print(f"      ! remapping failed: {exc}")
                record("remap", STAGE_FAILED, f"remap failed: {exc}")
    else:
        print("[3/7] Symbol remapping: skipped (not needed or disabled)")
        record("remap", STAGE_SKIPPED, "not needed or disabled")

    # Phase 4: Multi-Engine Decompilation & Verification
    print("[4/7] Multi-engine decompilation with bytecode verification ...")
    src_dir = out_dir / "src"
    rep = None
    decompile_error = ""
    try:
        rep = DC.decompile(
            current_jar, out_dir, engines_dir=engines_dir,
            jobs=jobs, timeout=timeout, verify_all=verify_all,
            clean_work=False, limit=0
        )
        DC.write_report(rep, out_dir)
        print(f"      results: {rep.ok} clean, {rep.partial} partial, {rep.failed + rep.missing} failed")
        if rep.coverage_avg is not None:
            print(f"      member name-hit rate: {rep.coverage_avg * 100:.1f}%")
    except Exception as exc:
        decompile_error = f"decompilation crashed: {exc}"
        print(f"      ! {decompile_error}")

    # Phase 4.5: deflat 抢救对比——原 jar 反编译若更差,采用 deflatted 版
    if unflattened_count > 0 and not no_deflat:
        preclean_jar = work_dir / "precleaned.jar"
        if preclean_jar.is_file():
            print("[4.5/7] trying de-flattened variant (rescue comparison) ...")
            alt_dir = work_dir / "src_deflat"
            try:
                trial_jar = preclean_jar
                if mapping_obj is not None and remapped_count > 0:
                    # 对比必须同映射:原 jar 走了 remap,deflatted 也要走
                    rj = work_dir / "precleaned_remapped.jar"
                    rc2, tt2 = MP.remap_jar(preclean_jar, rj, mapping_obj)
                    if rc2 > 0:
                        trial_jar = rj
                rep2 = DC.decompile(trial_jar, alt_dir, engines_dir=engines_dir,
                                    jobs=jobs, timeout=timeout, verify_all=verify_all,
                                    clean_work=False, limit=0)
                print(f"      deflatted variant: {rep2.ok} clean, {rep2.partial} partial, "
                      f"{rep2.failed + rep2.missing} failed")
                adopt = rep is None or rep2.ok > rep.ok
                if adopt:
                    gained = rep2.ok - (rep.ok if rep is not None else 0)
                    shutil.rmtree(src_dir, ignore_errors=True)
                    shutil.move(str(alt_dir / "src"), str(src_dir))
                    # Regenerate from rep2 instead of copying alt_dir/report.*:
                    # the copies described alt_dir/src, which the move just
                    # deleted, so every path in them was stale.
                    rep2.output = str(src_dir)
                    DC.write_report(rep2, out_dir)
                    rep = rep2
                    print(f"      adopted de-flattened results (+{gained} clean)")
                else:
                    shutil.rmtree(alt_dir, ignore_errors=True)
                    print("      kept original results (de-flattening did not help)")
            except Exception as exc:
                print(f"      ! rescue pass failed: {exc}")

    # 反编译阶段状态:以最终采用的 rep 为准(主跑或 4.5 采纳的抢救版)
    if rep is None:
        record("decompile", STAGE_FAILED, decompile_error or "no result produced")
    elif rep.total == 0:
        record("decompile", STAGE_FAILED, "0 classes decompiled")
    elif rep.failed + rep.missing > 0:
        record("decompile", STAGE_PARTIAL,
               f"{rep.ok} clean, {rep.partial} partial, {rep.failed + rep.missing} failed "
               f"of {rep.total}")
    else:
        record("decompile", STAGE_OK, f"{rep.ok} clean of {rep.total}")

    # Phase 5: Dynamic Decryption Replay (BSM Indy + Pool Recovery)
    indy_recovered = 0
    pool_recovered = 0
    # 子状态:None=未尝试;否则 (status, detail),status 取 STAGE_* 或 "no-target"
    indy_st: tuple[str, str] | None = None
    pool_st: tuple[str, str] | None = None
    if not no_recover and not allow_replay:
        print("[5/7] Dynamic replay string decryption: SKIPPED (safety gate)")
        print("      Dynamic replay EXECUTES code from the target jar; it is "
              "opt-in via --allow-replay / allow_replay=True.")
        record("replay", STAGE_SKIPPED,
               "safety gate: replay executes target code; opt in via --allow-replay")
    elif not no_recover:
        print("[5/7] Dynamic JVM replay string decryption "
              "(--allow-replay given: target code WILL be executed) ...")
        # 1. BSM Indy
        try:
            census = BM.scan_jar(current_jar)
            st = census["stats"]
            if st["sites"] > 0:
                print(f"      inspecting {st['sites']} indy callsite(s) across {st['classes_with_sites']} class(es) ...")
                java_bin = EN.find_java() or "java"
                rec_dir = work_dir / "recover"
                rc_code = RC.recover(original_jar, rec_dir, timeout=timeout,
                                     with_stubs=with_stubs, cp=cp, cp_file=cp_file,
                                     java=java_bin, allow_exec=True)
                rec_tsv = rec_dir / "recovered.tsv"
                if rec_tsv.is_file():
                    st_rw = RC.rewrite_sources(src_dir, rec_tsv)
                    indy_recovered = st_rw.get("replaced", 0)
                    if indy_recovered > 0:
                        print(f"      indy: {indy_recovered} callsite(s) decrypted and rewritten")
                if rc_code == 0:
                    indy_st = (STAGE_OK, f"rc=0, {indy_recovered} callsite(s) rewritten")
                elif rc_code == 3:
                    indy_st = (STAGE_FAILED, "replay blocked by exec gate (unexpected inside pipeline)")
                else:
                    indy_st = (STAGE_FAILED,
                               f"recovery driver failed (rc={rc_code}); "
                               f"{indy_recovered} callsite(s) rewritten; see _pipeline/recover/")
            else:
                indy_st = ("no-target", f"0 indy callsites in {st.get('classes_with_sites', 0)} classes")
        except Exception as exc:
            indy_st = (STAGE_FAILED, f"indy decryption error: {exc}")
            print(f"      ! indy decryption skipped: {exc}")

        # 2. String Pool
        try:
            pool_dir = work_dir / "pool"
            pool_spec = pool_dir / "pool_spec.tsv"
            st_scan = PL.scan_spec(src_dir, pool_spec)
            if st_scan.get("accessors", 0) > 0 and st_scan.get("unique", 0) > 0:
                print(f"      inspecting {st_scan['unique']} pool site(s) across {st_scan['pool_classes']} accessor class(es) ...")
                harvest_tsv = pool_dir / "pool_harvest.tsv"
                sep = ";" if sys.platform == "win32" else ":"
                pool_cp = (str(original_jar) + (sep if cp else "") + cp) if original_jar else cp
                java_bin = EN.find_java() or "java"
                h_res = PL.harvest(pool_spec, harvest_tsv, pool_dir, timeout=timeout,
                                   with_stubs=with_stubs, cp=pool_cp,
                                   cp_file=cp_file, java=java_bin, allow_exec=True)
                if harvest_tsv.is_file():
                    tmp_pool = work_dir / "src_pool"
                    st_apply = PL.apply(src_dir, harvest_tsv, tmp_pool)
                    pool_recovered = st_apply.get("replaced", 0)
                    if pool_recovered > 0:
                        shutil.rmtree(src_dir, ignore_errors=True)
                        shutil.copytree(tmp_pool, src_dir)
                        shutil.rmtree(tmp_pool, ignore_errors=True)
                        print(f"      pool: {pool_recovered} callsite(s) decrypted and rewritten")
                if h_res.get("ok"):
                    pool_st = (STAGE_OK, f"rc={h_res.get('returncode')}, {pool_recovered} callsite(s) rewritten")
                else:
                    why = "timeout killed driver" if h_res.get("timed_out") else \
                        (h_res.get("err") or f"rc={h_res.get('returncode')}")
                    pool_st = (STAGE_FAILED,
                               f"harvest failed: {why}; {pool_recovered} callsite(s) rewritten; "
                               f"see _pipeline/pool/")
            else:
                pool_st = ("no-target", "0 pool accessor sites found")
        except Exception as exc:
            pool_st = (STAGE_FAILED, f"pool decryption error: {exc}")
            print(f"      ! pool decryption skipped: {exc}")

        # 聚合:无目标≠失败;部分失败=partial;全失败=failed
        attempted = [s for s in (indy_st, pool_st) if s is not None]
        n_target = sum(1 for s, _ in attempted if s != "no-target")
        n_fail = sum(1 for s, _ in attempted if s == STAGE_FAILED)
        detail = f"indy[{indy_st[1]}]; pool[{pool_st[1]}]" \
            if (indy_st and pool_st) else \
            f"indy[{indy_st[1]}]" if indy_st else f"pool[{pool_st[1]}]"
        if n_target == 0:
            record("replay", STAGE_SKIPPED, "no replay targets found: " + detail)
        elif n_fail == n_target and n_target > 0:
            record("replay", STAGE_FAILED, detail)
        elif n_fail:
            record("replay", STAGE_PARTIAL, detail)
        else:
            record("replay", STAGE_OK, detail)
    else:
        print("[5/7] Dynamic replay string decryption: disabled (--no-recover)")
        record("replay", STAGE_SKIPPED, "disabled (--no-recover)")

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
                record("natives", STAGE_OK,
                       f"{nat_libs_count} lib(s), {nat_methods_count} native method(s), "
                       f"{rev_jni_count} reverse JNI call(s)")
            else:
                print("      native: no native binaries found")
                record("natives", STAGE_OK, "no native binaries found")
        except Exception as exc:
            print(f"      ! native triage failed: {exc}")
            record("natives", STAGE_FAILED, f"native triage error: {exc}")
    else:
        print("[6/7] Native library triage: disabled")
        record("natives", STAGE_SKIPPED, "disabled (--no-natives)")

    # Behavioral analysis (Mixin hooks & threat signals)
    hooks_count = 0
    patched_cls_count = 0
    signals_count = 0
    threat_count = 0

    if not no_analyze:
        analysis_failures = []
        try:
            a = AZ.analyze(current_jar, mapping=mapping_obj, mapping_desc=mapping_desc)
            AZ.write_analysis(a, out_dir)
            hooks_count = len(a.hooks)
            patched_cls_count = len(a.hook_groups())
            signals_count = len(a.classes)
            print(f"      analysis: {hooks_count} Mixin hook(s) across {patched_cls_count} class(es), "
                  f"{signals_count} high-risk signal class(es)")
        except Exception as exc:
            analysis_failures.append(f"mixin analysis error: {exc}")
            print(f"      ! analysis failed: {exc}")

        try:
            d = ST.dump_strings(current_jar)
            ST.write_tsv(d, out_dir / "strings.tsv")
            ST.write_json(d, out_dir / "strings.json")
            # literals, not labels: one literal can carry url+credential, and
            # summing tag_counts() used to report more "threat strings" than
            # there were strings
            threat_count = sum(1 for _cls, _s, tags in d.rows if tags)
            print(f"      strings: {d.total} literal(s) dumped, {threat_count} tagged")
        except Exception as exc:
            analysis_failures.append(f"strings dump error: {exc}")
            print(f"      ! strings dump failed: {exc}")

        if not analysis_failures:
            record("analysis", STAGE_OK)
        elif len(analysis_failures) == 2:
            record("analysis", STAGE_FAILED, "; ".join(analysis_failures))
        else:
            record("analysis", STAGE_PARTIAL, "; ".join(analysis_failures))
    else:
        print("      behavioral analysis: disabled")
        record("analysis", STAGE_SKIPPED, "disabled (--no-analyze)")

    # Phase 7: Master Executive Summary Report
    print("[7/7] Generating pipeline summary ...")
    elapsed = time.time() - t0
    record("summary", STAGE_OK, "pipeline_summary.md / pipeline_summary.json")
    res = PipelineResult(
        target_jar=target,
        out_dir=out_dir,
        profile=prof,
        unflattened_methods=unflattened_count,
        remapped_classes=remapped_count,
        mapping_name=mapping_desc,
        decompile_total=rep.total if rep is not None else 0,
        decompile_ok=rep.ok if rep is not None else 0,
        decompile_partial=rep.partial if rep is not None else 0,
        decompile_failed=(rep.failed + rep.missing) if rep is not None else 0,
        coverage_avg=rep.coverage_avg if rep is not None else None,
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
        stages=stages,
        strict=strict,
    )
    md_sum, json_sum = write_pipeline_summary(res, out_dir)
    print(f"      summary: {md_sum}")
    print(f"      json   : {json_sum}")

    # Phase 8: Automated IDE Project Export
    if export_project:
        print("\n[8/8] Exporting complete IDE Gradle project ...")
        from . import project as PJ
        proj_dir = out_dir / "project"
        try:
            p_stats = PJ.export_project(
                source_jar=target,
                out_dir=proj_dir,
                src_dir=out_dir / "src",
                mc_version=prof.mc_version,
                with_stubs=True,
            )
            print(f"      project: {proj_dir} ({p_stats['java_files']} sources, {p_stats['files_repaired']} repaired)")
            export_detail = (f"{p_stats['java_files']} sources, "
                             f"{p_stats['files_repaired']} repaired")
            if p_stats.get("files_repaired"):
                n_rules = p_stats.get("repair_rules_applied", 0)
                print(f"      self-heal audit: repair-log.md ({n_rules} rule(s)); "
                      f"originals kept in project/src-original/")
                export_detail += f"; {n_rules} self-heal rule(s) logged"
                # 证据分级:导出=可阅读;--compile 通过=可编译(在下方编译验证处升级)
            if compile_verify:
                print("      running javac compilation verification ...")
                c_rep = PJ.verify_compilation(proj_dir)
                print(f"      {c_rep.summary()}")
                export_detail += f"; {c_rep.summary()}"
                # 编译通过=ok;导出成功但仍有编译问题=partial(证据级别未达"可编译")
                if not c_rep.success:
                    res.stages.append(StageStatus("export", STAGE_PARTIAL, export_detail))
                else:
                    res.stages.append(StageStatus("export", STAGE_OK, export_detail))
            else:
                res.stages.append(StageStatus("export", STAGE_OK,
                                              export_detail + "; compilation not verified (--compile to enable)"))
        except Exception as exc:
            print(f"      ! project export failed: {exc}")
            res.stages.append(StageStatus("export", STAGE_FAILED, f"export error: {exc}"))
        # export 阶段可能改变 overall/exit code -> 刷新总报告使其一致
        md_sum, json_sum = write_pipeline_summary(res, out_dir)

    if clean_work:
        shutil.rmtree(work_dir, ignore_errors=True)

    print("=== Stage summary ===")
    for s in res.stages:
        line = f"  {s.name:<10}: {s.status}"
        if s.detail and s.status != STAGE_OK:
            line += f" ({s.detail})"
        print(line)
    print(f"=== Pipeline finished in {time.time() - t0:.2f}s : "
          f"status={res.overall_status}, exit code {res.exit_code}"
          + (" (strict)" if res.strict else "") + " ===")

    if launch_web:
        print()
        print("Launching Web Workbench ...")
        WB.start_server(out_dir, port=web_port, open_browser=True)

    return res
