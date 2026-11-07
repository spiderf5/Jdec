#!/usr/bin/env python3
"""Regression entry point: prepare the fixtures, then run every suite in order.

The cases themselves live in ``suites/`` — one module per area — and the
shared fixtures, constants and assertions live in ``harness.py``. This file
only decides the order and turns a failure count into an exit code.

Order matters and is deliberate: `core` runs first because the later suites
assume the fixture jars exist and the engine cache is warm, and the two
slow Minecraft/real-sample groups run last so a missing authorised sample
cannot hide the ordinary results.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_fixtures  # noqa: E402
import harness as H  # noqa: E402
from suites import (  # noqa: E402
    acceptance,
    core,
    integration,
    recovery,
    rewrite,
    runtime,
    semantics,
    tooling,
    web,
)


def main() -> int:
    with_mc = "--with-mc" in sys.argv
    if not H.SAMPLE.exists() and build_fixtures.ensure_sample_jar(quiet=False) is None:
        print("missing tests/sample.jar and could not build it: no working javac\n"
              "  -> set JAVA_HOME to a JDK (e.g. JAVA_HOME=D:\\java21) or put javac\n"
              "     on PATH, then re-run. sample.jar is the prerequisite of every\n"
              "     other case, so the suite cannot degrade to a partial run.")
        return 2
    H._prepare_engines()
    # every fixture must exist before the first test that touches one: several
    # tests only guard with `if MIXIN.exists()`, so a late build silently drops
    # their assertions on a fresh checkout
    build_fixtures.ensure_mixin_jar(quiet=True)
    H._run(core.test_roundtrip_sample)
    H._run(core.test_classfile_parser_survives_mutation)
    H._run(core.test_synthetic_members_ignored)
    H._run(core.test_scoring_sees_obfuscated_names)
    H._run(core.test_partial_failure_is_not_total_failure)
    H._run(core.test_score_decl_and_noise)
    H._run(core.test_unbalanced_braces_are_proportional)
    H._run(core.test_end_to_end_sample)
    H._run(core.test_case_colliding_class_names)
    H._run(core.test_iso_buckets)
    H._run(core.test_safe_rel_covers_package_segments)
    H._run(core.test_web_report_rel_reverse_lookup)
    H._run(core.test_pipeline_summary_target_is_resolvable)
    H._run(core.test_bytecode_and_string_quality)
    H._run(core.test_safety_and_byte_fidelity)
    H._run(core.test_binary_semantics)
    H._run(core.test_degradation_accounting)
    H._run(core.test_tool_hardening)
    H._run(core.test_polish)
    H._run(core.test_cli_exit_codes)
    H._run(core.test_readme_doc_links)
    H._run(rewrite.test_ir_roundtrip)
    H._run(rewrite.test_toolchain_single_entry)
    H._run(rewrite.test_verify_gate)
    H._run(rewrite.test_deflat_output_loads)
    H._run(rewrite.test_deflat_paths_agree)
    H._run(rewrite.test_deflat_parallel_matches_serial)
    H._run(rewrite.test_behaviour_is_preserved)
    H._run(runtime.test_sandbox_isolation)
    H._run(runtime.test_isolation_backends)
    H._run(runtime.test_benchmark_is_reproducible)
    H._run(runtime.test_offline_engine_bundle)
    H._run(runtime.test_union_denominator_guard)
    H._run(runtime.test_replay_timeout_cleanup)
    H._run(runtime.test_engine_install_safety)
    H._run(runtime.test_engines_cli_consistency)
    H._run(acceptance.test_support_matrix_per_corpus_gate)
    H._run(acceptance.test_benchmark_report_hygiene)
    H._run(acceptance.test_stage04_acceptance_harness)
    H._run(acceptance.test_indy_payload_resolution)
    H._run(acceptance.test_probe_profile_phases)
    H._run(acceptance.test_native_libs_and_rva)
    H._run(acceptance.test_nativedb_bundle)
    H._run(acceptance.test_support_matrix_selfcheck)
    H._run(acceptance.test_acceptance_chain_is_shipped_and_independent)
    H._run(semantics.test_frame_generation)
    H._run(semantics.test_ir_transforms)
    H._run(semantics.test_pipeline_gate)
    H._run(semantics.test_devirt_output_loads)
    H._run(semantics.test_devirt_behaviour)
    H._run(semantics.test_devirt_realistic_vm)
    H._run(semantics.test_jsr_subroutine_is_left_alone)
    H._run(semantics.test_dead_branch_is_not_nop_ed)
    H._run(semantics.test_rewritten_list_from_both_paths)
    H._run(semantics.test_reason_replay_and_rollback)
    H._run(semantics.test_unflatten_strict_rejection)
    H._run(semantics.test_interp_same_negative_and_models)
    H._run(semantics.test_interp_engine_semantics)
    H._run(semantics.test_interp_lambda_and_streams)
    H._run(semantics.test_behave_semantics)
    H._run(semantics.test_receiver_and_argument_synthesis)
    H._run(semantics.test_behave_classpath)
    H._run(semantics.test_verify_skips_multirelease)
    H._run(semantics.test_hierarchy_extra_classpath)
    H._run(semantics.test_missing_dependency_gate)
    H._run(semantics.test_deflat_failure_accounting)
    H._run(semantics.test_coverage_accounting)
    H._run(semantics.test_case_derivation)
    H._run(semantics.test_verify_matrix)
    H._run(semantics.test_focus_reports_unjudged)
    H._run(semantics.test_insert_branch_to_label)
    H._run(semantics.test_dead_code_keeps_control_flow)
    H._run(semantics.test_frames_match_javac)
    H._run(semantics.test_ir_assembly_changes_length)
    H._run(semantics.test_weak_engine_is_rescued)
    H._run(recovery.test_yarn_compose)
    H._run(recovery.test_official_srg_compose)
    H._run(recovery.test_auto_mapping_set_flavor)
    H._run(recovery.test_java_escape)
    H._run(recovery.test_rewrite_sources)
    H._run(recovery.test_recover_triage)
    H._run(recovery.test_manifest_and_resources)
    H._run(recovery.test_rewrite_escapes)
    H._run(recovery.test_bsm_scan_and_parse_resilience)
    H._run(recovery.test_recover_spec_generation_and_quarantine)
    H._run(recovery.test_replay_safety_gate)
    H._run(recovery.test_resource_anomaly)
    H._run(recovery.test_scorecard_smoke)
    H._run(tooling.test_pool_roundtrip)
    H._run(tooling.test_web_template_js)
    H._run(tooling.test_pool_qualified_and_full_string)
    H._run(tooling.test_pool_overload_dispatch)
    H._run(tooling.test_probe_fingerprints_json)
    H._run(tooling.test_platform_classpath_separator)
    H._run(tooling.test_procyon_bridge_is_built)
    H._run(tooling.test_remap_failure_accounting)
    H._run(tooling.test_devirt_opcode_disambiguation)
    H._run(tooling.test_code_pool_json_integrity)
    H._run(tooling.test_max_stack_dataflow)
    H._run(tooling.test_pool_verify_fq_callsites)
    H._run(tooling.test_attribution_gates)
    H._run(tooling.test_ops_pool)
    H._run(tooling.test_jint)
    H._run(tooling.test_clinit_sim)
    H._run(tooling.test_ghidra_integration)
    H._run(tooling.test_native_elf_and_ghidra_annotate)
    H._run(tooling.test_score_and_signal_enhancements)
    H._run(tooling.test_multimodule_enhancements)
    H._run(tooling.test_advanced_roadmap_features)
    H._run(tooling.test_pipeline_automation)
    H._run(tooling.test_pipeline_stage_status)
    H._run(tooling.test_rewrite_skips_comments_strings)
    H._run(tooling.test_bvm_extract_code_id_descriptor_gate)
    H._run(web.test_web_callgraph_error_semantics)
    H._run(web.test_web_workbench_features)
    H._run(web.test_web_source_path_containment)
    H._run(web.test_web_bytecode_endpoint)
    H._run(web.test_web_class_tags)
    H._run(integration.test_export_rejects_escaping_resources)
    H._run(integration.test_native_extract_keeps_same_basename)
    H._run(integration.test_stub_bundle_failure_is_visible)
    H._run(integration.test_web_cross_site_guard)
    H._run(integration.test_cli_json_and_version)
    H._run(integration.test_review_2026_11_01)
    H._run(integration.test_container_classification)
    H._run(integration.test_corrupt_container_is_a_verdict)
    H._run(integration.test_callgraph_and_reachability)
    H._run(integration.test_conservative_prune)
    H._run(integration.test_decompiler_trap_pruning)
    H._run(integration.test_project_export_and_recompilability)
    H._run(integration.test_selfheal_audit)
    H._run(integration.test_cfg_and_dynamic_mocks)
    H._run(integration.test_bvm_and_native_extensions)
    H._run(integration.test_sakura_architecture_improvements)
    H._run(integration.test_bridge_prune_and_clean_idempotence)
    if build_fixtures.ensure_mixin_jar() is None:
        print("skipping mixin tests: tests/mixin.jar could not be built "
              "(run tests/build_fixtures.py)")
    else:
        H._run(integration.test_annotated_classes_roundtrip)
        H._run(integration.test_mixin_fixture)
        H._run(integration.test_refmap)
        H._run(integration.test_string_dump)
        H._run(integration.test_indy_encoding)
        H._run(integration.test_signals)
        H._run(integration.test_bytecode_decodes)
        H._run(integration.test_flow_fingerprints)
        H._run(integration.test_native_reporting)
    if with_mc:
        missing = [p for p in (H.MC_JAR, H.MC_MAP) if not p.exists()]
        if missing:
            # the core suite already ran: print its numbers before exiting, or
            # the "missing fixtures" path looks like a total failure
            print("missing MC fixtures: " + ", ".join(str(p) for p in missing))
            print(f"  put them under {H.MC_JAR.parent} (gitignored) and re-run, "
                  f"or drop --with-mc for the core suite")
            print(f"\n{H._passed} passed, {H._failed} failed (core suite only)")
            return 2
        H._run(integration.test_mc_roundtrip)
        H._run(integration.test_mojang_mapping_direction)
        H._run(integration.test_remap_rewrites_call_sites)
        H._run(integration.test_remapped_class_is_valid_bytecode)
        H._run(integration.test_mc_is_not_flow_obfuscated)
        H._run(integration.test_real_zkm_sample)
        H._run(integration.test_grounding_real_mc_sample)
        H._run(integration.test_real_zkm_clean_pipeline)
    print(f"\n{H._passed} passed, {H._failed} failed")
    return 1 if H._failed else 0


if __name__ == "__main__":
    sys.exit(main())
