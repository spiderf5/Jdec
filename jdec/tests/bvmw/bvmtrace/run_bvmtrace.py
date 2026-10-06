"""Stage-3 acceptance: instrumented runtime trace vs static decode.

Pipeline (needs a JDK + the ASM jars in ../lib):
  1. compile BVMTrace.java + BVMTraceTransform.java (build dir)
  2. ASM-transform the 4 VM main classes in calc-bytecodevm.jar
  3. run the instrumented jar through the Calc driver -> trace TSV
  4. join every trace event (set, slot, mapped, shard, seed) against the
     static decode + routing; validate the next_pc execution chain and the
     Calc program outputs.

Usage:  python tests/bvmw/bvmtrace/run_bvmtrace.py
Exit:   0 = PASS, 1 = FAIL, 2 = environment unsupported (JDK/ASM missing).
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent          # tests/bvmw/bvmtrace
BVMW = HERE.parent                              # tests/bvmw
JDEC_ROOT = BVMW.parents[1]                     # jdec repo root (tests/bvmw/x -> jdec)

sys.path.insert(0, str(JDEC_ROOT))

from jdec import bvmw_devirt as dv              # noqa: E402

JAR_IN = BVMW / "calc-bytecodevm.jar"
ASM_CP = [str(BVMW / "lib" / "asm-9.9.jar"),
          str(BVMW / "lib" / "asm-tree-9.9.jar")]

# Calc fixture ground truth (from the unprotected calc.jar source bytecode)
EXPECTED_ADD = 16                                # (2+3+0+1+2)*2
EXPECTED_GREET = "Hello, world! from alpha-beta-gamma"


def mix_expected() -> int:
    x = (305419896 ^ 25214903917) & 0xFFFFFFFFFFFFFFFF
    x = (x * 2685821657736338717) & 0xFFFFFFFFFFFFFFFF
    return x >> 13                               # lushr 13 (logical)


def _cp(*parts: str) -> str:
    return ";".join(parts)


def main() -> int:
    javac = shutil.which("javac")
    java = shutil.which("java")
    if not (javac and java and all(Path(p).exists() for p in ASM_CP)):
        print("SKIP: javac/java or ASM jars unavailable")
        return 2
    if not JAR_IN.exists():
        print(f"SKIP: fixture missing: {JAR_IN}")
        return 2

    work = Path(tempfile.mkdtemp(prefix="bvmw_trace_"))
    cls = work / "cls"
    cls.mkdir()
    fail = 0

    # 1. compile ----------------------------------------------------------
    r = subprocess.run(
        [javac, "-encoding", "UTF-8",
         "-cp", _cp(*ASM_CP), "-d", str(cls),
         str(HERE / "BVMTrace.java"), str(HERE / "BVMTraceTransform.java")],
        capture_output=True, text=True)
    if r.returncode:
        print("FAIL: javac:", r.stderr[:500])
        return 1

    # 2. transform --------------------------------------------------------
    jar_out = work / "calc_trace.jar"
    r = subprocess.run(
        [java, "-cp", _cp(str(cls), *ASM_CP),
         "BVMTraceTransform", "transform", str(JAR_IN), str(jar_out)],
        capture_output=True, text=True)
    if r.returncode:
        print("FAIL: transform:", r.stdout[-500:], r.stderr[:500])
        return 1
    n_instr = r.stdout.count("instrumented")
    if n_instr != 4:
        print(f"FAIL: instrumented {n_instr} classes, expected 4")
        fail += 1

    # 3. run --------------------------------------------------------------
    trace = work / "trace.tsv"
    r = subprocess.run(
        [java, f"-Dbvmw.trace={trace}", "-cp", str(jar_out), "BVMTrace", "run"],
        capture_output=True, text=True, timeout=120)
    lines = {ln.split("=", 1)[0]: ln.split("=", 1)[1]
             for ln in r.stdout.splitlines() if "=" in ln}
    checks = [("add(2,3)", str(EXPECTED_ADD)),
              ("greet", EXPECTED_GREET),
              ("mix", str(mix_expected()))]
    for key, want in checks:
        got = lines.get(key)
        if got != want:
            print(f"FAIL: program output {key}: got {got!r} want {want!r}")
            fail += 1
        else:
            print(f"ok  output {key}={got}")
    if r.returncode:
        print("FAIL: driver exit", r.returncode, r.stderr[:300])
        fail += 1
    if not trace.exists():
        print("FAIL: no trace produced")
        return 1

    # 4. static decode + join --------------------------------------------
    classes = dv.load_classes(JAR_IN)
    sets = dv.discover_vm_sets(classes)
    static: dict[int, dict[int, dict]] = {}
    routing: dict[int, dict] = {}
    for vs in sets:
        dec = dv.decode_method(vs, 0)
        rt = dv.extract_routing(vs.main_cf)
        dv.annotate_routing(vs, dec, rt)
        routing[vs.index] = rt
        static[vs.index] = {s["slot"]: s for s in dec.slots}

    events: list[dict] = []
    for ln in trace.read_text(encoding="utf-8").splitlines():
        if not ln.startswith("E\t"):
            continue
        _, seq, seti, shard, seed, mapped, slot, aux = ln.split("\t")
        events.append({"seq": int(seq), "set": int(seti), "shard": int(shard),
                       "seed": int(seed), "mapped": int(mapped),
                       "slot": int(slot), "aux": int(aux)})
    print(f"trace events: {len(events)}")

    trans_seeds: dict[int, set] = {
        i: set((sh, sd) for sh, sd in routing[i].get("transitions", {}).values())
        for i in routing}
    n_mapped = n_route = 0
    fsm_events = cand_events = 0
    for ev in events:
        st = static.get(ev["set"], {}).get(ev["slot"])
        if st is None:
            print(f"FAIL: event {ev['seq']} set{ev['set']} slot{ev['slot']} "
                  f"not in static decode")
            fail += 1
            continue
        if ev["mapped"] != st["dispatch_opcode"]:
            print(f"FAIL: event {ev['seq']} set{ev['set']} slot{ev['slot']} "
                  f"mapped {ev['mapped']} != static "
                  f"{st['dispatch_opcode']}")
            fail += 1
        else:
            n_mapped += 1
        cands = st.get("handler_candidates")
        rec_shard = st.get("shard")
        if cands:
            # variant D: token maps to a handler array, picked index is a
            # runtime value -> validate against the array's full contents
            cand_events += 1
            if (ev["shard"], ev["seed"]) not in set(cands):
                print(f"FAIL: event {ev['seq']} set{ev['set']} "
                      f"slot{ev['slot']}: handler ({ev['shard']}, "
                      f"{ev['seed']}) not in token array candidates")
                fail += 1
            else:
                n_route += 1
        elif rec_shard is not None and rec_shard != -1:
            if (ev["shard"], ev["seed"]) != (rec_shard, st.get("shard_seed")):
                print(f"FAIL: event {ev['seq']} set{ev['set']} "
                      f"slot{ev['slot']}: handler ({ev['shard']}, "
                      f"{ev['seed']}) != static ({rec_shard}, "
                      f"{st.get('shard_seed')})")
                fail += 1
            else:
                n_route += 1
        else:
            # FSM flavor: token resolved through the transitions table
            fsm_events += 1
            ent = routing[ev["set"]]["entries"].get(st.get("dispatch_token"))
            if ent is None:
                print(f"FAIL: event {ev['seq']} set{ev['set']} "
                      f"slot{ev['slot']}: token not in FSM symbols")
                fail += 1
            elif (ev["shard"], ev["seed"]) not in trans_seeds[ev["set"]]:
                print(f"FAIL: event {ev['seq']} set{ev['set']} "
                      f"slot{ev['slot']}: handler ({ev['shard']}, "
                      f"{ev['seed']}) not in transitions table")
                fail += 1
            else:
                n_route += 1

    # 5. next_pc execution chain (next_pc is a value in the pc domain,
    #    so join through the per-set pc -> slot index) ----------------------
    pc2slot: dict[int, dict[int, int]] = {
        i: {s["pc"]: s["slot"] for s in static[i].values()} for i in static}
    obey = viol = 0
    for a, b in zip(events, events[1:]):
        if a["set"] != b["set"]:
            continue                     # program boundary
        nxt = static[a["set"]][a["slot"]]["next_pc"]
        target = pc2slot[a["set"]].get(nxt)
        if target is None:
            continue                     # next_pc == -1 (return) or unknown
        if b["slot"] == target:
            obey += 1
        else:
            viol += 1
    print(f"next_pc chain: {obey} obeyed, {viol} diverged "
          f"(branches/loops jump elsewhere by design)")
    if obey == 0:
        print("FAIL: next_pc chain has zero matches")
        fail += 1

    per_set = {}
    for ev in events:
        per_set[ev["set"]] = per_set.get(ev["set"], 0) + 1
    print("events per set:",
          " ".join(f"set{k}={v}" for k, v in sorted(per_set.items())),
          f"| mapped {n_mapped}/{len(events)}, "
          f"routed {n_route}/{len(events)} "
          f"(array-candidates {cand_events}, FSM-table {fsm_events})")

    print(f"\nworkdir: {work}")
    print("RESULT:", "FAIL" if fail else "PASS", f"({fail} failures)")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
