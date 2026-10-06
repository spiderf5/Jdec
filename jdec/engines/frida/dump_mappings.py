"""Frida wrapper: run a JVM target with one of the engines/frida/*.js
scripts and collect the events into TSV files.

Two quirks this wrapper works around (both verified on Zulu 21, win32):
1. frida-java-bridge refuses to initialize on modern JDKs ("Java API only
   partially available ... Missing: VMThread::execute, ..."), so the JS
   scripts acquire the JNIEnv function table through jvm.dll's
   JNI_GetCreatedJavaVMs + AttachCurrentThread (bridge-free).
2. JS timers (setInterval) never fire in these targets — top-level code and
   python-driven rpc calls work. So the python side pumps
   rpc.exports.try_install() on every instrumented process.

Usage:
  python dump_mappings.py --java <java.exe> --script regnatives.js \
      --out mappings.tsv [--jni-out jnitrace.tsv] [--timeout 60] \
      -- <java args...>

Events:
  regnatives: {cls, method, sig, ptr}   -> --out    (one row per method)
  jni:        {tid, fn, args[]}         -> --jni-out (raw trace lines)
  info/error/log:                          -> stderr
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

import frida


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--java", default="java")
    ap.add_argument("--script", required=True)
    ap.add_argument("--out", default="mappings.tsv")
    ap.add_argument("--jni-out")
    ap.add_argument("--payload-out", default=None,
                    help="copy dropped native libraries here")
    ap.add_argument("--stdout-markers", default=None,
                    help="capture the target's stdout (ENTER/EXIT markers "
                         "from the harness) to this file, in true order")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--attach-name", default="java",
                    help="process-name prefix to race-attach")
    ap.add_argument("--attach-delay", type=float, default=0.0,
                    help="seconds to wait after spawn before attaching "
                         "(lets -agentpath JVMTI agents finish Agent_OnLoad)")
    ap.add_argument("--retries", type=int, default=0,
                    help="re-spawn attempts when the JVM dies early "
                         "(JVM8 safepoint deadlocks vs frida threads are "
                         "probabilistic)")
    ap.add_argument("--play-wait", type=float, default=180.0,
                    help="gameplay window between attach phases: user plays "
                         "the game (frida detached) to trigger lazy "
                         "function-body decryption")
    ap.add_argument("--cp-file", default=None,
                    help="read the raw classpath from this file and splice it "
                         "into java_args where '@@CP@@' appears (bypasses "
                         "cmd.exe set /p 1023-char truncation)")
    ap.add_argument("--cp-extra", default=None,
                    help="one extra classpath entry appended after --cp-file")
    ap.add_argument("java_args", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    java_args = [a for a in args.java_args if a != "--"]

    if any("@@CP@@" in a for a in java_args):
        if not args.cp_file:
            ap.error("java_args contain '@@CP@@' but --cp-file was not given")
        cp = Path(args.cp_file).read_text(encoding="utf-8").strip()
        if args.cp_extra:
            cp += ";" + args.cp_extra
        for entry in cp.split(";"):
            if entry and not Path(entry).exists():
                print(f"[warn] classpath entry missing: {entry}",
                      file=sys.stderr)
        java_args = [a.replace("@@CP@@", cp) for a in java_args]
        print(f"[info] classpath spliced from {args.cp_file} "
              f"({len(cp)} chars, {cp.count(';') + 1} entries)", file=sys.stderr)

    script_src = Path(args.script).read_text(encoding="utf-8")
    rows: list[dict] = []
    memchunks: dict[int, bytes] = {}
    device = frida.get_local_device()
    pids: set[int] = set()
    scripts: list = []

    def on_message(message, _data):
        if message.get("type") == "send":
            rows.append(message["payload"])
            p = message["payload"]
            if p.get("type") == "payload":
                print(f"[payload] {p.get('path')}", file=sys.stderr)
            elif p.get("type") == "info":
                print(f"[info] {p.get('msg')}", file=sys.stderr)
            elif p.get("type") == "error":
                print(f"[script-error] {p.get('msg')}", file=sys.stderr)
            elif p.get("type") == "memchunk":
                if _data:
                    memchunks[p["off"]] = _data
            elif p.get("type") == "memdump-done":
                total = p["size"]
                buf = bytearray(total)
                for off, chunk in memchunks.items():
                    end = min(off + len(chunk), total)
                    buf[off:end] = chunk[: end - off]
                out_path = Path("memdump_" + p["name"])
                out_path.write_bytes(bytes(buf))
                print(f"[info] memory dump written: {out_path.resolve()} "
                      f"({total} bytes, runtime base {p['base']})",
                      file=sys.stderr)
        elif message.get("type") == "log":
            print(f"[log] {message.get('payload', '')}", file=sys.stderr)
        elif message.get("type") == "error":
            print(f"[error] {message.get('description')}", file=sys.stderr)

    def instrument(pid: int, tag: str) -> bool:
        try:
            session = frida.attach(pid)
        except Exception as e:
            print(f"[warn] attach {tag} pid={pid}: {e}", file=sys.stderr)
            return False
        pids.add(pid)
        script = session.create_script(script_src)
        script.on("message", on_message)
        script.load()
        scripts.append(script)
        print(f"[info] script loaded into {tag} pid={pid}", file=sys.stderr)
        return True

    def alive(p: int) -> bool:
        try:
            device.get_process(p)
            return True
        except Exception:
            return False

    def reg_rows() -> int:
        return sum(1 for r in rows if r.get("type") == "regnatives")

    attempts = max(1, args.retries + 1)
    for attempt in range(1, attempts + 1):
        start_rows = reg_rows()
        stdout_file = None
        stdout_thread = None
        popen = subprocess.Popen(
            [args.java] + java_args,
            stdout=(open(args.stdout_markers, "w", encoding="utf-8")
                    if args.stdout_markers else None))
        pids.add(popen.pid)
        if args.attach_delay > 0:
            print(f"[info] waiting {args.attach_delay}s before attach "
                  f"(agent OnLoad window)", file=sys.stderr)
            time.sleep(args.attach_delay)
        instrument(popen.pid, "target")
        print(f"[info] launched pid={popen.pid} (attempt {attempt}/{attempts}),"
              f" pumping + racing (timeout {args.timeout}s)", file=sys.stderr)

        t0 = time.time()
        last_java_seen = time.time()
        last_enum = 0.0
        settled = False
        while time.time() - t0 < args.timeout and not settled:
            # HOT: pump try_install on known pids only (~20ms cadence — the
            # VM-ready window on short-lived targets can be ~1s)
            for sc in list(scripts):
                try:
                    if sc.exports.tryinstall():
                        break
                except Exception:
                    pass
            # SETTLED: registrations captured (>=80 rows) and quiet for 3s.
            # DETACH immediately — total frida attach window stays ~1min,
            # dodging the JVM8 safepoint deadlock that builds up while both
            # the cracked agent's attached thread and frida are resident.
            # The game keeps running (agent-only, survives: probe3) while
            # the user triggers feature code, decrypting function bodies.
            if (reg_rows() - start_rows >= 80 and scripts
                    and time.time() - last_enum > 3.0 and not any(
                        r.get("type") == "regnatives" for r in rows[-3:])):
                for sc in list(scripts):
                    try:
                        sc.session.detach()
                    except Exception:
                        pass
                scripts.clear()
                settled = True
                print(f"[info] registrations settled ({reg_rows() - start_rows} "
                      f"rows) — detached; game runs free for "
                      f"{args.play_wait}s gameplay phase", file=sys.stderr)
            # COLD: look for spawned helper processes occasionally
            if time.time() - last_enum > 0.5:
                last_enum = time.time()
                try:
                    for proc in device.enumerate_processes():
                        if proc.name.lower().startswith(args.attach_name):
                            last_java_seen = time.time()
                            if proc.pid not in pids:
                                instrument(proc.pid, "race")
                except Exception as e:
                    print(f"[warn] enumerate: {e}", file=sys.stderr)
                if time.time() - last_java_seen > 3.0 and popen.poll() is not None:
                    break  # target gone and no java left
            time.sleep(0.02)

        gained = reg_rows() - start_rows
        if settled and popen.poll() is None:
            # PHASE 2: gameplay window — user triggers feature code in the
            # running game; frida is fully detached so no safepoint clash
            print(f"[info] PHASE 2: play the game now "
                  f"({args.play_wait}s, frida detached)", file=sys.stderr)
            end = time.time() + args.play_wait
            while time.time() < end and popen.poll() is None:
                time.sleep(1.0)
            # PHASE 3: short re-attach for the memory dump only
            if popen.poll() is None:
                print("[info] PHASE 3: re-attaching for module memory dump",
                      file=sys.stderr)
                try:
                    session = device.attach(popen.pid)
                    pids.add(popen.pid)
                    sc = session.create_script(script_src)
                    sc.on("message", on_message)
                    sc.load()
                    scripts.append(sc)
                    for _ in range(40):
                        try:
                            if sc.exports.tryinstall():
                                break
                        except Exception:
                            pass
                        time.sleep(0.25)
                    sc.exports.dumpmodule()
                    # wait for the dump transfer to finish (46MB in 1MiB
                    # chunks; on_message writes the file on memdump-done)
                    for _ in range(75):
                        if list(Path(".").glob("memdump_*.lib")):
                            break
                        time.sleep(1.0)
                except Exception as e:
                    print(f"[warn] phase 3 re-attach failed: {e}",
                          file=sys.stderr)
            for p in list(pids):
                if alive(p):
                    try:
                        subprocess.run(["taskkill", "/F", "/PID", str(p)],
                                       capture_output=True, timeout=10)
                    except Exception:
                        pass
            break  # two-phase flow completes in one attempt
        for p in list(pids):
            if alive(p):
                try:
                    subprocess.run(["taskkill", "/F", "/PID", str(p)],
                                   capture_output=True, timeout=10)
                except Exception:
                    pass

        # success = reached the detach/gameplay handoff; a crash that merely
        # banked rows must NOT count as success (rows without the memdump
        # miss the decrypted function bodies)
        if settled or attempt == attempts:
            break
        # JVM-side safepoint deadlocks (frida thread vs JVM 8 GC) kill the
        # game probabilistically; re-spawn and try again on fresh rows only
        print(f"[info] attempt {attempt} yielded {gained} rows — retrying",
              file=sys.stderr)
        rows = [r for r in rows if r.get("type") not in
                ("regnatives", "jni", "memchunk", "memdump-done")]
        pids.clear()
        scripts.clear()
        time.sleep(2.0)

    if args.payload_out:
        import os
        import shutil
        os.makedirs(args.payload_out, exist_ok=True)
        for r in rows:
            if r.get("type") == "payload":
                src = r["path"]
                if os.path.exists(src):
                    dst = os.path.join(args.payload_out, os.path.basename(src))
                    try:
                        shutil.copy2(src, dst)
                        print(f"[payload] copied {src} -> {dst}", file=sys.stderr)
                    except Exception as e:
                        print(f"[warn] copy {src}: {e}", file=sys.stderr)

    nat = [r for r in rows if r.get("type") == "regnatives"]
    jni = [r for r in rows if r.get("type") == "jni"]
    with open(args.out, "w", encoding="utf-8") as f:
        for r in nat:
            # 列: cls, method, sig, ptr, [base, module] —— 后两列供 Ghidra
            # 地址表模式做基址换算(runtime ptr - runtime base + image base)
            f.write(f"{r['cls']}\t{r['method']}\t{r['sig']}\t{r['ptr']}")
            if r.get("base"):
                f.write(f"\t{r['base']}\t{r.get('mod', '?')}")
            f.write("\n")
    if args.jni_out:
        with open(args.jni_out, "w", encoding="utf-8") as f:
            for r in jni:
                f.write(f"{r['tid']}\t{r['fn']}\t" + "\t".join(r["args"]) + "\n")
    print(f"[info] registered-natives rows: {len(nat)} -> {args.out}", file=sys.stderr)
    if args.jni_out:
        print(f"[info] jni trace rows: {len(jni)} -> {args.jni_out}", file=sys.stderr)
    return 0 if nat or jni else 1


if __name__ == "__main__":
    sys.exit(main())
