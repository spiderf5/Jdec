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
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--attach-name", default="java",
                    help="process-name prefix to race-attach")
    ap.add_argument("java_args", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    java_args = [a for a in args.java_args if a != "--"]

    script_src = Path(args.script).read_text(encoding="utf-8")
    rows: list[dict] = []
    device = frida.get_local_device()
    pids: set[int] = set()
    scripts: list = []

    def on_message(message, _data):
        if message.get("type") == "send":
            rows.append(message["payload"])
            p = message["payload"]
            if p.get("type") == "info":
                print(f"[info] {p.get('msg')}", file=sys.stderr)
            elif p.get("type") == "error":
                print(f"[script-error] {p.get('msg')}", file=sys.stderr)
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

    popen = subprocess.Popen([args.java] + java_args)
    pids.add(popen.pid)
    instrument(popen.pid, "target")
    print(f"[info] launched pid={popen.pid}, pumping + racing "
          f"(timeout {args.timeout}s)", file=sys.stderr)

    t0 = time.time()
    last_java_seen = time.time()
    last_enum = 0.0
    while time.time() - t0 < args.timeout:
        # HOT: pump try_install on known pids only (~20ms cadence — the
        # VM-ready window on short-lived targets can be ~1s)
        for sc in list(scripts):
            try:
                if sc.exports.tryinstall():
                    break
            except Exception:
                pass
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

    for p in list(pids):
        if alive(p):
            try:
                subprocess.run(["taskkill", "/F", "/PID", str(p)],
                               capture_output=True, timeout=10)
            except Exception:
                pass

    nat = [r for r in rows if r.get("type") == "regnatives"]
    jni = [r for r in rows if r.get("type") == "jni"]
    with open(args.out, "w", encoding="utf-8") as f:
        for r in nat:
            f.write(f"{r['cls']}\t{r['method']}\t{r['sig']}\t{r['ptr']}\n")
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
