"""scorecard 子命令：固定口径的回归基准。

动机（lf21 双管线对标反思）："迭代很多"却答不出"比上版好了多少"——
每轮改进靠当次样本现场数数，口径还会漂。本命令对同一组样本反复跑出
同一张表（probe/strings 口径，可选 analyze/decompile），JSON 落盘，
--compare 读上一张出 delta。真实样本外置后样本集即固定。

用法：
  python jdec.py scorecard D:/MC/samples/*.jar -o out/scorecard.json
  python jdec.py scorecard D:/MC/samples -o out/scorecard.json --analyze
  python jdec.py scorecard ... --compare out/last.json
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from . import engines as EN
from . import strings as ST
from .analyze import analyze as run_analyze
from .decompile import decompile
from .probe import profile_jar


def _git_rev() -> str:
    try:
        r = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                           capture_output=True, text=True, timeout=10,
                           cwd=Path(__file__).resolve().parent.parent)
        return r.stdout.strip() if r.returncode == 0 else "?"
    except Exception:  # noqa: BLE001
        return "?"


def score_jar(jar: Path, do_analyze: bool = False, do_decompile: bool = False,
              engines_dir: Path | None = None, timeout: int = 1800) -> dict:
    t0 = time.time()
    prof = profile_jar(jar)
    row: dict = {
        "jar": jar.name,
        "size_mb": round(jar.stat().st_size / 1048576, 1),
        "classes": prof.classes,
        "obfuscation": round(prof.obfuscation, 1),
        "obfuscator": prof.obfuscator or "",
        "mc": " ".join(filter(None, [prof.mc_version, prof.mc_flavor])),
    }
    d = ST.dump_strings(jar)
    row["strings"] = d.total
    row["strings_suspicious"] = d.only_suspicious().total
    row["strings_unreadable"] = d.unreadable
    if do_analyze:
        a = run_analyze(jar)
        row["hooks"] = len(a.hooks)
        row["hook_classes"] = a.hook_stats.get("with_hooks", 0)
        row["notes"] = len(a.notes)
    if do_decompile:
        out_dir = jar.parent / (jar.stem + "_scorecard_dec")
        missing = EN.ensure_engines(engines_dir, quiet=True)
        usable = [k for k in EN.ENGINES if EN.ENGINES[k].available(engines_dir)]
        if not usable:
            row["dec_error"] = "no engines"
        else:
            try:
                rep = decompile(jar, out_dir, engines_dir, timeout=timeout)
                row["dec_ok"] = rep.ok
                row["dec_partial"] = rep.partial
                row["dec_failed"] = rep.failed + rep.missing
                row["dec_coverage"] = (round(rep.coverage_avg, 3)
                                       if rep.coverage_avg is not None else None)
                row["dec_elapsed"] = round(rep.elapsed, 1)
            except Exception as exc:  # noqa: BLE001
                row["dec_error"] = str(exc)[:200]
    row["elapsed_s"] = round(time.time() - t0, 1)
    return row


_DELTA_KEYS = ["classes", "obfuscation", "strings", "strings_suspicious",
               "hooks", "hook_classes", "dec_ok", "dec_failed"]


def compare_rows(old_rows: list[dict], new_rows: list[dict]) -> list[dict]:
    """按 jar 名对齐，产出 delta 行（只列口径内有变化的字段）。"""
    old = {r["jar"]: r for r in old_rows}
    out = []
    for r in new_rows:
        o = old.get(r["jar"])
        if o is None:
            out.append({"jar": r["jar"], "status": "new"})
            continue
        diffs = {}
        for k in _DELTA_KEYS:
            if k in r or k in o:
                ov, nv = o.get(k), r.get(k)
                if ov != nv:
                    diffs[k] = [ov, nv]
        if diffs:
            out.append({"jar": r["jar"], "status": "changed", "diffs": diffs})
        else:
            out.append({"jar": r["jar"], "status": "same"})
    return out


def write_scorecard(rows: list[dict], out_path: Path, flags: dict,
                    compare_path: Path | None = None) -> tuple[Path, dict]:
    payload = {
        "meta": {"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                 "jdec_rev": _git_rev(), "flags": flags},
        "rows": rows,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=1),
                        encoding="utf-8")
    deltas = None
    if compare_path is not None:
        try:
            old = json.loads(Path(compare_path).read_text(encoding="utf-8"))
            deltas = compare_rows(old.get("rows", []), rows)
        except Exception as exc:  # noqa: BLE001
            print(f"! compare failed: {exc}")
        payload["compare"] = deltas
        out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=1),
                            encoding="utf-8")
    return out_path, deltas


def render_markdown(rows: list[dict], deltas: list[dict] | None,
                    flags: dict) -> str:
    L = ["# jdec scorecard", ""]
    L.append(f"flags: {json.dumps(flags)}")
    L.append("")
    cols = ["jar", "classes", "obfuscation", "obfuscator", "strings",
            "strings_suspicious"]
    if flags.get("analyze"):
        cols += ["hooks", "hook_classes"]
    if flags.get("decompile"):
        cols += ["dec_ok", "dec_partial", "dec_failed", "dec_elapsed"]
    cols.append("elapsed_s")
    L.append("| " + " | ".join(cols) + " |")
    L.append("|" + "---|" * len(cols))
    for r in rows:
        L.append("| " + " | ".join(str(r.get(c, "")) for c in cols) + " |")
    if deltas:
        L += ["", "## vs previous", ""]
        for d in deltas:
            if d["status"] == "same":
                continue
            if d["status"] == "new":
                L.append(f"- `{d['jar']}`: new")
                continue
            parts = [f"{k}: {ov} -> {nv}"
                     for k, (ov, nv) in d["diffs"].items()]
            L.append(f"- `{d['jar']}`: " + "; ".join(parts))
    return "\n".join(L) + "\n"


def collect_jars(inputs: list[str]) -> list[Path]:
    out: list[Path] = []
    for s in inputs:
        p = Path(s)
        if p.is_dir():
            out.extend(sorted(p.glob("*.jar")))
        elif p.is_file():
            out.append(p)
    # 同名去重，保序
    seen = set()
    uniq = []
    for p in out:
        if p.resolve() not in seen:
            seen.add(p.resolve())
            uniq.append(p)
    return uniq
