#!/usr/bin/env python3
"""Executable support matrix: one independent-corpus regression per mechanism.

Stage 04 asks for 6-8 mechanism classes with explicit support items, each
backed by an independent sample regression. This module is the registry and
the runner. It does NOT ship the corpora: real jars stay outside the tree and
are supplied with --hmcl / --neo or the JDEC_MATRIX_* environment variables.
The report is generated on demand and not committed: it is evidence
for the code state that produced it, and it went stale twice.

Two modes:
  * full       - run every mechanism against the two real corpora and write a
                 JSON report with per-mechanism numbers and a verdict.
  * --selfcheck - run only the in-repo negative controls, so CI can prove the
                 harness is honest without holding authorised samples.

Generated fixtures are used ONLY as negative controls. They are never counted
as independent samples and never upgrade a mechanism's evidence level.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import platform
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT / "src"))

from jdec import cli as CL  # noqa: E402
from jdec import container as CT  # noqa: E402
from jdec.mechanisms import MECHANISMS as MECH  # noqa: E402


@dataclass
class Rule:
    """A declarative pass rule evaluated against extracted metrics.

    ``scope`` decides which corpora a rule must hold for. ``all`` (default)
    checks every declared corpus independently, ``any`` checks the aggregate
    once, and a corpus key such as ``neo`` restricts the check to that corpus.
    Rules whose evidence is inherently cross-corpus (joined signature text,
    container magic injected after extraction) use ``any``.
    """

    kind: str
    key: str = ""
    minimum: int = 0
    equals: str = ""
    scope: str = "all"

    def holds(self, values: dict, rcs: list[int]) -> bool:
        if self.kind == "all_zero_rc":
            return bool(rcs) and all(rc == 0 for rc in rcs)
        if self.kind == "min":
            value = values.get(self.key, 0)
            return isinstance(value, int) and value >= self.minimum
        if self.kind == "equals":
            return values.get(self.key, "") == self.equals
        if self.kind == "contains":
            return bool(self.equals) and self.equals in str(values.get(self.key, ""))
        if self.kind == "absent":
            return bool(self.equals) and self.equals not in str(
                values.get(self.key, ""))
        if self.kind == "max":
            value = values.get(self.key, 0)
            return isinstance(value, int) and value <= self.minimum
        if self.kind == "pair_equal":
            if "/" not in self.key:
                return False
            a, b = self.key.split("/", 1)
            va, vb = values.get(a, -1), values.get(b, -2)
            return va == vb and va > 0
        if self.kind == "magic":
            return values.get(self.key) == self.equals
        return False


@dataclass
class MechanismSpec:
    id: str
    name: str
    support: str
    not_covered: str
    corpora: tuple[str, ...]
    steps: tuple[tuple[str, ...], ...]
    metrics: tuple[tuple[str, str], ...]
    rules: tuple[Rule, ...]
    rule_text: str
    expected: dict[str, str] = field(default_factory=dict)


#: What "this command still works" means, per mechanism. The claim itself
#: (support / not_covered), the corpora and the CLI chain live in
#: `mechanisms.py`: this layer used to carry a second copy and the two drifted
#: (the diagnostic copy still described M1 as goto-flood rewriting after the
#: acceptance layer had separated javac's switch lowering from flattening).
_RULES: dict[str, tuple[tuple[Rule, ...], str]] = {
    "M1": ((Rule("all_zero_rc"), Rule("min", "rewritten", 1),
            Rule("min", "verified", 1)),
           "退出 0；改写方法数 > 0；verify 通过类数 > 0 且无拒绝"),
    "M2": ((Rule("all_zero_rc"), Rule("min", "cls_ok", 1),
            Rule("pair_equal", "cls_ok/cls_total"),
            Rule("pair_equal", "code_ok/code_total")),
           "退出 0；result=PASS；类与 Code 数组的相等数等于总数"),
    "M3": ((Rule("all_zero_rc"), Rule("min", "sites", 1)),
           "退出 0；两个语料都枚举出 > 0 个 indy 站点"),
    "M4": ((Rule("all_zero_rc"),
            Rule("contains", "signature", equals="ProGuard / R8", scope="any"),
            Rule("absent", "signature", equals="ZKM 27 enhanced", scope="any")),
           "退出 0；HMCL 命中 ProGuard/R8；两语料均不得误报 ZKM 27 "
           "（独立金标准确认常量池无 DESKeySpec / DES-CBC / zelix）"),
    "M5": ((Rule("all_zero_rc"), Rule("min", "strings", 1),
            Rule("min", "tagged", 1),
            Rule("max", "encrypted_blob", 0, scope="any")),
           "退出 0；字符串数与标签数 > 0；独立金标准确认无 DES 密文的语料"
           "不得标出 encrypted-blob（旧规则的 8 个全是内部类名假阳性）"),
    "M6": ((Rule("all_zero_rc"), Rule("min", "libs", 1),
            Rule("min", "exports", 1), Rule("min", "native_methods", 1)),
           "退出 0；HMCL 提取出 PE 库、导出表项与 Java 侧 native 方法"),
    "M7": ((Rule("all_zero_rc"),
            Rule("contains", "minecraft", equals="1.8.9"),
            Rule("contains", "minecraft", equals="Forge")),
           "退出 0；NeoRaven 识别为 1.8.9 / Forge，且 analyze 输出 Mixin 说明"),
    "M8": ((Rule("all_zero_rc"), Rule("min", "entries", 1),
            Rule("min", "classes", 1),
            Rule("magic", "magic_hmcl", equals="4d5a", scope="any"),
            Rule("magic", "magic_neo", equals="504b", scope="any")),
           "退出 0；按 magic 区分 MZ 自解压 stub (4d5a) 与普通 PK jar (504b)，"
           "两者都能读出条目与类数"),
}


MECHANISMS: tuple[MechanismSpec, ...] = tuple(
    MechanismSpec(
        id=m.id, name=m.name, support=m.support, not_covered=m.not_covered,
        corpora=m.diag_corpora, steps=m.diag_steps,
        metrics=tuple(m.patterns.items()),
        rules=_RULES[m.id][0], rule_text=_RULES[m.id][1],
    )
    for m in MECH
)



def _capture(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            rc = CL.main(argv)
        except SystemExit as exc:  # argparse --help etc.
            rc = int(exc.code or 0)
    return rc, buf.getvalue()


def _extract(text: str, metrics: tuple[tuple[str, str], ...]) -> dict:
    """Aggregate every match across all corpora/steps, not just the first one.

    Counts keep the maximum (each corpus is measured separately); text values
    are joined so a rule can look for a signature from either corpus.
    """
    out: dict = {}
    for label, pattern in metrics:
        vals: list[str] = []
        for m in re.finditer(pattern, text):
            vals.append((m.group(1) if m.groups() else "1").strip())
        if not vals:
            continue
        if all(v.isdigit() for v in vals):
            out[label] = max(int(v) for v in vals)
        else:
            seen: list[str] = []
            for v in vals:
                if v not in seen:
                    seen.append(v)
            out[label] = " | ".join(seen)
    return out


def _corpus_info(path: Path) -> dict:
    """Hash in 1 MiB chunks: these corpora are 10-15 MB each."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
    return {"name": path.name, "size": size, "sha256": digest.hexdigest()}


def run_mechanism(spec: MechanismSpec, corpora: dict, out: Path,
                  javafx: list[str]) -> dict:
    texts: list[str] = []
    rcs: list[int] = []
    commands: list[str] = []
    kinds: dict[str, str] = {}
    per_texts: dict[str, list[str]] = {}
    per_rcs: dict[str, list[int]] = {}
    for key in spec.corpora:
        jar = corpora.get(key)
        if not jar:
            continue
        kinds[key] = str(CT.kind_of(Path(jar)))
        cp: list[str] = []
        for entry in javafx:
            cp += ["--cp", entry]
        per_texts[key] = []
        per_rcs[key] = []
        for step in spec.steps:
            argv: list[str] = []
            for part in step:
                if part == "{cp}":
                    argv.extend(cp)
                else:
                    argv.append(part.format(jar=str(jar), out=str(out), key=key))
            rc, text = _capture(argv)
            rcs.append(rc)
            texts.append(text)
            per_rcs[key].append(rc)
            per_texts[key].append(text)
            # The report is committed; never leak local absolute paths.
            safe: list[str] = []
            for part in argv:
                cleaned = str(part)
                for ckey, cpath in corpora.items():
                    cleaned = cleaned.replace(str(cpath), f"<{ckey.upper()}>")
                cleaned = cleaned.replace(str(out), "<WORKDIR>")
                for entry in javafx:
                    cleaned = cleaned.replace(entry, Path(entry).name)
                safe.append(cleaned)
            commands.append("jdec " + " ".join(safe))
    combined = "\n".join(texts)
    values = _extract(combined, spec.metrics)
    # magic_* keys are injected AFTER _extract: they are file facts, not
    # stdout metrics, so rules reading them must declare scope="any".
    extras: dict[str, str] = {}
    for key in spec.corpora:
        jar = corpora.get(key)
        if jar:
            with Path(jar).open("rb") as fh:
                extras[f"magic_{key}"] = fh.read(2).hex()
            kinds[key] = f"{kinds.get(key, '?')}/0x{extras[f'magic_{key}']}"
    values.update(extras)

    per_values: dict[str, dict] = {}
    for key, ctexts in per_texts.items():
        pv = _extract("\n".join(ctexts), spec.metrics)
        pv.update(extras)
        per_values[key] = pv

    # `_extract` keeps the MAX per metric for the report. Feeding that
    # aggregate into a per-corpus rule let one corpus with a big number hide
    # a zero on another, so rules are now evaluated against each corpus's own
    # metrics. `any` rules keep the aggregate for genuinely cross-corpus facts.
    complete = len(per_rcs) == len(spec.corpora)
    holds: list[bool] = []
    for rule in spec.rules:
        if rule.scope == "any":
            ok = rule.holds(values, rcs)
        elif rule.scope in per_rcs:
            ok = rule.holds(per_values[rule.scope], per_rcs[rule.scope])
        else:
            ok = bool(per_rcs) and all(
                rule.holds(per_values[k], rs) for k, rs in per_rcs.items())
        holds.append(ok)
    passed = complete and bool(rcs) and all(holds)
    return {
        "id": spec.id, "name": spec.name, "support": spec.support,
        "not_covered": spec.not_covered, "corpora": list(spec.corpora),
        "container_kinds": kinds, "commands": commands,
        "exit_codes": rcs, "metrics": values,
        "per_corpus": {k: {"metrics": per_values[k], "exit_codes": per_rcs[k]}
                       for k in per_rcs},
        "rule": spec.rule_text,
        "rules": [{"kind": r.kind, "key": r.key, "minimum": r.minimum,
                   "equals": r.equals, "scope": r.scope, "holds": ok}
                  for r, ok in zip(spec.rules, holds)],
        "verdict": "PASS" if passed else ("SKIP" if not rcs else "FAIL"),
    }

def _sanitise(text: str, repo: Path, out: Path | None = None) -> str:
    """Reports are committed; CLI transcripts must not carry local paths."""
    clean = text.replace(str(repo), "<REPO>").replace(
        str(repo).replace("\\", "/"), "<REPO>")
    if out is not None:
        clean = clean.replace(str(out), "<WORKDIR>").replace(
            str(out).replace("\\", "/"), "<WORKDIR>")
    return clean


SCOPE_NOTE = (
    "Diagnostic CLI smoke checks only. PASS means eight EXISTING CLI commands "
    "ran on two real jars and produced non-empty numbers of the expected shape. "
    "It is NOT evidence that ROADMAP stage 04 is met: no mechanism implementation "
    "was added by this harness, most rules are self-referential existence checks, "
    "and the strict 'independent sample regression per mechanism' is unverified. "
    "See docs/SUPPORT_MATRIX.md section 9."
)


def negative_controls(repo: Path, out: Path) -> list[dict]:
    """In-repo fixtures only: prove the gates are not vacuously true."""
    results = []
    sample = repo / "src/tests/sample.jar"   # deliberately truncated class
    if sample.is_file():
        rc, text = _capture(["ircheck", str(sample), "--limit", "2"])
        results.append({
            "name": "a truncated class must not be reported as a clean PASS",
            "command": "jdec ircheck src/tests/sample.jar --limit 2",
            "exit_code": rc,
            "passed": rc != 0 or "PASS" not in text,
            "evidence": _sanitise(text[-300:], repo, out),
        })
    flow = repo / "src/tests/flow.jar"
    if flow.is_file():
        rc, text = _capture(["ircheck", str(flow), "--limit", "2"])
        results.append({
            "name": "a clean fixture must still pass the same gate",
            "command": "jdec ircheck src/tests/flow.jar --limit 2",
            "exit_code": rc, "passed": rc == 0 and "PASS" in text,
            "evidence": _sanitise(text[-300:], repo, out),
        })
    return results


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--hmcl", default=os.environ.get("JDEC_MATRIX_HMCL"))
    p.add_argument("--neo", default=os.environ.get("JDEC_MATRIX_NEO"))
    p.add_argument("--javafx-dir", default=os.environ.get("JDEC_MATRIX_JAVAFX"),
                   help="directory holding the three JavaFX jars (classpath is "
                        "part of the deflat measurement)")
    p.add_argument("--json", type=Path, default=None)
    p.add_argument("--workdir", type=Path, default=None)
    p.add_argument("--selfcheck", action="store_true",
                   help="only run in-repo negative controls (CI mode)")
    args = p.parse_args(argv)

    import tempfile
    keep = None
    if args.workdir:
        args.workdir.mkdir(parents=True, exist_ok=True)
        out = args.workdir
    else:
        keep = tempfile.TemporaryDirectory(prefix="jdec_matrix_")
        out = Path(keep.name)

    javafx: list[str] = []
    if args.javafx_dir:
        javafx = [str(x) for x in sorted(Path(args.javafx_dir).glob("javafx-*.jar"))]

    try:
        report: dict = {
            "schema": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "python": platform.python_version(),
            "mode": "selfcheck" if args.selfcheck else "full",
            "javafx_entries": [Path(x).name for x in javafx],
            "mechanisms": [], "negative_controls": [],
            "note": ("Real corpora stay outside the tree; generated fixtures "
                     "are negative controls only and are NOT independent samples."),
        }
        neg = negative_controls(ROOT, out)
        report["negative_controls"] = neg
        if args.selfcheck:
            ok = bool(neg) and all(n["passed"] for n in neg)
            report["verdict"] = "PASS" if ok else "FAIL"
            report["scope"] = SCOPE_NOTE
            report["stage_04_threshold_met"] = False
            if args.json:
                args.json.parent.mkdir(parents=True, exist_ok=True)
                args.json.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                                     encoding="utf-8", newline="\n")
            print(f"selfcheck: {sum(n['passed'] for n in neg)}/{len(neg)} controls passed")
            return 0 if ok else 1

        corpora = {}
        for key, value in (("hmcl", args.hmcl), ("neo", args.neo)):
            if value and Path(value).is_file():
                corpora[key] = Path(value)
        report["corpora"] = {k: _corpus_info(v) for k, v in corpora.items()}
        report["missing_corpora"] = [k for k in ("hmcl", "neo") if k not in corpora]

        for spec in MECHANISMS:
            entry = run_mechanism(spec, corpora, out, javafx)
            report["mechanisms"].append(entry)
            print(f"  {entry['id']} {entry['verdict']:<4} {entry['name']}")
            print(f"      metrics: {entry['metrics']}")

        passed = sum(m["verdict"] == "PASS" for m in report["mechanisms"])
        neg_ok = bool(neg) and all(n["passed"] for n in neg)
        overall = (passed == len(MECHANISMS) and neg_ok
                   and not report["missing_corpora"])
        report["passed"] = passed
        report["total"] = len(MECHANISMS)
        report["verdict"] = "PASS" if overall else "FAIL"
        report["scope"] = SCOPE_NOTE
        report["stage_04_threshold_met"] = False
        if args.json:
            args.json.parent.mkdir(parents=True, exist_ok=True)
            args.json.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                                 encoding="utf-8", newline="\n")
        print(f"\nsupport matrix: {passed}/{len(MECHANISMS)} mechanisms PASS, "
              f"{sum(n['passed'] for n in neg)}/{len(neg)} negative controls, "
              f"verdict {report['verdict']}")
        if report["missing_corpora"]:
            print("missing corpora: " + ", ".join(report["missing_corpora"]))
        if args.json:
            print(f"report: {args.json}")
        return 0 if overall else 1
    finally:
        if keep is not None:
            keep.cleanup()


if __name__ == "__main__":
    sys.exit(main())
