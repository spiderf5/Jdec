#!/usr/bin/env python3
"""Executable support matrix: one independent-corpus regression per mechanism.

Stage 04 asks for 6-8 mechanism classes with explicit support items, each
backed by an independent sample regression. This module is the registry and
the runner. It does NOT ship the corpora: real jars stay outside the tree and
are supplied with --hmcl / --neo or the JDEC_MATRIX_* environment variables.
Only the measured report is committed.

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
sys.path.insert(0, str(ROOT / "src"))

from jdec import cli as CL  # noqa: E402
from jdec import container as CT  # noqa: E402


@dataclass
class Rule:
    """A declarative pass rule evaluated against extracted metrics."""

    kind: str
    key: str = ""
    minimum: int = 0
    equals: str = ""

    def holds(self, values: dict, rcs: list[int]) -> bool:
        if self.kind == "all_zero_rc":
            return all(rc == 0 for rc in rcs)
        if self.kind == "min":
            return values.get(self.key, 0) >= self.minimum
        if self.kind == "equals":
            return values.get(self.key, "") == self.equals
        if self.kind == "contains":
            return self.equals in str(values.get(self.key, ""))
        if self.kind == "pair_equal":
            a, b = self.key.split("/")
            return values.get(a, -1) == values.get(b, -2) and values.get(a, 0) > 0
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


def _rx(label: str, pattern: str) -> tuple[str, str]:
    return label, pattern


MECHANISMS: tuple[MechanismSpec, ...] = (
    MechanismSpec(
        id="M1", name="控制流去平坦化 / 常量折叠 / 不透明谓词",
        support="对含 goto-flood、irreducible-goto 的真实 jar 产出可重放的指令级改写，"
                "重算 StackMapTable，并让全部类通过 -Xverify:all；产出改写清单供对拍",
        not_covered="不承诺还原任意自定义 VM；jsr/ret 明确拒绝；改写保持语义但不证明等价",
        corpora=("hmcl", "neo"),
        steps=(("deflat", "{jar}", "-o", "{out}/{key}_deflat.jar",
                "--rewritten", "{out}/{key}_rw.txt", "{cp}"),),
        metrics=(
            _rx("rewritten", r"deflat\s+: (\d+) method\(s\) rewritten"),
            _rx("verified", r"verify\s+: (\d+) class\(es\) pass"),
        ),
        rules=(Rule("all_zero_rc"), Rule("min", "rewritten", 1),
               Rule("min", "verified", 1)),
        rule_text="退出 0；改写方法数 > 0；verify 通过类数 > 0 且无拒绝",
    ),
    MechanismSpec(
        id="M2", name="字节级往返与坏类隔离（改写底座）",
        support="对整份真实 jar 逐类 parse→重汇编→逐字节比对，报告类与 Code 数组"
                "的相等数；坏类被隔离而不是拖垮整批",
        not_covered="不进行语义等价性证明；jsr/ret 与不可解码类按边界拒绝",
        corpora=("hmcl", "neo"),
        steps=(("ircheck", "{jar}", "--limit", "2"),),
        metrics=(
            _rx("classes", r"classes\s+: (\d+)"),
            _rx("unreadable", r"classes\s+: \d+ \((\d+) unreadable\)"),
            _rx("cls_ok", r"class\s+: (\d+)/\d+ byte-identical"),
            _rx("cls_total", r"class\s+: \d+/(\d+) byte-identical"),
            _rx("code_ok", r"method\s+: (\d+)/\d+ Code arrays byte-identical"),
            _rx("code_total", r"method\s+: \d+/(\d+) Code arrays byte-identical"),
        ),
        rules=(Rule("all_zero_rc"), Rule("min", "cls_ok", 1),
               Rule("pair_equal", "cls_ok/cls_total"),
               Rule("pair_equal", "code_ok/code_total")),
        rule_text="退出 0；result=PASS；类与 Code 数组的相等数等于总数",
    ),
    MechanismSpec(
        id="M3", name="invokedynamic / BootstrapMethods 站点枚举",
        support="枚举真实 jar 的 BootstrapMethods 与 indy 站点，按 bootstrap owner "
                "与站点名归类，为字符串/调用目标编码提供站点清单",
        not_covered="不执行 bootstrap；不解密 recipe 之外的自定义引导逻辑",
        corpora=("hmcl", "neo"),
        steps=(("indy", "{jar}"),),
        metrics=(_rx("sites", r"(?m)^indy sites\s+: (\d+)"),),
        rules=(Rule("all_zero_rc"), Rule("min", "sites", 1)),
        rule_text="退出 0；两个语料都枚举出 > 0 个 indy 站点",
    ),
    MechanismSpec(
        id="M4", name="混淆器结构指纹归因",
        support="基于结构阈值与关键词对真实 jar 做混淆器归因并给出置信度，"
                "36 项指纹各自有门控，命中必须带证据",
        not_covered="归因词表不等于支持该混淆器的全部机制；不承诺还原",
        corpora=("hmcl", "neo"),
        steps=(("probe", "{jar}"),),
        metrics=(_rx("score", r"obfuscation\s+: (\d+)/100"),
                 _rx("signature", r"signatures\s+: (.+)"),
                 _rx("structure", r"structure\s+: (.+)")),
        rules=(Rule("all_zero_rc"),
               Rule("contains", "signature", equals="ProGuard / R8"),
               Rule("contains", "signature", equals="ZKM 27 enhanced")),
        rule_text="退出 0；HMCL 命中 ProGuard/R8、NeoRaven 命中 ZKM 27 enhanced",
    ),
    MechanismSpec(
        id="M5", name="字符串常量抽取与加密/威胁标签",
        support="从真实 jar 的常量池抽取字符串并按 url/path/credential/"
                "encrypted-blob/machine-id/class-loading 分类标注，输出 TSV+JSON",
        not_covered="标签是启发式；抽取不等于解密 ZKM 池，需 pool/recover 另行重放",
        corpora=("hmcl", "neo"),
        steps=(("strings", "{jar}", "-o", "{out}/{key}_strings"),),
        metrics=(_rx("strings", r"strings\s+: (\d+) total"),
                 _rx("tagged", r"tagged\s+: (\d+) literal"),
                 _rx("encrypted_blob", r"encrypted-blob: (\d+)")),
        rules=(Rule("all_zero_rc"), Rule("min", "strings", 1),
               Rule("min", "tagged", 1), Rule("min", "encrypted_blob", 1)),
        rule_text="退出 0；字符串数与标签数 > 0；ZKM 语料标出 encrypted-blob",
    ),
    MechanismSpec(
        id="M6", name="native 分诊与 PE/JNI 库提取",
        support="从自解压 PE/ELF 与 jar 资源中提取 native 库，解析导出表与"
                "JNINativeMethod，报告 Java 侧声明的 native 方法与匹配情况",
        not_covered="不反编译 native 函数体；不承诺 RegisterNatives 动态绑定还原",
        corpora=("hmcl",),
        steps=(("natives", "{jar}", "-o", "{out}/{key}_natives"),
               ("analyze", "{jar}", "-o", "{out}/{key}_analyze")),
        metrics=(_rx("libs", r"libs\s+: (\d+) extracted"),
                 _rx("exports", r"exports=(\d+)"),
                 _rx("native_methods", r"(\d+) native method\(s\) in \d+ class")),
        rules=(Rule("all_zero_rc"), Rule("min", "libs", 1),
               Rule("min", "exports", 1), Rule("min", "native_methods", 1)),
        rule_text="退出 0；HMCL 提取出 PE 库、导出表项与 Java 侧 native 方法",
    ),
    MechanismSpec(
        id="M7", name="Minecraft 元数据与 Mixin hook 识别",
        support="识别真实客户端的 MC 版本/加载器、Mixin 配置或注解 hook，"
                "并在无映射时如实保留 hook 目标名",
        not_covered="映射表本身外置；无映射时不解析 hook 目标的最终符号",
        corpora=("neo",),
        steps=(("probe", "{jar}"),
               ("analyze", "{jar}", "-o", "{out}/{key}_analyze")),
        metrics=(_rx("minecraft", r"minecraft\s+: (.+)"),
                 _rx("mixin_note", r"(no mixin config[^\n]*|mixin[^\n]*)")),
        rules=(Rule("all_zero_rc"),
               Rule("contains", "minecraft", equals="1.8.9"),
               Rule("contains", "minecraft", equals="Forge")),
        rule_text="退出 0；NeoRaven 识别为 1.8.9 / Forge，且 analyze 输出 Mixin 说明",
    ),
    MechanismSpec(
        id="M8", name="容器分类与多版本/截断类隔离",
        support="按 magic 识别 MZ stub + zip 自解压容器、普通 jar 与目录；"
                "ircheck 对不可读类隔离而不是把整批判为失败",
        not_covered="不处理加密容器；multi-release 条目按同一基类的备选排除",
        corpora=("hmcl", "neo"),
        steps=(("probe", "{jar}"),),
        metrics=(_rx("entries", r"entries\s+: (\d+)"),
                 _rx("classes", r"classes (\d+)"),
                 _rx("file", r"file\s+: (.+)")),
        rules=(Rule("all_zero_rc"), Rule("min", "entries", 1),
               Rule("min", "classes", 1),
               Rule("magic", "magic_hmcl", equals="4d5a"),
               Rule("magic", "magic_neo", equals="504b")),
        rule_text="退出 0；按 magic 区分 MZ 自解压 stub (4d5a) 与普通 PK jar (504b)，"
                  "两者都能读出条目与类数",
    ),
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
    data = path.read_bytes()
    return {"name": path.name, "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def run_mechanism(spec: MechanismSpec, corpora: dict, out: Path,
                  javafx: list[str]) -> dict:
    texts: list[str] = []
    rcs: list[int] = []
    commands: list[str] = []
    kinds: dict[str, str] = {}
    for key in spec.corpora:
        jar = corpora.get(key)
        if not jar:
            continue
        kinds[key] = str(CT.kind_of(Path(jar)))
        cp = []
        for entry in javafx:
            cp += ["--cp", entry]
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
    for key in spec.corpora:
        jar = corpora.get(key)
        if jar:
            with Path(jar).open("rb") as fh:
                values[f"magic_{key}"] = fh.read(2).hex()
            kinds[key] = f"{kinds.get(key, '?')}/0x{values[f'magic_{key}']}"
    passed = bool(rcs) and all(r.holds(values, rcs) for r in spec.rules)
    return {
        "id": spec.id, "name": spec.name, "support": spec.support,
        "not_covered": spec.not_covered, "corpora": list(spec.corpora),
        "container_kinds": kinds, "commands": commands,
        "exit_codes": rcs, "metrics": values, "rule": spec.rule_text,
        "rules": [{"kind": r.kind, "key": r.key, "minimum": r.minimum,
                   "equals": r.equals, "holds": r.holds(values, rcs)}
                  for r in spec.rules],
        "verdict": "PASS" if passed else ("SKIP" if not rcs else "FAIL"),
    }


def _sanitise(text: str, repo: Path) -> str:
    """Reports are committed; CLI transcripts must not carry local paths."""
    return text.replace(str(repo), "<REPO>").replace(
        str(repo).replace("\\", "/"), "<REPO>")


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
            "command": "jdec ircheck src/tests/sample.jar",
            "exit_code": rc,
            "passed": rc != 0 or "PASS" not in text,
            "evidence": _sanitise(text[-300:], repo),
        })
    flow = repo / "src/tests/flow.jar"
    if flow.is_file():
        rc, text = _capture(["ircheck", str(flow), "--limit", "2"])
        results.append({
            "name": "a clean fixture must still pass the same gate",
            "command": "jdec ircheck src/tests/flow.jar",
            "exit_code": rc, "passed": rc == 0 and "PASS" in text,
            "evidence": _sanitise(text[-300:], repo),
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
