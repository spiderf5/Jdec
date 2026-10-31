"""Byte-exactness gate: parse a class, rebuild it, compare with the input.

This is deliberately dumb and deliberately strict. It does not score, it does
not "mostly" pass, and it does not know what an obfuscator is. Either the
bytes come back identical or the layer below the IR is not ready.

Two levels are checked, because they fail for different reasons:

  class   `classfile.parse(x).serialize() == x`
          catches lost/duplicated attributes, constant-pool reordering, and
          mUTF-8 round-trip damage

  method  `bytecode.encode(bytecode.decode(code)) == code`
          catches assembler bugs: switch padding, `wide` operands, the
          trailing bytes of invokeinterface/invokedynamic, multianewarray's
          dimension byte, s16 branch ranges

A method whose Code attribute cannot even be decoded is reported as
`undecodable`, not as a pass. "We could not look" and "we looked and it was
fine" are different answers; stage 01 of the roadmap exists because they used
to be conflated.
"""

from __future__ import annotations

import json
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .. import annotations as AN
from .. import bytecode as BC
from .. import classfile as CF


@dataclass
class MethodMismatch:
    """One method that did not come back byte-identical."""

    cls: str
    method: str
    desc: str
    reason: str                 # decode | encode | bytes
    detail: str = ""
    original_len: int = 0
    produced_len: int = 0
    first_diff: int = -1

    def to_dict(self) -> dict:
        return {
            "class": self.cls, "method": self.method, "descriptor": self.desc,
            "reason": self.reason, "detail": self.detail,
            "original_len": self.original_len,
            "produced_len": self.produced_len,
            "first_diff": self.first_diff,
        }

    def describe(self) -> str:
        where = f"{self.cls}.{self.method}{self.desc}"
        if self.reason == "bytes":
            return (f"{where}: {self.original_len} -> {self.produced_len} bytes, "
                    f"first difference at offset {self.first_diff}")
        return f"{where}: {self.reason}: {self.detail}"


@dataclass
class AuditReport:
    target: str = ""
    classes: int = 0
    classes_unreadable: int = 0
    class_mismatch: list[str] = field(default_factory=list)
    methods: int = 0
    methods_undecodable: int = 0
    methods_no_code: int = 0
    mismatches: list[MethodMismatch] = field(default_factory=list)
    undecodable: list[str] = field(default_factory=list)
    elapsed: float = 0.0

    @property
    def ok(self) -> bool:
        return (not self.class_mismatch and not self.mismatches
                and self.classes > 0 and self.methods > 0)

    @property
    def checked_classes(self) -> int:
        return self.classes - len(self.class_mismatch)

    def summary(self) -> str:
        lines = [
            f"target    : {self.target}",
            f"classes   : {self.classes} ({self.classes_unreadable} unreadable)",
            f"class     : {self.checked_classes}/{self.classes} byte-identical",
            f"method    : {self.methods - len(self.mismatches)}/{self.methods} "
            f"Code arrays byte-identical",
        ]
        if self.methods_undecodable:
            lines.append(f"not covered: {self.methods_undecodable} method(s) whose "
                         f"Code attribute could not be decoded")
        if self.methods_no_code:
            lines.append(f"no code   : {self.methods_no_code} abstract/native method(s)")
        lines.append(f"elapsed   : {self.elapsed:.2f}s")
        lines.append(f"result    : {'PASS' if self.ok else 'FAIL'}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "classes": self.classes,
            "classes_unreadable": self.classes_unreadable,
            "class_mismatch": list(self.class_mismatch),
            "methods": self.methods,
            "methods_undecodable": self.methods_undecodable,
            "methods_no_code": self.methods_no_code,
            "mismatches": [m.to_dict() for m in self.mismatches],
            "undecodable": list(self.undecodable),
            "elapsed_seconds": round(self.elapsed, 3),
            "ok": self.ok,
        }

    def write_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2),
                        encoding="utf-8")


def _first_diff(a: bytes, b: bytes) -> int:
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    return -1 if len(a) == len(b) else n


def audit_class_bytes(data: bytes, name: str,
                      report: AuditReport) -> None:
    """Round-trip one class file, recording the outcome in `report`."""
    try:
        cf = CF.parse(data)
    except Exception:
        report.classes_unreadable += 1
        return
    report.classes += 1

    rebuilt = cf.serialize()
    if rebuilt != data:
        report.class_mismatch.append(name)

    for m in cf.methods:
        label = cf.utf8(m.name_index) if m.name_index else "?"
        desc = cf.utf8(m.descriptor_index) if m.descriptor_index else "?"
        try:
            payload = AN.member_attributes(cf, m).get("Code")
        except Exception as exc:  # malformed attribute table: do not guess
            report.methods_undecodable += 1
            if len(report.undecodable) < 50:
                report.undecodable.append(f"{name}.{label}{desc}: {exc}")
            continue
        if not payload:
            # abstract or native: there is no bytecode to reproduce, and that
            # is different from "there is bytecode we cannot read"
            report.methods_no_code += 1
            continue
        try:
            ci = BC.parse_code(payload, decode_insns=False)
        except BC.BytecodeError as exc:
            report.methods_undecodable += 1
            if len(report.undecodable) < 50:
                report.undecodable.append(f"{name}.{label}{desc}: {exc}")
            continue
        try:
            insns = BC.decode(ci.code)
        except BC.BytecodeError as exc:
            report.methods_undecodable += 1
            if len(report.undecodable) < 50:
                report.undecodable.append(f"{name}.{label}{desc}: {exc}")
            continue
        report.methods += 1
        try:
            produced = BC.encode(insns)
        except BC.BytecodeError as exc:
            report.mismatches.append(MethodMismatch(
                name, label, desc, "encode", str(exc),
                original_len=len(ci.code)))
            continue
        if produced != ci.code:
            report.mismatches.append(MethodMismatch(
                name, label, desc, "bytes",
                original_len=len(ci.code), produced_len=len(produced),
                first_diff=_first_diff(ci.code, produced)))


def audit_jar(path: Path) -> AuditReport:
    report = AuditReport(target=str(path))
    t0 = time.time()
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if not info.filename.endswith(".class"):
                continue
            audit_class_bytes(z.read(info.filename),
                              info.filename[:-len(".class")], report)
    report.elapsed = time.time() - t0
    return report


def audit_dir(path: Path) -> AuditReport:
    report = AuditReport(target=str(path))
    t0 = time.time()
    for f in sorted(path.rglob("*.class")):
        rel = f.relative_to(path).as_posix()
        audit_class_bytes(f.read_bytes(), rel[:-len(".class")], report)
    report.elapsed = time.time() - t0
    return report


def audit_path(path: Path) -> AuditReport:
    """Audit a jar, a .class file, or a directory tree of classes."""
    p = Path(path)
    if p.is_dir():
        return audit_dir(p)
    if p.suffix.lower() in (".jar", ".zip"):
        return audit_jar(p)
    report = AuditReport(target=str(p))
    t0 = time.time()
    audit_class_bytes(p.read_bytes(), p.stem, report)
    report.elapsed = time.time() - t0
    return report
