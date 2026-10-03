"""Dump the string constants of a jar.

Obfuscated code is unreadable, but it still has to talk to the outside world:
URLs it connects to, file names it writes, commands it shells out to, the
tokens it checks. Those literals are constant-pool entries, which is exactly
the kind of thing an obfuscator cannot rename away.

This is the cheapest possible analysis - one pass, no execution, no rewriting -
and on a cheat client it is often more productive than reading decompiled code.
"""

from __future__ import annotations

import json
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import annotations as AN
from . import classfile as CF

# literals worth a second look in a game client
_SUSPICIOUS = (
    (re.compile(r"https?://", re.I), "url"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "ip"),
    (re.compile(r"\.exe\b|\.dll\b|\.jar\b", re.I), "binary"),
    (re.compile(r"\\Users\\|/home/|%APPDATA%|\.minecraft", re.I), "path"),
    (re.compile(r"hwid|machine.?id|hardware|serial|uuid", re.I), "machine-id"),
    (re.compile(r"token|license|licence|serial|auth|password|passwd|secret", re.I),
     "credential"),
    (re.compile(r"Runtime|getRuntime|ProcessBuilder|cmd\.exe|powershell", re.I),
     "exec"),
    (re.compile(r"ClassLoader|defineClass|Unsafe", re.I), "class-loading"),
)


def classify(s: str) -> list[str]:
    """Which of the interesting categories a literal falls into."""
    out: list[str] = []
    for rx, label in _SUSPICIOUS:
        if rx.search(s):
            out.append(label)
    return out


@dataclass
class StringDump:
    rows: list[tuple[str, str, list[str]]] = field(default_factory=list)
    classes_scanned: int = 0
    classes_with_strings: int = 0
    unreadable: int = 0

    @property
    def total(self) -> int:
        return len(self.rows)

    def grep(self, needle: str) -> "StringDump":
        low = needle.lower()
        return StringDump(
            rows=[r for r in self.rows if low in r[1].lower()],
            classes_scanned=self.classes_scanned,
            classes_with_strings=self.classes_with_strings,
            unreadable=self.unreadable,
        )

    def only_suspicious(self) -> "StringDump":
        return StringDump(
            rows=[r for r in self.rows if r[2]],
            classes_scanned=self.classes_scanned,
            classes_with_strings=self.classes_with_strings,
            unreadable=self.unreadable,
        )


def dump_strings(jar: Path, limit: int = 0, min_len: int = 1) -> StringDump:
    d = StringDump()
    with zipfile.ZipFile(jar) as z:
        entries = [n for n in z.namelist()
                   if n.endswith(".class") and not n.startswith("META-INF/")]
        if limit:
            entries = entries[:limit]
        for n in entries:
            try:
                cf = CF.parse(z.read(n))
            except Exception:
                d.unreadable += 1
                continue
            d.classes_scanned += 1
            seen: set[str] = set()
            for s in AN.constant_strings(cf):
                if len(s) < min_len or s in seen:
                    continue
                seen.add(s)
                d.rows.append((cf.name, s, classify(s)))
            if seen:
                d.classes_with_strings += 1
    return d


def _cell(s: str) -> str:
    """Keep the TSV parseable and the terminal safe."""
    return (s.replace("\\", "\\\\").replace("\t", "\\t")
             .replace("\r", "\\r").replace("\n", "\\n"))


def write_tsv(d: StringDump, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        f.write("class\tstring\ttags\n")
        for cls, s, tags in d.rows:
            f.write(f"{cls}\t{_cell(s)}\t{','.join(tags)}\n")
    return path


def write_json(d: StringDump, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    by_class: dict[str, list] = {}
    for cls, s, tags in d.rows:
        by_class.setdefault(cls, []).append({"string": s, "tags": tags})
    path.write_text(json.dumps(
        {"classes_scanned": d.classes_scanned, "total": d.total,
         "unreadable": d.unreadable, "strings": by_class},
        indent=1, ensure_ascii=False), encoding="utf-8")
    return path
