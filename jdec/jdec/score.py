"""Scoring decompiler output against bytecode ground truth.

The whole point of running several engines is being able to tell which one
actually won. Guessing from file size or line count is worthless, so we use
the class file itself as the answer key: every field and method that exists in
the bytecode should show up as an identifier in the source. A method that the
decompiler dropped, or that collapsed into "// couldn't be decompiled", simply
will not appear.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .classfile import ClassFile

_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")

# phrases that mean the engine gave up on at least part of the class
_HARD_ERROR_PATTERNS = [
    re.compile(p, re.I) for p in (
        r"could\s*n'?o?t\s+be\s+decompiled",
        r"unable\s+to\s+decompile",
        r"failed\s+to\s+decompile",
        r"internal\s+error",
        r"decompiler\s+error",
        r"stack\s*overflow",
        r"unsupported\s+class\s+version",
        r"\$FF:\s*couldn",
        r"error\s+while\s+decompiling",
        r"exception\s+in\s+thread",
        r"method\s+dump\s+skipped",
        r"decompilation\s+failed",
        r"decompilation\s+aborted",
    )
]

# bytecode mnemonics leaking into what is supposed to be Java source
_LEFTOVER_RE = re.compile(
    r"\b(?:iload|istore|aload|astore|lload|lstore|dload|dstore|fload|fstore"
    r"|invokevirtual|invokespecial|invokestatic|invokeinterface|invokedynamic"
    r"|getfield|putfield|getstatic|putstatic|iconst|lconst|bipush|sipush"
    r"|areturn|ireturn|lreturn|dreturn|freturn|anewarray|newarray|multianewarray"
    r"|monitorenter|monitorexit|checkcast|jsr|dup2?|swap|pop2?|tableswitch"
    r"|lookupswitch)\b"
)

_SUGAR_PATTERNS = {
    "lambda": re.compile(r"->"),
    "for-each": re.compile(r"for\s*\([^;)]*\s+:\s+"),
    "switch": re.compile(r"\bswitch\s*\("),
    "try-with-resources": re.compile(r"try\s*\([^)]*\)"),
    "generics": re.compile(r"<[A-Z][A-Za-z0-9_$]*(?:\s*,\s*[A-Z?][^<>]*)?>[\s(]"),
    "var": re.compile(r"\bvar\s+[A-Za-z_$]"),
    "string-switch": re.compile(r"\bswitch\s*\(\s*[A-Za-z_$][\w$]*\s*\)"),
}


@dataclass
class Quality:
    score: float
    coverage: float
    matched: int
    total: int
    hard_error: bool
    leftover: int
    unbalanced: bool
    sugar: list[str] = field(default_factory=list)
    lines: int = 0
    issues: list[str] = field(default_factory=list)
    # `hard_error` stays "the engine printed a give-up note somewhere", which is
    # not the same as "the class is unusable"; this is the stricter question.
    class_level_failure: bool = False
    damaged_fraction: float = 0.0

    @property
    def usable(self) -> bool:
        return (not self.class_level_failure) and self.score >= 40.0


def _member_name_floor(cf: ClassFile) -> int:
    """How short a member name may be and still count as recovered.

    A fixed floor of 3 quietly destroys the measurement on obfuscated input:
    ZKM renames everything to a, b, c, so every candidate is filtered out,
    the candidate set empties, coverage becomes 1.0 and the worst-recovered
    class in the jar scores highest. When most member names are already short,
    the class *is* the obfuscated case and the floor has to drop to 1.
    """
    names = [n for n, _ in cf.method_sigs() if not n.startswith("<")]
    names += [n for n, _ in cf.field_sigs()]
    if not names:
        return 1
    short = sum(1 for n in names if len(n) < 3)
    return 1 if short * 2 >= len(names) else 3


def _hard_error_spans(src: str) -> list[tuple[int, int]]:
    """Character ranges covered by an engine's "I could not decompile this" note.

    Decompilers emit these as block comments wrapped around the one method they
    gave up on, so the span runs from the comment opener to the matching closer.
    Locating them lets a class that lost a single method be told apart from a
    class the engine refused outright.
    """
    spans: list[tuple[int, int]] = []
    for p in _HARD_ERROR_PATTERNS:
        for m in p.finditer(src):
            start = src.rfind("/*", 0, m.start())
            if start == -1:
                continue
            end = src.find("*/", m.end())
            if end == -1:
                continue
            spans.append((start, end + 2))
    return spans


def evaluate(src: str, cf: ClassFile, min_name_len: int | None = None) -> Quality:
    floor = min_name_len if min_name_len is not None else _member_name_floor(cf)
    idents = set(_IDENT_RE.findall(src))

    # javac synthesises these for records/enums; their absence from the source
    # is normal, not a recovery failure
    synthesized = set()
    if cf.super_name == "java/lang/Record":
        synthesized |= {"equals", "hashCode", "toString"}
    elif cf.super_name == "java/lang/Enum":
        synthesized |= {"equals", "hashCode", "toString", "values", "valueOf"}

    candidates: set[str] = set()
    for n, _d in cf.method_sigs():
        if n.startswith("<") or n in synthesized:
            continue
        if len(n) >= floor:
            candidates.add(n)
    for n, _d in cf.field_sigs():
        if n.startswith("<"):
            continue
        if len(n) >= floor:
            candidates.add(n)

    # constructors appear under the class's own simple name; when a nested
    # class is printed as `static class c` (name lost) or folded into its
    # outer type, any segment of A$B$C showing up counts as recovered
    has_init = any(n == "<init>" for n, _ in cf.method_sigs())
    segments = [p for p in cf.name.rsplit("/", 1)[-1].split("$") if len(p) >= floor]
    ctor_ok = (not has_init) or any(p in idents for p in segments)

    total = len(candidates)
    matched = len(candidates & idents)
    coverage = (matched / total) if total else 1.0

    hard_error = any(p.search(src) for p in _HARD_ERROR_PATTERNS)
    spans = _hard_error_spans(src) if hard_error else []

    # How much of the class did the engine actually give up on? A decompiler
    # that lost one method out of fifteen still produced a usable file, so
    # blunting the whole class to `failed` over one comment throws away real
    # work. Measure the give-up as a share of the output instead.
    if spans and len(src) > 0:
        covered = sum(e - s for s, e in spans)
        damaged = min(1.0, covered / float(len(src)))
    else:
        damaged = 0.0

    # A class the engine refused outright has no source at all, which shows up
    # as an empty or near-empty file rather than as a bounded comment.
    if hard_error and (not src.strip() or damaged > 0.5):
        hard_error_class_level = True
    else:
        hard_error_class_level = False

    leftover = len(_LEFTOVER_RE.findall(src))
    opens, closes = src.count("{"), src.count("}")
    brace_skew = abs(opens - closes) / float(max(1, opens))
    # Proportional, not absolute: a single truncated method in a 6000-line
    # file leaves a handful of unbalanced braces and that is not a failure.
    unbalanced = brace_skew > 0.02 or (opens == 0 and "interface" not in src and ";" not in src)

    sugar = [k for k, rx in _SUGAR_PATTERNS.items() if rx.search(src)]

    issues: list[str] = []
    if hard_error_class_level:
        issues.append("engine reported a decompilation error")
    elif hard_error:
        issues.append(f"engine gave up on part of the class ({damaged * 100:.0f}% of output)")
    if leftover:
        issues.append(f"{leftover} bytecode mnemonic(s) left in output")
    if unbalanced:
        issues.append(f"unbalanced braces ({opens} '{'{'}' vs {closes} '{'}'}')")
    if total and coverage < 1.0:
        missing = sorted(candidates - idents)
        if len(missing) <= 6:
            issues.append("missing members: " + ", ".join(missing))
        else:
            issues.append(f"{len(missing)} members not recovered")

    score = 100.0 * coverage
    # Full penalty only when the engine refused the class. A bounded give-up is
    # charged in proportion to how much of the file it actually covers.
    if hard_error_class_level:
        score -= 45.0
    elif hard_error:
        score -= 45.0 * damaged
    score -= min(30.0, leftover * 3.0)
    if unbalanced:
        score -= 25.0
    # reward idiomatic reconstruction, small weights so they only break ties
    score += min(8.0, len(sugar) * 1.6)
    if not ctor_ok:
        # the type is present but printed under no recognisable name, which
        # usually means the engine lost the nested class name
        score -= 10.0
        issues.append("class name not present in output")
    score = max(0.0, min(100.0, score))

    return Quality(
        score=round(score, 1), coverage=round(coverage, 3), matched=matched, total=total,
        hard_error=hard_error, leftover=leftover, unbalanced=unbalanced, sugar=sugar,
        lines=src.count("\n") + 1, issues=issues,
        class_level_failure=hard_error_class_level, damaged_fraction=round(damaged, 4),
    )


def better(a: Quality, b: Quality | None) -> bool:
    if b is None:
        return True
    if a.usable != b.usable:
        return a.usable
    if abs(a.score - b.score) > 1.0:
        return a.score > b.score
    return a.lines > b.lines  # more recovered detail wins a near tie
