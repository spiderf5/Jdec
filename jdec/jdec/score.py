"""Scoring decompiler output against bytecode ground truth.

The whole point of running several engines is being able to tell which one
actually won. Guessing from file size or line count is worthless, so we use
the class file itself as the answer key: every field and method that exists in
the bytecode should show up as a *declaration* in the source. A method that the
decompiler dropped, or that collapsed into "// couldn't be decompiled", simply
will not appear.

Matching discipline (REVIEW-2026-10-07 §1.1):
  * comments and string/char literals are stripped before matching, so an
    engine note listing the real member names cannot fake a recovery;
  * only declaration-shaped occurrences count - a call site `foo(x);` is a
    reference, not proof the member was recovered;
  * same-name overloads are counted individually, so recovering one of two
    overloads no longer scores as a perfect recovery.
The metric is therefore a member *name-hit* rate (COVERAGE_METRIC), not a
signature-recovery rate, and reports label it as such.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .classfile import ClassFile

_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")

# What `coverage` honestly measures, used verbatim in reports: a member counts
# as recovered when a *declaration-shaped* occurrence of its name survives in
# the output. It is a name-hit rate, not a signature-recovery rate.
COVERAGE_METRIC = "member name-hit rate"

# Java reserved words that must never be read as a declaration's return type
# (they are how call statements imitate declarations: "return foo(x);").
_NON_TYPE_KEYWORDS = (
    "new|return|if|else|for|while|do|switch|case|break|continue|throw|throws|"
    "try|catch|finally|assert|instanceof|import|package|extends|implements|"
    "this|super|yield|sealed|permits|record|var|enum|interface|class"
)
_MODS = r"(?:public|protected|private|static|final|abstract|synchronized|native|strictfp|default|transient|volatile)"
_ANN = r"@[\w$.]+(?:\((?:[^()]|\([^()]*\))*\))?"
_GEN = r"<[^<>]*(?:<[^<>]*>[^<>]*)*>"
_TYPE = (
    r"(?!(?:" + _NON_TYPE_KEYWORDS + r")\b)"
    r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*"
    r"(?:" + _GEN + r")?(?:\[\])*"
)
_PREFIX = r"(?:^|[{};])[ \t]*(?:(?:" + _ANN + r")\s*)*"

# A method declaration: modifiers and/or a return type, then NAME(...), then
# `{` (body) or `;` (abstract/interface/native). A bare call `foo(x);` has
# neither modifier nor type in front of the name, so it does not match.
# Terminators are lookaheads on purpose: consuming them would eat the very
# separator the next one-line declaration needs as its prefix.
_GENS = r"(?:" + _GEN + r")\s+"   # a generic parameter segment, e.g. <T extends C<T>>
_METHOD_DECL_RE = re.compile(
    _PREFIX
    + r"(?:(?:" + _MODS + r"\s+)+" + r"(?:" + _GENS + r")*" + r"(?:" + _TYPE + r"\s+)?"
    + r"|(?:^|[{};])[ \t]*(?:(?:" + _ANN + r")\s*)*(?:" + _MODS + r"\s+)*(?:" + _GENS + r")*"
    + _TYPE + r"\s+)"
    + r"(?P<name>[A-Za-z_$][\w$]*)[ \t]*\("
    + r"[^;{)]*(?:\([^)]*\)[^;{)]*)*"
    + r"\)[ \t]*(?:throws\s+[\w$.,\s]+?)?(?=[;{])"
    , re.M
)

# A field declaration: a type (mandatory - bare assignments like `x = y;` are
# statements, not declarations) then NAME followed by `=`, `;` or `,`. `,` is
# both a separator and a prefix so multi-declarator lines count every name.
_FIELD_DECL_RE = re.compile(
    r"(?:^|[{};,])[ \t]*(?:(?:" + _ANN + r")\s*)*(?:" + _MODS + r"\s+)*(?:" + _GENS + r")*"
    + _TYPE + r"\s+(?P<name>[A-Za-z_$][\w$]*)[ \t]*(?:\[\])*(?=[=;,])"
    , re.M
)

# Enum constants are fields in bytecode: `enum Color { RED, GREEN; ... }`
_ENUM_RE = re.compile(
    r"\benum\s+[\w$]+\s*(?:" + _GEN + r")?(?:\s+implements\s+[\w$.,\s]+)?\{([^{}]*)")
# Record components are fields in bytecode: `record Point(int x, int y) {}`
_RECORD_RE = re.compile(r"\brecord\s+[\w$]+\s*\(([^)]*)\)")

_JAVA_KEYWORDS_FOR_DECLS = set(
    "abstract assert boolean break byte case catch char class const continue "
    "default do double else enum extends final finally float for goto if "
    "implements import instanceof int interface long native new package "
    "private protected public return short static strictfp super switch "
    "synchronized this throw throws transient try void volatile while "
    "true false null var record sealed permits yield".split())

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
    """Scoring result for one engine's output against the bytecode answer key.

    `coverage` is a **member name-hit rate** (see COVERAGE_METRIC): the share
    of bytecode members whose name shows up in a *declaration position* of the
    output, with comments and string literals stripped first and same-name
    overloads counted individually. It is deliberately not labelled a
    signature-recovery rate - a regex cannot read descriptors out of Java
    source reliably, and an honest metric beats a flattering one.
    """

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


def _strip_noise(src: str) -> str:
    """Blank comments and string/char literals, preserving length and lines.

    Coverage matching must not be fooled by identifiers that only live in a
    comment (an engine note listing the real member names) or inside a string
    literal (encrypted pool payloads), so member matching runs over this
    sanitised text. Newlines survive so `^`-anchored scans stay aligned.
    """
    out = list(src)
    n = len(src)

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] not in "\r\n":
                out[k] = " "

    i = 0
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = src.find("\n", i)
            e = n if j < 0 else j
            blank(i, e)
            i = e
        elif c == "/" and nxt == "*":
            j = src.find("*/", i + 2)
            e = n if j < 0 else j + 2
            blank(i, e)
            i = e
        elif c == '"':
            if src[i:i + 3] == '"""':            # text block
                j = src.find('"""', i + 3)
                e = n if j < 0 else j + 3
                blank(i, e)
                i = e
                continue
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                elif src[j] == '"':
                    j += 1
                    break
                else:
                    j += 1
            else:
                j = n
            blank(i, j)
            i = j
        elif c == "'":                           # char literal
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                elif src[j] == "'":
                    j += 1
                    break
                else:
                    j += 1
            else:
                j = n
            blank(i, j)
            i = j
        else:
            i += 1
    return "".join(out)


def _decl_counts(stripped: str) -> dict[str, int]:
    """How many times each identifier appears in declaration position.

    Counts method declarations (`public void foo(...) {`), field declarations
    (`int foo;`), enum constants and record components. A call site `foo(x);`
    is a reference, not a declaration, and never counts.
    """
    counts: dict[str, int] = {}
    for m in _METHOD_DECL_RE.finditer(stripped):
        counts[m.group("name")] = counts.get(m.group("name"), 0) + 1
    for m in _FIELD_DECL_RE.finditer(stripped):
        counts[m.group("name")] = counts.get(m.group("name"), 0) + 1
    for em in _ENUM_RE.finditer(stripped):
        body = em.group(1)
        head = body.split(";", 1)[0]
        for ident in _IDENT_RE.findall(head):
            if ident not in _JAVA_KEYWORDS_FOR_DECLS:
                counts[ident] = counts.get(ident, 0) + 1
    for rm in _RECORD_RE.finditer(stripped):
        for part in rm.group(1).split(","):
            idents = _IDENT_RE.findall(part)
            if idents and idents[-1] not in _JAVA_KEYWORDS_FOR_DECLS:
                counts[idents[-1]] = counts.get(idents[-1], 0) + 1
    return counts


def evaluate(src: str, cf: ClassFile, min_name_len: int | None = None) -> Quality:
    floor = min_name_len if min_name_len is not None else _member_name_floor(cf)
    stripped = _strip_noise(src)
    decls = _decl_counts(stripped)

    # javac synthesises these for records/enums; their absence from the source
    # is normal, not a recovery failure
    synthesized = set()
    if cf.super_name == "java/lang/Record":
        synthesized |= {"equals", "hashCode", "toString"}
    elif cf.super_name == "java/lang/Enum":
        synthesized |= {"equals", "hashCode", "toString", "values", "valueOf"}

    # candidates carry their per-name multiplicity: two same-name overloads
    # are two candidates, so a source that recovers only one of them no
    # longer scores a perfect coverage (§1.1 of REVIEW-2026-10-07)
    method_cands: dict[str, int] = {}
    for n, _d in cf.method_sigs():
        if n.startswith("<") or n in synthesized:
            continue
        if len(n) >= floor:
            method_cands[n] = method_cands.get(n, 0) + 1
    field_cands: dict[str, int] = {}
    for n, _d in cf.field_sigs():
        if n.startswith("<"):
            continue
        if len(n) >= floor:
            field_cands[n] = field_cands.get(n, 0) + 1

    # constructors appear under the class's own simple name; when a nested
    # class is printed as `static class c` (name lost) or folded into its
    # outer type, any segment of A$B$C showing up *as a declaration* counts.
    # A bare `p in idents` test was useless on obfuscated input: with names
    # like `a`, any identifier anywhere in the file made it pass.
    has_init = any(n == "<init>" for n, _ in cf.method_sigs())
    segments = [p for p in cf.name.rsplit("/", 1)[-1].split("$") if len(p) >= floor]
    ctor_ok = (not has_init) or bool(segments) and bool(re.search(
        r"\b(?:class|interface|enum|record)\s+(?:" +
        "|".join(re.escape(p) for p in segments) + r")\b", stripped))

    total = sum(method_cands.values()) + sum(field_cands.values())
    matched = sum(min(k, decls.get(n, 0)) for n, k in method_cands.items())
    matched += sum(min(k, decls.get(n, 0)) for n, k in field_cands.items())
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
    opens, closes = _count_braces(src)
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
        shortfall = {n: k for n, k in method_cands.items() if decls.get(n, 0) < k}
        shortfall.update({n: k for n, k in field_cands.items() if decls.get(n, 0) < k})
        missing = sorted(shortfall)
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


def _count_braces(src: str) -> tuple[int, int]:
    """Count { } outside string/char literals, text blocks and comments.

    Counting every brace in the raw text charged real Java - a format string
    containing '{', a javadoc brace - as truncation damage (a flat -25 on the
    score), so only structural braces count now.
    """
    opens = closes = 0
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = src.find("\n", i)
            if j < 0:
                break
            i = j + 1
        elif c == "/" and nxt == "*":
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif c == '"':
            if src[i:i + 3] == '"""':          # text block
                j = src.find('"""', i + 3)
                i = n if j < 0 else j + 3
                continue
            i += 1
            while i < n:                       # string literal
                if src[i] == "\\":
                    i += 2
                elif src[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
        elif c == "'":                         # char literal
            i += 1
            while i < n:
                if src[i] == "\\":
                    i += 2
                elif src[i] == "'":
                    i += 1
                    break
                else:
                    i += 1
        else:
            if c == "{":
                opens += 1
            elif c == "}":
                closes += 1
            i += 1
    return opens, closes


def better(a: Quality, b: Quality | None) -> bool:
    if b is None:
        return True
    if a.usable != b.usable:
        return a.usable
    if abs(a.score - b.score) > 1.0:
        return a.score > b.score
    # near tie: prefer the more complete recovery, then the cleaner output;
    # only when those agree does sheer size break the tie
    if a.coverage != b.coverage:
        return a.coverage > b.coverage
    if len(a.issues) != len(b.issues):
        return len(a.issues) < len(b.issues)
    return a.lines > b.lines  # more recovered detail wins a near tie
