"""Automated IDE project generation, Java source recompilability repair, and javac verification.

Decompiled code often fails to compile in IDEs (IntelliJ IDEA, Eclipse, VS Code) due to:
1. Missing project scaffolding (build.gradle, settings.gradle, gradle.properties);
2. JVM bytecode vs JLS source specification gaps:
   - Synthetic bridge methods (ACC_BRIDGE / ACC_SYNTHETIC) causing duplicate method definitions;
   - Raw types and incompatible wildcard casts;
   - Ambiguous method overloads with untyped null;
3. Obfuscator naming traps:
   - Reserved Java keywords as identifiers (e.g. goto, default, assert, enum, switch);
   - Windows reserved filenames (CON, PRN, AUX, NUL);
   - Case-colliding class names in the same package;
4. Missing external Minecraft / library dependencies on the classpath.

This module bridges the compilation gap:
- Normalizes and repairs Java source code (stripping bridge duplicates, escaping keywords);
- Generates a production-ready Gradle project tailored to Minecraft (Fabric Loom / ForgeGradle) or Generic Java;
- Provides an automated compile loop (javac diagnostics -> iterative AST/line repairs -> recompilation).
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
import urllib.parse
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import classfile as CF
from . import mcmod as MM
from . import probe as PB
from . import toolchain as TC
from . import stubs as SB

# Java reserved words that cannot be used as variable/parameter names in valid source
JAVA_KEYWORDS = {
    "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char",
    "class", "const", "continue", "default", "do", "double", "else", "enum",
    "extends", "final", "finally", "float", "for", "goto", "if", "implements",
    "import", "instanceof", "int", "interface", "long", "native", "new",
    "package", "private", "protected", "public", "return", "short", "static",
    "strictfp", "super", "switch", "synchronized", "this", "throw", "throws",
    "transient", "try", "void", "volatile", "while",
    "true", "false", "null",
}

# Identifier keywords that are especially prone to obfuscator reuse
ESCAPABLE_KEYWORDS = {
    "goto", "const", "default", "assert", "enum", "native", "strictfp",
    "transient", "volatile", "interface", "abstract", "final", "static",
    "synchronized", "package", "import", "class", "extends", "implements",
    "throws", "throw", "return", "catch", "finally", "try", "switch",
    "case", "break", "continue", "while", "do", "for", "if", "else",
    "instanceof", "new", "this", "super",
}

# Windows reserved device names that cause filesystem corruption or hang on NTFS
WINDOWS_RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
}

# Zero-width spaces, joiners, BOMs, and BiDi override characters commonly inserted by obfuscators
ZERO_WIDTH_CHARS = re.compile(r"[\u200b\u200c\u200d\ufeff\u202a-\u202e\u2060-\u206f]")

# Unbox cascade expressions commonly left as artifacts by Vineflower and CFR
_VAL_EXPR = r"[\w$.]+(?:\[[^\]]*\])?"
UNBOX_VARIANTS = [
    re.compile(r"(?P<v>" + _VAL_EXPR + r")\s+instanceof\s+Boolean\s*\?\s*\(Boolean\)(?P=v)\s*:\s*\((?P=v)\s+instanceof\s+Character\s*\?\s*\(char\)\(\(Number\)(?P=v)\)\.intValue\(\)\s*:\s*\(\(Number\)(?P=v)\)\.intValue\(\)\)\)"),
    re.compile(r"(?P<v>" + _VAL_EXPR + r")\s+instanceof\s+Boolean\s*\?\s*\(Boolean\)(?P=v)\s*:\s*\((?P=v)\s+instanceof\s+Character\s*\?\s*\(Character\)(?P=v)\s*:\s*\(\(Number\)(?P=v)\)\.intValue\(\)\)\)"),
    re.compile(r"(?P<v>" + _VAL_EXPR + r")\s+instanceof\s+Boolean\s*\?\s*\(Boolean\)(?P=v)\s*:\s*\((?P=v)\s+instanceof\s+Character\s*\?\s*\(int\)\(\(Character\)(?P=v)\)\.charValue\(\)\s*:\s*\(\(Number\)(?P=v)\)\.intValue\(\)\)\)"),
    re.compile(r"(?P<v>" + _VAL_EXPR + r")\s+instanceof\s+Boolean\s*\?\s*(?P=v)\s*:\s*\((?P=v)\s+instanceof\s+Character\s*\?\s*\(Character\)(?P=v)\s*:\s*\(\(Number\)(?P=v)\)\.intValue\(\)\)\)"),
]


def normalize_unbox(source_code: str) -> tuple[str, int]:
    """Normalize decompiler unboxing cascade ternaries into valid Java typed expressions."""
    def repl(m):
        v = m.group("v")
        return (f"({v} instanceof Boolean"
                f" ? (((Boolean){v}).booleanValue() ? 1 : 0)"
                f" : ({v} instanceof Character"
                f" ? ((Character){v}).charValue()"
                f" : ((Number){v}).intValue()))")

    edits = 0
    cur = source_code
    prev = None
    while prev != cur:
        prev = cur
        for pat in UNBOX_VARIANTS:
            cur, count = pat.subn(repl, cur)
            edits += count
    return cur, edits


def _mask_noncode(src: str) -> str:
    """Blank out comments and string/char literals, preserving offsets and newlines.

    Rewrites are computed on the masked text and applied to the original by
    offset, so text that merely *looks* like a cast inside a comment or literal
    is never modified.
    """
    out = list(src)
    i, n = 0, len(src)

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif c == "/" and nxt == "*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
        elif c == '"':
            if src[i:i + 3] == '"""':
                j = src.find('"""', i + 3)
                j = n if j < 0 else j + 3
            else:
                j = i + 1
                while j < n:
                    if src[j] == "\\":
                        j += 2
                    elif src[j] == '"':
                        j += 1
                        break
                    else:
                        j += 1
            blank(i, j)
            i = j
        elif c == "'":
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                elif src[j] == "'":
                    j += 1
                    break
                else:
                    j += 1
            blank(i, j)
            i = j
        else:
            i += 1
    return "".join(out)


# Operand shapes the rewriter accepts. A simple identifier / field chain is safe
# to evaluate twice; a call is only accepted for the boolean form, which
# evaluates it once via Boolean.TRUE.equals(...).
_OPERAND_SIMPLE = r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*"
_OPERAND_CALL = r"[A-Za-z_$][A-Za-z0-9_$.]*(?:\([^()]*\))?"
_OPERAND = rf"(?:{_OPERAND_CALL}|{_OPERAND_SIMPLE})"

_BOOL_CAST = r"\(\s*boolean\s*\)\s*"
_NUM_CAST = r"\(\s*(int|long|float|double|char|byte|short)\s*\)\s*"

_UNBOX_PATTERNS = [
    # boolean b = (boolean)x;   (group 1 = cast+operand, group 2 = operand)
    re.compile(rf"\bboolean\s+[A-Za-z_$][\w$]*\s*=\s*({_BOOL_CAST}({_OPERAND}))"),
    # if ((boolean)x) / while ((boolean)x)
    re.compile(rf"\b(?:if|while)\s*\(\s*({_BOOL_CAST}({_OPERAND}))"),
    # (boolean)x ? a : b
    re.compile(rf"({_BOOL_CAST}({_OPERAND}))\s*\?"),
]

_NUMERIC_DEFAULTS = {
    "int": ("0", "intValue"), "long": ("0L", "longValue"),
    "float": ("0.0F", "floatValue"), "double": ("0.0", "doubleValue"),
    "byte": ("(byte)0", "byteValue"), "short": ("(short)0", "shortValue"),
    "char": ("'\\0'", "charValue"),
}

_PRIMITIVE_TYPES = frozenset({
    "byte", "short", "int", "long", "float", "double", "boolean", "char",
})
_BOXED_TYPES = frozenset({
    "Byte", "Short", "Integer", "Long", "Float", "Double", "Boolean",
    "Character", "Number", "Object", "String",
})

# declaration / parameter: <type> <name> followed by = ; , ) :
_DECL_RE = re.compile(
    r"(?:^|[;{}(,])\s*(?:final\s+)?"
    r"([A-Za-z_$][A-Za-z0-9_$.]*(?:\s*<[^;{}()]*>)?(?:\[\])*)\s+"
    r"([A-Za-z_$][A-Za-z0-9_$]*)\s*(?=[=;,):])",
    re.M,
)


def _declared_types(src: str) -> dict[str, str]:
    """Best-effort map of local/field/parameter name -> declared type text.

    Used only to decide whether `(int)x` is an unboxing (x is a reference) or a
    no-op cast on an int. Unknown names are treated as "do not rewrite".
    """
    masked = _mask_noncode(src)
    out: dict[str, str] = {}
    for m in _DECL_RE.finditer(masked):
        type_txt, name = m.group(1), m.group(2)
        if type_txt.strip() == "var":
            continue          # inferred below
        head = type_txt.split("<", 1)[0].rsplit(".", 1)[-1]
        if head in JAVA_KEYWORDS or type_txt in JAVA_KEYWORDS:
            continue
        out.setdefault(name, type_txt)

    # `var` has no declared type; recover the obvious initializer shapes only.
    for m in _VAR_DECL_RE.finditer(masked):
        name, rhs = m.group(1), m.group(2).strip()
        inferred = None
        mm = re.match(r"new\s+([A-Za-z_$][\w$.]*(?:\s*<[^;>]*>)?)", rhs)
        if mm:
            inferred = mm.group(1)
        else:
            mm = re.match(r"\(\s*([A-Za-z_$][\w$.]*(?:\s*<[^>]*>)?)\s*\)", rhs)
            if mm:
                inferred = mm.group(1)
            elif re.fullmatch(r"[A-Za-z_$][\w$]*", rhs) and rhs in out:
                inferred = out[rhs]
        if inferred:
            out.setdefault(name, inferred)
    return out


def _reference_kind(type_txt: str | None) -> bool | None:
    """True = reference, False = primitive, None = cannot tell."""
    if not type_txt:
        return None
    base = re.sub(r"(\[\])+$", "", type_txt.strip())
    base = base.split("<", 1)[0].strip()
    simple = base.rsplit(".", 1)[-1].strip()
    if simple in _PRIMITIVE_TYPES:
        return False
    if simple in _BOXED_TYPES:
        return True
    if simple[:1].isupper():
        return True
    return None


def _simple_class_name(type_txt: str) -> str:
    base = re.sub(r"(\[\])+$", "", type_txt.strip())
    base = base.split("<", 1)[0].strip()
    return base.rsplit(".", 1)[-1].strip()


_CLASS_HEADER_RE = re.compile(
    r"^\s*(?:public\s+)?(?:abstract\s+|final\s+)?(?:class|interface|enum|record)\s+"
    r"([A-Za-z_$][\w$]*)(?:\s*<[^>{}]*>)?"
    r"(?:\s+extends\s+([A-Za-z_$][\w$.]*))?", re.M)

_FIELD_DECL_RE = re.compile(
    r"^(?:(?:public|protected|private|static|final|transient|volatile)\s+)*"
    r"([A-Za-z_$][\w$.]*(?:\s*<[^;{}]*>)?(?:\[\])*)\s+"
    r"([A-Za-z_$][\w$]*)\s*(?:=|;)")

_VAR_DECL_RE = re.compile(r"\bvar\s+([A-Za-z_$][\w$]*)\s*=\s*([^;]+);")


@dataclass
class SourceTypeIndex:
    """Project-wide field map used to resolve cross-class unboxing operands.

    Deliberately shallow: one entry per class, fields only, no method return
    inference. Unknown stays unknown, which keeps the rewrite conservative.
    """
    fields: dict[str, dict[str, str]] = field(default_factory=dict)
    supers: dict[str, str] = field(default_factory=dict)

    def add_file(self, code: str) -> None:
        masked = _mask_noncode(code)
        m = _CLASS_HEADER_RE.search(masked)
        if not m:
            return
        cls, sup = m.group(1), m.group(2)
        if sup:
            self.supers.setdefault(cls, _simple_class_name(sup))
        depth = 0
        for line in masked.splitlines():
            if depth == 1:
                fm = _FIELD_DECL_RE.match(line.strip())
                if fm and _simple_class_name(fm.group(1)) not in JAVA_KEYWORDS:
                    self.fields.setdefault(cls, {}).setdefault(fm.group(2), fm.group(1))
            depth += line.count("{") - line.count("}")
            if depth < 0:
                depth = 0

    def field_type(self, cls: str | None, name: str) -> str | None:
        seen: set[str] = set()
        cur = cls
        while cur and cur not in seen:
            seen.add(cur)
            fields = self.fields.get(cur)
            if fields and name in fields:
                return fields[name]
            cur = self.supers.get(cur)
        return None


def build_source_type_index(root: Path) -> SourceTypeIndex:
    """Index every .java under `root` so operands like `other.field` can resolve."""
    idx = SourceTypeIndex()
    if not root.is_dir():
        return idx
    for j_file in root.rglob("*.java"):
        try:
            idx.add_file(j_file.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return idx


def _resolve_operand_type(
    operand: str,
    declared: dict[str, str],
    type_index: SourceTypeIndex | None,
    current_class: str | None,
) -> str | None:
    parts = operand.split(".")
    if parts[0] == "this":
        parts = parts[1:]
        if len(parts) == 1 and type_index:
            return type_index.field_type(current_class, parts[0])
        return None
    if len(parts) == 1:
        if operand in declared:
            return declared[operand]
        if type_index:
            return type_index.field_type(current_class, operand)
        return None
    cur = declared.get(parts[0])
    if cur is None and type_index:
        cur = type_index.field_type(current_class, parts[0])
    if cur is None or type_index is None:
        return None
    for seg in parts[1:]:
        cur = type_index.field_type(_simple_class_name(cur), seg)
        if cur is None:
            return None
    return cur


def normalize_primitive_unboxing(
    source_code: str,
    include_numeric: bool = True,
    type_index: "SourceTypeIndex | None" = None,
    current_class: str | None = None,
) -> tuple[str, int]:
    """Rewrite raw unboxing casts so a null stub return cannot throw NPE.

    boolean (always):
        (boolean)x              -> Boolean.TRUE.equals(x)
    numeric (include_numeric, default on):
        (int)x                  -> (x == null ? 0 : ((Number)x).intValue())
        (char)x                 -> (x == null ? '\\0' : ((Character)x).charValue())

    Numeric rewriting only fires when the operand is a declared reference type
    (boxed class, Object, String, or a class name) and a simple identifier /
    field chain. `(int)someInt` is a legal no-op cast and is left alone, as are
    operands whose declaration cannot be found — the duplicated read in the
    ternary is only safe when it has no side effects.

    Operand types come from local declarations and, when supplied, a project-wide
    `SourceTypeIndex` for `this.field` / `other.field` chains.

    Comments and string/char literals are masked before matching, so text that
    merely looks like a cast is left untouched.
    """
    if not source_code:
        return source_code, 0

    masked = _mask_noncode(source_code)
    spans: list[tuple[int, int, str]] = []

    for pat in _UNBOX_PATTERNS:
        for m in pat.finditer(masked):
            start, end = m.span(1)
            operand = m.group(2)
            spans.append((start, end, f"Boolean.TRUE.equals({operand})"))

    if include_numeric:
        # `(int)call()` and `(int)arr[0]` are not simple lvalues: a duplicated
        # read would change behaviour, so they are left untouched.
        pat_num = re.compile(rf"{_NUM_CAST}({_OPERAND_SIMPLE})(?!\s*[\(\[]|[A-Za-z0-9_$])")
        declared = _declared_types(source_code)
        for m in pat_num.finditer(masked):
            prim, operand = m.group(1), m.group(2)
            type_txt = _resolve_operand_type(operand, declared, type_index, current_class)
            if _reference_kind(type_txt) is not True:
                continue
            default, accessor = _NUMERIC_DEFAULTS[prim]
            box = "Character" if prim == "char" else "Number"
            repl = f"({operand} == null ? {default} : (({box}){operand}).{accessor}())"
            spans.append((m.start(), m.end(), repl))

    if not spans:
        return source_code, 0

    # right-to-left so earlier offsets stay valid; drop overlaps
    spans.sort(key=lambda s: (s[0], s[1]), reverse=True)
    out = source_code
    last_start = len(source_code) + 1
    applied = 0
    for start, end, repl in spans:
        if end > last_start:
            continue
        out = out[:start] + repl + out[end:]
        last_start = start
        applied += 1
    return out, applied


@dataclass
class CompilationIssue:
    file_path: Path
    line_number: int
    column: int
    message: str
    code_line: str = ""


@dataclass
class CompilationReport:
    success: bool
    total_files: int
    compiled_files: int
    issues: list[CompilationIssue] = field(default_factory=list)
    repaired_count: int = 0
    javac_output: str = ""

    def summary(self) -> str:
        status = "SUCCESS" if self.success else "FAILED"
        return (
            f"Compilation [{status}]: {self.compiled_files}/{self.total_files} files clean, "
            f"{len(self.issues)} issue(s), {self.repaired_count} repair(s) applied."
        )


def sanitize_keyword_identifiers(source_code: str) -> tuple[str, int]:
    """Safely escape reserved keyword identifiers (e.g. goto -> goto_) in variable declarations."""
    edits = 0
    lines = source_code.splitlines()
    out_lines = []

    # Types commonly preceding variable declarations
    types_pat = (
        r"(?:int|long|short|byte|float|double|boolean|char|String|Object|"
        r"[A-Z][A-Za-z0-9_$<>\[\], ]*)"
    )

    for line in lines:
        stripped = line.strip()
        # Skip package and import statements
        if stripped.startswith("package ") or stripped.startswith("import "):
            out_lines.append(line)
            continue

        mod_line = line

        # Unused Java keywords 'goto' and 'const' can never legally appear as language syntax
        for unused_kw in ("goto", "const"):
            p_unused = re.compile(r"\b" + unused_kw + r"\b")
            matches = len(p_unused.findall(mod_line))
            if matches > 0:
                mod_line = p_unused.sub(unused_kw + "_", mod_line)
                edits += matches

        # Match parameter or local variable declarations: <Type> <keyword> [=,)]
        for kw in ESCAPABLE_KEYWORDS:
            if kw in ("goto", "const"):
                continue
            # Pattern 1: Parameter declaration, e.g. (int goto, String default)
            p_decl = re.compile(r"(\b" + types_pat + r"\s+)\b(" + kw + r")\b(\s*[,)=;])")
            if p_decl.search(mod_line):
                mod_line = p_decl.sub(r"\1\2_\3", mod_line)
                edits += 1

            # Pattern 2: Assignment / declaration, e.g. goto = 5; or int goto;
            p_assign = re.compile(r"(\b(?:private|protected|public)?\s*(?:static\s+)?(?:final\s+)?" + types_pat + r"\s+)\b(" + kw + r")\b(\s*[;=])")
            if p_assign.search(mod_line):
                mod_line = p_assign.sub(r"\1\2_\3", mod_line)
                edits += 1

            # Pattern 3: Member access, e.g. this.goto or instance.default
            p_mem = re.compile(r"(\bthis\.)\b(" + kw + r")\b")
            if p_mem.search(mod_line):
                mod_line = p_mem.sub(r"\1\2_", mod_line)
                edits += 1

        out_lines.append(mod_line)

    return "\n".join(out_lines), edits


def prune_duplicate_bridge_methods(source_code: str) -> tuple[str, int]:
    """Comment out duplicate synthetic bridge methods that differ only by return type.

    Every line of the chosen method is prefixed with `//`, so the result stays
    brace-balanced for javac and for the scoring pass. A method whose end cannot
    be located is left alone rather than truncated.
    """
    lines = source_code.splitlines()
    masked_lines = _mask_noncode(source_code).splitlines()

    m_decl_pat = re.compile(
        r"^[ \t]*(?:(?:public|protected|private|static|final|synchronized|abstract|default)\s+)*"
        r"(?:<[^>]+>\s+)?([A-Za-z0-9_$.<>\[\]]+)\s+([A-Za-z0-9_$]+)\s*\(([^)]*)\)"
    )

    methods_seen: dict[tuple[str, tuple[str, ...]], list[int]] = {}
    for idx, line in enumerate(masked_lines):
        m = m_decl_pat.match(line)
        if not m:
            continue
        _ret_type, m_name, params = m.groups()
        if m_name in ("if", "for", "while", "switch", "catch"):
            continue
        methods_seen.setdefault((m_name, _param_types(params)), []).append(idx)

    def method_end(start: int) -> int | None:
        depth = 0
        started = False
        for j in range(start, len(masked_lines)):
            line = masked_lines[j]
            depth += line.count("{") - line.count("}")
            if "{" in line:
                started = True
            if started and depth <= 0:
                return j
            if not started and line.rstrip().endswith(";"):
                return j
        return None

    def has_marker(l_idx: int) -> bool:
        # markers live in comments, which the mask blanks: read the raw lines
        prev = "\n".join(lines[max(0, l_idx - 3):l_idx])
        return ("$FF: bridge method" in prev or "$FF: synthetic method" in prev
                or "/* bridge */" in prev)

    def delegates(l_idx: int, name: str) -> bool:
        body = "\n".join(masked_lines[l_idx:min(len(masked_lines), l_idx + 4)])
        return f"return this.{name}(" in body or f"return {name}(" in body

    lines_to_comment: set[int] = set()
    edits = 0
    for (m_name, _ptypes), idxs in methods_seen.items():
        if len(idxs) < 2:
            continue
        marked = [i for i in idxs if has_marker(i)]
        if marked:
            drop = list(marked)
        else:
            delegating = [i for i in idxs if delegates(i, m_name)]
            drop = delegating if len(delegating) == 1 else idxs[1:]
        keep = next((i for i in idxs if i not in drop), idxs[0])
        drop = [i for i in drop if i != keep]

        for start in drop:
            end = method_end(start)
            if end is None:
                continue                    # cannot locate the body: do not touch
            for j in range(start, end + 1):
                lines_to_comment.add(j)
            edits += 1

    if not edits:
        return source_code, 0

    out_lines = [
        "// [jdec: stripped duplicate bridge method] " + line if idx in lines_to_comment else line
        for idx, line in enumerate(lines)
    ]
    return "\n".join(out_lines), edits


def clean_source_for_compilation(
    code: str,
    expected_package: str | None = None,
    type_index: SourceTypeIndex | None = None,
    current_class: str | None = None,
) -> tuple[str, list[str]]:
    """Master source cleanup pass: strips zero-width chars, ensures package headers, escapes keywords, and strips bridge duplicates."""
    changes = []
    cur_code = code

    # 0. Zero-width and BiDi obfuscation characters
    stripped_code, zw_count = ZERO_WIDTH_CHARS.subn("", cur_code)
    if zw_count > 0:
        cur_code = stripped_code
        changes.append(f"Sanitized {zw_count} zero-width / bi-di obfuscation character(s)")

    # 1. Package header validation
    if expected_package:
        lines = cur_code.splitlines()
        has_pkg = any(l.strip().startswith("package ") for l in lines[:10])
        if not has_pkg and expected_package:
            cur_code = f"package {expected_package};\n\n" + cur_code
            changes.append(f"Added missing package declaration: package {expected_package};")

    # 2. Keyword identifier escaping
    cur_code, kw_edits = sanitize_keyword_identifiers(cur_code)
    if kw_edits > 0:
        changes.append(f"Escaped {kw_edits} reserved keyword identifier(s)")

    # 3. Duplicate bridge method pruning
    cur_code, br_edits = prune_duplicate_bridge_methods(cur_code)
    if br_edits > 0:
        changes.append(f"Pruned {br_edits} duplicate bridge method(s)")

    # 4. Decompiler unbox cascade normalization
    cur_code, unbox_edits = normalize_unbox(cur_code)
    if unbox_edits > 0:
        changes.append(f"Normalized {unbox_edits} unbox cascade expression(s)")

    # 5. Primitive unboxing null-safety
    cur_code, prim_edits = normalize_primitive_unboxing(
        cur_code, type_index=type_index, current_class=current_class)
    if prim_edits > 0:
        changes.append(f"Normalized {prim_edits} primitive unboxing expression(s)")

    # line-joining steps drop trailing newlines; normalise once so a second
    # pass over the output is byte-identical
    if cur_code and not cur_code.endswith("\n"):
        cur_code += "\n"

    return cur_code, changes


def enrich_safe_fallback_stubs(project_dir: Path, stub_files: list[Path] | None = None) -> int:
    """Upgrade null collection/iterator returns to immutable empty values.

    Only machine-synthesised stubs are touched: either the explicit `stub_files`
    list, or files carrying stubs.STUB_MARKER. A real class that happens to be
    named "Dispatcher" (or to contain a member called "dummyMethod") is never
    rewritten, because there is no reliable way to tell it apart from a stub by
    name alone.
    """
    java_src_root = project_dir / "src" / "main" / "java"
    if stub_files is not None:
        candidates = [p for p in stub_files if p.is_file()]
    elif java_src_root.is_dir():
        candidates = [p for p in java_src_root.rglob("*.java")
                      if SB.STUB_MARKER in p.read_text(encoding="utf-8", errors="replace")]
    else:
        return 0

    edits = 0
    rules = [
        (r"\b(?:List|Collection)\s*<[^>]*>", "Collections.emptyList()"),
        (r"\bMap\s*<[^>]*>", "Collections.emptyMap()"),
        (r"\bSet\s*<[^>]*>", "Collections.emptySet()"),
        (r"\bIterator\s*<[^>]*>", "Collections.emptyIterator()"),
    ]
    for j_file in candidates:
        raw = j_file.read_text(encoding="utf-8", errors="replace")
        content = raw

        for type_pat, replacement in rules:
            content = re.sub(
                rf"(\b{type_pat}\s+[A-Za-z_$][\w$]*\s*\([^)]*\)\s*\{{\s*return\s+)null(\s*;\s*\}})",
                rf"\1{replacement}\2",
                content,
            )
        if content == raw:
            continue

        if "import java.util.*;" not in content and "import java.util.Collections;" not in content:
            p_pkg = re.search(r"package\s+[\w.]+;\s*", content)
            if p_pkg:
                content = content[:p_pkg.end()] + "\nimport java.util.*;\n" + content[p_pkg.end():]
            else:
                content = "import java.util.*;\n" + content
        j_file.write_text(content, encoding="utf-8")
        edits += 1
    return edits


def _param_types(params: str) -> tuple[str, ...]:
    """Extract erased parameter types from a Java parameter list.

    Used to key static methods by real signature rather than by arity: `get(int)`
    and `get(String)` are different methods and must not be conflated.
    """
    out: list[str] = []
    for raw in params.split(","):
        raw = raw.strip()
        if not raw:
            continue
        raw = re.sub(r"\bfinal\b", "", raw).strip()
        raw = re.sub(r"@[\w.]+(?:\([^)]*\))?\s*", "", raw).strip()
        tokens = raw.split()
        out.append(" ".join(tokens[:-1]) if len(tokens) >= 2 else raw)
    return tuple(out)


def check_static_hiding_invariance(source_dir: Path) -> int:
    """Narrow a hiding static method's `Object` return type to the hidden one.

    JLS §8.4.8.2 requires a hiding static method to be return-type-substitutable
    for the method it hides. Decompilers often widen the subclass return to
    `Object`, which javac rejects. Only the safe direction is applied: `Object`
    is narrowed to the superclass's concrete type. Methods are matched by
    (name, parameter types) — never by arity alone.
    """
    edits = 0
    class_supers: dict[str, str] = {}
    class_files: dict[str, Path] = {}
    class_methods: dict[str, dict[tuple[str, tuple[str, ...]], tuple[str, tuple[str, ...]]]] = {}

    m_hdr = re.compile(r"^\s*public\s+(?:abstract\s+)?(class|interface)\s+([A-Za-z0-9_$]+)(?:\s+extends\s+([A-Za-z0-9_$]+))?", re.M)
    m_static = re.compile(r"^\s*public\s+static\s+([A-Za-z0-9_$.<>\[\]]+)\s+([A-Za-z0-9_$]+)\s*\(([^)]*)\)", re.M)

    for j_file in source_dir.rglob("*.java"):
        txt = j_file.read_text(encoding="utf-8", errors="replace")
        cls_match = m_hdr.search(txt)
        if not cls_match:
            continue
        c_name = cls_match.group(2)
        s_name = cls_match.group(3)
        if s_name:
            class_supers[c_name] = s_name
        class_files.setdefault(c_name, j_file)
        methods = {}
        for sm in m_static.finditer(txt):
            ret_t, m_name, params = sm.groups()
            p_types = _param_types(params)
            methods[(m_name, p_types)] = (ret_t, p_types)
        class_methods[c_name] = methods

    for c_name, s_name in class_supers.items():
        if s_name not in class_methods or c_name not in class_methods:
            continue
        for sig, (s_ret, s_types) in class_methods[s_name].items():
            if sig not in class_methods[c_name]:
                continue
            c_ret, _ = class_methods[c_name][sig]
            if c_ret != "Object" or s_ret == "Object":
                continue

            c_file = class_files.get(c_name)
            if c_file is None:
                continue
            content = c_file.read_text(encoding="utf-8", errors="replace")
            if s_types:
                param_pat = r"\s*,\s*".join(
                    re.escape(t) + r"\s+[A-Za-z_$][\w$]*" for t in s_types)
            else:
                param_pat = r"\s*"
            decl = re.compile(
                r"(public\s+static\s+)Object(\s+" + re.escape(sig[0]) + r"\s*\(" + param_pat + r"\s*\))")
            new_content, n = decl.subn(rf"\g<1>{s_ret}\g<2>", content, count=1)
            if n:
                c_file.write_text(new_content, encoding="utf-8")
                edits += n
    return edits


def generate_gradle_scaffold(
    project_dir: Path,
    project_name: str,
    java_version: str = "21",
    mc_version: str | None = None,
    mc_flavor: str | None = None,
) -> dict[str, Path]:
    """Generate production-grade build.gradle, settings.gradle, and gradle.properties."""
    project_dir.mkdir(parents=True, exist_ok=True)
    generated = {}

    # Map major java version string (e.g. '8', '17', '21')
    jvm_ver = "21"
    if java_version in ("8", "1.8"):
        jvm_ver = "1.8"
    elif java_version in ("11", "17", "21"):
        jvm_ver = java_version

    # 1. settings.gradle
    settings_file = project_dir / "settings.gradle"
    settings_content = [
        f"rootProject.name = '{project_name}'",
        "",
        "pluginManagement {",
        "    repositories {",
        "        mavenCentral()",
        "        gradlePluginPortal()",
        "        maven { url 'https://maven.fabricmc.net/' }",
        "        maven { url 'https://maven.minecraftforge.net/' }",
        "    }",
        "}",
        "",
        "dependencyResolutionManagement {",
        "    repositories {",
        "        mavenCentral()",
        "        maven { url 'https://libraries.minecraft.net/' }",
        "        maven { url 'https://maven.fabricmc.net/' }",
        "        maven { url 'https://maven.spongepowered.org/repository/maven-public/' }",
        "    }",
        "}",
    ]
    settings_file.write_text("\n".join(settings_content) + "\n", encoding="utf-8")
    generated["settings.gradle"] = settings_file

    # 2. gradle.properties
    props_file = project_dir / "gradle.properties"
    props_content = [
        "org.gradle.jvmargs=-Xmx2G",
        f"java_version={jvm_ver}",
    ]
    if mc_version:
        props_content.append(f"minecraft_version={mc_version}")
    props_file.write_text("\n".join(props_content) + "\n", encoding="utf-8")
    generated["gradle.properties"] = props_file

    # 3. build.gradle
    build_file = project_dir / "build.gradle"
    build_content = [
        "plugins {",
        "    id 'java'",
        "    id 'java-library'",
        "}",
        "",
        "group = 'com.deobf.reconstructed'",
        "version = '1.0.0-SNAPSHOT'",
        "",
        "java {",
        f"    sourceCompatibility = JavaVersion.toVersion('{jvm_ver}')",
        f"    targetCompatibility = JavaVersion.toVersion('{jvm_ver}')",
        "}",
        "",
        "repositories {",
        "    mavenCentral()",
        "    maven { url 'https://libraries.minecraft.net/' }",
        "    maven { url 'https://maven.fabricmc.net/' }",
        "}",
        "",
        "dependencies {",
        "    // Local classpath dependencies and bundled stubs",
        "    implementation fileTree(dir: 'libs', include: ['*.jar'])",
        "",
        "    // Standard modern Java libraries commonly used across Minecraft mods",
        "    compileOnly 'com.google.guava:guava:32.1.2-jre'",
        "    compileOnly 'com.google.code.gson:gson:2.10.1'",
        "    compileOnly 'org.apache.logging.log4j:log4j-api:2.20.0'",
        "    compileOnly 'io.netty:netty-all:4.1.97.Final'",
        "    compileOnly 'org.spongepowered:mixin:0.8.5'",
        "}",
        "",
        "tasks.withType(JavaCompile).configureEach {",
        "    options.encoding = 'UTF-8'",
        "    options.deprecation = false",
        "    options.compilerArgs += ['-Xlint:none']",
        "}",
        "",
        "jar {",
        "    from sourceSets.main.output",
        "    duplicatesStrategy = DuplicatesStrategy.EXCLUDE",
        "}",
    ]
    build_file.write_text("\n".join(build_content) + "\n", encoding="utf-8")
    generated["build.gradle"] = build_file

    # 4. README.md with IDE import instructions
    readme_file = project_dir / "README.md"
    readme_content = [
        f"# {project_name} — Reconstructed Java Project",
        "",
        "This project was automatically decompiled, de-flattened, decrypted, and projectized by **jdec**.",
        "",
        "## IDE Quickstart",
        "",
        "### IntelliJ IDEA (Recommended)",
        "1. Open IntelliJ IDEA -> **File -> Open...**;",
        f"2. Select the `{project_dir.name}/build.gradle` file;",
        "3. Choose **Open as Project**;",
        f"4. Verify the Project SDK is set to **Java {jvm_ver}** in *File -> Project Structure*.",
        "",
        "### Visual Studio Code",
        "1. Install the *Extension Pack for Java* (Microsoft);",
        f"2. Open the `{project_dir.name}` folder;",
        "3. Wait for the Java Language Server to import Gradle dependencies.",
        "",
        "## Command-Line Build",
        "```bash",
        "gradle build",
        "# or with wrapper if installed:",
        "./gradlew build",
        "```",
    ]
    readme_file.write_text("\n".join(readme_content) + "\n", encoding="utf-8")
    generated["README.md"] = readme_file

    # 5. .gitignore
    gitignore_file = project_dir / ".gitignore"
    gitignore_content = [
        ".gradle/",
        "build/",
        "!gradle/wrapper/gradle-wrapper.jar",
        ".idea/",
        "*.iml",
        "*.iws",
        "*.ipr",
        "out/",
        ".vscode/",
        ".DS_Store",
    ]
    gitignore_file.write_text("\n".join(gitignore_content) + "\n", encoding="utf-8")
    generated[".gitignore"] = gitignore_file

    # 6. gradlew.bat (Windows batch launcher)
    bat_file = project_dir / "gradlew.bat"
    bat_content = [
        "@rem Gradle startup script for Windows",
        "@if \"%DEBUG%\" == \"\" @echo off",
        "where gradle >nul 2>nul",
        "if %ERRORLEVEL% equ 0 (",
        "    gradle %*",
        ") else (",
        "    echo Gradle is not installed in PATH. Please install Gradle or open this project in IntelliJ IDEA.",
        "    exit /b 1",
        ")",
    ]
    bat_file.write_text("\r\n".join(bat_content) + "\r\n", encoding="utf-8")
    generated["gradlew.bat"] = bat_file

    # 7. gradlew (Unix launcher)
    sh_file = project_dir / "gradlew"
    sh_content = [
        "#!/bin/sh",
        "if command -v gradle >/dev/null 2>&1; then",
        "    exec gradle \"$@\"",
        "else",
        "    echo \"Gradle is not installed in PATH. Please install Gradle or open this project in IntelliJ IDEA.\"",
        "    exit 1",
        "fi",
    ]
    sh_file.write_text("\n".join(sh_content) + "\n", encoding="utf-8")
    try:
        sh_file.chmod(0o755)
    except Exception:
        pass
    generated["gradlew"] = sh_file

    return generated


def export_project(
    source_jar: Path,
    out_dir: Path,
    src_dir: Path | None = None,
    mc_version: str | None = None,
    with_stubs: bool = True,
    intermediary_jar: Path | str | None = None,
) -> dict[str, int]:
    """Export decompiled sources into a complete IDE-ready Gradle project."""
    out_dir.mkdir(parents=True, exist_ok=True)
    target_src = out_dir / "src" / "main" / "java"
    target_res = out_dir / "src" / "main" / "resources"
    target_libs = out_dir / "libs"
    target_src.mkdir(parents=True, exist_ok=True)
    target_res.mkdir(parents=True, exist_ok=True)
    target_libs.mkdir(parents=True, exist_ok=True)

    stats = {
        "java_files": 0,
        "resources_copied": 0,
        "files_repaired": 0,
        "stubs_bundled": 0,
    }
    # REVIEW 2.4: every self-heal is recorded so "compilable" is never
    # mistaken for "behaviour-equal". Originals go to src-original/.
    repairs: list[dict] = []

    # 1. Detect target profile and Java version
    prof = PB.profile_jar(source_jar) if source_jar.is_file() else None
    java_ver = "21"
    resolved_mc = mc_version
    flavor = None
    if prof:
        resolved_mc = resolved_mc or prof.mc_version
        flavor = prof.mc_flavor

    # Check bytecode major version from first valid classfile
    if source_jar.is_file() and source_jar.suffix.lower() == ".jar":
        try:
            with zipfile.ZipFile(source_jar) as z:
                for name in z.namelist():
                    if name.endswith(".class") and not name.startswith("META-INF/"):
                        data = z.read(name)
                        try:
                            cf = CF.parse(data)
                        except Exception:
                            continue
                        if cf.major == 52: java_ver = "8"
                        elif cf.major == 61: java_ver = "17"
                        elif cf.major >= 65: java_ver = "21"
                        break
        except Exception:
            pass

    # 2. Bundle runtime mocks and singletons into libs/
    stats["stubs_sources_only"] = 0
    if with_stubs:
        stubs_jar = target_libs / "mc_stubs.jar"
        try:
            SB.build_stubs_jar(stubs_jar)
            stats["stubs_bundled"] += 1
        except Exception as exc:
            # A jar full of .java files is NOT a classpath entry: javac needs
            # .class. Keep the sources for inspection, but never report them as
            # a bundled stub library - otherwise "stubs bundled: 1" hides the
            # reason every vanilla symbol fails to resolve.
            print(f"  ! stubs could not be compiled ({type(exc).__name__}: {exc}); "
                  f"writing sources only - vanilla symbols will not resolve")
            with zipfile.ZipFile(stubs_jar, "w", zipfile.ZIP_DEFLATED) as zst:
                for p, code in SB.STUB_SOURCES.items():
                    zst.writestr(p, code)
            stats["stubs_sources_only"] = 1

    # 3. Copy and clean Java source files
    if src_dir and src_dir.is_dir():
        actual_src = src_dir / "src" if (src_dir / "src").is_dir() else src_dir
        file_plans: list[dict] = []
        renames_by_pkg: dict[str, dict[str, str]] = {}
        full_class_renames: dict[str, str] = {}

        # Pass 1: Plan destinations and collect class renames for reserved names and case twin collisions
        for j_file in actual_src.rglob("*.java"):
            if "_work" in j_file.parts:
                continue
            rel = j_file.relative_to(actual_src)
            parts = list(rel.parts)
            fname = parts[-1]
            stem = fname[:-5] if fname.endswith(".java") else fname
            orig_cls = stem
            renamed_cls = None
            # decoded, because queued renames are keyed by the real class name
            # (`pkg.A.X`), not by the percent-encoded directory the collision
            # pass had to invent
            pkg = ".".join(urllib.parse.unquote(p) for p in parts[:-1])

            if stem.lower() in WINDOWS_RESERVED_NAMES:
                renamed_cls = f"_{stem}"
                parts[-1] = f"{renamed_cls}.java"
            elif "%" in stem:
                raw_stem = urllib.parse.unquote(stem)
                orig_cls = raw_stem
                parent_siblings = [
                    urllib.parse.unquote(p.stem).lower()
                    for p in j_file.parent.glob("*.java") if p != j_file
                ]
                if raw_stem.lower() in parent_siblings or os.name == "nt":
                    twin_cand = f"{raw_stem}_Twin"
                    counter = 1
                    while any(urllib.parse.unquote(p.stem).lower() == twin_cand.lower() for p in j_file.parent.glob("*.java")):
                        counter += 1
                        twin_cand = f"{raw_stem}_Twin{counter}"
                    renamed_cls = twin_cand
                    parts[-1] = f"{renamed_cls}.java"
                else:
                    parts[-1] = f"{raw_stem}.java"
                    if raw_stem != stem:
                        renamed_cls = raw_stem

            dest_file = target_src.joinpath(*parts)
            dest_file.parent.mkdir(parents=True, exist_ok=True)

            if renamed_cls and renamed_cls != orig_cls:
                renames_by_pkg.setdefault(pkg, {})[orig_cls] = renamed_cls
                if pkg:
                    full_class_renames[f"{pkg}.{orig_cls}"] = f"{pkg}.{renamed_cls}"
                else:
                    full_class_renames[orig_cls] = renamed_cls

            file_plans.append({
                "src": j_file,
                "dest": dest_file,
                "rel": rel,
                "pkg": pkg,
                "orig_cls": orig_cls,
                "renamed_cls": renamed_cls,
            })

        # Pass 2: Apply cross-file reference rewriting and compilation sanitation
        type_index = build_source_type_index(target_src)
        for item in file_plans:
            j_file = item["src"]
            dest_file = item["dest"]
            pkg = item["pkg"]
            orig_cls = item["orig_cls"]
            renamed_cls = item["renamed_cls"]

            code = j_file.read_text(encoding="utf-8", errors="replace")
            original_code = code  # REVIEW 2.4: untouched decompiler output

            # 1. Update fully qualified class references and imports across all packages
            for old_fqcn, new_fqcn in full_class_renames.items():
                code = re.sub(r"\b" + re.escape(old_fqcn) + r"\b", new_fqcn, code)

            # 2. Update references for renamed classes in the same package
            pkg_renames = renames_by_pkg.get(pkg, {})
            for old_name, new_name in pkg_renames.items():
                if renamed_cls == new_name and orig_cls == old_name:
                    # Within the renamed class's own file: update declaration, constructors, and self-types
                    code = re.sub(r"\b(class|interface|enum|record)\s+" + re.escape(old_name) + r"\b", r"\1 " + new_name, code)
                    code = re.sub(r"\b" + re.escape(old_name) + r"\s*\(", new_name + "(", code)
                    code = re.sub(r"\b" + re.escape(old_name) + r"\b", new_name, code)
                else:
                    # Sibling class in the same package using the renamed class
                    code = re.sub(r"\b" + re.escape(old_name) + r"\b", new_name, code)

            # 3. For any class that imported the renamed class from another package
            for imported_pkg, imp_renames in renames_by_pkg.items():
                if imported_pkg != pkg:
                    for old_name, new_name in imp_renames.items():
                        if f"{imported_pkg}.{new_name}" in code:
                            code = re.sub(r"\b" + re.escape(old_name) + r"\b", new_name, code)

            expected_pkg = pkg if pkg else None
            cleaned_code, changes = clean_source_for_compilation(
                code, expected_package=expected_pkg,
                type_index=type_index,
                current_class=renamed_cls or orig_cls)
            if changes or renamed_cls:
                stats["files_repaired"] += 1
                # REVIEW 2.4: keep the pre-repair source and log the exact rules.
                repair_rules = list(changes)
                if renamed_cls and renamed_cls != orig_cls:
                    repair_rules.append(
                        f"Renamed class {orig_cls} -> {renamed_cls} "
                        f"(reserved name / case-collision), references rewritten")
                orig_dir = out_dir / "src-original"
                orig_file = orig_dir / item["rel"]
                orig_file.parent.mkdir(parents=True, exist_ok=True)
                orig_file.write_text(original_code, encoding="utf-8")
                repairs.append({
                    "file": item["rel"].as_posix(),
                    "rules": repair_rules,
                    "orig_lines": len(original_code.splitlines()),
                    "new_lines": len(cleaned_code.splitlines()),
                })

            dest_file.write_text(cleaned_code, encoding="utf-8")
            stats["java_files"] += 1

    # 4. Extract resources from source jar
    #
    # Entry names come from the analysed jar, which is exactly the untrusted
    # input this tool exists for: `../../x` in a hostile sample must not be able
    # to write outside the exported project. Every destination is resolved and
    # containment-checked before the write; the rest are counted, never silent.
    stats["resources_skipped"] = 0
    stats["resource_failures"] = 0
    if source_jar.is_file() and source_jar.suffix.lower() == ".jar":
        try:
            with zipfile.ZipFile(source_jar) as z_in:
                res_root = target_res.resolve()
                for info in z_in.infolist():
                    name = info.filename
                    if name.endswith(".class") or name.endswith("/"):
                        continue
                    try:
                        dest = (target_res / name).resolve()
                    except (OSError, ValueError):
                        stats["resources_skipped"] += 1
                        continue
                    if not dest.is_relative_to(res_root):
                        stats["resources_skipped"] += 1
                        continue
                    try:
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(z_in.read(name))
                        stats["resources_copied"] += 1
                    except (OSError, zipfile.BadZipFile) as exc:
                        stats["resource_failures"] += 1
                        if stats["resource_failures"] == 1:
                            print(f"  ! resource {name}: {exc}")
        except (OSError, zipfile.BadZipFile) as exc:
            stats["resource_failures"] += 1
            print(f"  ! resources could not be extracted: {exc}")
        if stats["resources_skipped"]:
            print(f"  ! skipped {stats['resources_skipped']} unsafe jar "
                  f"entr(y/ies) escaping src/main/resources")

    # 5. Generate Gradle Scaffold
    proj_name = source_jar.stem + "_project"
    generate_gradle_scaffold(
        out_dir,
        project_name=proj_name,
        java_version=java_ver,
        mc_version=resolved_mc,
        mc_flavor=flavor,
    )

    # 6. REVIEW 2.4: self-heal audit log. Evidence ladder:
    #    readable < compilable < JVM-verified < behaviour-parity.
    #    Export alone proves "readable"; --compile proves "compilable" at best.
    #    The ladder's top two levels are not produced by this tool yet and are
    #    explicitly reported as such instead of being implied.
    if repairs:
        stats["repair_rules_applied"] = sum(len(r["rules"]) for r in repairs)
        log_path = out_dir / "repair-log.md"
        lines = [
            "# jdec Compilation Self-Heal Log",
            "",
            f"- target: `{source_jar.name}`",
            f"- exported: {stats['java_files']} java file(s); "
            f"{stats['files_repaired']} repaired; "
            f"{stats['repair_rules_applied']} rule(s) applied",
            "- pre-repair sources preserved under `src-original/` (mirrored paths)",
            "",
            "> **Evidence ladder**: readable < compilable < JVM-verified < behaviour-parity.",
            "> This export is at evidence level **readable**; with `--compile` success it",
            "> reaches **compilable**. JVM verification and behaviour-parity checks are",
            "> NOT implemented yet - a compiling project is not proven to behave like the",
            "> original target. Every rule below may have changed semantics.",
            "",
            "| File | Rules applied | Lines (orig -> repaired) |",
            "| :--- | :--- | :--- |",
        ]
        for r in repairs:
            rules = "; ".join(r["rules"]) if r["rules"] else "(reference rewrite only)"
            lines.append(f"| `{r['file']}` | {rules} | {r['orig_lines']} -> {r['new_lines']} |")
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return stats


def verify_compilation(
    project_dir: Path,
    javac_bin: str = "javac",
    max_repair_passes: int = 3,
    intermediary_jar: Path | str | None = None,
) -> CompilationReport:
    """Run an automated javac compile loop, diagnosing and auto-repairing compile errors."""
    java_src_root = project_dir / "src" / "main" / "java"
    libs_dir = project_dir / "libs"
    try:
        TC.require_javac("verifying the exported project")
    except TC.ToolchainError as exc:
        return CompilationReport(
            success=False, total_files=0, compiled_files=0,
            javac_output=str(exc))

    grounding = MM.IntermediaryGrounding(intermediary_jar) if intermediary_jar else None
    if grounding is not None and grounding.error:
        print(f"WARNING  : intermediary grounding unavailable ({grounding.error}); "
              f"stubs fall back to untyped shapes")

    java_files = list(java_src_root.rglob("*.java")) if java_src_root.is_dir() else []
    if not java_files:
        return CompilationReport(success=False, total_files=0, compiled_files=0, javac_output="No .java files found")

    total_repaired = 0
    repair_io_failures = 0
    issues: list[CompilationIssue] = []
    output = ""

    for pass_num in range(max_repair_passes):
        failures_at_pass_start = repair_io_failures
        # stubs synthesised in an earlier pass are now on disk: normalise them
        # before compiling, and re-check hiding invariants introduced by them
        if java_src_root.is_dir():
            check_static_hiding_invariance(java_src_root)
            enrich_safe_fallback_stubs(project_dir)
        tmp_classes = Path(tempfile.mkdtemp(prefix=f"jdec_compile_pass_{pass_num}_"))
        try:
            # Build classpath from libs/*.jar
            cp_jars = list(libs_dir.glob("*.jar")) if libs_dir.is_dir() else []
            sep = TC.path_sep()
            cp_arg = sep.join(str(j) for j in cp_jars)

            args = ["-J-Duser.language=en", "-encoding", "UTF-8", "-d", str(tmp_classes)]
            if cp_arg:
                args.extend(["-cp", cp_arg])
            # Use argfile for sources to prevent Windows command line 32KB overflow
            sources_file = tmp_classes / "sources.txt"
            sources_file.write_text("\n".join(f'"{f.resolve().as_posix()}"' for f in java_files), encoding="utf-8")
            args.append(f"@{sources_file}")

            try:
                proc = TC.run_javac(args, exe=javac_bin,
                                    purpose="verifying the exported project")
            except TC.ToolchainError as exc:
                return CompilationReport(
                    success=False, total_files=len(java_files), compiled_files=0,
                    repaired_count=total_repaired, javac_output=str(exc))
            output = (proc.stderr or "") + (proc.stdout or "")

            if proc.returncode == 0:
                shutil.rmtree(tmp_classes, ignore_errors=True)
                return CompilationReport(
                    success=True,
                    total_files=len(java_files),
                    compiled_files=len(java_files),
                    repaired_count=total_repaired,
                    javac_output=output,
                )

            # Parse javac errors supporting Windows drive letters, Unix paths, and English/localized tags
            # Format: <file>:<line>: error: <message> or <file>:<line>: 错误: <message>
            error_pat = re.compile(r"^(.+?):(\d+):\s*(?:error|错误):\s*(.+)$", re.M)
            issues = []
            files_to_repatch: dict[Path, list[tuple[int, str]]] = {}

            for match in error_pat.finditer(output):
                f_path_str, line_str, msg = match.groups()
                p = Path(f_path_str)
                line_no = int(line_str)
                issues.append(CompilationIssue(file_path=p, line_number=line_no, column=0, message=msg))
                files_to_repatch.setdefault(p, []).append((line_no, msg))

            # Apply automatic line-level repairs
            pass_repairs = 0
            for file_path, err_list in files_to_repatch.items():
                if file_path.is_file():
                    try:
                        content = file_path.read_text(encoding="utf-8", errors="replace")
                        lines = content.splitlines()
                        modified = False
                        # Process in reverse line order so line insertions/shifts do not displace earlier line numbers
                        sorted_errs = sorted(err_list, key=lambda x: x[0], reverse=True)
                        for l_num, msg in sorted_errs:
                            if 0 < l_num <= len(lines):
                                bad_line = lines[l_num - 1]
                                # Repair 1: Duplicate method or variable definition -> comment it out
                                if ("already defined" in msg) or ("已在类" in msg and "定义" in msg) or ("already defined" in output):
                                    brace_count = bad_line.count("{") - bad_line.count("}")
                                    lines[l_num - 1] = "// [jdec: auto-commented duplicate declaration] " + bad_line
                                    if brace_count > 0:
                                        for sub_i in range(l_num, min(len(lines), l_num + 60)):
                                            brace_count += lines[sub_i].count("{") - lines[sub_i].count("}")
                                            lines[sub_i] = "// [jdec: auto-commented duplicate declaration] " + lines[sub_i]
                                            if brace_count <= 0:
                                                break
                                    modified = True
                                    pass_repairs += 1
                                # Repair 2: Ambiguous method overload with untyped null
                                elif ("ambiguous" in msg) or ("不明确" in msg) or ("ambiguous" in output):
                                    if "null" in bad_line:
                                        cast_type = "Object"
                                        m_type = re.search(r"both method \w+\(([^),]+)", output)
                                        if m_type:
                                            cast_type = m_type.group(1).strip()
                                        lines[l_num - 1] = bad_line.replace("null", f"({cast_type}) null", 1)
                                        modified = True
                                        pass_repairs += 1
                                # Repair 3: Unreachable statement
                                elif ("unreachable statement" in msg) or ("无法访问的语句" in msg):
                                    lines[l_num - 1] = "// [jdec: auto-commented unreachable statement] " + bad_line
                                    modified = True
                                    pass_repairs += 1
                                # Repair 4: Missing return statement
                                elif ("missing return statement" in msg) or ("缺少返回语句" in msg):
                                    lines.insert(l_num - 1, "        throw new UnsupportedOperationException(\"jdec: auto-synthesized stub return\");")
                                    modified = True
                                    pass_repairs += 1
                                # Repair 5: boolean cannot be converted to long (e.g. stackWords[...] = booleanExpr)
                                elif ("cannot be converted to long" in msg and "boolean" in msg) or ("boolean无法转换为long" in msg):
                                    eq_match = re.search(r"^(\s*.*?=\s*)(.+?);?\s*$", bad_line)
                                    if eq_match:
                                        pre, rhs = eq_match.groups()
                                        lines[l_num - 1] = f"{pre}({rhs.strip().rstrip(';')}) ? 1L : 0L;"
                                        modified = True
                                        pass_repairs += 1
                                # Repair 6: int cannot be converted to boolean (e.g. (boolean)(intExpr))
                                elif ("cannot be converted to boolean" in msg and "int" in msg) or ("int无法转换为boolean" in msg):
                                    if "(boolean)(" in bad_line:
                                        line_part = bad_line.replace("(boolean)(", "(", 1)
                                        open_idx = line_part.find("(")
                                        depth = 1
                                        done = False
                                        j = l_num - 1
                                        while j < len(lines) and not done:
                                            start_ch = (open_idx + 1) if j == l_num - 1 else 0
                                            curr_str = line_part if j == l_num - 1 else lines[j]
                                            for ch_idx in range(start_ch, len(curr_str)):
                                                ch = curr_str[ch_idx]
                                                if ch == "(":
                                                    depth += 1
                                                elif ch == ")":
                                                    depth -= 1
                                                    if depth == 0:
                                                        if j == l_num - 1:
                                                            lines[j] = curr_str[:ch_idx + 1] + " != 0" + curr_str[ch_idx + 1:]
                                                        else:
                                                            lines[l_num - 1] = line_part
                                                            lines[j] = curr_str[:ch_idx + 1] + " != 0" + curr_str[ch_idx + 1:]
                                                        done = True
                                                        modified = True
                                                        pass_repairs += 1
                                                        break
                                            j += 1
                                # Repair 7: Unbox cascade incompatible types
                                elif ("incompatible types" in msg) or ("不兼容的类型" in msg):
                                    full_text = "\n".join(lines)
                                    norm_text, unbox_c = normalize_unbox(full_text)
                                    if unbox_c > 0:
                                        lines = norm_text.splitlines()
                                        modified = True
                                        pass_repairs += 1
                                # Repair 8: Static method hiding invariance violation (JLS §8.4.8.2)
                                elif ("cannot hide" in msg and "attempting to use incompatible return type" in msg) or ("无法隐藏" in msg and "不兼容" in msg):
                                    type_m = re.search(r"return type\s+(\w+)\s+is not\s+(\w+)", msg) or re.search(r"attempting to use incompatible return type:?\s*(\w+)\s+(?:is not|与)\s+(\w+)", msg)
                                    if type_m:
                                        bad_t, good_t = type_m.group(1), type_m.group(2)
                                        m_decl = re.sub(r"\bpublic\s+static\s+" + re.escape(bad_t) + r"\b", f"public static {good_t}", bad_line)
                                        if m_decl != bad_line:
                                            lines[l_num - 1] = m_decl
                                            modified = True
                                            pass_repairs += 1
                        if modified:
                            file_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    except Exception as exc:
                        # A repair that cannot be applied must not look applied:
                        # count it and say so once instead of a silent pass.
                        repair_io_failures += 1
                        if repair_io_failures == 1:
                            print(f"  ! repair skipped {file_path.name}: {exc}")

            # Repair 9: Missing package / class symbol auto-synthesis (cross-package imports & same-package symbols)
            for file_path in list(files_to_repatch.keys()):
                if file_path.is_file():
                    try:
                        code_txt = file_path.read_text(encoding="utf-8", errors="replace")
                        for imp_match in re.finditer(r"import\s+([\w.]+)\.([A-Za-z0-9_$]+);", code_txt):
                            pkg_name, cls_name = imp_match.groups()
                            is_missing_pkg = (
                                f"package {pkg_name} does not exist" in output
                                or f"程序包 {pkg_name} 不存在" in output
                                or f"程序包{pkg_name}不存在" in output
                            )
                            is_missing_cls = (
                                f"class {cls_name}" in output
                                or f"类 {cls_name}" in output
                                or f"类{cls_name}" in output
                            )
                            if is_missing_pkg or is_missing_cls:
                                stub_dir = java_src_root / Path(*pkg_name.split("."))
                                stub_file = stub_dir / f"{cls_name}.java"
                                if not stub_file.is_file():
                                    stub_dir.mkdir(parents=True, exist_ok=True)
                                    grounded = grounding.generate_grounded_stub(f"{pkg_name}/{cls_name}") if grounding and grounding.has_class(f"{pkg_name}/{cls_name}") else None
                                    if grounded:
                                        stub_file.write_text(grounded, encoding="utf-8")
                                    else:
                                        stub_code = (
                                            f"package {pkg_name};\n\n"
                                            f"{SB.STUB_MARKER}\n"
                                            f"import java.util.*;\n\n"
                                            f"public class {cls_name} {{\n"
                                            f"    public {cls_name}() {{}}\n"
                                            f"    public static Object dummyField;\n"
                                            f"    public Object dummyMember;\n"
                                            f"    public static Object dummyMethod(Object... args) {{ return null; }}\n"
                                            f"    public Object dummyCall(Object... args) {{ return null; }}\n"
                                            f"}}\n"
                                        )
                                        stub_file.write_text(stub_code, encoding="utf-8")
                                    if stub_file not in java_files:
                                        java_files.append(stub_file)
                                    pass_repairs += 1

                        for sym_m in re.finditer(r"(?:symbol|符号):\s+(?:class|类)\s+([A-Za-z0-9_$]+)", output):
                            cls_name = sym_m.group(1)
                            pkg_dir = file_path.parent
                            stub_file = pkg_dir / f"{cls_name}.java"
                            if not stub_file.is_file():
                                pkg_name = ""
                                first_lines = code_txt.splitlines()[:5]
                                for fl in first_lines:
                                    if fl.strip().startswith("package "):
                                        pkg_name = fl.strip()[8:].rstrip(";").strip()
                                        break
                                grounded = grounding.generate_grounded_stub(f"{pkg_name}/{cls_name}" if pkg_name else cls_name) if grounding and grounding.has_class(f"{pkg_name}/{cls_name}" if pkg_name else cls_name) else None
                                if grounded:
                                    stub_file.write_text(grounded, encoding="utf-8")
                                else:
                                    pkg_decl = f"package {pkg_name};\n\n" if pkg_name else ""
                                    stub_code = (
                                        f"{pkg_decl}"
                                        f"{SB.STUB_MARKER}\n"
                                        f"import java.util.*;\n\n"
                                        f"public class {cls_name} {{\n"
                                        f"    public {cls_name}() {{}}\n"
                                        f"    public static Object dummyField;\n"
                                        f"    public Object dummyMember;\n"
                                        f"    public static Object dummyMethod(Object... args) {{ return null; }}\n"
                                        f"    public Object dummyCall(Object... args) {{ return null; }}\n"
                                        f"}}\n"
                                    )
                                    stub_file.write_text(stub_code, encoding="utf-8")
                                if stub_file not in java_files:
                                    java_files.append(stub_file)
                                pass_repairs += 1
                    except Exception as exc:
                        repair_io_failures += 1
                        if repair_io_failures == 1:
                            print(f"  ! stub synthesis skipped {file_path.name}: {exc}")

            total_repaired += pass_repairs
            if repair_io_failures > failures_at_pass_start:
                print(f"  ! {repair_io_failures - failures_at_pass_start} repair(s) "
                      f"could not be applied in pass {pass_num + 1}")
            if pass_repairs == 0:
                # No automatic repairs could be applied; break loop
                shutil.rmtree(tmp_classes, ignore_errors=True)
                return CompilationReport(
                    success=False,
                    total_files=len(java_files),
                    compiled_files=len(java_files) - len(files_to_repatch),
                    issues=issues,
                    repaired_count=total_repaired,
                    javac_output=output,
                )

        finally:
            shutil.rmtree(tmp_classes, ignore_errors=True)

    return CompilationReport(
        success=False,
        total_files=len(java_files),
        compiled_files=0,
        issues=issues,
        repaired_count=total_repaired,
        javac_output=output,
    )
