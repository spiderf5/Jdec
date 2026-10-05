"""Semantic identifier recovery and LLM prompt generation for obfuscated code.

Obfuscated code contains methods like `a()`, `b()`, or `func_1234_a`. Even after
deobfuscating standard game mappings, mod-specific code and cheat features remain
opaque.

This module harvests semantic context for obfuscated members:
- Mixin hook targets (@Inject into "tick" -> onTick)
- String literals in the method body ("Connecting to %s" -> connectToServer)
- System/Network API calls made by the method
- Field type and accessor patterns (getter/setter)

It generates:
1. Structured LLM prompts ready for batched AI semantic renaming;
2. Rule-based heuristic ProGuard mapping files for immediate deobfuscation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# Match method declarations like:
# public void a(int x, String y) { ... }
_WS = "[ \t\r\n]*"
_WS_PLUS = "[ \t\r\n]+"
_WORD = "[A-Za-z0-9_$]"
_TYPE_CHAR = "[][A-Za-z0-9_$<>, \t]"
_METHOD_DECL = re.compile(
    '(?:public|protected|private|static|final|' + _WS_PLUS + ')+' + _WS_PLUS +
    '(' + _TYPE_CHAR + '+?)' + _WS_PLUS +
    '([A-Za-z_$]' + _WORD + '*)' + _WS +
    '[(]([^)]*)[)]' + _WS +
    '(?:throws' + _WS_PLUS + '[A-Za-z0-9_$, \t]+)?' + _WS + '[{]'
)
_STRING_LIT = re.compile('["\']([^"\']+)["\']')
_MIXIN_INJECT = re.compile('@Inject' + _WS + '[(][^)]*method' + _WS + '=' + _WS + '["\']([^"\']+)["\']')


@dataclass
class MemberContext:
    owner_class: str
    member_name: str
    is_method: bool = True
    return_type: str = ""
    parameters: str = ""
    strings: list[str] = field(default_factory=list)
    mixin_target: str | None = None
    suggested_name: str | None = None


def is_obfuscated_name(name: str) -> bool:
    """Returns True if the identifier appears mangled or short."""
    if len(name) <= 2 and name not in ("id", "go", "to", "up", "on", "in", "at", "as", "is", "of"):
        return True
    if re.fullmatch("[a-z][0-9]{1,3}", name):
        return True
    if name.startswith("func_") or name.startswith("field_") or name.startswith("m_") or name.startswith("f_"):
        return True
    return False


def scan_source_file(file_path: Path, package_prefix: str = "") -> list[MemberContext]:
    """Extract obfuscated members and their context from a single Java source."""
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    pkg_m = re.search(r'^\s*package\s+([A-Za-z0-9_.]+)\s*;', text, re.M)
    pkg = pkg_m.group(1) if pkg_m else package_prefix
    cls_name = (pkg + "/" if pkg else "") + file_path.stem

    candidates: list[MemberContext] = []

    # Find mixin annotations near methods
    lines = text.splitlines()
    for i, line in enumerate(lines):
        mm = _METHOD_DECL.search(line)
        if not mm:
            continue
        ret_type, name, params = mm.group(1).strip(), mm.group(2).strip(), mm.group(3).strip()
        if not is_obfuscated_name(name) or name in ("equals", "hashCode", "toString", "run", "call"):
            continue

        # Look for preceding @Inject
        mixin_target = None
        for back in range(max(0, i - 4), i):
            im = _MIXIN_INJECT.search(lines[back])
            if im:
                mixin_target = im.group(1)
                break

        # Collect strings in method body (next ~40 lines or until closing brace)
        body_chunk = "\n".join(lines[i:min(len(lines), i + 45)])
        found_strings = [s.group(1) for s in _STRING_LIT.finditer(body_chunk)][:5]

        # Generate a heuristic suggestion if possible
        suggestion = None
        if mixin_target:
            clean_tgt = mixin_target.replace("<", "").replace(">", "").strip()
            suggestion = "on" + clean_tgt[:1].upper() + clean_tgt[1:]
        elif found_strings:
            # Check for common keywords in strings
            joined_s = " ".join(found_strings).lower()
            if "connect" in joined_s or "socket" in joined_s:
                suggestion = "connectServer"
            elif "render" in joined_s or "draw" in joined_s:
                suggestion = "renderOverlay"
            elif "token" in joined_s or "auth" in joined_s:
                suggestion = "validateAuth"
            elif "init" in joined_s or "load" in joined_s:
                suggestion = "initializeComponent"

        ctx = MemberContext(
            owner_class=cls_name,
            member_name=name,
            is_method=True,
            return_type=ret_type,
            parameters=params,
            strings=found_strings,
            mixin_target=mixin_target,
            suggested_name=suggestion,
        )
        candidates.append(ctx)

    return candidates


def scan_source_tree(src_dir: Path) -> list[MemberContext]:
    """Scan all Java sources under src_dir."""
    candidates = []
    for p in sorted(src_dir.rglob("*.java")):
        candidates.extend(scan_source_file(p))
    return candidates


def export_llm_prompt(candidates: list[MemberContext], limit: int = 40) -> str:
    """Generate a structured prompt for LLMs to assign semantic names."""
    items = []
    for c in candidates[:limit]:
        items.append({
            "class": c.owner_class,
            "obfuscated_name": c.member_name,
            "signature": f"{c.return_type} ({c.parameters})",
            "strings_in_body": c.strings,
            "mixin_hook_target": c.mixin_target,
            "heuristic_suggestion": c.suggested_name,
        })

    prompt = (
        "You are an expert reverse engineer. Given the following list of obfuscated Java methods, "
        "their signature, referenced string literals, and Mixin hook targets, infer a clear, descriptive, "
        "camelCase name for each method.\n\n"
        "Return a JSON object mapping '<class>.<obfuscated_name>' to the new semantic name.\n\n"
        "```json\n" + json.dumps(items, indent=2) + "\n```\n"
    )
    return prompt


def _format_param_types(params: str) -> str:
    """Extract comma-separated parameter types from a method parameter string."""
    if not params.strip():
        return ""
    types = []
    for part in params.split(","):
        tokens = part.strip().split()
        if len(tokens) >= 2:
            types.append(tokens[-2])
        elif len(tokens) == 1:
            types.append(tokens[0])
    return ",".join(types)


def write_proguard_mapping(candidates: list[MemberContext], out_file: Path) -> int:
    """Export resolved heuristic suggestions to ProGuard format mapping."""
    by_class: dict[str, list[MemberContext]] = {}
    count = 0
    for c in candidates:
        if c.suggested_name and c.suggested_name != c.member_name:
            by_class.setdefault(c.owner_class, []).append(c)
            count += 1

    lines = []
    for cls, mems in sorted(by_class.items()):
        dotted = cls.replace("/", ".")
        lines.append(f"{dotted} -> {dotted}:")
        for m in mems:
            ret = m.return_type or "void"
            params_sig = _format_param_types(m.parameters)
            lines.append(f"    {ret} {m.member_name}({params_sig}) -> {m.suggested_name}")

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return count
