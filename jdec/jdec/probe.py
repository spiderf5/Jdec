"""Fingerprint a jar before touching it.

Decisions the rest of the pipeline depends on:
  * is this obfuscated, and roughly how badly?
  * which bytecode version - decides which engine leads
  * is this Minecraft, which version, vanilla or Forge/Fabric?
"""

from __future__ import annotations

import json
import re
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import obf as OB
from .classfile import parse, ClassFormatError

# word stems that appear constantly in hand-written Java identifiers.
# Their absence is the strongest single signal of name obfuscation.
_COMMON_STEMS = (
    "get", "set", "is", "has", "to", "from", "add", "remove", "put", "create",
    "build", "make", "read", "write", "load", "save", "open", "close", "init",
    "start", "stop", "run", "update", "render", "draw", "tick", "handle",
    "parse", "format", "find", "list", "size", "count", "name", "value",
    "type", "data", "index", "item", "next", "prev", "result", "state",
    "config", "manager", "service", "factory", "builder", "handler", "event",
    "client", "server", "player", "world", "block", "entity", "item",
    "on", "do", "apply", "check", "validate", "convert", "copy", "clear",
)

_STEM_RE = re.compile("|".join(sorted(_COMMON_STEMS, key=len, reverse=True)), re.I)
_MC_VERSION_IN_PATH = re.compile(r"(?<![\w.])(1\.\d{1,2}(?:\.\d{1,2})?|2[0-9]w\d{1,2}[a-z]?|\d{2}\.\d{1,2})(?![\w.])")

_KNOWN_OBFUSCATORS = {
    "com/allatori/": "Allatori",
    "com/dasho/": "Dash-O",
    "net/indiespot/": "Indiespot",
    "de/xbrowniecodez/": "unknown-java-obfuscator",
    "org/objectweb/asm/": None,  # just asm, not obfuscation
    "stringer/": "Stringer",
    "com/javadeobfuscator/": None,
}

_MC_MARKERS = (
    "net/minecraft/", "com/mojang/", "assets/minecraft/", "data/minecraft/",
    "pack.mcmeta", "net/minecraft/client/main/Main.class",
)
# A None name means 'this marker proves nothing'. Mixin ships under
# org/spongepowered/asm/, so every Fabric and Forge mixin mod carries that
# prefix - matching on `org/spongepowered/` alone labels them all as Sponge.
_FLAVORS = (
    ("net/neoforged/", "NeoForge"),
    ("net/minecraftforge/", "Forge"),
    ("cpw/mods/fml/", "FML/Forge"),
    ("net/fabricmc/", "Fabric"),
    ("org/quiltmc/", "Quilt"),
    ("org/spongepowered/asm/", None),
    ("org/spongepowered/", "Sponge"),
    ("net/launchwrapper/", "LaunchWrapper (legacy Forge)"),
)


@dataclass
class JarProfile:
    path: Path
    entries: int = 0
    classes: int = 0
    resources: int = 0
    java_versions: dict[str, int] = field(default_factory=dict)
    top_packages: list[tuple[str, int]] = field(default_factory=list)
    obfuscation: float = 0.0
    obfuscator: str | None = None
    unicode_names: int = 0
    is_minecraft: bool = False
    mc_version: str | None = None
    mc_flavor: str | None = None
    signatures: list[str] = field(default_factory=list)
    sample_classes: list[str] = field(default_factory=list)
    structural: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"file           : {self.path.name}",
            f"entries        : {self.entries}  (classes {self.classes}, resources {self.resources})",
            f"bytecode       : " + ", ".join(
                f"Java {k} x{v}" for k, v in sorted(self.java_versions.items(),
                                                    key=lambda kv: -kv[1])[:4]),
            f"obfuscation    : {self.obfuscation:.0f}/100"
            + (f"  ({self.obfuscator})" if self.obfuscator else ""),
        ]
        if self.is_minecraft:
            lines.append(
                f"minecraft      : yes"
                + (f" {self.mc_version}" if self.mc_version else " version unknown")
                + (f" / {self.mc_flavor}" if self.mc_flavor else ""))
        if self.top_packages:
            lines.append("top packages   : " + ", ".join(
                f"{p} ({c})" for p, c in self.top_packages[:5]))
        if self.structural:
            lines.append("structure      : " + "; ".join(self.structural[:4]))
        if self.signatures:
            lines.append("signatures     : " + "; ".join(self.signatures[:4]))
        return "\n".join(lines)


def _major_version(data: bytes) -> int | None:
    if len(data) < 8:
        return None
    try:
        return struct.unpack_from(">H", data, 6)[0]
    except struct.error:
        return None


def profile_jar(path: Path, sample: int = 400) -> JarProfile:
    prof = JarProfile(path=path)
    zf = zipfile.ZipFile(path)
    names = zf.namelist()
    prof.entries = len(names)
    class_names = [n for n in names if n.endswith(".class")]
    prof.classes = len(class_names)
    prof.resources = prof.entries - prof.classes

    joined = "\n".join(names)
    for m in _MC_MARKERS:
        if m in joined:
            prof.is_minecraft = True
            break
    for marker, flavor in _FLAVORS:
        if marker in joined:
            # a None marker is a verdict too: the prefix is uninformative and
            # a broader rule below must not get a second say
            if flavor:
                prof.mc_flavor = flavor
            break

    # version.json ships inside modern client jars
    if "version.json" in names:
        try:
            v = json.loads(zf.read("version.json"))
            prof.mc_version = v.get("id") or v.get("name")
        except Exception:
            pass
    if not prof.mc_version:
        m = _MC_VERSION_IN_PATH.search(str(path))
        if m:
            prof.mc_version = m.group(1)

    for marker, obf in _KNOWN_OBFUSCATORS.items():
        if marker in joined and obf:
            prof.obfuscator = obf
            prof.signatures.append(f"obfuscator package {marker}")
            break

    # bytecode versions across everything (cheap: header only)
    from .classfile import java_version_of
    versions: dict[str, int] = {}
    for n in class_names:
        try:
            with zf.open(n) as f:
                head = f.read(8)
        except Exception:
            continue
        mj = _major_version(head)
        if mj:
            versions[java_version_of(mj)] = versions.get(java_version_of(mj), 0) + 1
    prof.java_versions = versions

    # deep sample for naming statistics
    step = max(1, len(class_names) // sample)
    picked = class_names[::step][:sample]
    name_lengths: list[int] = []
    member_lengths: list[int] = []
    stem_hits = 0
    stem_total = 0
    pkg_counter: dict[str, int] = {}
    unicode_names = 0
    structural: dict[str, int] = {}

    for n in picked:
        try:
            data = zf.read(n)
            cf = parse(data)
        except (ClassFormatError, Exception):
            continue
        # structural fingerprints: ZKM ships no runtime library, so packages
        # alone can never identify it - the bytecode shape has to
        for k, v in OB.inspect_class(cf).items():
            structural[k] = structural.get(k, 0) + v
        if "/" in n:
            pkg = n.rsplit("/", 1)[0]
            pkg_counter[pkg] = pkg_counter.get(pkg, 0) + 1
        simple = cf.name.rsplit("/", 1)[-1]
        if any(ord(ch) > 127 for ch in simple):
            unicode_names += 1
        name_lengths.append(len(simple))
        prof.sample_classes.append(cf.name)
        for mn, _d in cf.method_sigs() + cf.field_sigs():
            if mn.startswith("<"):
                continue
            member_lengths.append(len(mn))
            stem_total += 1
            if _STEM_RE.search(mn):
                stem_hits += 1
            if any(ord(ch) > 127 for ch in mn):
                unicode_names += 1

    prof.unicode_names = unicode_names
    prof.top_packages = sorted(pkg_counter.items(), key=lambda kv: -kv[1])[:12]

    if not name_lengths:
        prof.obfuscation = 0.0
    else:
        cls_med = _median(name_lengths)
        mem_med = _median(member_lengths) if member_lengths else cls_med
        stem_ratio = (stem_hits / stem_total) if stem_total else 0.0
        short_ratio = sum(1 for x in member_lengths if x <= 2) / max(1, len(member_lengths))
        # each signal contributes independently; 0 = clean, 1 = mangled
        s_len = _clamp01((12 - cls_med) / 10)          # short class names
        s_mem = _clamp01((10 - mem_med) / 8)           # short member names
        s_stem = _clamp01((0.35 - stem_ratio) / 0.35)  # no readable word stems
        s_short = _clamp01(short_ratio / 0.5)          # lots of 1-2 char names
        prof.obfuscation = round(
            100 * (0.28 * s_len + 0.26 * s_mem + 0.30 * s_stem + 0.16 * s_short), 1)

    if structural:
        prof.structural = sorted(structural)
        vendor, conf = OB.attribute(structural, len(picked))
        if vendor and prof.obfuscator is None:
            prof.obfuscator = vendor
            prof.signatures.append(
                f"{vendor} structural fingerprint (confidence {conf:.2f})")
        elif vendor:
            prof.signatures.append(
                f"also matches {vendor} structurally (confidence {conf:.2f})")

    if unicode_names > 0 and prof.obfuscation < 70:
        prof.obfuscation = 85.0
        prof.signatures.append("non-ASCII identifiers present")
    if prof.obfuscation >= 55 and prof.obfuscator is None:
        prof.obfuscator = "ProGuard-like (name mangling)"
    if prof.is_minecraft and prof.obfuscation >= 55:
        prof.signatures.append("Minecraft jar appears obfuscated -> remap before decompiling")
    return prof


def _median(xs: list[int]) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    mid = len(s) // 2
    return float(s[mid]) if len(s) % 2 else (s[mid - 1] + s[mid]) / 2


def _clamp01(x: float) -> float:
    return 0.0 if x < 0 else (1.0 if x > 1 else x)
