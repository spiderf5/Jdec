"""Minecraft mod metadata and Mixin hook extraction.

A Minecraft client with a cheat client bolted on is almost always a mod:
Fabric/Quilt with `fabric.mod.json`, or Forge/NeoForge with `META-INF/mods.toml`.
Its own classes are renamed by the vendor's obfuscator, but the *hooks* into
the game are not - they are annotation values, and annotation values are
constant-pool constants rather than identifiers. `@Mixin(PlayerEntity.class)`
still names the game class after every other name in the jar has been mangled.

So the most useful thing jdec can tell you about such a jar is a list of
"this is what it changes in the game", which is what this module produces.
"""

from __future__ import annotations

import json
import re
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import annotations as AN
from . import classfile as CF

# annotation simple names that mark a mixin and its injection points.
# Anything not in this table is ignored; plenty of mods carry bespoke
# annotations and we do not want to guess at their meaning.
_MIXIN_KINDS = (
    "Inject", "Overwrite", "Redirect", "ModifyVariable", "ModifyArg",
    "ModifyConstant", "ModifyExpressionValue", "ModifyReturnValue",
    "Accessor", "Invoker", "Surrogate",
)


@dataclass
class ModMeta:
    loader: str | None = None           # fabric / forge / neoforge / quilt
    mod_id: str | None = None
    name: str | None = None
    version: str | None = None
    authors: list[str] = field(default_factory=list)
    description: str | None = None
    entrypoints: list[str] = field(default_factory=list)
    mixin_configs: list[str] = field(default_factory=list)
    source_file: str | None = None
    manifest: "ManifestInfo | None" = None

    def summary(self) -> str:
        bits = []
        if self.mod_id:
            bits.append(f"id={self.mod_id}")
        if self.name and self.name != self.mod_id:
            bits.append(f"name={self.name}")
        if self.version:
            bits.append(f"version={self.version}")
        if self.loader:
            bits.append(f"loader={self.loader}")
        if self.manifest:
            for k in ("Implementation-Vendor", "Specification-Vendor"):
                if self.manifest.main.get(k):
                    bits.append(f"vendor={self.manifest.main[k]}")
                    break
            ag = self.manifest.agent_attrs()
            if ag.get("Premain-Class") or ag.get("Agent-Class"):
                bits.append("java-agent")
        if self.entrypoints:
            bits.append(f"entries={','.join(self.entrypoints[:3])}")
        if self.mixin_configs:
            bits.append(f"mixin configs={','.join(self.mixin_configs[:3])}")
        return " ".join(bits) or "no mod metadata found"


# --------------------------------------------------------------------------
# MANIFEST.MF。真实样本教训（2026-10-04 对标）：Vendor、Premain/Agent-Class 声明
# 是最硬的身份情报，但只在 manifest 里——漏读它 = 漏掉"双模式 Java Agent"
# 这种定性级结论。所以 manifest 是固定采集项，不是可选加餐。
# --------------------------------------------------------------------------

_AGENT_ATTRS = ("Premain-Class", "Agent-Class", "Launcher-Agent-Class",
                "Can-Retransform-Classes", "Can-Redefine-Classes")


@dataclass
class ManifestInfo:
    main: dict[str, str] = field(default_factory=dict)
    sections: dict[str, dict[str, str]] = field(default_factory=dict)
    raw: str | None = None

    def agent_attrs(self) -> dict[str, str]:
        """Java Instrumentation agent 的能力声明（Premain/Agent-Class 等）。"""
        return {k: v for k, v in self.main.items() if k in _AGENT_ATTRS}


def parse_manifest(text: str) -> ManifestInfo:
    """JAR manifest 纯文本解析。行首空格 = 续行（去掉那一个空格接回上值）；
    空行分 section；首个 section 是 main attributes，其余按 Name: 头归档。"""
    info = ManifestInfo(raw=text)
    sections: list[dict[str, str]] = [{}]
    last_key: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        if not line.strip():
            if sections[-1]:
                sections.append({})
                last_key = None
            continue
        if line.startswith(" ") and last_key:
            sections[-1][last_key] += line[1:]
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            last_key = k.strip()
            sections[-1][last_key] = v.strip()
    info.main = dict(sections[0])
    rest: dict[str, dict[str, str]] = {}
    for sec in sections[1:]:
        if not sec:
            continue
        name = sec.pop("Name", None)
        rest[name if name else "(unnamed)"] = sec
    info.sections = rest
    return info


def read_manifest(jar: Path) -> ManifestInfo | None:
    try:
        with zipfile.ZipFile(jar) as z:
            if "META-INF/MANIFEST.MF" not in z.namelist():
                return None
            return parse_manifest(
                z.read("META-INF/MANIFEST.MF").decode("utf-8", "replace"))
    except Exception:
        return None


def resource_inventory(jar: Path, limit: int = 10) -> dict:
    """非 class 条目粗分类：总数、顶层目录、扩展名分布。

    资源本身就是情报（assets/ 品牌、着色器、字体、配置模板），而且
    ZKM 会改写资源内容（真实样本的 mods.toml 注释里全词 mod 被替换）——
    数量与分布先摆出来，人再去看内容。"""
    dirs: dict[str, int] = {}
    exts: dict[str, int] = {}
    n = 0
    with zipfile.ZipFile(jar) as z:
        for name in z.namelist():
            if name.endswith("/") or name.endswith(".class"):
                continue
            n += 1
            top = name.split("/", 1)[0] if "/" in name else "(root)"
            dirs[top] = dirs.get(top, 0) + 1
            base = name.rsplit("/", 1)[-1]
            ext = base.rsplit(".", 1)[-1].lower() if "." in base else "(none)"
            exts[ext] = exts.get(ext, 0) + 1
    return {"non_class": n,
            "top_dirs": sorted(dirs.items(), key=lambda kv: -kv[1])[:limit],
            "by_ext": sorted(exts.items(), key=lambda kv: -kv[1])[:limit]}


# 标识符级混淆启发式的字典：MC/Fabric/Forge 生态高频词 + 通用编程词。
# 检测的是"字典词被等长/近形随机串整体替换"的资源侧特征（真实样本实测：
# mods.toml 里全词 mod → 随机串，23 行命中——ZKM 资源处理物证）。
_KNOWN_WORDS = frozenset("""
mod mods name names version versions description authors author credits
license contact displayurl logo logofile url issues repository homepage
dependencies dependency required optional ordering side client server
environment entrypoints entrypoint main mixins mixin accesswidener depends
suggests breaks conflicts custom id icon sources contributors loader
fabricloader minecraft forge neoforge java language file jar assets textures
models blockstates lang sounds shaders pack packmeta format min max
schemaversion schema group provider adapter value type key data index list
set map string int bool float true false null title label text item block
entity gui config settings path root base ref links event events state
""".split())

_TEXT_EXT = frozenset(
    "json toml cfg properties txt lang yml yaml mcmeta".split())


def resource_anomaly(jar: Path, limit: int = 5, min_count: int = 5) -> dict:
    """文本资源里的疑似标识符替换（高频 + 非字典 + 拆不出字典词）。

    启发式，只报嫌疑不定性——命中后人工打开对应资源确认。
    返回 {"text_files": N, "tokens": M, "suspects": [(tok, count, files)]}.
    """
    import re
    from collections import Counter, defaultdict
    token = re.compile("[A-Za-z][A-Za-z0-9_$]{2,}")
    counts: Counter = Counter()
    where: defaultdict = defaultdict(set)
    text_files = 0
    with zipfile.ZipFile(jar) as z:
        for name in z.namelist():
            if name.endswith("/") or name.endswith(".class"):
                continue
            ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            if ext not in _TEXT_EXT:
                continue
            try:
                info = z.getinfo(name)
                if info.file_size > 1_000_000:
                    continue
                txt = z.read(name).decode("utf-8")
            except Exception:  # noqa: BLE001
                continue
            text_files += 1
            for m in token.finditer(txt):
                tok = m.group(0)
                counts[tok] += 1
                where[tok].add(name)
    suspects: list[tuple[str, int, int]] = []
    for tok, n in counts.most_common():
        if len(suspects) >= limit:
            break
        if n < min_count and len(where[tok]) < 2:
            continue
        if tok.lower() in _KNOWN_WORDS:
            continue
        # 驼峰/下划线复合词拆解：能拆出 >=3 字母字典词的不算嫌疑
        # （ConfigManager、getVersionUrl 这类正常命名）
        parts = re.split("[0-9_$]+|(?<=[a-z])(?=[A-Z])", tok)
        if any(p.lower() in _KNOWN_WORDS and len(p) >= 3 for p in parts):
            continue
        suspects.append((tok, n, len(where[tok])))
    return {"text_files": text_files, "tokens": len(counts),
            "suspects": suspects}


@dataclass
class MixinHook:
    """One place where the jar reaches into another class."""

    mixin_class: str                    # internal name of the class doing it
    kind: str                           # Mixin / Inject / Overwrite / ...
    target_class: str | None = None     # as written in the annotation
    target_method: str | None = None    # as written in the annotation
    named_class: str | None = None      # after mapping, if we had one
    named_method: str | None = None
    at: str | None = None               # @At value, e.g. HEAD / TAIL / RETURN
    entry: str | None = None            # jar entry, handy when names are mangled
    raw_method: str | None = None       # name as written before refmap lookup

    @property
    def resolved_class(self) -> str | None:
        return self.named_class or self.target_class

    @property
    def resolved_method(self) -> str | None:
        return self.named_method or self.target_method


@dataclass
class Refmap:
    """Fabric's refmap: intermediary name -> real (obfuscated) name.

    When a mod is built, every `@Inject(method = "...")` is rewritten to the
    intermediary name (`method_1234`) and the original name is parked in a
    refmap shipped alongside the mixin. Repositories that strip or mangle the
    mixin config usually forget the refmap, and it is the only remaining clue
    to what those opaque method names actually are.
    """

    mappings: dict[str, dict[str, str]] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)

    def method_name(self, mixin_class: str, name: str) -> str | None:
        return self.mappings.get(mixin_class, {}).get(name)

    def __len__(self) -> int:
        return sum(len(v) for v in self.mappings.values())


def load_refmap(jar: Path) -> Refmap:
    rep = Refmap()
    with zipfile.ZipFile(jar) as z:
        names = [n for n in z.namelist() if n.endswith(".json")]
        # a file called *refmap*.json is the intended one; the rest is a
        # fallback because the name is not guaranteed to survive repacking
        ordered = ([n for n in names if "refmap" in n.lower()]
                   + [n for n in names if "refmap" not in n.lower()])
        for n in ordered:
            try:
                doc = json.loads(z.read(n).decode("utf-8", "replace"))
            except Exception:
                continue
            if not isinstance(doc, dict):
                continue
            m = doc.get("mappings")
            if not isinstance(m, dict) or not m:
                continue
            found = False
            for cls, entries in m.items():
                if not isinstance(entries, dict):
                    continue
                table = rep.mappings.setdefault(cls.replace(".", "/"), {})
                for real, inter in entries.items():
                    if isinstance(inter, str):
                        # stored obf -> intermediary, we need the reverse
                        table[inter] = real
                        found = True
            if found:
                rep.sources.append(n)
    return rep


def apply_refmap(hooks: list[MixinHook], refmap: Refmap | None) -> int:
    """Rewrite intermediary method names back. Returns how many were mapped.

    The original name is kept in `raw_method` so a later mapping pass can still
    fall back to it, and so the report can show both spellings.
    """
    if refmap is None or not refmap.mappings:
        return 0
    changed = 0
    for h in hooks:
        if not h.target_method:
            continue
        real = refmap.method_name(h.mixin_class, h.target_method)
        if real and real != h.target_method:
            h.raw_method = h.target_method
            h.target_method = real
            changed += 1
    return changed


# --------------------------------------------------------------------------
# mod metadata
# --------------------------------------------------------------------------

def _first_dict(node) -> dict:
    if isinstance(node, dict):
        return node
    if isinstance(node, list) and node and isinstance(node[0], dict):
        return node[0]
    return {}


def read_mod_meta(jar: Path) -> ModMeta:
    """loader 元数据（fabric.mod.json / quilt.mod.json / mods.toml / mcmod.info）+ manifest。

    manifest 是固定采集项：不管 loader 是什么，身份/agent 声明都在那里。"""
    meta = _read_loader_meta(jar)
    meta.manifest = read_manifest(jar)
    if meta.loader is None and meta.manifest:
        ag = meta.manifest.agent_attrs()
        if ag.get("Premain-Class") or ag.get("Agent-Class"):
            meta.loader = "java-agent"
        elif "FMLCorePlugin" in meta.manifest.main:
            meta.loader = "forge (coremod)"
        elif "TweakClass" in meta.manifest.main:
            meta.loader = "launchwrapper (tweaker)"
    return meta


def _read_loader_meta(jar: Path) -> ModMeta:
    meta = ModMeta()
    with zipfile.ZipFile(jar) as z:
        names = set(z.namelist())

        if "fabric.mod.json" in names:
            try:
                doc = json.loads(z.read("fabric.mod.json").decode("utf-8", "replace"))
            except Exception:
                doc = {}
            meta.loader = "fabric"
            meta.source_file = "fabric.mod.json"
            meta.mod_id = doc.get("id")
            meta.version = doc.get("version")
            meta.name = (doc.get("name") if isinstance(doc.get("name"), str)
                         else doc.get("name"))
            if isinstance(doc.get("name"), dict):
                meta.name = str(doc["name"])
            meta.description = doc.get("description") if isinstance(
                doc.get("description"), str) else None
            authors = doc.get("authors")
            if isinstance(authors, list):
                meta.authors = [str(a) for a in authors if not isinstance(a, dict)]
            for group in ("main", "client", "server"):
                for e in (doc.get("entrypoints") or {}).get(group) or []:
                    if isinstance(e, str):
                        meta.entrypoints.append(e)
                    elif isinstance(e, dict) and e.get("value"):
                        meta.entrypoints.append(str(e["value"]))
            mix = doc.get("mixins")
            if isinstance(mix, str):
                meta.mixin_configs.append(mix)
            elif isinstance(mix, list):
                meta.mixin_configs += [str(m) for m in mix]
            return meta

        if "quilt.mod.json" in names:
            try:
                doc = json.loads(z.read("quilt.mod.json").decode("utf-8", "replace"))
            except Exception:
                doc = {}
            meta.loader = "quilt"
            meta.source_file = "quilt.mod.json"
            ql = doc.get("quilt_loader", {}) if isinstance(doc.get("quilt_loader"), dict) else {}
            meta.mod_id = ql.get("id") or doc.get("id")
            meta.version = ql.get("version") or doc.get("version")
            md = ql.get("metadata", {}) if isinstance(ql.get("metadata"), dict) else {}
            meta.name = md.get("name") or doc.get("name")
            meta.description = md.get("description") or doc.get("description")
            contribs = md.get("contributors", {})
            if isinstance(contribs, dict):
                meta.authors = list(contribs.keys())
            elif isinstance(contribs, list):
                meta.authors = [str(c) for c in contribs]
            elif isinstance(doc.get("authors"), list):
                meta.authors = [str(a) for a in doc["authors"] if not isinstance(a, dict)]

            eps = ql.get("entrypoints") or doc.get("entrypoints") or {}
            if isinstance(eps, dict):
                for group in ("main", "client", "server", "init"):
                    val = eps.get(group)
                    if isinstance(val, str):
                        meta.entrypoints.append(val)
                    elif isinstance(val, list):
                        for it in val:
                            if isinstance(it, str):
                                meta.entrypoints.append(it)
                            elif isinstance(it, dict) and it.get("value"):
                                meta.entrypoints.append(str(it["value"]))
            mix = doc.get("mixin") or doc.get("mixins") or ql.get("mixin") or ql.get("mixins")
            if isinstance(mix, str):
                meta.mixin_configs.append(mix)
            elif isinstance(mix, list):
                meta.mixin_configs += [str(m) for m in mix]
            return meta

        if "META-INF/mods.toml" in names or "META-INF/neoforge.mods.toml" in names:
            key = ("META-INF/neoforge.mods.toml"
                   if "META-INF/neoforge.mods.toml" in names else "META-INF/mods.toml")
            text = z.read(key).decode("utf-8", "replace")
            meta.loader = "neoforge" if "neoforge" in key else "forge"
            meta.source_file = key
            m = re.search(r'^\s*modId\s*=\s*[\'"]([^\'"]+)[\'"]', text, re.M)
            if m:
                meta.mod_id = m.group(1)
            m = re.search(r'^\s*displayName\s*=\s*[\'"]([^\'"]+)[\'"]', text, re.M)
            if m:
                meta.name = m.group(1)
            m = re.search(r'^\s*version\s*=\s*[\'"]([^\'"]+)[\'"]', text, re.M)
            if m:
                meta.version = m.group(1)
            m = re.search(r'^\s*authors\s*=\s*[\'"]([^\'"]+)[\'"]', text, re.M)
            if m:
                meta.authors = [a.strip() for a in m.group(1).split(",") if a.strip()]
            m = re.search(r'^\s*description\s*=\s*[\'"]{0,3}([^\'"\n]+)', text, re.M)
            if m:
                meta.description = m.group(1)
            # Forge declares mixin configs in [[mixins]] blocks
            meta.mixin_configs = re.findall(r'^\s*config\s*=\s*[\'"]([^\'"]+\.json)[\'"]', text, re.M)
            return meta

        if "mcmod.info" in names:
            try:
                doc = json.loads(z.read("mcmod.info").decode("utf-8", "replace"))
            except Exception:
                doc = {}
            d = _first_dict(doc)
            meta.loader = "forge (1.7-1.12)"
            meta.source_file = "mcmod.info"
            meta.mod_id = d.get("modid")
            meta.name = d.get("name")
            meta.version = d.get("version")
            meta.authors = d.get("authorList") or []
            meta.description = d.get("description")
            return meta

    return meta


def mixin_class_names(jar: Path, meta: ModMeta,
                      limit: int = 0) -> tuple[list[str], int]:
    """Class internal names declared by the mod's mixin configs.

    Returns (names, configs_read). An empty list means 'scan everything' -
    plenty of repacked clients drop or rename the config while leaving the
    annotations intact.
    """
    names: list[str] = []
    read = 0
    if not meta.mixin_configs:
        return names, 0
    with zipfile.ZipFile(jar) as z:
        for cfg in meta.mixin_configs:
            try:
                doc = json.loads(z.read(cfg).decode("utf-8", "replace"))
            except Exception:
                continue
            read += 1
            pkg = (doc.get("package") or "").replace(".", "/")
            for group in ("mixins", "client", "server"):
                for short in doc.get(group) or []:
                    if not isinstance(short, str):
                        continue
                    names.append(f"{pkg}/{short}" if pkg else short)
            if limit and len(names) >= limit:
                break
    return names, read


# --------------------------------------------------------------------------
# hook extraction
# --------------------------------------------------------------------------

def _normalize_class(raw: str) -> str:
    """Mixin targets are written either dotted or slashed; we store slashed."""
    return raw.replace(".", "/").strip()


def _class_annotation_values(cf, ann: AN.Annotation) -> list[str]:
    """Class targets out of a @Mixin annotation: value() or targets()."""
    out: list[str] = []
    for key in ("value", "targets", "target"):
        v = ann.values.get(key)
        if v is None:
            continue
        items = v if isinstance(v, list) else [v]
        for it in items:
            if isinstance(it, str) and it:
                out.append(_normalize_class(it))
    return out


def hooks_from_class(cf, entry: str | None = None) -> list[MixinHook]:
    """Every mixin annotation on one parsed class.

    An `@Inject` names only a method; the class it belongs to comes from the
    `@Mixin` on the type. Without inheriting it the hook list would be a pile
    of bare method names with nothing to attach them to.
    """
    hooks: list[MixinHook] = []
    self_name = cf.name

    class_targets: list[str] = []
    for ann in AN.class_annotations(cf):
        if ann.simple_type != "Mixin":
            continue
        targets = _class_annotation_values(cf, ann)
        if not targets:
            hooks.append(MixinHook(mixin_class=self_name, kind="Mixin", entry=entry))
            continue
        for t in targets:
            hooks.append(MixinHook(mixin_class=self_name, kind="Mixin",
                                   target_class=t, entry=entry))
        class_targets += targets

    for m in cf.methods:
        for ann in AN.member_annotations(cf, m):
            kind = ann.simple_type
            if kind not in _MIXIN_KINDS:
                continue
            at = None
            atv = ann.values.get("at")
            if isinstance(atv, list):           # @At is repeatable in source
                atv = next((x for x in atv if isinstance(x, AN.Annotation)), None)
            if isinstance(atv, AN.Annotation):
                vals = atv.strings("value")
                at = vals[0] if vals else atv.simple_type
            methods = ann.strings("method")
            owners = class_targets or [None]
            for owner in owners:
                if not methods:
                    hooks.append(MixinHook(mixin_class=self_name, kind=kind,
                                           target_class=owner, at=at, entry=entry))
                    continue
                for mn in methods:
                    hooks.append(MixinHook(mixin_class=self_name, kind=kind,
                                           target_class=owner, target_method=mn,
                                           at=at, entry=entry))
    return hooks


def collect_hooks(jar: Path, meta: ModMeta | None = None,
                  declared: list[str] | None = None,
                  scan_all: bool = True) -> tuple[list[MixinHook], dict]:
    """Walk the jar and pull out every mixin hook.

    Declared mixin classes are checked first because the config is cheap and
    exact; the full sweep is the fallback that still finds hooks in jars whose
    metadata was stripped.
    """
    meta = meta or ModMeta()
    stats = {"declared": 0, "scanned": 0, "with_hooks": 0, "unreadable": 0}
    hooks: list[MixinHook] = []
    entry_of: dict[str, str] = {}

    with zipfile.ZipFile(jar) as z:
        entries = [n for n in z.namelist()
                   if n.endswith(".class") and not n.startswith("META-INF/")]
        by_name: dict[str, str] = {}
        # index by path first: declared names come from the config and are
        # authoritative, but the entry may live under a mangled path
        data: dict[str, bytes] = {}
        for n in entries:
            try:
                data[n] = z.read(n)
            except Exception:
                continue
        for n, raw in list(data.items()):
            try:
                cf = CF.parse(raw)
            except Exception:
                stats["unreadable"] += 1
                continue
            by_name[cf.name] = n
            entry_of[cf.name] = n

        todo: list[str] = []
        if declared:
            todo = [d for d in declared if d in by_name]
            stats["declared"] = len(todo)
        if not todo and scan_all:
            todo = list(by_name)

        for name in todo:
            raw = data.get(by_name.get(name, ""))
            if raw is None:
                continue
            try:
                cf = CF.parse(raw)
            except Exception:
                stats["unreadable"] += 1
                continue
            stats["scanned"] += 1
            found = hooks_from_class(cf, entry=entry_of.get(name))
            if found:
                stats["with_hooks"] += 1
            hooks += found

    return hooks, stats


# --------------------------------------------------------------------------
# translating obfuscated targets into readable names
# --------------------------------------------------------------------------

def _dot_variants(name: str) -> list[str]:
    """Try both separators; mappings are keyed on internal (slashed) names."""
    out = [name]
    alt = name.replace("/", ".") if "/" in name else name.replace(".", "/")
    if alt != name:
        out.append(alt)
    return out


def translate_hooks(hooks: list[MixinHook], mapping) -> int:
    """Fill in named_class / named_method using a Minecraft mapping.

    Returns how many got at least one resolved name. Methods are looked up
    under the target class both as written and under its deobfuscated name,
    because a mixin may reference the game class by either.
    """
    if mapping is None:
        return 0
    resolved = 0
    for h in hooks:
        if h.target_class:
            for cand in _dot_variants(h.target_class):
                new = mapping.lookup_class(cand)
                if new:
                    h.named_class = new
                    break
        owners: list[str] = []
        if h.target_class:
            owners += _dot_variants(h.target_class)
        if h.named_class:
            owners.append(h.named_class)
        if h.target_method:
            for owner in owners:
                new = mapping.lookup_member(owner, h.target_method, None)
                if new:
                    h.named_method = new
                    break
        if h.named_class or h.named_method:
            resolved += 1
    return resolved


# --------------------------------------------------------------------------
# Intermediary Grounding: Anchor synthetic stubs to the actual Minecraft
# runtime jar (client-intermediary.jar). Prevents RT_* hallucinated symbols.
# --------------------------------------------------------------------------

def _parse_single_type(t_desc: str) -> str:
    prim_map = {
        "B": "byte", "C": "char", "D": "double", "F": "float",
        "I": "int", "J": "long", "S": "short", "Z": "boolean", "V": "void"
    }
    arr = 0
    i = 0
    while i < len(t_desc) and t_desc[i] == "[":
        arr += 1
        i += 1
    if i >= len(t_desc):
        return "Object"
    ch = t_desc[i]
    if ch == "L":
        semi = t_desc.find(";", i)
        base = t_desc[i + 1:semi].replace("/", ".") if semi != -1 else t_desc[i + 1:].replace("/", ".")
    elif ch in prim_map:
        base = prim_map[ch]
    else:
        base = "Object"
    return base + "[]" * arr


def _parse_jvm_descriptor(desc: str) -> tuple[list[str], str]:
    """Parse a JVM method descriptor e.g. '(Ljava/lang/String;I)Z' -> (['String', 'int'], 'boolean')."""
    prim_map = {
        "B": "byte", "C": "char", "D": "double", "F": "float",
        "I": "int", "J": "long", "S": "short", "Z": "boolean", "V": "void"
    }
    if not desc.startswith("("):
        return [], _parse_single_type(desc)

    end_paren = desc.find(")")
    if end_paren == -1:
        return [], "Object"

    param_part = desc[1:end_paren]
    ret_part = desc[end_paren + 1:]

    params = []
    i = 0
    while i < len(param_part):
        arr = 0
        while i < len(param_part) and param_part[i] == "[":
            arr += 1
            i += 1
        if i >= len(param_part):
            break
        ch = param_part[i]
        if ch == "L":
            semi = param_part.find(";", i)
            if semi == -1:
                t = param_part[i + 1:].replace("/", ".")
                i = len(param_part)
            else:
                t = param_part[i + 1:semi].replace("/", ".")
                i = semi + 1
        elif ch in prim_map:
            t = prim_map[ch]
            i += 1
        else:
            t = "Object"
            i += 1
        params.append(t + "[]" * arr)

    ret_type = _parse_single_type(ret_part)
    return params, ret_type


_PRIM_SIG = {
    "B": "byte", "C": "char", "D": "double", "F": "float", "I": "int",
    "J": "long", "S": "short", "Z": "boolean", "V": "void",
}


def _attr_text(cf: CF.ClassFile, attrs_blob: bytes, wanted: str) -> str | None:
    """Read a UTF-8-valued attribute (currently only `Signature`)."""
    if not attrs_blob or len(attrs_blob) < 2:
        return None
    count = struct.unpack_from(">H", attrs_blob, 0)[0]
    p = 2
    for _ in range(count):
        if p + 6 > len(attrs_blob):
            return None
        ni, ln = struct.unpack_from(">HI", attrs_blob, p)
        p += 6
        if p + ln > len(attrs_blob):
            return None
        if cf.utf8(ni) == wanted:
            raw = attrs_blob[p:p + ln]
            if len(raw) >= 2:
                return cf.utf8(struct.unpack_from(">H", raw, 0)[0])
            return None
        p += ln
    return None


def _attr_exceptions(cf: CF.ClassFile, attrs_blob: bytes) -> list[str]:
    """Read the `Exceptions` attribute (checked exceptions live there, not in Signature)."""
    if not attrs_blob or len(attrs_blob) < 2:
        return []
    count = struct.unpack_from(">H", attrs_blob, 0)[0]
    p = 2
    for _ in range(count):
        if p + 6 > len(attrs_blob):
            return []
        ni, ln = struct.unpack_from(">HI", attrs_blob, p)
        p += 6
        if p + ln > len(attrs_blob):
            return []
        if cf.utf8(ni) == "Exceptions" and ln >= 2:
            n = struct.unpack_from(">H", attrs_blob, p)[0]
            out = []
            for i in range(n):
                off = p + 2 + i * 2
                if off + 2 > p + ln:
                    break
                idx = struct.unpack_from(">H", attrs_blob, off)[0]
                out.append(cf.class_name(idx).replace("/", ".").replace("$", "."))
            return out
        p += ln
    return []


class _SigParser:
    """Minimal JVMS §4.7.9.1 signature parser (generics, wildcards, type vars)."""

    def __init__(self, s: str):
        self.s = s
        self.i = 0

    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def expect(self, ch: str) -> None:
        if self.peek() != ch:
            raise ValueError(f"signature: expected {ch!r} at {self.i}")
        self.i += 1

    def read_until(self, chars: str) -> str:
        j = self.i
        while j < len(self.s) and self.s[j] not in chars:
            j += 1
        out = self.s[self.i:j]
        self.i = j
        return out

    def type_sig(self) -> str:
        c = self.peek()
        if c in _PRIM_SIG:
            self.i += 1
            return _PRIM_SIG[c]
        if c == "[":
            self.i += 1
            return self.type_sig() + "[]"
        if c == "T":
            self.i += 1
            name = self.read_until(";")
            if self.peek() == ";":
                self.i += 1
            return name or "Object"
        if c == "L":
            return self.class_type()
        raise ValueError(f"signature: unexpected {c!r} at {self.i}")

    def type_args(self) -> str:
        self.expect("<")
        args = []
        while self.peek() not in (">", ""):
            c = self.peek()
            if c == "*":
                self.i += 1
                args.append("?")
            elif c == "+":
                self.i += 1
                args.append("? extends " + self.type_sig())
            elif c == "-":
                self.i += 1
                args.append("? super " + self.type_sig())
            else:
                args.append(self.type_sig())
        self.expect(">")
        return "<" + ", ".join(args) + ">"

    def class_type(self) -> str:
        self.expect("L")
        out = ""
        while True:
            c = self.peek()
            if c == "<":
                out += self.type_args()
            elif c == ".":
                self.i += 1
                out += "."
            elif c == ";":
                self.i += 1
                break
            elif c == "":
                break
            else:
                out += self.read_until("<.;").replace("/", ".").replace("$", ".")
        return out or "Object"


def _parse_type_signature(sig: str) -> str:
    return _SigParser(sig).type_sig()


def _parse_type_parameters(p: _SigParser) -> list[str]:
    tparams: list[str] = []
    if p.peek() != "<":
        return tparams
    p.i += 1
    while p.peek() not in (">", ""):
        name = p.read_until(":")
        p.expect(":")
        bounds: list[str] = []
        if p.peek() != ":":
            bounds.append(p.type_sig())
        while p.peek() == ":":
            p.i += 1
            bounds.append(p.type_sig())
        usable = [b for b in bounds if b and b != "java.lang.Object"]
        if usable:
            tparams.append(f"{name} extends " + " & ".join(usable))
        else:
            tparams.append(name)
    p.expect(">")
    return tparams


def _parse_method_signature(sig: str) -> tuple[list[str], list[str], str, list[str]]:
    p = _SigParser(sig)
    tparams = _parse_type_parameters(p)
    p.expect("(")
    params: list[str] = []
    while p.peek() not in (")", ""):
        params.append(p.type_sig())
    p.expect(")")
    ret = p.type_sig()
    throws: list[str] = []
    while p.peek() == "^":
        p.i += 1
        throws.append(p.type_sig())
    return tparams, params, ret, throws


def _parse_class_signature(sig: str) -> tuple[list[str], str | None, list[str]]:
    p = _SigParser(sig)
    tparams = _parse_type_parameters(p)
    sup = None
    if p.peek() == "L":
        sup = p.class_type()
    ifaces: list[str] = []
    while p.peek() == "L":
        ifaces.append(p.class_type())
    return tparams, sup, ifaces


def _unresolved_type_vars(types: list[str], declared: set[str]) -> bool:
    """True when a signature references a type variable the class never declared.

    Obfuscators sometimes keep a method Signature while dropping the class-level
    one; emitting `T` (including inside `List<T>`) in that case produces
    uncompilable source, so the caller must fall back to the erased descriptor.
    """
    for t in types:
        for tok in re.findall(r"\b[A-Z][A-Z0-9]?\b", t):
            if tok not in declared:
                return True
    return False


class IntermediaryGrounding:
    """Grounds Minecraft intermediary symbol generation against an actual client-intermediary.jar.

    Prevents synthetic hallucination of RT_* classes and mismatched method signatures.
    Reads true class kinds (interface, enum, record, class), real constructors, method
    descriptors, and field definitions directly from the game's intermediary jar.
    """

    def __init__(self, intermediary_jar: Path | str | None = None):
        self.jar_path = Path(intermediary_jar) if intermediary_jar else None
        self._classes: dict[str, CF.ClassFile] = {}
        self._namelist: set[str] = set()
        if self.jar_path and self.jar_path.is_file():
            self._load_index()

    def _load_index(self) -> None:
        try:
            with zipfile.ZipFile(self.jar_path, "r") as z:
                for name in z.namelist():
                    if name.endswith(".class") and not name.startswith("META-INF/"):
                        cls_name = name[:-6].replace("\\", "/")
                        self._namelist.add(cls_name)
        except Exception:
            pass

    def is_available(self) -> bool:
        return bool(self._namelist)

    def has_class(self, slash_or_dotted: str) -> bool:
        norm = slash_or_dotted.replace(".", "/").strip("/")
        return norm in self._namelist

    def get_classfile(self, slash_or_dotted: str) -> CF.ClassFile | None:
        norm = slash_or_dotted.replace(".", "/").strip("/")
        if norm not in self._namelist or not self.jar_path:
            return None
        if norm in self._classes:
            return self._classes[norm]
        try:
            with zipfile.ZipFile(self.jar_path, "r") as z:
                data = z.read(f"{norm}.class")
                cf = CF.parse(data)
                self._classes[norm] = cf
                return cf
        except Exception:
            return None

    def get_class_kind(self, slash_or_dotted: str) -> str:
        """Return 'interface', 'enum', 'record', or 'class'."""
        cf = self.get_classfile(slash_or_dotted)
        if not cf:
            return "class"
        flags = cf.access_flags
        if flags & 0x0200:
            return "interface"
        if flags & 0x4000:
            return "enum"
        if (cf.super_name or "") == "java/lang/Record":
            return "record"
        return "class"

    def _dollar_to_dot(self, tok: str) -> str:
        """`vr$a` -> `vr.a` when `vr` is a class in the jar (nested class).

        A `$` that is part of a genuine top-level name is left alone.
        """
        parts = tok.split(".")
        for i, seg in enumerate(parts):
            if "$" not in seg:
                continue
            head = seg.split("$", 1)[0]
            outer = "/".join(parts[:i] + [head])
            if outer in self._namelist:
                parts[i] = seg.replace("$", ".")
                return ".".join(parts)
            return tok
        return tok

    def _source_types(self, text: str) -> str:
        """Rewrite binary nested-class names to source form inside a type string."""
        if not text or "$" not in text:
            return text
        return re.sub(r"[A-Za-z_$][A-Za-z0-9_$.]*", lambda m: self._dollar_to_dot(m.group(0)), text)

    def generate_grounded_stub(self, slash_or_dotted: str) -> str | None:
        """Generate Java source for a class read from the real intermediary jar.

        The stub reproduces the type's kind, hierarchy, fields and method
        signatures with safe default bodies so surrounding decompiled code
        compiles. It does not reproduce behaviour.

        Shapes that javac would reject are normalised:
          * enum  -> `enum E { ; ... }` (constants are not reconstructed)
          * record -> a plain final class (component metadata is not rebuilt)
          * interface static/default methods get bodies; abstract ones end in `;`
        """
        from . import stubs as SB

        cf = self.get_classfile(slash_or_dotted)
        if not cf:
            return None

        fqcn = cf.name.replace("/", ".")
        pkg = fqcn.rsplit(".", 1)[0] if "." in fqcn else ""
        simple_name = fqcn.rsplit(".", 1)[-1]

        # Nested / anonymous / local classes (Outer$Inner, Outer$1) cannot be
        # reproduced as a top-level source file: the name would not resolve and
        # enum-constant bodies cannot be extended. Refuse rather than emit
        # something javac will reject.
        if "$" in simple_name:
            return None

        kind = self.get_class_kind(slash_or_dotted)
        is_interface = kind == "interface"
        # ACC_ENUM is also set on anonymous enum-constant bodies; only a class
        # whose superclass is java.lang.Enum is a real enum declaration.
        is_enum = kind == "enum" and (cf.super_name or "") == "java/lang/Enum"
        is_record = kind == "record"
        decl_kind = "class" if (is_record or (kind == "enum" and not is_enum)) else kind

        super_cls = cf.super_name
        if super_cls:
            super_cls = self._source_types(super_cls.replace("/", "."))
        if super_cls in ("java.lang.Object", "java.lang.Record", "java.lang.Enum"):
            super_cls = None

        interfaces = [self._source_types(i.replace("/", ".")) for i in cf.interface_names]

        # Class-level Signature carries generic type parameters and generic
        # supertypes; descriptors alone erase them.
        type_params: list[str] = []
        class_sig = _attr_text(cf, cf.attrs_blob, "Signature")
        if class_sig:
            try:
                type_params, sig_sup, sig_ifaces = _parse_class_signature(class_sig)
                if (sig_sup and decl_kind == "class"
                        and sig_sup not in ("java.lang.Object", "java.lang.Record", "java.lang.Enum")):
                    super_cls = sig_sup
                if sig_ifaces and not is_enum:
                    interfaces = [self._source_types(i) for i in sig_ifaces]
            except ValueError:
                type_params = []
        declared_tvars = {tp.split(" ", 1)[0].split("<", 1)[0] for tp in type_params}

        header = ["public"]
        if cf.access_flags & 0x0400 and decl_kind == "class":
            header.append("abstract")
        if is_record:
            header.append("final")
        header.append(decl_kind)
        header.append(simple_name + (f"<{', '.join(type_params)}>" if type_params else ""))
        if is_interface:
            if interfaces:
                header.append("extends " + ", ".join(interfaces))
        else:
            if super_cls:
                header.append("extends " + super_cls)
            if interfaces:
                header.append("implements " + ", ".join(interfaces))

        lines = []
        if pkg:
            lines.append(f"package {pkg};")
            lines.append("")
        lines.append(SB.STUB_MARKER)
        lines.append(" ".join(header) + " {")
        if is_enum:
            # no constants reconstructed: an explicit ';' opens the member list
            lines.append("    ;")

        for f in cf.fields:
            if f.is_synthetic or (f.access_flags & 0x4000):   # ACC_ENUM constants
                continue
            f_name = cf.utf8(f.name_index)
            f_type = _parse_single_type(cf.utf8(f.descriptor_index))
            f_sig = _attr_text(cf, f.attrs_blob, "Signature")
            if f_sig:
                try:
                    sig_type = _parse_type_signature(f_sig)
                    if not _unresolved_type_vars([sig_type], declared_tvars):
                        f_type = sig_type
                except ValueError:
                    pass
            f_type = self._source_types(f_type)
            if is_interface:
                # interface fields are implicitly public static final and must
                # be initialised in the declaration
                init = SB.default_primitive_return(f_type)
                lines.append(f"    public static final {f_type} {f_name} = {init};")
            else:
                mods = "public" + (" static" if f.access_flags & 0x0008 else "")
                lines.append(f"    {mods} {f_type} {f_name};")

        is_abstract = bool(cf.access_flags & 0x0400)
        ctor_mod = "protected" if is_abstract else "public"
        ctors = [(m, cf.utf8(m.descriptor_index)) for m in cf.methods
                 if cf.utf8(m.name_index) == "<init>" and not m.is_synthetic]
        if not is_interface and not is_enum:
            if not ctors:
                lines.append(f"    {ctor_mod} {simple_name}() {{}}")
            else:
                for c_m, c_desc in ctors:
                    p_types, _r = _parse_jvm_descriptor(c_desc)
                    c_sig = _attr_text(cf, c_m.attrs_blob, "Signature")
                    if c_sig:
                        try:
                            _tp, s_params, _r, _t = _parse_method_signature(c_sig)
                            if not _unresolved_type_vars(s_params, declared_tvars):
                                p_types = s_params
                        except ValueError:
                            pass
                    p_types = [self._source_types(t) for t in p_types]
                    params = ", ".join(f"{t} p{i}" for i, t in enumerate(p_types))
                    c_throws = _attr_exceptions(cf, c_m.attrs_blob)
                    c_throws_part = f" throws {', '.join(c_throws)}" if c_throws else ""
                    lines.append(f"    {ctor_mod} {simple_name}({params}){c_throws_part} {{}}")

        for m in cf.methods:
            if m.is_synthetic:
                continue
            m_name = cf.utf8(m.name_index)
            if m_name in ("<init>", "<clinit>"):
                continue
            if is_enum and m_name in ("values", "valueOf"):
                continue
            m_desc = cf.utf8(m.descriptor_index)
            p_types, r_type = _parse_jvm_descriptor(m_desc)
            throws: list[str] = []
            m_tparams: list[str] = []
            m_sig = _attr_text(cf, m.attrs_blob, "Signature")
            if m_sig:
                try:
                    s_tp, s_params, s_ret, s_throws = _parse_method_signature(m_sig)
                    visible = declared_tvars | {t.split(" ", 1)[0] for t in s_tp}
                    if not _unresolved_type_vars(s_params + [s_ret] + s_throws, visible):
                        m_tparams, p_types, r_type, throws = s_tp, s_params, s_ret, s_throws
                except ValueError:
                    pass
            if not throws:
                throws = _attr_exceptions(cf, m.attrs_blob)
            p_types = [self._source_types(t) for t in p_types]
            r_type = self._source_types(r_type)
            throws = [self._source_types(t) for t in throws]
            params = ", ".join(f"{t} p{i}" for i, t in enumerate(p_types))
            ret = SB.default_primitive_return(r_type)
            throws_part = f" throws {', '.join(throws)}" if throws else ""
            tparams_part = f"<{', '.join(m_tparams)}> " if m_tparams else ""

            mods = ["public"]
            if m.access_flags & 0x0008:
                mods.append("static")
            elif is_interface and not (m.access_flags & 0x0400) and not (m.access_flags & 0x0100):
                # a body in an interface is only legal for static/default/private
                mods.append("default")
            if m.access_flags & 0x0400:
                mods.append("abstract")
            if m.access_flags & 0x0100:
                mods.append("native")
            mod = " ".join(mods)

            bodyless = (m.access_flags & 0x0100) or (
                is_interface and (m.access_flags & 0x0400) and not (m.access_flags & 0x0008))
            if bodyless:
                lines.append(f"    {mod} {tparams_part}{r_type} {m_name}({params}){throws_part};")
            else:
                ret_stmt = f" return {ret};" if r_type != "void" else ""
                lines.append(f"    {mod} {tparams_part}{r_type} {m_name}({params}){throws_part} {{{ret_stmt} }}")

        lines.append("}")
        lines.append("")
        return "\n".join(lines)


# --------------------------------------------------------------------------
# Event Pipeline Detector & Weaver: Minecraft Cheat Client Event Bus / Keybind
# --------------------------------------------------------------------------

@dataclass
class EventPipelineInfo:
    keyboard_mixin: str | None = None
    keyboard_target: str | None = None
    event_bus_call: str | None = None
    bus_receiver: str | None = None
    key_event_class: str | None = None
    network_mixin: str | None = None
    chat_event_class: str | None = None
    detected_keycodes: list[int] = field(default_factory=list)

    def summary(self) -> str:
        parts = []
        if self.keyboard_mixin:
            parts.append(f"keyboard_mixin={self.keyboard_mixin}")
        if self.event_bus_call:
            parts.append(f"bus_call={self.event_bus_call}")
        if self.key_event_class:
            parts.append(f"key_event={self.key_event_class}")
        if self.chat_event_class:
            parts.append(f"chat_event={self.chat_event_class}")
        return ", ".join(parts) or "no event pipeline detected"


# Mixin targets that carry a keyboard / network pipeline. The class_* ids are
# Minecraft intermediary names and are version-specific, so callers can override
# both sets; nothing is matched by bare substring against the whole file.
MC_KEYBOARD_TARGETS = frozenset({"Keyboard", "class_309"})
MC_NETWORK_TARGETS = frozenset({
    "ClientPlayNetworkHandler", "ClientPacketListener", "class_634",
})

_MIXIN_TARGET_RE = re.compile(r"@Mixin\s*\(([^)]*)\)")


def _mixin_targets(txt: str) -> set[str]:
    """Collect simple names from a file's @Mixin(...) target list."""
    out: set[str] = set()
    for m in _MIXIN_TARGET_RE.finditer(txt):
        for raw in m.group(1).split(","):
            tok = raw.strip().strip('"')
            if not tok:
                continue
            tok = re.sub(r"\.class$", "", tok).strip()
            if "=" in tok:                      # value = X.class
                tok = tok.split("=", 1)[1].strip()
            out.add(tok.rsplit(".", 1)[-1].strip('"'))
    return out


def detect_event_pipelines(
    src_dir: Path | str,
    keyboard_targets: set[str] | frozenset[str] | None = None,
    network_targets: set[str] | frozenset[str] | None = None,
) -> EventPipelineInfo:
    """Scan decompiled sources for an event-bus publish pipeline.

    Detection is read-only: it reports what it found and never edits sources.
    """
    src_path = Path(src_dir)
    info = EventPipelineInfo()
    if not src_path.is_dir():
        return info

    kb_targets = set(keyboard_targets if keyboard_targets is not None else MC_KEYBOARD_TARGETS)
    net_targets = set(network_targets if network_targets is not None else MC_NETWORK_TARGETS)
    m_post = re.compile(
        r"([\w$.]+)\.(?:post|publish|dispatch|call)\s*\(\s*(?:new\s+([\w$.]+)|([A-Za-z0-9_$]+))")

    for j_file in sorted(src_path.rglob("*.java")):
        txt = j_file.read_text(encoding="utf-8", errors="replace")
        targets = _mixin_targets(txt)
        if not targets:
            continue

        if targets & kb_targets:
            info.keyboard_mixin = j_file.stem
            info.keyboard_target = next(t for t in sorted(targets) if t in kb_targets)
            m = m_post.search(txt)
            if m:
                info.bus_receiver = m.group(1)
                info.event_bus_call = m.group(0)
                info.key_event_class = m.group(2) or m.group(3)
        elif targets & net_targets:
            info.network_mixin = j_file.stem
            m = m_post.search(txt)
            if m:
                info.chat_event_class = m.group(2) or m.group(3)

    return info
