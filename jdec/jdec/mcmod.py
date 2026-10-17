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

    def generate_grounded_stub(self, slash_or_dotted: str) -> str | None:
        """Generate high-fidelity Java source for a Minecraft intermediary class."""
        from . import stubs as SB

        cf = self.get_classfile(slash_or_dotted)
        if not cf:
            return None

        fqcn = cf.name.replace("/", ".")
        pkg = fqcn.rsplit(".", 1)[0] if "." in fqcn else ""
        simple_name = fqcn.rsplit(".", 1)[-1]

        kind = self.get_class_kind(slash_or_dotted)
        super_cls = cf.super_name
        if super_cls:
            super_cls = super_cls.replace("/", ".")
        if super_cls in ("java.lang.Object", "java.lang.Record", "java.lang.Enum"):
            super_cls = None

        interfaces = [i.replace("/", ".") for i in cf.interface_names]

        header_parts = ["public"]
        if cf.access_flags & 0x0400 and kind == "class":
            header_parts.append("abstract")
        header_parts.append(kind)
        header_parts.append(simple_name)

        if kind == "interface":
            if interfaces:
                header_parts.append("extends " + ", ".join(interfaces))
        else:
            if super_cls:
                header_parts.append(f"extends {super_cls}")
            if interfaces:
                header_parts.append("implements " + ", ".join(interfaces))

        lines = []
        if pkg:
            lines.append(f"package {pkg};\n")
        lines.append(" ".join(header_parts) + " {")

        # Fields
        for f_name, f_desc in cf.field_sigs(include_synthetic=False):
            f_type = _parse_single_type(f_desc)
            lines.append(f"    public static Object {f_name};" if "$" in f_name else f"    public {f_type} {f_name};")

        # Constructors
        ctors = [desc for name, desc in cf.method_sigs() if name == "<init>"]
        if kind == "class":
            if not ctors:
                lines.append(f"    public {simple_name}() {{}}")
            else:
                for c_idx, c_desc in enumerate(ctors):
                    p_types, _ = _parse_jvm_descriptor(c_desc)
                    params = ", ".join(f"{t} p{i}" for i, t in enumerate(p_types))
                    lines.append(f"    public {simple_name}({params}) {{}}")

        # Methods
        for m_name, m_desc in cf.method_sigs(include_synthetic=False):
            if m_name in ("<init>", "<clinit>"):
                continue
            p_types, r_type = _parse_jvm_descriptor(m_desc)
            params = ", ".join(f"{t} p{i}" for i, t in enumerate(p_types))
            ret_val = SB.default_primitive_return(r_type)

            if kind == "interface":
                lines.append(f"    {r_type} {m_name}({params});")
            else:
                ret_stmt = f" return {ret_val};" if r_type != "void" else ""
                lines.append(f"    public {r_type} {m_name}({params}) {{{ret_stmt} }}")

        lines.append("}\n")
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


def detect_event_pipelines(src_dir: Path | str) -> EventPipelineInfo:
    """Scan decompiled sources for Minecraft client EventBus and Keybind pipelines."""
    src_path = Path(src_dir)
    info = EventPipelineInfo()
    if not src_path.is_dir():
        return info

    for j_file in src_path.rglob("*.java"):
        txt = j_file.read_text(encoding="utf-8", errors="replace")
        if ("class_309" in txt or "Keyboard" in txt) and "@Mixin" in txt:
            info.keyboard_mixin = j_file.stem
            info.keyboard_target = "net.minecraft.client.Keyboard"
            m_post = re.search(r"([\w$.]+)\.(?:post|publish|dispatch|call)\s*\(\s*(?:new\s+([\w$.]+)|([A-Za-z0-9_$]+))", txt)
            if m_post:
                info.bus_receiver = m_post.group(1)
                info.event_bus_call = m_post.group(0)
                event_cls = m_post.group(2) or m_post.group(3)
                if event_cls:
                    info.key_event_class = event_cls

        if ("class_634" in txt or "ClientPlayNetworkHandler" in txt) and "@Mixin" in txt:
            info.network_mixin = j_file.stem
            m_chat = re.search(r"([\w$.]+)\.(?:post|publish|dispatch|call)\s*\(\s*(?:new\s+([\w$.]+)|([A-Za-z0-9_$]+))", txt)
            if m_chat:
                event_cls = m_chat.group(2) or m_chat.group(3)
                if event_cls:
                    info.chat_event_class = event_cls

    return info


def weave_event_dispatcher_hook(
    src_dir: Path | str,
    pipeline: EventPipelineInfo,
    default_keys: list[int] | None = None,
) -> bool:
    """Weave an in-line keybind interceptor into the detected keyboard mixin."""
    if not pipeline.keyboard_mixin:
        return False
    keys = default_keys or [344, 96, 89, 260]  # Right Shift, Grave (`~`), Y, Insert
    src_path = Path(src_dir)
    target_files = list(src_path.rglob(f"{pipeline.keyboard_mixin}.java"))
    if not target_files:
        return False
    kb_file = target_files[0]
    content = kb_file.read_text(encoding="utf-8", errors="replace")
    if "[jdec: event dispatcher hook]" in content:
        return False

    m_meth = re.search(r"(?:public|private|protected)\s+void\s+(\w+)\s*\([^)]*int\s+([A-Za-z0-9_$]+)[^)]*\)\s*\{", content)
    if not m_meth:
        return False

    key_param = m_meth.group(2)
    hook_code = f"""
        // [jdec: event dispatcher hook] Intercept common client UI hotkeys
        if ({key_param} == {keys[0]} || {key_param} == {keys[1]} || {key_param} == {keys[2]} || {key_param} == {keys[3]}) {{
            // Auto-dispatched keybind event for client ClickGUI
        }}
"""
    insert_pos = m_meth.end()
    new_content = content[:insert_pos] + hook_code + content[insert_pos:]
    kb_file.write_text(new_content, encoding="utf-8")
    return True
