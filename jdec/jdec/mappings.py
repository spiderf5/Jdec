"""Minecraft deobfuscation: obtain mappings and apply them to bytecode.

Supported mapping formats
  * proguard  - Mojang's client.txt (direction is `named -> obf`, we invert it)
  * tiny v2   - Fabric intermediary / yarn (header lists namespaces)
  * tsrg      - legacy MCP, used by Forge for 1.7-1.12 era jars

Applying a mapping rewrites the constant pool in place. Two things make this
delicate and are handled explicitly:
  * member renames must be applied at every *call site* too (Fieldref /
    Methodref -> NameAndType), not just at the declaration, or the bytecode
    stops resolving
  * all lookups are decided against the *original* names before any write,
    because class renames would otherwise corrupt later lookups
"""

from __future__ import annotations

import io
import json
import re
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import classfile as CF
from .classfile import (
    C_CLASS, C_NAME_AND_TYPE, C_FIELDREF, C_METHODREF, C_INTERFACE_METHODREF, C_UTF8,
)

MOJANG_MANIFEST = "https://piston-meta.mojang.com/mc/game/version_manifest.json"
FABRIC_MAVEN = "https://maven.fabricmc.net"
FORGE_MAVEN = "https://maven.minecraftforge.net"


# --------------------------------------------------------------------------
# model
# --------------------------------------------------------------------------

@dataclass
class Mapping:
    classes: dict[str, str] = field(default_factory=dict)   # internal obf -> new internal
    members: dict[str, dict[tuple[str, str | None], str]] = field(default_factory=dict)
    source: str = ""
    params: dict[str, dict[str, str]] = field(default_factory=dict)

    def add_class(self, obf: str, new: str) -> None:
        if obf and new and obf != new:
            self.classes[obf] = new

    def add_member(self, owner: str, name: str, desc: str | None, new: str) -> None:
        if not new or new == name:
            return
        self.members.setdefault(owner, {})[(name, desc)] = new
        # also index without descriptor so desc-less formats can still hit
        self.members[owner].setdefault((name, None), new)

    def lookup_class(self, obf: str) -> str | None:
        return self.classes.get(obf)

    def lookup_member(self, owner: str, name: str, desc: str) -> str | None:
        m = self.members.get(owner)
        if not m:
            return None
        v = m.get((name, desc))
        if v is None:
            v = m.get((name, None))
        return v

    def __len__(self) -> int:
        return len(self.classes) + sum(len(v) // 2 for v in self.members.values())

    def describe(self) -> str:
        members = sum(len(v) // 2 for v in self.members.values())
        return f"{len(self.classes)} classes, {members} members ({self.source})"


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------

_PRIM = {"void": "V", "int": "I", "boolean": "Z", "byte": "B", "char": "C",
         "short": "S", "long": "J", "float": "F", "double": "D"}

_CLASS_LINE = re.compile(r"^(?P<named>[\w$.]+)\s*->\s*(?P<obf>[\w$]+):\s*$")
_METHOD_LINE = re.compile(
    r"^(?:(?P<s>\d+):(?P<e>\d+):)?\s*(?P<ret>[\w$.\[\]]+)\s+"
    r"(?P<name><init>|<clinit>|[\w$]+)\s*(?:\((?P<args>[^)]*)\))?\s*->\s*(?P<obf>\S+)\s*$")
_FIELD_LINE = re.compile(r"^(?P<type>[\w$.\[\]]+)\s+(?P<name>[\w$]+)\s*->\s*(?P<obf>\S+)\s*$")


def _type_to_desc(t: str) -> str:
    t = t.strip()
    arrays = 0
    while t.endswith("[]"):
        arrays += 1
        t = t[:-2]
    base = _PRIM.get(t)
    if base is None:
        base = "L" + t.replace(".", "/") + ";"
    return "[" * arrays + base


def parse_proguard(text: str, source: str = "proguard", invert: bool = True) -> Mapping:
    """Parse ProGuard/Mojang mapping text.

    Mojang ships `named -> obf`; for remapping an obfuscated jar we need
    `obf -> named`, hence invert=True by default.
    """
    m = Mapping(source=source)
    cur_named: str | None = None
    cur_obf: str | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith(" "):
            mc = _CLASS_LINE.match(line)
            if mc:
                cur_named = mc.group("named").replace(".", "/")
                cur_obf = mc.group("obf")
                if invert:
                    m.add_class(cur_obf, cur_named)
                else:
                    m.add_class(cur_named, cur_obf)
                continue
            cur_named = cur_obf = None
            continue
        if cur_obf is None or cur_named is None:
            continue
        body = line.strip()
        mm = _METHOD_LINE.match(body)
        if mm and (mm.group("args") is not None or mm.group("s")):
            ret = _type_to_desc(mm.group("ret"))
            args = mm.group("args") or ""
            desc = "(" + "".join(_type_to_desc(a) for a in args.split(",") if a.strip()) + ")" + ret
            name, obf = mm.group("name"), mm.group("obf")
            if obf == "<init>" or name == "<init>":
                continue
            if invert:
                m.add_member(cur_obf, obf, desc, name)
            else:
                m.add_member(cur_obf, name, desc, obf)
            continue
        mf = _FIELD_LINE.match(body)
        if mf:
            name, obf = mf.group("name"), mf.group("obf")
            if invert:
                m.add_member(cur_obf, obf, None, name)
            else:
                m.add_member(cur_obf, name, None, obf)
    return m


def parse_tiny(text: str, source: str = "tiny",
               from_ns: str | None = None, to_ns: str | None = None) -> Mapping:
    lines = text.splitlines()
    if not lines or not lines[0].startswith("tiny"):
        raise ValueError("not a tiny mapping file")
    header = lines[0].split("\t")
    namespaces = header[3:]
    m = Mapping(source=source)
    if from_ns is None:
        from_ns = namespaces[0]
    if to_ns is None:
        to_ns = namespaces[-1]
    if from_ns not in namespaces or to_ns not in namespaces:
        raise ValueError(f"namespaces {namespaces} lack {from_ns}/{to_ns}")
    a, b = namespaces.index(from_ns), namespaces.index(to_ns)

    cur_obf: str | None = None
    cur_new: str | None = None
    for line in lines[1:]:
        if not line.strip():
            continue
        # member rows are indented with a leading tab, so after splitting the
        # marker ("c" / "f" / "m") is only at parts[0] once empties are dropped
        parts = line.split("\t")
        k = 0
        while k < len(parts) and parts[k] == "":
            k += 1
        parts = parts[k:]
        if not parts:
            continue
        kind = parts[0]
        if kind == "c":
            vals = parts[1:]
            if max(a, b) >= len(vals):
                continue
            cur_obf, cur_new = vals[a], vals[b]
            m.add_class(cur_obf, cur_new)
        elif kind in ("f", "m"):
            desc = parts[1] if len(parts) > 1 else None
            vals = parts[2:]
            if max(a, b) >= len(vals) or cur_obf is None:
                continue
            name, new = vals[a], vals[b]
            if kind == "m":
                m.add_member(cur_obf, name, desc, new)
            else:
                m.add_member(cur_obf, name, None, new)
    return m


def parse_tsrg(text: str, source: str = "tsrg") -> Mapping:
    m = Mapping(source=source)
    cur_obf: str | None = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line.startswith("\t"):
            bits = line.split()
            if len(bits) >= 2:
                cur_obf = bits[0]
                m.add_class(bits[0], bits[1])
            continue
        bits = line.strip().split()
        if cur_obf is None:
            continue
        if len(bits) == 2:
            m.add_member(cur_obf, bits[0], None, bits[1])
        elif len(bits) >= 3:
            m.add_member(cur_obf, bits[0], bits[1], bits[2])
    return m


def load_mapping(path: Path, from_ns: str | None = None, to_ns: str | None = None,
                 invert: bool = True) -> Mapping:
    text = path.read_text("utf-8", "replace")
    if text.startswith("tiny") or "\ttiny\t" in text[:80]:
        return parse_tiny(text, source=path.name, from_ns=from_ns, to_ns=to_ns)
    head = text.lstrip().splitlines()[0] if text.strip() else ""
    if "->" in head or re.search(r"^\s+\d+:\d+:", text, re.M) or " -> " in text[:4000]:
        return parse_proguard(text, source=path.name, invert=invert)
    return parse_tsrg(text, source=path.name)


# --------------------------------------------------------------------------
# applying
# --------------------------------------------------------------------------

_TYPE_REF_RE = re.compile(r"L([A-Za-z0-9_$]+(?:/[A-Za-z0-9_$]+)*);")


def remap_class_bytes(data: bytes, mapping: Mapping) -> tuple[bytes | None, str | None, int]:
    """Remap one class. Returns (new bytes or None, new internal name, edits)."""
    cf = CF.parse(data)
    n = remap_class(cf, mapping)
    if n == 0:
        return None, cf.name, 0
    return cf.serialize(), cf.name, n


def remap_class(cf, mapping: Mapping) -> int:
    """Rewrite cf in place using `mapping`. Returns the number of edits."""
    if not mapping.classes and not mapping.members:
        return 0
    cp = cf.cp
    this_obf = cf.name
    changes = 0

    # ---- pass 1: decide everything against original names -----------------
    class_targets: list[tuple[int, str]] = []          # cp index -> new internal name
    nt_targets: list[tuple[int, int, str]] = []        # ref cp idx, nt idx, new name
    decl_targets: list[tuple[object, str]] = []        # Member -> new name

    for i in range(1, len(cp)):
        e = cp[i]
        if not e:
            continue
        tag = e[0]
        if tag == C_CLASS:
            old = cf.utf8(e[1][0])
            new = mapping.lookup_class(old)
            if new and new != old:
                class_targets.append((i, new))
        elif tag in (C_FIELDREF, C_METHODREF, C_INTERFACE_METHODREF):
            owner_idx = cp[e[1][0]]
            if not owner_idx or owner_idx[0] != C_CLASS:
                continue
            owner = cf.utf8(owner_idx[1][0])
            nt_idx = e[1][1]
            nt = cp[nt_idx]
            if not nt or nt[0] != C_NAME_AND_TYPE:
                continue
            name = cf.utf8(nt[1][0])
            desc = cf.utf8(nt[1][1])
            new = mapping.lookup_member(owner, name, desc)
            if new and new != name:
                nt_targets.append((i, nt_idx, new))

    for m in list(cf.methods) + list(cf.fields):
        name = cf.utf8(m.name_index)
        desc = cf.utf8(m.descriptor_index)
        new = mapping.lookup_member(this_obf, name, desc)
        if new and new != name:
            decl_targets.append((m, new))

    if not (class_targets or nt_targets or decl_targets) and not mapping.classes:
        return 0

    # ---- pass 2: rewrite type references inside every Utf8 ---------------
    classes = mapping.classes
    if classes:
        for i in range(1, len(cp)):
            e = cp[i]
            if not e or e[0] != C_UTF8:
                continue
            try:
                s = e[1].decode("utf-8", "replace")
            except Exception:
                continue
            if "L" not in s:
                continue
            hit = False

            def sub(mx: re.Match) -> str:
                nonlocal hit
                rep = classes.get(mx.group(1))
                if rep:
                    hit = True
                    return "L" + rep + ";"
                return mx.group(0)

            new_s = _TYPE_REF_RE.sub(sub, s)
            if hit:
                cp[i] = (C_UTF8, new_s.encode("utf-8"))
                cf._utf8_cache.pop(s, None)
                changes += 1

    # ---- pass 3: class entries -------------------------------------------
    cache: dict[str, int] = {}
    for i, new in class_targets:
        idx = cache.get(new)
        if idx is None:
            idx = cf.intern_utf8(new)
            cache[new] = idx
        cp[i] = (C_CLASS, [idx])
        changes += 1

    # ---- pass 4: member references (fresh NameAndType per rename) --------
    nt_cache: dict[tuple[str, int], int] = {}
    for ref_idx, nt_idx, new_name in nt_targets:
        nt = cp[nt_idx]
        desc_idx = nt[1][1]
        key = (new_name, desc_idx)
        n_idx = nt_cache.get(key)
        if n_idx is None:
            name_idx = cf.intern_utf8(new_name)
            cp.append((C_NAME_AND_TYPE, [name_idx, desc_idx]))
            n_idx = len(cp) - 1
            nt_cache[key] = n_idx
        tag = cp[ref_idx][0]
        cp[ref_idx] = (tag, [cp[ref_idx][1][0], n_idx])
        changes += 1

    # ---- pass 5: declarations --------------------------------------------
    for m, new in decl_targets:
        m.name_index = cf.intern_utf8(new)
        changes += 1

    return changes


def remap_jar(src: Path, dest: Path, mapping: Mapping,
              progress=None) -> tuple[int, int]:
    """Write a remapped copy of `src`. Returns (classes changed, classes total).

    Entries are written under their *new* internal name. Renaming only the
    bytes would leave a jar whose class names disagree with their paths, which
    no JVM or decompiler will load correctly.
    """
    changed = total = 0
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zout:
        for name in zin.namelist():
            data = zin.read(name)
            out_name = name
            if name.endswith(".class"):
                total += 1
                try:
                    new, new_name, n = remap_class_bytes(data, mapping)
                    if new is not None:
                        data = new
                        changed += 1
                    if new_name:
                        out_name = new_name + ".class"
                except Exception:
                    pass
                if progress and total % 1000 == 0:
                    progress(total, changed)
            try:
                zout.writestr(out_name, data)
            except Exception:
                zout.writestr(name, data)
    return changed, total


# --------------------------------------------------------------------------
# fetching
# --------------------------------------------------------------------------

def _get(url: str, timeout: int = 180) -> bytes:
    # some maven hosts (Forge) reject requests without a User-Agent
    req = urllib.request.Request(url, headers={"User-Agent": "jdec/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _get_json(url: str) -> dict:
    return json.loads(_get(url).decode("utf-8", "replace"))


def mc_version_url(version: str) -> str | None:
    manifest = _get_json(MOJANG_MANIFEST)
    for v in manifest["versions"]:
        if v["id"] == version:
            return v["url"]
    return None


def fetch_mojang_mappings(version: str, cache: Path) -> Mapping:
    """Download Mojang's official obfuscation map (released 1.14+)."""
    cache.mkdir(parents=True, exist_ok=True)
    cached = cache / f"mojang_{version}.txt"
    if not cached.exists():
        vurl = mc_version_url(version)
        if not vurl:
            raise RuntimeError(f"version '{version}' not found in Mojang manifest")
        vj = _get_json(vurl)
        cm = vj.get("downloads", {}).get("client_mappings")
        if not cm:
            raise RuntimeError(
                f"no client_mappings for {version} "
                "(Minecraft 26.1+ ships unobfuscated, so no mappings exist)")
        cached.write_bytes(_get(cm["url"]))
    return parse_proguard(cached.read_text("utf-8", "replace"),
                          source=f"mojang/{version}", invert=True)


def _latest_matching(meta_xml: str, prefix: str) -> str | None:
    vers = re.findall(r"<version>([^<]+)</version>", meta_xml)
    hits = [v for v in vers if v.startswith(prefix)]
    if not hits:
        return None
    def key(v: str):
        m = re.search(r"build\.(\d+)", v)
        return int(m.group(1)) if m else 0
    return sorted(hits, key=key)[-1]


def compose_yarn(inter: Mapping, yarn: Mapping, source: str) -> Mapping:
    """Compose obf -> intermediary -> named, keeping every namespace findable.

    Fabric mods ship in the intermediary namespace, so their mixin
    annotations reference `net.minecraft.class_310` / `method_1234` — names
    present in neither the official-name keys of the composed map nor any
    Mojang mapping; the same translations are therefore indexed a second
    time under the intermediary names. The Yarn member name is looked up
    under the *intermediary* owner: passing the official owner here would
    silently degrade every member value to its intermediary name.
    """
    i2n = yarn.classes
    out = Mapping(source=source)
    for obf, mid in inter.classes.items():
        out.add_class(obf, i2n.get(mid, mid))
    for owner, members in inter.members.items():
        mid_owner = inter.classes.get(owner, owner)
        for (name, desc), mid in members.items():
            if desc is None:
                continue
            final = yarn.lookup_member(mid_owner, mid, desc) or mid
            out.add_member(owner, name, desc, final)
            out.add_member(mid_owner, mid, desc, final)
    for obf, mid in inter.classes.items():
        out.add_class(mid, i2n.get(mid, mid))
    return out


def fetch_yarn_mappings(version: str, cache: Path) -> Mapping:
    """Fabric intermediary (obf -> class_NNNN) overlaid with Yarn names."""
    cache.mkdir(parents=True, exist_ok=True)
    inter_path = cache / f"intermediary_{version}.jar"
    if not inter_path.exists():
        url = f"{FABRIC_MAVEN}/net/fabricmc/intermediary/{version}/intermediary-{version}-v2.jar"
        try:
            inter_path.write_bytes(_get(url))
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"no Fabric intermediary for {version}: {exc}") from None

    with zipfile.ZipFile(inter_path) as z:
        tiny = z.read("mappings/mappings.tiny").decode("utf-8", "replace")
    namespaces = tiny.split("\t")[3:]
    inter = parse_tiny(tiny, source=f"intermediary/{version}",
                       from_ns="obf" if "obf" in namespaces else "official",
                       to_ns="intermediary")

    yarn_meta = _get(f"{FABRIC_MAVEN}/net/fabricmc/yarn/maven-metadata.xml").decode("utf-8", "replace")
    yarn_ver = _latest_matching(yarn_meta, version + "+build.")
    if not yarn_ver:
        return inter
    yarn_path = cache / f"yarn_{yarn_ver}.jar"
    if not yarn_path.exists():
        q = yarn_ver.replace("+", "%2B")
        url = f"{FABRIC_MAVEN}/net/fabricmc/yarn/{q}/yarn-{q}-v2.jar"
        yarn_path.write_bytes(_get(url))
    with zipfile.ZipFile(yarn_path) as z:
        ytiny = z.read("mappings/mappings.tiny").decode("utf-8", "replace")
    yarn = parse_tiny(ytiny, source=f"yarn/{yarn_ver}",
                      from_ns="intermediary", to_ns="named")

    return compose_yarn(inter, yarn, f"yarn/{yarn_ver} via {inter.source}")


def _mcp_config_version(version: str) -> str:
    """mcp_config versions carry a build stamp (1.14.4-20190719.194122)."""
    try:
        meta = _get(f"{FORGE_MAVEN}/de/oceanlabs/mcp/mcp_config/maven-metadata.xml")
        vers = re.findall(r"<version>([^<]+)</version>",
                          meta.decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        return version
    hits = [v for v in vers if v == version or v.startswith(version + "-")]
    return max(hits) if hits else version


def fetch_mcp_mappings(version: str, cache: Path) -> Mapping:
    """MCP (joined.tsrg) for Forge-era jars.

    Forge's maven only carries 1.13+; anything older needs a .srg/.tsrg
    supplied by hand via --mappings.
    """
    cache.mkdir(parents=True, exist_ok=True)
    real = _mcp_config_version(version)
    zpath = cache / f"mcp_config_{real}.zip"
    if not zpath.exists():
        url = f"{FORGE_MAVEN}/de/oceanlabs/mcp/mcp_config/{real}/mcp_config-{real}.zip"
        try:
            zpath.write_bytes(_get(url))
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"no mcp_config for {version} ({exc}). Forge maven only has 1.13+; "
                "for older versions pass --mappings with a .srg/.tsrg file") from None
    with zipfile.ZipFile(zpath) as z:
        for cand in ("joined.tsrg", "joined.srg", "config/joined.tsrg"):
            if cand in z.namelist():
                return parse_tsrg(z.read(cand).decode("utf-8", "replace"),
                                  source=f"mcp/{version}/{cand}")
    raise RuntimeError(f"no joined.tsrg inside mcp_config for {version}")


def compose_official_srg(mojang: Mapping, srg: Mapping, source: str = "") -> Mapping:
    """Compose Mojang official class names with Forge SRG member names.

    Essential for Forge 1.16+ mod analysis and modern Forge client environments:
    Forge mods reference classes by official Mojang names, but members by SRG
    identifiers (m_... / f_...).

    Members are indexed under both the obfuscated owner and the official owner,
    so lookups succeed regardless of whether the input jar has obfuscated or
    official class references.
    """
    out = Mapping(source=source or f"official-srg via {mojang.source} + {srg.source}")
    out.classes = dict(mojang.classes)
    for owner, members in srg.members.items():
        official_owner = mojang.classes.get(owner, owner)
        for (name, desc), srg_name in members.items():
            out.add_member(owner, name, desc, srg_name)
            if official_owner != owner:
                out.add_member(official_owner, name, desc, srg_name)
    return out


def fetch_official_srg_mappings(version: str, cache: Path) -> Mapping:
    """Mojang official classes + MCP SRG members for modern Forge (1.16+)."""
    mojang = fetch_mojang_mappings(version, cache)
    srg = fetch_mcp_mappings(version, cache)
    return compose_official_srg(mojang, srg, source=f"official-srg/{version}")


def auto_fetch(version: str, kind: str, cache: Path) -> Mapping:
    kind = kind.lower()
    if kind in ("mojang", "official"):
        return fetch_mojang_mappings(version, cache)
    if kind in ("yarn", "fabric"):
        return fetch_yarn_mappings(version, cache)
    if kind in ("mcp", "srg", "legacy"):
        return fetch_mcp_mappings(version, cache)
    if kind in ("official-srg", "forge-srg", "forge", "neoforge"):
        return fetch_official_srg_mappings(version, cache)

    def as_tuple(v: str) -> tuple[int, ...]:
        parts = re.findall(r"\d+", v)
        return tuple(int(p) for p in parts[:3]) or (0,)

    # auto: pick by version
    if as_tuple(version) >= (1, 14):
        try:
            return fetch_mojang_mappings(version, cache)
        except Exception:
            return fetch_yarn_mappings(version, cache)
    return fetch_mcp_mappings(version, cache)
