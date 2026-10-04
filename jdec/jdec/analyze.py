"""Semantic analysis of an obfuscated Minecraft client.

Two ideas drive this module.

The first: an obfuscator can rename a jar's own classes and members freely,
but it cannot rename the JDK or the game. Every call into `java/lang/Runtime`
or `net/minecraft/...` is therefore an un-renamable fingerprint of intent. So
even a jar whose identifiers are all `a`, `b`, `c` still tells us what it
touches.

The second: the interesting part of a cheat client is not its own code, it is
*where it reaches into the game*. That is declared in Mixin annotations, which
are constant-pool constants and survive mangling. So we can produce the list
of patched game classes and methods even when nothing else is readable.
"""

from __future__ import annotations

import json
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import annotations as AN
from . import bytecode as BC
from . import classfile as CF
from . import indy as INDY
from . import mappings as MP
from . import mcmod as MM
from . import obf as OB
from .probe import profile_jar, JarProfile

# --------------------------------------------------------------------------
# API fingerprints. Confusing your own names is easy; changing what JDK call
# you make is not, so these survive every obfuscator.
# --------------------------------------------------------------------------

_API_RULES: dict[str, list[tuple[str, str]]] = {
    "reflection": [
        ("java/lang/Class", "forName"),
        ("java/lang/reflect/Method", "invoke"),
        ("java/lang/invoke/MethodHandles", "lookup"),
    ],
    "native-library": [
        ("java/lang/System", "loadLibrary"),
        ("java/lang/System", "load"),
        ("java/lang/Runtime", "loadLibrary"),
    ],
    "process-exec": [
        ("java/lang/Runtime", "exec"),
        ("java/lang/ProcessBuilder", "start"),
    ],
    "network": [
        ("java/net/URL", "openConnection"),
        ("java/net/URLConnection", "connect"),
        ("java/net/Socket", "connect"),
        ("java/net/http/HttpClient", "send"),
    ],
    "crypto": [
        ("javax/crypto/Cipher", "doFinal"),
        ("javax/crypto/spec/SecretKeySpec", "<init>"),
    ],
    "hashing": [
        ("java/security/MessageDigest", "digest"),
    ],
    "self-integrity": [
        ("java/security/CodeSource", "getLocation"),
        ("java/lang/Class", "getProtectionDomain"),
        ("java/util/zip/ZipFile", "<init>"),
    ],
    "anti-debug": [
        ("java/lang/management/ManagementFactory", "getRuntimeMXBean"),
    ],
    "machine-fingerprint": [
        ("java/net/NetworkInterface", "getHardwareAddress"),
        ("java/net/InetAddress", "getLocalHost"),
    ],
    "jvm-shutdown": [
        ("java/lang/System", "exit"),
    ],
}

# strings that look like an encrypted payload rather than real text
_BLOB_RE = re.compile(r"^[A-Za-z0-9+/=]{24,}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{32,}$")

# which part of the game a hook lands in - enough to say "this one is about
# movement" or "this one is about rendering" without reading a line of code
_MC_AREAS: list[tuple[str, str]] = [
    (r".*[/.](Minecraft|MinecraftClient)$", "client main loop"),
    (r".*[/.](EntityPlayerSP|ClientPlayerEntity|LocalPlayer|PlayerEntity)$", "player"),
    (r".*[/.](EntityLivingBase|LivingEntity)$", "living entities"),
    (r".*[/.]Entity[A-Za-z]*$", "entities"),
    (r".*[/.](Gui|Screen|InGameHud|Hud)[A-Za-z]*$", "UI / overlay"),
    (r".*[/.]Render[A-Za-z]*$", "rendering"),
    (r".*[/.](WorldClient|ClientWorld|ClientLevel|World|Level)$", "world"),
    (r".*[/.](NetHandlerPlayClient|ClientPlayNetworkHandler|Connection)$", "networking"),
    (r".*[/.](Block[A-Za-z]*|BlockState)$", "blocks"),
    (r".*[/.](Item[A-Za-z]*|Inventory|Container)$", "items / inventory"),
    (r".*[/.](KeyBinding|Keyboard|Mouse)$", "input"),
    (r".*[/.](Timer|RenderTickCounter)$", "game timing"),
]

_NATIVE_LIB_RE = re.compile(r"\.(?:dll|so|dylib|jnilib)$", re.I)
# JNIC-style virtualisation compiles method bodies to x86 and leaves a native
# declaration behind, so the body simply is not in the bytecode. Its
# interpreter classes have recognisable names.
_VIRT_MARKERS = ("VNTable", "VNInstruction", "VNWriter", "vnbootstrap",
                 "jnic", "cpu/x86", "VirtualMachine")


@dataclass
class NativeReport:
    """What cannot be decompiled, and why."""

    methods: list[tuple[str, str, str]] = field(default_factory=list)
    per_class: dict[str, int] = field(default_factory=dict)
    libraries: list[tuple[str, int]] = field(default_factory=list)
    markers: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.methods)

    def verdict(self) -> str:
        if self.markers and self.total:
            return ("native/virtualised - method bodies live in the shipped "
                    "library and must be analysed as native code")
        if self.total and self.libraries:
            return "native methods backed by a shipped library"
        if self.total:
            return "native methods (bodies provided by the JRE or another library)"
        return "no native methods"


@dataclass
class ClassSignals:
    name: str
    entry: str
    signals: list[str] = field(default_factory=list)
    blobs: int = 0
    native_methods: list[str] = field(default_factory=list)


@dataclass
class Analysis:
    jar: Path
    profile: JarProfile
    meta: MM.ModMeta
    hooks: list[MM.MixinHook]
    hook_stats: dict
    classes: list[ClassSignals]
    obf: OB.ObfReport | None = None
    obf_classes: dict[str, list[str]] = field(default_factory=dict)
    indy: INDY.IndyReport | None = None
    native: NativeReport | None = None
    mapping_desc: str | None = None
    resources: dict = field(default_factory=dict)
    resource_anomaly: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def signal_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for c in self.classes:
            for s in c.signals:
                out[s] = out.get(s, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    @property
    def areas(self) -> list[tuple[str, int]]:
        """Game areas the hooks land in, most patched first."""
        out: dict[str, int] = {}
        for h in self.hooks:
            target = h.resolved_class
            if not target:
                continue
            simple = target.rsplit("/", 1)[-1]
            for rx, label in _MC_AREAS:
                if re.match(rx, target) or re.match(rx, simple):
                    out[label] = out.get(label, 0) + 1
                    break
        return sorted(out.items(), key=lambda kv: -kv[1])

    def hook_groups(self) -> list[tuple[str, list[MM.MixinHook]]]:
        """Hooks grouped by the game class they patch."""
        groups: dict[str, list[MM.MixinHook]] = {}
        for h in self.hooks:
            key = h.resolved_class or "(unknown target)"
            groups.setdefault(key, []).append(h)
        return sorted(groups.items(),
                      key=lambda kv: (-len(kv[1]), kv[0]))


# --------------------------------------------------------------------------
# scanning
# --------------------------------------------------------------------------

def class_signals(cf, strings: list[str] | None = None) -> ClassSignals:
    """Per-class API fingerprints. Pure function of one parsed class."""
    sig = ClassSignals(name=cf.name, entry="")
    owners = {(o, nm) for _k, o, nm, _d in AN.referenced_members(cf)}
    for label, rules in _API_RULES.items():
        if any((o, nm) in owners for o, nm in rules):
            sig.signals.append(label)

    if strings is None:
        strings = AN.constant_strings(cf)
    blobs = sum(1 for s in strings if _BLOB_RE.match(s) or _HEX_RE.match(s))
    if blobs >= 3:
        sig.signals.append("encrypted-strings")
        sig.blobs = blobs

    native = [cf.utf8(m.name_index) for m in cf.methods
              if m.access_flags & CF.ACC_NATIVE]
    if native:
        sig.signals.append("jni")
        # recorded whether or not anything else flagged the class, so the
        # native report costs no second parse of the jar
        sig.native_methods = native
    return sig


@dataclass
class JarScan:
    """Everything one pass over the jar produces."""

    signals: list[ClassSignals] = field(default_factory=list)
    hooks: list[MM.MixinHook] = field(default_factory=list)
    obf: OB.ObfReport | None = None
    obf_classes: dict[str, list[str]] = field(default_factory=dict)
    indy_refs: list[INDY.IndyRef] = field(default_factory=list)
    indy_by_class: dict[str, list[INDY.IndyRef]] = field(default_factory=dict)
    indy_sites: int = 0
    indy_classes_with_sites: int = 0
    classes_scanned: int = 0
    classes_with_hooks: int = 0
    unreadable: int = 0
    declared_mixins: int = 0
    mixin_configs_read: int = 0


def scan_jar(jar: Path, declared: list[str] | None = None,
             limit: int = 0) -> JarScan:
    """One parse per class, three answers.

    Signals, obfuscator attribution and mixin hooks all need the parsed class,
    and parsing dominates the runtime - walking the archive three times made
    analysis three times slower for no extra information.
    """
    res = JarScan()
    totals: dict[str, int] = {}
    class_hits: dict[str, dict[str, int]] = {}
    seen_declared: set[str] = set()

    with zipfile.ZipFile(jar) as z:
        entries = [n for n in z.namelist()
                   if n.endswith(".class") and not n.startswith("META-INF/")]
        if limit:
            entries = entries[:limit]
        for n in entries:
            try:
                cf = CF.parse(z.read(n))
            except Exception:
                res.unreadable += 1
                continue
            res.classes_scanned += 1
            if declared and cf.name in declared:
                seen_declared.add(cf.name)

            # decode each method once and share the result: both the
            # fingerprints and the indy census need the instruction stream
            codes = [BC.method_code(cf, m) for m in cf.methods]

            # one walk of the constant pool feeds both the string heuristics and
            # the indy table scan
            strings = AN.constant_strings(cf)

            sig = class_signals(cf, strings)
            sig.entry = n
            if sig.signals:
                res.signals.append(sig)

            hits = OB.inspect_class(cf, codes)
            if hits:
                res.obf_classes[cf.name] = sorted(hits)
                class_hits[cf.name] = hits
                for k, v in hits.items():
                    totals[k] = totals.get(k, 0) + v

            refs = INDY.refs_in_class(cf, strings)
            if refs:
                res.indy_refs += refs
                res.indy_by_class[cf.name] = refs

            sites = INDY.count_indy_sites(cf, codes)
            if sites:
                res.indy_sites += sites
                res.indy_classes_with_sites += 1

            found = MM.hooks_from_class(cf, entry=n)
            if found:
                res.hooks += found
                res.classes_with_hooks += 1

    res.obf = OB.build_report(totals, class_hits, res.classes_scanned,
                             len(class_hits), res.unreadable)
    res.declared_mixins = len(seen_declared)
    return res


def collect_native(jar: Path, classes: list[ClassSignals]) -> NativeReport:
    rep = NativeReport()
    for c in classes:
        if not c.native_methods:
            continue
        rep.per_class[c.name] = len(c.native_methods)
        for m in c.native_methods:
            rep.methods.append((c.name, m, ""))
        low = c.name.lower()
        for marker in _VIRT_MARKERS:
            if marker.lower() in low:
                rep.markers.append(c.name)
                break
    with zipfile.ZipFile(jar) as z:
        for info in z.infolist():
            if _NATIVE_LIB_RE.search(info.filename):
                rep.libraries.append((info.filename, info.file_size))
    return rep


def analyze(jar: Path, mapping=None, mapping_desc: str | None = None,
            limit: int = 0) -> Analysis:
    prof = profile_jar(jar)
    meta = MM.read_mod_meta(jar)
    declared, cfg_read = MM.mixin_class_names(jar, meta)
    scan = scan_jar(jar, declared=declared, limit=limit)

    # refmap first: it turns intermediary names back into real ones, and the
    # Minecraft mapping can then translate those. Doing it the other way round
    # leaves the hooks unresolvable, because no mapping knows method_1234.
    refmap = MM.load_refmap(jar)
    refmapped = MM.apply_refmap(scan.hooks, refmap)
    resolved = MM.translate_hooks(scan.hooks, mapping)

    notes: list[str] = []
    ag = meta.manifest.agent_attrs() if meta.manifest else {}
    if ag.get("Premain-Class") or ag.get("Agent-Class"):
        which = ", ".join(f"{k}={ag[k]}" for k in ("Premain-Class", "Agent-Class")
                          if ag.get(k))
        notes.append(f"java agent declared: {which} - attach/instrument capable, "
                     f"expect self-injection and runtime patching")
    vendors = [meta.manifest.main[k] for k in ("Implementation-Vendor",
                                               "Specification-Vendor")
               if meta.manifest and meta.manifest.main.get(k)]
    if vendors:
        notes.append(f"manifest vendor: {vendors[0]}")
    if refmapped:
        notes.append(f"refmap: {refmapped} hook method name(s) restored from "
                     + ", ".join(refmap.sources[:2]))
    if cfg_read and declared:
        notes.append(f"{scan.declared_mixins}/{len(declared)} declared mixin "
                     f"class(es) found in {cfg_read} config file(s)")
    elif scan.hooks:
        notes.append("no mixin config in metadata; hooks found by scanning annotations")
    if mapping is not None:
        notes.append(f"{resolved}/{len(scan.hooks)} hook reference(s) resolved through "
                     f"{mapping_desc or mapping.describe()}")
    elif scan.hooks:
        notes.append("hook targets left as-is (no Minecraft mapping loaded; "
                     "pass --mc-version to resolve them)")
    if scan.unreadable:
        notes.append(f"{scan.unreadable} class(es) could not be parsed and were "
                     f"skipped by every analysis")

    native = collect_native(jar, scan.signals)
    if native.total:
        notes.append(f"{native.total} native method(s) in {len(native.per_class)} "
                     f"class(es) - {native.verdict()}")
    if scan.obf is not None and scan.obf.vendor:
        notes.append(f"obfuscator attribution: {scan.obf.summary()}")

    indy = INDY.build_report(scan.indy_refs, scan.indy_by_class, scan.indy_sites,
                             scan.indy_classes_with_sites, scan.classes_scanned)
    if indy.confirmed:
        notes.append(f"indy obfuscation: {len(indy.refs)} encoded call target(s), "
                     f"{indy.sites} invokedynamic site(s)")

    stats = {"declared": scan.declared_mixins, "scanned": scan.classes_scanned,
             "with_hooks": scan.classes_with_hooks, "unreadable": scan.unreadable}
    anom = MM.resource_anomaly(jar)
    if anom["suspects"]:
        toks = ", ".join(f"{t}(x{n})" for t, n, _ in anom["suspects"])
        notes.append("resource identifier anomaly: " + toks
                     + " - high-frequency non-dictionary token(s) in text "
                       "resources; possible identifier-level obfuscation, "
                       "open the resource and verify by hand")
    return Analysis(
        jar=jar, profile=prof, meta=meta, hooks=scan.hooks, hook_stats=stats,
        classes=scan.signals, obf=scan.obf, obf_classes=scan.obf_classes,
        indy=indy, native=native, mapping_desc=mapping_desc,
        resources=MM.resource_inventory(jar), resource_anomaly=anom,
        notes=notes,
    )


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

def render_markdown(a: Analysis) -> str:
    L: list[str] = ["# jdec analysis", ""]
    L.append(f"- input: `{a.jar.name}`")
    L.append(f"- classes: {a.profile.classes}")
    L.append(f"- obfuscation: {a.profile.obfuscation:.0f}/100"
             + (f" ({a.profile.obfuscator})" if a.profile.obfuscator else ""))
    if a.profile.mc_version or a.profile.mc_flavor:
        L.append(f"- minecraft: {' '.join(filter(None, [a.profile.mc_version, a.profile.mc_flavor]))}")
    L.append(f"- mod: {a.meta.summary()}")
    L.append("")

    if a.meta.manifest and a.meta.manifest.main:
        L += ["## jar metadata", ""]
        L.append("| manifest attribute | value |")
        L.append("|---|---|")
        for k, v in sorted(a.meta.manifest.main.items()):
            L.append(f"| {k} | {v} |")
        L.append("")
        if a.meta.manifest.sections:
            L.append(f"- {len(a.meta.manifest.sections)} named per-entry "
                     f"section(s)")
        if a.resources:
            inv = a.resources
            L.append(f"- non-class entries: {inv['non_class']}")
            if inv["top_dirs"]:
                L.append("- top dirs: " + ", ".join(
                    f"{k} ({v})" for k, v in inv["top_dirs"][:8]))
            if inv["by_ext"]:
                L.append("- file types: " + ", ".join(
                    f"{k} ({v})" for k, v in inv["by_ext"][:8]))
        if a.resource_anomaly.get("suspects"):
            L.append("- identifier anomalies: " + ", ".join(
                f"`{t}` x{n}/{nf}files"
                for t, n, nf in a.resource_anomaly["suspects"]))
        L.append("")

    if a.notes:
        L += ["## notes", ""] + [f"- {n}" for n in a.notes] + [""]

    if a.obf is not None:
        L += ["## obfuscation", ""]
        if a.obf.vendor:
            L.append(f"- attributed to: **{a.obf.vendor}** "
                     f"(confidence {a.obf.confidence:.2f})")
        else:
            L.append("- no structural signature matched")
        L.append(f"- classes flagged: {a.obf.classes_flagged}/{a.obf.classes_scanned}")
        if a.obf.evidence:
            L.append("")
            L.append("| fingerprint | hits | classes |")
            L.append("|---|---|---|")
            for e in a.obf.evidence:
                L.append(f"| {e.label} | {e.hits} | {e.classes} |")
        else:
            L.append("- control flow, exception table and debug metadata look "
                     "like ordinary compiler output")
        L.append("")

    if a.hooks:
        L += ["## what it changes in the game", ""]
        areas = a.areas
        if areas:
            L.append("areas touched: " + ", ".join(f"{k} ({v})" for k, v in areas[:8]))
            L.append("")
        L.append("| patched class | hooks | kinds | methods |")
        L.append("|---|---|---|---|")
        for target, group in a.hook_groups()[:40]:
            kinds = sorted({h.kind for h in group})
            pairs = sorted({(h.resolved_method, h.raw_method) for h in group
                            if h.resolved_method})
            shown = ", ".join(f"`{n}`" + (f" &larr; `{r}`" if r else "")
                              for n, r in pairs[:4])
            if len(pairs) > 4:
                shown += f", +{len(pairs) - 4} more"
            L.append(f"| `{target}` | {len(group)} | {', '.join(kinds)} | {shown} |")
        if len(a.hook_groups()) > 40:
            L.append(f"| ... | {len(a.hook_groups()) - 40} more classes | | |")
        L.append("")
        L.append(f"total: {len(a.hooks)} hook(s) across {len(a.hook_groups())} "
                 f"target class(es)")
        L.append("")
    else:
        L += ["## what it changes in the game", "",
              "no Mixin annotations found.", ""]

    ind = a.indy
    if ind is not None and (ind.refs or ind.sites):
        L += ["## indy call-target encoding", ""]
        L.append(f"- {ind.verdict()}")
        L.append(f"- encoded references: {len(ind.refs)} in "
                 f"{len(ind.by_class)} class(es)")
        L.append(f"- invokedynamic sites: {ind.sites} in "
                 f"{ind.classes_with_sites} class(es)")
        if ind.refs:
            ops = ", ".join(f"{k} ({v})" for k, v in ind.op_counts().items())
            L.append(f"- operations: {ops}")
            L.append("")
            L.append("Call targets the bytecode no longer shows - decoded from "
                     "the encoded text, no execution required:")
            L.append("")
            L.append("| target | operation | table in |")
            L.append("|---|---|---|")
            for r in sorted(ind.refs, key=lambda r: (r.dotted, r.member))[:40]:
                holder = next((c for c, v in ind.by_class.items() if r in v), "?")
                L.append(f"| `{r.as_target()}` | {r.op_name} | `{holder}` |")
            if len(ind.refs) > 40:
                L.append(f"| ... | | {len(ind.refs) - 40} more |")
        L.append("")

    counts = a.signal_counts
    if counts or (a.native and a.native.total):
        L += ["## signals", ""]
        L.append("| signal | classes |")
        L.append("|---|---|")
        for k, v in counts.items():
            L.append(f"| {k} | {v} |")
        L.append("")
        interesting = [c for c in a.classes
                       if set(c.signals) & {"process-exec", "native-library", "jni",
                                            "anti-debug", "machine-fingerprint",
                                            "self-integrity", "reflection"}]
        interesting.sort(key=lambda c: -len(c.signals))
        if interesting:
            L += ["### classes worth looking at first", ""]
            L.append("| class | entry | signals |")
            L.append("|---|---|---|")
            for c in interesting[:25]:
                L.append(f"| `{c.name}` | `{c.entry}` | {', '.join(c.signals)} |")
            L.append("")

    # a native body is not a decompilation failure, so it gets its own section
    # rather than being buried in the class list
    nat = a.native
    if nat is not None and (nat.total or nat.libraries):
        L += ["## native code", ""]
        L.append(f"- {nat.total} native method(s) in {len(nat.per_class)} class(es)")
        L.append(f"- verdict: {nat.verdict()}")
        if nat.libraries:
            L.append("- libraries shipped in the jar:")
            for name, size in sorted(nat.libraries, key=lambda x: -x[1]):
                L.append(f"  - `{name}` ({size / 1024:.0f} KB)")
        if nat.markers:
            L.append(f"- virtualisation interpreter classes: "
                     + ", ".join(f"`{m}`" for m in nat.markers[:6]))
        if nat.per_class:
            L.append("")
            L.append("These methods keep their signature but have no bytecode, "
                     "so no decompiler can recover them:")
            L.append("")
            L.append("| class | native methods |")
            L.append("|---|---|")
            for name, n in sorted(nat.per_class.items(), key=lambda kv: -kv[1])[:20]:
                L.append(f"| `{name}` | {n} |")
            if len(nat.per_class) > 20:
                L.append(f"| ... | {len(nat.per_class) - 20} more classes |")
        L.append("")

    L += ["## input profile", "", "```", a.profile.summary(), "```", ""]
    return "\n".join(L)

def render_json(a: Analysis) -> str:
    payload = {
        "input": str(a.jar),
        "profile": {
            "classes": a.profile.classes,
            "obfuscation": a.profile.obfuscation,
            "obfuscator": a.profile.obfuscator,
            "mc_version": a.profile.mc_version,
            "mc_flavor": a.profile.mc_flavor,
        },
        "mod": {
            "id": a.meta.mod_id, "name": a.meta.name, "version": a.meta.version,
            "loader": a.meta.loader, "entrypoints": a.meta.entrypoints,
            "mixin_configs": a.meta.mixin_configs,
        },
        "manifest": (None if a.meta.manifest is None else {
            "main": a.meta.manifest.main,
            "agent": a.meta.manifest.agent_attrs(),
            "sections": len(a.meta.manifest.sections),
        }),
        "resources": a.resources,
        "resource_anomaly": a.resource_anomaly,
        "mapping": a.mapping_desc,
        "hooks": [
            {
                "mixin_class": h.mixin_class, "kind": h.kind,
                "target_class": h.target_class, "target_method": h.target_method,
                "named_class": h.named_class, "named_method": h.named_method,
                "raw_method": h.raw_method,
                "at": h.at, "entry": h.entry,
            }
            for h in a.hooks
        ],
        "areas": [{"area": k, "hooks": v} for k, v in a.areas],
        "obfuscation": None if a.obf is None else {
            "vendor": a.obf.vendor,
            "confidence": a.obf.confidence,
            "classes_flagged": a.obf.classes_flagged,
            "classes_scanned": a.obf.classes_scanned,
            "evidence": [{"key": e.key, "label": e.label, "hits": e.hits,
                          "classes": e.classes} for e in a.obf.evidence],
            "classes": a.obf_classes,
        },
        "signals": [
            {"class": c.name, "entry": c.entry, "signals": c.signals,
             "blobs": c.blobs, "native_methods": c.native_methods}
            for c in a.classes
        ],
        "notes": a.notes,
    }
    if a.indy is not None:
        payload["indy"] = {
            "confirmed": a.indy.confirmed,
            "verdict": a.indy.verdict(),
            "encoded_references": len(a.indy.refs),
            "indy_sites": a.indy.sites,
            "classes_with_sites": a.indy.classes_with_sites,
            "operations": a.indy.op_counts(),
            "references": [
                {"owner": r.dotted, "member": r.member, "desc": r.desc,
                 "op": r.op, "op_name": r.op_name, "raw": r.raw}
                for r in a.indy.refs
            ],
        }
    if a.native is not None:
        payload["native"] = {
            "methods": a.native.total,
            "classes": len(a.native.per_class),
            "verdict": a.native.verdict(),
            "libraries": [{"name": n, "size": s} for n, s in a.native.libraries],
            "virtualisation_markers": a.native.markers,
            "per_class": a.native.per_class,
        }
    return json.dumps(payload, indent=1)


def write_analysis(a: Analysis, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    md = out_dir / "analysis.md"
    js = out_dir / "analysis.json"
    md.write_text(render_markdown(a), encoding="utf-8")
    js.write_text(render_json(a), encoding="utf-8")
    return md, js


def print_summary(a: Analysis) -> None:
    if a.obf is not None:
        print(f"obfuscation: {a.obf.summary()}")
        for e in a.obf.evidence[:5]:
            print(f"  {e.label}: {e.hits} hit(s) in {e.classes} class(es)")
    print(f"mod        : {a.meta.summary()}")
    if a.hooks:
        print(f"hooks      : {len(a.hooks)} across {len(a.hook_groups())} "
              f"game class(es)")
        areas = a.areas
        if areas:
            print("areas      : " + ", ".join(f"{k} ({v})" for k, v in areas[:6]))
        for target, group in a.hook_groups()[:8]:
            methods = sorted({h.resolved_method for h in group if h.resolved_method})
            shown = ", ".join(methods[:3]) or "-"
            print(f"  {target:<52} {len(group):>3}  {shown}")
        if len(a.hook_groups()) > 8:
            print(f"  ... {len(a.hook_groups()) - 8} more")
    else:
        print("hooks      : none found")
    counts = a.signal_counts
    if counts:
        top = list(counts.items())[:8]
        print("signals    : " + ", ".join(f"{k} ({v})" for k, v in top))
    nat = a.native
    if nat is not None and nat.total:
        print(f"native     : {nat.total} method(s) in {len(nat.per_class)} class(es)")
        if nat.libraries:
            for name, size in sorted(nat.libraries, key=lambda x: -x[1])[:3]:
                print(f"  {name} ({size / 1024:.0f} KB)")
        print(f"  {nat.verdict()}")
    ind = a.indy
    if ind is not None and ind.refs:
        tag = "confirmed" if ind.confirmed else "hint only"
        print(f"indy       : {len(ind.refs)} encoded target(s) ({tag}), "
              f"{ind.sites} invokedynamic site(s)")
        for r in ind.refs[:5]:
            print(f"  {r.as_readable()}")
        if len(ind.refs) > 5:
            print(f"  ... {len(ind.refs) - 5} more")
    for n in a.notes:
        print(f"note       : {n}")
