"""Obfuscator attribution from bytecode structure.

Commercial obfuscators cannot be identified by package name. Zelix KlassMaster
in particular ships no runtime library: it is a pure bytecode-to-bytecode
transform, so an obfuscated jar contains nothing named after it. What it does
leave is structure that no compiler would produce:

* **exception handlers that jump backwards** - a handler whose target precedes
  the range it protects. javac cannot emit this, because an exception thrown
  inside a range cannot be handled before the range begins. This is ZKM's flow
  obfuscation fingerprint and is the single strongest signal available.
* **gotos that jump into a protected range** - makes the control flow graph
  irreducible, which is what defeats decompilers.
* **a decryption loop in `<clinit>`** - ZKM's string encryption keeps the
  ciphertext in a String/char array and XORs it with a rotating key selected
  by a `switch (i % 7)`-style dispatch, then `intern()`s the result.

These are measurable without executing anything, which is the point: jdec
should be able to tell you *what you are dealing with* before you decide how
hard to push.
"""

from __future__ import annotations

import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import annotations as AN
from . import bytecode as BC
from . import classfile as CF

OP_INVOKEVIRTUAL = 0xB6
OP_INVOKESPECIAL = 0xB7
OP_INVOKEINTERFACE = 0xB9

# how much each structural fingerprint says "ZKM". Weights are combined with a
# noisy-OR so several weak signals can add up without any single one being
# treated as proof.
_ZKM_WEIGHTS = {
    # Measured on a real ZKM 27 sample (Forge 1.7-1.12 mod, 723 classes) against
    # a vanilla 1.20.4 client as baseline. ZKM 27 does NOT use backwards
    # exception handlers (0 in all three jars) - its flow obfuscation is a goto
    # flood plus a wildly irreducible CFG. The handler fingerprint stays
    # weighted because it is still decisive for other obfuscators, but on its
    # own it would have missed this sample entirely.
    "handler-backjump": 0.45,
    "goto-flood": 0.35,          # vanilla 1.3%  vs  ZKM 27 13.9%
    "clinit-decryptor": 0.30,
    "reflect-lookup": 0.20,
    "irreducible-goto": 0.18,    # vanilla 0.32/class  vs  ZKM 27 6.9/class
    "char-xor-loop": 0.15,
    "long-constant-array": 0.10,
    "indy-long": 0.06,
    "param-object-array": 0.10,
}

# Weak corroboration must not turn into an attribution. A jar whose only
# evidence is a handful of indirect signs should read "unknown", not "ZKM".
_ATTRIBUTION_FLOOR = 0.35

# A fingerprint counts as evidence only when it fires on a large enough share
# of the jar. Measured class-hit rates:
#                     vanilla 1.20.4 (7787)   ZKM 27 sample (723)
#   clinit-decryptor        0.0%                    43.6%
#   goto-flood              3.1%                    46.9%
#   irreducible-goto        2.0%                    28.9%
#   long-constant-array     0.9%                    23.4%
#   indy-long               0.8%                    12.9%
# 10% therefore clears every baseline with several times the headroom, and
# keeps a handful of coincidental hits in one method from naming a vendor.
_MIN_HIT_RATIO = 0.10

# reported, but never used to name a vendor. Two of these are actively
# *inverted* as evidence: an official Minecraft jar has its SourceFile
# attributes stripped (100% mismatch) and far heavier method overloading
# (34%) than the ZKM-processed sample (0.1% and 3.7%).
# (Currently informational only - attribute() never reads it. Keep the tuple
# as the canonical "generic signal" list for future gate logic.)

# a class whose every jump is a goto is a flow-obfuscation smell; vanilla sits
# at 1.3% and ZKM 27 at 13.9%, so this threshold has an order of magnitude of
# headroom on both sides
_GOTO_FLOOD_RATIO = 0.10
_GOTO_FLOOD_MIN_INSNS = 20
_IRREDUCIBLE_PER_CLASS = 3

_LABELS = {
    "handler-backjump": "exception handlers jump backwards (flow obfuscation)",
    "irreducible-goto": "gotos jump into a protected range (irreducible control flow)",
    "clinit-decryptor": "string decryption loop in <clinit>",
    "reflect-lookup": "reflection lookup helpers (long -> Method/Field)",
    "indy-long": "invokedynamic + long constants (enhanced string encryption)",
    "char-xor-loop": "char-array XOR decryption loops",
    "long-constant-array": "long constant arrays (integer/long encryption)",
    "param-object-array": "signatures replaced by Object[] (parameter obfuscation)",
    "fake-sourcefile": "SourceFile attribute does not match the class",
    "line-number-reset": "line numbers reset or missing",
    "overload-collision": "heavy method name reuse across descriptors",
}

# signals that say "obfuscated" but not "by whom"
_GENERIC_KEYS = ("fake-sourcefile", "line-number-reset", "overload-collision")


@dataclass
class Evidence:
    key: str
    weight: float
    hits: int = 0
    classes: int = 0

    @property
    def label(self) -> str:
        return _LABELS.get(self.key, self.key)


@dataclass
class ObfReport:
    vendor: str | None = None
    confidence: float = 0.0
    evidence: list[Evidence] = field(default_factory=list)
    classes_scanned: int = 0
    classes_flagged: int = 0
    methods_flagged: int = 0
    unreadable: int = 0

    def summary(self) -> str:
        if not self.vendor:
            return "no structural signature matched"
        return (f"{self.vendor} (confidence {self.confidence:.2f}); "
                f"{self.classes_flagged}/{self.classes_scanned} classes flagged")


# --------------------------------------------------------------------------
# per-method analysis
# --------------------------------------------------------------------------

def _call_targets(cf, insns: list[BC.Insn]) -> list[tuple[str, str, str]]:
    """(owner, name, descriptor) for every invoke in the instruction stream."""
    out: list[tuple[str, str, str]] = []
    for insn in insns:
        if insn.op not in (OP_INVOKEVIRTUAL, BC.OP_INVOKESTATIC, OP_INVOKESPECIAL,
                           OP_INVOKEINTERFACE):
            continue
        if insn.arg is None:
            continue
        try:
            owner, name, desc = _resolve_member(cf, insn.arg)
        except Exception:
            continue
        out.append((owner, name, desc))
    return out


def _resolve_member(cf, idx: int) -> tuple[str, str, str]:
    from .classfile import C_NAME_AND_TYPE
    e = cf.cp[idx]
    if not e:
        raise CF.ClassFormatError("bad ref")
    owner = cf.class_name(e[1][0])
    nt = cf.cp[e[1][1]]
    if not nt or nt[0] != C_NAME_AND_TYPE:
        raise CF.ClassFormatError("bad name-and-type")
    return owner, cf.utf8(nt[1][0]), cf.utf8(nt[1][1])


def _has_backward_goto(insns: list[BC.Insn]) -> bool:
    return any(i.is_goto and i.jump_targets() and i.jump_targets()[0] < i.pc
               for i in insns)


def _is_decryptor(cf, ci: BC.CodeInfo, name: str) -> bool:
    """A char-array XOR loop that ends up producing a String."""
    ops = {i.op for i in ci.insns}
    if BC.OP_IXOR not in ops and BC.OP_LXOR not in ops:
        return False
    if not ({BC.OP_NEWARRAY, BC.OP_ANEWARRAY} & ops):
        return False
    if not _has_backward_goto(ci.insns):
        return False
    for owner, mname, desc in _call_targets(cf, ci.insns):
        if owner == "java/lang/String" and (
                desc.startswith("([C") or mname in ("intern", "valueOf")):
            return True
    return False


def inspect_method(cf, member, name: str, ci=None) -> dict[str, int]:
    """Fingerprints of one method. `ci` may be a pre-decoded CodeInfo."""
    hits: dict[str, int] = {}
    if ci is None:
        ci = BC.method_code(cf, member)
    if ci is None:
        return hits

    backjump = sum(1 for h in ci.handlers if h.jumps_backwards)
    if backjump:
        hits["handler-backjump"] = backjump

    if ci.insns and ci.handlers:
        # Irreducible flow: a jump landing strictly inside a protected range.
        # The source pc is deliberately not checked - measuring a vanilla
        # client against a real ZKM 27 sample showed the stricter rule missed
        # 4975 of 4977 occurrences and had no separating power at all.
        ranges = [(h.start_pc, h.end_pc) for h in ci.handlers
                  if h.end_pc > h.start_pc]
        for insn in ci.insns:
            if not insn.is_goto:
                continue
            for t in insn.jump_targets():
                if any(s < t < e for s, e in ranges):
                    hits["irreducible-goto"] = hits.get("irreducible-goto", 0) + 1
                    break

    # goto flood: ZKM 27 tears linear code apart with jumps instead of using
    # exception edges. Measured 13.9% on the sample against 1.3% on vanilla.
    if len(ci.insns) >= _GOTO_FLOOD_MIN_INSNS:
        gotos = sum(1 for i in ci.insns
                    if i.is_goto or i.op in (BC.OP_JSR, BC.OP_JSR_W))
        if gotos / len(ci.insns) >= _GOTO_FLOOD_RATIO:
            hits["goto-flood"] = hits.get("goto-flood", 0) + 1

    # invokedynamic alone proves nothing - every lambda uses one, and a
    # vanilla client has hundreds. ZKM's enhanced string encryption pairs each
    # ciphertext with a long key, so require several of both in one method.
    indies = sum(1 for i in ci.insns if i.op == BC.OP_INVOKEDYNAMIC)
    longs = sum(1 for i in ci.insns if i.op == BC.OP_LDC2_W)
    if indies >= 2 and longs >= 2:
        hits["indy-long"] = 1

    if name == "<clinit>" and _is_decryptor(cf, ci, name):
        hits["clinit-decryptor"] = 1
    elif _is_decryptor(cf, ci, name):
        hits["char-xor-loop"] = 1

    if name == "<clinit>":
        longs = sum(1 for i in ci.insns if i.op == BC.OP_LDC2_W)
        if longs >= 8:
            hits["long-constant-array"] = longs

    if ci.error:
        hits.setdefault("undecodable", 1)
    return hits


# --------------------------------------------------------------------------
# per-class analysis
# --------------------------------------------------------------------------

def _line_numbers(cf, member) -> list[int] | None:
    attrs = AN.member_attributes(cf, member)
    payload = attrs.get("Code")
    if not payload:
        return None
    try:
        code_len = struct.unpack_from(">I", payload, 4)[0]
        o = 8 + code_len
        hcount = struct.unpack_from(">H", payload, o)[0]
        o += 2 + 8 * hcount
        acount = struct.unpack_from(">H", payload, o)[0]
        o += 2
        for _ in range(acount):
            if o + 6 > len(payload):
                return None
            ni = struct.unpack_from(">H", payload, o)[0]
            ln = struct.unpack_from(">I", payload, o + 2)[0]
            o += 6
            try:
                if cf.utf8(ni) != "LineNumberTable":
                    o += ln
                    continue
            except Exception:
                o += ln
                continue
            body = payload[o:o + ln]
            n = struct.unpack_from(">H", body, 0)[0]
            return [struct.unpack_from(">H", body, 2 + 4 * k)[0] for k in range(n)]
    except (struct.error, IndexError):
        return None
    return None


def inspect_class(cf, codes: list | None = None) -> dict[str, int]:
    """Structural fingerprints of one class.

    `codes` is an optional list of pre-decoded CodeInfo parallel to
    `cf.methods`, so a caller walking the jar once does not pay for decoding
    every method twice.
    """
    hits: dict[str, int] = {}
    names: dict[str, int] = {}

    for i, m in enumerate(cf.methods):
        try:
            name = cf.utf8(m.name_index)
            desc = cf.utf8(m.descriptor_index)
        except Exception:
            continue
        if not name.startswith("<"):
            names[name] = names.get(name, 0) + 1
        if desc.startswith("([Ljava/lang/Object;)"):
            hits["param-object-array"] = hits.get("param-object-array", 0) + 1
        if desc.startswith("(J)") and ("reflect/Method" in desc or "reflect/Field" in desc):
            hits["reflect-lookup"] = hits.get("reflect-lookup", 0) + 1
        ci = codes[i] if codes is not None and i < len(codes) else None
        for k, v in inspect_method(cf, m, name, ci).items():
            hits[k] = hits.get(k, 0) + v

    if any(c >= 4 for c in names.values()):
        hits["overload-collision"] = max(names.values())

    attrs = AN.class_attributes(cf)
    try:
        src = cf.utf8(_utf8_index_of(cf, attrs["SourceFile"])) if "SourceFile" in attrs else None
    except Exception:
        src = None
    if src and not src.endswith(".java"):
        hits["fake-sourcefile"] = 1
    elif src:
        simple = cf.name.rsplit("/", 1)[-1].split("$")[0]
        if not src[:-5].endswith(simple):
            hits["fake-sourcefile"] = 1

    for m in cf.methods:
        lines = _line_numbers(cf, m)
        if lines is not None and len(lines) > 1 and max(lines) <= 1:
            hits["line-number-reset"] = hits.get("line-number-reset", 0) + 1
            break
    return hits


def _utf8_index_of(cf, payload: bytes) -> int:
    return struct.unpack_from(">H", payload, 0)[0]


# --------------------------------------------------------------------------
# jar-level attribution
# --------------------------------------------------------------------------

def attribute(hits: dict[str, int], classes_scanned: int = 0) -> tuple[str | None, float]:
    """Noisy-OR over the ZKM-specific fingerprints, with two guards.

    `hits` maps a fingerprint to the number of *classes* it fired on — not
    occurrences. (inspect_class returns occurrence counts per class; the jar
    walkers must collapse those to one hit per class before calling this, or
    the 10% gate loses its "share of the jar" meaning.) A fingerprint only
    counts when it reaches `_MIN_HIT_RATIO` of the jar, which is what
    separates "one method happens to be jumpy" from "this whole jar was
    flow-obfuscated".

    The floor is exclusive: confidence must be STRICTLY ABOVE
    `_ATTRIBUTION_FLOOR` (0.35) to name a vendor. A single `goto-flood`
    fingerprint (weight 0.35) therefore reads "unknown" on its own — exactly
    the "weak corroboration is not attribution" rule the floor encodes —
    while combinations of independent signals (e.g. goto-flood +
    long-constant-array = 0.42) do attribute. Callers that want the numeric
    confidence of a non-attributed run can read it from the second element.
    """
    need = _MIN_HIT_RATIO * classes_scanned if classes_scanned else 1
    present = [k for k in _ZKM_WEIGHTS if hits.get(k, 0) >= need and hits.get(k)]
    if not present:
        return None, 0.0
    miss = 1.0
    for k in present:
        miss *= (1.0 - _ZKM_WEIGHTS[k])
    conf = round(1.0 - miss, 2)
    if conf <= _ATTRIBUTION_FLOOR:
        return None, conf
    return "Zelix KlassMaster (ZKM)", conf


def build_report(totals: dict[str, int], class_hits: dict[str, dict[str, int]],
                  classes_scanned: int, classes_flagged: int,
                  unreadable: int) -> ObfReport:
    """Assemble a report from counts gathered by any traversal.

    Split out from the jar walk so a caller that is already parsing every
    class for other reasons does not have to parse them all again.
    """
    rep = ObfReport()
    rep.classes_scanned = classes_scanned
    rep.classes_flagged = classes_flagged
    rep.unreadable = unreadable
    rep.methods_flagged = sum(
        v for k, v in totals.items()
        if k in ("handler-backjump", "irreducible-goto"))
    # attribute() gates on *class* coverage (see its docstring); totals are
    # occurrence counts kept for the evidence display, so collapse the
    # per-class hits to one hit per class here
    class_counts = {k: sum(1 for h in class_hits.values() if h.get(k))
                    for k in _ZKM_WEIGHTS}
    rep.vendor, rep.confidence = attribute(class_counts, classes_scanned)
    rep.evidence = sorted(
        (Evidence(key=k, weight=_ZKM_WEIGHTS.get(k, 0.0), hits=v,
                  classes=sum(1 for h in class_hits.values() if h.get(k)))
         for k, v in totals.items()),
        key=lambda e: -e.weight)
    return rep


def scan_obfuscation(jar: Path, limit: int = 0) -> tuple[ObfReport, dict[str, list[str]]]:
    """Structural scan of a jar. Returns (report, class -> signals)."""
    totals: dict[str, int] = {}
    class_hits: dict[str, dict[str, int]] = {}
    per_class: dict[str, list[str]] = {}
    scanned = flagged = unreadable = 0

    with zipfile.ZipFile(jar) as z:
        entries = [n for n in z.namelist()
                   if n.endswith(".class") and not n.startswith("META-INF/")]
        if limit:
            entries = entries[:limit]
        for n in entries:
            try:
                cf = CF.parse(z.read(n))
            except Exception:
                unreadable += 1
                continue
            scanned += 1
            hits = inspect_class(cf)
            if not hits:
                continue
            flagged += 1
            class_hits[cf.name] = hits
            per_class[cf.name] = sorted(hits)
            for k, v in hits.items():
                totals[k] = totals.get(k, 0) + v

    return build_report(totals, class_hits, scanned, flagged, unreadable), per_class
