"""invokedynamic call-target encoding (superblaubeere27 / JObf family).

The most common obfuscation on Minecraft cheat clients is not ZKM's flow
surgery - it is rewriting every call site into an `invokedynamic` whose real
target is hidden in the bootstrap method. The target itself is parked in a
static `String[]` as text, and the *number of trailing spaces* is the operation:

    a/b/C:methodName:()V..      2 spaces -> findVirtual
    a/b/C:other:()I.            1 space  -> findStatic
    x/Y:field:I...              3 spaces -> getfield (instance)
    p/Q:method:(...)V....       4 spaces -> getstatic

Decoding these is pure text processing - nothing has to be executed, no class
has to be loaded. That matters: on a packed client this yields the call graph
that the bytecode no longer shows, which is exactly what you want when you are
trying to work out what a cheat client actually touches.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import bytecode as BC

# owner:member:descriptor followed by 1-6 spaces
INDY_ENCODED_REF = re.compile(
    r"^(?P<owner>[A-Za-z_$][A-Za-z0-9_$]*(?:[./][A-Za-z_$][A-Za-z0-9_$]*)*)"
    r":(?P<member>[A-Za-z_$<>][A-Za-z0-9_$<>]*)"
    r":(?P<desc>[^\s]{1,40})"
    r"(?P<pad> {1,6})$")

# trailing-space count -> what the call site actually does
OP_NAMES = {
    1: "static-call",
    2: "virtual-call",
    3: "field-get",
    4: "static-field-get",
    5: "field-set",
    6: "static-field-set",
}

# three or more is treated as conclusive; below that it stays a hint
CONFIRM_THRESHOLD = 3


@dataclass(frozen=True)
class IndyRef:
    owner: str
    member: str
    desc: str
    op: int
    raw: str

    @property
    def op_name(self) -> str:
        return OP_NAMES.get(self.op, f"op-{self.op}")

    @property
    def dotted(self) -> str:
        return self.owner.replace("/", ".")

    def as_target(self) -> str:
        """`a.b.C.method()V` or `a.b.C.field : I` - no operation annotation."""
        if "field" in self.op_name:
            return f"{self.dotted}.{self.member} : {self.desc}"
        return f"{self.dotted}.{self.member}{self.desc}"

    def as_readable(self) -> str:
        return f"{self.as_target()}  [{self.op_name}]"


def parse_ref(text: str) -> IndyRef | None:
    """Decode one encoded reference, or None if it is not one."""
    if not text or not text.endswith(" "):
        return None
    m = INDY_ENCODED_REF.match(text)
    if not m:
        return None
    return IndyRef(
        owner=m.group("owner").replace(".", "/"),
        member=m.group("member"),
        desc=m.group("desc"),
        op=len(m.group("pad")),
        raw=text,
    )


def refs_in_class(cf, strings: list[str] | None = None) -> list[IndyRef]:
    """Every encoded reference in one class's constant pool, deduplicated.

    `strings` may be the caller's already-extracted string constants; on a
    large jar walking the constant pool twice is measurable.
    """
    from . import annotations as AN
    out: dict[str, IndyRef] = {}
    for s in (strings if strings is not None else AN.constant_strings(cf)):
        ref = parse_ref(s)
        if ref is not None:
            out.setdefault(s, ref)
    return list(out.values())


@dataclass
class IndyReport:
    refs: list[IndyRef] = field(default_factory=list)
    by_class: dict[str, list[IndyRef]] = field(default_factory=dict)
    sites: int = 0                    # invokedynamic instructions seen
    classes_with_sites: int = 0
    classes_scanned: int = 0

    @property
    def confirmed(self) -> bool:
        return len(self.refs) >= CONFIRM_THRESHOLD

    def verdict(self) -> str:
        if not self.refs:
            return "no indy call-target encoding found"
        if not self.confirmed:
            return (f"{len(self.refs)} encoded reference(s) - below the "
                    f"{CONFIRM_THRESHOLD} threshold, treat as a hint only")
        return ("superblaubeere27 / JObf style indy obfuscation: call targets "
                "are encoded as text and hidden behind invokedynamic")

    def op_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.refs:
            out[r.op_name] = out.get(r.op_name, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    def owners(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.refs:
            out[r.dotted] = out.get(r.dotted, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def build_report(refs: list[IndyRef], by_class: dict[str, list[IndyRef]],
                 sites: int, classes_with_sites: int,
                 classes_scanned: int) -> IndyReport:
    return IndyReport(refs=refs, by_class=by_class, sites=sites,
                      classes_with_sites=classes_with_sites,
                      classes_scanned=classes_scanned)


def count_indy_sites(cf, codes: list | None = None) -> int:
    """How many invokedynamic instructions this class actually executes.

    `codes` is an optional list of pre-decoded CodeInfo parallel to
    `cf.methods`, shared with the obfuscation fingerprints.
    """
    total = 0
    for i, m in enumerate(cf.methods):
        ci = None
        if codes is not None and i < len(codes):
            ci = codes[i]
        else:
            ci = BC.method_code(cf, m, decode_insns=True)
        if ci is None or ci.error:
            continue
        total += sum(1 for x in ci.insns if x.op == BC.OP_INVOKEDYNAMIC)
    return total
