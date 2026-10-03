"""Read-only access to the parts of a class file `classfile` keeps opaque.

`classfile` deliberately stores attributes as raw blobs so that remapping can
rewrite names without ever re-encoding a Code or annotation structure. That is
what keeps parse -> serialise byte-exact. This module reads *out of* those
blobs and never writes back, so nothing here can break that guarantee.

Why it is worth having: for Minecraft mods the interesting facts are almost
entirely in annotations. `@Mixin` names the game class being patched and
`@Inject` names the method. Those values are constant-pool constants, so they
survive identifier mangling - a cheat client whose own code is renamed into
`a.b.c` still tells you exactly which part of the game it hooks.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from . import classfile as CF
from .classfile import (
    C_UTF8, C_INTEGER, C_FLOAT, C_LONG, C_DOUBLE, C_STRING, C_CLASS,
    C_FIELDREF, C_METHODREF, C_INTERFACE_METHODREF, C_NAME_AND_TYPE,
)

# attribute names we can interpret
A_CODE = "Code"
A_RUNTIME_VISIBLE = "RuntimeVisibleAnnotations"
A_RUNTIME_INVISIBLE = "RuntimeInvisibleAnnotations"
A_ANNOTATION_DEFAULT = "AnnotationDefault"

# element_value tags, as characters
_EV_PRIM = "BCDFIJSZs"
_EV_ENUM = "e"
_EV_CLASS = "c"
_EV_ANNOTATION = "@"
_EV_ARRAY = "["


class AttributeError_(Exception):
    """Malformed attribute; callers treat it as 'no annotations here'."""


@dataclass
class Annotation:
    """One annotation instance. `values` maps element name -> python value."""

    type: str                                  # field descriptor, e.g. Lorg/x/Mixin;
    values: dict[str, object] = field(default_factory=dict)

    @property
    def internal_type(self) -> str:
        """`Lorg/spongepowered/asm/mixin/Mixin;` -> `org/spongepowered/asm/mixin/Mixin`."""
        t = self.type
        if t.startswith("L") and t.endswith(";"):
            return t[1:-1]
        return t

    @property
    def simple_type(self) -> str:
        return self.internal_type.rsplit("/", 1)[-1]

    def get(self, name: str, default=None):
        return self.values.get(name, default)

    def strings(self, name: str) -> list[str]:
        """Element value as a list of strings, whatever shape it was stored in."""
        v = self.values.get(name)
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        if isinstance(v, list):
            return [x for x in v if isinstance(x, str)]
        return []


# --------------------------------------------------------------------------
# byte reader
# --------------------------------------------------------------------------

class _Reader:
    def __init__(self, data: bytes) -> None:
        self.b = data
        self.o = 0

    def u1(self) -> int:
        v = self.b[self.o]
        self.o += 1
        return v

    def u2(self) -> int:
        v = struct.unpack_from(">H", self.b, self.o)[0]
        self.o += 2
        return v

    def u4(self) -> int:
        v = struct.unpack_from(">I", self.b, self.o)[0]
        self.o += 4
        return v

    def take(self, n: int) -> bytes:
        v = self.b[self.o:self.o + n]
        self.o += n
        if len(v) != n:
            raise AttributeError_("truncated attribute")
        return v


# --------------------------------------------------------------------------
# attributes
# --------------------------------------------------------------------------

def parse_attributes(cf, blob: bytes) -> dict[str, bytes]:
    """Split an attributes blob into name -> payload. Later duplicates win."""
    out: dict[str, bytes] = {}
    if not blob:
        return out
    r = _Reader(blob)
    try:
        count = r.u2()
        for _ in range(count):
            ni = r.u2()
            ln = r.u4()
            try:
                name = cf.utf8(ni)
            except Exception:
                r.take(ln)
                continue
            out[name] = r.take(ln)
    except (AttributeError_, struct.error, IndexError):
        return out
    return out


def class_attributes(cf) -> dict[str, bytes]:
    return parse_attributes(cf, cf.attrs_blob)


def member_attributes(cf, member) -> dict[str, bytes]:
    return parse_attributes(cf, member.attrs_blob)


# --------------------------------------------------------------------------
# annotations
# --------------------------------------------------------------------------

def _const_value(cf, idx: int):
    """Constant pool entry -> python value, following the element_value tag."""
    if idx <= 0 or idx >= len(cf.cp):
        return None
    e = cf.cp[idx]
    if not e:
        return None
    tag = e[0]
    if tag == C_UTF8:
        return cf.utf8(idx)
    if tag == C_INTEGER:
        return struct.unpack(">i", e[1][0])[0]
    if tag == C_FLOAT:
        return struct.unpack(">f", e[1][0])[0]
    if tag == C_LONG:
        return struct.unpack(">q", e[1][0])[0]
    if tag == C_DOUBLE:
        return struct.unpack(">d", e[1][0])[0]
    return None


def _element_value(cf, r: _Reader):
    tag = chr(r.u1())
    if tag in _EV_PRIM:
        return _const_value(cf, r.u2())
    if tag == _EV_ENUM:
        ti = r.u2()
        ni = r.u2()
        try:
            return cf.utf8(ni)
        except Exception:
            return None
    if tag == _EV_CLASS:
        idx = r.u2()
        try:
            desc = cf.utf8(idx)
        except Exception:
            return None
        # stored as a descriptor: `Ljava/lang/String;` or `[[I`
        if desc.startswith("L") and desc.endswith(";"):
            return desc[1:-1]
        return desc
    if tag == _EV_ANNOTATION:
        return _annotation(cf, r)
    if tag == _EV_ARRAY:
        n = r.u2()
        return [_element_value(cf, r) for _ in range(n)]
    raise AttributeError_(f"unknown element_value tag {tag!r}")


def _annotation(cf, r: _Reader) -> Annotation:
    ti = r.u2()
    ann = Annotation(type=cf.utf8(ti))
    n = r.u2()
    for _ in range(n):
        name = cf.utf8(r.u2())
        ann.values[name] = _element_value(cf, r)
    return ann


def annotations_of(cf, blob: bytes) -> list[Annotation]:
    """Every annotation carried by one attributes blob."""
    attrs = parse_attributes(cf, blob)
    out: list[Annotation] = []
    for key in (A_RUNTIME_VISIBLE, A_RUNTIME_INVISIBLE):
        payload = attrs.get(key)
        if not payload:
            continue
        r = _Reader(payload)
        try:
            n = r.u2()
            for _ in range(n):
                out.append(_annotation(cf, r))
        except (AttributeError_, struct.error, IndexError, CF.ClassFormatError):
            break
    return out


def class_annotations(cf) -> list[Annotation]:
    return annotations_of(cf, cf.attrs_blob)


def member_annotations(cf, member) -> list[Annotation]:
    return annotations_of(cf, member.attrs_blob)


def annotation_of(cf, blob: bytes, simple_name: str) -> Annotation | None:
    for a in annotations_of(cf, blob):
        if a.simple_type == simple_name:
            return a
    return None


# --------------------------------------------------------------------------
# code
# --------------------------------------------------------------------------

def code_of(cf, member) -> bytes | None:
    """Bytecode of a method, or None (abstract/native/interface method)."""
    attrs = member_attributes(cf, member)
    payload = attrs.get(A_CODE)
    if not payload:
        return None
    r = _Reader(payload)
    try:
        r.u2()          # max_stack
        r.u2()          # max_locals
        n = r.u4()
        return r.take(n)
    except (AttributeError_, struct.error, IndexError):
        return None


# --------------------------------------------------------------------------
# constant pool views
# --------------------------------------------------------------------------

def constant_strings(cf) -> list[str]:
    """String constants in the pool - what `ldc` can push.

    Encrypted payloads show up here as base64/hex-looking blobs, which is the
    cheapest possible signal that a class carries string obfuscation.
    """
    out: list[str] = []
    for i in range(1, len(cf.cp)):
        e = cf.cp[i]
        if e and e[0] == C_STRING:
            try:
                out.append(cf.utf8(e[1][0]))
            except Exception:
                pass
    return out


def referenced_members(cf) -> list[tuple[str, str, str, str]]:
    """(kind, owner, name, descriptor) for every member the class refers to.

    Deliberately pool-level rather than instruction-level: it answers 'what
    APIs does this class know about', which is enough to spot reflection,
    native loading or network calls, without needing an opcode walker.
    """
    out: list[tuple[str, str, str, str]] = []
    for i in range(1, len(cf.cp)):
        e = cf.cp[i]
        if not e:
            continue
        if e[0] not in (C_FIELDREF, C_METHODREF, C_INTERFACE_METHODREF):
            continue
        kind = {C_FIELDREF: "field", C_METHODREF: "method",
                C_INTERFACE_METHODREF: "method"}[e[0]]
        try:
            owner = cf.class_name(e[1][0])
            nt = cf.cp[e[1][1]]
            if not nt or nt[0] != C_NAME_AND_TYPE:
                continue
            out.append((kind, owner, cf.utf8(nt[1][0]), cf.utf8(nt[1][1])))
        except Exception:
            continue
    return out


def referenced_classes(cf) -> list[str]:
    out: list[str] = []
    for i in range(1, len(cf.cp)):
        e = cf.cp[i]
        if e and e[0] == C_CLASS:
            try:
                out.append(cf.utf8(e[1][0]))
            except Exception:
                pass
    return out
