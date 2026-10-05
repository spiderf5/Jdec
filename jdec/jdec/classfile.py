"""Minimal zero-dependency Java .class file reader/writer.

Only what a decompilation driver actually needs:

* class / member signatures (ground truth for judging decompiler output)
* the class file version, access flags, constant pool
* in-place rewrite of constant-pool UTF8 entries, keeping all other
  structure byte-identical, so a remapped class stays valid bytecode.

The rewrite model matters: we never move anything except UTF8 payloads.
Constant pool indices are preserved; new entries are only ever *appended*,
and members' name_index may be repointed to an interned entry. That keeps
every attribute blob (Code, LineNumberTable, ...) untouched and therefore
consistent.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

# constant pool tags
C_UTF8 = 1
C_INTEGER = 3
C_FLOAT = 4
C_LONG = 5
C_DOUBLE = 6
C_CLASS = 7
C_STRING = 8
C_FIELDREF = 9
C_METHODREF = 10
C_INTERFACE_METHODREF = 11
C_NAME_AND_TYPE = 12
C_METHOD_HANDLE = 15
C_METHOD_TYPE = 16
C_DYNAMIC = 17
C_INVOKE_DYNAMIC = 18
C_MODULE = 19
C_PACKAGE = 20

# tag -> body layout, expressed as struct formats ('S' = u2 byte payload)
_CP_LAYOUT = {
    C_UTF8: ("u2len",),
    C_INTEGER: ("4",),
    C_FLOAT: ("4",),
    C_LONG: ("8",),
    C_DOUBLE: ("8",),
    C_CLASS: ("u2",),
    C_STRING: ("u2",),
    C_FIELDREF: ("u2", "u2"),
    C_METHODREF: ("u2", "u2"),
    C_INTERFACE_METHODREF: ("u2", "u2"),
    C_NAME_AND_TYPE: ("u2", "u2"),
    C_METHOD_HANDLE: ("u1", "u2"),
    C_METHOD_TYPE: ("u2",),
    C_DYNAMIC: ("u2", "u2"),
    C_INVOKE_DYNAMIC: ("u2", "u2"),
    C_MODULE: ("u2",),
    C_PACKAGE: ("u2",),
}

ACC_PUBLIC = 0x0001
ACC_STATIC = 0x0008
ACC_SYNTHETIC = 0x1000
ACC_BRIDGE = 0x0040
ACC_NATIVE = 0x0100

# major version -> Java release
_JAVA_MAJOR = {
    45: "1.1", 46: "1.2", 47: "1.3", 48: "1.4", 49: "5", 50: "6", 51: "7",
    52: "8", 53: "9", 54: "10", 55: "11", 56: "12", 57: "13", 58: "14",
    59: "15", 60: "16", 61: "17", 62: "18", 63: "19", 64: "20", 65: "21",
    66: "22", 67: "23", 68: "24", 69: "25", 70: "26",
}


def java_version_of(major: int) -> str:
    return _JAVA_MAJOR.get(major, f"?({major})")


def _u1(b: bytes, o: int) -> int:
    return b[o]


def _u2(b: bytes, o: int) -> int:
    return struct.unpack_from(">H", b, o)[0]


def _u4(b: bytes, o: int) -> int:
    return struct.unpack_from(">I", b, o)[0]


class ClassFormatError(Exception):
    pass


@dataclass
class Member:
    """A field_info or method_info. Attributes are kept as an opaque blob."""

    access_flags: int
    name_index: int
    descriptor_index: int
    attrs_blob: bytes  # u2 count + raw attribute entries

    @property
    def is_synthetic(self) -> bool:
        return bool(self.access_flags & ACC_SYNTHETIC)


@dataclass
class ClassFile:
    major: int
    minor: int
    access_flags: int
    this_class: int
    super_class: int
    interfaces: list[int]
    fields: list[Member]
    methods: list[Member]
    attrs_blob: bytes
    # parallel to constant pool, 1-based; None for the filler slot after
    # Long/Double. Entries are raw tuples: (tag, [payload...]) with UTF8
    # payload being raw bytes.
    cp: list = field(default_factory=list)
    _utf8_cache: dict = field(default_factory=dict, repr=False)

    # ---------------------------------------------------------------- basics

    @property
    def java_version(self) -> str:
        return java_version_of(self.major)

    def utf8(self, index: int) -> str:
        e = self.cp[index]
        if e[0] != C_UTF8:
            raise ClassFormatError(f"cp[{index}] is not Utf8")
        return e[1].decode("utf-8", "replace")

    def utf8_raw(self, index: int) -> bytes:
        return self.cp[index][1]

    def class_name(self, index: int) -> str:
        e = self.cp[index]
        if e[0] != C_CLASS:
            raise ClassFormatError(f"cp[{index}] is not Class")
        return self.utf8(e[1][0])

    @property
    def name(self) -> str:
        """Internal binary name, e.g. net/minecraft/client/Minecraft."""
        return self.class_name(self.this_class)

    @property
    def super_name(self) -> str | None:
        return self.class_name(self.super_class) if self.super_class else None

    @property
    def interface_names(self) -> list[str]:
        return [self.class_name(i) for i in self.interfaces]

    def field_sigs(self, include_synthetic: bool = False) -> list[tuple[str, str]]:
        return [
            (self.utf8(f.name_index), self.utf8(f.descriptor_index))
            for f in self.fields
            if include_synthetic or not f.is_synthetic
        ]

    def method_sigs(self, include_synthetic: bool = False) -> list[tuple[str, str]]:
        out = []
        for m in self.methods:
            if not include_synthetic and (m.is_synthetic or m.access_flags & ACC_BRIDGE):
                continue
            out.append((self.utf8(m.name_index), self.utf8(m.descriptor_index)))
        return out

    # ------------------------------------------------------------- rewriting

    def set_utf8(self, index: int, value: str) -> None:
        raw = value.encode("utf-8")
        self.cp[index] = (C_UTF8, raw)
        self._utf8_cache.pop(self._utf8_cache_get_key(index), None)
        self._utf8_cache[value] = index

    def _utf8_cache_get_key(self, index: int):
        for k, v in self._utf8_cache.items():
            if v == index:
                return k
        return None

    def intern_utf8(self, value: str) -> int:
        """Return the index of a Utf8 entry holding `value`, appending if needed."""
        if value in self._utf8_cache:
            idx = self._utf8_cache[value]
            if idx < len(self.cp) and self.cp[idx][0] == C_UTF8:
                try:
                    if self.cp[idx][1].decode("utf-8", "replace") == value:
                        return idx
                except Exception:
                    pass
        raw = value.encode("utf-8")
        self.cp.append((C_UTF8, raw))
        idx = len(self.cp) - 1
        self._utf8_cache[value] = idx
        return idx

    def add_class(self, internal_name: str) -> int:
        """Append a Class entry for `internal_name`; returns its index."""
        name_idx = self.intern_utf8(internal_name)
        self.cp.append((C_CLASS, [name_idx]))
        return len(self.cp) - 1

    # ------------------------------------------------------------ serializing

    def serialize(self) -> bytes:
        out = bytearray()
        out += struct.pack(">IHH", 0xCAFEBABE, self.minor, self.major)
        out += struct.pack(">H", len(self.cp))
        for e in self.cp[1:]:
            if e is None:  # filler slot after a Long/Double
                continue
            tag = e[0]
            out += struct.pack(">B", tag)
            if tag == C_UTF8:
                payload = e[1]
                out += struct.pack(">H", len(payload)) + payload
            elif tag in (C_INTEGER, C_FLOAT, C_LONG, C_DOUBLE):
                out += e[1][0]  # raw fixed-width payload
            elif tag == C_METHOD_HANDLE:
                out += struct.pack(">BH", e[1][0], e[1][1])  # u1 kind + u2 index
            else:
                for v in e[1]:
                    out += struct.pack(">H", v)
        out += struct.pack(">H", self.access_flags)
        out += struct.pack(">HH", self.this_class, self.super_class)
        out += struct.pack(">H", len(self.interfaces))
        for i in self.interfaces:
            out += struct.pack(">H", i)
        out += struct.pack(">H", len(self.fields))
        for f in self.fields:
            out += struct.pack(">HHH", f.access_flags, f.name_index, f.descriptor_index)
            out += f.attrs_blob
        out += struct.pack(">H", len(self.methods))
        for m in self.methods:
            out += struct.pack(">HHH", m.access_flags, m.name_index, m.descriptor_index)
            out += m.attrs_blob
        out += self.attrs_blob
        return bytes(out)


def parse(data: bytes) -> ClassFile:
    if len(data) < 10 or _u4(data, 0) != 0xCAFEBABE:
        raise ClassFormatError("not a class file")
    try:
        minor, major = _u2(data, 4), _u2(data, 6)
        cp_count = _u2(data, 8)
        o = 10
        cp: list = [None] * cp_count
        i = 1
        while i < cp_count:
            tag = _u1(data, o)
            o += 1
            if tag == C_UTF8:
                n = _u2(data, o)
                o += 2
                cp[i] = (C_UTF8, data[o:o + n])
                o += n
            else:
                layout = _CP_LAYOUT.get(tag)
                if layout is None:
                    raise ClassFormatError(f"unknown constant pool tag {tag} at {o - 1}")
                if tag in (C_LONG, C_DOUBLE):
                    cp[i] = (tag, [data[o:o + 8]])
                    o += 8
                    i += 1  # occupies two slots
                    cp[i] = None
                else:
                    vals = []
                    for kind in layout:
                        if kind == "u1":
                            vals.append(_u1(data, o))
                            o += 1
                        elif kind == "u2":
                            vals.append(_u2(data, o))
                            o += 2
                        else:  # fixed-width numeric payload ("4" / "8")
                            n = int(kind)
                            vals.append(data[o:o + n])
                            o += n
                    cp[i] = (tag, vals)
            i += 1

        access_flags = _u2(data, o); o += 2
        this_class = _u2(data, o); o += 2
        super_class = _u2(data, o); o += 2
        iface_count = _u2(data, o); o += 2
        interfaces = [_u2(data, o + 2 * k) for k in range(iface_count)]
        o += 2 * iface_count
        fields, o = _read_members(data, o)
        methods, o = _read_members(data, o)
        attrs_at = o
        attrs_count = _u2(data, o); o += 2
        for _ in range(attrs_count):
            o += 2
            ln = _u4(data, o); o += 4
            o += ln
        cf = ClassFile(
            major=major, minor=minor, access_flags=access_flags,
            this_class=this_class, super_class=super_class, interfaces=interfaces,
            fields=fields, methods=methods, attrs_blob=data[attrs_at:o], cp=cp,
        )
        _build_utf8_cache(cf)
        return cf
    except (struct.error, IndexError) as exc:
        raise ClassFormatError(f"truncated or malformed class file: {exc}") from exc



def _read_members(data: bytes, o: int):
    count = _u2(data, o); o += 2
    members: list[Member] = []
    start = o
    for _ in range(count):
        af = _u2(data, o); ni = _u2(data, o + 2); di = _u2(data, o + 4)
        o += 6
        ac = _u2(data, o); o += 2
        for _ in range(ac):
            o += 2
            ln = _u4(data, o); o += 4
            o += ln
        members.append(Member(af, ni, di, b""))
    # second pass: slice out each member's attribute blob
    p = start
    for m in members:
        p += 6
        blob_start = p  # includes attributes_count, so re-serialising is lossless
        ac = _u2(data, p); p += 2
        for _ in range(ac):
            p += 2
            ln = _u4(data, p); p += 4
            p += ln
        m.attrs_blob = data[blob_start:p]
    return members, o


def _build_utf8_cache(cf: ClassFile) -> None:
    # first occurrence wins; members are repointed explicitly when renamed
    for idx in range(1, len(cf.cp)):
        e = cf.cp[idx]
        if e and e[0] == C_UTF8:
            try:
                s = e[1].decode("utf-8", "replace")
            except Exception:
                continue
            cf._utf8_cache.setdefault(s, idx)


# --------------------------------------------------------------------------
# descriptor helpers
# --------------------------------------------------------------------------

def descriptor_classes(desc: str) -> list[str]:
    """Internal class names referenced by a field/method descriptor."""
    out: list[str] = []
    i = 0
    n = len(desc)
    while i < n:
        if desc[i] == "L":
            j = desc.find(";", i)
            if j == -1:
                break
            out.append(desc[i + 1:j])
            i = j + 1
        else:
            i += 1
    return out


def replace_descriptor_classes(desc: str, mapping: dict[str, str]) -> str:
    """Rewrite L...; segments using `mapping` (internal names)."""
    if "L" not in desc or not mapping:
        return desc
    out = []
    i = 0
    n = len(desc)
    while i < n:
        if desc[i] == "L":
            j = desc.find(";", i)
            if j == -1:
                out.append(desc[i:])
                break
            name = desc[i + 1:j]
            out.append("L" + mapping.get(name, name) + ";")
            i = j + 1
        else:
            out.append(desc[i])
            i += 1
    return "".join(out)


def pretty_descriptor(desc: str) -> str:
    """`(Ljava/lang/String;I)V` -> `(String, int)` for human-facing reports."""
    def one(d: str) -> str:
        prim = {"B": "byte", "C": "char", "D": "double", "F": "float",
                "I": "int", "J": "long", "S": "short", "Z": "boolean", "V": "void"}
        arrays = 0
        while d.startswith("["):
            arrays += 1
            d = d[1:]
        if d in prim:
            base = prim[d]
        elif d.startswith("L") and d.endswith(";"):
            base = d[1:-1].split("/")[-1]
        else:
            base = d
        return base + "[]" * arrays

    if desc.startswith("("):
        end = desc.find(")")
        if end == -1:
            return desc
        args = []
        i = 1
        while i < end:
            if desc[i] == "L":
                j = desc.find(";", i)
                args.append(one(desc[i:j + 1]))
                i = j + 1
            elif desc[i] == "[":
                j = i
                while desc[j] == "[":
                    j += 1
                if desc[j] == "L":
                    k = desc.find(";", j)
                    args.append(one(desc[i:k + 1]))
                    i = k + 1
                else:
                    args.append(one(desc[i:j + 1]))
                    i = j + 1
            else:
                args.append(one(desc[i]))
                i += 1
        return "(" + ", ".join(args) + ") " + one(desc[end + 1:])
    return one(desc)
