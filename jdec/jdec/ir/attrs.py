"""Read and write the sub-attribute table of a Code attribute.

StackMapTable is a child of Code, not of the method — `Member.attrs_blob` holds
attributes of the *member*, and the Code payload holds its own table one level
down. Getting that level wrong silently writes an attribute the JVM ignores.

Everything here works on raw payload bytes and keeps every foreign sub-attribute
(LineNumberTable, LocalVariableTable, …) untouched and in order.
"""

from __future__ import annotations

import struct

from .types import FrameError


def _split_code(payload: bytes):
    """(prefix_before_attr_count, [(name_idx, payload), ...])."""
    if len(payload) < 8:
        raise FrameError("Code attribute too short")
    o = 4
    code_len = struct.unpack_from(">I", payload, o)[0]
    o += 4 + code_len
    if o + 2 > len(payload):
        raise FrameError("Code attribute truncated before the exception table")
    exc_n = struct.unpack_from(">H", payload, o)[0]
    o += 2 + 8 * exc_n
    if o + 2 > len(payload):
        raise FrameError("Code attribute truncated before the attributes count")
    prefix = payload[:o]
    attr_n = struct.unpack_from(">H", payload, o)[0]
    o += 2
    entries = []
    for _ in range(attr_n):
        if o + 6 > len(payload):
            raise FrameError("truncated Code sub-attribute header")
        ni = struct.unpack_from(">H", payload, o)[0]
        ln = struct.unpack_from(">I", payload, o + 2)[0]
        if o + 6 + ln > len(payload):
            raise FrameError("truncated Code sub-attribute payload")
        entries.append((ni, payload[o + 6:o + 6 + ln]))
        o += 6 + ln
    return prefix, entries


def code_subattrs(cf, member) -> list:
    """[(name, payload)] for every attribute nested inside the Code attribute."""
    for name_idx, data in _member_attrs(member):
        if _safe_utf8(cf, name_idx) == "Code":
            _prefix, entries = _split_code(data)
            return [(_safe_utf8(cf, ni), body) for ni, body in entries]
    return []


def set_code_subattr(cf, member, name: str, data: bytes) -> None:
    """Replace (or append) one sub-attribute of the member's Code attribute."""
    name_idx = cf.intern_utf8(name)
    blob = member.attrs_blob
    if len(blob) < 2:
        raise FrameError("member has no attributes")
    count = struct.unpack_from(">H", blob, 0)[0]
    out = bytearray(blob[:2])
    o = 2
    replaced = False
    for _ in range(count):
        ni = struct.unpack_from(">H", blob, o)[0]
        ln = struct.unpack_from(">I", blob, o + 2)[0]
        payload = blob[o + 6:o + 6 + ln]
        if _safe_utf8(cf, ni) == "Code" and not replaced:
            prefix, entries = _split_code(payload)
            entries = [(a, b) for a, b in entries if _safe_utf8(cf, a) != name]
            entries.append((name_idx, data))
            new_payload = bytearray(prefix)
            new_payload += struct.pack(">H", len(entries))
            for a, b in entries:
                new_payload += struct.pack(">HI", a, len(b)) + b
            out += struct.pack(">HI", ni, len(new_payload)) + new_payload
            replaced = True
        else:
            out += blob[o:o + 6 + ln]
        o += 6 + ln
    if not replaced:
        raise FrameError("member has no Code attribute")
    member.attrs_blob = bytes(out)


def replace_code(cf, member, code: bytes, handlers,
                 max_stack: int | None = None,
                 max_locals: int | None = None) -> None:
    """Swap a method's code array and exception table, keeping other sub-attrs.

    The old StackMapTable is dropped, because the offsets just moved. The caller
    must write a new one (`frames.encode`) before the class is serialized.
    """
    for name_idx, data in _member_attrs(member):
        if _safe_utf8(cf, name_idx) != "Code":
            continue
        prefix, entries = _split_code(data)
        old_stack, old_locals = struct.unpack_from(">HH", prefix, 0)
        kept = [(a, b) for a, b in entries if _safe_utf8(cf, a) != "StackMapTable"]
        payload = bytearray()
        payload += struct.pack(">HH", max_stack if max_stack is not None else old_stack,
                               max_locals if max_locals is not None else old_locals)
        payload += struct.pack(">I", len(code)) + code
        payload += struct.pack(">H", len(handlers))
        for h in handlers:
            payload += struct.pack(">HHHH", h.start_pc, h.end_pc, h.handler_pc,
                                   h.catch_type)
        payload += struct.pack(">H", len(kept))
        for a, b in kept:
            payload += struct.pack(">HI", a, len(b)) + b
        _replace_member_attr(cf, member, "Code", bytes(payload))
        return
    raise FrameError("member has no Code attribute")


def remap_debug(cf, member, pc_map: dict, old_len: int, new_len: int) -> None:
    """Move debug tables onto a new layout after instructions were removed.

    A LineNumberTable entry whose `start_pc` is past the end of a shortened code
    array violates JVMS 4.7.12 ("must be a valid index into the code array").
    HotSpot's parser tolerates it, `javap` prints nonsense, and a decompiler may
    map a line to the wrong block — so shift every entry to the closest
    surviving instruction at or before its old position.
    """
    if not pc_map:
        return
    ordered = sorted(pc_map.items())

    def floor(pc: int) -> int:
        if pc in pc_map:
            return pc_map[pc]
        best = 0
        for old, new in ordered:
            if old >= pc:
                break
            best = new
        return best

    def fix_line_numbers(payload: bytes) -> bytes:
        if len(payload) < 2:
            return payload
        n = struct.unpack_from(">H", payload, 0)[0]
        if len(payload) < 2 + 4 * n:
            return payload
        out = bytearray(struct.pack(">H", n))
        for i in range(n):
            start, line = struct.unpack_from(">HH", payload, 2 + 4 * i)
            out += struct.pack(">HH", floor(start), line)
        return bytes(out)

    def fix_locals(payload: bytes) -> bytes:
        if len(payload) < 2:
            return payload
        n = struct.unpack_from(">H", payload, 0)[0]
        if len(payload) < 2 + 10 * n:
            return payload
        out = bytearray(struct.pack(">H", n))
        for i in range(n):
            start, length, name, desc, index = struct.unpack_from(
                ">HHHHH", payload, 2 + 10 * i)
            new_start = floor(start)
            end = new_len if start + length >= old_len else floor(start + length)
            out += struct.pack(">HHHHH", new_start, max(0, end - new_start),
                               name, desc, index)
        return bytes(out)

    fixers = {"LineNumberTable": fix_line_numbers,
              "LocalVariableTable": fix_locals,
              "LocalVariableTypeTable": fix_locals}
    for name_idx, data in _member_attrs(member):
        if _safe_utf8(cf, name_idx) != "Code":
            continue
        prefix, entries = _split_code(data)
        changed = False
        new_entries = []
        for ni, body in entries:
            fix = fixers.get(_safe_utf8(cf, ni))
            fixed = fix(body) if fix else body
            if fixed != body:
                changed = True
            new_entries.append((ni, fixed))
        if not changed:
            return
        payload = bytearray(prefix)
        payload += struct.pack(">H", len(new_entries))
        for a, b in new_entries:
            payload += struct.pack(">HI", a, len(b)) + b
        _replace_member_attr(cf, member, "Code", bytes(payload))
        return


def _replace_member_attr(cf, member, name: str, payload: bytes) -> None:
    blob = member.attrs_blob
    count = struct.unpack_from(">H", blob, 0)[0]
    out = bytearray(blob[:2])
    o = 2
    for _ in range(count):
        ni = struct.unpack_from(">H", blob, o)[0]
        ln = struct.unpack_from(">I", blob, o + 2)[0]
        body = blob[o + 6:o + 6 + ln]
        if _safe_utf8(cf, ni) == name:
            body = payload
        out += struct.pack(">HI", ni, len(body)) + body
        o += 6 + ln
    member.attrs_blob = bytes(out)


def remove_code_subattr(cf, member, name: str) -> bool:
    """Drop one sub-attribute; returns whether it was there."""
    blob = member.attrs_blob
    if len(blob) < 2:
        return False
    count = struct.unpack_from(">H", blob, 0)[0]
    out = bytearray(blob[:2])
    o = 2
    removed = False
    for _ in range(count):
        ni = struct.unpack_from(">H", blob, o)[0]
        ln = struct.unpack_from(">I", blob, o + 2)[0]
        payload = blob[o + 6:o + 6 + ln]
        if _safe_utf8(cf, ni) == "Code":
            prefix, entries = _split_code(payload)
            kept = [(a, b) for a, b in entries if _safe_utf8(cf, a) != name]
            removed = len(kept) != len(entries)
            new_payload = bytearray(prefix)
            new_payload += struct.pack(">H", len(kept))
            for a, b in kept:
                new_payload += struct.pack(">HI", a, len(b)) + b
            out += struct.pack(">HI", ni, len(new_payload)) + new_payload
        else:
            out += blob[o:o + 6 + ln]
        o += 6 + ln
    if removed:
        member.attrs_blob = bytes(out)
    return removed


def _member_attrs(member):
    blob = member.attrs_blob
    if len(blob) < 2:
        return
    count = struct.unpack_from(">H", blob, 0)[0]
    o = 2
    for _ in range(count):
        ni = struct.unpack_from(">H", blob, o)[0]
        ln = struct.unpack_from(">I", blob, o + 2)[0]
        yield ni, blob[o + 6:o + 6 + ln]
        o += 6 + ln


def _safe_utf8(cf, idx: int) -> str:
    try:
        return cf.utf8(idx)
    except Exception:
        return ""
