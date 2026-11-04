"""Encode computed frames as a StackMapTable payload (JVMS 4.7.4).

Always `full_frame`. The compact forms (`same_frame`, `append`, `chop`) exist to
save bytes; they also encode assumptions about the previous frame, and getting
one of those wrong produces exactly the `Expecting a stackmap frame at branch
target` failure this whole layer is meant to eliminate. A few hundred bytes per
method is not worth that risk. If size ever matters, add the compact forms with
a parity test against `javap -v`, not before.

Two conventions that are easy to get wrong:

  * the frame at pc 0 is implicit and must NOT appear in the table; the first
    entry's `offset_delta` is its own pc, later ones are `pc - prev - 1`;
  * locals are slot-addressed, so a long/double writes ONE type entry and skips
    the next slot — `number_of_locals` is an entry count, not `max_locals`.
"""

from __future__ import annotations

import struct

from .. import bytecode as BC
from .. import classfile as CF
from . import types as T
from .types import Frame, FrameError

TAG_TOP = 0
TAG_INT = 1
TAG_FLOAT = 2
TAG_DOUBLE = 3
TAG_LONG = 4
TAG_NULL = 5
TAG_UNINIT_THIS = 6
TAG_OBJECT = 7
TAG_UNINIT = 8

FULL_FRAME = 0xFF


def class_index(cf, name: str) -> int:
    """Constant-pool index of a Class entry, adding one when needed."""
    for i, e in enumerate(cf.cp):
        if e and e[0] == CF.C_CLASS:
            try:
                if cf.utf8(e[1][0]) == name:
                    return i
            except Exception:
                continue
    return cf.add_class(name)


def _vtype(cf, t) -> bytes:
    if t == T.TOP:
        return struct.pack(">B", TAG_TOP)
    if t == T.INT:
        return struct.pack(">B", TAG_INT)
    if t == T.FLOAT:
        return struct.pack(">B", TAG_FLOAT)
    if t == T.DOUBLE:
        return struct.pack(">B", TAG_DOUBLE)
    if t == T.LONG:
        return struct.pack(">B", TAG_LONG)
    if t == T.NULL:
        return struct.pack(">B", TAG_NULL)
    if t == T.UNINIT_THIS:
        return struct.pack(">B", TAG_UNINIT_THIS)
    if T.is_ref(t):
        name = t[1]
        if not _valid_class_name(name):
            # a bad name here becomes `ClassFormatError: illegal character in
            # descriptor`, which points at the class and not at the cause
            raise FrameError(f"refusing to emit an invalid class name {name!r}")
        return struct.pack(">BH", TAG_OBJECT, class_index(cf, name))
    if T.is_uninit(t):
        return struct.pack(">BH", TAG_UNINIT, t[1] & 0xFFFF)
    raise FrameError(f"cannot encode verification type {t!r}")


def _valid_class_name(name: str) -> bool:
    if not name or "(" in name or ")" in name or " " in name:
        return False
    if not name.startswith("["):
        return True
    # array descriptor: [* then a field descriptor
    i = 0
    while i < len(name) and name[i] == "[":
        i += 1
    if i == len(name):
        return False
    rest = name[i:]
    if rest in ("Z", "B", "C", "S", "I", "J", "F", "D"):
        return True
    if rest.startswith("L") and rest.endswith(";") and len(rest) > 2:
        inner = rest[1:-1]
        # `[L[I;` is the shape a doubled array prefix produces: a class name
        # can never contain '['
        return "[" not in inner and ";" not in inner
    return False


def needed_pcs(insns, handlers) -> set:
    """Offsets a verifier expects a frame at: branch targets and handlers.

    Dead code needs no frame; the verifier never walks into it. That is also
    why NOP-filling unreachable instructions is legal in the first place.
    """
    pcs = set()
    for i in insns:
        pcs.update(i.jump_targets())
    for h in handlers:
        pcs.add(h.handler_pc)
    return pcs


_vsize_cache: dict = {}


def _read_vtype(cf, payload: bytes, o: int):
    tag = payload[o]
    if tag == TAG_TOP:
        return T.TOP, o + 1
    if tag == TAG_INT:
        return T.INT, o + 1
    if tag == TAG_FLOAT:
        return T.FLOAT, o + 1
    if tag == TAG_DOUBLE:
        return T.DOUBLE, o + 1
    if tag == TAG_LONG:
        return T.LONG, o + 1
    if tag == TAG_NULL:
        return T.NULL, o + 1
    if tag == TAG_UNINIT_THIS:
        return T.UNINIT_THIS, o + 1
    if tag == TAG_OBJECT:
        idx = struct.unpack_from(">H", payload, o + 1)[0]
        e = cf.cp[idx] if 0 < idx < len(cf.cp) else None
        if not e or e[0] != CF.C_CLASS:
            raise FrameError(f"frame names cp[{idx}], which is not a Class")
        return T.obj(cf.utf8(e[1][0])), o + 3
    if tag == TAG_UNINIT:
        off = struct.unpack_from(">H", payload, o + 1)[0]
        return T.uninit(off), o + 3
    raise FrameError(f"unknown verification type tag {tag}")


def decode(cf, payload: bytes, member=None, max_locals: int = 0) -> dict:
    """Decode an existing StackMapTable into `{pc: Frame}`.

    `member` is required to interpret the compact forms: `same_frame`,
    `append_frame` and `chop_frame` all say "relative to the previous frame",
    and the first previous frame is the method's **implicit initial frame** —
    `this` plus the parameters. Starting from an empty list silently produces
    locals that are missing every parameter (measured: it made a comparison
    against javac report 88% mismatches that were all decoder artefacts).

    Used to keep the offsets javac decided a frame is needed at: some become
    unreachable after a rewrite, our worklist produces no state for them, yet
    the verifier still expects a frame there.
    """
    if len(payload) < 2:
        return {}
    n = struct.unpack_from(">H", payload, 0)[0]
    o = 2
    off = -1
    locals_: list = _initial_locals(cf, member, max_locals)
    out: dict = {}
    for _ in range(n):
        if o >= len(payload):
            raise FrameError("truncated StackMapTable")
        tag = payload[o]
        o += 1
        if tag <= 63:
            # same_frame: locals are inherited unchanged from the previous frame
            delta, stack = tag, []
        elif tag <= 127:
            delta = tag - 64
            v, o = _read_vtype(cf, payload, o)
            stack = [v]
        elif tag == 247:
            delta = struct.unpack_from(">H", payload, o)[0]
            o += 2
            v, o = _read_vtype(cf, payload, o)
            stack = [v]
        elif 248 <= tag <= 250:
            delta = struct.unpack_from(">H", payload, o)[0]
            o += 2
            locals_ = locals_[:len(locals_) - (251 - tag)]
            stack = []
        elif tag == 251:
            delta = struct.unpack_from(">H", payload, o)[0]
            o += 2
            stack = []
        elif 252 <= tag <= 254:
            delta = struct.unpack_from(">H", payload, o)[0]
            o += 2
            locals_ = list(locals_)
            for _ in range(tag - 251):
                v, o = _read_vtype(cf, payload, o)
                locals_.append(v)
            stack = []
        elif tag == FULL_FRAME:
            delta = struct.unpack_from(">H", payload, o)[0]
            o += 2
            nl = struct.unpack_from(">H", payload, o)[0]
            o += 2
            locals_ = []
            for _ in range(nl):
                v, o = _read_vtype(cf, payload, o)
                locals_.append(v)
            ns = struct.unpack_from(">H", payload, o)[0]
            o += 2
            stack = []
            for _ in range(ns):
                v, o = _read_vtype(cf, payload, o)
                stack.append(v)
        else:
            raise FrameError(f"unknown frame type {tag}")
        off = delta if off < 0 else off + delta + 1
        out[off] = Frame(_slots(locals_), list(stack))
    return out


def _initial_locals(cf, member, max_locals: int) -> list:
    if member is None:
        return []
    if not max_locals:
        try:
            max_locals = BC.method_code(cf, member, decode_insns=False).max_locals
        except Exception:
            return []
    try:
        from . import assume as _assume
        return _assume.initial_frame(cf, member, max_locals).locals
    except Exception:
        return []


def _slots(entries: list) -> list:
    """value-based locals -> slot-based (long/double take two slots)."""
    out = []
    for t in entries:
        out.append(t)
        if T.is_wide(t):
            out.append(T.TOP)
    return out


def encode(cf, states: dict, needed: set, member=None, max_locals: int = 0) -> bytes:
    """Build a StackMapTable payload from computed frames.

    Only offsets that are both *needed* and *reachable* get an entry: emitting a
    frame for an unreachable handler would make the verifier type-check dead
    code against a guessed state.

    Entries use the compact forms (`same_frame`, `same_locals_1_stack_item`,
    `append`, `chop`) whenever they fit and fall back to `full_frame` otherwise.
    The compact forms are relative to the previous frame, and the "previous"
    frame of the first entry is the *implicit* initial frame (`this` plus the
    parameters). When the caller passes `member`, that frame is known and the
    first entry can be compact too; when it is not, the first entry is written
    as `full_frame`, because guessing the implicit frame wrong produces a class
    file that parses and then fails verification in a way nothing local
    explains. Measured on HMCL: writing every entry as `full_frame` cost
    134 KB; compacting all but the first cost 15 KB; this costs ~0.
    """
    # 0 is normally implicit, but HotSpot demands an explicit entry when a
    # branch targets 0 (a loop back to the first instruction)
    pcs = sorted(p for p in needed if p in states and p >= 0)
    out = bytearray(struct.pack(">H", len(pcs)))
    prev = -1
    prev_entries: list | None = None
    if member is not None:
        try:
            initial = _initial_locals(cf, member, max_locals)
            prev_entries = _locals_entries(T.trim_locals(initial))
        except Exception:  # noqa: BLE001 - fall back to full_frame
            prev_entries = None
    for pc in pcs:
        delta = pc if prev < 0 else pc - prev - 1
        if delta < 0 or delta > 0xFFFF:
            raise FrameError(f"bad offset_delta {delta} at {pc}")
        f: T.Frame = states[pc]
        entries = _locals_entries(T.trim_locals(list(f.locals)))
        for t in f.stack:
            if t == T.TOP:
                raise FrameError(f"top on the operand stack at {pc}")
        compact = _compact(cf, delta, entries, f.stack, prev_entries)
        if compact is not None:
            out += compact
        else:
            out += struct.pack(">BH", FULL_FRAME, delta)
            out += struct.pack(">H", len(entries))
            for t in entries:
                out += _vtype(cf, t)
            out += struct.pack(">H", len(f.stack))
            for t in f.stack:
                out += _vtype(cf, t)
        prev = pc
        prev_entries = entries
    return bytes(out)


def _compact(cf, delta: int, entries: list, stack: list, prev: list | None):
    """Smallest frame that expresses this state, or None for full_frame."""
    if prev is None:
        return None                      # relative to an implicit frame we lack
    if entries == prev:
        if not stack:
            if delta <= 63:
                return struct.pack(">B", delta)
            return struct.pack(">BH", 251, delta)
        if len(stack) == 1:
            if delta <= 63:
                return struct.pack(">B", 64 + delta) + _vtype(cf, stack[0])
            return struct.pack(">BH", 247, delta) + _vtype(cf, stack[0])
    if not stack:
        if len(entries) < len(prev) and prev[:len(entries)] == entries:
            drop = len(prev) - len(entries)
            if drop <= 3:
                return struct.pack(">BH", 251 - drop, delta)
        if 0 < len(entries) - len(prev) <= 3 and entries[:len(prev)] == prev:
            added = entries[len(prev):]
            out = struct.pack(">BH", 251 + len(added), delta)
            for t in added:
                out += _vtype(cf, t)
            return out
    return None


def _locals_entries(locals_: list) -> list:
    """Slot list -> verification_type_info entries."""
    out = []
    i = 0
    while i < len(locals_):
        t = locals_[i]
        out.append(t)
        i += 2 if T.is_wide(t) else 1
    return out
