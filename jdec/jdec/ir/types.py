"""The verification type lattice from JVMS 4.10.1.2.

Kept deliberately small: seven primitive tokens, a null token, top, object
types (arrays included, as `("obj", "[Ljava/lang/String;")`), and the two
uninitialized forms the verifier needs for constructors.

Why a separate module instead of reusing `devirt._FIXED_EFFECTS`: that table is
keyed by *opcode name* and counts **slots**, not types — `ISHL` and `FADD` are
both `(2, 1)`. Slot counts cannot answer "is this value assignable to the
receiver of `invokevirtual`", which is exactly what frame generation needs.

The one deliberate approximation is `merge` of two unrelated object types: it
falls back to `java/lang/Object`. That is always *sound* for the verifier (a
frame may widen), but it can be too wide for the instruction that consumes the
value — a later `invokevirtual Foo.m` on an Object-typed slot fails. M1 accepts
that and reverts the method; M2 replaces the fallback with a real common
supertype computed from the jar index.
"""

from __future__ import annotations

INT = "int"          # also boolean / byte / char / short: one verifier type
FLOAT = "float"
LONG = "long"
DOUBLE = "double"
NULL = "null"
TOP = "top"          # unusable / not yet assigned

UNINIT_THIS: tuple = ("uninit", -1)

OBJECT = ("obj", "java/lang/Object")


class FrameError(Exception):
    """The method cannot be typed. The caller must revert it, not guess."""


def obj(name: str) -> tuple:
    return ("obj", name)


def uninit(pc: int) -> tuple:
    return ("uninit", pc)


def is_ref(t) -> bool:
    return isinstance(t, tuple) and t[0] == "obj"


def is_uninit(t) -> bool:
    return isinstance(t, tuple) and t[0] == "uninit"


def is_wide(t) -> bool:
    """Category-2 values: two local slots, one operand-stack value."""
    return t in (LONG, DOUBLE)


def type_of_field_descriptor(desc: str) -> object:
    """Field descriptor -> verification type."""
    if not desc:
        raise FrameError("empty field descriptor")
    c = desc[0]
    if c == "B" or c == "C" or c == "S" or c == "Z" or c == "I":
        return INT
    if c == "F":
        return FLOAT
    if c == "J":
        return LONG
    if c == "D":
        return DOUBLE
    if c == "L" and desc.endswith(";"):
        return obj(desc[1:-1])
    if c == "[":
        return obj(desc)          # array: keep the descriptor as its identity
    raise FrameError(f"bad field descriptor {desc!r}")


def params_of_method_descriptor(desc: str) -> list:
    """Parameter types of a method descriptor, `this` excluded."""
    if not desc.startswith("("):
        raise FrameError(f"bad method descriptor {desc!r}")
    end = desc.index(")")
    out: list = []
    i = 1
    while i < end:
        c = desc[i]
        if c == "[":
            j = i
            while desc[j] == "[":
                j += 1
            if desc[j] == "L":
                j = desc.index(";", j) + 1
            else:
                j += 1
            out.append(obj(desc[i:j]))
            i = j
            continue
        if c == "L":
            j = desc.index(";", i) + 1
            out.append(obj(desc[i + 1:j - 1]))
            i = j
            continue
        out.append(type_of_field_descriptor(c))
        i += 1
    return out


def return_of_method_descriptor(desc: str) -> object | None:
    ret = desc.split(")", 1)[1]
    if ret == "V":
        return None
    return type_of_field_descriptor(ret)


def slot_width(t) -> int:
    return 2 if is_wide(t) else 1


def merge(a, b, hier=None):
    """Least upper bound in the verification lattice.

    Incompatible *locals* merge to TOP, not to an error: the slot becomes
    unusable, but the frame is still well-formed, and javac/obfuscators do reuse
    a slot with different types on paths that never read it afterwards. The
    stack does not allow that — see `merge_frames`.

    `hier` supplies real common supertypes. Without it two unrelated reference
    types widen to Object, which is sound for the frame but can be too wide for
    the instruction that consumes the value.
    """
    if a == b:
        return a
    if a == TOP or b == TOP:
        # an undefined slot stays undefined: using it is a verification error
        return TOP
    if a == NULL and is_ref(b):
        return b
    if b == NULL and is_ref(a):
        return a
    if is_uninit(a) or is_uninit(b):
        # two different uninitialized values never merge into something usable,
        # and HotSpot rejects the frame outright
        raise FrameError(f"cannot merge uninitialized value {a} with {b}")
    if is_ref(a) and is_ref(b):
        if hier is not None:
            return obj(hier.lca(a[1], b[1]))
        return OBJECT
    return TOP


def merge_frames(a, b, max_locals: int, hier=None):
    """Merge two frames; returns (frame, changed) or raises FrameError."""
    if len(a.stack) != len(b.stack):
        raise FrameError(
            f"stack height differs at a join point ({len(a.stack)} vs {len(b.stack)})")
    locals_a = list(a.locals) + [TOP] * (max_locals - len(a.locals))
    locals_b = list(b.locals) + [TOP] * (max_locals - len(b.locals))
    out_locals = [merge(x, y, hier) for x, y in zip(locals_a, locals_b)]
    out_stack = []
    for x, y in zip(a.stack, b.stack):
        m = merge(x, y, hier)
        if m == TOP:
            # `top` is not a legal operand-stack type: the two paths disagree
            # about what is on the stack, so the method cannot be typed
            raise FrameError(f"incompatible stack types at a join point: {x} vs {y}")
        out_stack.append(m)
    merged = Frame(trim_locals(out_locals), out_stack)
    return merged, merged != a


def trim_locals(locals_: list) -> list:
    n = len(locals_)
    while n > 0 and locals_[n - 1] == TOP:
        n -= 1
    return locals_[:n]


class Frame:
    """A verification frame. `locals` is slot-based, `stack` is value-based.

    Locals use one entry per *slot* (long/double take two, the second being
    TOP), because that is how `max_locals` and `istore_3` are numbered. The
    operand stack uses one entry per *value*, because JVMS 4.10.1 treats a
    long/double on the stack as a single value.
    """

    __slots__ = ("locals", "stack")

    def __init__(self, locals_=None, stack=None):
        self.locals = list(locals_ or [])
        self.stack = list(stack or [])

    def copy(self) -> "Frame":
        return Frame(self.locals, self.stack)

    def __eq__(self, other) -> bool:
        return (isinstance(other, Frame) and self.locals == other.locals
                and self.stack == other.stack)

    def __repr__(self) -> str:
        return f"Frame(locals={self.locals}, stack={self.stack})"

    # ---- locals -----------------------------------------------------
    def get_local(self, idx: int):
        return self.locals[idx] if idx < len(self.locals) else TOP

    def set_local(self, idx: int, t) -> None:
        width = slot_width(t)
        while len(self.locals) < idx + width:
            self.locals.append(TOP)
        self.locals[idx] = t
        if width == 2:
            self.locals[idx + 1] = TOP

    # ---- stack ------------------------------------------------------
    def push(self, t) -> None:
        self.stack.append(t)

    def pop(self, expect=None):
        if not self.stack:
            raise FrameError("operand stack underflow")
        t = self.stack.pop()
        if expect is not None and expect != TOP and t != expect:
            raise FrameError(f"expected {expect} on the stack, found {t}")
        return t

    def pop_ref(self):
        t = self.pop()
        if not (is_ref(t) or t == NULL or is_uninit(t)):
            raise FrameError(f"expected a reference on the stack, found {t}")
        return t
