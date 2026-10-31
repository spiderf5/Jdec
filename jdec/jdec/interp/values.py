"""A concrete-value interpreter for differential execution.

It executes the *same method body* from two jars on the same inputs and
compares results. Everything external (files, network, threads, unmodelled
JDK calls) is either a deterministic in-memory model or an `Opaque` value.

The one rule that makes the results usable: a value that came out of an
`Opaque` call may never decide a branch, be returned, or reach a side effect.
If it does, the whole execution is `inconclusive` — never `same`. Treating
"unknown == unknown" as agreement is exactly the false pass `behave` used to
have, and this module does not repeat it.

This is a same-model differential engine, not a JVM. The operand stack is
**slot-based exactly as JVMS specifies**: a long/double occupies two slots
(the value plus a `VOID` filler), so `dup2`/`pop2`/`swap` are verbatim spec
translations and a category-2 value can never silently corrupt the stack
shape — the previous single-slot model mis-executed every `dup2` over a long
and every `double` argument list, which surfaced as dozens of "field access
on a non-object" verdicts. `monitor` is a no-op, and identity comparisons
follow the model, not the memory layout. Both sides of a diff run the same
engine, so those choices cancel; they are documented so nobody mistakes the
interpreter for a verifier.
"""

from __future__ import annotations

from dataclasses import dataclass, field


OP_GOTO = 0xA7
OP_TABLESWITCH = 0xAA
OP_LOOKUPSWITCH = 0xAB

INT = "I"
LONG = "J"

#: The second slot of a category-2 value (long/double). The JVM operand stack
#: counts slots, not values; this filler is what makes `dup2`/`pop2`/`swap`
#: correct by construction. It must never escape into a comparison — `pop2`
#: unwraps it, and `same_value` refuses any stack that leaked one.
VOID = object()


class JavaThrow(Exception):
    """An exception in flight: class name, message, and the thrown object."""

    def __init__(self, cls: str, message: str, obj: "Obj | None" = None):
        super().__init__(f"{cls}: {message}")
        self.cls = cls
        self.message = message
        self.obj = obj or Obj(cls, {"detailMessage": message})


class Inconclusive(Exception):
    """The model cannot decide this execution; never reported as `same`."""


class Unsupported(Exception):
    """An opcode or call the model does not cover; the caller marks the run."""


@dataclass
class Obj:
    cls: str
    fields: dict = field(default_factory=dict)
    identity: int = 0


@dataclass
class Arr:
    component: str
    items: list


@dataclass(frozen=True)
class Opaque:
    source: str
    sequence: int
    #: 0 = produced during class initialisation, 1 = during the run itself.
    #: A clinit-era Opaque is a *structural* placeholder: both sides run the
    #: same clinit, so "same source on both sides" is a real consistency
    #: check even though the value is unknowable. A run-era Opaque taints the
    #: outcome and must never read as agreement.
    epoch: int = 1


@dataclass
class Frame:
    locals: list
    stack: list
    pc: int = 0

    def push(self, v):
        """Push one category-1 slot."""
        self.stack.append(v)

    def push2(self, v):
        """Push a category-2 value: its slot plus the filler slot."""
        self.stack.append(v)
        self.stack.append(VOID)

    def pop(self):
        if not self.stack:
            raise Unsupported("stack underflow")
        return self.stack.pop()

    def pop2(self):
        """Pop a category-2 value (two slots). A wrong shape is an engine bug."""
        if len(self.stack) < 2 or self.stack[-1] is not VOID:
            raise Unsupported(
                f"corrupt operand stack: expected a two-slot value, got "
                f"{type(self.stack[-1]).__name__ if self.stack else 'empty'}")
        self.stack.pop()
        return self.stack.pop()

    def pop_int(self):
        return as_int(self.pop())

    def get(self, idx):
        return self.locals[idx]

    def set(self, idx, v):
        self.locals[idx] = v


class Heap:
    """One side of one trial. Never shared across sides or trials."""

    def __init__(self, opaque_seed: int = 0):
        self.statics: dict[tuple[str, str], object] = {}
        self.initialized: set[str] = set()
        self.objects: list[Obj] = []
        self.vfs: dict[str, object] = {}
        self.stdout: list[bytes] = []
        self.interned: dict[str, str] = {}
        self.temp_counter = 0
        #: 0 while class initialisers run, 1 once the method under test runs
        self.epoch = 0
        self._opaque = opaque_seed
        self._identity = 0

    def new_identity(self) -> int:
        self._identity += 1
        return self._identity

    def opaque(self, source: str) -> Opaque:
        self._opaque += 1
        return Opaque(source, self._opaque, self.epoch)

    def intern(self, text: str) -> str:
        return self.interned.setdefault(text, text)

    def snapshot(self) -> dict:
        return {"statics": dict(self.statics), "vfs": _snapshot_vfs(self.vfs),
                "stdout": b"".join(self.stdout)}


@dataclass
class Outcome:
    kind: str                     # return/throw/unsupported/inconclusive
    value: object = None
    exception: str = ""
    reason: str = ""
    steps: int = 0


def _snapshot_vfs(vfs: dict) -> dict:
    out = {}
    for key, value in vfs.items():
        if isinstance(value, (bytes, bytearray)):
            out[key] = "file:" + value.hex()
        else:
            out[key] = "dir"
    return out


def default_value(desc: str, heap: Heap):
    """The JVM default for a descriptor, or a model instance for objects."""
    if desc == "V":
        return None
    if desc.startswith("L"):
        name = desc[1:-1]
        if name == "java/lang/String":
            return heap.intern("")
        return make_model(name, heap)
    if desc.startswith("["):
        return None                        # an unset field is null, not an array
    return 0


def make_model(name: str, heap: Heap):
    """A deterministic instance for the interfaces/classes we model."""
    if name == "java/util/List" or name == "java/util/Collection":
        return Obj("java/util/ArrayList", {"items": []})
    if name == "java/util/Map":
        return Obj("java/util/HashMap", {"entries": {}})
    if name == "java/util/Set":
        return Obj("java/util/LinkedHashSet", {"items": []})
    if name == "java/nio/file/Path":
        return Obj(name, {"path": "/case/input"})
    if name == "java/lang/CharSequence":
        return heap.intern("")
    if name == "java/lang/StringBuilder":
        return Obj(name, {"buf": ""})
    if name in ("java/lang/Runnable",):
        return Obj(name, {"body": None})
    if name == "java/lang/Object":
        return Obj(name, {})
    return None


# --- primitive helpers ------------------------------------------------------

def as_int(v) -> int:
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, int):
        return v
    if isinstance(v, Obj) and v.cls == "java/lang/Character":
        return ord(v.fields.get("value", "\0"))
    if isinstance(v, Obj):
        # an unboxed model value (Integer.valueOf and friends)
        if "value" in v.fields:
            return as_int(v.fields["value"])
        # an object in an int context is a failed checkcast in the JVM
        # (unboxing = checkcast + intValue), which both sides can agree on
        raise JavaThrow("java/lang/ClassCastException",
                        f"{v.cls} cannot be cast to a primitive int")
    if v is None:
        # unboxing null (or indexing through null) is an NPE in the JVM, and
        # a throw the two sides can agree on
        raise JavaThrow("java/lang/NullPointerException", "unboxing null")
    if isinstance(v, Opaque):
        raise Unsupported(f"expected an int, got an Opaque value from "
                          f"{v.source}")
    raise Unsupported(f"expected an int, got {type(v).__name__}")


def is_opaque(v) -> bool:
    if isinstance(v, Opaque):
        return True
    if isinstance(v, Obj):
        return any(is_opaque(x) for x in v.fields.values())
    if isinstance(v, Arr):
        return any(is_opaque(x) for x in v.items)
    if isinstance(v, (list, tuple)):
        # model collections keep their elements in a plain list field; without
        # this branch an Opaque inside a queue silently dodged the taint
        # check and produced a false DIFF
        return any(is_opaque(x) for x in v)
    if isinstance(v, dict):
        return any(is_opaque(x) for x in v.values())
    return False


def is_run_opaque(v) -> bool:
    """Only the Opaques produced by *this* run poison a verdict."""
    if isinstance(v, Opaque):
        return v.epoch >= 1
    if isinstance(v, Obj):
        return any(is_run_opaque(x) for x in v.fields.values())
    if isinstance(v, Arr):
        return any(is_run_opaque(x) for x in v.items)
    if isinstance(v, (list, tuple)):
        return any(is_run_opaque(x) for x in v)
    if isinstance(v, dict):
        return any(is_run_opaque(x) for x in v.values())
    return False


def jstr(v) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, Obj):
        if "value" in v.fields and isinstance(v.fields["value"], str):
            return v.fields["value"]
        if v.cls == "java/lang/StringBuilder":
            return v.fields.get("buf", "")
    if v is None:
        return "null"
    if isinstance(v, Opaque):
        raise Unsupported(f"cannot render an Opaque value from {v.source} "
                          f"as a string")
    raise Unsupported(f"cannot render {type(v).__name__} as a string")


def _append_text(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, str):
        return v
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if v != v:
            return "NaN"
        if v == float("inf"):
            return "Infinity"
        if v == float("-inf"):
            return "-Infinity"
        return _java_number(v)
    if isinstance(v, Obj):
        if "buf" in v.fields:
            return v.fields["buf"]
        if "value" in v.fields:
            raw = v.fields["value"]
            if isinstance(raw, str):
                return raw
            return _append_text(raw)
        if "path" in v.fields:
            return v.fields["path"]
        return _to_text(v)
    if isinstance(v, Arr):
        return f"[{v.component}@model]"
    raise Unsupported("cannot append this value to a StringBuilder")


def _java_number(v: float) -> str:
    """Close enough to Double.toString for a differential verdict: both sides
    run the same model, so only determinism matters, not JDK formatting."""
    return repr(v)


def _to_text(obj: Obj) -> str:
    return f"{obj.cls}@model"
