"""Derive behaviour cases for the methods a rewrite actually touched.

Writing cases by hand does not scale: `deflat` rewrites 411 methods in a 15 MB
jar, and four hand-written cases over two of them say almost nothing. This
module reads the jar, finds the methods a rewrite changed, and generates cases
from their descriptors — statically, without executing anything.

Two things make that honest rather than a rubber stamp:

**What can be invoked at all.** The driver builds a receiver, so an instance
method no longer needs a no-arg constructor: it tries the class's own
constructor, then an enum constant, then a zero-state instance. Parameters may
be primitives, `String`, arrays or arbitrary objects (`@null` / `@new` tokens,
see `behave.py`). What stays excluded is what cannot be *observed* reliably: a
method that reads the clock, uses a RNG, starts threads or writes to the
filesystem produces different answers for reasons that have nothing to do with
the rewrite, and the denylist is per **method**, not per class — a class with one
`spawn()` helper should still contribute its pure string function.

The denylist is a list of *classes* plus *(class, method)* pairs, not package
prefixes: the old prefix rule killed every method that so much as mentioned
`java/nio/file/Path`, which is a parameter type, not an IO operation. Measured
on HMCL, that alone dropped ~40 rewritten methods that could be invoked.

**A self-consistency baseline runs first.** `原始 × 原始` is executed twice in
two *separate* JVM processes; cases whose two runs disagree are dropped. That
catches randomness and races. It does not catch everything — a second-resolution
clock still reads the same in two runs, and `HashMap` iteration order is stable
within one process — so the baseline is necessary, not sufficient, and the
denylist works alongside it.

Whatever survives is evidence. What does not survive is reported, not silently
dropped: `Derivation.dropped` carries a reason for every case that did not make
it, because "we tested 40 of 411 methods" has to be visible.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import bytecode as BC
from . import classfile as CF
from .behave import Case, compare

ACC_ABSTRACT = 0x0400
ACC_INTERFACE = 0x0200

_PRIM = {"I": "int", "J": "long", "Z": "boolean", "S": "short",
         "B": "byte", "C": "char", "D": "double", "F": "float"}

_VOID = "V"
_STRING = "Ljava/lang/String;"

# Fixed inputs. Deliberately small: MIN_VALUE / MAX_VALUE turn a loop bound
# into an out-of-memory instead of a test.
_VALUES = {
    "int": ("0", "1", "-7", "42"),
    "long": ("0", "1", "-7", "42"),
    "boolean": ("false", "true"),
    "short": ("0", "1", "-7"),
    "byte": ("0", "1", "-7"),
    "char": ("a", "0", "Z"),
    "double": ("0.0", "1.0", "-2.5"),
    "float": ("0.0", "1.0", "-2.5"),
    "java.lang.String": ("", "a", "hello", "HELLO"),
}

# Classes whose *use* is enough to make a method unobservable: threads, RNGs,
# clocks, filesystem and network writes. Over-approximate on purpose — a
# missing case costs coverage, a flaky case costs credibility.
_DENY_CLASS_PREFIX = (
    "java/lang/Thread", "java/lang/ProcessBuilder", "java/lang/Runtime",
    "java/util/Random", "java/security/SecureRandom",
    "java/util/concurrent/", "java/util/Timer",
    "java/util/Date", "java/time/Clock",
    "java/io/File", "java/io/RandomAccessFile", "java/io/PrintStream",
    "java/io/PrintWriter", "java/io/FileDescriptor",
    "java/nio/file/Files", "java/nio/channels/",
    "java/net/", "javax/net/", "javax/script/",
)

# Calling *these* is the problem, not mentioning the class: `System.out` and
# `System.arraycopy` are everywhere, `System.nanoTime` is not.
_DENY_MEMBER = {
    ("java/lang/System", "currentTimeMillis"), ("java/lang/System", "nanoTime"),
    ("java/lang/System", "identityHashCode"), ("java/lang/System", "exit"),
    ("java/lang/System", "gc"), ("java/lang/System", "load"),
    ("java/lang/System", "loadLibrary"), ("java/lang/System", "setProperty"),
    ("java/lang/System", "setSecurityManager"),
    ("java/lang/Math", "random"), ("java/lang/StrictMath", "random"),
    ("java/util/UUID", "randomUUID"),
    ("java/util/Locale", "getDefault"),
    ("java/nio/charset/Charset", "defaultCharset"),
    ("java/time/Instant", "now"), ("java/time/LocalDate", "now"),
    ("java/time/LocalTime", "now"), ("java/time/LocalDateTime", "now"),
    ("java/time/ZonedDateTime", "now"), ("java/time/OffsetDateTime", "now"),
    ("java/time/Year", "now"), ("java/time/YearMonth", "now"),
    ("java/time/MonthDay", "now"),
}

# Per-parameter inputs. `@null` / `@new` are driver tokens (see behave.py): a
# reference parameter gets a real zero-state instance instead of only null,
# which is the difference between "NPE on both sides" and an actual answer.
_REF_VALUES = ("@null", "@new")
_OBJECT_VALUES = ("@s:hello", "@null", "@new")
_BOX_VALUES = {
    "Ljava/lang/Integer;": ("@i:0", "@i:42", "@null"),
    "Ljava/lang/Long;": ("@l:0", "@l:42", "@null"),
    "Ljava/lang/Boolean;": ("@z:true", "@z:false", "@null"),
    "Ljava/lang/Double;": ("@d:1.5", "@d:0.0", "@null"),
    "Ljava/lang/Float;": ("@f:1.5", "@f:0.0", "@null"),
    "Ljava/lang/Character;": ("@c:a", "@c:Z", "@null"),
    "Ljava/lang/Byte;": ("@b:0", "@b:1", "@null"),
    "Ljava/lang/Short;": ("@h:0", "@h:1", "@null"),
}

MAX_ARITY = 8


@dataclass
class Derivation:
    """What was derived, and what was not."""

    cases: list = field(default_factory=list)
    considered: int = 0          # methods the caller asked about
    eligible: int = 0            # passed the signature filter
    dropped: dict = field(default_factory=dict)   # reason -> how many methods
    examples: list = field(default_factory=list)  # a few "class.method: why"
    reason_of: dict = field(default_factory=dict)  # (class, method) -> reason

    def note(self, reason: str, where: str = "", key=None) -> None:
        self.dropped[reason] = self.dropped.get(reason, 0) + 1
        if key is not None:
            self.reason_of[key] = reason
        if where and len(self.examples) < 8:
            self.examples.append(f"{where}: {reason}")

    def summary(self) -> str:
        if not self.considered:
            return "no methods to derive cases for"
        bits = [f"{len(self.cases)} case(s) from {self.eligible} of "
                f"{self.considered} method(s)"]
        for reason, n in sorted(self.dropped.items(), key=lambda kv: -kv[1]):
            bits.append(f"{n} {reason}")
        return "; ".join(bits)


# --------------------------------------------------------------------------
# descriptors and signatures
# --------------------------------------------------------------------------

def split_descriptor(desc: str) -> tuple[list[str], str]:
    """`(I[Ljava/lang/String;)V` -> (["I", "[Ljava/lang/String;"], "V")."""
    if not desc.startswith("("):
        raise ValueError(f"not a method descriptor: {desc!r}")
    params: list[str] = []
    i = 1
    while i < len(desc) and desc[i] != ")":
        j = i
        while j < len(desc) and desc[j] == "[":
            j += 1
        if j >= len(desc):
            raise ValueError(f"truncated descriptor: {desc!r}")
        if desc[j] == "L":
            k = desc.find(";", j)
            if k < 0:
                raise ValueError(f"unterminated class in descriptor: {desc!r}")
            params.append(desc[i:k + 1])
            i = k + 1
        else:
            params.append(desc[i:j + 1])
            i = j + 1
    if i >= len(desc):
        raise ValueError(f"descriptor has no return type: {desc!r}")
    return params, desc[i + 1:]


def _type_name(param: str) -> str | None:
    """The name the driver passes to `Class.forName`, or None if it cannot.

    Reference types are passed as `null` by the driver — a weak input, but a
    real one (it exercises null checks and the early-return paths), and the
    baseline throws away the cases that only produce an NPE on both sides.
    Array types work because `Class.forName("[I")` is the binary name of
    `int[]`; the value is null there too.
    """
    if param in _PRIM:
        return _PRIM[param]
    if param == _STRING:
        return "java.lang.String"
    if param.startswith("["):
        # `Class.forName` wants the binary name: "[I" for int[], but
        # "[Ljava.lang.String;" (dots) for a reference component.
        if param.startswith("[L") and param.endswith(";"):
            return param[:-1].replace("/", ".") + ";"
        return param
    if param.startswith("L") and param.endswith(";"):
        return param[1:-1].replace("/", ".")
    return None


def _eligible(cf, member) -> str | None:
    """None if the method can be derived, else the reason it cannot.

    A no-arg constructor is no longer required: the driver can build a receiver
    from an enum constant or as a zero-state instance, which is deterministic
    and identical on both sides. What it *cannot* do is instantiate an abstract
    class or an interface, so those instance methods stay out.
    """
    flags = member.access_flags
    name = cf.utf8(member.name_index)
    class_flags = getattr(cf, "access_flags", 0)
    if not flags & CF.ACC_STATIC and class_flags & (ACC_ABSTRACT | ACC_INTERFACE):
        return "instance method on an abstract type"
    if flags & (ACC_ABSTRACT | CF.ACC_NATIVE):
        return "abstract or native"
    if flags & CF.ACC_BRIDGE:
        # a bridge forwards to the real method: same body, same case, twice
        return "bridge"
    if flags & CF.ACC_SYNTHETIC and not (
            name.startswith("lambda$") or name.startswith("access$")):
        pass          # a lambda body is still a method with a descriptor
    if name in ("<init>", "<clinit>"):
        # no descriptor-level way to call a constructor as a method
        return "constructor or class initialiser"
    # `lambda$...` / `access$...` are synthetic but they are ordinary methods
    # with an ordinary descriptor, and they are exactly the kind of small body
    # a de-flattener rewrites: they stay in.
    try:
        params, _ret = split_descriptor(cf.utf8(member.descriptor_index))
    except (ValueError, Exception):
        return "unreadable descriptor"
    if len(params) > MAX_ARITY:
        return f"more than {MAX_ARITY} parameters"
    if any(_type_name(p) is None for p in params):
        return "unresolvable parameter type"
    # The return type is not a filter: the driver renders any object with
    # toString, and an identity hash makes both sides differ, which the
    # baseline then drops as unstable.
    return None


# Opcodes whose operand is a constant-pool index we can resolve to a name.
_CP_OPERAND = {0x12, 0x13, 0x14,                       # ldc, ldc_w, ldc2_w
               0xB2, 0xB3, 0xB4, 0xB5,                 # get/put field/static
               0xB6, 0xB7, 0xB8, 0xB9,                 # invoke*
               0xBB, 0xBD, 0xC0, 0xC1}                 # new, anewarray, checkcast, instanceof


def _resolve(cf, idx: int) -> tuple[str | None, str | None]:
    """(class name, member name) for a constant-pool index, best effort."""
    if not (0 < idx < len(cf.cp)):
        return None, None
    entry = cf.cp[idx]
    if not entry:
        return None, None
    try:
        if entry[0] == CF.C_CLASS:
            return cf.utf8(entry[1][0]), None
        if entry[0] in (CF.C_FIELDREF, CF.C_METHODREF, CF.C_INTERFACE_METHODREF):
            owner = cf.cp[entry[1][0]]
            cls = cf.utf8(owner[1][0]) if owner and owner[0] == CF.C_CLASS else None
            nt = cf.cp[entry[1][1]]
            name = (cf.utf8(nt[1][0])
                    if nt and nt[0] == CF.C_NAME_AND_TYPE else None)
            return cls, name
    except Exception:  # noqa: BLE001 - a broken entry is not a reason to stop
        return None, None
    return None, None


def _method_denied(cf, member) -> str | None:
    """Does *this method* read the clock, use a RNG, start threads or do IO?

    Per method on purpose: a class is not tainted by its siblings. Resolving the
    constants the body references is exact enough and costs one decode.
    """
    try:
        ci = BC.method_code(cf, member)
    except Exception:  # noqa: BLE001 - undecodable body, the caller drops it
        return None
    if ci is None or not ci.insns:
        return None
    for ins in ci.insns:
        if ins.op not in _CP_OPERAND or ins.arg is None:
            continue
        cls, name = _resolve(cf, ins.arg)
        if cls:
            for prefix in _DENY_CLASS_PREFIX:
                if cls.startswith(prefix):
                    return f"touches {cls}"
        if cls and name and (cls, name) in _DENY_MEMBER:
            return f"calls {cls}.{name}"
    return None


# --------------------------------------------------------------------------
# case generation
# --------------------------------------------------------------------------

def _tokens_for(param: str, per_param: int) -> tuple:
    """Inputs for one parameter, as driver tokens (see `behave.py`)."""
    if param in _PRIM:
        return _VALUES[_PRIM[param]]
    if param == _STRING:
        return _VALUES["java.lang.String"]
    if param.startswith("["):
        return ("@arr0", "@arr1")
    if param in _BOX_VALUES:
        return _BOX_VALUES[param]
    if param in ("Ljava/lang/Object;", "Ljava/lang/CharSequence;"):
        return _OBJECT_VALUES
    return _REF_VALUES


def _cases_for(cls: str, name: str, params: list[str], per_param: int) -> list[Case]:
    types = tuple(_type_name(p) for p in params)
    if not types:
        return [Case(cls, name, (), ())]
    pools = [_tokens_for(p, per_param) for p in params]
    if len(types) == 1:
        return [Case(cls, name, types, (v,)) for v in pools[0][:per_param]]
    # Several parameters: walk them pairwise instead of taking the product.
    # Size stays linear and every value still appears across the set.
    out = []
    for k in range(per_param):
        out.append(Case(cls, name, types, tuple(p[k % len(p)] for p in pools)))
    return out


def derive(jar: Path, rewritten=None, *, per_param: int = 4) -> Derivation:
    """Generate cases for `rewritten` methods (or every method when None).

    `rewritten` is `[(internal/class/Name, method, descriptor)]`, exactly what
    `deflat` / `devirt` report in `stats["rewritten"]`. Only those classes are
    opened, which is what keeps this cheap on a 3740-class jar.
    """
    want: dict[str, list[tuple[str, str]]] = {}
    der = Derivation()
    if rewritten:
        for cls, name, desc in rewritten:
            want.setdefault(cls, []).append((name, desc))
            der.considered += 1

    with zipfile.ZipFile(jar) as z:
        names = set(z.namelist())
        for cls, methods in want.items():
            entry = cls + ".class"
            if entry not in names:
                for name, _desc in methods:
                    der.note("class not in the jar", f"{cls}.{name}")
                continue
            try:
                cf = CF.parse(z.read(entry))
            except Exception:  # noqa: BLE001 - unreadable class, no cases
                for name, _desc in methods:
                    der.note("class did not parse", f"{cls}.{name}")
                continue
            by_sig = {(cf.utf8(m.name_index), cf.utf8(m.descriptor_index)): m
                      for m in cf.methods}
            for name, desc in methods:
                member = by_sig.get((name, desc))
                if member is None:
                    der.note("method not found", f"{cls}.{name}")
                    continue
                reason = _eligible(cf, member)
                if reason:
                    der.note(reason, f"{cls}.{name}", key=(cls, name))
                    continue
                denied = _method_denied(cf, member)
                if denied:
                    der.note(denied, f"{cls}.{name}", key=(cls, name))
                    continue
                params, _ret = split_descriptor(desc)
                cases = _cases_for(cf.name, name, params, per_param)
                if not cases:
                    der.note("no usable inputs", f"{cls}.{name}")
                    continue
                der.eligible += 1
                der.cases.extend(cases)
    return der


def stabilise(cases: list[Case], jar: Path, *, java: str | None = None,
              timeout: int = 300, classpath=(),
              sandbox: bool = False) -> tuple[list[Case], dict]:
    """Keep the cases that are worth running against the rewrite.

    Two filters, both measured on `original × original`:

    **stable** — `compare` starts a fresh JVM per call, so two calls are two
    processes: a method reading a clock, iterating a hash map or racing with
    itself has a real chance to differ. Such a case can never be evidence.

    **judged** — a case that throws on one side and not the other, or that the
    driver could not invoke at all, is not evidence. A case that throws the
    *same* exception twice is: the same input produced the same observable
    outcome. It is weaker than a returned value (`pick(null)` NPE-ing at entry
    says little), so it is kept and counted apart (`throws`) instead of being
    thrown away.
    """
    counts = {"unstable": 0, "throws": 0, "kept": 0}
    if not cases:
        return [], counts
    first = compare(jar, jar, cases, java=java, timeout=timeout,
                    classpath=classpath, sandbox=sandbox)
    second = compare(jar, jar, cases, java=java, timeout=timeout,
                     classpath=classpath, sandbox=sandbox)
    keep: list[Case] = []
    for i, case in enumerate(cases):
        a = first.outcomes[i] if i < len(first.outcomes) else None
        b = second.outcomes[i] if i < len(second.outcomes) else None
        if not (a is not None and b is not None and a.judged and b.judged
                and a.status == "same" and b.status == "same"
                and a.left == b.left):
            counts["unstable"] += 1
            continue
        if not a.left.startswith("OK:"):
            counts["throws"] += 1
        keep.append(case)
    counts["kept"] = len(keep)
    return keep, counts


# --------------------------------------------------------------------------
# coverage
# --------------------------------------------------------------------------

def coverage(rows, outcomes, der=None, kept=None) -> dict:
    """How many of the rewritten methods actually produced a verdict.

    `rows` is what `deflat --rewritten` wrote, `outcomes` what `behave` saw,
    `der` the derivation (it knows why a method never got a case) and `kept`
    the cases that survived the stability baseline.

    A method counts as judged when at least one case reached it and both jars
    agreed; the kinds are kept apart because a returned value is stronger
    evidence than an identical exception. Every method that is *not* judged
    carries the reason it was not, including "the class would not load" —
    which is the difference between "we chose not to test it" and "it cannot
    be tested here".
    """
    rank = {"none": 0, "throw": 1, "value": 2}
    best: dict[tuple[str, str], str] = {}
    why: dict[tuple[str, str], str] = {}
    for o in outcomes:
        key = (o.case.cls, o.case.method)
        if rank[o.evidence] > rank.get(best.get(key, "none"), 0):
            best[key] = o.evidence
        if o.status in ("unusable", "inconclusive") and key not in why:
            # the driver's own words beat our summary: "NoClassDefFoundError:
            # net/minecraft/client/Minecraft" says *why*, "could not be
            # invoked" only says *that*
            detail = ""
            for side in (o.left, o.right):
                if side.startswith("ERROR:"):
                    detail = side[len("ERROR:"):]
                    break
            if not detail:
                detail = (o.reason or o.left or "").strip() or "not invokable"
            prefix = "inconclusive: " if o.status == "inconclusive" \
                else "unusable at runtime: "
            why[key] = prefix + detail[:120]
    reasons = {} if der is None else getattr(der, "reason_of", {})
    kept_keys = None if kept is None else {(c.cls, c.method) for c in kept}
    total = len({(c, n) for c, n, _d in rows}) if rows else len(best)
    value = sum(1 for v in best.values() if v == "value")
    throw = sum(1 for v in best.values() if v == "throw")
    missing = []            # [(class, method, why)]
    wanted = ({(c, n) for c, n, _d in rows} if rows else set(best))
    for key in sorted(wanted):
        if best.get(key) in ("value", "throw"):
            continue
        if key in reasons:
            reason = reasons[key]
        elif kept_keys is not None and key not in kept_keys:
            reason = ("every input was dropped by the stability baseline "
                      "(the original disagreed with itself)")
        else:
            reason = why.get(key, "cases were derived but none produced a "
                                  "verdict")
        missing.append((key[0], key[1], reason))
    return {"total": total, "judged": value + throw, "value": value,
            "throw": throw, "missing": missing}
