"""Differential driver: run the same method from two jars on the same inputs."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..behave import Case, CaseOutcome
from .engine import Interp, Universe
from .values import (VOID, Arr, Heap, JavaThrow, Obj, Opaque, Outcome,
                     Unsupported,
                     default_value,
                     is_opaque, is_run_opaque)


@dataclass
class MethodDiff:
    row: tuple
    verdict: str                 # same/diff/inconclusive
    reason: str = ""
    trials: int = 0
    evidence: str = "value"      # value/throw, for the same/diff verdicts

    def describe(self) -> str:
        cls, name, desc = self.row
        return f"{cls}.{name}{desc}: {self.verdict}" + \
               (f" ({self.reason})" if self.reason else "")


@dataclass
class InterpReport:
    rows: list[MethodDiff] = field(default_factory=list)
    elapsed: float = 0.0

    @property
    def same(self) -> int:
        return sum(1 for r in self.rows if r.verdict == "same")

    @property
    def diff(self) -> list[MethodDiff]:
        return [r for r in self.rows if r.verdict == "diff"]

    @property
    def inconclusive(self) -> list[MethodDiff]:
        return [r for r in self.rows if r.verdict == "inconclusive"]

    @property
    def judged(self) -> int:
        return sum(1 for r in self.rows if r.verdict in ("same", "diff"))

    def summary(self) -> str:
        lines = [f"methods   : {len(self.rows)}",
                 f"same      : {self.same}",
                 f"diff      : {len(self.diff)}",
                 f"inconcl.  : {len(self.inconclusive)}",
                 f"elapsed   : {self.elapsed:.1f}s"]
        return "\n".join(lines)


def outcomes(report: InterpReport) -> list[CaseOutcome]:
    """The same shape the JVM harness produces, for `cases.coverage`."""
    out: list[CaseOutcome] = []
    for diff in report.rows:
        cls, name, desc = diff.row
        status = diff.verdict if diff.verdict in ("same", "diff") \
            else "inconclusive"
        marker = "THROW:" if diff.evidence == "throw" else "OK:"
        out.append(CaseOutcome(Case(cls, name), marker, marker, status,
                               diff.reason))
    return out


def _inputs(desc: str, heap: Heap, trial: int) -> list:
    body = desc[1:desc.index(")")]
    descs: list[str] = []
    i = 0
    while i < len(body):
        start = i
        while body[i] == "[":
            i += 1
        if body[i] == "L":
            i = body.index(";", i) + 1
        else:
            i += 1
        descs.append(body[start:i])

    pools: list[list] = []
    for d in descs:
        if d == "I" or d == "J":
            pools.append([0, 1, -1, 7])
        elif d == "Z":
            pools.append([0, 1])
        elif d in ("S", "B"):
            pools.append([0, 1, -1])
        elif d == "C":
            pools.append([ord("a"), ord("0"), ord("Z")])
        elif d in ("F", "D"):
            pools.append([0.0, 1.5, -2.5])
        elif d == "Ljava/lang/String;" or d == "Ljava/lang/CharSequence;":
            pools.append([heap.intern(""), heap.intern("a"),
                          heap.intern("hello")])
        elif d.startswith("["):
            comp = d[1:]
            fill = default_value("L" + comp + ";" if not comp.startswith("[")
                                 else comp, heap)
            pools.append([Arr(comp, []), Arr(comp, [fill])])
        elif d == "Ljava/nio/file/Path;":
            pools.append([Obj("java/nio/file/Path", {"path": "/case/a.txt"}),
                          Obj("java/nio/file/Path", {"path": "/case/missing"})])
        elif d.startswith("L"):
            # a stand-in instance is deterministic and lets the method read
            # default fields; only *calling* anything on it turns Opaque. A
            # bare Opaque input would poison every method that stores it.
            internal = d[1:-1]
            if internal in ("java/util/List", "java/util/Collection",
                            "java/util/ArrayList"):
                # an empty list filters everything away; rotate real contents
                pools.append([
                    Obj("java/util/ArrayList", {"items": []}),
                    Obj("java/util/ArrayList", {"items": [heap.intern("a")]}),
                    Obj("java/util/ArrayList",
                        {"items": [heap.intern("a"), heap.intern("bb"),
                                   heap.intern("")]}),
                ])
            elif internal in ("java/util/Map",):
                pools.append([
                    Obj("java/util/HashMap", {"entries": {}}),
                    Obj("java/util/HashMap",
                        {"entries": {"k": heap.intern("v")}}),
                ])
            else:
                model = default_value(d, heap)
                pools.append([model if model is not None
                              else Obj(internal, {})])
    if not pools:
        return []
    return [pool[trial % len(pool)] for pool in pools]


def _same_value(a, b, memo) -> bool:
    if a is VOID or b is VOID:
        raise Unsupported("a two-slot filler leaked into a comparison")
    if isinstance(a, Opaque) or isinstance(b, Opaque):
        # clinit-era Opaques are structural placeholders: both sides ran the
        # same clinit, so matching sources prove the initialisers agree on
        # *what* they could not compute. Run-era Opaques never agree.
        if isinstance(a, Opaque) and isinstance(b, Opaque):
            return a.epoch == 0 and b.epoch == 0 and a.source == b.source
        return False
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    if isinstance(a, Arr) and isinstance(b, Arr):
        key = (id(a), id(b))
        if key in memo:
            return memo[key]
        memo[key] = True
        ok = a.component == b.component and len(a.items) == len(b.items) and \
            all(_same_value(x, y, memo)
                for x, y in zip(a.items, b.items))
        memo[key] = ok
        return ok
    if isinstance(a, Obj) and isinstance(b, Obj):
        key = (id(a), id(b))
        if key in memo:
            return memo[key]
        memo[key] = True
        ok = a.cls == b.cls and _same_value(a.fields, b.fields, memo)
        memo[key] = ok
        return ok
    if isinstance(a, dict) and isinstance(b, dict):
        if set(a) != set(b):
            return False
        return all(_same_value(a[k], b[k], memo) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        # a model collection's items: without this branch every Obj holding a
        # list read as "different static state" (the false DIFF on HMCL)
        if len(a) != len(b):
            return False
        return all(_same_value(x, y, memo) for x, y in zip(a, b))
    return False


def _verdict(left: Outcome, right: Outcome,
             left_heap: Heap, right_heap: Heap):
    if left.kind in ("unsupported", "inconclusive") \
            or right.kind in ("unsupported", "inconclusive"):
        reason = left.reason or right.reason or "not modelled"
        return "inconclusive", reason
    if left.kind != right.kind:
        return "diff", f"{left.kind} vs {right.kind}"
    if left.kind == "throw":
        if left.exception != right.exception:
            return "diff", f"{left.exception} vs {right.exception}"
    elif not _same_value(left.value, right.value, {}):
        return "diff", "different return values"
    l, r = left_heap.snapshot(), right_heap.snapshot()
    if l["stdout"] != r["stdout"]:
        return "diff", "different stdout"
    if l["vfs"] != r["vfs"]:
        return "diff", "different filesystem effects"
    # Static fields are part of the observable contract: a later method could
    # read them, so anything stored into one is evidence. Opaques produced by
    # *this* run poison the verdict; clinit-era Opaques are structural
    # placeholders that `_same_value` compares by source (both sides ran the
    # same initialiser, so agreement there is a real check on the clinit).
    lstat, rstat = l["statics"], r["statics"]
    for key in set(lstat) | set(rstat):
        lv, rv = lstat.get(key), rstat.get(key)
        if is_run_opaque(lv) or is_run_opaque(rv):
            return "inconclusive", "static state depends on an unmodelled call"
        if not _same_value(lv, rv, {}):
            return "diff", f"different static state at {key[0]}.{key[1]}"
    return "same", ""


def compare_method(left_jar, right_jar, row: tuple[str, str, str],
                   *, trials: int = 4, shared_cache: dict | None = None
                   ) -> MethodDiff:
    cls, name, desc = row
    left = Universe(left_jar, shared_cache)
    right = Universe(right_jar, shared_cache)
    from .models import Models
    model = Models()
    reasons: list[str] = []
    evidence = "value"
    for trial in range(max(1, trials)):
        try:
            left_heap, right_heap = Heap(), Heap()
            args = _inputs(desc, left_heap, trial)
            right_args = _inputs(desc, right_heap, trial)
            left_it = Interp(left, left_heap, model)
            right_it = Interp(right, right_heap, model)
            # class initialisers run in epoch 0 (their Opaques are structural
            # placeholders); the method under test runs in epoch 1. A clinit
            # that throws is deterministic on both sides (same static prefix,
            # same exception later) and does not poison the run — but the two
            # sides must agree on *whether and what* it threw, otherwise the
            # remaining state diverges before the method even starts.
            init_results = []
            for it in (left_it, right_it):
                threw = ""
                try:
                    it._ensure_init(cls)
                except JavaThrow as exc:
                    threw = exc.cls
                except Exception:  # noqa: BLE001 - deterministic both sides
                    threw = "<unmodelled>"
                init_results.append(threw)
            if init_results[0] != init_results[1]:
                reasons.append("class initialisation differs: "
                               f"{init_results[0]!r} vs {init_results[1]!r}")
                continue
            left_heap.epoch = 1
            right_heap.epoch = 1
            if name == "<init>":
                left_out = left_it.invoke(
                    cls, name, desc, Obj(cls, {}), args)
                right_out = right_it.invoke(
                    cls, name, desc, Obj(cls, {}), right_args)
                if left_out.kind == "return" and right_out.kind == "return":
                    left_out.value = left_out.value or Obj(cls, {})
                    right_out.value = right_out.value or Obj(cls, {})
            else:
                left_out = left_it.invoke(
                    cls, name, desc, None, args)
                right_out = right_it.invoke(
                    cls, name, desc, None, right_args)
            verdict, reason = _verdict(left_out, right_out, left_heap,
                                       right_heap)
            evidence = ("throw" if left_out.kind == "throw" else "value")
        except Exception as exc:  # noqa: BLE001 - an engine bug is not a diff
            reasons.append(f"engine error: {type(exc).__name__}: {exc}"[:160])
            continue
        if verdict == "diff":
            return MethodDiff(row, "diff", reason, trials, evidence)
        if verdict == "inconclusive":
            reasons.append(reason)
    if reasons:
        return MethodDiff(row, "inconclusive", reasons[0], trials)
    return MethodDiff(row, "same", "", trials, evidence)


def compare_rows(left_jar, right_jar, rows, *, trials: int = 4,
                 progress=None) -> InterpReport:
    import time as _time
    report = InterpReport()
    started = _time.monotonic()
    cache: dict = {}
    for i, row in enumerate(rows or []):
        report.rows.append(compare_method(left_jar, right_jar, row,
                                          trials=trials, shared_cache=cache))
        if progress:
            progress(i + 1, len(rows))
    report.elapsed = _time.monotonic() - started
    return report
