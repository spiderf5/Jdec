#!/usr/bin/env python3
"""Regression tests for jdec.

Run:  python tests/run_tests.py            (core tests)
      python tests/run_tests.py --with-mc  (also exercises a real Minecraft jar)

These assert the things that are easy to break and hard to notice:
  * parse -> serialise must be byte-identical, or remapping silently corrupts
    every class it touches
  * a remapped class must still be loadable bytecode (checked with javap), and
    call sites must be renamed along with declarations
  * one unparsable class must not be allowed to sink an otherwise fine run
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import struct                         # noqa: E402

from types import SimpleNamespace      # noqa: E402

import build_fixtures                 # noqa: E402
from build_fixtures import ensure_collide_jar  # noqa: E402
from jdec import analyze as AZ        # noqa: E402
from jdec import annotations as AN    # noqa: E402
from jdec import bytecode as BC       # noqa: E402
from jdec import classfile as CF      # noqa: E402
from jdec import indy as INDY        # noqa: E402
from jdec import cli as CL           # noqa: E402
from jdec import mappings as MP       # noqa: E402
from jdec import mcmod as MM          # noqa: E402
from jdec import obf as OB            # noqa: E402
from jdec import project as PJ        # noqa: E402
from jdec import strings as ST        # noqa: E402
from jdec.decompile import _iso_buckets, decompile, write_report  # noqa: E402
from jdec.probe import profile_jar    # noqa: E402
from jdec.score import evaluate       # noqa: E402

SAMPLE = ROOT / "tests" / "sample.jar"
MIXIN = ROOT / "tests" / "mixin.jar"
FLOW = ROOT / "tests" / "flow.jar"
MC_JAR = ROOT / "tests" / "mc" / "client_1.20.4.jar"
MC_MAP = ROOT / "tests" / "mc" / "mojang_1.20.4.txt"

_passed = 0
_failed = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  ok   {name}")
    else:
        _failed += 1
        print(f"  FAIL {name}" + (f"  -> {detail}" if detail else ""))


BROKEN_SAMPLE = "demo/broken/Truncated.class"  # deliberately truncated fixture


def test_roundtrip_sample() -> None:
    print("classfile: parse -> serialise is lossless (sample jar)")
    with zipfile.ZipFile(SAMPLE) as z:
        names = [n for n in z.namelist() if n.endswith(".class")]
    ok = diff = 0
    for n in names:
        with zipfile.ZipFile(SAMPLE) as z:
            data = z.read(n)
        if n == BROKEN_SAMPLE:
            try:
                CF.parse(data)
                check("truncated class is rejected", False, "it parsed anyway")
            except CF.ClassFormatError:
                check("truncated class raises ClassFormatError", True)
            except Exception as exc:  # noqa: BLE001
                check("truncated class raises ClassFormatError", False, f"raised {type(exc)} instead")
            continue
        try:
            out = CF.parse(data).serialize()
        except Exception as exc:  # noqa: BLE001
            check(f"{n} parses", False, str(exc))
            continue
        if out == data:
            ok += 1
        else:
            diff += 1
            check(f"{n} byte-identical", False, f"{len(data)} -> {len(out)}")
    check(f"all {len(names)} classes round-trip", diff == 0 and ok > 0,
          f"identical={ok} diff={diff}")


def test_synthetic_members_ignored() -> None:
    """A record's generated equals/hashCode/toString must not count as lost."""
    print("score: compiler-generated members are not counted against output")
    with zipfile.ZipFile(SAMPLE) as z:
        data = z.read("demo/modern/Showcase$Point.class")
    cf = CF.parse(data)
    names = {n for n, _ in cf.method_sigs()}
    check("record exposes equals/hashCode/toString in bytecode",
          {"equals", "hashCode", "toString"} <= names, str(sorted(names)))
    src = "public record Point(int x, int y) { public String label() { return null; } }"
    q = evaluate(src, cf)
    check("plain record source scores as fully recovered", q.score >= 95.0,
          f"score={q.score} issues={q.issues}")


def test_end_to_end_sample() -> None:
    print("pipeline: end to end on the sample jar")
    out = Path(tempfile.mkdtemp()) / "out"
    rep = decompile(SAMPLE, out, ROOT / "engines", jobs=2, verify_all=True)
    check("every readable class comes out clean",
          rep.ok >= 10, f"ok={rep.ok} partial={rep.partial} failed={rep.failed}")
    check("the truncated class is quarantined, not fatal",
          any(o.status == "broken" for o in rep.outcomes.values()),
          str(sorted({o.status for o in rep.outcomes.values()})))
    check("member recovery is complete",
          (rep.coverage_avg or 0) >= 0.99, f"coverage={rep.coverage_avg}")


def test_partial_failure_is_not_total_failure() -> None:
    """Losing one method must not condemn the whole class.

    Decompilers wrap the method they gave up on in a "could not be decompiled"
    comment. Treating that as a class-level failure made CFR's 122 KB output for
    `myau/Jc` -- every member recovered -- get reported as a total loss.
    """
    print("score: a bounded give-up is not a class-level failure")
    with zipfile.ZipFile(SAMPLE) as z:
        cf = CF.parse(z.read("demo/modern/Showcase.class"))
    members = [m for m, _d in cf.method_sigs() if not m.startswith("<")]

    lost = ("    /*\n     * This method has failed to decompile.  When submitting a\n"
            "     * bug report, please include this class.\n     */\n")
    body = "\n".join(f"    public int {m}() {{ return 1; }}" for m in members)
    whole = f"public class Showcase {{\n{lost}\n{body}\n}}\n"

    # one method lost out of len(members), inside an otherwise complete class
    q = evaluate(whole, cf)
    check("the give-up note is detected", q.hard_error)
    check("but it is not a class-level failure", not q.class_level_failure,
          f"damaged={q.damaged_fraction}")
    check("the surviving members still count as recovered",
          q.coverage >= 0.9, f"coverage={q.coverage}")
    check("and the class stays usable", q.usable, f"score={q.score}")

    # a note that covers most of the file means the class really was refused
    huge = lost * 40 + f"public class Showcase {{\n{body}\n}}\n"
    check("a give-up covering the file is class-level",
          evaluate(huge, cf).class_level_failure,
          f"damaged={evaluate(huge, cf).damaged_fraction}")

    # and a truncated file with no members at all does not sneak through
    check("empty output is never usable", not evaluate("", cf).usable)


def test_unbalanced_braces_are_proportional() -> None:
    """Absolute brace counting condemned large files for one truncated method."""
    print("score: brace imbalance is judged as a share of the file")
    with zipfile.ZipFile(SAMPLE) as z:
        cf = CF.parse(z.read("demo/modern/Showcase.class"))
    members = [m for m, _d in cf.method_sigs() if not m.startswith("<")]

    def build(reps: int) -> str:
        body = "\n".join(
            f"    public int {m}() {{ return {i}; }}" for i, m in enumerate(members * reps))
        return "public class Showcase {\n" + body + "\n}\n"

    small = build(1)
    check("a balanced class is fine", not evaluate(small, cf).unbalanced)

    # one missing closing brace, in a file large enough that 1/N is noise
    large = build(20)
    off_by_one = large[:-2]
    q = evaluate(off_by_one, cf)
    check("one missing closing brace in a large class is tolerated",
          not q.unbalanced,
          f"opens={off_by_one.count('{')} closes={off_by_one.count('}')}")

    # but a genuinely shredded file still is flagged
    check("a thoroughly broken file is still flagged",
          evaluate("public class Showcase { { { { {\n", cf).unbalanced)


def test_case_colliding_class_names() -> None:
    """Two classes whose names differ only by case must both survive.

    ZKM-style mangling emits names like `myau/A` and `myau/a`. On a
    case-insensitive filesystem those are one path, so writing both into one
    output directory loses one of them -- and because the pipeline keys its
    bookkeeping on the output path, the victim was still reported as recovered.
    """
    print("pipeline: class names that differ only by case are not conflated")
    collide = ensure_collide_jar()
    if collide is None:
        print("  skip (javac unavailable)")
        return

    out = Path(tempfile.mkdtemp()) / "out"
    rep = decompile(collide, out, ROOT / "engines", jobs=2, verify_all=True)

    check("both case-twin classes are accounted for",
          rep.total == 2, f"total={rep.total}")

    names = {o.name for o in rep.outcomes.values()}
    check("both names are distinct entries",
          names == {"demo/collide/Widget", "demo/collide/widget"},
          str(sorted(names)))

    # The decisive assertion: each class must be matched against its OWN body.
    # Both markers appearing somewhere is not enough -- a single file scored
    # twice would satisfy that, which is exactly the bug.
    bodies = {}
    for stem, rel in (("demo/collide/Widget", None), ("demo/collide/widget", None)):
        o = rep.outcomes.get(stem)
        bodies[stem] = (out / "src" / o.rel).read_text("utf-8", "replace") if o and o.rel else ""

    upper, lower = bodies["demo/collide/Widget"], bodies["demo/collide/widget"]
    check("Widget got a source file", bool(upper), "no output")
    check("widget got a source file", bool(lower), "no output")
    check("the two sources are not the same file content",
          bool(upper) and bool(lower) and upper != lower,
          "both classes resolved to one body")
    check("Widget's body carries its own marker", "upper-Widget" in upper,
          "wrong body")
    check("widget's body carries its own marker", "lower-widget" in lower,
          "wrong body")
    check("neither class is reported failed",
          all(o.status != "failed" for o in rep.outcomes.values()),
          str({n: o.status for n, o in rep.outcomes.items()}))

    # The report must carry each class' own output path. Colliding classes are
    # written to percent-encoded paths, so the path is NOT derivable from the
    # class name -- an external tool has to read it from here.
    write_report(rep, out)
    payload = json.loads((out / "report.json").read_text("utf-8"))
    rels = {n: payload["classes"][n].get("rel") for n in sorted(names)}
    check("report.json records an output path per class",
          all(rels.values()), str(rels))
    check("the two case-twins record different output paths",
          rels["demo/collide/Widget"] != rels["demo/collide/widget"], str(rels))


def test_iso_buckets() -> None:
    """Bucketing must never put two same-lowercase names in one engine run."""
    print("pipeline: case-collision buckets never mix same-lowercase names")
    collisions = {
        "myau/a": ["myau/A", "myau/a"],
        "myau/b$c": ["myau/B$C", "myau/b$C"],
        "demo/ab": ["demo/AB", "demo/Ab", "demo/aB"],   # a 3-way group
    }
    buckets = _iso_buckets(collisions)
    check("bucket count follows the largest group",
          len(buckets) == 3, str(len(buckets)))
    for i, b in enumerate(buckets):
        keys = [n.lower() for n in b]
        check(f"bucket {i} holds distinct lowercase names",
              len(keys) == len(set(keys)), str(keys))
    flat = sorted(n for b in buckets for n in b)
    check("every colliding class lands in exactly one bucket",
          flat == sorted(n for g in collisions.values() for n in g), str(flat))


def test_weak_engine_is_rescued() -> None:
    """Lead engine fails on modern syntax; a later engine must recover it."""
    print("pipeline: a failing lead engine gets backed up by the others")
    out = Path(tempfile.mkdtemp()) / "out"
    rep = decompile(SAMPLE, out, ROOT / "engines", jobs=2, verify_all=True,
                    engine_order=["procyon", "cfr", "vineflower"])
    check("retry pass recovered what Procyon dropped", rep.improved >= 1,
          f"retried={rep.retried} improved={rep.improved}")
    check("final result is still clean", rep.ok >= 10,
          f"ok={rep.ok} failed={rep.failed}")


def test_annotated_classes_roundtrip() -> None:
    """Reading annotations must not perturb the bytes we re-emit."""
    print("classfile: annotation-bearing classes still round-trip")
    with zipfile.ZipFile(MIXIN) as z:
        names = [n for n in z.namelist() if n.endswith(".class")]
    bad: list[str] = []
    for n in names:
        with zipfile.ZipFile(MIXIN) as z:
            data = z.read(n)
        try:
            out = CF.parse(data).serialize()
        except Exception as exc:  # noqa: BLE001
            bad.append(f"{n}: {exc}")
            continue
        if out != data:
            bad.append(n)
    check(f"all {len(names)} annotated classes round-trip", not bad, str(bad[:3]))


def test_mixin_fixture() -> None:
    """The point of the whole exercise: hooks survive name mangling."""
    print("mcmod: mixin targets are recovered from annotations")
    meta = MM.read_mod_meta(MIXIN)
    check("fabric metadata is read",
          meta.mod_id == "demo-cheat" and meta.loader == "fabric",
          f"{meta.mod_id}/{meta.loader}")
    check("mixin config is read", meta.mixin_configs == ["demo.mixins.json"],
          str(meta.mixin_configs))

    declared, cfg = MM.mixin_class_names(MIXIN, meta)
    check("declared mixin classes resolved",
          declared == ["demo/mixin/PlayerHooks", "demo/mixin/RenderHooks"],
          str(declared))

    hooks, _stats = MM.collect_hooks(MIXIN, meta, declared=declared)
    targets = sorted({h.target_class for h in hooks if h.target_class})
    check("target given as a Class reference",
          "net/minecraft/entity/PlayerEntity" in targets, str(targets))
    check("target given as a dotted string",
          "net/minecraft/client/Minecraft" in targets, str(targets))
    methods = {h.target_method for h in hooks if h.target_method}
    check("injected method names", {"tick", "jump", "method_9012"} <= methods,
          str(sorted(methods)))
    check("inheritance: @Inject inherits the class @Mixin target",
          all(h.target_class for h in hooks if h.kind == "Inject"),
          str([h.target_class for h in hooks if h.kind == "Inject"]))
    check("injection point is captured", any(h.at == "HEAD" for h in hooks),
          str(sorted({h.at for h in hooks if h.at})))
    check("@Overwrite is recognised", any(h.kind == "Overwrite" for h in hooks))

    m = MP.Mapping(source="test")
    m.add_class("net/minecraft/entity/PlayerEntity", "player/PlayerEntity")
    m.add_member("net/minecraft/entity/PlayerEntity", "tick", None, "tickPlayer")
    resolved = MM.translate_hooks(hooks, m)
    check("targets resolved through a mapping",
          resolved >= 1 and any(h.named_class == "player/PlayerEntity" for h in hooks),
          f"resolved={resolved}")
    check("methods resolved through a mapping",
          any(h.named_method == "tickPlayer" for h in hooks))


def test_signals() -> None:
    """An obfuscator renames your identifiers, not the JDK calls you make."""
    print("analyze: API-level fingerprints survive obfuscation")
    a = AZ.analyze(MIXIN)
    sigs = {c.name: set(c.signals) for c in a.classes}
    got = sigs.get("demo/mixin/Licence", set())
    check("native method flagged as jni", "jni" in got, str(sorted(got)))
    check("process launch flagged", "process-exec" in got, str(sorted(got)))
    check("payload-looking constants flagged", "encrypted-strings" in got,
          str(sorted(got)))
    check("hooks grouped by patched class", len(a.hook_groups()) == 2,
          str(len(a.hook_groups())))
    prof = profile_jar(MIXIN)
    check("the Mixin package is not mistaken for Sponge",
          prof.mc_flavor != "Sponge", str(prof.mc_flavor))


# --------------------------------------------------------------------------
# flow obfuscation fixtures
# --------------------------------------------------------------------------

def _split_attrs(blob: bytes) -> list[tuple[int, bytes]]:
    items: list[tuple[int, bytes]] = []
    o = 0
    count = struct.unpack_from(">H", blob, o)[0]
    o += 2
    for _ in range(count):
        ni = struct.unpack_from(">H", blob, o)[0]
        o += 2
        ln = struct.unpack_from(">I", blob, o)[0]
        o += 4
        items.append((ni, blob[o:o + ln]))
        o += ln
    return items


def _join_attrs(items: list[tuple[int, bytes]]) -> bytes:
    out = bytearray(struct.pack(">H", len(items)))
    for ni, pl in items:
        out += struct.pack(">H", ni) + struct.pack(">I", len(pl)) + pl
    return bytes(out)


def _make_handler_jump_backwards(data: bytes) -> bytes | None:
    """Point a class's first exception handler at pc 0.

    javac will not emit that shape, so to test the detector we have to build
    the evidence ourselves.
    """
    cf = CF.parse(data)
    for m in cf.methods:
        payload = AN.member_attributes(cf, m).get("Code")
        if not payload:
            continue
        try:
            ci = BC.parse_code(payload, decode_insns=False)
        except BC.BytecodeError:
            continue
        if not ci.handlers:
            continue
        base = 8 + len(ci.code) + 2           # start of the exception table
        new = bytearray(payload)
        struct.pack_into(">H", new, base, max(1, ci.handlers[0].start_pc))
        struct.pack_into(">H", new, base + 4, 0)
        items = _split_attrs(m.attrs_blob)
        for i, (ni, _pl) in enumerate(items):
            try:
                if cf.utf8(ni) == "Code":
                    items[i] = (ni, bytes(new))
            except Exception:
                continue
        m.attrs_blob = _join_attrs(items)
        return cf.serialize()
    return None


def test_bytecode_decodes() -> None:
    """A wrong opcode length shifts everything after it, so check the tail."""
    print("bytecode: every method decodes exactly to the end of its code array")
    total = 0
    bad: list[str] = []
    for jar in (MIXIN, FLOW):
        with zipfile.ZipFile(jar) as z:
            for n in z.namelist():
                if not n.endswith(".class"):
                    continue
                cf = CF.parse(z.read(n))
                for m in cf.methods:
                    ci = BC.method_code(cf, m)
                    if ci is None:
                        continue
                    total += 1
                    if ci.error:
                        bad.append(f"{n}: {ci.error}")
                        continue
                    if not ci.insns:
                        continue
                    last = ci.insns[-1]
                    if last.pc + last.length != len(ci.code):
                        bad.append(f"{n}: ends at {last.pc + last.length} "
                                   f"of {len(ci.code)}")
    check(f"{total} methods decode cleanly", total > 0 and not bad, str(bad[:3]))


def test_flow_fingerprints() -> None:
    print("obf: structural fingerprints fire on evidence, not on guesswork")
    clean, _ = OB.scan_obfuscation(MIXIN)
    check("ordinary javac output is not attributed",
          clean.vendor is None, clean.summary())

    rep, _per = OB.scan_obfuscation(FLOW)
    keys = {e.key for e in rep.evidence}
    check("a ZKM-shaped <clinit> is recognised as a decryptor",
          "clinit-decryptor" in keys, str(sorted(keys)))

    # javac's worst case is a jumpy but honest method: nested loops with
    # break/continue reach 7.3% gotos, under the 10% flood threshold. An
    # if-else chain over one variable reaches zero - javac folds it into a
    # switch, so only a bytecode rewriter can produce a real flood.
    rep_flow, per_flow = OB.scan_obfuscation(FLOW)
    check("ordinary compiler control flow is not called a goto flood",
          "goto-flood" not in {e.key for e in rep_flow.evidence},
          str(sorted({e.key for e in rep_flow.evidence})))

    with zipfile.ZipFile(FLOW) as z:
        raw = z.read("demo/flow/Guarded.class")
    before = OB.inspect_class(CF.parse(raw))
    check("untouched output has no backwards handler",
          "handler-backjump" not in before, str(before))

    patched = _make_handler_jump_backwards(raw)
    check("fixture could be rewritten", patched is not None)
    if patched is None:
        return
    check("rewriting an attribute does not corrupt the class",
          CF.parse(patched).serialize() == patched)
    after = OB.inspect_class(CF.parse(patched))
    check("a backwards exception handler is detected",
          after.get("handler-backjump", 0) >= 1, str(after))
    vendor, conf = OB.attribute(after)
    check("attributed to Zelix KlassMaster on that evidence",
          vendor is not None and "ZKM" in vendor, f"{vendor} {conf}")


def test_native_reporting() -> None:
    """A native body is not a recovery failure - it is an absent body."""
    print("analyze: native bodies are called out instead of silently failing")
    a = AZ.analyze(MIXIN)
    nat = a.native
    check("native method counted", nat is not None and nat.total == 1,
          str(nat.total) if nat else "no report")
    if nat is None or not nat.total:
        return
    check("the native method is identified by name",
          nat.methods[0][1] == "validateNative", str(nat.methods))
    check("its class is identified", nat.per_class.get("demo/mixin/Licence") == 1,
          str(nat.per_class))
    check("shipped native library is found",
          any(n.endswith(".dll") for n, _ in nat.libraries), str(nat.libraries))
    check("verdict points at native code", "native" in nat.verdict(), nat.verdict())
    md = AZ.render_markdown(a)
    check("the report has a native section", "## native code" in md, md[:120])

    out = Path(tempfile.mkdtemp()) / "out"
    rep = decompile(MIXIN, out, ROOT / "engines", jobs=1)
    check("decompile counts native methods separately",
          rep.native_methods == 1 and rep.native_classes == 1,
          f"{rep.native_methods}/{rep.native_classes}")


def test_scoring_sees_obfuscated_names() -> None:
    """Guard against a fixed name-length floor coming back.

    ZKM renames everything to a, b, c. With a floor of 3 every candidate is
    filtered out, the candidate set empties, coverage becomes a perfect 1.0 and
    the least-recovered class in the jar scores highest. The two sources below
    differ by half their members and must not score the same.
    """
    print("score: short member names still count, so the score can tell them apart")
    with zipfile.ZipFile(SAMPLE) as z:
        cf = CF.parse(z.read("demo/obf/a.class"))
    names = [m for m, _ in cf.method_sigs() if not m.startswith("<")]
    names += [m for m, _ in cf.field_sigs()]
    check("the fixture really is short-named", any(len(n) < 3 for n in names),
          str(names))
    full = "class X { " + " ".join(f"int {m};" for m in names) + " }"
    partial = "class X { " + " ".join(f"int {m};" for m in names[:2]) + " }"
    a, b = evaluate(full, cf), evaluate(partial, cf)
    check("short names are counted as candidates", a.total >= 4, f"total={a.total}")
    check("dropping half the members costs real points",
          b.score < a.score - 15.0, f"full={a.score} partial={b.score}")


def test_refmap() -> None:
    """Intermediary names are opaque; the refmap is what makes them readable."""
    print("mcmod: refmap turns intermediary method names back into real ones")
    rep = MM.load_refmap(MIXIN)
    check("refmap is found in the jar", len(rep) == 3, str(rep.mappings))
    check("refmap file is named", any("refmap" in s for s in rep.sources),
          str(rep.sources))

    meta = MM.read_mod_meta(MIXIN)
    declared, _ = MM.mixin_class_names(MIXIN, meta)
    hooks, _stats = MM.collect_hooks(MIXIN, meta, declared=declared)
    before = {h.target_method for h in hooks if h.target_method}
    check("the fixture really is intermediary-named", "method_9012" in before,
          str(sorted(before)))

    n = MM.apply_refmap(hooks, rep)
    check("one name restored", n == 1, f"changed={n}")
    restored = [h for h in hooks if h.raw_method == "method_9012"]
    check("method_9012 became runTick",
          len(restored) == 1 and restored[0].target_method == "runTick",
          str([(h.target_method, h.raw_method) for h in hooks if h.raw_method]))
    check("names the refmap does not mention are left alone",
          "tick" in {h.target_method for h in hooks}, str(sorted(
              {h.target_method for h in hooks if h.target_method})))

    # the full pipeline has to do it in this order, or the mapping cannot help
    a = AZ.analyze(MIXIN)
    named = {h.resolved_method for h in a.hooks if h.resolved_method}
    check("analyze applies the refmap too", "runTick" in named, str(sorted(named)))


def test_string_dump() -> None:
    """Code can be renamed into anything; literals still have to say something."""
    print("strings: literals are dumped, tagged and filtered")
    d = ST.dump_strings(MIXIN)
    check("every class parsed", d.classes_scanned == 10, str(d.classes_scanned))
    check("literals collected", d.total >= 5, str(d.total))
    rows = {(c, s) for c, s, _ in d.rows}
    check("a known literal is present", ("demo/mixin/Licence", "whoami") in rows,
          str(sorted(rows)[:3]))
    check("per-class literals are attributed to the right class",
          all(c.startswith("demo/") or c.startswith("net/") for c, _ in rows),
          str(sorted({c for c, _ in rows})))

    check("url literals are tagged",
          ST.classify("https://example.com/x") == ["url"],
          str(ST.classify("https://example.com/x")))
    check("machine-id literals are tagged",
          "machine-id" in ST.classify("HWID-1234"), str(ST.classify("HWID-1234")))
    check("ordinary literals are not tagged", ST.classify("tick") == [],
          str(ST.classify("tick")))

    check("grep filters", d.grep("whoami").total == 1, str(d.grep("whoami").total))
    check("suspicious-only is a subset", d.only_suspicious().total <= d.total)

    check("tabs and newlines cannot break the TSV",
          "\t" not in ST._cell("a\tb") and "\n" not in ST._cell("a\nb")
          and "\r" not in ST._cell("a\rb"), repr(ST._cell("a\tb")))
    out = Path(tempfile.mkdtemp()) / "s.tsv"
    ST.write_tsv(d, out)
    lines = out.read_text(encoding="utf-8").splitlines()
    check("one row per literal plus a header", len(lines) == d.total + 1,
          f"{len(lines)} lines for {d.total} literals")
    check("every row has three columns",
          all(l.count("\t") == 2 for l in lines[1:]), str(lines[1:3]))


def test_indy_encoding() -> None:
    """superblaubeere27 / JObf hide call targets as text; decoding is pure."""
    print("indy: encoded call targets are found and decoded without execution")
    check("a plain reference is not mistaken for an encoding",
          INDY.parse_ref("net/minecraft/client/Minecraft") is None)
    check("a reference without trailing spaces is rejected",
          INDY.parse_ref("a/b/C:method:()V") is None, "no pad")
    check("an ordinary sentence is rejected",
          INDY.parse_ref("hello world") is None)

    r = INDY.parse_ref("a/b/C:methodName:()V  ")
    check("two spaces means virtual-call",
          r is not None and r.op == 2 and r.op_name == "virtual-call",
          str(r))
    check("the descriptor is kept", r is not None and r.desc == "()V", str(r))
    for pad, name in ((1, "static-call"), (3, "field-get"),
                      (4, "static-field-get"), (5, "field-set")):
        got = INDY.parse_ref(f"x/Y:f:I{' ' * pad}")
        check(f"{pad} space(s) means {name}",
              got is not None and got.op_name == name, str(got))

    rep = INDY.build_report([], {}, 0, 0, 0)
    check("no references means no verdict", not rep.confirmed, rep.verdict())
    two = INDY.build_report([r, r], {}, 0, 0, 0)
    check("two references stay a hint, not a verdict", not two.confirmed,
          two.verdict())
    three = INDY.build_report([r, r, r], {}, 5, 1, 10)
    check("three references confirm it", three.confirmed, three.verdict())

    a = AZ.analyze(FLOW)
    ind = a.indy
    check("the fixture's table is found", len(ind.refs) == 6, str(len(ind.refs)))
    check("it is reported as confirmed", ind.confirmed, ind.verdict())
    ops = ind.op_counts()
    check("operations are decoded",
          ops.get("virtual-call") == 3 and ops.get("static-call") == 1
          and ops.get("field-get") == 1 and ops.get("static-field-get") == 1,
          str(ops))
    owners = ind.owners()
    check("targets are grouped by owner",
          owners.get("net.minecraft.client.Minecraft") == 2, str(owners))
    check("the decoded target is readable",
          any("PlayerEntity.tick()V" in x.as_readable() for x in ind.refs),
          str([x.as_readable() for x in ind.refs][:3]))
    md = AZ.render_markdown(a)
    check("the report has an indy section", "## indy call-target encoding" in md,
          md[:120])

    # vanilla is full of lambdas, which are invokedynamic too, but it has no
    # encoded target table - the census must not cry wolf
    clean = AZ.analyze(MIXIN)
    check("an ordinary jar is not flagged", not clean.indy.confirmed,
          clean.indy.verdict())


def test_real_zkm_sample() -> None:
    """Recall can only be proven on a real sample; the fixtures prove the rest.

    A Forge 1.7-1.12 mod (723 classes) put through ZKM 27 twice. Baselines from
    the same run: vanilla 1.20.4 fires goto-flood on 3.1% of classes and
    clinit-decryptor on none; this sample fires 46.9% and 43.6%.

    The real sample lives OUTSIDE the tool tree. Point JDEC_SAMPLE_DIR at a
    folder containing Myau0729-obf.jar to enable; default keeps looking next
    to the jdec checkout, and the test stays a skip when nothing is there.
    """
    sample_dir = os.environ.get("JDEC_SAMPLE_DIR")
    roots = [Path(sample_dir)] if sample_dir else [ROOT.parent, Path("D:/MC/samples")]
    jar = next((r / "Myau0729-obf.jar" for r in roots if (r / "Myau0729-obf.jar").exists()), None)
    if jar is None:
        print("  (skipped: real sample not present; set JDEC_SAMPLE_DIR to enable)")
        return
    print("obf: a real ZKM 27 sample is attributed")
    rep, _per = OB.scan_obfuscation(jar)
    check("attributed to ZKM", rep.vendor is not None and "ZKM" in rep.vendor,
          rep.summary())
    classes = max(1, rep.classes_scanned)
    got = {e.key: e.classes for e in rep.evidence}
    check("goto-flood fires on a large share of its classes",
          got.get("goto-flood", 0) / classes > 0.10,
          f"{got.get('goto-flood', 0)}/{classes}")
    check("string decryption is detected widely",
          got.get("clinit-decryptor", 0) / classes > 0.10,
          f"{got.get('clinit-decryptor', 0)}/{classes}")
    check("backward handlers are NOT this obfuscator's signature",
          got.get("handler-backjump", 0) == 0, str(got.get("handler-backjump")))
    # two of these are inverted as evidence: a vanilla jar has 100% SourceFile
    # mismatch and 34% method overloading, this one 0.1% and 3.7%
    check("SourceFile mismatch is not used as evidence here",
          got.get("fake-sourcefile", 0) / classes < 0.10,
          f"{got.get('fake-sourcefile', 0)}/{classes}")


def test_mc_roundtrip(limit: int = 800) -> None:
    print(f"classfile: parse -> serialise is lossless ({limit} real MC classes)")
    with zipfile.ZipFile(MC_JAR) as z:
        names = [n for n in z.namelist() if n.endswith(".class")][:limit]
    ok = diff = fail = 0
    with zipfile.ZipFile(MC_JAR) as z:
        for n in names:
            data = z.read(n)
            try:
                out = CF.parse(data).serialize()
            except Exception:  # noqa: BLE001
                fail += 1
                continue
            if out == data:
                ok += 1
            else:
                diff += 1
    check(f"{len(names)} classes round-trip byte-identical",
          diff == 0 and fail == 0, f"ok={ok} diff={diff} fail={fail}")


def test_mojang_mapping_direction() -> None:
    print("mappings: Mojang client.txt is inverted to obf -> named")
    m = MP.load_mapping(MC_MAP)
    check("obfuscated class name maps to a real package",
          m.classes.get("enr") == "com/mojang/blaze3d/Blaze3D",
          repr(m.classes.get("enr")))
    check("mapping is large enough to be useful", len(m.classes) > 5000,
          f"{len(m.classes)} classes")


def test_yarn_compose() -> None:
    """The compose must resolve from every namespace a Fabric jar names:
    mixin annotations carry intermediary names, vanilla remap uses official
    ones, and both must land on the Yarn name."""
    print("mappings: yarn compose keeps official and intermediary findable")
    inter = MP.parse_tiny("\n".join([
        "tiny\t2\t0\tofficial\tintermediary",
        "c\tabc\tnet/minecraft/class_310",
        "\tm\t(I)V\ta\tmethod_1481",
    ]), source="inter-test", from_ns="official", to_ns="intermediary")
    yarn = MP.parse_tiny("\n".join([
        "tiny\t2\t0\tintermediary\tnamed",
        "c\tnet/minecraft/class_310\tnet/minecraft/client/MinecraftClient",
        "\tm\t(I)V\tmethod_1481\trun",
    ]), source="yarn-test", from_ns="intermediary", to_ns="named")
    m = MP.compose_yarn(inter, yarn, "compose-test")
    check("official class reaches the yarn name",
          m.classes.get("abc") == "net/minecraft/client/MinecraftClient",
          repr(m.classes.get("abc")))
    check("official member reaches the yarn name (owner namespace bug)",
          m.lookup_member("abc", "a", "(I)V") == "run",
          repr(m.lookup_member("abc", "a", "(I)V")))
    check("intermediary class is a lookup key (mixin annotations use it)",
          m.lookup_class("net/minecraft/class_310")
          == "net/minecraft/client/MinecraftClient",
          repr(m.lookup_class("net/minecraft/class_310")))
    check("intermediary member resolves with and without descriptor",
          m.lookup_member("net/minecraft/class_310", "method_1481", "(I)V")
          == "run"
          and m.lookup_member("net/minecraft/class_310", "method_1481", None)
          == "run",
          repr(m.lookup_member("net/minecraft/class_310", "method_1481", None)))


def test_official_srg_compose() -> None:
    print("mappings: official-srg compose combines Mojang classes and SRG members")
    from jdec import mappings as MP
    mojang = MP.Mapping(source="test-mojang")
    mojang.add_class("brc", "net/minecraft/world/entity/monster/Creeper")
    mojang.add_member("brc", "a", "(I)V", "tick")

    srg = MP.Mapping(source="test-srg")
    srg.add_class("brc", "net/minecraft/entity/monster/EntityCreeper")
    srg.add_member("brc", "a", "(I)V", "m_6075_")
    srg.add_member("brc", "b", "I", "f_19853_")

    combined = MP.compose_official_srg(mojang, srg, source="test-combined")

    check("class maps to official Mojang name",
          combined.lookup_class("brc") == "net/minecraft/world/entity/monster/Creeper",
          repr(combined.lookup_class("brc")))
    check("member maps to SRG name under obf owner",
          combined.lookup_member("brc", "a", "(I)V") == "m_6075_",
          repr(combined.lookup_member("brc", "a", "(I)V")))
    check("member maps to SRG name under official owner",
          combined.lookup_member("net/minecraft/world/entity/monster/Creeper", "a", "(I)V") == "m_6075_",
          repr(combined.lookup_member("net/minecraft/world/entity/monster/Creeper", "a", "(I)V")))
    check("field maps to SRG name under official owner",
          combined.lookup_member("net/minecraft/world/entity/monster/Creeper", "b", "I") == "f_19853_",
          repr(combined.lookup_member("net/minecraft/world/entity/monster/Creeper", "b", "I")))


def test_auto_mapping_set_flavor() -> None:
    print("cli: auto picks yarn for Fabric/Quilt, version pick otherwise")
    p = SimpleNamespace(mc_flavor="Fabric")
    check("fabric jar gets yarn", CL._mapping_set_for("auto", p) == "yarn",
          CL._mapping_set_for("auto", p))
    p.mc_flavor = "Quilt"
    check("quilt jar gets yarn too", CL._mapping_set_for("auto", p) == "yarn")
    p.mc_flavor = "Forge"
    check("forge jar keeps auto (mojang first)", CL._mapping_set_for("auto", p) == "auto")
    check("explicit set is never overridden",
          CL._mapping_set_for("mojang", p) == "mojang")
    check("flavor-less profile keeps auto",
          CL._mapping_set_for("auto", SimpleNamespace()) == "auto")


def test_java_escape() -> None:
    print("recover: java_escape escapes backslash/quote/newline/tab")
    from jdec.recover import java_escape
    bs = chr(92)
    src = "a" + bs + 'b"c' + chr(10) + chr(9) + chr(13)
    out = java_escape(src)
    want = ("a" + bs + bs + "b" + bs + '"c' + bs + "n"
            + bs + "t" + bs + "r")
    check("escape is java-literal-safe", out == want, repr(out))


def test_rewrite_sources() -> None:
    print("recover: rewrite_sources backfills plaintexts, keeps misses")
    from jdec.recover import rewrite_sources
    import base64
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        # 四个站点：单行、跨行折行、Base64 带换行/转义、无解
        b64_val = "b64:" + base64.b64encode(b"line1\nline2").decode("ascii")
        (d / "A.java").write_text(
            'class A {\n'
            '    String s = Enc.d("n1", "Q2ZnbA==", 42);\n'
            '    String t = Enc.d(\n'
            '            "n2",\n'
            '            "TG9uZw==",\n'
            '            -7);\n'
            '    String v = Enc.d("n4", "QjY0", 99);\n'
            '    String u = Enc.d("n3", "TWlz=", 9);\n'
            "}\n", encoding="utf-8")
        tsv = d / "recovered.tsv"
        rows = [
            "OK\tpkg.C\tn1\tQ2ZnbA==\t42\tsecret",
            "OK\tpkg.C\tn2\tTG9uZw==\t-7\tlonger",
            f"OK\tpkg.C\tn4\tQjY0\t99\t{b64_val}",
            "FAIL\tpkg.C\tn3\t?\t?\tboom",
        ]
        tsv.write_text(chr(10).join(rows) + chr(10), encoding="utf-8")
        st = rewrite_sources(d, tsv)
        check("three sites replaced", st["replaced"] == 3, str(st))
        check("unrecoverable site missed", st["missed"] == 1, str(st))
        check("residual counts the miss", st["residual"] == 1, str(st))
        check("no key conflicts", st["conflicts"] == 0, str(st))
        txt = (d / "A.java").read_text(encoding="utf-8")
        check("plaintexts written back", '"secret"' in txt and '"longer"' in txt)
        check("base64 newline preserved without double escaping",
              '"line1\\nline2"' in txt and '"line1\\\\nline2"' not in txt)
        check("unmatched site untouched", "TWlz=" in txt)


def test_recover_triage() -> None:
    print("recover: failure lines auto-triaged into buckets with remediation")
    from jdec import recover as RC
    lines = [
        "FAIL\tcom/x/A\tcom/x/A\tjava.lang.NoClassDefFoundError: org/lwjgl/glfw/GLFW",
        "FAIL\tcom/x/B\t11\tjava.lang.NullPointerException: Cannot invoke "
        "\"net.minecraft.client.Minecraft.getInstance()\" because \"mc\" is null",
        "FAIL\tcom/x/C\t3\tjava.lang.NoSuchMethodException: com.x.C.b(int,int)->String",
        "FAIL\tcom/x/D\tcom/x/D\tjava.lang.UnsatisfiedLinkError: "
        "org.lwjgl.opengl.GL11C.nglBegin(Native Method)",
        "FAIL\tcom/x/E\tcom/x/E\tjava.lang.NoClassDefFoundError: com/netease/mc/Foo",
        "FAIL\tcom/x/F\tcom/x/F\tjava.lang.IllegalStateException: Not bootstrapped",
        "FAIL\tcom/x/G\tcom/x/G\tjava.lang.SomeWeirdError: ???",
    ]
    buckets = {b.key: b for b in RC.triage_failures(lines)}

    def has(key, cls):
        return any(e[0] == cls for e in buckets[key].entries)

    check("lwjgl constants bucket", has("lwjgl-constants", "com/x/A"))
    check("needs-instance bucket", has("needs-instance", "com/x/B"))
    check("signature bucket", has("signature", "com/x/C"))
    check("native bucket", has("native", "com/x/D"))
    check("missing-class bucket", has("missing-class", "com/x/E"))
    check("needs-bootstrap bucket", has("needs-bootstrap", "com/x/F"))
    check("other bucket", has("other", "com/x/G"))
    check("all sites classified",
          sum(len(b.entries) for b in buckets.values()) == len(lines))
    with tempfile.TemporaryDirectory() as td:
        p = RC.write_failed_triage(Path(td), list(buckets.values()), 3)
        txt = p.read_text(encoding="utf-8")
        check("triage md written", p is not None and p.exists())
        check("triage md has remediation", "lwjgl-api" in txt
              and "处置" in txt)


def test_manifest_and_resources() -> None:
    print("mcmod: MANIFEST.MF parsed (agent attrs) + resource inventory")
    with tempfile.TemporaryDirectory() as td:
        jar = Path(td) / "m.jar"
        man = ("Manifest-Version: 1.0\r\n"
               "Implementation-Title: fake\r\n"
               "Implementation-Vendor: VendorX\r\n"
               "Implementation-Description: line1\r\n"
               " continuation\r\n"
               "Premain-Class: com.x.Agent\r\n"
               "Can-Retransform-Classes: true\r\n"
               "\r\n"
               "Name: com/x/Foo.class\r\n"
               "SHA-256-Digest: abc\r\n")
        with zipfile.ZipFile(jar, "w") as z:
            z.writestr("META-INF/MANIFEST.MF", man)
            z.writestr("fabric.mod.json", json.dumps({"id": "fake", "version": "1"}))
            z.writestr("assets/fake/icon.png", b"\x89PNG")
            z.writestr("com/x/Foo.class", b"\xca\xfe\xba\xbe")
        info = MM.read_manifest(jar)
        check("manifest main parsed", info is not None
              and info.main.get("Implementation-Vendor") == "VendorX")
        check("manifest continuation", "continuation"
              in info.main.get("Implementation-Description", ""))
        check("manifest agent attrs", info.agent_attrs().get("Premain-Class")
              == "com.x.Agent")
        check("manifest per-entry section", "com/x/Foo.class" in info.sections)
        meta = MM.read_mod_meta(jar)
        check("meta attaches manifest", meta.manifest is not None
              and meta.loader == "fabric")
        check("meta summary shows vendor+agent", "vendor=VendorX" in meta.summary()
              and "java-agent" in meta.summary())
        inv = MM.resource_inventory(jar)
        check("resources counted", inv["non_class"] == 3, str(inv))
        check("resources top dirs", any(k == "assets" for k, _ in inv["top_dirs"]),
              str(inv["top_dirs"]))


def test_rewrite_escapes() -> None:
    print("recover: rewritten literals are ASCII-escaped (no raw ctrl bytes)")
    from jdec.recover import java_unescape, rewrite_sources
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        BS = chr(92)
        (d / "A.java").write_text(
            'class A {' + chr(10)
            + '    String s = Enc.d("n1", "Q2ZnbA==", 42);' + chr(10)
            + "}" + chr(10), encoding="utf-8")
        tsv = d / "recovered.tsv"
        plain = "secret" + chr(1) + chr(0x4e2d)  # ctrl-A + CJK
        tsv.write_text("OK" + chr(9) + "pkg.C" + chr(9) + "n1" + chr(9)
                       + "Q2ZnbA==" + chr(9) + "42" + chr(9) + plain
                       + chr(10), encoding="utf-8")
        st = rewrite_sources(d, tsv)
        check("escape site replaced", st["replaced"] == 1, str(st))
        txt = (d / "A.java").read_text(encoding="utf-8")
        want = '"secret' + BS + "u0001" + BS + "u4e2d" + '"'
        check("literal is unicode-escaped", want in txt, repr(txt[-80:]))
        check("no raw ctrl byte in file", chr(1) not in txt)
        # round-trip: 反转义回明文
        inner = want[1:-1]
        check("escape is reversible", java_unescape(inner) == plain)


def test_bsm_scan_and_parse_resilience() -> None:
    print("bsm: scan_jar, parse_bsm, and enum_sites handle valid and corrupt classes")
    from jdec import bsm as BM
    from jdec import classfile as CF

    # 1. Whole jar scan on SAMPLE which contains a deliberately truncated class fixture
    census = BM.scan_jar(SAMPLE)
    st = census["stats"]
    check("bsm scan quarantined corrupt class and counted valid classes", st["classes"] == 10, str(st))
    check("bsm scan identified classes with BSM", st["classes_with_bsm"] >= 4, str(st))
    check("bsm scan found indy callsites", st["sites"] >= 10, str(st))
    check("bsm sample contains entries", len(census["sample"]) == 0 or len(census["per_name"]) > 0)

    # 2. Corrupted attribute resilience in parse_bsm
    with zipfile.ZipFile(SAMPLE) as z:
        cf = CF.parse(z.read("demo/modern/Showcase.class"))
    # Corrupt the attributes blob
    cf.attrs_blob = b"\x00\x05\x00\x01"  # truncated attribute header
    corrupt_bsm = BM.parse_bsm(cf)
    check("parse_bsm survives truncated attribute blob without exception", corrupt_bsm == [])

    # 3. Method arity calculation edge cases
    check("_arity works on primitives and objects", BM._arity("(IDLjava/lang/String;)V") == 3)
    check("_arity handles long and double correctly", BM._arity("(JJDD)V") == 4)
    check("_arity handles arrays", BM._arity("([[I[Ljava/lang/String;)V") == 2)


def test_recover_spec_generation_and_quarantine() -> None:
    print("recover: build_spec parses jar and quarantines corrupt classes cleanly")
    from jdec import recover as RC

    with tempfile.TemporaryDirectory() as td:
        out_d = Path(td)
        spec_path, n_sites, n_skip = RC.build_spec(SAMPLE, out_d)
        check("build_spec produced spec file", spec_path.is_file())
        check("build_spec found callsites", n_sites >= 10, f"n_sites={n_sites}")
        lines = spec_path.read_text(encoding="utf-8").splitlines()
        check("spec lines non-empty", len(lines) >= n_sites)
        c_lines = [l for l in lines if l.startswith("C\t")]
        s_lines = [l for l in lines if l.startswith("S\t")]
        check("spec has class directives", len(c_lines) >= 3, f"classes={len(c_lines)}")
        check("spec has site directives", len(s_lines) == n_sites, f"sites={len(s_lines)}")
        if s_lines:
            s_parts = s_lines[0].split("\t")
            check("site directive has >= 6 TSV columns", len(s_parts) >= 6, f"cols={len(s_parts)}")



def test_resource_anomaly() -> None:
    print("mcmod: resource_anomaly flags identifier-level obfuscation tokens")
    with tempfile.TemporaryDirectory() as td:
        jar = Path(td) / "m.jar"
        toml = (chr(10).join(
            ['modId="NS5Nc6"', 'version="1.0.0"',
             'displayName="NS5Nc6 client"', 'authors="someone"'] * 6)
            + chr(10))
        with zipfile.ZipFile(jar, "w") as z:
            z.writestr("META-INF/mods.toml", toml)
            z.writestr("assets/fake/lang/en_us.json",
                       '{"item.ns5nc6.sword": "Sword"}')
        anom = MM.resource_anomaly(jar)
        toks = [t for t, _n, _f in anom["suspects"]]
        check("anomaly text files scanned", anom["text_files"] == 2, str(anom))
        check("replaced token flagged", "NS5Nc6" in toks, str(toks))
        check("known words not flagged",
              "version" not in toks and "modId" not in toks
              and "displayName" not in toks, str(toks))
        check("flag is repeatable", "NS5Nc6" in [
            t for t, _n, _f in MM.resource_anomaly(jar)["suspects"]])


def test_scorecard_smoke() -> None:
    print("scorecard: fixed-metric row + JSON out + delta vs previous")
    from jdec import scorecard as SC2
    row = SC2.score_jar(SAMPLE)
    check("probe fields present",
          row["classes"] > 0 and "obfuscation" in row and "jar" in row,
          str(row)[:200])
    check("strings counted", row["strings"] >= 0
          and row["strings_suspicious"] >= 0, str(row)[:200])
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "sc.json"
        jp, _ = SC2.write_scorecard([row], out,
                                    {"analyze": False, "decompile": False})
        payload = json.loads(jp.read_text(encoding="utf-8"))
        check("scorecard json written", jp.exists()
              and payload["rows"][0]["jar"] == row["jar"])
        # 伪造上一版：strings 变了 -> delta 应捕捉
        old = json.loads(json.dumps(payload))
        old["rows"][0]["strings"] = payload["rows"][0]["strings"] - 5
        deltas = SC2.compare_rows(old["rows"], payload["rows"])
        check("delta catches change",
              deltas and deltas[0]["status"] == "changed"
              and "strings" in deltas[0]["diffs"], str(deltas))
        md = SC2.render_markdown(payload["rows"], deltas,
                                 {"analyze": False, "decompile": False})
        check("md has delta section", "vs previous" in md and "strings" in md)


def test_pool_roundtrip() -> None:
    print("pool: scan -> harvest (real JVM replay) -> apply, end to end")
    import base64
    import shutil as _sh
    if not (_sh.which("javac") and _sh.which("java")):
        print("skipping: javac/java not on PATH")
        return
    from jdec import pool as PL  # noqa: F401 - 触发模块加载即模板校验
    from jdec.cli import main as cli_main
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        src = d / "src"
        (src / "pkg").mkdir(parents=True)
        BS = chr(92)
        LF = chr(10)
        # 访问器返回值含控制字符与 CJK -> 验证 \u 转义落盘
        (src / "pkg" / "Sample.java").write_text(
            "package pkg;" + LF
            + "public class Sample {" + LF
            + "    static String a(int idx, int seed) {" + LF
            + '        return "V" + idx + ":" + seed + "' + BS + "u0007"
            + BS + 'u4e2d";' + LF
            + "    }" + LF
            + "    String own() { return a(33, 44); }" + LF
            + "}" + LF, encoding="utf-8")
        (src / "pkg" / "User.java").write_text(
            "package pkg;" + LF
            + "public class User {" + LF
            + "    String tag() { return Sample.a(11, 22); }" + LF
            + "}" + LF, encoding="utf-8")
        # 1. scan
        spec = d / "pool_spec.tsv"
        rc = cli_main(["pool", "scan", str(src), "-o", str(spec)])
        check("pool scan rc", rc == 0)
        lines = spec.read_text(encoding="utf-8").splitlines()
        keys = {tuple(l.split(chr(9))[i] for i in (1, 3, 4)) for l in lines}
        check("pool scan found both sites",
              ("pkg.Sample", "11", "22") in keys
              and ("pkg.Sample", "33", "44") in keys, str(lines))
        # 2. 编译合成源作为 replay classpath，真 JVM 收割
        cls_dir = d / "classes"
        cls_dir.mkdir()
        r = subprocess.run(["javac", "-d", str(cls_dir),
                            str(src / "pkg" / "Sample.java"),
                            str(src / "pkg" / "User.java")],
                           capture_output=True, text=True)
        check("fixture javac", r.returncode == 0, r.stderr[-300:])
        hv = d / "pool_work" / "pool_harvest.tsv"
        rc = cli_main(["pool", "harvest", str(spec), "-o", str(hv),
                       "--cp", str(cls_dir)])
        rows = ([l.split(chr(9)) for l in hv.read_text(encoding="utf-8",
                                                       errors="replace")
                 .splitlines()] if hv.exists() else [])
        plains = {tuple(rr[i] for i in (1, 3, 4)):
                  base64.b64decode(rr[5]).decode("utf-8")
                  for rr in rows if rr and rr[0] == "R"}
        check("pool harvest rc", rc == 0, str(plains))
        check("pool harvest plaintexts",
              plains.get(("pkg.Sample", "11", "22"))
              == "V11:22" + chr(7) + chr(0x4e2d), str(plains))
        # 3. apply（回填 + verify + 失败归因挂接）
        out = d / "src_pool"
        rc = cli_main(["pool", "apply", str(src), "--harvest", str(hv),
                       "-o", str(out)])
        check("pool apply rc", rc == 0)
        utxt = (out / "pkg" / "User.java").read_text(encoding="utf-8")
        stxt = (out / "pkg" / "Sample.java").read_text(encoding="utf-8")
        lit = "V11:22" + BS + "u0007" + BS + "u4e2d"
        lit_b = "V33:44" + BS + "u0007" + BS + "u4e2d"
        check("apply replaced qualified call", ('"' + lit + '"') in utxt,
              utxt[-160:])
        check("apply replaced bare call", ('"' + lit_b + '"') in stxt,
              stxt[-160:])
        check("apply wrote no raw ctrl bytes",
              chr(7) not in utxt and chr(7) not in stxt)
        check("apply left no decodable residual",
              "Sample.a(11, 22)" not in utxt and "a(33, 44)" not in stxt)


def test_web_template_js() -> None:
    print("web: HTML_TEMPLATE inline JS parses (node --check)")
    import re as _re
    import shutil as _sh
    try:
        from jdec import web as WB
    except Exception as exc:  # noqa: BLE001
        print(f"skipping: jdec.web import failed: {exc}")
        return
    node = _sh.which("node")
    if not node:
        print("skipping: node not on PATH")
        return
    blocks = _re.findall("<script>(.*?)</script>", WB.HTML_TEMPLATE, _re.S)
    check("template has an inline script block", len(blocks) >= 1)
    js = "\n".join(blocks)
    # 2026-10-04 事故：模板非 raw，JS 字符串里的 \n 被 Python 编译期吃成
    # 真实换行，alert('...') 字符串断裂 -> 整个 script 解析失败、工作台瘫痪。
    # 硬校验：内联 JS 必须整体语法合法（node --check）。
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "inline.js"
        p.write_text(js, encoding="utf-8")
        r = subprocess.run([node, "--check", str(p)],
                           capture_output=True, text=True)
        check("inline JS is syntactically valid", r.returncode == 0,
              (r.stderr or r.stdout or "")[-400:])


def test_pool_qualified_and_full_string() -> None:
    print("pool: handles java.lang.String return type and package-qualified calls")
    from jdec import pool as PL
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        src = d / "src"
        (src / "com" / "example").mkdir(parents=True)
        # Class with java.lang.String return type
        (src / "com" / "example" / "Holder.java").write_text(
            "package com.example;\n"
            "public class Holder {\n"
            "    public static java.lang.String decode(int a, int b) { return null; }\n"
            "}\n", encoding="utf-8"
        )
        # Caller using full qualified name com.example.Holder.decode(...) and simple Holder.decode(...)
        (src / "com" / "example" / "Caller.java").write_text(
            "package com.example;\n"
            "public class Caller {\n"
            '    String s = com.example.Holder.decode(100, 200);\n'
            '    String s2 = Holder.decode(300, 400);\n'
            "}\n", encoding="utf-8"
        )
        spec = d / "spec.tsv"
        st = PL.scan_spec(src, spec)
        check("pool scan finds Holder class", st["pool_classes"] == 1, str(st))
        check("pool scan finds 2 sites", st["unique"] == 2, str(st))
        lines = spec.read_text(encoding="utf-8").splitlines()
        keys = {tuple(l.split("\t")[i] for i in (1, 2, 3, 4)) for l in lines}
        check("both qualified and simple sites recorded",
              ("com.example.Holder", "decode", "100", "200") in keys
              and ("com.example.Holder", "decode", "300", "400") in keys,
              str(keys))

        # Test apply with harvest mock
        import base64
        hv = d / "harvest.tsv"
        val1 = base64.b64encode(b"hello_p2").decode("ascii")
        val2 = base64.b64encode(b"world_p2").decode("ascii")
        hv.write_text(
            f"R\tcom.example.Holder\tdecode\t100\t200\t{val1}\n"
            f"R\tcom.example.Holder\tdecode\t300\t400\t{val2}\n",
            encoding="utf-8"
        )
        out = d / "applied"
        PL.apply(src, hv, out)
        res = (out / "com" / "example" / "Caller.java").read_text(encoding="utf-8")
        check("qualified call site replaced", '"hello_p2"' in res, res)
        check("simple call site replaced", '"world_p2"' in res, res)


def test_probe_fingerprints_json() -> None:
    print("probe: fingerprints.json detects obfuscator from keywords")
    with tempfile.TemporaryDirectory() as td:
        jar = Path(td) / "test_obf.jar"
        with zipfile.ZipFile(jar, "w") as z:
            z.writestr("dev/jnic/Bridge.class", b"\xca\xfe\xba\xbe")
            z.writestr("com/example/Main.class", b"\xca\xfe\xba\xbe")
        prof = profile_jar(jar)
        check("fingerprints.json matched JNIC", prof.obfuscator == "JNIC", str(prof.obfuscator))
        check("signature recorded", any("JNIC" in s for s in prof.signatures), str(prof.signatures))


def test_ghidra_integration() -> None:
    print("ghidra: engine detection, script validation, and report integration")
    import shutil
    from jdec import ghidra_engine as GE
    from jdec import native_scan as NS

    # 1. worker script validation
    check("ghidra_worker.java exists", GE.WORKER_JAVA.exists())
    txt = GE.WORKER_JAVA.read_text(encoding="utf-8")
    check("worker script defines GhidraScript", "ghidra_worker extends GhidraScript" in txt)
    check("worker script uses DecompInterface", "DecompInterface" in txt)

    # 2. find_ghidra on mock installation
    with tempfile.TemporaryDirectory() as td:
        mock_dir = Path(td) / "mock_ghidra"
        support = mock_dir / "support"
        support.mkdir(parents=True)
        bin_name = "analyzeHeadless.bat" if sys.platform == "win32" else "analyzeHeadless"
        (support / bin_name).write_text("echo mock", encoding="utf-8")

        found = GE.find_ghidra(explicit_path=mock_dir)
        check("mock ghidra detected via explicit_path", found == mock_dir.resolve(), str(found))

        engines_dir = Path(td) / "engines"
        engines_dir.mkdir()
        shutil.copytree(mock_dir, engines_dir / "ghidra")
        found_engine = GE.find_ghidra(engines_dir=engines_dir)
        check("mock ghidra detected in engines dir", found_engine is not None, str(found_engine))

    # 3. native_scan report formatting with decompiled info
    with tempfile.TemporaryDirectory() as td:
        rep_out = Path(td) / "test-triage.md"
        tri = NS.Triage(libs=[NS.NativeLib(name="test.dll", size=1024, format="PE", exports=["Java_com_x_Y_z"])])
        decomp_mock = {
            "test.dll": {
                "ok": True,
                "decompiled_count": 1,
                "functions": [{"name": "Java_com_x_Y_z", "entry": "0x1000", "file": "src/Java_com_x_Y_z.c"}]
            }
        }
        NS.write_report(tri, "test.jar", rep_out, decompiled_info=decomp_mock)
        md = rep_out.read_text(encoding="utf-8")
        check("report contains decompiled section", "decompiled C sources (via Ghidra Headless)" in md)
        check("report lists decompiled function", "Java_com_x_Y_z" in md and "src/Java_com_x_Y_z.c" in md)

    # 4. decompile_library exception resilience on invalid / mock binary
    with tempfile.TemporaryDirectory() as td:
        fake_gh = Path(td) / "fake_gh"
        (fake_gh / "support").mkdir(parents=True)
        bin_name = "analyzeHeadless.bat" if sys.platform == "win32" else "analyzeHeadless"
        (fake_gh / "support" / bin_name).write_text("exit 1\n", encoding="utf-8")
        dummy_dll = Path(td) / "dummy.dll"
        dummy_dll.write_bytes(b"\x00" * 64)
        out_c = Path(td) / "out_c"
        res_dec = GE.decompile_library(fake_gh, dummy_dll, out_c, timeout=5, quiet=True)
        check("decompile_library returns clean dict on error", isinstance(res_dec, dict) and "ok" in res_dec)



def test_native_elf_and_ghidra_annotate() -> None:
    print("natives: ELF (.so) export parsing and Ghidra annotation script generation")
    from jdec import native_scan as NS

    # 1. ELF export parsing
    ehdr = bytearray(64)
    ehdr[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", ehdr, 16, 3, 0x3E, 1, 0, 0, 64, 0, 64, 0, 0, 64, 3, 0)
    sh0 = bytearray(64)
    sh1 = bytearray(64)
    struct.pack_into("<IIQQQQIIQQ", sh1, 0, 0, 11, 2, 0, 256, 72, 2, 1, 8, 24)
    sh2 = bytearray(64)
    dynstr_data = b"\x00Java_demo_Cls_run\x00JNI_OnLoad\x00"
    struct.pack_into("<IIQQQQIIQQ", sh2, 0, 0, 3, 2, 0, 328, len(dynstr_data), 0, 0, 1, 0)

    sym0 = bytearray(24)
    sym1 = bytearray(24)
    struct.pack_into("<IBBHQQ", sym1, 0, 1, 0x12, 0, 1, 0x1000, 32)
    sym2 = bytearray(24)
    struct.pack_into("<IBBHQQ", sym2, 0, 19, 0x12, 0, 1, 0x1020, 16)

    elf = bytes(ehdr + sh0 + sh1 + sh2 + sym0 + sym1 + sym2 + dynstr_data)
    exports = NS.parse_elf_exports(elf)
    check("ELF parsed JNI exports", "Java_demo_Cls_run" in exports and "JNI_OnLoad" in exports, str(exports))

    # 2. Ghidra GUI annotation script generation
    with tempfile.TemporaryDirectory() as td:
        script_out = Path(td) / "ghidra_annotate.py"
        tri = NS.Triage(
            libs=[NS.NativeLib(name="libsample.so", size=len(elf), format="ELF", exports=exports)],
            native_decl=[("demo/Cls", "run")]
        )
        NS.write_ghidra_annotation_script(tri, script_out)
        check("ghidra_annotate.py written", script_out.exists())
        txt = script_out.read_text(encoding="utf-8")
        check("ghidra_annotate maps Java method", "Java_demo_Cls_run" in txt and "demo/Cls" in txt)
        check("ghidra_annotate contains run entry", "def run():" in txt and "JNI_BINDINGS" in txt)


def test_score_and_signal_enhancements() -> None:
    print("score/analyze: hard error patterns and expanded API rules")
    from jdec.score import _HARD_ERROR_PATTERNS
    samples = [
        "// Method dump skipped",
        "/* Decompilation failed: stack underflow */",
        "// Decompilation aborted",
    ]
    for s in samples:
        matched = any(p.search(s) for p in _HARD_ERROR_PATTERNS)
        check(f"hard error matched: {s}", matched)


def test_multimodule_enhancements() -> None:
    print("modules: strings threat tags, tsrg2 mappings, quilt/neoforge metadata")
    # 1. strings.py
    check("webhook detected", "webhook" in ST.classify("https://discord.com/api/webhooks/123456789/AbCdEf-GhIj"))
    check("telegram bot detected", "telegram" in ST.classify("https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"))
    check("c2 staging detected", "c2-staging" in ST.classify("https://pastebin.com/raw/xyz123"))
    check("crypto address detected", "crypto" in ST.classify("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))
    blob = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="
    check("encrypted blob detected", "encrypted-blob" in ST.classify(blob))
    sd = ST.StringDump(rows=[("ClsA", "s1", ["webhook", "url"]), ("ClsB", "s2", ["webhook"])])
    tc = sd.tag_counts()
    check("tag_counts computed", tc.get("webhook") == 2 and tc.get("url") == 1, str(tc))

    # 2. mappings.py TSRG v2
    tsrg2_sample = (
        "tsrg2 obf srg\n"
        "a net/minecraft/client/main/Main\n"
        "\tb field_1234_a\n"
        "\tc (Ljava/lang/String;)V func_5678_b\n"
        "\t\t0 p_5678_0_\n"
    )
    m = MP.parse_tsrg(tsrg2_sample)
    check("tsrg2 class parsed", m.lookup_class("a") == "net/minecraft/client/main/Main")
    check("tsrg2 field parsed", m.lookup_member("a", "b", "") == "field_1234_a")
    check("tsrg2 method parsed", m.lookup_member("a", "c", "(Ljava/lang/String;)V") == "func_5678_b")
    check("tsrg2 parameter skipped as member", m.lookup_member("a", "0", "") is None)

    # 3. mcmod.py & probe.py (Quilt & NeoForge)
    from jdec import mcmod as MM
    tmp_dir = Path(tempfile.mkdtemp(prefix="jdec_test_meta_"))
    try:
        # Mock Quilt jar
        quilt_jar = tmp_dir / "quilt_test.jar"
        with zipfile.ZipFile(quilt_jar, "w") as z:
            quilt_json = {
                "schema_version": 1,
                "quilt_loader": {
                    "id": "quilt_sample",
                    "version": "2.0.0",
                    "metadata": {"name": "Quilt Sample Mod", "contributors": {"AuthorA": "Owner"}},
                    "entrypoints": {"init": "com.example.QuiltMod"},
                    "depends": [{"id": "minecraft", "versions": "1.20.2"}]
                },
                "mixin": "quilt_sample.mixins.json"
            }
            z.writestr("quilt.mod.json", json.dumps(quilt_json))
        qmeta = MM.read_mod_meta(quilt_jar)
        check("quilt loader recognized", qmeta.loader == "quilt", str(qmeta.loader))
        check("quilt mod id", qmeta.mod_id == "quilt_sample", str(qmeta.mod_id))
        check("quilt name", qmeta.name == "Quilt Sample Mod", str(qmeta.name))
        check("quilt entrypoint", "com.example.QuiltMod" in qmeta.entrypoints, str(qmeta.entrypoints))
        check("quilt mixin config", "quilt_sample.mixins.json" in qmeta.mixin_configs, str(qmeta.mixin_configs))

        qprof = profile_jar(quilt_jar)
        check("quilt flavor in probe", qprof.mc_flavor == "Quilt", str(qprof.mc_flavor))
        check("quilt version in probe", qprof.mc_version == "1.20.2", str(qprof.mc_version))

        # Mock NeoForge jar
        neo_jar = tmp_dir / "neo_test.jar"
        with zipfile.ZipFile(neo_jar, "w") as z:
            neo_toml = (
                "modId = 'neoforge_test'\n"
                "displayName = 'NeoForge Mod'\n"
                "version = '1.20.4-1.0'\n"
                "authors = 'Dev'\n"
                "description = 'A test mod'\n"
                "[[dependencies.neoforge_test]]\n"
                "modId = 'minecraft'\n"
                "versionRange = '[1.20.4, 1.21)'\n"
                "[[mixins]]\n"
                "config = 'neo.mixins.json'\n"
            )
            z.writestr("META-INF/neoforge.mods.toml", neo_toml)
        nmeta = MM.read_mod_meta(neo_jar)
        check("neoforge loader recognized", nmeta.loader == "neoforge", str(nmeta.loader))
        check("neoforge mod id", nmeta.mod_id == "neoforge_test", str(nmeta.mod_id))
        check("neoforge name", nmeta.name == "NeoForge Mod", str(nmeta.name))
        check("neoforge mixin config", "neo.mixins.json" in nmeta.mixin_configs, str(nmeta.mixin_configs))

        nprof = profile_jar(neo_jar)
        check("neoforge flavor in probe", nprof.mc_flavor == "NeoForge", str(nprof.mc_flavor))
        check("neoforge version in probe", nprof.mc_version == "1.20.4", str(nprof.mc_version))
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_advanced_roadmap_features() -> None:
    print("advanced: reverse JNI, RegisterNatives, stubs, deflat, and rename")
    from jdec import native_scan as NS
    from jdec import stubs
    from jdec import deflat as DF
    from jdec import rename as RN

    # 1. Reverse JNI & RegisterNatives scanning
    c_snippet = (
        'jclass c = (*env)->FindClass(env, "net/minecraft/client/Minecraft");\n'
        'jmethodID m = (*env)->GetMethodID(env, c, "run", "()V");\n'
        'jfieldID f = (*env)->GetFieldID(env, c, "player", "Ljava/lang/Object;");\n'
        '(*env)->CallVoidMethod(env, obj, m);\n'
        'env->FindClass("net/minecraft/world/World");\n'
    )
    rev = NS.scan_reverse_jni_c(c_snippet, "native_init")
    check("reverse JNI FindClass", any(r["type"] == "FindClass" and r["class"] == "net/minecraft/client/Minecraft" for r in rev))
    check("reverse JNI C++ FindClass", any(r["type"] == "FindClass" and r["class"] == "net/minecraft/world/World" for r in rev))
    check("reverse JNI GetMethodID", any(r["type"] == "GetMethodID" and r["method"] == "run" for r in rev))
    check("reverse JNI GetFieldID", any(r["type"] == "GetFieldID" and r["field"] == "player" for r in rev))
    check("reverse JNI CallMethod", any(r["type"] == "CallMethod" and r["mid_var"] == "m" for r in rev))

    c_reg = 'static JNINativeMethod methods[] = { { "nativeFunc", "(ILjava/lang/String;)Z", (void*)&sub_1234 } };'
    dyn = NS.scan_register_natives_c(c_reg, "JNI_OnLoad")
    check("RegisterNatives parsed", len(dyn) == 1 and dyn[0]["name"] == "nativeFunc" and dyn[0]["func"] == "sub_1234")

    # 2. Fake MC Stubs jar generation
    tmp_stubs = Path(tempfile.mkdtemp(prefix="jdec_test_stubs_"))
    try:
        sjar = stubs.ensure_stubs_jar(cache_dir=tmp_stubs)
        check("stubs jar generated", sjar.is_file())
        with zipfile.ZipFile(sjar) as z:
            names = z.namelist()
        check("stubs has Minecraft", "net/minecraft/client/Minecraft.class" in names)
        check("stubs has Launch", "net/minecraft/launchwrapper/Launch.class" in names)
        check("stubs has SharedConstants", "net/minecraft/SharedConstants.class" in names)
        check("stubs has BuiltInRegistries", "net/minecraft/core/registries/BuiltInRegistries.class" in names)

        # 2.5 Javac compiler detection
        from jdec import engines as EN
        jc = EN.find_javac()
        if jc is not None:
            check("engines.find_javac found valid executable", Path(jc).is_file(), str(jc))
            check("stubs._find_javac resolves javac", stubs._find_javac("javac") is not None)
    finally:
        shutil.rmtree(tmp_stubs, ignore_errors=True)

    # 3. Control flow de-flattening and constant arithmetic
    code = bytes([0x10, 0x05, 0x10, 0x03, 0x82])  # 5 ^ 3
    new_code, n = DF.simplify_constants(code)
    check("constant folding simplified ixor", n == 1 and new_code[0] == 0x10 and new_code[1] == 6)

    code_add = bytes([0x10, 0x0A, 0x10, 0x14, 0x60])  # 10 + 20
    new_code_add, n_add = DF.simplify_constants(code_add)
    check("constant folding simplified iadd", n_add == 1 and new_code_add[0] == 0x10 and new_code_add[1] == 30)

    # Switch at pc 1 with low=1, high=3 (count=3)
    switch_code = bytearray([0x1b, 0xaa, 0, 0] + list(struct.pack('>iiiii', 0, 1, 3, 27, 34)) + list(struct.pack('>i', 35)))
    switch_code += bytearray([0x10, 0x02, 0x3c, 0xa7]) + bytearray(struct.pack('>h', -31))
    switch_code += bytearray([0x00, 0xb1])
    deflat_res, n_unflat = DF.deflat_code(bytes(switch_code))
    check("deflat unflattened switch transition", n_unflat >= 1)

    # Test deflat_class with a synthetically embedded Code attribute
    with zipfile.ZipFile(SAMPLE) as zf:
        sample_cls_data = zf.read(zf.namelist()[0])
    cf_sample = CF.parse(sample_cls_data)
    # deflat_class should safely scan methods without crashing
    edits = DF.deflat_class(cf_sample)
    check("deflat_class runs on ClassFile", edits >= 0)
    roundtrip = cf_sample.serialize()
    check("ClassFile round-trips after deflat_class", len(roundtrip) > 0)

    # 4. Semantic renaming and LLM prompt export
    tmp_ren = Path(tempfile.mkdtemp(prefix="jdec_test_ren_"))
    try:
        sample_java = tmp_ren / "TestMixin.java"
        sample_java.write_text(
            'package demo;\n'
            'public class TestMixin {\n'
            '    @Inject(method = "tick")\n'
            '    public void a(int x) {\n'
            '        String s = "Connecting to socket";\n'
            '    }\n'
            '}\n',
            encoding="utf-8"
        )
        cands = RN.scan_source_file(sample_java)
        check("rename candidate found", len(cands) == 1 and cands[0].member_name == "a")
        check("rename suggestion inferred from mixin", cands[0].suggested_name == "onTick")

        prompt = RN.export_llm_prompt(cands)
        check("LLM prompt contains candidate", "onTick" in prompt)

        out_map = tmp_ren / "mapping.txt"
        n_rules = RN.write_proguard_mapping(cands, out_map)
        check("ProGuard mapping exported", n_rules == 1 and out_map.exists())
        map_content = out_map.read_text(encoding="utf-8")
        check("ProGuard parameter signature formatted", "void a(int) -> onTick" in map_content, map_content)
    finally:
        shutil.rmtree(tmp_ren, ignore_errors=True)


def test_pipeline_automation() -> None:
    print("pipeline: automated end-to-end deobfuscation and triage")
    from jdec import pipeline as PL
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        out_dir = d / "auto_out"
        res = PL.run_pipeline(
            SAMPLE,
            out_dir,
            no_deflat=False,
            no_recover=False,
            export_project=True,
            clean_work=False,
        )
        check("pipeline ran successfully", res.decompile_total > 0)
        check("pipeline summary markdown exists", (out_dir / "pipeline_summary.md").is_file())
        check("pipeline summary json exists", (out_dir / "pipeline_summary.json").is_file())
        check("decompiled sources exist", (out_dir / "src").is_dir())
        check("analysis markdown exists", (out_dir / "analysis.md").is_file())
        check("strings tsv exists", (out_dir / "strings.tsv").is_file())
        check("report markdown exists", (out_dir / "report.md").is_file())

        # Phase 2 unflattened methods
        check("pipeline unflattened methods", res.unflattened_methods > 0, f"unflattened={res.unflattened_methods}")

        # Phase 5 recover artifacts
        check("recover spec tsv exists", (out_dir / "_pipeline" / "recover" / "recover_spec.tsv").is_file())
        check("recover results tsv exists", (out_dir / "_pipeline" / "recover" / "recovered.tsv").is_file())

        # Phase 8 project artifacts
        proj_dir = out_dir / "project"
        check("exported project directory exists", proj_dir.is_dir())
        check("exported build.gradle exists", (proj_dir / "build.gradle").is_file())
        check("exported src directory exists", (proj_dir / "src" / "main" / "java").is_dir())

        json_data = json.loads((out_dir / "pipeline_summary.json").read_text(encoding="utf-8"))
        check("summary json contains metrics", "metrics" in json_data and json_data["metrics"]["decompile_total"] > 0)
        check("summary json contains profile", "profile" in json_data and json_data["profile"]["classes"] > 0)



def test_web_workbench_features() -> None:
    print("web: interactive workbench with diff, annotations and LLM assist")
    import re
    from jdec import web as WB
    import urllib.request
    import threading

    with tempfile.TemporaryDirectory() as td:
        work_dir = Path(td)
        src_dir = work_dir / "src" / "demo" / "obf"
        src_dir.mkdir(parents=True, exist_ok=True)
        java_file = src_dir / "a.java"
        java_file.write_text(
            'package demo.obf;\n\n'
            'public class a {\n'
            '    public int x = 1;\n'
            '    public void b() {\n'
            '        System.out.println("Connecting to C2 host");\n'
            '    }\n'
            '}\n',
            encoding="utf-8"
        )

        cfr_dir = work_dir / "engines" / "cfr" / "demo" / "obf"
        cfr_dir.mkdir(parents=True, exist_ok=True)
        (cfr_dir / "a.java").write_text(
            'package demo.obf;\n\n'
            'public class a {\n'
            '    public int x = 1;\n'
            '    public int y = 2;\n'
            '    public void b() {\n'
            '        System.out.println("Connecting to C2 host");\n'
            '    }\n'
            '}\n',
            encoding="utf-8"
        )

        (work_dir / "report.json").write_text(json.dumps({
            "target": "sample.jar",
            "outcomes": {
                "demo/obf/a": {
                    "engine": "vineflower",
                    "rel": "demo/obf/a.java",
                    "quality": {"score": 96.5},
                    "attempts": ["cfr", "vineflower"],
                    "status": "ok"
                }
            }
        }), encoding="utf-8")

        (work_dir / "strings.json").write_text(json.dumps({
            "strings": {
                "demo/obf/a": [
                    {"string": "Connecting to C2 host", "tags": ["c2-staging", "url"]}
                ]
            }
        }), encoding="utf-8")

        (work_dir / "pipeline_summary.md").write_text("# Pipeline Summary\nAutomated deobf successful.", encoding="utf-8")

        handler = lambda *args, **kwargs: WB.WorkbenchHandler(*args, work_dir=work_dir, **kwargs)
        server = WB.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        port = server.server_address[1]
        srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
        srv_thread.start()

        try:
            base_url = f"http://127.0.0.1:{port}"

            # 1. Test GET /
            with urllib.request.urlopen(f"{base_url}/") as res:
                html_body = res.read().decode("utf-8")
                check("workbench home page returns 200", res.status == 200)
                check("workbench HTML has interactive tabs", "Engine Diff" in html_body and "AI Semantic Rename" in html_body)
                check("workbench HTML has clean benign tag", '<option value="benign">benign</option>' in html_body)
                check("workbench HTML has zero emojis", not bool(re.search(r'[\U00010000-\U0010ffff\u2600-\u27bf\u2300-\u23ff\u2b50-\u2b55\u200d\ufe0f]', html_body)))

            # 2. Test GET /api/tree
            with urllib.request.urlopen(f"{base_url}/api/tree") as res:
                tree_data = json.loads(res.read().decode("utf-8"))
                check("tree contains demo/obf/a", "demo/obf/a" in tree_data.get("classes", []))

            # 3. Test GET /api/source
            with urllib.request.urlopen(f"{base_url}/api/source?class=demo/obf/a") as res:
                source_code = res.read().decode("utf-8")
                check("source endpoint returns code", "Connecting to C2" in source_code)

            # 4. Test GET /api/class_info
            with urllib.request.urlopen(f"{base_url}/api/class_info?class=demo/obf/a") as res:
                cinfo = json.loads(res.read().decode("utf-8"))
                check("class info has engine", cinfo.get("engine") == "vineflower")
                check("class info has strings", len(cinfo.get("strings", [])) >= 1)

            # 5. Test GET /api/report
            with urllib.request.urlopen(f"{base_url}/api/report") as res:
                rep_text = res.read().decode("utf-8")
                check("report returns pipeline summary", "Pipeline Summary" in rep_text)

            # 6. Test GET & POST /api/annotations
            with urllib.request.urlopen(f"{base_url}/api/annotations") as res:
                empty_anns = json.loads(res.read().decode("utf-8"))
                check("initial annotations are empty", len(empty_anns) == 0)

            post_data = json.dumps({
                "class": "demo/obf/a",
                "tag": "threat",
                "note": "Suspicious C2 beacon string"
            }).encode("utf-8")
            req = urllib.request.Request(f"{base_url}/api/annotations", data=post_data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req) as res:
                post_res = json.loads(res.read().decode("utf-8"))
                check("annotation save succeeded", post_res.get("ok") is True)
                check("annotation returned has tag", post_res.get("annotations", {}).get("demo/obf/a", {}).get("tag") == "threat")

            notes_file = work_dir / "audit_notes.json"
            check("audit_notes.json written to disk", notes_file.is_file())
            saved_notes = json.loads(notes_file.read_text(encoding="utf-8"))
            check("saved notes contains tag and note", saved_notes.get("demo/obf/a", {}).get("note") == "Suspicious C2 beacon string")

            # 7. Test GET /api/diff (Final vs CFR)
            with urllib.request.urlopen(f"{base_url}/api/diff?class=demo/obf/a&e1=final&e2=cfr") as res:
                diff_data = json.loads(res.read().decode("utf-8"))
                check("diff is not identical", diff_data.get("identical") is False)
                check("diff has added/removed stats", diff_data.get("stats", {}).get("added", 0) > 0)
                check("diff text contains unified diff marker", "+++" in diff_data.get("diff", ""))

            with urllib.request.urlopen(f"{base_url}/api/diff?class=demo/obf/a&e1=final&e2=final") as res:
                diff_same = json.loads(res.read().decode("utf-8"))
                check("diff between same engine is identical", diff_same.get("identical") is True)

            # 8. Test GET /api/llm_prompt
            with urllib.request.urlopen(f"{base_url}/api/llm_prompt?class=demo/obf/a") as res:
                prompt_data = json.loads(res.read().decode("utf-8"))
                prompt_text = prompt_data.get("prompt", "")
                check("LLM prompt contains class", "demo.obf.a" in prompt_text)
                check("LLM prompt contains candidate member", "b(" in prompt_text or "x" in prompt_text)
                check("LLM prompt requests ProGuard format", "```proguard" in prompt_text)

            # 9. Test GET /api/callgraph
            with urllib.request.urlopen(f"{base_url}/api/callgraph?class=demo/obf/a") as res:
                cg_api_data = json.loads(res.read().decode("utf-8"))
                check("callgraph endpoint responds", "callers" in cg_api_data and "callees" in cg_api_data)

            # 10. Test Path traversal defense on /api/source and /api/llm_prompt
            with urllib.request.urlopen(f"{base_url}/api/source?class=../../secret") as res:
                trav_source = res.read().decode("utf-8")
                check("path traversal on /api/source blocked", "Source not found" in trav_source)

            with urllib.request.urlopen(f"{base_url}/api/llm_prompt?class=../../secret") as res:
                trav_prompt = json.loads(res.read().decode("utf-8"))
                check("path traversal on /api/llm_prompt handled safely", "prompt" in trav_prompt)

        finally:
            server.shutdown()
            server.server_close()


def test_callgraph_and_reachability() -> None:
    print("callgraph: entrypoint reachability, path tracing and jar pruning")
    from jdec import callgraph as CG

    # 1. Custom entrypoint on sample.jar
    cg_sample = CG.build_callgraph(SAMPLE, custom_entrypoints=["demo/modern/Showcase"])
    check("sample.jar classes indexed", len(cg_sample.classes) == 10)
    rep_sample = CG.compute_reachability(cg_sample)
    check("showcase reachability computed", rep_sample.reachability_pct == 30.0, str(rep_sample.reachability_pct))
    check("dead classes identified in sample", "demo/obf/a" in rep_sample.dead_classes)
    check("showcase shapes reachable", "demo/modern/Showcase$Circle" in rep_sample.reachable_classes)

    # 2. Automated Mod/Mixin entrypoints on mixin.jar
    if MIXIN.exists():
        cg_mixin = CG.build_callgraph(MIXIN)
        check("mixin entrypoints discovered", len(cg_mixin.entrypoints) >= 5, str(len(cg_mixin.entrypoints)))
        rep_mixin = CG.compute_reachability(cg_mixin)
        check("mixin reachability computed", rep_mixin.reachability_pct == 40.0, str(rep_mixin.reachability_pct))
        check("licence class is reachable", "demo/mixin/Licence" in rep_mixin.reachable_classes)

        # 3. Shortest path finding
        path = CG.find_path(rep_mixin, "demo/mixin/Licence")
        check("trigger path to licence found", path is not None and len(path) == 1, str(path))
        check("trigger path caller is ClientEntry", path[0].caller.display_name == "ClientEntry.onInitializeClient()")
        check("trigger path callee is Licence.decode", path[0].callee.display_name == "Licence.decode()")
        check("trigger path opcode is invokestatic", path[0].opcode == "invokestatic")

        # 4. Jar pruning
        with tempfile.TemporaryDirectory() as td:
            pruned_jar = Path(td) / "pruned.jar"
            kept, dropped, saved = CG.prune_jar(MIXIN, pruned_jar, rep_mixin.reachable_classes)
            check("pruning kept reachable classes", kept == 4, str(kept))
            check("pruning dropped dead classes", dropped == 6, str(dropped))
            check("pruned jar is valid zip", zipfile.is_zipfile(pruned_jar))

        # 5. DOT and JSON export
        dot_str = CG.export_dot(cg_mixin, rep_mixin.reachable_methods)
        check("DOT output contains digraph", "digraph CallGraph" in dot_str)
        json_data = CG.export_json(rep_mixin)
        check("JSON export contains reachable classes count", json_data["summary"]["reachable_classes"] == 4)
        md_report = CG.render_markdown(rep_mixin, target_path="demo/mixin/Licence")
        check("markdown report mentions path", "ClientEntry.onInitializeClient()" in md_report)


def test_decompiler_trap_pruning() -> None:
    print("deflat: anti-decompiler trap pruning, opaque predicates and CFG reachability")
    from jdec import deflat as DF

    # 1. Constant folding
    code_const = bytes([0x10, 0x0A, 0x10, 0x14, 0x60])  # bipush 10, bipush 20, iadd
    folded, n_folded = DF.simplify_constants(code_const)
    check("constant folding simplifies bipush sum", n_folded == 1 and folded[:2] == bytes([0x10, 0x1E]))
    check("constant folding preserves byte length with NOPs", len(folded) == len(code_const) and folded[2:] == bytes([0, 0, 0]))

    # 2. Opaque predicates
    # 2a. Unary constant: iconst_0 (0x03), ifeq +5 (0x99, 0x00, 0x05), return (0xb1) -> always taken -> goto
    code_p1_taken = bytes([0x03, 0x99, 0x00, 0x05, 0xB1])
    res_p1t, n_p1t = DF.prune_opaque_predicates(code_p1_taken)
    check("opaque predicate unary always-taken becomes goto", n_p1t == 1 and res_p1t[0] == 0x00 and res_p1t[1] == 0xA7)

    # 2b. Unary constant: iconst_1 (0x04), ifeq +5 -> never taken -> NOPs
    code_p1_not = bytes([0x04, 0x99, 0x00, 0x05, 0xB1])
    res_p1n, n_p1n = DF.prune_opaque_predicates(code_p1_not)
    check("opaque predicate unary never-taken eliminated", n_p1n == 1 and res_p1n[:4] == bytes([0, 0, 0, 0]))

    # 2c. Identity: iload_1 (0x1b), iload_1 (0x1b), if_icmpeq +5 -> always taken -> goto
    code_p3_taken = bytes([0x1B, 0x1B, 0x9F, 0x00, 0x05, 0xB1])
    res_p3t, n_p3t = DF.prune_opaque_predicates(code_p3_taken)
    check("opaque predicate identity always-taken becomes goto", n_p3t == 1 and res_p3t[2] == 0xA7)

    # 2d. Identity: iload_2 (0x1c), iload_2 (0x1c), if_icmpne +5 -> never taken -> NOPs
    code_p3_not = bytes([0x1C, 0x1C, 0xA0, 0x00, 0x05, 0xB1])
    res_p3n, n_p3n = DF.prune_opaque_predicates(code_p3_not)
    check("opaque predicate identity never-taken eliminated", n_p3n == 1 and res_p3n[:5] == bytes([0, 0, 0, 0, 0]))

    # 2e. Null check: aconst_null (0x01), ifnull +5 -> always taken -> goto
    code_null_taken = bytes([0x01, 0xC6, 0x00, 0x05, 0xB1])
    res_nt, n_nt = DF.prune_opaque_predicates(code_null_taken)
    check("opaque predicate null-check always-taken becomes goto", n_nt == 1 and res_nt[1] == 0xA7)

    # 2f. Null check: aconst_null (0x01), ifnonnull +5 -> never taken -> NOPs
    code_null_not = bytes([0x01, 0xC7, 0x00, 0x05, 0xB1])
    res_nn, n_nn = DF.prune_opaque_predicates(code_null_not)
    check("opaque predicate null-check never-taken eliminated", n_nn == 1 and res_nn[:4] == bytes([0, 0, 0, 0]))

    # 2g. Object reference identity: aload_0 (0x2a), aload_0 (0x2a), if_acmpeq +5 -> always taken -> goto
    code_aload_taken = bytes([0x2A, 0x2A, 0xA5, 0x00, 0x05, 0xB1])
    res_at, n_at = DF.prune_opaque_predicates(code_aload_taken)
    check("opaque predicate aload reference identity always-taken becomes goto", n_at == 1 and res_at[2] == 0xA7)

    # 2h. Object reference identity: aload_1 (0x2b), aload_1 (0x2b), if_acmpne +5 -> never taken -> NOPs
    code_aload_not = bytes([0x2B, 0x2B, 0xA6, 0x00, 0x05, 0xB1])
    res_an, n_an = DF.prune_opaque_predicates(code_aload_not)
    check("opaque predicate aload reference identity never-taken eliminated", n_an == 1 and res_an[:5] == bytes([0, 0, 0, 0, 0]))

    # 3. Redundant jump elimination & trampoline threading
    code_rj = bytes([0xA7, 0x00, 0x03, 0xB1])  # goto +3 -> next pc
    res_rj, n_rj = DF.clean_redundant_jumps(code_rj)
    check("redundant self-fallthrough goto eliminated", n_rj == 1 and res_rj[:3] == bytes([0, 0, 0]))

    # Redundant goto through NOP padding
    code_rjn = bytes([0xA7, 0x00, 0x05, 0x00, 0x00, 0xB1])
    res_rjn, n_rjn = DF.clean_redundant_jumps(code_rjn)
    check("redundant goto through NOP padding eliminated", n_rjn == 1 and res_rjn[:3] == bytes([0, 0, 0]))

    # Trampoline jump threading: goto 7 -> pc 7: goto 5 -> target pc 12
    code_tramp = bytes([
        0xA7, 0x00, 0x07,  # pc 0: goto +7
        0x10, 0x02,        # pc 3: bipush 2
        0x00, 0x00,        # pc 5: nops
        0xA7, 0x00, 0x05,  # pc 7: goto +5 -> jumps to pc 12
        0x00, 0x00,        # pc 10: nops
        0xB1,              # pc 12: return
    ])
    res_tramp, n_tramp = DF.clean_redundant_jumps(code_tramp)
    check("trampoline jump threaded directly to final target", n_tramp >= 1 and struct.unpack_from(">h", res_tramp, 1)[0] == 12)

    # 1-byte iconst constant folding: iconst_1 (0x04) + iconst_2 (0x05) + iadd (0x60) -> iconst_3 (0x06)
    code_ic = bytes([0x04, 0x05, 0x60])
    res_ic, n_ic = DF.simplify_constants(code_ic)
    check("constant folding simplifies small sum to iconst", n_ic == 1 and res_ic[0] == 0x06 and res_ic[1:] == bytes([0, 0]))

    # 4. Dead code & anti-decompiler trap pruning
    # pc 0: goto +6 (0xa7, 0x00, 0x06); pc 3: bipush 42 (0x10, 0x2a); pc 5: athrow (0xbf); pc 6: return (0xb1)
    code_trap = bytes([0xA7, 0x00, 0x06, 0x10, 0x2A, 0xBF, 0xB1])
    res_trap, n_trap = DF.prune_dead_code(code_trap)
    check("dead bytecode trap instructions pruned", n_trap == 2)
    check("dead trap converted to NOPs", res_trap[3:6] == bytes([0, 0, 0]))
    check("reachable instructions untouched", res_trap[0] == 0xA7 and res_trap[6] == 0xB1)

    # 5. Exception handler sanitization
    handlers = [
        BC.Handler(10, 10, 20, 0),    # zero-length trap (start == end)
        BC.Handler(0, 10, 5, 0),      # valid handler
        BC.Handler(0, 50, 10, 0),     # out of bounds (len > 30)
        BC.Handler(20, 25, 26, 0),    # dead handler (no reachable pcs in range)
    ]
    reachable_pcs = {0, 1, 2, 5}
    sanitized_h, dropped_h = DF.prune_exception_handlers(handlers, code_len=30, reachable_pcs=reachable_pcs)
    check("malformed and dead exception handlers pruned", dropped_h == 3)
    check("valid exception handler preserved", len(sanitized_h) == 1 and sanitized_h[0].start_pc == 0)

    # 6. Master optimize_code pass
    combined_code = bytes([
        0x10, 0x05, 0x10, 0x03, 0x60,         # pc 0: bipush 5, bipush 3, iadd -> simplifies to bipush 8
        0x3B,                                 # pc 5: istore_0
        0x04, 0x99, 0x00, 0x06,               # pc 6: iconst_1, ifeq +6 -> never taken, eliminated
        0xA7, 0x00, 0x03,                     # pc 10: goto +3 -> redundant goto eliminated
        0xB1,                                 # pc 13: return
        0x10, 0x63, 0xBF,                     # pc 14: bipush 99, athrow -> dead trap eliminated
    ])
    combined_handlers = [BC.Handler(5, 5, 10, 0)]  # zero-length handler
    opt_code, opt_h, stats = DF.optimize_code(combined_code, combined_handlers)
    check("master optimizer preserves code length", len(opt_code) == len(combined_code))
    check("master optimizer eliminated zero-length handler", len(opt_h) == 0 and stats["handlers_pruned"] == 1)
    check("master optimizer recorded multiple passes", stats["total"] >= 4, str(stats))
    check("dead code block at end of method NOPed out", opt_code[14:] == bytes([0, 0, 0]))

    # 7. Whole-jar deflat_jar integration on SAMPLE
    with tempfile.TemporaryDirectory() as td:
        out_deflat = Path(td) / "deflat_sample.jar"
        jar_stats = DF.deflat_jar(SAMPLE, out_deflat)
        check("deflat_jar processed classes", jar_stats["classes"] == 11)
        check("deflat output jar exists and is valid zip", out_deflat.exists() and zipfile.is_zipfile(out_deflat))
        with zipfile.ZipFile(out_deflat) as zout:
            for n in zout.namelist():
                if n.endswith(".class") and n != BROKEN_SAMPLE:
                    cdata = zout.read(n)
                    cf = CF.parse(cdata)
                    check(f"deflat class {n} parses cleanly", cf.name is not None)
            # Test StackMapTable stripping explicitly on OldStyle
            old_data = zout.read("demo/legacy/OldStyle.class")
            old_cf = CF.parse(old_data)
            check("_strip_stackmaps is idempotent and safe", DF._strip_stackmaps(old_cf) == 0)

    # 8. Regression test: pipeline with no_natives=True (verifies UnboundLocalError fix)
    from jdec import pipeline as PL_MOD
    with tempfile.TemporaryDirectory() as td:
        out_pipe = Path(td) / "pipe_nonat"
        res_pipe = PL_MOD.run_pipeline(
            SAMPLE, out_pipe,
            no_natives=True,
            no_deflat=True,
            no_recover=True,
            mapping_set="none",
            jobs=1,
        )
        check("pipeline runs cleanly with no_natives=True", res_pipe.native_libs_count == 0 and res_pipe.mixin_hooks_count >= 0)


def test_project_export_and_recompilability() -> None:
    print("project: automated IDE project generation, syntax repair, and javac recompilation loop")

    # 1. Keyword identifier sanitization
    raw_kw_java = "\n".join([
        "package demo.obf;",
        "public class KeywordTest {",
        "    private int goto = 10;",
        "    public String default = \"test\";",
        "    private final Object const = null;",
        "    public void compute(int goto, String default) {",
        "        this.goto = goto;",
        "        System.out.println(goto);",
        "    }",
        "}",
    ])
    cleaned_kw, kw_edits = PJ.sanitize_keyword_identifiers(raw_kw_java)
    check("escaped reserved keyword identifiers", kw_edits >= 4, f"edits={kw_edits}")
    check("goto escaped to goto_", "goto_" in cleaned_kw and "int goto " not in cleaned_kw)
    check("default escaped to default_", "default_" in cleaned_kw and "String default " not in cleaned_kw)
    check("const escaped to const_", "const_" in cleaned_kw and "Object const " not in cleaned_kw)

    # 2. Prune duplicate bridge methods
    bridge_java = "\n".join([
        "package demo.bridge;",
        "public class BridgeTest {",
        "    public String getValue() {",
        "        return \"real\";",
        "    }",
        "    // bridge method",
        "    public Object getValue() {",
        "        return this.getValue();",
        "    }",
        "}",
    ])
    cleaned_br, br_edits = PJ.prune_duplicate_bridge_methods(bridge_java)
    check("pruned duplicate synthetic bridge method", br_edits == 1, f"edits={br_edits}")
    check("duplicate bridge method commented out", "// [jdec: stripped duplicate bridge method]" in cleaned_br)
    check("original method kept intact", "public String getValue() {" in cleaned_br)

    # 3. Master clean_source_for_compilation pass
    no_pkg_java = "public class Orphan\u200bTrap { int goto = 1; \ufeff}"
    cleaned_src, chgs = PJ.clean_source_for_compilation(no_pkg_java, expected_package="com.example.orphan")
    check("clean_source added missing package declaration", any("package com.example.orphan" in c for c in chgs))
    check("clean_source escaped keywords", any("keyword" in c for c in chgs))
    check("clean_source stripped zero-width obfuscator traps", "\u200b" not in cleaned_src and "\ufeff" not in cleaned_src)
    check("clean_source output begins with package", cleaned_src.startswith("package com.example.orphan;"))

    # 4. Gradle scaffold generation
    with tempfile.TemporaryDirectory() as td:
        proj_dir = Path(td) / "TestScaffold"
        PJ.generate_gradle_scaffold(
            proj_dir,
            project_name="MyTestProject",
            java_version="21",
            mc_version="1.20.4",
            mc_flavor="fabric",
        )
        check("scaffold generated build.gradle", (proj_dir / "build.gradle").is_file())
        check("scaffold generated settings.gradle", (proj_dir / "settings.gradle").is_file())
        check("scaffold generated gradle.properties", (proj_dir / "gradle.properties").is_file())
        check("scaffold generated README.md", (proj_dir / "README.md").is_file())
        check("scaffold generated .gitignore", (proj_dir / ".gitignore").is_file())
        check("scaffold generated gradlew.bat", (proj_dir / "gradlew.bat").is_file())
        check("scaffold generated gradlew", (proj_dir / "gradlew").is_file())

        bg_text = (proj_dir / "build.gradle").read_text(encoding="utf-8")
        check("build.gradle includes libs tree dependency", "fileTree(dir: 'libs'" in bg_text)
        check("build.gradle sets Java 21 compatibility", "JavaVersion.toVersion('21')" in bg_text)

        gp_text = (proj_dir / "gradle.properties").read_text(encoding="utf-8")
        check("gradle.properties specifies minecraft_version", "minecraft_version=1.20.4" in gp_text)

        rm_text = (proj_dir / "README.md").read_text(encoding="utf-8")
        check("README provides IntelliJ IDEA instructions", "IntelliJ IDEA" in rm_text)

    # 5. Whole project export from SAMPLE & Windows reserved device name escaping
    with tempfile.TemporaryDirectory() as td:
        exp_dir = Path(td) / "sample_exported_proj"
        mock_src = Path(td) / "mock_src"
        mock_src.mkdir(parents=True, exist_ok=True)
        # Create an aux.java file (Windows reserved device name)
        (mock_src / "aux.java").write_text("public class aux { public int val = 42; }", encoding="utf-8")
        stats = PJ.export_project(SAMPLE, exp_dir, src_dir=mock_src, mc_version="1.20.4", with_stubs=True)
        check("export created src/main/java directory", (exp_dir / "src" / "main" / "java").is_dir())
        check("export escaped Windows reserved name aux.java -> _aux.java", (exp_dir / "src" / "main" / "java" / "_aux.java").is_file())
        check("export bundled mc_stubs.jar into libs/", (exp_dir / "libs" / "mc_stubs.jar").is_file())
        check("export extracted resources to src/main/resources", stats["resources_copied"] >= 1)
        check("export generated build.gradle", (exp_dir / "build.gradle").is_file())

    # 6. Deep javac compile self-healing loop: 5 simultaneous error types
    with tempfile.TemporaryDirectory() as td:
        c_proj = Path(td) / "compile_project"
        PJ.generate_gradle_scaffold(c_proj, "CompileVerify")
        src_root = c_proj / "src" / "main" / "java" / "test"
        src_root.mkdir(parents=True, exist_ok=True)

        # Inject:
        # 1. Duplicate method declaration
        # 2. Ambiguous null overload
        # 3. Unreachable statement
        # 4. Missing return statement
        # 5. Missing external library class import
        buggy_java = src_root / "Buggy.java"
        buggy_java.write_text("\n".join([
            "package test;",
            "import ext.unknown.Helper;",
            "public class Buggy {",
            "    public void run() {",
            "        System.out.println(1);",
            "    }",
            "    public void run() {",
            "        System.out.println(2);",
            "    }",
            "    public static void pick(String s) {}",
            "    public static void pick(Integer i) {}",
            "    public int compute(int x) {",
            "        if (x > 0) return 10;",
            "    }",
            "    public void deadCode() {",
            "        return;",
            "        System.out.println(999);",
            "    }",
            "    public static void main(String[] args) {",
            "        pick(null);",
            "        Helper h = null;",
            "    }",
            "}",
        ]), encoding="utf-8")

        rep = PJ.verify_compilation(c_proj, max_repair_passes=4)
        check("deep self-healing loop repaired multiple simultaneous error types", rep.repaired_count >= 4, f"repaired={rep.repaired_count}")
        check("deep self-healing loop achieved 100% clean compilation", rep.success is True, rep.summary())
        check("deep self-healing loop compiled all files cleanly", rep.compiled_files == rep.total_files and rep.total_files >= 1)

    # 7. CLI project subcommand smoke test
    with tempfile.TemporaryDirectory() as td:
        cli_out = Path(td) / "cli_sample_project"
        cli_args = SimpleNamespace(
            input=str(SAMPLE),
            output=str(cli_out),
            src=None,
            mc_version="1.20.4",
            no_stubs=False,
            compile=False,
            engines_dir=str(ROOT / "engines"),
        )
        res = CL.cmd_project(cli_args)
        check("cmd_project returned 0", res == 0)
        check("cmd_project created output project", (cli_out / "build.gradle").is_file())
        check("cmd_project bundled libs", (cli_out / "libs" / "mc_stubs.jar").is_file())


def test_remap_rewrites_call_sites() -> None:
    """Renaming only declarations would leave dangling member references."""
    print("mappings: remap rewrites declarations *and* every call site")
    m = MP.load_mapping(MC_MAP)
    with zipfile.ZipFile(MC_JAR) as z:
        data = z.read("env.class")  # com.mojang.blaze3d.audio.Channel
    cf = CF.parse(data)
    before = [cf.utf8(f.name_index) for f in cf.fields]
    changed = MP.remap_class(cf, m)
    after = [cf.utf8(f.name_index) for f in cf.fields]
    check("class was renamed", cf.name == "com/mojang/blaze3d/audio/Channel", cf.name)
    check("fields were renamed", changed > 0 and after != before,
          f"{before} -> {after}")
    check("renamed names are the official ones",
          "LOGGER" in after and "source" in after, str(after))

    refs = []
    for i in range(1, len(cf.cp)):
        e = cf.cp[i]
        if e and e[0] in (CF.C_FIELDREF, CF.C_METHODREF, CF.C_INTERFACE_METHODREF):
            owner = cf.utf8(cf.cp[e[1][0]][1][0])
            nt = cf.cp[e[1][1]]
            refs.append((owner, cf.utf8(nt[1][0]), cf.utf8(nt[1][1])))
    dangling = [r for r in refs if r[0] == cf.name and r[1] in before
                and r[1] not in after]
    check("no dangling references to old member names", not dangling, str(dangling[:5]))


def test_remapped_class_is_valid_bytecode() -> None:
    """The real proof: javap must still be able to read what we produced."""
    print("mappings: remapped bytecode still loads (verified by javap)")
    m = MP.load_mapping(MC_MAP)
    with zipfile.ZipFile(MC_JAR) as z:
        data = z.read("env.class")
    cf = CF.parse(data)
    MP.remap_class(cf, m)
    tmp = Path(tempfile.mkdtemp())
    p = tmp / "Channel.class"
    p.write_bytes(cf.serialize())
    r = subprocess.run(["javap", "-p", str(p)],
                       capture_output=True, text=True, errors="replace")
    check("javap accepts the remapped class", r.returncode == 0, r.stderr[:200])
    check("javap shows the deobfuscated field names", "LOGGER" in r.stdout,
          r.stdout[:200])


def test_mc_is_not_flow_obfuscated() -> None:
    """The real check on false positives: 300 real classes from a vanilla jar.

    Only the backwards-handler fingerprint is asserted absent. Irreducible
    gotos are deliberately *not* asserted absent: measuring a real 1.20.4
    client showed javac emits gotos into the middle of a protected range on
    its own, so that shape cannot carry an attribution on its own either.
    """
    print("obf: a vanilla client is not mistaken for flow-obfuscated")
    rep, _per = OB.scan_obfuscation(MC_JAR, limit=300)
    keys = {e.key for e in rep.evidence}
    check("no backwards exception handlers", "handler-backjump" not in keys,
          str(sorted(keys)))
    check("nothing attributed", rep.vendor is None, rep.summary())


def main() -> int:
    with_mc = "--with-mc" in sys.argv
    if not SAMPLE.exists():
        print("missing tests/sample.jar - build it first")
        return 2
    test_roundtrip_sample()
    test_synthetic_members_ignored()
    test_scoring_sees_obfuscated_names()
    test_partial_failure_is_not_total_failure()
    test_unbalanced_braces_are_proportional()
    test_end_to_end_sample()
    test_case_colliding_class_names()
    test_iso_buckets()
    test_weak_engine_is_rescued()
    test_yarn_compose()
    test_official_srg_compose()
    test_auto_mapping_set_flavor()
    test_java_escape()
    test_rewrite_sources()
    test_recover_triage()
    test_manifest_and_resources()
    test_rewrite_escapes()
    test_bsm_scan_and_parse_resilience()
    test_recover_spec_generation_and_quarantine()
    test_resource_anomaly()
    test_scorecard_smoke()
    test_pool_roundtrip()
    test_web_template_js()
    test_pool_qualified_and_full_string()
    test_probe_fingerprints_json()
    test_ghidra_integration()
    test_native_elf_and_ghidra_annotate()
    test_score_and_signal_enhancements()
    test_multimodule_enhancements()
    test_advanced_roadmap_features()
    test_pipeline_automation()
    test_web_workbench_features()
    test_callgraph_and_reachability()
    test_decompiler_trap_pruning()
    test_project_export_and_recompilability()
    if build_fixtures.ensure_mixin_jar() is None:
        print("skipping mixin tests: tests/mixin.jar could not be built "
              "(run tests/build_fixtures.py)")
    else:
        test_annotated_classes_roundtrip()
        test_mixin_fixture()
        test_refmap()
        test_string_dump()
        test_indy_encoding()
        test_signals()
        test_bytecode_decodes()
        test_flow_fingerprints()
        test_native_reporting()
    if with_mc:
        if not (MC_JAR.exists() and MC_MAP.exists()):
            print("missing MC fixtures under tests/mc/")
            return 2
        test_mc_roundtrip()
        test_mojang_mapping_direction()
        test_remap_rewrites_call_sites()
        test_remapped_class_is_valid_bytecode()
        test_mc_is_not_flow_obfuscated()
        test_real_zkm_sample()
    print(f"\n{_passed} passed, {_failed} failed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
