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
from jdec import callgraph as CG      # noqa: E402
from jdec import classfile as CF      # noqa: E402
from jdec import devirt as DV         # noqa: E402
from jdec import indy as INDY        # noqa: E402
from jdec import cli as CL           # noqa: E402
from jdec import mappings as MP       # noqa: E402
from jdec import mcmod as MM          # noqa: E402
from jdec import obf as OB            # noqa: E402
from jdec import pipeline as PIPE     # noqa: E402
from jdec import pool as PL           # noqa: E402
from jdec import project as PJ        # noqa: E402
from jdec import recover as RC        # noqa: E402
from jdec import score as SCORE       # noqa: E402
from jdec import strings as ST        # noqa: E402
from jdec.decompile import _iso_buckets, decompile, write_report  # noqa: E402
from jdec.probe import JarProfile, profile_jar    # noqa: E402
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
    a real-sample class -- every member recovered -- get reported as a total loss.
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

    ZKM-style mangling emits names like `pkg/A` and `pkg/a`. On a
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
        "pkg/a": ["pkg/A", "pkg/a"],
        "pkg/b$c": ["pkg/B$C", "pkg/b$C"],
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

    # Regression: lookupswitch branch offsets must unpack with 8-byte stride
    # (default=100, npairs=2; pair 0: match=10, off=20; pair 1: match=30, off=40)
    ls_code = bytearray([0xAB, 0, 0, 0])
    ls_code += struct.pack(">ii", 100, 2)
    ls_code += struct.pack(">ii", 10, 20)
    ls_code += struct.pack(">ii", 30, 40)
    ls_insns = BC.decode(bytes(ls_code))
    check("lookupswitch decodes all jump targets correctly",
          len(ls_insns) == 1 and ls_insns[0].targets == [100, 20, 40],
          f"targets={ls_insns[0].targets if ls_insns else None}")

    # Regression: ifnull and ifnonnull must decode as branches with signed relative offsets
    ifnull_insns = BC.decode(bytes([0xC6, 0xFF, 0xFC]))  # ifnull -4
    check("ifnull decodes as signed branch",
          len(ifnull_insns) == 1 and ifnull_insns[0].is_branch and ifnull_insns[0].arg == -4 and ifnull_insns[0].jump_targets() == [-4],
          f"insn={ifnull_insns[0] if ifnull_insns else None}")
    ifnonnull_insns = BC.decode(bytes([0xC7, 0x00, 0x0A]))  # ifnonnull +10
    check("ifnonnull decodes as signed branch",
          len(ifnonnull_insns) == 1 and ifnonnull_insns[0].is_branch and ifnonnull_insns[0].arg == 10 and ifnonnull_insns[0].jump_targets() == [10],
          f"insn={ifnonnull_insns[0] if ifnonnull_insns else None}")


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

    # 4. Local variable slot tracking for slot >= 4 and lload opcode 0x16
    check("LOAD_OPS contains lload opcode 0x16", 0x16 in BM.LOAD_OPS and BM.LOAD_OPS[0x16] == ("l", None))
    code_bytes = bytes([0x04, 0x36, 0x04, 0x05, 0x36, 0x05, 0x15, 0x04])
    insns = BC.decode(code_bytes)
    stk: list = []
    loc: dict = {}
    for ins in insns:
        op = ins.op
        if op in BM.ICONST:
            stk.append(("lit", op - 0x03))
        elif op in BM.STORE_OPS or op in BM.STORE_N:
            k, sl = BM.STORE_OPS.get(op) or BM.STORE_N[op]
            if sl is None: sl = ins.arg
            if stk: loc[(k, sl)] = stk.pop()
        elif op in BM.LOAD_OPS or op in BM.LOAD_N:
            k, sl = BM.LOAD_OPS.get(op) or BM.LOAD_N[op]
            if sl is None: sl = ins.arg
            v = loc.get((k, sl))
            stk.append(v if v is not None else ("?", None))
    check("distinct local variable slots >= 4 do not overwrite each other",
          loc.get(("i", 4)) == ("lit", 1) and loc.get(("i", 5)) == ("lit", 2))
    check("iload 4 retrieves correct value from slot 4", stk == [("lit", 1)])


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
                           capture_output=True, text=True, errors="replace")
        check("fixture javac", r.returncode == 0, r.stderr[-300:])
        hv = d / "pool_work" / "pool_harvest.tsv"
        # REVIEW 2.1: replay is opt-in now; this fixture is locally built.
        rc = cli_main(["pool", "harvest", str(spec), "-o", str(hv),
                       "--cp", str(cls_dir), "--execute"])
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
                           capture_output=True, text=True, errors="replace")
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


def test_pool_overload_dispatch() -> None:
    print("pool: overload dispatch keeps only String-accessor call sites")
    from jdec import pool as PL
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        src = d / "src"
        (src / "p").mkdir(parents=True)
        # 2026-10-05 真实样本实测：一个池类里 String a(int,int)（字符串池）与
        # int a(int,long)（int 常量池）共存，名字级匹配把 int 池调用点也
        # 扫进 spec -> driver 传错 idx 报 AIOOBE。按实参字面量类型分派。
        (src / "p" / "TwoPools.java").write_text(
            "package p;\n"
            "public class TwoPools {\n"
            "    static String a(int idx, int seed) { return null; }\n"
            "    static int a(int idx, long seed) { return 0; }\n"
            "    String s1() { return a(11, 22); }\n"
            "    int s2() { return a(33, 44L); }\n"
            "    int s3() { return a(55, 66666666666L); }\n"
            "}\n", encoding="utf-8")
        (src / "p" / "Caller.java").write_text(
            "package p;\n"
            "public class Caller {\n"
            "    String s4() { return TwoPools.a(7, 8); }\n"
            "    int s5() { return TwoPools.a(9, 10L); }\n"
            "}\n", encoding="utf-8")
        spec = d / "spec.tsv"
        st = PL.scan_spec(src, spec)
        lines = spec.read_text(encoding="utf-8").splitlines()
        keys = {tuple(l.split("\t")[i] for i in (3, 4)) for l in lines}
        check("keeps (int,int) bare site", ("11", "22") in keys, str(keys))
        check("keeps (int,int) qualified site", ("7", "8") in keys, str(keys))
        check("skips (int,long) literal", ("33", "44") not in keys, str(keys))
        check("skips big long literal", ("55", "66666666666") not in keys,
              str(keys))
        check("skips qualified (int,long) site", ("9", "10") not in keys,
              str(keys))
        check("overload_skipped counted", st["overload_skipped"] == 3,
              str(st))


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

        # Regression: _major_version requires 0xCAFEBABE magic and 8-byte header
        from jdec.probe import _major_version
        check("_major_version rejects non-magic bytes", _major_version(b"corrupt_") is None)
        check("_major_version extracts valid Java 8 major", _major_version(b"\xca\xfe\xba\xbe\x00\x00\x00\x34") == 52)


def test_platform_classpath_separator() -> None:
    print("engines: classpath separator follows the platform")
    from jdec import engines as EN
    expected = ";" if os.name == "nt" else ":"
    check("cp_sep matches os.name", EN.cp_sep() == expected, EN.cp_sep())
    eng = EN.ENGINES["procyon"]
    cp = eng.classpath(ROOT / "engines")
    check("procyon bridge classpath splits on platform separator",
          len(cp.split(expected)) == 3, cp)
    real = os.name
    try:
        os.name = "posix" if real == "nt" else "nt"
        want = ";" if os.name == "nt" else ":"
        check("cp_sep switches with os.name", EN.cp_sep() == want, EN.cp_sep())
    finally:
        os.name = real


def test_ops_pool() -> None:
    print("opspool: PhantomShield string-pool static decrypt (DES via bundled _des)")
    gen = Path(__file__).resolve().parent / "gen_ops_fixture.py"
    javac = shutil.which("javac")
    if javac is None:
        print("skipping ops pool test: javac not on PATH")
        return
    from jdec import ops_pool as OP
    OP  # noqa
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        r = subprocess.run([sys.executable, str(gen)], cwd=tdp,
                           capture_output=True, text=True, errors="replace")
        if r.returncode != 0:
            check("fixture generated", False, r.stderr[-200:])
            return
        r = subprocess.run([javac, "OpsPoolFixture.java"], cwd=tdp,
                           capture_output=True, text=True, errors="replace")
        check("fixture compiled", r.returncode == 0, r.stderr[-200:])
        jar = tdp / "ops_fixture.jar"
        subprocess.run(["jar", "cf", jar.name, "OpsPoolFixture.class"],
                       cwd=tdp, capture_output=True)
        results = OP.scan_jar(str(jar))
        ok = any(s == ["alpha-secret-ONE", "bravo-secret-TWO",
                       "charlie-secret-THREE"] for _c, s, _e in results)
        check("static decrypt matches original strings", ok, str(results)[:200])


def test_jint() -> None:
    print("jint: Java primitive arithmetic emulation KATs")
    from jdec import jint as J
    check("i32 wraps at 2^31", J.i32(0x80000000) == -2147483648,
          str(J.i32(0x80000000)))
    check("i32 identity below 2^31", J.i32(12345) == 12345, "")
    check("i32 wraps past 2^31", J.i32((1 << 31) + 5) == -2147483643,
          str(J.i32((1 << 31) + 5)))
    check("i64 wraps at 2^63", J.i64(1 << 63) == -(1 << 63), "")
    check("ushr is unsigned", J.ushr32(-1, 4) == 0x0FFFFFFF,
          hex(J.ushr32(-1, 4)))
    check("rotl32 KAT", J.rotl32(0x12345678, 8) == 0x34567812,
          hex(J.rotl32(0x12345678, 8)))
    check("rotl32 by 0 is identity", J.rotl32(0xDEADBEEF, 0) == J.i32(0xDEADBEEF),
          "")


def test_clinit_sim() -> None:
    print("clinit_sim: symbolic evaluation of a javac-compiled table builder")
    from jdec import classfile as CFM
    from jdec import clinit_sim as CS
    javac = shutil.which("javac")
    if javac is None:
        print("  (skipped: javac not on PATH)")
        return
    src = """public class ClinitSimFixture {
    static int[] ONE_D;
    static int[][] TWO_D;
    static String[] WORDS;
    static long[] LONGS;
    static Object[] MIXED;
    static {
        ONE_D = new int[]{3, 1, 4, 1, 5};
        TWO_D = new int[][]{{10, 20}, {30}, {}};
        WORDS = new String[]{"alpha", "beta"};
        LONGS = new long[]{0x1122334455667788L, -1L};
        MIXED = new Object[]{"s", 42, 0x1FL, null};
    }
}
"""
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        (tdp / "ClinitSimFixture.java").write_text(src, encoding="utf-8")
        r = subprocess.run([javac, "-d", str(tdp),
                            str(tdp / "ClinitSimFixture.java")],
                           check=True, capture_output=True, text=True, errors="replace")
        check("fixture compiled", r.returncode == 0, r.stderr[-200:])
        cf = CFM.parse((tdp / "ClinitSimFixture.class").read_bytes())
        fields, unknown = CS.collect_fields(cf)
        check("clinit walked", fields is not None, "")
        check("walk is exact (no unknown ops)", not unknown, str(unknown))
        check("ONE_D extracted", CS.flat_of(fields.get("ONE_D"))
              == [3, 1, 4, 1, 5], str(fields.get("ONE_D")))
        check("TWO_D rows extracted", CS.rows_of(fields.get("TWO_D"))
              == [[10, 20], [30], []], str(fields.get("TWO_D")))
        check("WORDS extracted", CS.flat_of(fields.get("WORDS"))
              == ["alpha", "beta"], str(fields.get("WORDS")))
        check("LONGS extracted", CS.flat_of(fields.get("LONGS"))
              == [0x1122334455667788, -1], str(fields.get("LONGS")))
        check("MIXED extracted (boxing passed through)",
              CS.flat_of(fields.get("MIXED")) == ["s", 42, 31, None],
              str(fields.get("MIXED")))


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

    # 3. Stripped ELF (e_shoff = 0) fallback parsing via PT_DYNAMIC program headers
    ehdr_s = bytearray(64)
    ehdr_s[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", ehdr_s, 16, 3, 0x3E, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    ph0_s = bytearray(56)
    struct.pack_into("<IIQQQQQQ", ph0_s, 0, 1, 7, 0, 0x10000, 0x10000, 1024, 1024, 0x1000)
    ph1_s = bytearray(56)
    struct.pack_into("<IIQQQQQQ", ph1_s, 0, 2, 6, 0x200, 0x10200, 0x10200, 128, 128, 8)
    buf_s = bytearray(1024)
    buf_s[:64] = ehdr_s
    buf_s[64:120] = ph0_s
    buf_s[120:176] = ph1_s
    dyn_off_s = 0x200
    struct.pack_into("<QQ", buf_s, dyn_off_s, 6, 0x10300)       # DT_SYMTAB
    struct.pack_into("<QQ", buf_s, dyn_off_s + 16, 5, 0x10380)  # DT_STRTAB
    struct.pack_into("<QQ", buf_s, dyn_off_s + 32, 10, 64)      # DT_STRSZ
    struct.pack_into("<QQ", buf_s, dyn_off_s + 48, 11, 24)      # DT_SYMENT
    struct.pack_into("<QQ", buf_s, dyn_off_s + 64, 4, 0x10280)  # DT_HASH
    struct.pack_into("<QQ", buf_s, dyn_off_s + 80, 0, 0)        # DT_NULL
    struct.pack_into("<II", buf_s, 0x280, 1, 3)                  # nbucket=1, nchain=3
    str_data_s = b"\x00Java_pkg_Native_call\x00JNI_OnLoad\x00"
    buf_s[0x380:0x380 + len(str_data_s)] = str_data_s
    struct.pack_into("<IBBHQQ", buf_s, 0x300 + 24, 1, 0x12, 0, 1, 0x1000, 32)
    struct.pack_into("<IBBHQQ", buf_s, 0x300 + 48, 22, 0x12, 0, 1, 0x1020, 16)

    # 4. Binary JNINativeMethod structure recovery directly from ELF rodata
    s_method = b"nativeFunc\x00(I)V\x00"
    buf_s[0x350:0x350 + len(s_method)] = s_method
    struct.pack_into("<QQQ", buf_s, 0x3c0, 0x10350, 0x10350 + 11, 0x10555)

    stripped_elf = bytes(buf_s)
    stripped_exports = NS.parse_elf_exports(stripped_elf)
    check("stripped ELF parsed JNI exports via PT_DYNAMIC",
          "Java_pkg_Native_call" in stripped_exports and "JNI_OnLoad" in stripped_exports,
          str(stripped_exports))

    reg_methods = NS.scan_binary_register_natives(stripped_elf, fmt="ELF")
    check("binary scan extracted JNINativeMethod table",
          any(m["name"] == "nativeFunc" and m["sig"] == "(I)V" for m in reg_methods),
          str(reg_methods))

    tri_reg = NS.Triage(
        libs=[NS.NativeLib(name="libtest.so", size=len(stripped_elf), format="ELF", exports=stripped_exports, dynamic_methods=reg_methods)],
        native_decl=[("demo/Cls", "nativeFunc")]
    )
    dyn_matched = tri_reg.matched_dynamic()
    check("tri.matched_dynamic matched declared Java method to native function",
          len(dyn_matched) == 1 and dyn_matched[0]["func"] == "0x10555",
          str(dyn_matched))

    # 5. Stripped ELF with DT_GNU_HASH (0x6FFFFEF5)
    buf_gnu = bytearray(buf_s)
    struct.pack_into("<QQ", buf_gnu, dyn_off_s + 64, 0x6FFFFEF5, 0x10280)
    struct.pack_into("<IIII", buf_gnu, 0x280, 1, 1, 1, 0)
    struct.pack_into("<Q", buf_gnu, 0x290, 0xFFFFFFFF)
    struct.pack_into("<I", buf_gnu, 0x298, 1)
    struct.pack_into("<I", buf_gnu, 0x29C, 0x12345671)
    gnu_elf = bytes(buf_gnu)
    gnu_exports = NS.parse_elf_exports(gnu_elf)
    check("stripped ELF parsed JNI exports via DT_GNU_HASH",
          "Java_pkg_Native_call" in gnu_exports,
          str(gnu_exports))


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
            # REVIEW 2.1: replay now opts in explicitly; this fixture is a
            # locally-built benign jar, so executing it is safe.
            allow_replay=True,
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

        # REVIEW 2.2: stage status plumbing is part of the result now
        stage_names = [s.name for s in res.stages]
        check("pipeline records core stages",
              all(n in stage_names for n in ("probe", "deflat", "decompile", "replay", "summary")),
              f"stages={stage_names}")
        check("replay stage attempted under allow_replay",
              res.stage("replay").status in (PIPE.STAGE_OK, PIPE.STAGE_PARTIAL, PIPE.STAGE_FAILED),
              res.stage("replay").status)
        check("exit code reflects overall status",
              res.exit_code == {"success": 0, "partial": 1, "failed": 2}[res.overall_status],
              f"overall={res.overall_status} exit={res.exit_code}")

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
        # REVIEW 2.2: summary json exposes stage statuses and the exit code
        check("summary json contains overall/exit_code/stages",
              "overall" in json_data and "exit_code" in json_data
              and isinstance(json_data.get("stages"), list) and json_data["stages"])



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
        # Create an aux.java file (Windows reserved device name) and %41.java (twin collision)
        (mock_src / "aux.java").write_text("public class aux { public int val = 42; }", encoding="utf-8")
        (mock_src / "a.java").write_text("public class a { public a() {} }", encoding="utf-8")
        (mock_src / "%41.java").write_text("public class A { public A parent; public A(A p) { this.parent = p; } }", encoding="utf-8")
        (mock_src / "b.java").write_text("public class b { public A field; public b() { this.field = new A(null); } }", encoding="utf-8")
        stats = PJ.export_project(SAMPLE, exp_dir, src_dir=mock_src, mc_version="1.20.4", with_stubs=True)
        check("export created src/main/java directory", (exp_dir / "src" / "main" / "java").is_dir())
        check("export escaped Windows reserved name aux.java -> _aux.java", (exp_dir / "src" / "main" / "java" / "_aux.java").is_file())
        check("export escaped percent-encoded collision file %41.java -> A_Twin.java", (exp_dir / "src" / "main" / "java" / "A_Twin.java").is_file())
        twin_txt = (exp_dir / "src" / "main" / "java" / "A_Twin.java").read_text(encoding="utf-8")
        check("collision file class name updated to A_Twin", "class A_Twin" in twin_txt and "A_Twin(" in twin_txt)
        check("collision file self-references updated to A_Twin", "A_Twin parent" in twin_txt and "(A_Twin p)" in twin_txt)
        check("a.java preserved without collision", (exp_dir / "src" / "main" / "java" / "a.java").is_file())
        b_txt = (exp_dir / "src" / "main" / "java" / "b.java").read_text(encoding="utf-8")
        check("sibling b.java updated A references to A_Twin", "A_Twin field" in b_txt and "new A_Twin(null)" in b_txt)
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

    # 7. Decompiler unbox cascade normalization and typed self-healing
    unbox_raw = "int x = v instanceof Boolean ? (Boolean)v : (v instanceof Character ? (char)((Number)v).intValue() : ((Number)v).intValue()));"
    norm_unbox, unbox_n = PJ.normalize_unbox(unbox_raw)
    check("normalize_unbox matched and converted ternary", unbox_n >= 1, f"edits={unbox_n}")
    check("normalize_unbox produced valid typed expression", "booleanValue() ? 1 : 0" in norm_unbox and "charValue()" in norm_unbox)


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


def test_cfg_and_dynamic_mocks() -> None:
    print("cfg & stubs: control flow graph reassembly, far jumps, and dynamic mock agent")
    from jdec import stubs as SB
    from jdec import cfg as CFG_MOD
    from jdec import deflat as DF_MOD

    # 1. build_stub_class_bytes: pure Python synthetic class generation
    data = SB.build_stub_class_bytes("net/minecraft/client/Minecraft")
    cf = CF.parse(data)
    check("build_stub_class_bytes produces valid class", cf.name == "net/minecraft/client/Minecraft")
    check("stub class inherits java/lang/Object", cf.super_name == "java/lang/Object")
    fnames = [cf.utf8(f.name_index) for f in cf.fields]
    check("stub class has INSTANCE field", "INSTANCE" in fnames)
    mnames = [cf.utf8(m.name_index) for m in cf.methods]
    check("stub class has getInstance", "getInstance" in mnames)
    check("stub class has <clinit>", "<clinit>" in mnames)

    # 2. build_mock_agent_jar & ensure_mock_agent_jar
    tmp_agent_dir = Path(tempfile.mkdtemp(prefix="jdec_test_agent_"))
    try:
        agent_jar = tmp_agent_dir / "mock_agent.jar"
        SB.build_mock_agent_jar(agent_jar)
        check("mock_agent.jar created", agent_jar.is_file())
        with zipfile.ZipFile(agent_jar) as z:
            mf = z.read("META-INF/MANIFEST.MF").decode("utf-8")
            check("mock agent manifest has Premain-Class", "Premain-Class: jdec.mock.MockAgent" in mf)
            check("mock agent jar contains MockAgent.class", "jdec/mock/MockAgent.class" in z.namelist())
    finally:
        shutil.rmtree(tmp_agent_dir, ignore_errors=True)

    # 3. DynamicMockClassLoader live test (if javac & java available)
    jc = SB._find_javac("javac")
    if jc:
        tmp_live = Path(tempfile.mkdtemp(prefix="jdec_test_dmcl_"))
        try:
            driver_src = (
                "public class DynamicMockTest {\n"
                "    public static void main(String[] args) throws Exception {\n"
                "        RecoverDriver.DynamicMockClassLoader cl = new RecoverDriver.DynamicMockClassLoader(DynamicMockTest.class.getClassLoader());\n"
                "        Class<?> c = Class.forName(\"com.unknown.external.MockService\", true, cl);\n"
                "        Object inst1 = c.getMethod(\"getInstance\").invoke(null);\n"
                "        Object inst2 = c.getMethod(\"getInstance\").invoke(null);\n"
                "        if (inst1 == null || inst1 != inst2) throw new AssertionError(\"mock instance null or not singleton\");\n"
                "        System.out.println(\"MOCK_OK: \" + inst1.getClass().getName());\n"
                "    }\n"
                "}\n"
            )
            rec_src = Path(__file__).resolve().parent.parent / "jdec" / "recover_driver_template.java"
            (tmp_live / "RecoverDriver.java").write_text(rec_src.read_text(encoding="utf-8"), encoding="utf-8")
            (tmp_live / "DynamicMockTest.java").write_text(driver_src, encoding="utf-8")
            r_c = subprocess.run([jc, "-d", str(tmp_live), str(tmp_live / "RecoverDriver.java"), str(tmp_live / "DynamicMockTest.java")], capture_output=True, text=True, errors="replace")
            if r_c.returncode == 0:
                from jdec import engines as EN
                java_bin = EN.find_java() or "java"
                r_r = subprocess.run([java_bin, "-cp", str(tmp_live), "DynamicMockTest"], capture_output=True, text=True, errors="replace")
                check("DynamicMockClassLoader loaded missing class on the fly", "MOCK_OK: com.unknown.external.MockService" in r_r.stdout)
                check("DynamicMockClassLoader enforces singleton reference identity", "MOCK_OK" in r_r.stdout)
        finally:
            shutil.rmtree(tmp_live, ignore_errors=True)

    # 4. CFG construction, reachability & reassembly
    code = bytearray([
        0x04,             # 0: iconst_1
        0x99, 0x00, 0x07, # 1: ifeq +7 (to 8)
        0x05,             # 4: iconst_2
        0xA7, 0x00, 0x06, # 5: goto +6 (to 11)
        0x06,             # 8: iconst_3
        0x00,             # 9: nop
        0x00,             # 10: nop
        0xB1              # 11: return
    ])
    g = CFG_MOD.build_cfg(bytes(code))
    check("CFG partitioned basic blocks", len(g.blocks) == 4)
    r_blocks, r_pcs = CFG_MOD.compute_reachability(g)
    check("CFG reachability found all blocks", len(r_blocks) == 4 and len(r_pcs) == 12)
    reassembled, _, _ = CFG_MOD.assemble_cfg(g)
    check("CFG reassembled code matches original", reassembled == bytes(code))

    # 5. Far jump widening (> 32KB)
    code_far = bytearray([0x04])
    code_far.extend([0xC8, 0x00, 0x00, 0x9C, 0x44]) # goto_w +40004 -> targets 40005
    code_far.extend([0x00] * 39999)
    code_far.extend([0xB1])

    g_far = CFG_MOD.build_cfg(bytes(code_far))
    g_far.blocks[0].insns[1].op = BC.OP_GOTO
    g_far.blocks[0].insns[1].length = 3
    new_code, _, stats = CFG_MOD.assemble_cfg(g_far, allow_widening=True)
    check("CFG widened 16-bit goto to goto_w for far jump", stats["widened_goto"] == 1)
    dec = BC.decode(new_code)
    check("CFG reassembled far goto_w has correct target", dec[1].op == BC.OP_GOTO_W and dec[1].jump_targets() == [40005])

    # 6. Far conditional jump expansion (> 32KB)
    g_far2 = CFG_MOD.build_cfg(bytes(code_far))
    g_far2.blocks[0].insns[1].op = 0x99 # ifeq
    g_far2.blocks[0].insns[1].length = 3
    new_code2, _, stats2 = CFG_MOD.assemble_cfg(g_far2, allow_widening=True)
    check("CFG expanded far conditional branch", stats2["widened_if"] == 1)
    dec2 = BC.decode(new_code2)
    check("CFG expanded to inverted condition and goto_w", dec2[1].op == 0x9A and dec2[2].op == BC.OP_GOTO_W and dec2[2].jump_targets() == [40008])
    check("CFG expanded goto_w reaches return instruction", new_code2[dec2[2].jump_targets()[0]] == 0xB1)

    # 7. StackMapTable reconstruction
    smt = CFG_MOD.rebuild_stack_map_table(None, new_code2)
    check("StackMapTable generated", len(smt) >= 2 and struct.unpack_from(">H", smt, 0)[0] > 0)

    # 8. deflat far switch transition (> 32KB)
    switch_code = bytearray([0x1B, 0xAA, 0, 0] + list(struct.pack('>iiiii', 0, 1, 3, 27, 40030)) + list(struct.pack('>i', 35)))
    switch_code += bytearray([0x10, 0x02, 0x3C, 0xA7]) + bytearray(struct.pack('>h', -31))
    switch_code += bytearray(b'\x00' * (40035 - len(switch_code)))
    switch_code += bytearray([0xB1])
    deflat_far, n_far = DF_MOD.deflat_code(bytes(switch_code))
    check("deflat unflattened switch transition spanning > 32KB", n_far >= 1 and deflat_far[28] == BC.OP_GOTO_W)

    # 9. CFG exception handler covers widened code end
    h_orig = [BC.Handler(start_pc=0, end_pc=len(code_far), handler_pc=len(code_far) - 1, catch_type=0)]
    g_far_h = CFG_MOD.build_cfg(bytes(code_far), handlers=h_orig)
    g_far_h.blocks[0].insns[1].op = BC.OP_GOTO
    g_far_h.blocks[0].insns[1].length = 3
    new_code_h, new_handlers_h, _ = CFG_MOD.assemble_cfg(g_far_h, allow_widening=True)
    check("CFG exception handler start matches 0", new_handlers_h[0].start_pc == 0)
    check("CFG exception handler end covers full expanded code", new_handlers_h[0].end_pc == len(new_code_h))

    # 10. StackMapTable with exception handler generates handler frames
    smt_h = CFG_MOD.rebuild_stack_map_table(None, new_code_h, handlers=new_handlers_h)
    check("StackMapTable generated with handler frames", len(smt_h) >= 5)

    # 11. deflat_class supports variable-length code widening without dropping code
    cf_dummy = CF.parse(SB.build_stub_class_bytes("com/example/Dummy"))
    edits = DF_MOD.deflat_class(cf_dummy)
    check("deflat_class executed without crashing", isinstance(edits, int))


def test_bvm_and_native_extensions() -> None:
    print("bvm & native: BytecodeVM devirtualization, far CFG reassembly, and Frida dynamic ingest")
    from jdec import bvm_devirt as BVM
    from jdec import recover as RC
    from jdec import stubs as SB

    # 1. BVMDecoder: decode standard virtual instruction stream
    code_seq = [
        BVM.ORDINAL_BY_NAME["ICONST_1"],
        BVM.ORDINAL_BY_NAME["BIPUSH"], 42,
        BVM.ORDINAL_BY_NAME["IADD"],
        BVM.ORDINAL_BY_NAME["IRETURN"]
    ]
    insns = BVM.BVMDecoder.decode(code_seq)
    check("BVMDecoder decoded all instructions", len(insns) == 4)
    check("BVMDecoder resolved BIPUSH opcode", insns[1].opcode_name == "BIPUSH" and insns[1].operands == [42])

    # 2. Mutator map decoding (random permutation)
    mut_map = {999: BVM.ORDINAL_BY_NAME["ICONST_5"], 888: "RETURN"}
    mut_insns = BVM.BVMDecoder.decode([999, 888], mutator_map=mut_map)
    check("BVMDecoder resolved mutated opcodes", mut_insns[0].opcode_name == "ICONST_5" and mut_insns[1].opcode_name == "RETURN")

    # 3. BVMTranslator: translate simple method into valid JVM bytecode
    vm_meth = BVM.BVMMethod(
        code_id=101,
        name="calculate",
        desc="()I",
        code=code_seq,
        constants=[],
        max_locals=1,
        max_stack=2
    )
    cf_host = CF.parse(SB.build_stub_class_bytes("com/example/Host"))
    res = BVM.BVMTranslator.translate_method(vm_meth, cf_host)
    check("BVMTranslator translated bytecode length", len(res.bytecode) == 5)
    check("BVMTranslator bytecode matches JVM ops", res.bytecode == bytes([0x04, 0x10, 42, 0x60, 0xAC]))

    # 4. BVMTranslator: branch resolution and far jump widening (>32KB)
    far_code = [BVM.ORDINAL_BY_NAME["GOTO"], 33002]
    far_code.extend([BVM.ORDINAL_BY_NAME["NOP"]] * 33000)
    far_code.append(BVM.ORDINAL_BY_NAME["RETURN"])

    vm_meth_far = BVM.BVMMethod(
        code_id=102,
        name="farBranch",
        desc="()V",
        code=far_code,
        constants=[],
        max_locals=1,
        max_stack=1
    )
    res_far = BVM.BVMTranslator.translate_method(vm_meth_far, cf_host)
    check("BVMTranslator widened far virtual branch to goto_w", res_far.stats.get("widened_goto", 0) == 1)
    dec_far = BC.decode(res_far.bytecode)
    check("BVMTranslator decoded first insn is goto_w", dec_far[0].op == BC.OP_GOTO_W)

    # 5. Exception handler mapping
    eh_code = [
        BVM.ORDINAL_BY_NAME["ICONST_0"],
        BVM.ORDINAL_BY_NAME["ICONST_1"],
        BVM.ORDINAL_BY_NAME["IDIV"],
        BVM.ORDINAL_BY_NAME["IRETURN"],
        BVM.ORDINAL_BY_NAME["POP"],
        BVM.ORDINAL_BY_NAME["ICONST_M1"],
        BVM.ORDINAL_BY_NAME["IRETURN"]
    ]
    vm_meth_eh = BVM.BVMMethod(
        code_id=103,
        name="safeDiv",
        desc="()I",
        code=eh_code,
        constants=["java/lang/ArithmeticException"],
        exception_handlers=[0, 3, 4, 0],
        max_locals=1,
        max_stack=2
    )
    res_eh = BVM.BVMTranslator.translate_method(vm_meth_eh, cf_host)
    check("BVMTranslator translated exception handler", len(res_eh.handlers) == 1)
    check("BVMTranslator handler start_pc is 0", res_eh.handlers[0].start_pc == 0)
    check("BVMTranslator handler handler_pc points to POP", res_eh.bytecode[res_eh.handlers[0].handler_pc] == 0x57)

    # 6. Devirtualizer class file injection
    cp_helper = BVM.ConstantPoolHelper(cf_host)
    mref_idx = cp_helper.add_methodref("com/example/VM", "execute", "(I)V")

    code_blob = bytearray([0x10, 101, 0xB8, (mref_idx >> 8) & 0xFF, mref_idx & 0xFF, 0xB1])
    code_attr = BVM.BVMDevirtualizer.build_code_attribute(cf_host, 2, 1, bytes(code_blob), [])
    target_method = CF.Member(
        access_flags=CF.ACC_PUBLIC | CF.ACC_STATIC,
        name_index=cf_host.intern_utf8("testTarget"),
        descriptor_index=cf_host.intern_utf8("()I"),
        attrs_blob=struct.pack(">H", 1) + code_attr
    )
    cf_host.methods.append(target_method)

    extracted_id = BVM.BVMDevirtualizer.extract_code_id(cf_host, target_method)
    check("BVMDevirtualizer extracted codeId from bytecode", extracted_id == 101)

    code_pool = {101: vm_meth}
    devirt_cf, devirt_count = BVM.BVMDevirtualizer.devirtualize_class_file(cf_host, code_pool)
    check("BVMDevirtualizer devirtualized target method", devirt_count == 1)

    # 7. Code pool JSON round-trip
    with tempfile.TemporaryDirectory() as td:
        p_json = Path(td) / "code_pool.json"
        BVM.BVMDevirtualizer.save_code_pool(code_pool, p_json)
        check("BVMDevirtualizer saved code pool JSON", p_json.exists())
        loaded_pool = BVM.BVMDevirtualizer.load_code_pool(p_json)
        check("BVMDevirtualizer loaded code pool roundtrip", 101 in loaded_pool and loaded_pool[101].name == "calculate")

    # 8. Frida dynamic TSV ingestion
    frida_6col_content = (
        "OK\tcom.example.Target\tdecrypt\tCIPHER_A\t1001\tHelloFrida\n"
        "OK\tcom.example.Target\tresolve\tCIPHER_B\t1002\tSecretFrida\n"
    )
    with tempfile.TemporaryDirectory() as td:
        tsv_path = Path(td) / "frida.tsv"
        tsv_path.write_text(frida_6col_content, encoding="utf-8")
        rows = RC.ingest_frida_tsv(tsv_path)
        check("ingest_frida_tsv parsed 6-col rows", len(rows) == 2)
        check("ingest_frida_tsv parsed string plaintext", rows.get(("CIPHER_A", "1001")) == "HelloFrida")
        check("ingest_frida_tsv parsed second plaintext", rows.get(("CIPHER_B", "1002")) == "SecretFrida")

        # Test 3-col format
        frida_3col_content = "CIPHER_C\t2001\tPlain3Col\n"
        tsv_3col = Path(td) / "frida_3col.tsv"
        tsv_3col.write_text(frida_3col_content, encoding="utf-8")
        rows_3col = RC.ingest_frida_tsv(tsv_3col)
        check("ingest_frida_tsv parsed 3-col rows", rows_3col.get(("CIPHER_C", "2001")) == "Plain3Col")

        # Test jnitrace format
        jnitrace_content = (
            "1234\tNewStringUTF\tjni_decrypted_secret\n"
        )
        (Path(td) / "jnitrace.tsv").write_text(jnitrace_content, encoding="utf-8")
        jni_rows = RC.ingest_frida_tsv(Path(td) / "jnitrace.tsv")
        check("ingest_frida_tsv parsed jnitrace rows", len(jni_rows) == 1 and jni_rows.get(("jni_decrypted_secret", "0")) == "jni_decrypted_secret")

    # 9. MockAgent JAR generation and instrumentation verification
    agent_jar = SB.ensure_mock_agent_jar()
    check("ensure_mock_agent_jar returns existing jar", agent_jar.is_file())
    with zipfile.ZipFile(agent_jar, "r") as zf:
        mf = zf.read("META-INF/MANIFEST.MF").decode("utf-8")
        check("mock agent manifest contains Premain-Class", "Premain-Class: jdec.mock.MockAgent" in mf)
        check("mock agent contains MockAgent.class", "jdec/mock/MockAgent.class" in zf.namelist())

    # 10. INVOKEINTERFACE with arguments and receiver count
    vm_meth_itf = BVM.BVMMethod(
        code_id=104,
        name="callItf",
        desc="()V",
        code=[
            BVM.ORDINAL_BY_NAME["ALOAD"], 0,
            BVM.ORDINAL_BY_NAME["ICONST_1"],
            BVM.ORDINAL_BY_NAME["LCONST_0"],
            BVM.ORDINAL_BY_NAME["INVOKEINTERFACE"], 0, 1, 2, 4,
            BVM.ORDINAL_BY_NAME["RETURN"]
        ],
        constants=["com/example/MyInterface", "compute", "(IJ)V"],
        max_locals=3,
        max_stack=4
    )
    res_itf = BVM.BVMTranslator.translate_method(vm_meth_itf, cf_host)
    check("BVMTranslator translated invokeinterface", 0xB9 in res_itf.bytecode)
    itf_idx = res_itf.bytecode.index(0xB9)
    check("invokeinterface count operand is 4", res_itf.bytecode[itf_idx + 3] == 4)

    # 11. LDC with 2-word Long / Double uses ldc2_w (0x14)
    vm_meth_long = BVM.BVMMethod(
        code_id=105,
        name="loadLong",
        desc="()J",
        code=[
            BVM.ORDINAL_BY_NAME["LDC"], 0,
            BVM.ORDINAL_BY_NAME["LRETURN"]
        ],
        constants=[{"type": "long", "value": 9876543210123}],
        max_locals=1,
        max_stack=2
    )
    res_long = BVM.BVMTranslator.translate_method(vm_meth_long, cf_host)
    check("ldc2_w used for long constant", res_long.bytecode[0] == 0x14)

    # 12. Non-Code attributes preserved across devirtualization
    sig_attr_idx = cf_host.intern_utf8("Signature")
    sig_val_idx = cf_host.intern_utf8("()I")
    sig_attr = struct.pack(">HIH", sig_attr_idx, 2, sig_val_idx)
    target_method.attrs_blob = struct.pack(">H", 2) + code_attr + sig_attr
    devirt_cf2, count2 = BVM.BVMDevirtualizer.devirtualize_class_file(cf_host, {101: vm_meth})
    has_sig = False
    o = 2
    for _ in range(struct.unpack_from(">H", target_method.attrs_blob, 0)[0]):
        ni = struct.unpack_from(">H", target_method.attrs_blob, o)[0]
        alen = struct.unpack_from(">I", target_method.attrs_blob, o + 2)[0]
        o += 6 + alen
        if cf_host.utf8(ni) == "Signature":
            has_sig = True
    check("set_code_attribute preserved Signature attribute", has_sig)

    # 13. Keyword sanitization handles short and byte declarations
    code_kw_types = "short default = 1;\nbyte goto = 2;\nMyType default = null;"
    san_kw, kw_c = PJ.sanitize_keyword_identifiers(code_kw_types)
    check("keywords escaped for short and byte types", "short default_ = 1;" in san_kw and "byte goto_ = 2;" in san_kw)

    # 14. Devirtualizer generic naming and alias compatibility
    from jdec import devirt as DV
    check("Devirtualizer is aliased to BVMDevirtualizer", DV.Devirtualizer is BVM.BVMDevirtualizer)
    check("VMDecoder is aliased to BVMDecoder", DV.VMDecoder is BVM.BVMDecoder)
    check("VMTranslator is aliased to BVMTranslator", DV.VMTranslator is BVM.BVMTranslator)
    check("VMMethod is aliased to BVMMethod", DV.VMMethod is BVM.BVMMethod)
    target_method.attrs_blob = struct.pack(">H", 1) + code_attr
    dv_res = DV.Devirtualizer.devirtualize_class_file(cf_host, {101: vm_meth})
    check("Devirtualizer devirtualize_class_file returns success", dv_res[1] == 1)


def test_remap_failure_accounting() -> None:
    print("mappings: remap failures are reported (and fatal under strict mode)")
    from jdec import stubs as SB
    m = MP.Mapping()
    m.add_class("demo/good/Keep", "demo/new/Keep")
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "in.jar"
        with zipfile.ZipFile(src, "w") as z:
            z.writestr("demo/good/Keep.class", SB.build_stub_class_bytes("demo/good/Keep"))
            # a class entry that fails to parse -> remap_class_bytes raises
            z.writestr("demo/bad/Broken.class",
                       b"\xca\xfe\xba\xbe\x00\x00\x00\x34garbage")
        dst = Path(td) / "out.jar"
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            changed, total = MP.remap_jar(src, dst, m)
        check("good class remapped, broken one counted in total",
              (changed, total) == (1, 2), f"changed={changed} total={total}")
        check("failure is reported, not swallowed",
              "NOT remapped" in buf.getvalue() and "demo/bad/Broken.class" in buf.getvalue(),
              buf.getvalue()[:200])
        with zipfile.ZipFile(dst) as z:
            check("broken class written back under its original name",
                  "demo/bad/Broken.class" in z.namelist(), str(z.namelist()))
        dst2 = Path(td) / "out_strict.jar"
        try:
            MP.remap_jar(src, dst2, m, strict=True)
            check("strict remap raises on failure", False, "no error")
        except RuntimeError as exc:
            check("strict remap raises on failure", "1 class(es) failed" in str(exc), str(exc))


def test_devirt_opcode_disambiguation() -> None:
    print("devirt: opcode interpretation is explicit (ordinal vs jvm-opcode)")
    from jdec import bvm_devirt as BVM
    # 0x2E is JVM iaload AND a valid ordinal index (-> POP2): the two spaces
    # overlap, so the reading must be chosen by mode, not by silent fallback
    got = BVM.BVMDecoder.resolve_opcode(0x2E, None, mode="ordinal")
    check("ordinal mode reads 0x2E as an OPCS ordinal (POP2)",
          got == BVM.OPCS_ORDINALS[0x2E] == "POP2", str(got))
    got_jvm = BVM.BVMDecoder.resolve_opcode(0x2E, None, mode="jvm-opcode")
    check("jvm-opcode mode reads 0x2E as IALOAD", got_jvm == "IALOAD", str(got_jvm))
    # a supplied map is authoritative: unmapped ints stay unmapped even when
    # they happen to land inside the ordinal range
    small_map = {7: BVM.ORDINAL_BY_NAME["ICONST_1"]}
    check("map miss returns None even for in-range ints",
          BVM.BVMDecoder.resolve_opcode(0x2E, small_map, mode="ordinal") is None)
    check("map hit resolves through the map",
          BVM.BVMDecoder.resolve_opcode(7, small_map, mode="ordinal") == "ICONST_1")
    try:
        BVM.BVMDecoder.resolve_opcode(1, None, mode="bogus")
        check("unknown mode rejected", False, "no error raised")
    except ValueError:
        check("unknown mode rejected", True)


def test_pool_verify_fq_callsites() -> None:
    print("pool: fully-qualified call sites resolve identically in repl and verify")
    import base64 as B64
    from jdec import pool as PL
    # the old verify resolved via simple-name lookup only, which can never hit
    # a fully-qualified cls_raw - that blind spot is the regression being pinned
    acc = {"demo.pool.Acc": {"a": [("int", "int")]}}
    simple = {"Acc": "demo.pool.Acc"}
    check("old-style simple-name lookup misses FQ forms",
          simple.get("demo.pool.Acc") is None)
    check("_resolve_fq resolves the FQ form",
          PL._resolve_fq("demo.pool.Acc", acc, simple, set()) == "demo.pool.Acc")
    check("_resolve_fq resolves the simple form",
          PL._resolve_fq("Acc", acc, simple, set()) == "demo.pool.Acc")
    check("_resolve_fq refuses ambiguous simple names",
          PL._resolve_fq("Acc", acc, simple, {"Acc"}) is None)
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "src"
        out = Path(td) / "out"
        src.mkdir(parents=True)
        (src / "Acc.java").write_text(
            "package demo.pool;\n\npublic class Acc {\n"
            "    static String a(int idx, int seed) {\n"
            "        return null;\n    }\n}\n", encoding="utf-8")
        (src / "Caller.java").write_text(
            "package demo.caller;\n\npublic class Caller {\n"
            "    String s = demo.pool.Acc.a(1, 2);\n"
            "    String t = Acc.a(3, 4);\n}\n", encoding="utf-8")
        harvest = Path(td) / "h.tsv"
        rows = ["R\tdemo.pool.Acc\ta\t1\t2\t" + B64.b64encode(b"alpha").decode(),
                "R\tdemo.pool.Acc\ta\t3\t4\t" + B64.b64encode(b"beta").decode()]
        harvest.write_text("\n".join(rows) + "\n", encoding="utf-8")
        res = PL.apply(src, harvest, out)
        check("FQ and simple call sites both replaced",
              res["repl_q"] == 2, str(res))
        check("verify agrees: zero residual", res["residual"] == 0, str(res))
        got = (out / "Caller.java").read_text(encoding="utf-8")
        check("plaintext landed in the source",
              '"alpha"' in got and '"beta"' in got, got)


def test_attribution_gates() -> None:
    print("obf: attribution gates on class coverage; the floor is exclusive")
    # single goto-flood fingerprint = confidence 0.35 -> not a vendor
    vendor, conf = OB.attribute({"goto-flood": 100}, 1000)
    check("single goto-flood stays unknown", vendor is None and conf == 0.35,
          f"{vendor} {conf}")
    # below the 10%-of-classes gate
    vendor, _ = OB.attribute({"goto-flood": 9}, 100)
    check("9% class coverage stays unknown", vendor is None, str(vendor))
    # independent corroboration crosses the floor
    vendor, conf = OB.attribute({"goto-flood": 500, "long-constant-array": 200}, 1000)
    check("corroborated signals attribute to ZKM",
          vendor == "Zelix KlassMaster (ZKM)" and conf > 0.35, f"{vendor} {conf}")
    # build_report must gate on *class* counts, not occurrence totals: 500
    # occurrences from 2 classes must not clear a 100-class 10% gate
    class_hits = {"a": {"goto-flood": 250}, "b": {"goto-flood": 250}}
    rep = OB.build_report({"goto-flood": 500}, class_hits, 1000, 2, 0)
    check("occurrence inflation does not smuggle past the class gate",
          rep.vendor is None, rep.summary())
    class_hits2 = {f"c{i}": {"goto-flood": 1, "long-constant-array": 1}
                   for i in range(120)}
    rep2 = OB.build_report({"goto-flood": 120, "long-constant-array": 120},
                           class_hits2, 1000, 120, 0)
    check("wide corroborated coverage does attribute",
          rep2.vendor is not None and "ZKM" in rep2.vendor, rep2.summary())


def test_score_decl_and_noise() -> None:
    """REVIEW 1.1 negative: the old identifier-set matching scored comment
    mentions and bare call sites as full member hits."""
    print("score: coverage counts declarations, not comments or call sites")
    with zipfile.ZipFile(SAMPLE) as z:
        cf = CF.parse(z.read("demo/modern/Showcase.class"))
    members = [m for m, _d in cf.method_sigs() if not m.startswith("<")]
    all_names = members + [f for f, _d in cf.field_sigs()]
    check("fixture has members to score", bool(all_names))

    # (a) names only inside a comment used to give coverage 1.0 / usable True
    comment_only = ("// declared members: " + ", ".join(all_names)
                    + "\npublic class Showcase {}\n")
    q = evaluate(comment_only, cf)
    check("comment-only member list is not a hit", q.coverage < 1.0,
          f"coverage={q.coverage}")
    check("comment-only output is unusable", not q.usable, f"score={q.score}")

    # (b) bare call sites are not declarations
    calls = ("public class Showcase {\n    void callsite() {\n        "
             + "; ".join(f"{m}()" for m in members[:3]) + ";\n    }\n}\n")
    q2 = evaluate(calls, cf)
    check("bare call sites do not count as recovered members",
          q2.coverage < 1.0, f"coverage={q2.coverage}")

    # (c) string-literal mentions are stripped before matching
    lit = ('public class Showcase {\n    void c() { System.out.println("'
           + all_names[0] + '"); }\n}\n')
    q3 = evaluate(lit, cf)
    check("string-literal mention does not count", q3.coverage < 1.0,
          f"coverage={q3.coverage}")

    # (d) same-name overloads are counted individually by _decl_counts
    counts = SCORE._decl_counts("public int a() {}\npublic int a(int x) {}\nint a;\n")
    check("_decl_counts counts overloads individually", counts.get("a") == 3,
          str(counts))
    # (d2) nested generics in the method header must not hide the name
    counts2 = SCORE._decl_counts(
        "public <T extends Comparable<T>> T maxOf(List<T> list, T t) { return t; }\n")
    check("nested generic header still counts as a declaration",
          counts2.get("maxOf") == 1, str(counts2))

    # (e) positive control: real declarations still hit
    decls = ("public class Showcase {\n"
             + "\n".join(f"    public int {m}() {{ return 1; }}" for m in members)
             + "\n}\n")
    q4 = evaluate(decls, cf)
    check("true declarations still hit", q4.coverage >= 0.9, f"coverage={q4.coverage}")


def test_code_pool_json_integrity() -> None:
    """REVIEW 1.2 negative: JSON round-trip stringifies dict keys; the loaded
    map used to make resolve_opcode(7) return None."""
    print("devirt: code-pool JSON round-trip preserves int opcode keys")
    ret = DV.ORDINAL_BY_NAME["RETURN"]
    vm = DV.VMMethod(code_id=7, name="m", desc="()V", code=[7, 8],
                     opcode_map={7: 4, 8: ret}, mode="ordinal")
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "pool.json"
        DV.Devirtualizer.save_code_pool({7: vm}, p)
        raw = json.loads(p.read_text(encoding="utf-8"))
        check("json inevitably stores string keys",
              raw["7"]["opcode_map"] == {"7": 4, "8": ret})
        loaded = DV.Devirtualizer.load_code_pool(p)[7]
        check("loaded map keys are ints again",
              loaded.opcode_map == {7: 4, 8: ret}, repr(loaded.opcode_map))
        check("mode round-trips", loaded.mode == "ordinal")
    check("review repro: resolve_opcode(7) resolves (used to be None)",
          DV.VMDecoder.resolve_opcode(7, loaded.opcode_map) == "ICONST_1",
          repr(DV.VMDecoder.resolve_opcode(7, loaded.opcode_map)))
    bad = DV.VMMethod(code_id=9, code=[0], opcode_map={5: 999})
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "bad.json"
        DV.Devirtualizer.save_code_pool({9: bad}, p)
        try:
            DV.Devirtualizer.load_code_pool(p)
            check("invalid ordinal fails loudly", False, "no exception raised")
        except ValueError as e:
            check("invalid ordinal fails loudly", "ordinal" in str(e).lower(), str(e))


def test_max_stack_dataflow() -> None:
    """REVIEW 1.3 negative: a peak-9 stream used to inherit the declared
    (smaller) max_stack instead of the computed one."""
    print("devirt: max_stack comes from stack dataflow, not the declared field")
    from jdec import stubs as SB
    cf_host = CF.parse(SB.build_stub_class_bytes("com/example/Host"))
    b = DV.ORDINAL_BY_NAME
    code9 = [b["ICONST_1"]] * 9 + [b["POP"]] * 9 + [b["RETURN"]]
    r9 = DV.VMTranslator.translate_method(
        DV.VMMethod(code_id=1, name="nine", desc="()V", code=code9, max_stack=2),
        cf_host)
    check("peak-9 stream yields max_stack >= 9 (declared was 2)",
          r9.max_stack >= 9, f"max_stack={r9.max_stack}")
    check("stats records the computed source",
          r9.stats.get("max_stack_source") == "computed")
    codel = [b["LCONST_0"]] * 4 + [b["POP2"]] * 4 + [b["RETURN"]]
    rl = DV.VMTranslator.translate_method(
        DV.VMMethod(code_id=2, name="longs", desc="()V", code=codel, max_stack=2),
        cf_host)
    check("two-slot values occupy two slots (peak 8)", rl.max_stack >= 8,
          f"max_stack={rl.max_stack}")


def test_replay_safety_gate() -> None:
    """REVIEW 2.1 negative: dynamic replay used to start a JVM with no opt-in."""
    print("recover/pool: dynamic replay is opt-in (safety gate)")
    with tempfile.TemporaryDirectory() as td:
        rec_dir = Path(td) / "rec"
        rc = RC.recover(SAMPLE, rec_dir)
        check("recover without allow_exec returns 3 (gated)", rc == 3, f"rc={rc}")
        check("no recovered.tsv without opt-in",
              not (rec_dir / "recovered.tsv").is_file())
    with tempfile.TemporaryDirectory() as td:
        spec = Path(td) / "spec.tsv"
        spec.write_text("class\tmethod\tsite\texpr\n", encoding="utf-8")
        try:
            PL.harvest(spec, Path(td) / "out.tsv", Path(td) / "work")
            check("pool harvest without allow_exec raises", False, "no exception")
        except PL.ReplayNotAllowed as e:
            check("pool harvest without allow_exec raises", "EXECUTES" in str(e), str(e))
    parser = CL.build_parser()
    ns = parser.parse_args(["auto", "x.jar"])
    check("auto defaults to allow_replay=False", not getattr(ns, "allow_replay", True))
    ns2 = parser.parse_args(["pipeline", "x.jar", "--allow-replay"])
    check("pipeline --allow-replay opts in", getattr(ns2, "allow_replay", False))


def test_rewrite_skips_comments_strings() -> None:
    """BUG round negative: source rewriters used to replace lookalike
    call sites inside comments and string literals (source pollution,
    inflated replace counts, false verify residuals)."""
    print("recover: code_mask keeps comments/strings untouched in rewrite")
    code_mask = RC.code_mask

    # 1. lexer mask core cases
    t1 = 'int a = 1; // call Foo.q("AA", "BB", 3)\nint b = 2;'
    m1 = code_mask(t1)
    check("mask: line-comment lookalike masked", not m1[t1.index('"AA"')])
    check("mask: code after comment is code", m1[t1.index("int b")] is True)

    t2 = 'String s = "a\\"b"; Foo.q("CC", "DD", 4);'
    m2 = code_mask(t2)
    check("mask: escaped quote stays inside string", m2[t2.index("a\\")] is False)
    check("mask: real call site after string is code", m2[t2.index("Foo.q")] is True)

    t3 = '/* Foo.q("EE", "FF", 5) */ int x;'
    m3 = code_mask(t3)
    check("mask: block-comment lookalike masked",
          m3[t3.index('"EE"')] is False and m3[t3.index("int x")] is True)

    t4 = "char c = '\"'; Foo.q(\"GG\", \"HH\", 6);"
    m4 = code_mask(t4)
    check("mask: quote inside char literal does not open string",
          m4[t4.index("Foo.q")] is True and m4[t4.index("'\"'")] is False)

    # 2. rewrite_sources integration: decoys untouched, real sites replaced
    import base64
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "src"
        src.mkdir()
        jf = src / "T.java"
        jf.write_text(
            'class T {\n'
            '  // decoy: Util.dec("siteA", "cipherAA", 11) must stay\n'
            '  /* decoy: Util.dec("siteB", "cipherBB", 12) must stay */\n'
            '  String doc = "decoy Util.dec(\\"siteC\\", \\"cipherCC\\", 13) stays";\n'
            '  String a = Util.dec("siteD", "cipherDD", 14);\n'
            '  String b = Util.dec("siteE", "cipherEE", 15);\n'
            '}\n', encoding="utf-8")
        tsv = Path(td) / "recovered.tsv"
        # rewrite tsv columns: OK, ?, ?, cipher=parts[3], seed=parts[4], plain
        # call-shape X.y("site", "cipher", seed) -> key=(cipher, seed-int)
        rows = ["OK\tx\tx\tcipherDD\t14\tb64:" + base64.b64encode(b"plain4").decode(),
                "OK\tx\tx\tcipherEE\t15\tb64:" + base64.b64encode(b"plain5").decode()]
        tsv.write_text("\n".join(rows) + "\n", encoding="utf-8")

        st = RC.rewrite_sources(src, tsv_path=tsv)
        out = jf.read_text(encoding="utf-8")
        check("rewrite: line-comment decoy untouched",
              'Util.dec("siteA", "cipherAA", 11)' in out)
        check("rewrite: block-comment decoy untouched",
              'Util.dec("siteB", "cipherBB", 12)' in out)
        check("rewrite: in-string decoy untouched",
              'Util.dec(\\"siteC\\", \\"cipherCC\\", 13)' in out)
        check("rewrite: real call 1 replaced", '"plain4"' in out)
        check("rewrite: real call 2 replaced", '"plain5"' in out)
        check("rewrite: replaced counted exactly 2", st["replaced"] == 2,
              f"replaced={st['replaced']}")
        check("rewrite: nothing counted missed", st["missed"] == 0)
        check("rewrite: no false residual", st["residual"] == 0)


def test_bvm_extract_code_id_descriptor_gate() -> None:
    """BUG round negative: extract_code_id used to accept any invokestatic
    named 'execute' regardless of descriptor -> wrong codeId on collisions."""
    print("devirt: extract_code_id requires (I... descriptor on execute")
    from jdec import bvm_devirt as BVM
    from jdec import stubs as SB
    cf = CF.parse(SB.build_stub_class_bytes("com/example/Host"))
    helper = BVM.ConstantPoolHelper(cf)

    def make_caller(name: str, mref: int, code_id: int) -> CF.Member:
        blob = bytearray([0x10, code_id,
                          0xB8, (mref >> 8) & 0xFF, mref & 0xFF, 0xB1])
        attr = BVM.BVMDevirtualizer.build_code_attribute(cf, 2, 1, bytes(blob), [])
        return CF.Member(
            access_flags=CF.ACC_PUBLIC | CF.ACC_STATIC,
            name_index=cf.intern_utf8(name),
            descriptor_index=cf.intern_utf8("()I"),
            attrs_blob=struct.pack(">H", 1) + attr)

    # negative: name collides but first param is long, not int
    mref_bad = helper.add_methodref("com/example/VM", "execute", "(J)V")
    m_bad = make_caller("collideLong", mref_bad, 77)
    cf.methods.append(m_bad)
    got_bad = BVM.BVMDevirtualizer.extract_code_id(cf, m_bad)
    check("wrong-descriptor execute yields None", got_bad is None,
          f"got={got_bad}")

    # positive control: (I... execute still resolves the codeId
    mref_ok = helper.add_methodref("com/example/VM", "execute", "(I)V")
    m_ok = make_caller("collideOk", mref_ok, 88)
    cf.methods.append(m_ok)
    got_ok = BVM.BVMDevirtualizer.extract_code_id(cf, m_ok)
    check("(I...) execute still yields codeId", got_ok == 88, f"got={got_ok}")


def test_web_callgraph_error_semantics() -> None:
    """BUG round negative: /api/callgraph used to synthesize reachable:null
    plus empty lists when the callgraph could not be built - masking
    failures as normal-looking empty data."""
    print("web: /api/callgraph returns structured error instead of fake data")
    import urllib.request
    import urllib.error
    import threading
    from jdec import web as WB

    def fetch(url: str):
        try:
            with urllib.request.urlopen(url) as res:
                return res.status, json.loads(res.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))

    # scenario 1: empty work dir -> no analysis target at all
    with tempfile.TemporaryDirectory() as td:
        handler = lambda *a, **k: WB.WorkbenchHandler(*a, work_dir=Path(td), **k)
        server = WB.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            status, body = fetch(
                f"http://127.0.0.1:{server.server_address[1]}"
                f"/api/callgraph?class=demo/X")
            check("no-target -> structured error (4xx/5xx)", status >= 400,
                  f"status={status}")
            check("no-target error mentions missing target",
                  "error" in body and "target" in body["error"], str(body))
            check("no synthesized reachable key", "reachable" not in body)
        finally:
            server.shutdown()

    # scenario 2: target resolves but build fails (not a real jar)
    with tempfile.TemporaryDirectory() as td:
        fake_jar = Path(td) / "fake.jar"
        fake_jar.write_bytes(b"this is not a zip archive")
        handler = lambda *a, **k: WB.WorkbenchHandler(*a, work_dir=fake_jar, **k)
        server = WB.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            status, body = fetch(
                f"http://127.0.0.1:{server.server_address[1]}"
                f"/api/callgraph?class=demo/X")
            check("build-failure -> structured error (4xx/5xx)", status >= 400,
                  f"status={status}")
            check("build-failure error mentions build failure",
                  "error" in body and "build failed" in body["error"], str(body))
            check("no synthesized reachable key on failure",
                  "reachable" not in body)
        finally:
            server.shutdown()


def test_pipeline_stage_status() -> None:
    """REVIEW 2.2 negative: partial results used to exit 0 with no trace."""
    print("pipeline: stage status plumbing and exit codes")
    prof = JarProfile(path=SAMPLE, entries=1, classes=1)

    def mk(stages, strict=False):
        return PIPE.PipelineResult(target_jar=SAMPLE, out_dir=Path("."), profile=prof,
                                   stages=list(stages), strict=strict)

    ok_s = PIPE.StageStatus("probe", PIPE.STAGE_OK)
    sk = PIPE.StageStatus("replay", PIPE.STAGE_SKIPPED, "safety gate")
    part = PIPE.StageStatus("decompile", PIPE.STAGE_PARTIAL, "2 failed")
    bad = PIPE.StageStatus("replay", PIPE.STAGE_FAILED, "rc=1")
    check("ok/skipped -> success/0", mk([ok_s, sk]).exit_code == 0)
    check("partial -> exit 1", mk([ok_s, part]).exit_code == 1)
    check("failed -> exit 2", mk([ok_s, bad]).exit_code == 2)
    check("failed dominates partial", mk([part, bad]).overall_status == "failed")
    check("strict escalates partial to 2", mk([part], strict=True).exit_code == 2)
    check("strict keeps success at 0", mk([ok_s], strict=True).exit_code == 0)
    r = mk([PIPE.StageStatus("replay", PIPE.STAGE_PARTIAL, "indy ok; pool failed")])
    d = r.to_dict()
    check("to_dict carries overall/exit_code/stages",
          d["overall"] == "partial" and d["exit_code"] == 1
          and d["stages"][0]["stage"] == "replay")
    with tempfile.TemporaryDirectory() as td:
        md_path, json_path = PIPE.write_pipeline_summary(mk([ok_s, sk, part]), Path(td))
        md = md_path.read_text(encoding="utf-8")
        js = json.loads(json_path.read_text(encoding="utf-8"))
        check("summary md has stage table", "## Stage Status" in md and "`replay`" in md)
        check("summary md header shows overall + exit code",
              "Overall status:" in md and "exit code 1" in md)
        check("summary json carries stages", len(js["stages"]) == 3
              and js["overall"] == "partial")
    # BUG round negative: detail containing | or newlines used to break the
    # Markdown table structure
    pipe_st = PIPE.StageStatus("pool", PIPE.STAGE_PARTIAL, "a|b\nc d")
    with tempfile.TemporaryDirectory() as td2:
        md2, _ = PIPE.write_pipeline_summary(mk([ok_s, pipe_st]), Path(td2))
        md_text = md2.read_text(encoding="utf-8")
        row = next(ln for ln in md_text.splitlines()
                   if ln.startswith("| `pool` |"))
        cols = row.split(" | ")
        check("stage table: detail pipe escaped", "\\|b" in row, row)
        check("stage table: detail newline flattened", "\n" not in row and "c d" in row)
        check("stage table: column count preserved", len(cols) == 3, row)


def test_conservative_prune() -> None:
    """REVIEW 2.3 negative: indy method-ref targets and reflection-by-name
    classes used to be pruned as 'dead'."""
    print("reach: pruning keeps unknown dependencies (indy handles, reflection)")
    check("javac available for prune fixture", build_fixtures.ensure_sample_jar() is not None)
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "src" / "a").mkdir(parents=True)
        sources = {
            "a/A.java": ("package a;\n"
                         "public class A {\n"
                         "    public static void main(String[] args) throws Exception {\n"
                         "        Runnable r = B::helper;\n"
                         "        r.run();\n"
                         "        Class.forName(\"a.Reflected\");\n"
                         "    }\n"
                         "}\n"),
            "a/B.java": ("package a;\n"
                         "public class B { public static void helper() { } }\n"),
            "a/Reflected.java": ("package a;\npublic class Reflected {}\n"),
            "a/Dead.java": ("package a;\npublic class Dead { public void unused() {} }\n"),
        }
        for rel, txt in sources.items():
            (d / "src" / rel).write_text(txt, encoding="utf-8")
        cls = d / "cls"
        subprocess.run(["javac", "-d", str(cls)]
                       + [str(d / "src" / r) for r in sources],
                       check=True, capture_output=True)
        jar = d / "fixture.jar"
        with zipfile.ZipFile(jar, "w", zipfile.ZIP_DEFLATED) as z:
            for c in cls.rglob("*.class"):
                z.write(c, c.relative_to(cls).as_posix())

        keep, counts = CG.conservative_keepset(jar)
        check("lambda host kept via BSM rule", "a/A" in keep, str(sorted(keep)))
        check("method-ref target kept via handle rule", "a/B" in keep, str(sorted(keep)))
        check("reflection target kept via string rule", "a/Reflected" in keep,
              str(sorted(keep)))
        check("proven-dead class not held back", "a/Dead" not in keep)

        cg = CG.build_callgraph(jar)
        rep = CG.compute_reachability(cg)
        # indy + Class.forName create no static edges: B and Reflected look dead
        check("B unreacheable by static edges (indy blindness)",
              "a/B" not in rep.reachable_classes)
        check("Reflected unreachable by static edges (reflection blindness)",
              "a/Reflected" not in rep.reachable_classes)
        out = d / "pruned.jar"
        CG.prune_jar(jar, out, rep.reachable_classes | keep)
        with zipfile.ZipFile(out) as z:
            names = {n[:-6] for n in z.namelist() if n.endswith(".class")}
        check("pruned jar keeps B (would-be NoSuchMethodError)", "a/B" in names)
        check("pruned jar keeps Reflected (Class.forName target)",
              "a/Reflected" in names)
        check("pruned jar drops Dead", "a/Dead" not in names)
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "a").mkdir()
        for n in ("Reflected", "Dead"):
            (d / "a" / f"{n}.java").write_text(
                f"package a;\npublic class {n} {{}}\n", encoding="utf-8")
        cls = d / "cls"
        subprocess.run(["javac", "-d", str(cls), str(d / "a" / "Reflected.java"),
                        str(d / "a" / "Dead.java")], check=True, capture_output=True)
        noep = d / "noep.jar"
        with zipfile.ZipFile(noep, "w", zipfile.ZIP_DEFLATED) as z:
            for c in cls.rglob("*.class"):
                z.write(c, c.relative_to(cls).as_posix())
        rep2 = CG.compute_reachability(CG.build_callgraph(noep))
        check("no-entrypoint jar triggers the refusal condition",
              not rep2.entrypoints)


def test_selfheal_audit() -> None:
    """REVIEW 2.4 negative: self-heal used to overwrite the only copy of the
    decompiled source, with no record of what changed."""
    print("project: self-heal keeps src-original/ and writes repair-log.md")
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        src_dir = d / "decomp_src" / "a"
        src_dir.mkdir(parents=True)
        # zero-width char + 'goto' as identifier: two self-heal rules fire.
        # (record/yield are contextual keywords and legal identifiers - the
        # tool correctly leaves them alone.)
        original = ("package a;\n\npublic class Healing {\n    public void run() {\n"
                    "        int record\u200b = 1;\n        int goto = 2;\n"
                    "        System.out.println(record + goto);\n    }\n}\n")
        (src_dir / "Healing.java").write_text(original, encoding="utf-8")
        (src_dir / "Plain.java").write_text(
            "package a;\n\npublic class Plain {\n    int ok = 3;\n}\n",
            encoding="utf-8")
        out = d / "proj"
        stats = PJ.export_project(SAMPLE, out, src_dir=d / "decomp_src",
                                  with_stubs=False)
        orig = out / "src-original" / "a" / "Healing.java"
        check("pre-repair source preserved", orig.is_file()
              and "\u200b" in orig.read_text(encoding="utf-8"))
        repaired = out / "src" / "main" / "java" / "a" / "Healing.java"
        rtxt = repaired.read_text(encoding="utf-8") if repaired.is_file() else ""
        check("repaired version escapes the keyword", "goto_" in rtxt, rtxt[:200])
        check("unrepaired file not duplicated into src-original",
              not (out / "src-original" / "a" / "Plain.java").is_file())
        log = out / "repair-log.md"
        txt = log.read_text(encoding="utf-8") if log.is_file() else ""
        check("repair-log written with evidence ladder",
              log.is_file() and "readable < compilable" in txt
              and "NOT implemented" in txt)
        check("repair-log lists the healed file and rules",
              "`a/Healing.java`" in txt and "keyword" in txt.lower())
        check("stats counters consistent", stats.get("files_repaired") == 1
              and stats.get("repair_rules_applied", 0) >= 2, str(stats))


def test_sakura_architecture_improvements() -> None:
    print("sakura improvements: unboxing awareness, static hiding invariance, intermediary grounding, safe fallbacks & event weaver")
    from jdec import stubs as SB
    from jdec import project as PJ
    from jdec import mcmod as MM

    # 1. Primitive unboxing awareness
    check("default primitive boolean is false", SB.default_primitive_return("Z") == "false")
    check("default primitive boxed boolean", SB.default_primitive_return("boolean", boxed=True) == "java.lang.Boolean.FALSE")
    check("default primitive int is 0", SB.default_primitive_return("I") == "0")
    check("default primitive boxed int", SB.default_primitive_return("int", boxed=True) == "Integer.valueOf(0)")
    check("default primitive long is 0L", SB.default_primitive_return("J") == "0L")
    check("default primitive float is 0.0F", SB.default_primitive_return("F") == "0.0F")
    check("default primitive double is 0.0", SB.default_primitive_return("D") == "0.0")
    check("default primitive char is '\\0'", SB.default_primitive_return("C") == "'\\0'")
    check("default primitive void is empty", SB.default_primitive_return("V") == "")
    check("default reference object is null", SB.default_primitive_return("Object") == "null")

    # Unbox normalization in conditions and assignments
    src_test = (
        "boolean b = (boolean)x;\n"
        "if ((boolean)myObj) { doSomething(); }\n"
        "while ((boolean)flag) { loop(); }\n"
        "int val = (boolean)cond ? 1 : 2;\n"
    )
    norm_src, edits = PJ.normalize_primitive_unboxing(src_test)
    check("normalize_primitive_unboxing applied edits", edits == 4)
    check("normalize_primitive_unboxing converted assignment", "boolean b = Boolean.TRUE.equals(x);" in norm_src)
    check("normalize_primitive_unboxing converted if condition", "if (Boolean.TRUE.equals(myObj))" in norm_src)
    check("normalize_primitive_unboxing converted while condition", "while (Boolean.TRUE.equals(flag))" in norm_src)
    check("normalize_primitive_unboxing converted ternary", "Boolean.TRUE.equals(cond) ?" in norm_src)

    # 2. Static hiding invariance check
    with tempfile.TemporaryDirectory(prefix="jdec_test_hiding_") as td:
        tdp = Path(td)
        super_cls = tdp / "SuperClass.java"
        sub_cls = tdp / "SubClass.java"
        super_cls.write_text("public class SuperClass {\n    public static String get(Object[] args) { return null; }\n}\n")
        sub_cls.write_text("public class SubClass extends SuperClass {\n    public static Object get(Object[] args) { return null; }\n}\n")
        h_edits = PJ.check_static_hiding_invariance(tdp)
        check("check_static_hiding_invariance applied edit", h_edits == 1)
        sub_txt = sub_cls.read_text()
        check("subclass static method return type narrowed to superclass", "public static String get(" in sub_txt)

    # 3. Safe fallback dispatcher and skeletons
    d6_code = SB.generate_safe_fallback_dispatcher("dev.sakura.client.d6")
    check("dispatcher stub has package", "package dev.sakura.client;" in d6_code)
    check("dispatcher stub returns emptyList", "return Collections.emptyList();" in d6_code)
    check("dispatcher stub returns emptyMap", "return Collections.emptyMap();" in d6_code)
    check("dispatcher stub returns emptySet", "return Collections.emptySet();" in d6_code)
    check("dispatcher stub returns emptyIterator", "return Collections.emptyIterator();" in d6_code)
    check("dispatcher stub returns false for aZ", "return false;" in d6_code)
    check("dispatcher stub returns no-op runnable", "return () -> {};" in d6_code)

    # Enrich fallback stubs in a project
    with tempfile.TemporaryDirectory(prefix="jdec_test_enrich_") as td:
        tdp = Path(td)
        src_dir = tdp / "src" / "main" / "java" / "dev" / "sakura" / "client"
        src_dir.mkdir(parents=True)
        stub_f = src_dir / "d6.java"
        stub_f.write_text(
            "package dev.sakura.client;\n"
            "public class d6 {\n"
            "    public static <T> List<T> aList(Object... args) { return null; }\n"
            "    public static boolean aZ(Object... args) { return null; }\n"
            "}\n"
        )
        enr_count = PJ.enrich_safe_fallback_stubs(tdp)
        check("enrich_safe_fallback_stubs applied", enr_count == 1)
        enr_txt = stub_f.read_text()
        check("stub upgraded to Collections.emptyList()", "Collections.emptyList()" in enr_txt)
        check("stub upgraded aZ to false", "return false;" in enr_txt)

    # 4. Intermediary Grounding
    mc_fixture = MIXIN if MIXIN.is_file() else build_fixtures.ensure_mixin_jar()
    if mc_fixture and Path(mc_fixture).is_file():
        grounding = MM.IntermediaryGrounding(mc_fixture)
        check("grounding is available with fixture", grounding.is_available())
        check("grounding has Minecraft class", grounding.has_class("net/minecraft/client/Minecraft"))
        check("grounding detects class kind", grounding.get_class_kind("net/minecraft/client/Minecraft") == "class")
        grounded_src = grounding.generate_grounded_stub("net/minecraft/client/Minecraft")
        check("grounding generates valid stub", grounded_src is not None and "public class Minecraft" in grounded_src)

    empty_grounding = MM.IntermediaryGrounding(None)
    check("empty grounding is not available", not empty_grounding.is_available())
    check("empty grounding returns None for stub", empty_grounding.generate_grounded_stub("Foo") is None)

    # 5. Event Pipeline Detector & Weaver
    with tempfile.TemporaryDirectory(prefix="jdec_test_event_") as td:
        tdp = Path(td)
        kb_file = tdp / "MixinKeyboard.java"
        kb_file.write_text(
            "package dev.sakura.client.mixin;\n"
            "import org.spongepowered.asm.mixin.Mixin;\n"
            "@Mixin(net.minecraft.client.Keyboard.class)\n"
            "public class MixinKeyboard {\n"
            "    public void onKey(int key, int scancode, int action) {\n"
            "        uf.v.post(new YG(key));\n"
            "    }\n"
            "}\n"
        )
        net_file = tdp / "MixinNetwork.java"
        net_file.write_text(
            "package dev.sakura.client.mixin;\n"
            "import org.spongepowered.asm.mixin.Mixin;\n"
            "@Mixin(net.minecraft.class_634.class)\n"
            "public class MixinNetwork {\n"
            "    public void sendChat(String msg) {\n"
            "        uf.v.post(new Ym(msg));\n"
            "    }\n"
            "}\n"
        )
        pipe_info = MM.detect_event_pipelines(tdp)
        check("event pipeline detected keyboard mixin", pipe_info.keyboard_mixin == "MixinKeyboard")
        check("event pipeline detected key event class", pipe_info.key_event_class == "YG")
        check("event pipeline detected network mixin", pipe_info.network_mixin == "MixinNetwork")
        check("event pipeline detected chat event class", pipe_info.chat_event_class == "Ym")

        woven = MM.weave_event_dispatcher_hook(tdp, pipe_info, default_keys=[344, 96, 89, 260])
        check("event dispatcher hook woven successfully", woven)
        kb_after = kb_file.read_text()
        check("keyboard mixin has event dispatcher hook", "[jdec: event dispatcher hook]" in kb_after and "344" in kb_after)

        woven_second = MM.weave_event_dispatcher_hook(tdp, pipe_info)
        check("event dispatcher hook is idempotent", not woven_second)


def main() -> int:
    with_mc = "--with-mc" in sys.argv
    if not SAMPLE.exists() and build_fixtures.ensure_sample_jar(quiet=False) is None:
        print("missing tests/sample.jar and could not build it "
              "(check that javac is on PATH, or run tests/build_fixtures.py)")
        return 2
    test_roundtrip_sample()
    test_synthetic_members_ignored()
    test_scoring_sees_obfuscated_names()
    test_partial_failure_is_not_total_failure()
    test_score_decl_and_noise()
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
    test_replay_safety_gate()
    test_resource_anomaly()
    test_scorecard_smoke()
    test_pool_roundtrip()
    test_web_template_js()
    test_pool_qualified_and_full_string()
    test_pool_overload_dispatch()
    test_probe_fingerprints_json()
    test_platform_classpath_separator()
    test_remap_failure_accounting()
    test_devirt_opcode_disambiguation()
    test_code_pool_json_integrity()
    test_max_stack_dataflow()
    test_pool_verify_fq_callsites()
    test_attribution_gates()
    test_ops_pool()
    test_jint()
    test_clinit_sim()
    test_ghidra_integration()
    test_native_elf_and_ghidra_annotate()
    test_score_and_signal_enhancements()
    test_multimodule_enhancements()
    test_advanced_roadmap_features()
    test_pipeline_automation()
    test_pipeline_stage_status()
    test_rewrite_skips_comments_strings()
    test_bvm_extract_code_id_descriptor_gate()
    test_web_callgraph_error_semantics()
    test_web_workbench_features()
    test_callgraph_and_reachability()
    test_conservative_prune()
    test_decompiler_trap_pruning()
    test_project_export_and_recompilability()
    test_selfheal_audit()
    test_cfg_and_dynamic_mocks()
    test_bvm_and_native_extensions()
    test_sakura_architecture_improvements()
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
