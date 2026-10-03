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
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import struct                         # noqa: E402

import build_fixtures                 # noqa: E402
from build_fixtures import ensure_collide_jar  # noqa: E402
from jdec import analyze as AZ        # noqa: E402
from jdec import annotations as AN    # noqa: E402
from jdec import bytecode as BC       # noqa: E402
from jdec import classfile as CF      # noqa: E402
from jdec import indy as INDY        # noqa: E402
from jdec import mappings as MP       # noqa: E402
from jdec import mcmod as MM          # noqa: E402
from jdec import obf as OB            # noqa: E402
from jdec import strings as ST        # noqa: E402
from jdec.decompile import decompile, write_report  # noqa: E402
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
            except Exception:  # noqa: BLE001
                check("truncated class is rejected", True)
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
    test_weak_engine_is_rescued()
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
