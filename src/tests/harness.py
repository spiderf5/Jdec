#!/usr/bin/env python3
"""Shared fixtures, constants and assertions for the regression suites.

Run:  python src/tests/run_tests.py            (core tests)
      python src/tests/run_tests.py --with-mc  (also exercises a real Minecraft jar)

The cases live in ``suites/``; this module is the re-export hub they import
from, which is why its imports look unused to a linter. Keeping the constants
in one place also keeps the engine cache and every fixture path at one path
depth, independent of which suite asks for them.

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
import traceback
import urllib.parse
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
from jdec import engines as EN  # noqa: E402
from jdec.decompile import (_iso_buckets, _owns_file, _scan_error_markers,
                            ClassOutcome, decompile, write_report)  # noqa: E402
from jdec.probe import JarProfile, profile_jar    # noqa: E402
from jdec.score import evaluate       # noqa: E402

# Every javac/java lookup in this file goes through these two. A JDK reachable
# only through JAVA_HOME (no PATH entry) is a normal Windows setup; resolving
# them once here keeps the gates and the subprocess calls in agreement.
JAVAC = build_fixtures._javac()
JAVA = EN.find_java()


def _jdk_tool(name: str) -> str | None:
    """javap/jar sit next to javac, which may be reachable only via JAVA_HOME."""
    if JAVAC:
        cand = Path(JAVAC).parent / (name + (".exe" if sys.platform == "win32" else ""))
        if cand.is_file():
            return str(cand)
    return shutil.which(name)


JAVAP = _jdk_tool("javap")

SAMPLE = ROOT / "tests" / "sample.jar"
MIXIN = ROOT / "tests" / "mixin.jar"
FLOW = ROOT / "tests" / "flow.jar"
SHAPES = ROOT / "tests" / "shapes.jar"
MC_JAR = ROOT / "tests" / "mc" / "client_1.20.4.jar"
MC_MAP = ROOT / "tests" / "mc" / "mojang_1.20.4.txt"


ENGINES_DIR = ROOT.parent / "engines"
ENGINES_READY = False


def _prepare_engines(quiet: bool = False) -> bool:
    """Make sure the decompiler jars are present before any test needs them.

    The jars are gitignored, so a fresh checkout has none. A test that needs an
    engine must be skipped with a reason rather than killing the whole run -
    decompile() raises EngineUnavailable when no engine is available.
    """
    global ENGINES_READY
    try:
        EN.ensure_engines(ENGINES_DIR, quiet=quiet)
    except Exception as exc:  # noqa: BLE001
        if not quiet:
            print(f"engine setup failed: {exc}")
    ENGINES_READY = any(EN.ENGINES[k].available(ENGINES_DIR) for k in EN.ENGINES)
    if ENGINES_READY and EN.find_java() is None:
        # The jars are on disk but nothing can run them. Treat that as "no
        # engine" so every engine-dependent case skips with a reason instead of
        # failing one by one with "java not found on PATH".
        ENGINES_READY = False
        if not quiet:
            print("NOTE       : decompiler jars present but no Java runtime found "
                  "(set JAVA_HOME); engine-dependent tests will be SKIPPED")
    if not ENGINES_READY and not quiet:
        print("NOTE       : no decompiler engine available (offline?); "
              "engine-dependent tests will be SKIPPED")
    return ENGINES_READY


def _no_engines() -> bool:
    if ENGINES_READY:
        return False
    print("  (skipped: decompiler engines unavailable; run `python jdec.py engines`)")
    return True



_passed = 0
_failed = 0



def _jdk_tool(name: str) -> str | None:
    """javap/jar sit next to javac, which may be reachable only via JAVA_HOME."""
    if JAVAC:
        cand = Path(JAVAC).parent / (name + (".exe" if sys.platform == "win32" else ""))
        if cand.is_file():
            return str(cand)
    return shutil.which(name)


def _prepare_engines(quiet: bool = False) -> bool:
    """Make sure the decompiler jars are present before any test needs them.

    The jars are gitignored, so a fresh checkout has none. A test that needs an
    engine must be skipped with a reason rather than killing the whole run -
    decompile() raises EngineUnavailable when no engine is available.
    """
    global ENGINES_READY
    try:
        EN.ensure_engines(ENGINES_DIR, quiet=quiet)
    except Exception as exc:  # noqa: BLE001
        if not quiet:
            print(f"engine setup failed: {exc}")
    ENGINES_READY = any(EN.ENGINES[k].available(ENGINES_DIR) for k in EN.ENGINES)
    if ENGINES_READY and EN.find_java() is None:
        # The jars are on disk but nothing can run them. Treat that as "no
        # engine" so every engine-dependent case skips with a reason instead of
        # failing one by one with "java not found on PATH".
        ENGINES_READY = False
        if not quiet:
            print("NOTE       : decompiler jars present but no Java runtime found "
                  "(set JAVA_HOME); engine-dependent tests will be SKIPPED")
    if not ENGINES_READY and not quiet:
        print("NOTE       : no decompiler engine available (offline?); "
              "engine-dependent tests will be SKIPPED")
    return ENGINES_READY


def _no_engines() -> bool:
    if ENGINES_READY:
        return False
    print("  (skipped: decompiler engines unavailable; run `python jdec.py engines`)")
    return True


def check(name: str, cond: bool, detail: str = "") -> None:
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  ok   {name}")
    else:
        _failed += 1
        print(f"  FAIL {name}" + (f"  -> {detail}" if detail else ""))

BROKEN_SAMPLE = "demo/broken/Truncated.class"  # deliberately truncated fixture


def _synthetic_pe(names_rva: int = 0x10A0, name_bytes: bytes = b"Java_test_Foo\x00") -> bytes:
    """Minimal PE32 image with one export name; used to pin the export-table layout."""
    buf = bytearray(0x320)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)          # e_lfanew
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", buf, 0x86, 1)             # NumberOfSections
    struct.pack_into("<H", buf, 0x94, 0xE0)          # SizeOfOptionalHeader
    struct.pack_into("<H", buf, 0x98, 0x10B)         # PE32 magic
    struct.pack_into("<II", buf, 0xF8, 0x1000, 0x100)  # export dir RVA/size
    struct.pack_into("<I", buf, 0x178 + 8, 0x1000)   # section VirtualSize
    struct.pack_into("<I", buf, 0x178 + 12, 0x1000)  # section VirtualAddress
    struct.pack_into("<I", buf, 0x178 + 16, 0x320)   # SizeOfRawData
    struct.pack_into("<I", buf, 0x178 + 20, 0x200)   # PointerToRawData
    exp = 0x200
    struct.pack_into("<I", buf, exp + 20, 1)         # NumberOfFunctions
    struct.pack_into("<I", buf, exp + 24, 1)         # NumberOfNames
    struct.pack_into("<I", buf, exp + 28, 0x1040)    # AddressOfFunctions (decoy)
    struct.pack_into("<I", buf, exp + 32, 0x1060)    # AddressOfNames
    struct.pack_into("<I", buf, exp + 36, 0x1080)    # AddressOfNameOrdinals
    struct.pack_into("<I", buf, 0x240, 0x10C0)       # function -> decoy string
    struct.pack_into("<I", buf, 0x260, names_rva)
    buf[0x2A0:0x2A0 + len(name_bytes)] = name_bytes
    buf[0x2C0:0x2C0 + 6] = b"DECOY\x00"
    return bytes(buf)


def _compile_java(td: Path, files: dict[str, str], classpath=()) -> Path:
    """Compile `{relative/path.java: source}` under `td/src` into `td/classes`."""
    src = td / "src"
    cls = td / "classes"
    for rel, text in files.items():
        f = src / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")
    cls.mkdir(parents=True, exist_ok=True)
    import subprocess
    cp = [str(c) for c in classpath]
    proc = subprocess.run([JAVAC, "-nowarn", "-d", str(cls)]
                          + (["-cp", os.pathsep.join(cp)] if cp else [])
                          + [str(p) for p in sorted(src.rglob("*.java"))],
                          capture_output=True, text=True, errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr[-1500:])
    return cls


def _jar_from(classes: Path, out: Path, extra: dict[str, bytes] | None = None) -> Path:
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(classes.rglob("*.class")):
            z.write(p, p.relative_to(classes).as_posix())
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return out


def _looks_like_signature(name: str) -> bool:
    upper = name.upper()
    return upper.startswith("META-INF/") and upper.endswith(
        (".SF", ".RSA", ".DSA", ".EC"))


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


def _run(fn) -> None:
    """Run one test; a crash counts as a failure instead of ending the suite.

    Without this a single unexpected exception aborts the run: the remaining
    tests never execute and CI reports one red job with no indication of which
    assertions still hold. That is how a Windows-only constant
    (subprocess.CREATE_NEW_PROCESS_GROUP) produced seven red jobs across
    ubuntu and macos, all stopping at the same test.
    """
    global _failed
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - a crashing test is a failure
        _failed += 1
        frame = traceback.extract_tb(exc.__traceback__)[-1]
        print(f"  FAIL {fn.__name__} raised {type(exc).__name__}: {exc}"
              f"  ({Path(frame.filename).name}:{frame.lineno})")

