#!/usr/bin/env python3
"""Build the Mixin fixture jar used by the regression tests.

Run directly to rebuild, or let run_tests.py call `ensure_mixin_jar()`:

    python tests/build_fixtures.py

The fixture is a tiny Fabric-style mod: a couple of @Mixin classes targeting
stand-in game classes, plus one class that looks like licence/native code. It
is compiled with javac only - no Mixin dependency - because the annotation
*shapes* are what jdec reads, and those are just constant-pool constants.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "tests" / "samples" / "mixin"
BUILD = ROOT / "tests" / "build" / "mixin"
JAR = ROOT / "tests" / "mixin.jar"
JSR_JAR = ROOT / "tests" / "jsr.jar"

FLOW_SRC = ROOT / "tests" / "samples" / "flow"
FLOW_BUILD = ROOT / "tests" / "build" / "flow"
FLOW_JAR = ROOT / "tests" / "flow.jar"

# Case-twin fixture. The two sources live in separate roots because javac (and
# the filesystem) cannot hold `Widget.java` and `widget.java` side by side on
# Windows; the zip is case-sensitive, so the jar can still carry both classes.
COLLIDE_SRC = ROOT / "tests" / "samples" / "collide_upper"
COLLIDE_SRC_LOWER = ROOT / "tests" / "samples" / "collide_lower"
COLLIDE_BUILD = ROOT / "tests" / "build" / "collide_upper"
COLLIDE_BUILD_LOWER = ROOT / "tests" / "build" / "collide_lower"
COLLIDE_JAR = ROOT / "tests" / "collide.jar"

# The main regression sample: the three demo subtrees plus one class that is
# compiled and then deliberately truncated (parse must reject it).
DEMO_SRC = ROOT / "tests" / "samples" / "demo"
DEMO_BUILD = ROOT / "tests" / "build" / "demo"
BROKEN_BUILD = ROOT / "tests" / "build" / "broken"
BROKEN_CLASS = "demo/broken/Truncated.class"
SAMPLE_JAR = ROOT / "tests" / "sample.jar"

# A second, tiny fixture compiled with `--release 8` (class file major 52).
# The main fixtures are built by whatever javac is installed, i.e. major 65 on
# a JDK 21 machine, and a JDK 8 verifier cannot read those at all — so without
# this the "does the output load on more than one JVM" matrix would have
# nothing to judge inside the repo.
LEGACY8_SRC = ROOT / "tests" / "samples" / "legacy8"
LEGACY8_BUILD = ROOT / "tests" / "build" / "legacy8"
LEGACY8_JAR = ROOT / "tests" / "legacy8.jar"

# written at the jar root, as Fabric would ship them
META_FILES = ("fabric.mod.json", "demo.mixins.json", "demo.refmap.json")


def _javac() -> str | None:
    """Locate javac the same way the engines do.

    `shutil.which` alone is not enough: a perfectly normal Windows setup is
    "JDK installed under D:\\java21 and JAVA_HOME points at it, but no PATH
    entry".  The fixture build used to fail there and the whole suite aborted
    before a single assertion, while `engines.find_javac()` (which does honour
    JAVA_HOME and the usual install dirs) would have found it.  Reuse it.
    """
    try:
        from jdec.engines import find_javac
        exe = find_javac()
        if exe:
            return exe
    except Exception:  # noqa: BLE001 - tests must still run without the package
        pass
    exe = shutil.which("javac")
    if exe:
        return exe
    java = shutil.which("java")
    if not java:
        return None
    cand = Path(java).resolve().parent / ("javac.exe" if sys.platform == "win32" else "javac")
    return str(cand) if cand.exists() else None


def _compile(javac: str, src: Path, build: Path) -> None:
    if build.exists():
        shutil.rmtree(build, ignore_errors=True)
    build.mkdir(parents=True, exist_ok=True)
    sources = sorted(str(p) for p in src.rglob("*.java"))
    if not sources:
        raise RuntimeError(f"no sources under {src}")
    proc = subprocess.run([javac, "-nowarn", "-d", str(build)] + sources,
                          capture_output=True, text=True, errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(f"javac failed:\n{proc.stderr[:2000]}")


def _compile_release(javac: str, src: Path, build: Path, release: int) -> None:
    """Like _compile, but pinned to a class-file version (needs javac 9+)."""
    if build.exists():
        shutil.rmtree(build, ignore_errors=True)
    build.mkdir(parents=True, exist_ok=True)
    sources = sorted(str(p) for p in src.rglob("*.java"))
    if not sources:
        raise RuntimeError(f"no sources under {src}")
    proc = subprocess.run([javac, "-nowarn", "--release", str(release),
                           "-d", str(build)] + sources,
                          capture_output=True, text=True, errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(f"javac --release {release} failed://n{proc.stderr[:2000]}")


def ensure_legacy8_jar(quiet: bool = True) -> Path | None:
    """Class files at major 52, so JDK 8 / 17 / 21 can all judge them."""
    javac = _javac()
    if javac is None:
        if not quiet:
            print("javac not found: cannot build legacy8.jar")
        return None
    if not LEGACY8_SRC.is_dir():
        if not quiet:
            print(f"no sources at {LEGACY8_SRC}")
        return None
    try:
        _compile_release(javac, LEGACY8_SRC, LEGACY8_BUILD, 8)
    except Exception as exc:  # noqa: BLE001 - old javac without --release
        if not quiet:
            print(f"legacy8 fixture not built: {exc}")
        return None
    LEGACY8_JAR.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(LEGACY8_JAR, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(LEGACY8_BUILD.rglob("*.class")):
            z.write(p, p.relative_to(LEGACY8_BUILD).as_posix())
    return LEGACY8_JAR


def build_jsr_class_bytes() -> bytes:
    """A class at major 50 whose method uses `jsr`/`ret`.

    javac has not emitted a subroutine since Java 6, so this cannot be compiled
    — and `jsr` is illegal in class files from major 51 on, which is why the
    fixture has to be at 50 and why the frames are deliberately absent (the
    type-inference verifier runs for 50.0 methods without a StackMapTable).
    """
    import struct

    cp = bytearray()
    count = 0

    def utf8(s: str) -> int:
        nonlocal count
        b = s.encode("utf-8")
        cp.extend(b"\x01" + struct.pack(">H", len(b)) + b)
        count += 1
        return count

    def cls(name_idx: int) -> int:
        nonlocal count
        cp.extend(b"\x07" + struct.pack(">H", name_idx))
        count += 1
        return count

    def nat(n: int, d: int) -> int:
        nonlocal count
        cp.extend(b"\x0C" + struct.pack(">HH", n, d))
        count += 1
        return count

    def methodref(c: int, nt: int) -> int:
        nonlocal count
        cp.extend(b"\x0A" + struct.pack(">HH", c, nt))
        count += 1
        return count

    this_name = utf8("demo/jsr/JsrDemo")
    this_class = cls(this_name)
    obj_name = utf8("java/lang/Object")
    obj_class = cls(obj_name)
    init = utf8("<init>")
    void_desc = utf8("()V")
    code_name = utf8("Code")
    init_nat = nat(init, void_desc)
    obj_init = methodref(obj_class, init_nat)
    choose = utf8("choose")
    int_desc = utf8("(I)I")

    def method(flags: int, name_idx: int, desc_idx: int, max_stack: int,
               max_locals: int, code: bytes) -> bytes:
        body = struct.pack(">HHI", max_stack, max_locals, len(code)) + code
        body += struct.pack(">HH", 0, 0)          # no handlers, no attributes
        attr = struct.pack(">HI", code_name, len(body)) + body
        return (struct.pack(">HHHH", flags, name_idx, desc_idx, 1) + attr)

    # iconst_2, iconst_3, iadd, pop  -> something for the folder to chew on
    # iconst_1, jsr +4 (-> 9), ireturn, astore_1, ret 1
    choose_code = bytes([0x05, 0x06, 0x60, 0x57,
                         0x04, 0xA8, 0x00, 0x04, 0xAC,
                         0x4B, 0xA9, 0x01])
    body = (struct.pack(">HHHH", 0x0021, this_class, obj_class, 0)
            + struct.pack(">H", 0)
            + struct.pack(">H", 2)
            + method(0x0001, init, void_desc, 1, 1,
                     bytes([0x2A, 0xB7, obj_init >> 8, obj_init & 0xFF, 0xB1]))
            + method(0x0009, choose, int_desc, 2, 2, choose_code)
            + struct.pack(">H", 0))
    return (b"\xCA\xFE\xBA\xBE" + struct.pack(">HH", 0, 50)
            + struct.pack(">H", count + 1) + bytes(cp) + body)


def ensure_jsr_jar(quiet: bool = True) -> Path:
    """Materialise tests/jsr.jar (hand-built; no compiler can produce this)."""
    data = build_jsr_class_bytes()
    if not JSR_JAR.is_file() or JSR_JAR.read_bytes() != data:
        JSR_JAR.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(JSR_JAR, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("demo/jsr/JsrDemo.class", data)
    return JSR_JAR


def build() -> Path:
    javac = _javac()
    if javac is None:
        raise RuntimeError("javac not found on PATH")

    _compile(javac, SRC, BUILD)
    JAR.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(JAR, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(BUILD.rglob("*.class")):
            z.write(p, p.relative_to(BUILD).as_posix())
        for name in META_FILES:
            src = SRC / name
            if src.exists():
                z.write(src, name)
        # a stand-in for the library a JNIC-style virtualiser would ship, so
        # the native-library path is exercised without shipping real machine code
        z.writestr("windows/x86_64/protect.dll", bytes(range(256)) * 32)

    _compile(javac, FLOW_SRC, FLOW_BUILD)
    with zipfile.ZipFile(FLOW_JAR, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(FLOW_BUILD.rglob("*.class")):
            z.write(p, p.relative_to(FLOW_BUILD).as_posix())

    _build_collide(javac)
    _build_sample_jar(javac)
    return JAR


def _build_sample_jar(javac: str) -> Path:
    """Build tests/sample.jar from the demo sources plus a truncated class.

    The truncated entry is produced by compiling demo/broken/Truncated.java
    and cutting the class bytes mid-constant-pool, so CF.parse hits EOF and
    must raise ClassFormatError (the "quarantine, don't crash" behaviour).
    """
    for sub in ("legacy", "modern", "obf"):
        _compile(javac, DEMO_SRC / sub, DEMO_BUILD / sub)
    _compile(javac, DEMO_SRC / "broken", BROKEN_BUILD)
    broken_path = BROKEN_BUILD / "demo" / "broken" / "Truncated.class"
    if not broken_path.exists():
        raise RuntimeError(f"javac did not produce {broken_path}")
    broken_bytes = broken_path.read_bytes()
    # deterministic truncation: keep the header + part of the constant pool
    cut = max(11, len(broken_bytes) // 2)
    truncated = broken_bytes[:cut]

    SAMPLE_JAR.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(SAMPLE_JAR, "w", zipfile.ZIP_DEFLATED) as z:
        for sub in ("legacy", "modern", "obf"):
            bdir = DEMO_BUILD / sub
            for p in sorted(bdir.rglob("*.class")):
                # javac lays classes under <bdir>/demo/<sub>/...; the jar must
                # carry the package path only
                z.write(p, p.relative_to(bdir).as_posix())
        z.writestr(BROKEN_CLASS, truncated)
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n\r\n")
    return SAMPLE_JAR


def ensure_sample_jar(quiet: bool = True) -> Path | None:
    if SAMPLE_JAR.exists():
        return SAMPLE_JAR
    javac = _javac()
    if javac is None:
        return None
    try:
        path = _build_sample_jar(javac)
        if not quiet:
            print(f"built {path}")
        return path
    except Exception as exc:  # noqa: BLE001
        if not quiet:
            print(f"could not build sample fixture: {exc}")
        return None


def _build_collide(javac: str) -> Path:
    """Build a jar holding two classes whose names differ only by letter case."""
    _compile(javac, COLLIDE_SRC, COLLIDE_BUILD)
    _compile(javac, COLLIDE_SRC_LOWER, COLLIDE_BUILD_LOWER)
    COLLIDE_JAR.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(COLLIDE_JAR, "w", zipfile.ZIP_DEFLATED) as z:
        for build in (COLLIDE_BUILD, COLLIDE_BUILD_LOWER):
            for p in sorted(build.rglob("*.class")):
                z.write(p, p.relative_to(build).as_posix())
    return COLLIDE_JAR


def ensure_collide_jar(quiet: bool = True) -> Path | None:
    if COLLIDE_JAR.exists():
        return COLLIDE_JAR
    javac = _javac()
    if javac is None:
        return None
    try:
        path = _build_collide(javac)
        if not quiet:
            print(f"built {path}")
        return path
    except Exception as exc:  # noqa: BLE001
        if not quiet:
            print(f"could not build collide fixture: {exc}")
        return None


def ensure_mixin_jar(quiet: bool = True) -> Path | None:
    if JAR.exists() and FLOW_JAR.exists():
        return JAR
    try:
        path = build()
        if not quiet:
            print(f"built {path} and {FLOW_JAR}")
        return path
    except Exception as exc:  # noqa: BLE001
        if not quiet:
            print(f"could not build mixin fixture: {exc}")
        return None


if __name__ == "__main__":
    try:
        print(f"built {build()}")
    except Exception as exc:  # noqa: BLE001
        print(f"failed: {exc}")
        sys.exit(1)
