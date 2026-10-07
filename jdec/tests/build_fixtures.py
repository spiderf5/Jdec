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

# written at the jar root, as Fabric would ship them
META_FILES = ("fabric.mod.json", "demo.mixins.json", "demo.refmap.json")


def _javac() -> str | None:
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
