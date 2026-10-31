"""One place for JDK discovery, javac invocation and classpath plumbing.

Six call sites used to resolve javac and spawn it themselves — stub building
(twice), the replay driver, the pool driver, project compilation, and the
Procyon bridge. Each had its own timeout, its own encoding flags and its own
idea of what "javac is missing" looks like; two of them kept the bare string
``"javac"`` and let ``subprocess`` raise ``FileNotFoundError`` under the caller.

The rule now: `run_javac` is the only function in this package that starts a
compiler. Everything else asks it, and a timeout is always a `ToolchainError`
with a message a user can act on.

Discovery itself stays in `engines` (it also has to find `java` for the
decompiler engines, and it knows the install-directory fallbacks). This module
only delegates to it, so `mock.patch("jdec.engines.find_java")` keeps working.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

JAVAC_TIMEOUT = 300

_MISSING_JAVAC = ("javac not found: set JAVA_HOME to a JDK or put javac on PATH "
                  "(this step needs a full JDK, not just a JRE)")
_MISSING_JAVA = "java not found: set JAVA_HOME to a JDK or put java on PATH"


def default_engines_dir() -> Path:
    """Where downloaded engine jars and generated agents live.

    A source checkout keeps the historical ``jdec/engines`` directory so
    existing downloads and tests stay put. An installed wheel must never
    write to ``site-packages/engines`` (shared, read-only and unversioned),
    so it uses the per-user cache instead.
    """
    pkg = Path(__file__).resolve().parent
    repo_root = pkg.parent.parent
    if (repo_root / "jdec.py").is_file() or (repo_root / ".git").is_dir():
        return pkg.parent / "engines"
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA")
                    or (Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME")
                    or (Path.home() / ".cache"))
    return base / "jdec" / "engines"


class ToolchainError(RuntimeError):
    """The JDK is missing, unreachable, or hung. Always actionable."""


def cp_sep() -> str:
    """Classpath separator for the platform the JVM runs on."""
    from . import engines as EN
    return EN.cp_sep()


path_sep = cp_sep


def find_java() -> str:
    """Absolute path to `java`, or "" when there is none."""
    from . import engines as EN
    return EN.find_java() or ""


def find_javac(bin_name: str = "javac") -> str:
    """Absolute path to `javac`, or "" when there is none.

    An explicit non-default `bin_name` is authoritative: if the caller named a
    compiler and it is not there, quietly compiling with a different JDK would
    attribute the result to the wrong toolchain.
    """
    if bin_name != "javac":
        return bin_name if Path(bin_name).is_file() else ""
    from . import engines as EN
    return EN.find_javac() or ""


def require_javac(purpose: str = "") -> str:
    exe = find_javac()
    if not exe:
        raise ToolchainError(_MISSING_JAVAC
                             + (f" [{purpose}]" if purpose else ""))
    return exe


def require_java(purpose: str = "") -> str:
    exe = find_java()
    if not exe:
        raise ToolchainError(_MISSING_JAVA
                             + (f" [{purpose}]" if purpose else ""))
    return exe


def run_javac(args, *, exe: str | None = None, cwd=None,
              timeout: int = JAVAC_TIMEOUT,
              purpose: str = "") -> subprocess.CompletedProcess:
    """Run javac and return the CompletedProcess; raise on timeout/absence.

    `exe` lets a caller honour an explicit compiler override (a `javac_bin`
    argument); when omitted the normal discovery runs. The caller keeps
    deciding what a non-zero exit means — each one prints a different
    diagnostic — but it no longer decides whether the process could start.
    """
    if exe and exe != "javac":
        # a bare "javac" is the sentinel for "discover it" — treating it as an
        # explicit path ignored JAVA_HOME and only ever looked at PATH
        if not (Path(exe).is_file() or shutil.which(exe)):
            raise ToolchainError(
                f"javac not found at {exe!r}"
                + (f" [{purpose}]" if purpose else ""))
    else:
        exe = require_javac(purpose)
    cmd = [exe] + [str(a) for a in args]
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              errors="replace", check=False,
                              cwd=str(cwd) if cwd else None, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ToolchainError(
            f"javac timed out after {timeout}s"
            + (f" while {purpose}" if purpose else "")) from None
    except OSError as exc:
        raise ToolchainError(f"cannot run javac ({exe}): {exc}") from None


def norm_classpath(cp: str) -> str:
    """Normalise a classpath for the JVM: backslashes gone, MSYS drives fixed.

    java @argfiles treat a backslash as an escape character, and MSYS-style
    paths (`/d/x`) are not accepted either, so both are rewritten to `D:/x`.
    Windows only: on POSIX the input is already in the form java expects and
    any rewrite (`/a/b` -> `a:/b`) would only corrupt it.
    """
    if os.name != "nt":
        return cp
    cp = cp.replace("\\", "/")
    return re.sub(r"(^|;)/([A-Za-z0-9_])/", r"\1\2:/", cp)
