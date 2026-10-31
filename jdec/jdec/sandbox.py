"""JVM-level isolation for replaying code from the jar under analysis.

The dynamic stages (`behave`, `recover`, `pool`) load classes from the target
and run their code. Process-tree termination and `-Xverify:none` are not a
sandbox. This module installs a Java `SecurityManager` at JVM start that:

  * allows filesystem writes only below a per-run root,
  * denies network access, process execution, native libraries and `System.exit`,
  * leaves reads, reflection, class loading, threads and properties alone
    (a decoder needs those, and they do not cross the boundary).

Native code is outside a Java sandbox. `loadLibrary` is denied so a jar cannot
enter it; hostile native payloads still need an OS/container boundary.

JDK 9-23 only: the SecurityManager was removed in JDK 24. Callers must pass
`--no-sandbox` on a newer JVM, which is a deliberate opt-out, not a fallback.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path

from . import engines as EN
from . import toolchain as TC

MANAGER_CLASS = "jdecsandbox.SandboxManager"

MANAGER_SOURCE = r'''package jdecsandbox;

import java.io.File;
import java.security.Permission;

/**
 * Java-level isolation for replaying code from an untrusted jar.
 *
 * Installed at JVM start with -Djava.security.manager=jdecsandbox.SandboxManager
 * and -Djdec.sandbox.root=&lt;dir&gt;. It denies process execution, network access,
 * native libraries and JVM exit, and allows filesystem writes only below the
 * configured root. Reads, reflection, class loading, threads and properties are
 * allowed: the replay driver needs them, and they are the operations a decoder
 * legitimately performs.
 *
 * This is not an OS boundary: native code, if it can be loaded at all, runs
 * outside it. loadLibrary is therefore denied by default.
 */
public final class SandboxManager extends SecurityManager {
    private final String root;
    private final java.util.Set<String> drivers;

    public SandboxManager() {
        String r = System.getProperty("jdec.sandbox.root");
        String canonical = null;
        if (r != null && !r.isEmpty()) {
            try {
                canonical = new File(r).getCanonicalPath();
            } catch (Exception ignored) {
                canonical = null;
            }
        }
        this.root = canonical;
        java.util.Set<String> set = new java.util.HashSet<>();
        String d = System.getProperty("jdec.sandbox.drivers", "");
        for (String s : d.split(",")) {
            s = s.trim();
            if (!s.isEmpty()) set.add(s);
        }
        this.drivers = set;
    }

    /** The replay driver itself exits at the end; target code may not. */
    private boolean driverExit() {
        ClassLoader mine = SandboxManager.class.getClassLoader();
        for (Class<?> c : getClassContext()) {
            if (c != null && drivers.contains(c.getName())
                    && c.getClassLoader() == mine) {
                return true;
            }
        }
        return false;
    }

    private boolean within(String path) {
        if (root == null) {
            return false;
        }
        try {
            String p = new File(path).getCanonicalPath();
            return p.equals(root) || p.startsWith(root + File.separator);
        } catch (Exception ignored) {
            return false;
        }
    }

    @Override
    public void checkPermission(Permission perm) {
        if (perm instanceof java.io.FilePermission) {
            String actions = perm.getActions();
            if (actions.contains("execute")) {
                throw new SecurityException("sandbox: process execution denied");
            }
            if (actions.contains("write") || actions.contains("delete")) {
                if (!within(perm.getName())) {
                    throw new SecurityException(
                        "sandbox: write outside " + root + " denied: " + perm.getName());
                }
            }
            return;
        }
        if (perm instanceof java.net.SocketPermission
                || perm instanceof java.net.NetPermission) {
            throw new SecurityException("sandbox: network access denied");
        }
        if (perm instanceof RuntimePermission) {
            String name = perm.getName();
            if (name.startsWith("exitVM")) {
                if (driverExit()) {
                    return;
                }
                throw new SecurityException("sandbox: JVM exit denied");
            }
            if (name.startsWith("setSecurityManager")
                    || name.startsWith("createSecurityManager")) {
                throw new SecurityException("sandbox: security manager change denied");
            }
            if (name.startsWith("loadLibrary")) {
                throw new SecurityException("sandbox: native library denied");
            }
        }
        // Reads, reflection, class loading, threads and property access stay
        // allowed: a decoder needs them and they do not cross the boundary.
    }

    @Override
    public void checkPermission(Permission perm, Object context) {
        checkPermission(perm);
    }
}
'''


_PLAIN_JARS: dict[tuple, Path] = {}


def plain_jar(path: Path, dest_dir: Path | None = None) -> Path:
    """Return a jar URLClassLoader can open under the sandbox.

    A self-extracting installer starts with a native stub, so the file is a
    valid zip for `zipfile`/`JarFile` but URLClassPath cannot resolve classes
    from it once a SecurityManager is installed. Repack the entries into a
    plain jar; an ordinary jar is returned unchanged.
    """
    path = Path(path)
    try:
        magic = path.open("rb").read(4)
    except OSError:
        return path
    if magic == b"PK\x03\x04":
        return path
    try:
        st = path.stat()
    except OSError:
        return path
    key = (str(path.resolve()), st.st_mtime_ns, st.st_size)
    hit = _PLAIN_JARS.get(key)
    if hit is not None and hit.is_file():
        return hit
    digest = hashlib.sha1(str(key).encode("utf-8")).hexdigest()[:12]
    cache = Path(tempfile.gettempdir()) / "jdec_plain_jars"
    cache.mkdir(parents=True, exist_ok=True)
    out = cache / f"{path.stem}-{digest}.jar"
    if not out.is_file():
        # stored, not deflated: the entries are class files and a temp copy
        # is thrown away; recompressing 10+ MB on every compare() is waste
        with zipfile.ZipFile(path) as zin, \
                zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zout:
            for info in zin.infolist():
                zout.writestr(info.filename, zin.read(info.filename))
    _PLAIN_JARS[key] = out
    return out


class SandboxError(TC.ToolchainError):
    """The JVM cannot provide the Java-level sandbox (or javac is missing)."""


_CACHE: Path | None = None
_MAJOR: dict[str, int] = {}


def _cache_dir() -> Path:
    key = hashlib.sha256(MANAGER_SOURCE.encode("utf-8")).hexdigest()[:12]
    return Path(tempfile.gettempdir()) / f"jdec_sandbox_{key}"


def manager_path() -> Path:
    """Directory holding the compiled manager; built once per source hash."""
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    d = _cache_dir()
    cls = d / "jdecsandbox" / "SandboxManager.class"
    if not cls.is_file():
        d.mkdir(parents=True, exist_ok=True)
        src = d / "SandboxManager.java"
        src.write_text(MANAGER_SOURCE, encoding="utf-8")
        r = TC.run_javac(["-encoding", "UTF-8", "-d", str(d), str(src)],
                         purpose="building the sandbox manager")
        if r.returncode != 0 or not cls.is_file():
            raise SandboxError(
                "cannot build the sandbox manager: "
                + (r.stderr or r.stdout or "")[-800:])
    _CACHE = d
    return d


def java_major(java: str | None = None) -> int:
    exe = java or EN.find_java()
    if not exe:
        raise SandboxError("java not found: set JAVA_HOME or put java on PATH")
    if exe in _MAJOR:
        return _MAJOR[exe]
    try:
        proc = subprocess.run([exe, "-version"], capture_output=True, text=True,
                              errors="replace", timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SandboxError(f"cannot ask {exe} for its version: {exc}") from None
    text = (proc.stderr or "") + (proc.stdout or "")
    m = re.search(r'version "(\d+)(?:\.(\d+))?', text)
    if not m:
        raise SandboxError("cannot read the JVM version from " + text[-200:])
    major = int(m.group(1))
    if major == 1:                       # 1.8 -> 8
        major = int(m.group(2) or 0)
    _MAJOR[exe] = major
    return major


def check_available(java: str | None = None) -> None:
    major = java_major(java)
    if major < 9:
        raise SandboxError(
            f"JDK {major} has no SecurityManager-based sandbox; JDK 9-23 required")
    if major >= 24:
        raise SandboxError(
            "the SecurityManager was removed in JDK 24; replay on JDK 9-23, "
            "or pass --no-sandbox to run without isolation")
    manager_path()


def jvm_args(root: Path, java: str | None = None, drivers=(),
             tmp: Path | None = None) -> list[str]:
    """JVM options that install the sandbox, with writes rooted at `root`.

    `drivers` names the replay driver classes that may call System.exit;
    every other class in the process is denied that permission. `tmp` is
    java.io.tmpdir and must stay inside `root` (defaults to it).
    """
    check_available(java)
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    tmp = Path(tmp).resolve() if tmp is not None else root
    if not (tmp == root or str(tmp).startswith(str(root) + os.sep)):
        raise SandboxError(f"java.io.tmpdir must be inside the sandbox root: {tmp}")
    tmp.mkdir(parents=True, exist_ok=True)
    args = [
        f"-Djava.security.manager={MANAGER_CLASS}",
        f"-Djdec.sandbox.root={root}",
        f"-Djava.io.tmpdir={tmp}",
    ]
    if drivers:
        args.append("-Djdec.sandbox.drivers=" + ",".join(drivers))
    return args


def classpath_entry(java: str | None = None) -> Path:
    """Directory to add to the JVM classpath so the manager can be loaded."""
    return manager_path()


def argfile_lines(root: Path, java: str | None = None, drivers=(),
                  tmp: Path | None = None) -> str:
    """`jvm_args` as lines for a `java @argsfile`; spaces are quoted."""
    out = []
    for arg in jvm_args(root, java=java, drivers=drivers, tmp=tmp):
        if " " in arg and "=" in arg:
            key, value = arg.split("=", 1)
            arg = f'{key}="{value}"'
        out.append(arg + "\n")
    return "".join(out)
