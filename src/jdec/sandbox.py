"""JVM-level isolation for replaying code from the jar under analysis.

The dynamic stages (`behave`, `recover`, `pool`) load classes from the target
and run their code. Process-tree termination and `-Xverify:none` are not a
sandbox. This module installs a Java `SecurityManager` at JVM start that:

  * allows filesystem writes only below a per-run root,
  * denies network access, process execution, native libraries and `System.exit`,
  * allows deep reflection (`setAccessible`) only from a driver frame: it is the
    door to `sun.misc.Unsafe`, and Unsafe can rewrite the manager's own `root`
    field and undo every check below. Reads, class loading, threads and
    properties stay allowed - a decoder needs them and they do not cross the
    boundary.

A target that needs `setAccessible` on its own classes therefore runs inside a
driver method, not on its own: the driver is the frame the check looks at.
Native code is outside a Java sandbox. `loadLibrary` is denied so a jar cannot
enter it; hostile native payloads still need an OS/container boundary.

The Java layer is an enhancement, not a hard dependency: SecurityManager was
removed in JDK 24 (JEP 486). Two backends are selected automatically:

  * `manager` (JDK 9-23): the Java checks above, plus the process-level layer.
  * `process` (JDK 24+ or any JDK without a manager): process-level isolation
    only - a dedicated work dir, a trimmed child environment, its own process
    group and whole-tree termination on timeout. There is NO per-operation
    denial of writes/network/native calls in this mode, so it is only safe for
    trusted jars. `--no-sandbox` remains a full, explicit opt-out.

Neither backend is an OS/container boundary: a hostile native payload still
needs a container or an unprivileged user. That is a deployment decision, not
something a Java flag can promise.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import NamedTuple

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
 * configured root. Reads, class loading, threads and properties are allowed:
 * the replay driver needs them, and they are the operations a decoder
 * legitimately performs. Deep reflection is allowed from a driver frame only,
 * because setAccessible leads to sun.misc.Unsafe, and Unsafe can rewrite this
 * object's own `root` field.
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

    /**
     * Is the *nearest* non-JDK frame a driver?
     *
     * driverExit() asks "is a driver somewhere on the stack", which is right
     * for an exit the driver performs itself. Reflection needs a stricter
     * question: target code is always invoked from a driver, so a whole-stack
     * test answers "yes" for the target as well and hands it setAccessible -
     * which is all it takes to read sun.misc.Unsafe and rewrite this object's
     * `root` field.
     */
    private boolean driverFrame() {
        ClassLoader mine = SandboxManager.class.getClassLoader();
        for (Class<?> c : getClassContext()) {
            if (c == null) continue;
            String n = c.getName();
            if (n.startsWith("java.") || n.startsWith("javax.")
                    || n.startsWith("jdk.") || n.startsWith("sun.")
                    || n.startsWith("jdecsandbox.")) {
                continue;                        // JDK plumbing, and this class
            }
            return drivers.contains(n) && c.getClassLoader() == mine;
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
        if (perm instanceof java.lang.reflect.ReflectPermission) {
            // setAccessible is the door to sun.misc.Unsafe, and Unsafe writes
            // `root` below and undoes every check in this method. Drivers do
            // their own reflection; target code that runs *under* a driver
            // frame is a different thing, hence the nearest-frame test.
            if (!driverFrame()) {
                throw new SecurityException("sandbox: deep reflection denied");
            }
            return;
        }
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
        // Reads, class loading, threads and property access stay allowed: a
        // decoder needs them and they do not cross the boundary. Reflection is
        // decided above, and only for driver frames.
    }

    @Override
    public void checkPermission(Permission perm, Object context) {
        checkPermission(perm);
    }
}
'''


_PLAIN_JARS: dict[tuple, Path] = {}


def plain_jar(path: Path, dest_dir: Path | None = None) -> Path:
    """Return a jar a replay classloader can open reliably.

    A self-extracting installer starts with a native stub, so the file is a
    valid zip for `zipfile`/`JarFile` but URLClassPath cannot resolve classes
    from it once the sandbox is installed. Repacking also normalises inputs
    for the process backend; an ordinary jar is returned unchanged.
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
    """Replay cannot run under the requested isolation backend."""


_CACHE: Path | None = None
_MAJOR: dict[str, int] = {}

MANAGER = "manager"
PROCESS = "process"
_BACKENDS = (MANAGER, PROCESS)

# Names whose value should never reach a process that executes target code.
_SENSITIVE_SUFFIX = ("_TOKEN", "_KEY", "_SECRET", "_PASSWORD", "_PASSWD",
                     "_CREDENTIAL", "_CREDENTIALS", "_APIKEY")
_SENSITIVE_EXACT = {
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN", "GH_TOKEN", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS", "JAVA_OPTIONS", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
}
# Windows needs these to start any process at all; keep them regardless of the
# filtering rules below.
_ENV_KEEP = {
    "PATH", "JAVA_HOME", "HOME", "USER", "LANG", "LC_ALL", "TZ", "TMPDIR",
    "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "TEMP",
    "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMFILES",
    "PROGRAMDATA", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
}


class IsolationPlan(NamedTuple):
    backend: str
    major: int
    note: str


def container_available() -> str | None:
    """A container CLI, if one exists. Reserved for an OS-level backend."""
    for name in ("docker", "podman"):
        exe = shutil.which(name)
        if exe:
            return exe
    return None


def child_env(base: dict[str, str] | None = None) -> dict[str, str]:
    """Copy the environment without credentials, proxies or JVM-injection vars.

    This is defence in depth for a process that runs code from the jar under
    analysis, not an isolation boundary: the child can still read files the
    user can read. It stops accidental credential disclosure and stops an
    inherited JAVA_TOOL_OPTIONS from silently changing the replay JVM.
    """
    env = dict(base if base is not None else os.environ)
    for key in list(env):
        up = key.upper()
        if up in _ENV_KEEP:
            continue
        if (up in _SENSITIVE_EXACT or up.endswith(_SENSITIVE_SUFFIX)
                or up.startswith(("AWS_", "GCP_", "AZURE_"))):
            env.pop(key, None)
    return env


def run_replay(cmd: list[str], timeout: int, *, harden: bool = True,
               **popen_kw) -> subprocess.CompletedProcess:
    """Run a replay JVM; on timeout kill the WHOLE process tree.

    subprocess.run only kills the direct child, leaving grandchildren alive.
    With ``harden`` the child also gets a trimmed environment and its own
    process group, so ``os.killpg`` / ``taskkill /T`` cannot reach the caller.
    Returns a CompletedProcess with a ``timed_out`` attribute.
    """
    popen_kw.setdefault("stdout", subprocess.PIPE)
    popen_kw.setdefault("stderr", subprocess.PIPE)
    text_mode = bool(popen_kw.get("text") or popen_kw.get("encoding")
                     or popen_kw.get("universal_newlines"))
    empty = "" if text_mode else b""
    if harden:
        popen_kw.setdefault("env", child_env())
        if os.name == "nt":
            popen_kw.setdefault("creationflags",
                                subprocess.CREATE_NEW_PROCESS_GROUP)
        else:
            popen_kw.setdefault("start_new_session", True)
    proc = subprocess.Popen(cmd, **popen_kw)
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                               capture_output=True, timeout=30)
            elif harden:
                # start_new_session=True means pgid == pid, so this cannot
                # reach the caller even if the group leader already exited.
                os.killpg(os.getpgid(proc.pid), 9)
            else:
                # Without its own session the child shares OUR process group.
                # killpg here would SIGKILL the caller (and the CI runner).
                proc.kill()
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            out, err = proc.communicate(timeout=30)
        except Exception:
            out, err = empty, empty
            try:
                proc.kill()
            except Exception:
                pass
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
        # communicate() normally closes these; make sure a failed cleanup
        # does not leave pipe handles open behind a CompletedProcess.
        for stream in (proc.stdout, proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except Exception:
                pass
    r = subprocess.CompletedProcess(cmd, 1 if timed_out else proc.returncode,
                                    out if out is not None else empty,
                                    err if err is not None else empty)
    r.timed_out = timed_out  # type: ignore[attr-defined]
    return r

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


def plan(java: str | None = None, backend: str | None = None) -> IsolationPlan:
    """Choose an isolation backend for this JVM.

    ``manager`` still gives per-operation denials on JDK 9-23. JDK 24+ has no
    SecurityManager, so it falls back to the process layer instead of making
    every replay command fail. Containers are never selected implicitly: they
    need an image and a mount policy supplied by the operator.
    """
    major = java_major(java)
    if backend is None:
        backend = os.environ.get("JDEC_ISOLATION") or None
    if backend is not None and backend not in _BACKENDS:
        raise SandboxError(
            f"unknown isolation backend: {backend} (expected manager or process)")
    chosen = backend or (MANAGER if 9 <= major <= 23 else PROCESS)
    if chosen == MANAGER:
        if not 9 <= major <= 23:
            raise SandboxError(
                f"JDK {major} cannot run the SecurityManager backend; "
                f"use --isolation process")
        manager_path()
        return IsolationPlan(MANAGER, major,
                             "Java SecurityManager + process-level isolation")
    return IsolationPlan(PROCESS, major,
                         "process-level isolation only; no per-operation denial")


def check_available(java: str | None = None) -> None:
    """Fail only when replay cannot run at all; JDK 24+ is no longer a failure."""
    plan(java)


def jvm_args(root: Path, java: str | None = None, drivers=(),
             tmp: Path | None = None, backend: str | None = None) -> list[str]:
    """JVM options for the chosen backend, with writes rooted at `root`.

    `drivers` names the replay driver classes that may call System.exit; it is
    only meaningful for the manager backend. `tmp` is java.io.tmpdir and must
    stay inside `root` (defaults to it).
    """
    chosen = plan(java, backend)
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    tmp = Path(tmp).resolve() if tmp is not None else root
    if not (tmp == root or str(tmp).startswith(str(root) + os.sep)):
        raise SandboxError(f"java.io.tmpdir must be inside the sandbox root: {tmp}")
    tmp.mkdir(parents=True, exist_ok=True)
    args = [f"-Djdec.sandbox.root={root}", f"-Djava.io.tmpdir={tmp}"]
    if chosen.backend == MANAGER:
        args.insert(0, f"-Djava.security.manager={MANAGER_CLASS}")
        if drivers:
            args.append("-Djdec.sandbox.drivers=" + ",".join(drivers))
    else:
        print("isolation: JDK has no SecurityManager; process-level isolation "
              "only - writes, network, native calls and exit are NOT denied. "
              "Run trusted jars only.", file=sys.stderr)
    return args


def classpath_entry(java: str | None = None,
                    backend: str | None = None) -> Path | None:
    """Classpath dir for the manager, or None when no manager is installed."""
    return manager_path() if plan(java, backend).backend == MANAGER else None


def argfile_lines(root: Path, java: str | None = None, drivers=(),
                  tmp: Path | None = None, backend: str | None = None) -> str:
    """`jvm_args` as lines for a `java @argsfile`; spaces are quoted."""
    out = []
    for arg in jvm_args(root, java=java, drivers=drivers, tmp=tmp,
                        backend=backend):
        if " " in arg and "=" in arg:
            key, value = arg.split("=", 1)
            arg = f'{key}="{value}"'
        out.append(arg + "\n")
    return "".join(out)
