"""JVM verification gate: does the class actually load under `-Xverify:all`?

This is the roadmap's stage-02 threshold made executable. Every bytecode rewrite
in this package claims to be behaviour-preserving; the only authority on that is
the JVM's own verifier, so the claim is only worth what this gate can show.

Why a driver instead of `javap -v` or a bytecode-only check: the verifier's rules
(StackMapTable agreement, type merges at join points, uninitialized-this, the
protected-range rules for exception handlers) are implemented *in the JVM*. Any
re-implementation here would be a second, weaker opinion that can disagree with
the only one that matters.

Two distinctions this module refuses to blur:

  INVALID     the verifier rejected the class (VerifyError / ClassFormatError).
              A rewrite did this; it must not ship.
  UNRESOLVED  a *dependency* was missing (NoClassDefFoundError). Not a verdict
              on our bytecode — the classpath was incomplete, so the gate says
              so instead of implying the class is fine.

A jar that verifies on input must verify after a rewrite. `verify_or_keep`
enforces that per class.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import engines as EN
from . import toolchain as TC

DRIVER_CLASS = "JdecVerifyDriver"

DRIVER_JAVA = r"""
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * Loads and *links* every class named in args[0].
 *
 * Linking is the point: verification happens during linking. Three approaches
 * were measured against a deliberately broken class (constructor ending in
 * ireturn), and only the last one works:
 *
 *   Class.forName(name, false, loader)  loads, does not link
 *   loader.resolveClass(c)              no-op on JDK 21 (native stub is gone)
 *   Class.forName(name, true, loader)   links and verifies, but RUNS <clinit>
 *   c.getDeclaredMethods()              links and verifies, no initialiser
 *
 * The last one is used: reflection cannot answer without the class being
 * linked, so it forces verification without executing any code from an
 * untrusted jar. (Getting this wrong is how a verifier reports PASS on every
 * input: the first version used forName and did exactly that.)
 */
public final class JdecVerifyDriver {
    private static final class Linker extends URLClassLoader {
        Linker(URL[] urls, ClassLoader parent) { super(urls, parent); }

        void load_and_link(String binary) throws Throwable {
            Class<?> c = loadClass(binary, false);
            // forces link_class() -> verification; <clinit> still does not run
            c.getDeclaredMethods();
            c.getDeclaredConstructors();
        }
    }

    public static void main(String[] args) throws Exception {
        List<String> names = Files.readAllLines(Paths.get(args[0]), StandardCharsets.UTF_8);
        // The classpath comes from -cp, so read it from the JVM instead of
        // re-passing it as argv: one source of truth, and a relative entry is
        // resolved against the same working directory the JVM used.
        String[] entries = System.getProperty("java.class.path").split(File.pathSeparator);
        URL[] urls = new URL[entries.length];
        for (int i = 0; i < entries.length; i++) {
            urls[i] = Paths.get(entries[i]).toUri().toURL();
        }
        PrintStream out = new PrintStream(new FileOutputStream(FileDescriptor.out), true, "UTF-8");
        // Platform parent, not the application loader: the application loader
        // already sees this same classpath, so parent-first delegation would
        // define every class outside our Linker and resolveClass() would then be
        // a no-op on somebody else's class (measured: a deliberately broken
        // class still reported PASS).
        ClassLoader parent = platformOrBootstrap();
        Linker loader = new Linker(urls, parent);
        for (String raw : names) {
            String name = raw.trim();
            if (name.isEmpty()) continue;
            String binary = name.replace('/', '.');
            try {
                loader.load_and_link(binary);
                out.println("OK\t" + name);
            } catch (Throwable t) {
                out.println(kind(t) + "\t" + name + "\t" + oneLine(t));
            }
        }
        out.flush();
    }

    /** The platform loader, or the bootstrap loader on JDK 8.
     *
     * `ClassLoader.getPlatformClassLoader()` is JDK 9+. The driver is compiled
     * with --release 8 so one build runs on every JDK in the matrix; calling
     * that method directly would make the whole 8 column impossible.
     */
    private static ClassLoader platformOrBootstrap() {
        try {
            java.lang.reflect.Method m =
                    ClassLoader.class.getMethod("getPlatformClassLoader");
            return (ClassLoader) m.invoke(null);
        } catch (Throwable t) {
            return null;   // JDK 8: the bootstrap loader is the right parent
        }
    }

    /** Classify by what was thrown for THIS class, not by its root cause.
     *
     * Walking the cause chain made the gate nondeterministic: a class whose
     * supertype failed verification throws NoClassDefFoundError with a
     * VerifyError cause, so it was reported INVALID in some load orders and
     * UNRESOLVED in others (measured: 3 vs 0 on the same jar). A class that is
     * itself broken throws VerifyError directly, so nothing is lost.
     */
    private static String kind(Throwable t) {
        String n = t.getClass().getName();
        if (n.equals("java.lang.UnsupportedClassVersionError")) {
            // the bytes were never looked at; saying "invalid" would be a lie
            // and would make an old JDK report a whole jar as broken
            return "SKIP";
        }
        if (n.equals("java.lang.VerifyError") || n.equals("java.lang.ClassFormatError")) {
            return "INVALID";
        }
        if (n.equals("java.lang.NoClassDefFoundError")
                || n.equals("java.lang.ClassNotFoundException")) {
            return "UNRESOLVED";
        }
        if (t instanceof LinkageError) return "INVALID";
        return "ERROR";
    }

    private static String oneLine(Throwable t) {
        String m = t.getClass().getName() + ": " + t.getMessage();
        return m.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ');
    }
}
"""

_CP_SEP = os.pathsep


@dataclass
class VerifyIssue:
    cls: str
    kind: str          # INVALID | UNRESOLVED | ERROR
    detail: str = ""

    def describe(self) -> str:
        return f"{self.cls}: {self.kind}: {self.detail}"


@dataclass
class VerifyReport:
    target: str = ""
    checked: int = 0
    verified: int = 0
    invalid: list[VerifyIssue] = field(default_factory=list)
    unresolved: list[VerifyIssue] = field(default_factory=list)
    skipped: list[VerifyIssue] = field(default_factory=list)
    errors: list[VerifyIssue] = field(default_factory=list)
    elapsed: float = 0.0
    driver_output: str = ""

    @property
    def ok(self) -> bool:
        """Every class in the target was judged, and nothing was rejected.

        Unresolved and skipped are not a pass: in both cases the verifier never
        looked at the class, and "not judged" must never read as "fine".
        """
        return (self.checked > 0 and not self.invalid and not self.errors
                and not self.unresolved and not self.skipped)

    @property
    def verdict(self) -> str:
        if self.invalid:
            return "FAIL"
        if self.unresolved:
            return "INCOMPLETE"
        if self.skipped:
            return "PARTIAL"
        if not self.checked:
            return "NOTHING CHECKED"
        return "PASS"

    def summary(self) -> str:
        lines = [
            f"target    : {self.target}",
            f"checked   : {self.checked} class(es)",
            f"verified  : {self.verified}",
        ]
        if self.invalid:
            lines.append(f"INVALID   : {len(self.invalid)} (verifier rejected)")
        if self.unresolved:
            lines.append(f"unresolved: {len(self.unresolved)} (dependency missing, "
                         f"not judged)")
        if self.skipped:
            lines.append(f"skipped   : {len(self.skipped)} (class file newer than "
                         f"this JVM, no verdict)")
        if self.errors:
            lines.append(f"errors    : {len(self.errors)}")
        lines.append(f"elapsed   : {self.elapsed:.2f}s")
        lines.append(f"result    : {self.verdict}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "checked": self.checked,
            "verified": self.verified,
            "invalid": [i.__dict__ for i in self.invalid],
            "unresolved": [i.__dict__ for i in self.unresolved],
            "skipped": [i.__dict__ for i in self.skipped],
            "errors": [i.__dict__ for i in self.errors],
            "elapsed_seconds": round(self.elapsed, 3),
            "verdict": self.verdict,
        }

    def write_json(self, path: Path) -> None:
        import json
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2),
                        encoding="utf-8")


def _driver_dir() -> Path:
    """Compile the driver once per process, keyed by its own source hash.

    Keying on the source matters: a cached .class from an older driver silently
    kept the bug where classes were loaded but never linked, and every run said
    PASS. Never cache a verifier by file name alone.
    """
    global _DRIVER_CACHE
    if _DRIVER_CACHE is not None and (_DRIVER_CACHE / f"{DRIVER_CLASS}.class").is_file():
        return _DRIVER_CACHE
    import hashlib
    key = hashlib.sha256(DRIVER_JAVA.encode("utf-8")).hexdigest()[:12]
    out = Path(tempfile.gettempdir()) / f"jdec_verify_driver_{key}"
    cls = out / f"{DRIVER_CLASS}.class"
    if not cls.is_file():
        out.mkdir(parents=True, exist_ok=True)
        src = out / f"{DRIVER_CLASS}.java"
        src.write_text(DRIVER_JAVA, encoding="utf-8")
        args = ["-encoding", "UTF-8", "-d", str(out), str(src)]
        r = TC.run_javac(["--release", "8"] + args,
                         purpose="building the verification driver")
        if r.returncode != 0:
            # javac 8 has no --release; the driver still has to build there
            r = TC.run_javac(args, purpose="building the verification driver")
        if r.returncode != 0:
            raise TC.ToolchainError(
                "cannot build the JVM verification driver: "
                + (r.stderr or r.stdout or "")[-800:])
    _DRIVER_CACHE = out
    return out


_DRIVER_CACHE: Path | None = None


def class_names(target: Path) -> list[str]:
    """Internal names (a/b/C) of every class in a jar or a class directory.

    Multi-release jars carry a second copy of some classes under
    `META-INF/versions/N/`. Those are *the same* classes (the JVM picks one at
    load time); enumerating them produced `NoClassDefFoundError: ... (wrong
    name: ...)` for every one of them, which then read as "dependency missing".
    Measured on HMCL: 47 of the 1043 unresolved classes were this artefact.
    """
    p = Path(target)
    if p.is_dir():
        return sorted(f.relative_to(p).as_posix()[:-len(".class")]
                      for f in p.rglob("*.class"))
    with zipfile.ZipFile(p) as z:
        return [i.filename[:-len(".class")] for i in z.infolist()
                if i.filename.endswith(".class")
                and not i.filename.endswith("module-info.class")
                and not i.filename.startswith("META-INF/")]


_JVM_MAJOR: dict[tuple[str, float], int] = {}


def jvm_major(exe: str) -> int:
    """Highest class-file major version this JVM will load (52 = Java 8, 65 = 21).

    Returns 0 when it cannot be determined, in which case nothing is skipped —
    an unknown JVM is treated as "judge everything and let it fail", which is
    the old behaviour.
    """
    try:
        st = os.stat(exe)
        key = (str(exe), st.st_mtime)
    except OSError:
        key = (str(exe), 0.0)
    if key in _JVM_MAJOR:
        return _JVM_MAJOR[key]
    major = 0
    try:
        r = subprocess.run([exe, "-XshowSettings:properties", "-version"],
                           capture_output=True, text=True, errors="replace",
                           timeout=30)
        for line in (r.stderr or "").splitlines():
            if "java.class.version" in line and "=" in line:
                major = int(float(line.split("=", 1)[1].strip()))
                break
    except Exception:  # noqa: BLE001 - an unprobeable JVM is not fatal
        major = 0
    _JVM_MAJOR[key] = major
    return major


def class_majors(target: Path) -> dict[str, int]:
    """internal name -> class-file major version. Reads 8 bytes per class."""
    out: dict[str, int] = {}
    p = Path(target)
    if p.is_dir():
        for f in p.rglob("*.class"):
            try:
                head = f.read_bytes()[:8]
            except OSError:
                continue
            if len(head) >= 8 and head[:4] == b"\xca\xfe\xba\xbe":
                out[f.relative_to(p).as_posix()[:-len(".class")]] = int.from_bytes(
                    head[6:8], "big")
        return out
    with zipfile.ZipFile(p) as z:
        for info in z.infolist():
            name = info.filename
            if not name.endswith(".class") or name.endswith("module-info.class"):
                continue
            if name.startswith("META-INF/"):
                continue      # multi-release copy of a class already counted
            try:
                with z.open(info) as fh:
                    head = fh.read(8)
            except Exception:  # noqa: BLE001 - unreadable entry, no version
                continue
            if len(head) >= 8 and head[:4] == b"\xca\xfe\xba\xbe":
                out[name[:-len(".class")]] = int.from_bytes(head[6:8], "big")
    return out


def _join_cp(entries: list[str]) -> str:
    return _CP_SEP.join(TC.norm_classpath(str(e)) for e in entries)


def verify(target: Path, *, classpath=(), timeout: int = 900,
           limit: int = 0, java: str | None = None) -> VerifyReport:
    """Load every class in `target` under -Xverify:all and report the verdict.

    `classpath` must contain whatever the target's classes reference (for a
    rewritten jar that is normally the original jar), otherwise the verifier
    cannot resolve supertypes and every class comes back UNRESOLVED.
    """
    rep = VerifyReport(target=str(target))
    t0 = time.time()
    names = class_names(target)
    if limit:
        names = names[:limit]
    if not names:
        rep.elapsed = time.time() - t0
        return rep
    rep.checked = len(names)

    drv = _driver_dir()
    exe = java or EN.find_java()
    if not exe:
        raise TC.ToolchainError(
            "java not found: set JAVA_HOME to a JDK or put java on PATH "
            "[running the verification driver]")

    # A class file newer than the JVM is not invalid — it was never read. Ask
    # the JVM what it accepts and hand it only the classes it can load.
    ceiling = jvm_major(exe)
    if ceiling:
        majors = class_majors(target)
        too_new = [n for n in names if majors.get(n, 0) > ceiling]
        if too_new:
            rep.skipped = [VerifyIssue(n, "SKIP",
                                       f"class v{majors[n]} > jvm v{ceiling}")
                           for n in too_new]
            skip = set(too_new)
            names = [n for n in names if n not in skip]
    if not names:
        rep.elapsed = time.time() - t0
        return rep

    with tempfile.TemporaryDirectory(prefix="jdec_verify_") as td:
        names_file = Path(td) / "classes.txt"
        names_file.write_text("\n".join(names), encoding="utf-8")
        cp = _join_cp([str(drv), str(Path(target).resolve())]
                      + [str(Path(c).resolve()) for c in classpath])
        cmd = [exe, "-Xverify:all", "-Xshare:off", "-XX:+UseSerialGC",
               "-cp", cp, DRIVER_CLASS, str(names_file)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  errors="replace", timeout=timeout)
        except subprocess.TimeoutExpired:
            raise TC.ToolchainError(
                f"the verification driver timed out after {timeout}s "
                f"on {rep.checked} class(es)") from None
        rep.driver_output = (proc.stderr or "")[-4000:]

    for line in (proc.stdout or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        kind, name = parts[0], parts[1]
        detail = parts[2] if len(parts) > 2 else ""
        if kind == "OK":
            rep.verified += 1
        elif kind == "INVALID":
            rep.invalid.append(VerifyIssue(name, kind, detail))
        elif kind == "UNRESOLVED":
            rep.unresolved.append(VerifyIssue(name, kind, detail))
        elif kind == "SKIP":
            rep.skipped.append(VerifyIssue(name, kind, detail))
        else:
            rep.errors.append(VerifyIssue(name, kind, detail))

    rep.elapsed = time.time() - t0
    return rep


def verify_jar_pair(original: Path, rewritten: Path,
                    **kw) -> VerifyReport:
    """Verify a rewritten jar with the original on the classpath."""
    return verify(rewritten, classpath=[original], **kw)


def offending_classes(rep: VerifyReport) -> list[str]:
    return [i.cls for i in rep.invalid]


@dataclass
class KeepResult:
    """Outcome of "verify, then put back whatever the verifier rejected"."""

    verified: int = 0
    reverted: list[str] = field(default_factory=list)
    unresolved: int = 0
    unjudged_rewritten: int = 0      # rewritten methods in an unresolved class
    input_invalid: int = 0
    still_invalid: list[str] = field(default_factory=list)
    skipped: str | None = None

    @property
    def ok(self) -> bool:
        return not self.still_invalid and self.skipped is None

    def summary(self) -> str:
        if self.skipped:
            return f"verification skipped: {self.skipped}"
        parts = [f"{self.verified} verified"]
        if self.reverted:
            parts.append(f"{len(self.reverted)} reverted to the original")
        if self.still_invalid:
            parts.append(f"{len(self.still_invalid)} still invalid")
        if self.unresolved:
            extra = (f", {self.unjudged_rewritten} of them rewritten"
                     if self.unjudged_rewritten else "")
            parts.append(f"{self.unresolved} not judged (missing deps{extra})")
        return ", ".join(parts)

    def to_dict(self) -> dict:
        out = {
            "verified": self.verified,
            "reverted": list(self.reverted),
            "unresolved": self.unresolved,
            "unjudged_rewritten": self.unjudged_rewritten,
            "input_invalid": self.input_invalid,
            "still_invalid": list(self.still_invalid),
        }
        # a `"skipped": None` key reads as "verify was skipped" to anyone doing
        # `"skipped" in report`, and that is a different statement from "it ran"
        if self.skipped:
            out["skipped"] = self.skipped
        return out


def unjudged_rewritten(rep: VerifyReport, rows) -> list[str]:
    """Rewritten methods living in a class the verifier never judged.

    This is the number that matters. "0 rejected" over a jar where a quarter of
    the classes were never looked at is a much weaker claim than the same
    sentence over a fully judged jar, and the difference is exactly these
    methods.
    """
    bad = ({i.cls for i in rep.invalid} | {i.cls for i in rep.unresolved}
           | {i.cls for i in rep.skipped})
    return [f"{cls}.{name}{desc}" for cls, name, desc in rows if cls in bad]


def verify_or_keep(original: Path, rewritten: Path, *,
                   java: str | None = None,
                   timeout: int = 900,
                   classpath=(),
                   rows=None) -> KeepResult:
    """Guarantee that a rewritten jar is never worse than its input.

    Every class the verifier rejects *because of the rewrite* is replaced with
    the original bytes in place. A class that was already invalid in the input
    is left alone — reverting it would change nothing, and claiming a fix we did
    not make is worse than reporting it.

    The jar is rewritten in place (`rewritten`), so callers keep pointing at the
    same path their pipeline already uses.
    """
    res = KeepResult()
    extra = [Path(c) for c in classpath]
    rep_in = verify(original, classpath=extra, java=java, timeout=timeout)
    rep_out = verify(rewritten, classpath=[original] + extra,
                     java=java, timeout=timeout)
    bad_in = {i.cls for i in rep_in.invalid}
    res.input_invalid = len(bad_in)
    res.unresolved = len(rep_out.unresolved)
    if rows:
        # "0 rejected" over a jar where some classes were never looked at is a
        # conditional claim. Count the rewritten methods that fall in that hole
        # so the caller can say so instead of implying a clean sweep.
        res.unjudged_rewritten = len(unjudged_rewritten(rep_out, rows))

    to_revert = [i.cls for i in rep_out.invalid if i.cls not in bad_in]
    if not to_revert:
        res.verified = rep_out.verified
        res.still_invalid = sorted(bad_in & {i.cls for i in rep_out.invalid})
        return res

    keep = set(to_revert)
    tmp = rewritten.with_name(rewritten.name + ".keep")
    with zipfile.ZipFile(original) as zo, \
            zipfile.ZipFile(rewritten) as zr, \
            zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zw:
        original_names = set(zo.namelist())
        for info in zr.infolist():
            name = info.filename
            cls = name[:-len(".class")] if name.endswith(".class") else None
            if cls in keep and name in original_names:
                zw.writestr(name, zo.read(name))
            else:
                zw.writestr(info, zr.read(name))
    tmp.replace(rewritten)

    res.reverted = to_revert
    after = verify(rewritten, classpath=[original] + extra,
                   java=java, timeout=timeout)
    res.verified = after.verified
    res.still_invalid = sorted(i.cls for i in after.invalid)
    res.unresolved = len(after.unresolved)
    return res
