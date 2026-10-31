"""Differential behaviour check: same inputs, two jars, same answers.

The JVM gate (`verify`) proves a rewritten class *loads*. It says nothing about
whether it still computes the same thing — a rewrite can be perfectly legal
bytecode and still return a different string. This module is the other half of
"behaviour-preserving": run the same method over the same arguments in the
original and the rewritten jar, in separate class loaders, and compare the
result (or the exception thrown).

Scope, stated honestly:

  * it compares a **declared list of cases** — it is a regression harness, not a
    proof. Nobody can prove equivalence of arbitrary bytecode here.
  * methods are invoked reflectively with int / long / boolean / String
    arguments; arrays and objects beyond String are out of scope.
  * `Class.forName(..., true, ...)` initialises the class, so `<clinit>` side
    effects (string decryptors, for instance) are exercised. That means this
    module **executes code from the target jar**; the CLI refuses to run without
    an explicit `--execute`, on the same reasoning as `recover`.

The value is in the cases you write: `OldStyle.pick("hello")` is exactly the
shape of thing a de-flattener can silently break.
"""

from __future__ import annotations

import hashlib
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import engines as EN
from . import toolchain as TC

DRIVER_CLASS = "JdecBehaveDriver"

DRIVER_JAVA = r"""
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * Runs one declared case against two jars and prints SAME / DIFF.
 *
 * Each jar gets its own loader so the two copies of a class never shadow each
 * other, and `Class.forName(..., true, ...)` is used on purpose: the static
 * initialiser is part of the behaviour we are comparing.
 */
public final class JdecBehaveDriver {
    public static void main(String[] args) throws Exception {
        List<String> lines = Files.readAllLines(Paths.get(args[0]), StandardCharsets.UTF_8);
        ClassLoader parent = ClassLoader.getPlatformClassLoader();
        URLClassLoader left = new URLClassLoader(new URL[]{Paths.get(args[1]).toUri().toURL()}, parent);
        URLClassLoader right = new URLClassLoader(new URL[]{Paths.get(args[2]).toUri().toURL()}, parent);
        PrintStream out = new PrintStream(new FileOutputStream(FileDescriptor.out), true, "UTF-8");
        for (String line : lines) {
            if (line.trim().isEmpty() || line.startsWith("#")) continue;
            String[] p = line.split("\\|", -1);
            String cls = p[0].trim().replace('/', '.');
            String m = p[1].trim();
            String types = p.length > 2 ? p[2].trim() : "";
            String vals = p.length > 3 ? p[3] : "";
            String a = run(left, cls, m, types, vals);
            String b = run(right, cls, m, types, vals);
            out.println((a.equals(b) ? "SAME" : "DIFF") + "\t" + cls + "." + m
                    + "\t" + a + "\t" + b);
        }
        out.flush();
    }

    private static String run(ClassLoader loader, String cls, String method,
                              String types, String vals) {
        try {
            Class<?> c = Class.forName(cls, true, loader);
            Class<?>[] pt = paramTypes(loader, types);
            Object[] av = argValues(loader, pt, vals);
            Method mm = c.getDeclaredMethod(method, pt);
            Object target = null;
            if (!Modifier.isStatic(mm.getModifiers())) {
                target = c.getDeclaredConstructor().newInstance();
            }
            mm.setAccessible(true);
            return "OK:" + render(mm.invoke(target, av));
        } catch (InvocationTargetException e) {
            Throwable t = e.getCause() == null ? e : e.getCause();
            return "THROW:" + t.getClass().getName() + ":" + oneLine(t.getMessage());
        } catch (Throwable t) {
            return "ERROR:" + t.getClass().getName() + ":" + oneLine(t.getMessage());
        }
    }

    private static Class<?>[] paramTypes(ClassLoader l, String types) throws Exception {
        if (types.isEmpty()) return new Class<?>[0];
        String[] parts = types.split(",");
        Class<?>[] out = new Class<?>[parts.length];
        for (int i = 0; i < parts.length; i++) {
            String t = parts[i].trim();
            switch (t) {
                case "int": out[i] = int.class; break;
                case "long": out[i] = long.class; break;
                case "boolean": out[i] = boolean.class; break;
                case "double": out[i] = double.class; break;
                case "float": out[i] = float.class; break;
                case "short": out[i] = short.class; break;
                case "byte": out[i] = byte.class; break;
                case "char": out[i] = char.class; break;
                default: out[i] = Class.forName(t, false, l);
            }
        }
        return out;
    }

    private static Object[] argValues(ClassLoader l, Class<?>[] pt, String vals) {
        if (pt.length == 0) return new Object[0];
        String[] parts = vals.isEmpty() ? new String[0] : vals.split(",", -1);
        Object[] out = new Object[pt.length];
        for (int i = 0; i < pt.length; i++) {
            String v = i < parts.length ? parts[i] : "";
            Class<?> t = pt[i];
            if (t == String.class) out[i] = v;
            else if (t == int.class) out[i] = Integer.parseInt(v.trim());
            else if (t == long.class) out[i] = Long.parseLong(v.trim());
            else if (t == boolean.class) out[i] = Boolean.parseBoolean(v.trim());
            else if (t == double.class) out[i] = Double.parseDouble(v.trim());
            else if (t == float.class) out[i] = Float.parseFloat(v.trim());
            else if (t == short.class) out[i] = Short.parseShort(v.trim());
            else if (t == byte.class) out[i] = Byte.parseByte(v.trim());
            else if (t == char.class) out[i] = v.isEmpty() ? '\0' : v.charAt(0);
            else out[i] = null;
        }
        return out;
    }

    private static String render(Object o) {
        if (o == null) return "null";
        if (o instanceof String) return "s:" + o;
        return o.getClass().getSimpleName() + ":" + o;
    }

    private static String oneLine(String s) {
        if (s == null) return "";
        return s.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ');
    }
}
"""


@dataclass
class Case:
    cls: str
    method: str
    arg_types: tuple[str, ...] = ()
    arg_values: tuple[str, ...] = ()

    def line(self) -> str:
        return f"{self.cls}|{self.method}|{','.join(self.arg_types)}|{','.join(self.arg_values)}"

    def describe(self) -> str:
        args = ", ".join(f"{t}={v}" for t, v in zip(self.arg_types, self.arg_values))
        return f"{self.cls}.{self.method}({args})"


@dataclass
class CaseOutcome:
    case: Case
    left: str
    right: str

    @property
    def same(self) -> bool:
        return self.left == self.right

    def describe(self) -> str:
        return f"{self.case.describe()}: {self.left} != {self.right}"


@dataclass
class BehaveReport:
    original: str = ""
    rewritten: str = ""
    outcomes: list[CaseOutcome] = field(default_factory=list)
    elapsed: float = 0.0
    driver_output: str = ""

    @property
    def compared(self) -> int:
        return len(self.outcomes)

    @property
    def diffs(self) -> list[CaseOutcome]:
        return [o for o in self.outcomes if not o.same]

    @property
    def ok(self) -> bool:
        return bool(self.outcomes) and not self.diffs

    def summary(self) -> str:
        lines = [
            f"original  : {self.original}",
            f"rewritten : {self.rewritten}",
            f"cases     : {self.compared}",
            f"identical : {self.compared - len(self.diffs)}",
            f"elapsed   : {self.elapsed:.2f}s",
            f"result    : {'PASS' if self.ok else 'FAIL'}",
        ]
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "original": self.original,
            "rewritten": self.rewritten,
            "compared": self.compared,
            "diffs": [{"case": o.case.describe(), "left": o.left, "right": o.right}
                      for o in self.diffs],
            "elapsed_seconds": round(self.elapsed, 3),
            "ok": self.ok,
        }

    def write_json(self, path: Path) -> None:
        import json
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2),
                        encoding="utf-8")


def parse_spec(text: str) -> list[Case]:
    """Parse `class|method|argTypes|argValues` lines. `#` starts a comment."""
    out: list[Case] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 2:
            raise ValueError(f"bad case line: {raw!r} (want class|method|types|values)")
        cls, method = parts[0], parts[1]
        types = tuple(t for t in (parts[2].split(",") if len(parts) > 2 and parts[2] else []))
        # a trailing "|" is one empty argument, not "no arguments": pick("")
        # and pick() are different cases and must stay different
        values = tuple(parts[3].split(",")) if len(parts) > 3 else ()
        out.append(Case(cls, method, types, values))
    return out


def _driver_dir() -> Path:
    global _DRIVER_CACHE
    if _DRIVER_CACHE is not None and (_DRIVER_CACHE / f"{DRIVER_CLASS}.class").is_file():
        return _DRIVER_CACHE
    key = hashlib.sha256(DRIVER_JAVA.encode("utf-8")).hexdigest()[:12]
    out = Path(tempfile.gettempdir()) / f"jdec_behave_driver_{key}"
    if not (out / f"{DRIVER_CLASS}.class").is_file():
        out.mkdir(parents=True, exist_ok=True)
        src = out / f"{DRIVER_CLASS}.java"
        src.write_text(DRIVER_JAVA, encoding="utf-8")
        r = TC.run_javac(["-encoding", "UTF-8", "-d", str(out), str(src)],
                         purpose="building the behaviour driver")
        if r.returncode != 0:
            raise TC.ToolchainError(
                "cannot build the behaviour driver: "
                + (r.stderr or r.stdout or "")[-800:])
    _DRIVER_CACHE = out
    return out


_DRIVER_CACHE: Path | None = None


def compare(original: Path, rewritten: Path, cases: list[Case],
            *, java: str | None = None, timeout: int = 300) -> BehaveReport:
    """Run every case against both jars and compare. Executes target code."""
    rep = BehaveReport(original=str(original), rewritten=str(rewritten))
    if not cases:
        return rep
    t0 = time.time()
    drv = _driver_dir()
    exe = java or EN.find_java()
    if not exe:
        raise TC.ToolchainError(
            "java not found: set JAVA_HOME to a JDK or put java on PATH "
            "[running the behaviour driver]")

    with tempfile.TemporaryDirectory(prefix="jdec_behave_") as td:
        spec = Path(td) / "cases.txt"
        spec.write_text("\n".join(c.line() for c in cases), encoding="utf-8")
        cp = TC.path_sep().join(str(x) for x in (drv,))
        cmd = [exe, "-cp", cp, DRIVER_CLASS, str(spec),
               str(Path(original).resolve()), str(Path(rewritten).resolve())]
        import subprocess
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  errors="replace", timeout=timeout)
        except subprocess.TimeoutExpired:
            raise TC.ToolchainError(
                f"the behaviour driver timed out after {timeout}s") from None
        rep.driver_output = (proc.stderr or "")[-4000:]

    # The driver prints exactly one line per case, in spec order; match by
    # position rather than by name, because two cases can share class+method
    # and differ only in arguments.
    lines = [ln for ln in (proc.stdout or "").splitlines() if ln.count("\t") >= 3]
    for case, line in zip(cases, lines):
        parts = line.split("\t")
        rep.outcomes.append(CaseOutcome(case, parts[2], parts[3]))
    rep.elapsed = time.time() - t0
    return rep
