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
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
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
 * Runs one declared case against two jars and prints JUDGED / UNUSABLE.
 *
 * Each jar gets its own loader so the two copies of a class never shadow each
 * other, and `Class.forName(..., true, ...)` is used on purpose: the static
 * initialiser is part of the behaviour we are comparing. Extra classpath
 * entries (argv[3:]) go into *both* loaders, otherwise a class whose supertypes
 * live in a separate library cannot even be loaded and the case is unusable.
 *
 * Making a receiver used to require a no-arg constructor, which excluded 193 of
 * HMCL's 411 rewritten methods. The order is now: real constructor, enum
 * constant, zero-state instance via Unsafe. A zero-state instance is not
 * pretty, but it is deterministic and identical on both sides, which is what a
 * differential run needs.
 */
public final class JdecBehaveDriver {

    /** A target method can block forever (a lock, a socket, a toolkit thread).
     *  Without a per-case cap one such method kills the whole run and every
     *  other case loses its verdict, so each invocation gets its own thread and
     *  a deadline. */
    private static final long CASE_TIMEOUT_MS = 3000L;

    private static Object unsafe;
    private static Method allocate;
    private static final java.util.Map<ClassLoader, java.util.Map<String, Class<?>>> CLASSES =
            new java.util.WeakHashMap<ClassLoader, java.util.Map<String, Class<?>>>();

    public static void main(String[] args) throws Exception {
        List<String> lines = Files.readAllLines(Paths.get(args[0]), StandardCharsets.UTF_8);
        ClassLoader parent = platformLoader();
        URLClassLoader left = new URLClassLoader(urls(args[1], args), parent);
        URLClassLoader right = new URLClassLoader(urls(args[2], args), parent);
        PrintStream out = new PrintStream(new FileOutputStream(FileDescriptor.out), true, "UTF-8");
        int index = 0;
        for (String line : lines) {
            if (line.trim().isEmpty() || line.startsWith("#")) continue;
            index++;
            String[] p = line.split("\\|", -1);
            String cls = p[0].trim().replace('/', '.');
            String m = p[1].trim();
            String types = p.length > 2 ? p[2].trim() : "";
            String vals = p.length > 3 ? p[3] : "";
            String a = callWithTimeout(left, cls, m, types, vals);
            String b = callWithTimeout(right, cls, m, types, vals);
            // A case the harness cannot even invoke is not evidence of anything.
            // Reporting it as SAME (the old behaviour, because both sides said
            // ERROR: with the same text) silently turned "not tested" into
            // "identical" — so usability is decided here, comparison in Python.
            String verdict = (judged(a) && judged(b)) ? "JUDGED" : "UNUSABLE";
            out.println(verdict + "\t" + index + "\t" + cls + "." + m
                    + "\t" + a + "\t" + b);
        }
        out.flush();
        // a case that timed out may have left a non-daemon thread behind
        Runtime.getRuntime().halt(0);
    }

    private static String callWithTimeout(final ClassLoader loader, final String cls,
                                          final String m, final String types,
                                          final String vals) {
        final String[] box = new String[1];
        Thread t = new Thread(new Runnable() {
            public void run() {
                box[0] = JdecBehaveDriver.run(loader, cls, m, types, vals);
            }
        });
        t.setDaemon(true);
        t.start();
        try {
            t.join(CASE_TIMEOUT_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (box[0] == null) {
            return "ERROR:Timeout:no result in " + CASE_TIMEOUT_MS + "ms";
        }
        return box[0];
    }

    /** `Class.forName(..., true, ...)` runs the static initialiser, which is
     *  part of the behaviour — but once per class, not once per case. */
    private static Class<?> load(ClassLoader loader, String name) throws Exception {
        java.util.Map<String, Class<?>> m;
        synchronized (CLASSES) {
            m = CLASSES.get(loader);
            if (m == null) {
                m = new java.util.HashMap<String, Class<?>>();
                CLASSES.put(loader, m);
            }
        }
        Class<?> c = m.get(name);
        if (c == null) {
            c = Class.forName(name, true, loader);
            m.put(name, c);
        }
        return c;
    }

    private static URL[] urls(String jar, String[] args) throws Exception {
        java.util.List<URL> out = new java.util.ArrayList<URL>();
        out.add(Paths.get(jar).toUri().toURL());
        for (int i = 3; i < args.length; i++) {
            out.add(Paths.get(args[i]).toUri().toURL());
        }
        return out.toArray(new URL[out.size()]);
    }

    /** JDK 9+ has a platform loader; on 8 its parent (the extension loader) is
     *  the closest thing, and the driver has to build on both. */
    private static ClassLoader platformLoader() {
        try {
            Method m = ClassLoader.class.getMethod("getPlatformClassLoader");
            return (ClassLoader) m.invoke(null);
        } catch (Throwable t) {
            ClassLoader s = ClassLoader.getSystemClassLoader();
            return s == null ? null : s.getParent();
        }
    }

    private static String run(ClassLoader loader, String cls, String method,
                              String types, String vals) {
        try {
            Class<?> c = load(loader, cls);
            Class<?>[] pt = paramTypes(loader, types);
            Object[] av = argValues(loader, pt, vals);
            Method mm = c.getDeclaredMethod(method, pt);
            Object target = null;
            if (!Modifier.isStatic(mm.getModifiers())) target = newInstance(c);
            mm.setAccessible(true);
            return "OK:" + render(mm.invoke(target, av));
        } catch (InvocationTargetException e) {
            Throwable t = e.getCause() == null ? e : e.getCause();
            return "THROW:" + t.getClass().getName() + ":" + maskIds(oneLine(t.getMessage()));
        } catch (Throwable t) {
            return "ERROR:" + t.getClass().getName() + ":" + maskIds(oneLine(t.getMessage()));
        }
    }

    // ---------------------------------------------------------------- receiver

    private static Object newInstance(Class<?> c) {
        // 1. the class's own no-arg constructor: real state, real invariants
        try {
            Constructor<?> k = c.getDeclaredConstructor();
            k.setAccessible(true);
            return k.newInstance();
        } catch (NoSuchMethodException e) {
            // no no-arg constructor: fall through
        } catch (Throwable t) {
            // the constructor ran and threw; a zero-state instance is still a
            // usable receiver, and both jars get exactly the same treatment
        }
        // 2. an enum value: the only instances the class actually has
        try {
            if (c.isEnum()) {
                Object[] cs = c.getEnumConstants();
                if (cs != null && cs.length > 0) return cs[0];
            }
        } catch (Throwable t) {
            // ignore
        }
        // 3. a platform implementation for a JDK interface (List, Map, ...)
        Object impl = platformImpl(c);
        if (impl != null) return impl;
        // 4. a constructor with arguments we can synthesise: real state, and
        //    the library's own invariants hold
        Object built = construct(c, 0);
        if (built != null) return built;
        // 5. zero-state instance: fields are the JVM defaults, no constructor
        return allocateInstance(c);
    }

    /** Pick the shortest constructor whose parameters can all be synthesised. */
    private static Object construct(Class<?> c, int depth) {
        if (depth > 1) return null;
        Constructor<?>[] ks;
        try {
            ks = c.getDeclaredConstructors();
        } catch (Throwable t) {
            return null;
        }
        java.util.Arrays.sort(ks, new java.util.Comparator<Constructor<?>>() {
            public int compare(Constructor<?> a, Constructor<?> b) {
                return a.getParameterTypes().length - b.getParameterTypes().length;
            }
        });
        for (int i = 0; i < ks.length && i < 4; i++) {
            Constructor<?> k = ks[i];
            Class<?>[] pt = k.getParameterTypes();
            if (pt.length == 0 || pt.length > 3) continue;
            Object[] args = new Object[pt.length];
            boolean ok = true;
            for (int j = 0; j < pt.length; j++) {
                args[j] = sample(pt[j], depth + 1);
                if (args[j] == null && pt[j].isPrimitive()) { ok = false; break; }
            }
            if (!ok) continue;
            try {
                k.setAccessible(true);
                return k.newInstance(args);
            } catch (Throwable t) {
                // this constructor does not like the sample values; try the next
            }
        }
        return null;
    }

    /** A deterministic, cheap value of the requested type. */
    private static Object sample(Class<?> t, int depth) {
        if (t == String.class) return "";
        if (t == int.class || t == Integer.class) return Integer.valueOf(0);
        if (t == long.class || t == Long.class) return Long.valueOf(0L);
        if (t == boolean.class || t == Boolean.class) return Boolean.FALSE;
        if (t == double.class || t == Double.class) return Double.valueOf(0.0);
        if (t == float.class || t == Float.class) return Float.valueOf(0.0f);
        if (t == short.class || t == Short.class) return Short.valueOf((short) 0);
        if (t == byte.class || t == Byte.class) return Byte.valueOf((byte) 0);
        if (t == char.class || t == Character.class) return Character.valueOf((char) 0);
        if (t.isArray()) return Array.newInstance(t.getComponentType(), 0);
        if (t.isEnum()) {
            Object[] cs = t.getEnumConstants();
            return cs == null || cs.length == 0 ? null : cs[0];
        }
        Object impl = platformImpl(t);
        if (impl != null) return impl;
        if (depth > 1) return null;
        try {
            Constructor<?> k = t.getDeclaredConstructor();
            k.setAccessible(true);
            return k.newInstance();
        } catch (Throwable e) {
            return null;
        }
    }

    private static Object platformImpl(Class<?> c) {
        Object[] cands = new Object[]{
            new java.util.ArrayList<Object>(),
            new java.util.LinkedHashSet<Object>(),
            new java.util.LinkedHashMap<Object, Object>(),
            new java.util.TreeMap<Object, Object>(),
            "",
            Boolean.FALSE,
            Integer.valueOf(0),
            new java.util.concurrent.atomic.AtomicInteger(0),
            new java.util.concurrent.atomic.AtomicLong(0),
        };
        for (int i = 0; i < cands.length; i++) {
            if (c.isInstance(cands[i])) return cands[i];
        }
        return null;
    }

    private static Object allocateInstance(Class<?> c) {
        try {
            if (allocate == null) {
                Class<?> uc = Class.forName("sun.misc.Unsafe");
                Field f = uc.getDeclaredField("theUnsafe");
                f.setAccessible(true);
                unsafe = f.get(null);
                allocate = uc.getMethod("allocateInstance", Class.class);
            }
            return allocate.invoke(unsafe, c);
        } catch (Throwable t) {
            return null;
        }
    }

    // ------------------------------------------------------------- parameters

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
            out[i] = value(pt[i], v);
        }
        return out;
    }

    /** A plain token is a literal for a primitive/String parameter; `@...` is a
     *  control token that lets a reference parameter get something better than
     *  null, and `@@x` is the literal string "@x". */
    private static Object value(Class<?> t, String raw) {
        String v = raw.trim();
        if (v.startsWith("@@")) v = v.substring(1);
        else if (v.startsWith("@")) return control(t, v.substring(1));
        if (t == String.class) return raw;
        if (t == int.class) return Integer.valueOf(v);
        if (t == long.class) return Long.valueOf(v);
        if (t == boolean.class) return Boolean.valueOf(v);
        if (t == double.class) return Double.valueOf(v);
        if (t == float.class) return Float.valueOf(v);
        if (t == short.class) return Short.valueOf(v);
        if (t == byte.class) return Byte.valueOf(v);
        if (t == char.class) return Character.valueOf(v.isEmpty() ? '\0' : v.charAt(0));
        return null;
    }

    private static Object control(Class<?> t, String body) {
        if (body.equals("null")) return null;
        if (body.equals("new")) return t.isPrimitive() ? null : newInstance(t);
        if (body.equals("arr0") || body.equals("arr1")) {
            if (!t.isArray()) return null;
            return Array.newInstance(t.getComponentType(), body.equals("arr1") ? 1 : 0);
        }
        if (body.startsWith("s:")) {
            String s = body.substring(2);
            return t.isAssignableFrom(String.class) ? (Object) s : null;
        }
        if (body.startsWith("i:")) return box(Integer.valueOf(body.substring(2)), t);
        if (body.startsWith("l:")) return box(Long.valueOf(body.substring(2)), t);
        if (body.startsWith("z:")) return box(Boolean.valueOf(body.substring(2)), t);
        if (body.startsWith("d:")) return box(Double.valueOf(body.substring(2)), t);
        if (body.startsWith("f:")) return box(Float.valueOf(body.substring(2)), t);
        if (body.startsWith("c:")) return box(Character.valueOf(body.substring(2).charAt(0)), t);
        if (body.startsWith("b:")) return box(Byte.valueOf(body.substring(2)), t);
        if (body.startsWith("h:")) return box(Short.valueOf(body.substring(2)), t);
        return null;
    }

    private static Object box(Object v, Class<?> t) {
        return t.isInstance(v) ? v : null;
    }

    // ---------------------------------------------------------------- results

    /** Did this run actually observe the method? */
    private static boolean judged(String s) {
        return s.startsWith("OK:") || s.startsWith("THROW:");
    }

    private static boolean overridesToString(Class<?> c) {
        try {
            return c.getMethod("toString").getDeclaringClass() != Object.class;
        } catch (Throwable t) {
            return false;
        }
    }

    /** Render deterministically. An object that does not override toString is
     *  reported by its class name: `Object@1a2b3c` differs between two runs for
     *  reasons that have nothing to do with the rewrite. */
    private static String render(Object o) {
        if (o == null) return "null";
        if (o instanceof String) return "s:" + oneLine((String) o);
        if (o instanceof Character) return "c:" + o;
        if (o instanceof Number || o instanceof Boolean) {
            return o.getClass().getSimpleName() + ":" + o;
        }
        Class<?> c = o.getClass();
        if (c.isArray()) return "arr" + arrayText(o);
        if (!overridesToString(c)) return "ref:" + c.getName();
        String text = String.valueOf(o);
        // `Object.toString` inside a container (`[Foo@1a2b, ...]`) is an
        // identity hash: the two sides live in different loaders, so it can
        // never match and the case would read as a difference that is not one.
        return c.getSimpleName() + ":" + oneLine(maskIds(text));
    }

    private static String arrayText(Object a) {
        int n = Array.getLength(a);
        StringBuilder b = new StringBuilder("[");
        for (int i = 0; i < n && i < 8; i++) {
            if (i > 0) b.append(',');
            Object v = Array.get(a, i);
            b.append(v instanceof String ? oneLine((String) v) : String.valueOf(v));
        }
        if (n > 8) b.append(",...");
        return b.append(']').toString();
    }

    /** One line, no tabs: the whole protocol is tab-separated, and a method
     *  returning "a\tb" used to shift every following field by one. */
    private static String oneLine(String s) {
        if (s == null) return "";
        return s.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ');
    }

    /** Identity hashes are not behaviour: the two sides run in different
     *  loaders, so `java.lang.Object@5e2de80c` can never match. Masking them is
     *  what keeps a container of plain objects (`[Foo@1a2b, Foo@3c4d]`) from
     *  reading as a difference. A method whose *only* output is an identity
     *  hash still gets dropped by the stability baseline, because the two runs
     *  of the original disagree before masking is even applied. */
    private static String maskIds(String s) {
        if (s == null) return "";
        return s.replaceAll("@[0-9a-fA-F]{4,}", "@<id>");
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
    """One declared case, on both jars.

    `status` is the only thing that decides anything:

      same      both sides observed the method and agree
      diff      both sides observed it and disagree
      unusable  at least one side could not even be invoked (bad type, missing
                class, timeout). This is *not* evidence, and it is deliberately
                not reported as `diff` either: "we could not test it" and "the
                rewrite changed it" are different claims.
    """

    case: Case
    left: str
    right: str
    status: str = "unusable"
    reason: str = ""

    @property
    def same(self) -> bool:
        return self.status == "same"

    @property
    def judged(self) -> bool:
        return self.status in ("same", "diff")

    @property
    def evidence(self) -> str:
        """What kind of observation this was: a returned value or a throw.

        Both are differential evidence — the same input produced the same
        observable outcome on both jars — but they are not equally strong, so
        the report keeps them apart instead of merging them into one number.
        """
        if not self.judged:
            return "none"
        return "throw" if self.left.startswith("THROW:") else "value"

    def describe(self) -> str:
        if self.status == "unusable":
            why = self.reason or f"{self.left} / {self.right}"
            return f"{self.case.describe()}: unusable ({why})"
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
        """Cases that produced a verdict. Unusable ones are not counted."""
        return sum(1 for o in self.outcomes if o.judged)

    @property
    def identical(self) -> int:
        return sum(1 for o in self.outcomes if o.status == "same")

    @property
    def values_identical(self) -> int:
        return sum(1 for o in self.outcomes
                   if o.status == "same" and o.evidence == "value")

    @property
    def throws_identical(self) -> int:
        return sum(1 for o in self.outcomes
                   if o.status == "same" and o.evidence == "throw")

    @property
    def diffs(self) -> list[CaseOutcome]:
        return [o for o in self.outcomes if o.status == "diff"]

    @property
    def unusable(self) -> list[CaseOutcome]:
        return [o for o in self.outcomes if o.status == "unusable"]

    @property
    def ok(self) -> bool:
        return self.verdict == "PASS"

    @property
    def verdict(self) -> str:
        """PASS / PARTIAL / FAIL / NO VERDICT.

        `PARTIAL` exists because "9 cases agreed, 1 could not be invoked" is
        neither a pass nor a failure. Collapsing it into PASS is how the old
        `same == left == right` rule turned untested cases into evidence;
        collapsing it into FAIL would report a rewrite as broken when the
        harness simply could not reach the method.
        """
        if self.diffs:
            return "FAIL"
        if self.compared == 0:
            return "NO VERDICT"
        return "PASS" if not self.unusable else "PARTIAL"

    def summary(self) -> str:
        lines = [
            f"original  : {self.original}",
            f"rewritten : {self.rewritten}",
            f"cases     : {len(self.outcomes)}",
            f"judged    : {self.compared}",
            f"identical : {self.identical} "
            f"({self.values_identical} value, {self.throws_identical} throw)",
        ]
        if self.unusable:
            lines.append(f"unusable  : {len(self.unusable)} "
                         f"(the harness could not invoke them)")
        lines += [
            f"elapsed   : {self.elapsed:.2f}s",
            f"result    : {self.verdict}",
        ]
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "original": self.original,
            "rewritten": self.rewritten,
            "cases": len(self.outcomes),
            "compared": self.compared,
            "identical": self.identical,
            "identical_values": self.values_identical,
            "identical_throws": self.throws_identical,
            "verdict": self.verdict,
            "diffs": [{"case": o.case.describe(), "left": o.left, "right": o.right}
                      for o in self.diffs],
            "unusable": [{"case": o.case.describe(), "left": o.left,
                          "right": o.right, "reason": o.reason}
                         for o in self.unusable],
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
    # the build flags are part of the identity: a cached class built for the
    # host JVM would not run on an older one
    key = hashlib.sha256((DRIVER_JAVA + "|release8").encode("utf-8")).hexdigest()[:12]
    out = Path(tempfile.gettempdir()) / f"jdec_behave_driver_{key}"
    if not (out / f"{DRIVER_CLASS}.class").is_file():
        out.mkdir(parents=True, exist_ok=True)
        src = out / f"{DRIVER_CLASS}.java"
        src.write_text(DRIVER_JAVA, encoding="utf-8")
        args = ["-encoding", "UTF-8", "-d", str(out), str(src)]
        # same rule as the verification driver: build for 8 so one build runs
        # on every JVM in the matrix. `sun.misc.Unsafe` is reached by name,
        # never referenced at compile time, so `--release 8` still compiles it.
        r = TC.run_javac(["--release", "8"] + args,
                         purpose="building the behaviour driver")
        if r.returncode != 0:
            r = TC.run_javac(args, purpose="building the behaviour driver")
        if r.returncode != 0:
            raise TC.ToolchainError(
                "cannot build the behaviour driver: "
                + (r.stderr or r.stdout or "")[-800:])
    _DRIVER_CACHE = out
    return out


_DRIVER_CACHE: Path | None = None


def compare(original: Path, rewritten: Path, cases: list[Case],
            *, java: str | None = None, timeout: int = 300,
            classpath=()) -> BehaveReport:
    """Run every case against both jars and compare. Executes target code.

    `classpath` is for the libraries the target references but does not
    contain (a JavaFX UI jar, say). Without them the class cannot be loaded and
    every case lands in `unusable` — "not tested" again. The entries go into
    both loaders, so the two sides still differ only in the jar under test.
    """
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
        cmd += [str(Path(c).resolve()) for c in classpath]
        import subprocess
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  errors="replace", timeout=timeout)
        except subprocess.TimeoutExpired:
            raise TC.ToolchainError(
                f"the behaviour driver timed out after {timeout}s") from None
        rep.driver_output = (proc.stderr or "")[-4000:]

    # The driver stamps every line with the case's 1-based index. Pairing by
    # position (`zip`) silently shifted every result by one as soon as a case
    # produced no line, which is exactly how "not tested" turns into "same".
    by_index: dict[int, list[str]] = {}
    for ln in (proc.stdout or "").splitlines():
        parts = ln.split("\t")
        if len(parts) < 5:
            continue
        try:
            idx = int(parts[1])
        except ValueError:
            continue
        by_index[idx] = parts

    for i, case in enumerate(cases, 1):
        parts = by_index.get(i)
        if parts is None:
            rep.outcomes.append(CaseOutcome(case, "", "", "unusable",
                                            "driver produced no line"))
            continue
        verdict, left, right = parts[0], parts[3], parts[4]
        if verdict == "JUDGED":
            status = "same" if left == right else "diff"
            rep.outcomes.append(CaseOutcome(case, left, right, status))
        else:
            rep.outcomes.append(CaseOutcome(case, left, right, "unusable",
                                            "method could not be invoked"))
    rep.elapsed = time.time() - t0
    return rep
