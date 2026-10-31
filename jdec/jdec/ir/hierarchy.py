"""Just enough class hierarchy to compute a common supertype.

`merge` needs a least upper bound for two reference types. Falling back to
`java/lang/Object` is always *sound* for the frame itself, but the value is then
too wide for whatever consumes it: a multi-catch handler whose two catch types
merge to Object can no longer be passed to a constructor that wants a
`Throwable` — measured on HMCL, that alone accounted for most of the residual
verify failures.

The index only needs `this_class`, `super_class` and `interfaces`, so building it
costs one parse per class and no member information. Arrays are handled
structurally: same dimension and both components references -> LCA of the
components, otherwise Object.
"""

from __future__ import annotations

import zipfile
from collections import deque
from pathlib import Path

from .. import classfile as CF

OBJECT = "java/lang/Object"

# The jar only describes its own classes; any merge that involves a JDK type
# would otherwise find no common ancestor and widen to Object. That is sound for
# the frame but too wide at the use site — an `athrow` on an Object fails, which
# is how a multi-catch handler turns into a VerifyError.
#
# Seeding the JDK chains that actually show up in merges is not a general
# solution, but it is the difference between "most methods" and "all methods".
# Jar entries are added after this and win.
_JDK_SEED = {
    "java/lang/Throwable": ("java/lang/Object", ()),
    "java/lang/Exception": ("java/lang/Throwable", ()),
    "java/lang/Error": ("java/lang/Throwable", ()),
    "java/lang/RuntimeException": ("java/lang/Exception", ()),
    "java/lang/IllegalArgumentException": ("java/lang/RuntimeException", ()),
    "java/lang/IllegalStateException": ("java/lang/RuntimeException", ()),
    "java/lang/NullPointerException": ("java/lang/RuntimeException", ()),
    "java/lang/IndexOutOfBoundsException": ("java/lang/RuntimeException", ()),
    "java/lang/ArrayIndexOutOfBoundsException": ("java/lang/IndexOutOfBoundsException", ()),
    "java/lang/ClassCastException": ("java/lang/RuntimeException", ()),
    "java/lang/UnsupportedOperationException": ("java/lang/RuntimeException", ()),
    "java/lang/NumberFormatException": ("java/lang/IllegalArgumentException", ()),
    "java/lang/ArithmeticException": ("java/lang/RuntimeException", ()),
    "java/lang/SecurityException": ("java/lang/RuntimeException", ()),
    "java/lang/InterruptedException": ("java/lang/Exception", ()),
    "java/lang/ReflectiveOperationException": ("java/lang/Exception", ()),
    "java/io/IOException": ("java/lang/Exception", ()),
    "java/io/UncheckedIOException": ("java/lang/RuntimeException", ()),
    "java/lang/Number": ("java/lang/Object", ()),
    "java/lang/Integer": ("java/lang/Number", ("java/lang/Comparable",)),
    "java/lang/Long": ("java/lang/Number", ("java/lang/Comparable",)),
    "java/lang/Double": ("java/lang/Number", ("java/lang/Comparable",)),
    "java/lang/Float": ("java/lang/Number", ("java/lang/Comparable",)),
    "java/lang/Short": ("java/lang/Number", ("java/lang/Comparable",)),
    "java/lang/Byte": ("java/lang/Number", ("java/lang/Comparable",)),
    "java/lang/Boolean": ("java/lang/Object", ("java/lang/Comparable",)),
    "java/lang/Character": ("java/lang/Object", ("java/lang/Comparable",)),
    "java/lang/String": ("java/lang/Object", ("java/lang/CharSequence", "java/lang/Comparable")),
    "java/lang/CharSequence": ("java/lang/Object", ()),
    "java/lang/Comparable": ("java/lang/Object", ()),
    "java/lang/Iterable": ("java/lang/Object", ()),
    "java/lang/Enum": ("java/lang/Object", ("java/lang/Comparable",)),
    "java/lang/Record": ("java/lang/Object", ()),
    "java/lang/Cloneable": ("java/lang/Object", ()),
    "java/io/Serializable": ("java/lang/Object", ()),
    "java/util/Collection": ("java/lang/Iterable", ()),
    "java/util/List": ("java/util/Collection", ()),
    "java/util/Set": ("java/util/Collection", ()),
    "java/util/Map": ("java/lang/Object", ()),
}


_SUPERS_JAVA = r"""
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

/** Prints `name<TAB>super<TAB>i1,i2,...` for every name the platform can see. */
public final class JdecSupersDriver {
    public static void main(String[] args) throws Exception {
        List<String> names = Files.readAllLines(Paths.get(args[0]), StandardCharsets.UTF_8);
        PrintStream out = new PrintStream(new FileOutputStream(FileDescriptor.out), true, "UTF-8");
        ClassLoader loader = ClassLoader.getPlatformClassLoader();
        for (String raw : names) {
            String name = raw.trim();
            if (name.isEmpty()) continue;
            try {
                Class<?> c = Class.forName(name.replace('/', '.'), false, loader);
                Class<?> sup = c.getSuperclass();
                StringBuilder ifs = new StringBuilder();
                for (Class<?> i : c.getInterfaces()) {
                    if (ifs.length() > 0) ifs.append(',');
                    ifs.append(i.getName().replace('.', '/'));
                }
                out.println(name + "\t" + (sup == null ? "" : sup.getName().replace('.', '/'))
                        + "\t" + ifs);
            } catch (Throwable t) {
                // not on the platform (or a dependency of it is missing): skip
            }
        }
        out.flush();
    }
}
"""

_SUPERS_CACHE: dict | None = None


def resolve_platform_types(names, java=None, timeout: int = 120) -> dict:
    """Ask the JVM for the supertypes of platform classes.

    A hardcoded seed cannot cover `UnsupportedCharsetException extends
    IllegalArgumentException`; guessing there produces a handler frame that is
    too wide to pass to the method that consumes it. One JVM start, one answer
    per name, and anything the platform cannot see is simply left unknown.
    """
    global _SUPERS_CACHE
    if _SUPERS_CACHE is None:
        _SUPERS_CACHE = {}
    todo = [n for n in names if n not in _SUPERS_CACHE]
    if not todo:
        return {n: _SUPERS_CACHE[n] for n in names if n in _SUPERS_CACHE}

    import hashlib
    import subprocess
    import tempfile

    from .. import engines as EN
    from .. import toolchain as TC

    exe = java or EN.find_java()
    if not exe:
        return {}
    key = hashlib.sha256(_SUPERS_JAVA.encode("utf-8")).hexdigest()[:10]
    drv = Path(tempfile.gettempdir()) / f"jdec_supers_driver_{key}"
    if not (drv / "JdecSupersDriver.class").is_file():
        drv.mkdir(parents=True, exist_ok=True)
        src = drv / "JdecSupersDriver.java"
        src.write_text(_SUPERS_JAVA, encoding="utf-8")
        r = TC.run_javac(["-encoding", "UTF-8", "-d", str(drv), str(src)],
                         purpose="building the hierarchy driver")
        if r.returncode != 0:
            return {}
    with tempfile.TemporaryDirectory(prefix="jdec_supers_") as td:
        f = Path(td) / "names.txt"
        f.write_text("\n".join(todo), encoding="utf-8")
        try:
            proc = subprocess.run(
                [exe, "-cp", str(drv), "JdecSupersDriver", str(f)],
                capture_output=True, text=True, errors="replace", timeout=timeout)
        except (subprocess.TimeoutExpired, OSError):
            return {}
    for line in (proc.stdout or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        name, sup, ifs = parts[0], parts[1], parts[2]
        _SUPERS_CACHE[name] = (sup, tuple(i for i in ifs.split(",") if i))
    return {n: _SUPERS_CACHE[n] for n in names if n in _SUPERS_CACHE}


class Hierarchy:
    def __init__(self, seed_jdk: bool = True):
        self._parents: dict[str, tuple[str, ...]] = {}
        self._anc: dict[str, dict[str, int]] = {}
        self._lca: dict[tuple[str, str], str] = {}
        # Names referenced by an indexed class but defined by no class on
        # the classpath. A merge that touches one of them widens to Object.
        self.unresolved: set[str] = set()
        if seed_jdk:
            for name, (sup, ifaces) in _JDK_SEED.items():
                self._parents[name] = (sup,) + tuple(ifaces)
    # ---- building ---------------------------------------------------
    def add(self, name: str, super_name: str | None,
            interfaces=()) -> None:
        parents = []
        if super_name:
            parents.append(super_name)
        parents.extend(interfaces)
        self._parents[name] = tuple(parents)
        self._anc.pop(name, None)
        self._lca.clear()

    @classmethod
    def from_jar(cls, path: Path, extra=()) -> "Hierarchy":
        """Index `path`, plus any `extra` jars/dirs that hold its dependencies.

        A library the target references but does not contain (JavaFX in HMCL)
        has no known supertypes, so every merge involving it widens to
        `java/lang/Object` — sound for the frame, but too wide at the consumer:
        the verifier then rejects the class with "Type Object is not assignable
        to javafx/animation/Animation". Indexing the dependency jars costs one
        parse each and removes the whole class of failure.
        """
        h = cls()
        referenced: set[str] = set()
        with zipfile.ZipFile(path) as z:
            cls._index_zips([z], h, referenced)
        for e in extra:
            p = Path(e)
            if p.is_dir():
                cls._index_dir(p, h, referenced)
            elif p.is_file() and zipfile.is_zipfile(p):
                with zipfile.ZipFile(p) as z:
                    cls._index_zips([z], h, referenced)
        # Anything still unknown is a platform type. Without its supertypes, a
        # merge between two JDK exceptions widens to Object and the handler
        # frame becomes too wide at the use site.
        missing = [n for n in referenced
                   if n not in h._parents and not n.startswith("[")]
        for name, (sup, ifaces) in resolve_platform_types(sorted(missing)).items():
            if name not in h._parents:
                h._parents[name] = ((sup,) if sup else ()) + tuple(ifaces)
        # Whatever is still unowned is a dependency the caller did not pass.
        # Name them: a merge involving one of these is exactly the case where
        # the frame widens to Object and still looks valid under the same,
        # incomplete classpath the verifier was given.
        h.unresolved = {n for n in referenced
                        if n not in h._parents and not n.startswith("[")}
        return h

    @staticmethod
    def _index_zips(zips, h: "Hierarchy", referenced: set) -> None:
        for z in zips:
            for info in z.infolist():
                if not info.filename.endswith(".class"):
                    continue
                if info.filename.startswith("META-INF/"):
                    continue      # multi-release copy: the base entry is indexed
                try:
                    cf = CF.parse(z.read(info.filename))
                except Exception:
                    continue
                h._index_one(cf, referenced)

    @staticmethod
    def _index_dir(root: Path, h: "Hierarchy", referenced: set) -> None:
        for f in Path(root).rglob("*.class"):
            try:
                cf = CF.parse(f.read_bytes())
            except Exception:
                continue
            h._index_one(cf, referenced)

    def _index_one(self, cf, referenced: set) -> None:
        try:
            sup = None
            if cf.super_class:
                e = cf.cp[cf.super_class]
                if e and e[0] == CF.C_CLASS:
                    sup = cf.utf8(e[1][0])
            ifaces = []
            for i in cf.interfaces:
                e = cf.cp[i]
                if e and e[0] == CF.C_CLASS:
                    ifaces.append(cf.utf8(e[1][0]))
            # The target's own definition always wins; a dependency may only
            # fill in what the target does not define.
            if cf.name not in self._parents:
                self.add(cf.name, sup, ifaces)
            for e in cf.cp:
                if e and e[0] == CF.C_CLASS:
                    try:
                        referenced.add(cf.utf8(e[1][0]))
                    except Exception:
                        pass
        except Exception:
            pass

    @classmethod
    def from_classes(cls, classes, extra=()) -> "Hierarchy":
        """Build from already-parsed ClassFile objects (no second pass)."""
        h = cls()
        referenced: set[str] = set()
        for cf in classes:
            h._index_one(cf, referenced)
        for e in extra:
            p = Path(e)
            if p.is_dir():
                cls._index_dir(p, h, referenced)
            elif p.is_file() and zipfile.is_zipfile(p):
                with zipfile.ZipFile(p) as z:
                    cls._index_zips([z], h, referenced)
        return h

    # ---- queries ----------------------------------------------------
    def parents(self, name: str) -> tuple[str, ...]:
        return self._parents.get(name, ())

    def ancestors(self, name: str) -> dict[str, int]:
        """name -> distance to that ancestor (name itself at 0)."""
        cached = self._anc.get(name)
        if cached is not None:
            return cached
        out = {name: 0}
        queue = deque([(name, 0)])
        while queue:
            cur, d = queue.popleft()
            for p in self.parents(cur):
                if p not in out:
                    out[p] = d + 1
                    queue.append((p, d + 1))
        self._anc[name] = out
        return out

    def lca(self, a: str, b: str) -> str:
        if a == b:
            return a
        key = (a, b) if a <= b else (b, a)
        hit = self._lca.get(key)
        if hit is not None:
            return hit
        if a.startswith("[") or b.startswith("["):
            result = self._lca_arrays(a, b)
        else:
            result = self._lca_objects(a, b)
        self._lca[key] = result
        return result

    def _lca_objects(self, a: str, b: str) -> str:
        anc_a = self.ancestors(a)
        best = None
        seen = set()
        queue = deque([(b, 0)])
        while queue:
            cur, d = queue.popleft()
            if cur in seen:
                continue
            seen.add(cur)
            if cur in anc_a:
                score = d + anc_a[cur]
                if best is None or score < best[0]:
                    best = (score, cur)
            for p in self.parents(cur):
                queue.append((p, d + 1))
        return best[1] if best else OBJECT

    def _lca_arrays(self, a: str, b: str) -> str:
        # only the common case is worth modelling: same rank, both reference
        # components. Everything else is Object, which is always a supertype.
        if not (a.startswith("[") and b.startswith("[")):
            return OBJECT
        if a[1:2] != b[1:2]:
            return OBJECT
        ca, cb = a[1:], b[1:]
        if ca.startswith("L") and cb.startswith("L") and ca.endswith(";"):
            inner = self.lca(ca[1:-1], cb[1:-1])
            return "[L" + inner + ";"
        return OBJECT
