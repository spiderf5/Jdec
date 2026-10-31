"""Decompiler engine registry and invocation.

Three engines are wired up, each with a distinct failure profile:

* CFR 0.152       - best overall accuracy, most modern-syntax coverage
* Vineflower 1.11 - Fernflower successor, strong on generics/annotations
* Procyon 0.6.0   - weak on Java 14+, but often the one that gets through
                    obfuscated Java 6-8 bytecode (older Minecraft)

Engines are driven as subprocesses over a directory tree of .class files.
That keeps JVM startups proportional to *chunks*, not to class count.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

MAVEN = "https://repo1.maven.org/maven2"

# Maven Central publishes an official .sha1 per artifact (verified against the
# local copies 2026-10-07).  A download - and every cached copy, forever - is
# held to these values, so a truncated or silently swapped jar can never be
# adopted as an engine.
_SHA1: dict[str, str] = {
    "cfr-0.152.jar": "48ef4892cfe8feffddbbd0ff077735140557db74",
    "vineflower-1.11.1.jar": "77767cdbc76d116c6d5e1565ec387e531085b9f4",
    "procyon-compilertools-0.6.0.jar": "44c59529227960fec1be237ac97304303caf0ba3",
    "procyon-core-0.6.0.jar": "8f5a33f81d7027d11f1eeb609d9f467f97454c1c",
}


def _sha1(data: bytes) -> str:
    import hashlib
    return hashlib.sha1(data).hexdigest()


def cp_sep() -> str:
    """Classpath separator for the platform the JVM runs on.

    Windows java wants ';', POSIX java wants ':'.  Hardcoding ';' made the
    Procyon bridge classpath (and CFR/Vineflower extra classpaths) a single
    invalid path on Linux/macOS.
    """
    return ";" if os.name == "nt" else ":"

# engine key -> (file name, maven path or None)
_ARTIFACTS: dict[str, list[tuple[str, str]]] = {
    "cfr": [("cfr-0.152.jar", f"{MAVEN}/org/benf/cfr/0.152/cfr-0.152.jar")],
    "vineflower": [
        ("vineflower-1.11.1.jar", f"{MAVEN}/org/vineflower/vineflower/1.11.1/vineflower-1.11.1.jar")
    ],
    "procyon": [
        ("procyon-compilertools-0.6.0.jar",
         f"{MAVEN}/org/bitbucket/mstrobel/procyon-compilertools/0.6.0/procyon-compilertools-0.6.0.jar"),
        ("procyon-core-0.6.0.jar",
         f"{MAVEN}/org/bitbucket/mstrobel/procyon-core/0.6.0/procyon-core-0.6.0.jar"),
    ],
}


def find_java() -> str | None:
    jh = os.environ.get("JAVA_HOME")
    if jh:
        candidate = Path(jh) / "bin" / ("java.exe" if os.name == "nt" else "java")
        if candidate.is_file():
            return str(candidate)
    exe = shutil.which("java")
    if exe:
        return exe
    for c in (
        r"C:\Program Files\Java\jdk-21\bin\java.exe",
        r"C:\Program Files\Zulu\zulu-21\bin\java.exe",
        r"C:\Program Files\Eclipse Adoptium\jdk-21\bin\java.exe",
        r"C:\Program Files\Java\jdk-17\bin\java.exe",
        r"C:\Program Files\Zulu\zulu-17\bin\java.exe",
        r"C:\Program Files\Eclipse Adoptium\jdk-17\bin\java.exe",
    ):
        if Path(c).exists():
            return c
    return None


def find_javac() -> str | None:
    jh = os.environ.get("JAVA_HOME")
    if jh:
        candidate = Path(jh) / "bin" / ("javac.exe" if os.name == "nt" else "javac")
        if candidate.is_file():
            return str(candidate)
    exe = shutil.which("javac")
    if exe:
        return exe
    j = find_java()
    if j:
        candidate = Path(j).parent / ("javac.exe" if os.name == "nt" else "javac")
        if candidate.is_file():
            return str(candidate)
    for c in (
        r"C:\Program Files\Java\jdk-21\bin\javac.exe",
        r"C:\Program Files\Zulu\zulu-21\bin\javac.exe",
        r"C:\Program Files\Eclipse Adoptium\jdk-21\bin\javac.exe",
        r"C:\Program Files\Java\jdk-17\bin\javac.exe",
        r"C:\Program Files\Zulu\zulu-17\bin\javac.exe",
        r"C:\Program Files\Eclipse Adoptium\jdk-17\bin\javac.exe",
    ):
        if Path(c).exists():
            return c
    return None



@dataclass
class Engine:
    key: str
    label: str
    jars: list[str]
    priority: int
    needs_jar_input: bool = False
    main_class: str | None = None
    bridge_dir: str | None = None
    # variant name -> extra CLI args appended for that variant
    variants: dict[str, list[str]] = field(default_factory=dict)

    def classpath(self, engines_dir: Path) -> str:
        parts = []
        if self.bridge_dir:
            parts.append(str(engines_dir / self.bridge_dir))
        parts += [str(engines_dir / j) for j in self.jars]
        return cp_sep().join(parts)

    def available(self, engines_dir: Path) -> bool:
        for j in self.jars:
            p = engines_dir / j
            if not p.exists() or p.stat().st_size <= 10_000:
                return False
            try:
                with zipfile.ZipFile(p) as z:
                    z.namelist()          # reads the central directory
            except Exception:
                return False
        return not self.bridge_dir or (engines_dir / self.bridge_dir / "ProcyonBridge.class").exists()


ENGINES: dict[str, Engine] = {
    "cfr": Engine(
        key="cfr",
        label="CFR 0.152",
        jars=["cfr-0.152.jar"],
        priority=3,
        variants={
            "default": ["--comments", "false", "--silent", "true", "--hideutf", "false"],
            # more permissive: pushes harder through damaged / obfuscated flow,
            # at the cost of occasionally producing less idiomatic code
            "lenient": [
                "--comments", "false", "--silent", "true", "--hideutf", "false",
                "--recover", "true", "--recovertypeclash", "true",
                "--recovertypehints", "true", "--forcetopsort", "true",
                "--aggressivesizethreshold", "30000",
                "--removebadgenerics", "true", "--ignoreexceptions", "true",
            ],
        },
    ),
    "vineflower": Engine(
        key="vineflower",
        label="Vineflower 1.11.1",
        jars=["vineflower-1.11.1.jar"],
        priority=2,
        variants={
            "default": ["-log=ERROR", "-dgs=1"],
            "lenient": ["-log=ERROR", "-dgs=1", "-rsy=1", "-iec=1", "-iib=1"],
        },
    ),
    "procyon": Engine(
        key="procyon",
        label="Procyon 0.6.0",
        jars=["procyon-compilertools-0.6.0.jar", "procyon-core-0.6.0.jar"],
        priority=1,
        needs_jar_input=True,
        main_class="ProcyonBridge",
        bridge_dir="bridge",
        variants={"default": ["1"], "lenient": ["1"]},
    ),
}


def ensure_procyon_bridge(engines_dir: Path, quiet: bool = False) -> bool:
    """Compile ProcyonBridge.java when the .class is missing.

    The .java ships with the repo but the .class is gitignored, so without this
    step the Procyon engine never becomes available() on a fresh checkout - it
    silently drops out of the engine order.
    """
    import subprocess

    src = engines_dir / "ProcyonBridge.java"
    cls = engines_dir / "ProcyonBridge.class"
    if not src.is_file():
        return cls.is_file()
    if cls.is_file():
        return True

    javac = find_javac()
    if not javac:
        if not quiet:
            print("  ! javac not found: cannot build ProcyonBridge")
        return False
    out_dir = engines_dir / "bridge"
    out_dir.mkdir(parents=True, exist_ok=True)
    jars = [j for j in (
        "procyon-core-0.6.0.jar", "procyon-compilertools-0.6.0.jar")
        if (engines_dir / j).is_file()]
    cp = cp_sep().join(str(engines_dir / j) for j in jars)
    from . import toolchain as TC
    try:
        r = TC.run_javac(["-nowarn", "-cp", cp, "-d", str(out_dir), str(src)],
                         exe=javac, purpose="building the Procyon bridge")
    except TC.ToolchainError as exc:
        if not quiet:
            print(f"  ! ProcyonBridge build failed: {exc}")
        return False
    if r.returncode != 0 or not (out_dir / "ProcyonBridge.class").is_file():
        if not quiet:
            print("  ! ProcyonBridge build failed:\n"
                  + (r.stderr or r.stdout or "")[-800:])
        return False
    if not quiet:
        print("  built bridge/ProcyonBridge.class")
    return True


def ensure_engines(engines_dir: Path, want: list[str] | None = None, quiet: bool = False) -> list[str]:
    """Download missing engine jars. Returns the list of unavailable engines."""
    import urllib.request

    engines_dir.mkdir(parents=True, exist_ok=True)
    missing: list[str] = []
    for key in want or list(ENGINES):
        for fname, url in _ARTIFACTS.get(key, []):
            dest = engines_dir / fname
            want_hash = _SHA1.get(fname)
            if dest.exists():
                intact = dest.stat().st_size > 10_000
                if intact and want_hash:
                    intact = _sha1(dest.read_bytes()) == want_hash
                if intact:
                    continue
                # truncated or tampered cached copy: refuse and re-fetch
                if not quiet:
                    print(f"  ! {fname} failed verification, re-downloading ...")
                try:
                    dest.unlink()
                except OSError:
                    missing.append(key)
                    break
            if not quiet:
                print(f"  downloading {fname} ...")
            try:
                with urllib.request.urlopen(url, timeout=180) as r:
                    data = r.read()
                if want_hash and _sha1(data) != want_hash:
                    if not quiet:
                        print(f"  ! {fname}: sha1 mismatch - refusing to install")
                    missing.append(key)
                    break
                dest.write_bytes(data)
            except Exception as exc:  # noqa: BLE001
                if not quiet:
                    print(f"  ! failed: {exc}")
                missing.append(key)
                break
    ensure_procyon_bridge(engines_dir, quiet=quiet)
    return sorted(set(missing))


@dataclass
class RunResult:
    engine: str
    variant: str
    ok: bool
    files: dict[str, Path]  # relative path (a/b/C.java) -> absolute path
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    seconds: float = 0.0


def _collect(out_dir: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    if not out_dir.exists():
        return files
    for p in out_dir.rglob("*.java"):
        try:
            rel = p.relative_to(out_dir).as_posix()
        except ValueError:
            continue
        if p.stat().st_size == 0:
            continue
        files[rel] = p
    return files


def _pack_jar(src_dir: Path, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(src_dir.rglob("*.class")):
            z.write(p, p.relative_to(src_dir).as_posix())
    return dest


def run_engine(
    engine: Engine,
    engines_dir: Path,
    input_path: Path,
    out_dir: Path,
    variant: str = "default",
    timeout: int = 1800,
    memory: str = "4g",
    extra_cp: list[str] | None = None,
    verbose: bool = False,
) -> RunResult:
    """Run one engine over `input_path` (a jar or a directory of classes)."""
    import time

    # the JVM runs with cwd=engines_dir, so every path must be absolute
    engines_dir = Path(engines_dir).resolve()
    input_path = Path(input_path).resolve()
    out_dir = Path(out_dir).resolve()

    java = find_java()
    if java is None:
        return RunResult(engine.key, variant, False, {}, error="java not found on PATH")

    out_dir.mkdir(parents=True, exist_ok=True)
    extra = list(engine.variants.get(variant, engine.variants.get("default", [])))

    target = input_path
    tmp_jar: Path | None = None
    if engine.needs_jar_input and input_path.is_dir():
        tmp_jar = out_dir.parent / f"_procyon_in_{out_dir.name}.jar"
        target = _pack_jar(input_path, tmp_jar)

    if engine.main_class:
        cmd = [java, f"-Xmx{memory}", "-cp", engine.classpath(engines_dir), engine.main_class,
               str(target), str(out_dir)] + extra
    elif engine.key == "vineflower":
        cmd = [java, f"-Xmx{memory}", "-jar", str(engines_dir / engine.jars[0])] + extra + [
            str(target), str(out_dir)]
    else:  # cfr
        cmd = [java, f"-Xmx{memory}", "-jar", str(engines_dir / engine.jars[0]), str(target),
               "--outputdir", str(out_dir)] + extra

    if extra_cp:
        if engine.key == "cfr":
            cmd += ["--extraclasspath", cp_sep().join(extra_cp)]
        elif engine.key == "vineflower":
            cmd = cmd[:-2] + [f"-e={cp_sep().join(extra_cp)}"] + cmd[-2:]

    t0 = time.time()
    if verbose:
        print("      $ " + " ".join(f'"{c}"' if " " in c else c for c in cmd))
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            cwd=str(engines_dir), text=True, errors="replace",
        )
        out, err, rc = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return RunResult(engine.key, variant, False, _collect(out_dir),
                         error=f"timeout after {timeout}s", seconds=time.time() - t0)
    except Exception as exc:  # noqa: BLE001
        return RunResult(engine.key, variant, False, {}, error=str(exc), seconds=time.time() - t0)
    finally:
        if tmp_jar and tmp_jar.exists():
            try:
                tmp_jar.unlink()
            except OSError:
                pass

    files = _collect(out_dir)
    ok = bool(files) and rc == 0
    return RunResult(engine.key, variant, ok, files, out[:4000], err[:4000],
                     "" if ok else f"exit={rc}", time.time() - t0)
