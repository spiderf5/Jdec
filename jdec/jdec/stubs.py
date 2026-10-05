"""Synthetic Minecraft runtime stubs for headless recovery and constant replay.

When obfuscated classes decrypt constants or initialize static fields, their
<clinit> or decryptors often touch Minecraft.getInstance(), BuiltInRegistries,
or Bootstrap. Without a running game instance, this throws NullPointerException
or IllegalStateException, causing dynamic replay in recover.py / pool.py to fail.

This module builds or serves a minimal mock jar (mc_stubs.jar) containing dummy
singletons and non-null instances. Prepending it to the replay classpath
resolves the 'needs-instance' and 'needs-bootstrap' failure buckets.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

# Java source code for runtime mocks
STUB_SOURCES = {
    "net/minecraft/client/Minecraft.java": """package net.minecraft.client;
public class Minecraft {
    private static final Minecraft INSTANCE = new Minecraft();
    public static Minecraft getInstance() { return INSTANCE; }
    public static Minecraft getMinecraft() { return INSTANCE; }

    // Legacy (1.7 - 1.12.2) and Modern (1.14+) player/world/UI fields
    public Object thePlayer = new Object();
    public Object theWorld = new Object();
    public Object player = new Object();
    public Object level = new Object();
    public Object fontRenderer = new Object();
    public Object fontRendererObj = new Object();
    public Object font = new Object();
    public Object gameSettings = new Object();
    public Object options = new Object();
    public Object currentScreen = null;
    public Object screen = null;
    public java.io.File mcDataDir = new java.io.File(".");
    public java.io.File gameDirectory = new java.io.File(".");

    public String getUser() { return "DevPlayer"; }
    public boolean isRunning() { return true; }
    public boolean isSingleplayer() { return false; }
    public Object getSession() { return new Object(); }
}
""",
    "net/minecraft/launchwrapper/Launch.java": """package net.minecraft.launchwrapper;
import java.util.HashMap;
import java.util.Map;
public class Launch {
    public static Map<String, Object> blackboard = new HashMap<String, Object>();
}
""",
    "net/minecraft/SharedConstants.java": """package net.minecraft;
public class SharedConstants {
    public static boolean IS_RUNNING_IN_IDE = false;
    public static void tryDetectVersion() {}
}
""",
    "net/minecraft/server/Bootstrap.java": """package net.minecraft.server;
public class Bootstrap {
    public static boolean isBootstrapped = true;
    public static void bootStrap() {}
}
""",
    "net/minecraft/core/registries/BuiltInRegistries.java": """package net.minecraft.core.registries;
public class BuiltInRegistries {
    public static final Object BLOCK = new Object();
    public static final Object ITEM = new Object();
    public static final Object ENTITY_TYPE = new Object();
}
"""
}


def _find_javac(bin_name: str = "javac") -> str:
    """Find javac on PATH, in JAVA_HOME, or via engines detection."""
    if bin_name != "javac" and Path(bin_name).is_file():
        return bin_name
    from . import engines
    jc = engines.find_javac()
    if jc:
        return jc
    w = shutil.which(bin_name)
    if w:
        return w
    jh = os.environ.get("JAVA_HOME")
    if jh:
        candidate = Path(jh) / "bin" / (bin_name + (".exe" if os.name == "nt" else ""))
        if candidate.is_file():
            return str(candidate)
    return bin_name


def build_stubs_jar(dest: Path, javac_bin: str = "javac") -> Path:
    """Compile stub Java sources and package them into a jar."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp_dir = Path(tempfile.mkdtemp(prefix="jdec_stubs_build_"))
    javac_resolved = _find_javac(javac_bin)
    try:
        java_files = []
        for rel_path, src in STUB_SOURCES.items():
            fpath = tmp_dir / rel_path
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text(src, encoding="utf-8")
            java_files.append(str(fpath))

        # Compile with javac
        cmd = [javac_resolved, "-source", "8", "-target", "8"] + java_files
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except Exception:
            r = None

        if r is None or r.returncode != 0:
            # Fallback without -source 8 / -target 8 (for newer javac)
            cmd = [javac_resolved] + java_files
            r = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if r.returncode != 0:
            raise RuntimeError(f"javac failed to compile stubs: {r.stderr or r.stdout}")

        # Pack into jar
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
            for cls_file in tmp_dir.rglob("*.class"):
                arcname = cls_file.relative_to(tmp_dir).as_posix()
                z.write(cls_file, arcname)

        return dest
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def ensure_stubs_jar(cache_dir: Path | None = None) -> Path:
    """Get or build the cached mc_stubs.jar."""
    if cache_dir is None:
        cache_dir = Path(__file__).resolve().parent.parent / "engines"
    cache_dir.mkdir(parents=True, exist_ok=True)
    stub_jar = cache_dir / "mc_stubs.jar"
    if not stub_jar.is_file():
        build_stubs_jar(stub_jar)
    return stub_jar
