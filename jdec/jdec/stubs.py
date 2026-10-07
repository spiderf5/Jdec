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
            r = subprocess.run(cmd, capture_output=True, text=True,
                               errors="replace", check=False)
        except Exception:
            r = None

        if r is None or r.returncode != 0:
            # Fallback without -source 8 / -target 8 (for newer javac)
            cmd = [javac_resolved] + java_files
            r = subprocess.run(cmd, capture_output=True, text=True,
                               errors="replace", check=False)

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


def build_stub_class_bytes(slash_name: str) -> bytes:
    """Generate a minimal, compliant Java 8 .class bytecode for a synthetic mock class.

    Includes:
    - Default constructor <init>()V
    - Static initializer <clinit>()V initializing public static final INSTANCE
    - Public static field `public static final <slashName> INSTANCE`
    - Singleton factory methods:
      - getInstance() returning <slashName>
      - getInstance() returning Object
      - get() returning Object
      - instance() returning Object
      - getMinecraft() returning Object
    """
    import struct
    slash_name = slash_name.replace(".", "/")
    typed_desc = f"()L{slash_name};"
    field_desc = f"L{slash_name};"

    buf = bytearray()
    buf.extend(b"\xCA\xFE\xBA\xBE")  # magic
    buf.extend(struct.pack(">HH", 0, 52))  # Java 8 (major 52)
    buf.extend(struct.pack(">H", 22))  # constant pool count = 22 (1..21)

    def add_utf8(s: str) -> None:
        b = s.encode("utf-8")
        buf.extend(b"\x01" + struct.pack(">H", len(b)) + b)

    def add_class(name_idx: int) -> None:
        buf.extend(b"\x07" + struct.pack(">H", name_idx))

    def add_nat(name_idx: int, desc_idx: int) -> None:
        buf.extend(b"\x0C" + struct.pack(">HH", name_idx, desc_idx))

    def add_methodref(cls_idx: int, nat_idx: int) -> None:
        buf.extend(b"\x0A" + struct.pack(">HH", cls_idx, nat_idx))

    def add_fieldref(cls_idx: int, nat_idx: int) -> None:
        buf.extend(b"\x09" + struct.pack(">HH", cls_idx, nat_idx))

    add_utf8(slash_name)               # 1
    add_class(1)                       # 2 (This class)
    add_utf8("java/lang/Object")       # 3
    add_class(3)                       # 4 (Object class)
    add_utf8("<init>")                 # 5
    add_utf8("()V")                    # 6
    add_utf8("Code")                   # 7
    add_nat(5, 6)                      # 8 (<init>:()V)
    add_methodref(4, 8)                # 9 (Object.<init>:()V)
    add_utf8("getInstance")            # 10
    add_utf8("()Ljava/lang/Object;")   # 11
    add_methodref(2, 8)                # 12 (This.<init>:()V)
    add_utf8("get")                    # 13
    add_utf8("instance")               # 14
    add_utf8("getMinecraft")           # 15
    add_utf8(typed_desc)               # 16
    add_utf8("INSTANCE")               # 17
    add_utf8(field_desc)               # 18
    add_nat(17, 18)                    # 19 (INSTANCE:LThis;)
    add_fieldref(2, 19)                # 20 (This.INSTANCE)
    add_utf8("<clinit>")               # 21

    # access_flags, this_class, super_class, interfaces_count
    buf.extend(struct.pack(">HHHH", 0x0001, 2, 4, 0))

    # fields: 1 field (public static final INSTANCE)
    buf.extend(struct.pack(">H", 1))
    buf.extend(struct.pack(">HHHH", 0x0019, 17, 18, 0))

    # methods: 7 methods
    buf.extend(struct.pack(">H", 7))

    # 1. <init>()V: aload_0, invokespecial Object.<init>, return
    init_code = b"\x2A\xB7\x00\x09\xB1"
    buf.extend(struct.pack(">HHH", 0x0001, 5, 6))
    buf.extend(struct.pack(">HHIHHI", 1, 7, len(init_code) + 12, 1, 1, len(init_code)))
    buf.extend(init_code)
    buf.extend(struct.pack(">HH", 0, 0))

    # 2. <clinit>()V: new #2, dup, invokespecial #12, putstatic #20, return
    clinit_code = b"\xBB\x00\x02\x59\xB7\x00\x0C\xB3\x00\x14\xB1"
    buf.extend(struct.pack(">HHH", 0x0008, 21, 6))
    buf.extend(struct.pack(">HHIHHI", 1, 7, len(clinit_code) + 12, 2, 0, len(clinit_code)))
    buf.extend(clinit_code)
    buf.extend(struct.pack(">HH", 0, 0))

    # Singleton factory code: getstatic #20 (INSTANCE), areturn
    sing_code = b"\xB2\x00\x14\xB0"

    # 3. getInstance() returning typed this
    buf.extend(struct.pack(">HHH", 0x0009, 10, 16))
    buf.extend(struct.pack(">HHIHHI", 1, 7, len(sing_code) + 12, 1, 0, len(sing_code)))
    buf.extend(sing_code)
    buf.extend(struct.pack(">HH", 0, 0))

    # 4..7 other singleton methods returning Object
    for name_idx in [10, 13, 14, 15]:
        buf.extend(struct.pack(">HHH", 0x0009, name_idx, 11))
        buf.extend(struct.pack(">HHIHHI", 1, 7, len(sing_code) + 12, 1, 0, len(sing_code)))
        buf.extend(sing_code)
        buf.extend(struct.pack(">HH", 0, 0))

    # attributes_count: 0
    buf.extend(struct.pack(">H", 0))
    return bytes(buf)


MOCK_AGENT_JAVA = """package jdec.mock;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

public class MockAgent {
    public static void premain(String agentArgs, Instrumentation inst) {
        inst.addTransformer(new NativeLinkTransformer(), true);
    }

    public static void agentmain(String agentArgs, Instrumentation inst) {
        premain(agentArgs, inst);
    }

    static class NativeLinkTransformer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain, byte[] buf) {
            if (className == null || className.startsWith("java/") || className.startsWith("jdk/") || className.startsWith("sun/")) {
                return null;
            }
            if (buf == null || buf.length < 10) return null;
            if ((buf[0] & 0xFF) != 0xCA || (buf[1] & 0xFF) != 0xFE ||
                (buf[2] & 0xFF) != 0xBA || (buf[3] & 0xFF) != 0xBE) return null;

            try {
                int cpCount = ((buf[8] & 0xFF) << 8) | (buf[9] & 0xFF);
                int pos = 10;
                int[] cpOffsets = new int[cpCount];
                int[] cpTags = new int[cpCount];
                for (int i = 1; i < cpCount; i++) {
                    cpOffsets[i] = pos;
                    int tag = buf[pos++] & 0xFF;
                    cpTags[i] = tag;
                    if (tag == 7 || tag == 8 || tag == 16 || tag == 19 || tag == 20) {
                        pos += 2;
                    } else if (tag == 9 || tag == 10 || tag == 11 || tag == 3 || tag == 4 || tag == 12 || tag == 17 || tag == 18) {
                        pos += 4;
                    } else if (tag == 5 || tag == 6) {
                        pos += 8;
                        i++;
                    } else if (tag == 15) {
                        pos += 3;
                    } else if (tag == 1) {
                        int len = ((buf[pos] & 0xFF) << 8) | (buf[pos + 1] & 0xFF);
                        pos += 2 + len;
                    } else {
                        return null;
                    }
                }

                boolean[] isLoadLibMethodref = new boolean[cpCount];
                boolean hasTarget = false;
                for (int i = 1; i < cpCount; i++) {
                    if (cpTags[i] == 10) {
                        int off = cpOffsets[i] + 1;
                        int clsIdx = ((buf[off] & 0xFF) << 8) | (buf[off + 1] & 0xFF);
                        int natIdx = ((buf[off + 2] & 0xFF) << 8) | (buf[off + 3] & 0xFF);
                        if (clsIdx > 0 && clsIdx < cpCount && cpTags[clsIdx] == 7 &&
                            natIdx > 0 && natIdx < cpCount && cpTags[natIdx] == 12) {
                            int clsNameIdx = ((buf[cpOffsets[clsIdx] + 1] & 0xFF) << 8) | (buf[cpOffsets[clsIdx] + 2] & 0xFF);
                            int natNameIdx = ((buf[cpOffsets[natIdx] + 1] & 0xFF) << 8) | (buf[cpOffsets[natIdx] + 2] & 0xFF);
                            int natDescIdx = ((buf[cpOffsets[natIdx] + 3] & 0xFF) << 8) | (buf[cpOffsets[natIdx] + 4] & 0xFF);

                            if (utf8Equals(buf, cpOffsets, cpTags, clsNameIdx, "java/lang/System") &&
                                (utf8Equals(buf, cpOffsets, cpTags, natNameIdx, "loadLibrary") ||
                                 utf8Equals(buf, cpOffsets, cpTags, natNameIdx, "load")) &&
                                utf8Equals(buf, cpOffsets, cpTags, natDescIdx, "(Ljava/lang/String;)V")) {
                                isLoadLibMethodref[i] = true;
                                hasTarget = true;
                            }
                        }
                    }
                }

                if (!hasTarget) return null;

                byte[] out = buf.clone();
                for (int p = pos; p < out.length - 2; p++) {
                    if ((out[p] & 0xFF) == 0xB8) {
                        int midx = ((out[p + 1] & 0xFF) << 8) | (out[p + 2] & 0xFF);
                        if (midx > 0 && midx < cpCount && isLoadLibMethodref[midx]) {
                            out[p] = (byte) 0x57;     // pop
                            out[p + 1] = (byte) 0x00; // nop
                            out[p + 2] = (byte) 0x00; // nop
                        }
                    }
                }
                return out;
            } catch (Throwable ignored) {
                return null;
            }
        }

        private boolean utf8Equals(byte[] buf, int[] cpOffsets, int[] cpTags, int idx, String str) {
            if (idx <= 0 || idx >= cpTags.length || cpTags[idx] != 1) return false;
            int off = cpOffsets[idx] + 1;
            int len = ((buf[off] & 0xFF) << 8) | (buf[off + 1] & 0xFF);
            byte[] strBytes = str.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            if (len != strBytes.length) return false;
            off += 2;
            for (int i = 0; i < len; i++) {
                if (buf[off + i] != strBytes[i]) return false;
            }
            return true;
        }
    }
}
"""


def build_mock_agent_jar(dest: Path, javac_bin: str = "javac") -> Path:
    """Build a Java Instrumentation Agent jar with Premain-Class to intercept native link errors."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    manifest = (
        "Manifest-Version: 1.0\r\n"
        "Premain-Class: jdec.mock.MockAgent\r\n"
        "Agent-Class: jdec.mock.MockAgent\r\n"
        "Can-Redefine-Classes: true\r\n"
        "Can-Retransform-Classes: true\r\n"
        "\r\n"
    )
    tmp_dir = Path(tempfile.mkdtemp(prefix="jdec_agent_build_"))
    try:
        agent_src = tmp_dir / "jdec" / "mock" / "MockAgent.java"
        agent_src.parent.mkdir(parents=True, exist_ok=True)
        agent_src.write_text(MOCK_AGENT_JAVA, encoding="utf-8")
        javac_resolved = _find_javac(javac_bin)
        cmd = [javac_resolved, str(agent_src)]
        r = subprocess.run(cmd, capture_output=True, text=True,
                           errors="replace", check=False)
        if r.returncode == 0:
            with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("META-INF/MANIFEST.MF", manifest)
                for cls_file in tmp_dir.rglob("*.class"):
                    arcname = cls_file.relative_to(tmp_dir).as_posix()
                    z.write(cls_file, arcname)
            return dest
    except Exception:
        pass
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # Fallback to bytecode builder if javac is unavailable
    agent_bytes = build_stub_class_bytes("jdec/mock/MockAgent")
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("META-INF/MANIFEST.MF", manifest)
        z.writestr("jdec/mock/MockAgent.class", agent_bytes)
    return dest


def ensure_mock_agent_jar(cache_dir: Path | None = None) -> Path:
    """Get or build the cached mock_agent.jar."""
    if cache_dir is None:
        cache_dir = Path(__file__).resolve().parent.parent / "engines"
    cache_dir.mkdir(parents=True, exist_ok=True)
    agent_jar = cache_dir / "mock_agent.jar"
    if not agent_jar.is_file():
        build_mock_agent_jar(agent_jar)
    return agent_jar


