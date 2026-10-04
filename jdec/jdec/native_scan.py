"""Native-library triage: extract shipped libs and read their PE export table.

jdec 的字节码侧到此为止（native 方法体不在 class 文件里），这个模块把
"711 个方法在 DLL 里"变成可执行的下一步：提取库、列出 JNI 导出符号、
判断静态注册还是 JNI_OnLoad 动态注册，输出给 Ghidra/IDA 分析师的任务清单。
只解析、不执行目标代码——与 jdec 其余部分同一纪律。

PE 解析是纯 struct 的最小实现（导出表 + 段表 RVA 映射），无第三方依赖。
ELF/Mach-O 库只提取不解析，报告里说明。
"""

from __future__ import annotations

import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

NATIVE_EXTS = (".dll", ".so", ".dylib", ".jnilib")


@dataclass
class NativeLib:
    name: str
    size: int
    format: str            # "PE" | "ELF" | "Mach-O" | "unknown"
    exports: list[str] = field(default_factory=list)
    jni_exports: list[str] = field(default_factory=list)   # Java_* / JNI_OnLoad
    strings: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class Triage:
    libs: list[NativeLib]
    # java-side native declarations from the jar: (class, method)
    native_decl: list[tuple[str, str]] = field(default_factory=list)

    def matched_static(self) -> set[str]:
        """JNI-exported symbol names that correspond to declared methods."""
        want = set()
        for cls, meth in self.native_decl:
            jni = "Java_" + cls.replace("/", ".").replace("_", "_1").replace(".", "_") \
                  + "_" + meth.replace("_", "_1")
            want.add(jni)
        return want & set().union(*[set(l.jni_exports) for l in self.libs]) if self.libs else set()


# ---------------------------------------------------------------- PE parsing

def _rva_to_offset(sections: list[tuple[int, int, int]], rva: int) -> int | None:
    """sections: (virtual_address, virtual_size, raw_ptr)."""
    for va, vsz, raw in sections:
        if va <= rva < va + max(vsz, 1 << 20):
            if raw == 0:
                return None
            return rva - va + raw
    return None


def parse_pe_exports(data: bytes) -> list[str]:
    """Exported symbol names of a PE image; empty on any structural surprise."""
    try:
        if data[:2] != b"MZ":
            return []
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_off:pe_off + 4] != b"PE\x00\x00":
            return []
        coff = pe_off + 4
        nsec = struct.unpack_from("<H", data, coff + 2)[0]
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic == 0x20B:      # PE32+
            dd_base = opt + 112
        elif magic == 0x10B:    # PE32
            dd_base = opt + 96
        else:
            return []
        export_rva, export_sz = struct.unpack_from("<II", data, dd_base)
        if not export_rva:
            return []
        sec_tab = opt + opt_size
        sections = []
        for i in range(nsec):
            s = sec_tab + i * 40
            vsz, va, rsz, raw = struct.unpack_from("<I", data, s + 8)[0], \
                struct.unpack_from("<I", data, s + 12)[0], \
                struct.unpack_from("<I", data, s + 16)[0], \
                struct.unpack_from("<I", data, s + 20)[0]
            sections.append((va, vsz, raw))
        exp = _rva_to_offset(sections, export_rva)
        if exp is None:
            return []
        (n_funcs, n_names, addr_names_rva) = struct.unpack_from("<III", data, exp + 20)[0:3]
        names_off = _rva_to_offset(sections, addr_names_rva)
        if names_off is None:
            return []
        out = []
        for i in range(n_names):
            nrva = struct.unpack_from("<I", data, names_off + i * 4)[0]
            noff = _rva_to_offset(sections, nrva)
            if noff is None:
                continue
            end = data.find(b"\x00", noff)
            out.append(data[noff:end].decode("ascii", "replace"))
        return out
    except (struct.error, IndexError):
        return []


def scan_strings(data: bytes, min_len: int = 5, limit: int = 4000) -> list[str]:
    """ASCII printable runs; the cheapest cross-check against Java-side constants."""
    out, cur = [], bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii"))
                if len(out) >= limit:
                    break
            cur.clear()
    if len(cur) >= min_len and len(out) < limit:
        out.append(cur.decode("ascii"))
    return out


# ------------------------------------------------------------------ pipeline

def detect_format(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "PE"
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "Mach-O"
    return "unknown"


def extract_libs(jar: Path, out_dir: Path) -> list[tuple[str, bytes]]:
    with zipfile.ZipFile(jar) as zf:
        found = [(n, zf.read(n)) for n in zf.namelist()
                 if n.lower().endswith(NATIVE_EXTS)]
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, data in found:
        (out_dir / Path(name).name).write_bytes(data)
    return found


def triage(jar: Path, out_dir: Path, collect_decl=True) -> Triage:
    from . import classfile as CF       # 延迟导入：仅 jar 路径才付出解析成本

    libs = extract_libs(jar, out_dir)
    tri = Triage(libs=[])
    for name, data in libs:
        lib = NativeLib(name=Path(name).name, size=len(data),
                        format=detect_format(data))
        if lib.format == "PE":
            lib.exports = parse_pe_exports(data)
            lib.jni_exports = [s for s in lib.exports
                               if s.startswith("Java_") or s.startswith("JNI_On")]
        else:
            lib.error = "PE 以外的格式仅提取不解析（ELF/Mach-O 待补）"
        lib.strings = scan_strings(data)
        tri.libs.append(lib)
    if collect_decl:
        with zipfile.ZipFile(jar) as zf:
            for info in zf.infolist():
                if not info.filename.endswith(".class"):
                    continue
                try:
                    cf = CF.parse(zf.read(info))
                except CF.ClassFormatError:
                    continue
                for m in cf.methods:
                    if m.access_flags & 0x0100:
                        tri.native_decl.append((cf.name, cf.utf8(m.name_index)))
    return tri


def write_report(tri: Triage, jar_name: str, out: Path) -> None:
    static = tri.matched_static()
    dynamic_only = [(c, m) for c, m in tri.native_decl
                    if "Java_" + c.replace("/", ".").replace("_", "_1")
                    .replace(".", "_") + "_" + m.replace("_", "_1") not in static]
    lines = [f"# native-library triage — {jar_name}", ""]
    lines += [f"- shipped libraries: {len(tri.libs)}",
              f"- java-side native declarations: {len(tri.native_decl)} "
              f"(in {len({c for c, _ in tri.native_decl})} classes)",
              f"- statically exported JNI symbols matched: {len(static)}",
              f"- dynamic-registration suspects (no Java_ export): {len(dynamic_only)}",
              ""]
    for lib in tri.libs:
        lines += [f"## {lib.name} ({lib.size / 1048576:.1f} MB, {lib.format})", ""]
        if lib.error:
            lines += [f"- {lib.error}", ""]
        lines += [f"- exports: {len(lib.exports)} total, "
                  f"{len(lib.jni_exports)} JNI-related",
                  f"- strings ≥5 chars: {len(lib.strings)}"]
        if lib.jni_exports:
            show = ", ".join(lib.jni_exports[:12])
            lines += [f"- JNI symbols (first 12): `{show}`"]
        lines += [""]
    lines += ["## next steps for a Ghidra/IDA analyst", ""]
    if tri.libs:
        lines += ["1. load the extracted libraries from this output directory"]
    if any(not lib.jni_exports and lib.format == "PE" for lib in tri.libs):
        lines += ["2. no Java_* exports but Java side declares natives → "
                  "methods are registered dynamically: start at `JNI_OnLoad`, "
                  "find `RegisterNatives` calls to recover the method↔function map"]
    if static:
        lines += [f"3. {len(static)} statically exported JNI symbols map 1:1 to "
                  "declared methods — disassemble those addresses directly"]
    interesting = [s for lib in tri.libs for s in lib.strings
                   if any(k in s.lower() for k in
                          ("http", ".com", ".cn", "token", "hwid", "license",
                           "auth", "discord", "api"))]
    if interesting:
        lines += ["4. suspicious strings inside the libraries (verify in disassembly):"]
        seen = set()
        for s in interesting[:40]:
            if s not in seen:
                seen.add(s)
                lines += [f"   - `{s}`"]
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
