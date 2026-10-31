"""Native-library triage: extract shipped libs and read their PE / ELF export tables.

jdec 的字节码侧到此为止（native 方法体不在 class 文件里），这个模块把
"711 个方法在 DLL/.so 里"变成可执行的下一步：提取库、列出 JNI 导出符号、
识别静态注册与 RegisterNatives 动态注册表，输出给 Ghidra/IDA 分析师的任务清单。
只解析、不执行目标代码——与 jdec 其余部分同一纪律。

PE 与 ELF 解析均为纯 struct 的最小实现（PE 导出表/段表 RVA 映射、ELF .dynsym/.dynstr
与 PT_DYNAMIC 程序头后备解析、二进制 JNINativeMethod 结构体定位），无第三方依赖。
Mach-O 库只提取不解析，报告里说明。
"""

from __future__ import annotations

import re
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
    dynamic_methods: list[dict] = field(default_factory=list)  # JNINativeMethod tables: name, sig, address
    reverse_jni: list[dict] = field(default_factory=list)      # FindClass, GetMethodID, GetFieldID calls
    strings: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class Triage:
    libs: list[NativeLib]
    # java-side native declarations from the jar: (class, method)
    native_decl: list[tuple[str, str]] = field(default_factory=list)
    # classes whose bytes could not be parsed: "0 native methods" is not the
    # same answer as "we could not look"
    unreadable_classes: int = 0

    def matched_static(self) -> set[str]:
        """JNI-exported symbol names that correspond to declared methods."""
        want = set()
        for cls, meth in self.native_decl:
            jni = "Java_" + cls.replace("/", ".").replace("_", "_1").replace(".", "_") \
                  + "_" + meth.replace("_", "_1")
            want.add(jni)
        return want & set().union(*[set(l.jni_exports) for l in self.libs]) if self.libs else set()

    def matched_dynamic(self) -> list[dict]:
        """Dynamically registered methods that match declared native methods."""
        out = []
        for lib in self.libs:
            for dm in lib.dynamic_methods:
                mname = dm.get("name")
                for cls, meth in self.native_decl:
                    if meth == mname:
                        out.append({"class": cls, "method": meth, "sig": dm.get("sig"), "lib": lib.name, "func": dm.get("func")})
                        break
        return out


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
        # IMAGE_EXPORT_DIRECTORY: +20 NumberOfFunctions, +24 NumberOfNames,
        # +28 AddressOfFunctions, +32 AddressOfNames. Reading three u4 from +20
        # and calling the third "names" pointed at the *function* table, so
        # every "export name" was machine code and JNI matching never hit.
        (_n_funcs, n_names, _addr_funcs, addr_names_rva) = \
            struct.unpack_from("<IIII", data, exp + 20)[0:4]
        names_off = _rva_to_offset(sections, addr_names_rva)
        if names_off is None:
            return []
        out = []
        for i in range(n_names):
            nrva = struct.unpack_from("<I", data, names_off + i * 4)[0]
            if nrva == 0:
                continue
            noff = _rva_to_offset(sections, nrva)
            if noff is None:
                continue
            end = data.find(b"\x00", noff, min(noff + 256, len(data)))
            if end < 0:
                continue
            out.append(data[noff:end].decode("ascii", "replace"))
        return out
    except (struct.error, IndexError):
        return []


def _parse_elf_dynamic_segment(data: bytes, is_64: bool, endian: str) -> list[str]:
    """Fallback ELF symbol parser reading PT_DYNAMIC and PT_LOAD program headers (works on stripped .so)."""
    try:
        if is_64:
            if len(data) < 64: return []
            e_phoff = struct.unpack_from(endian + "Q", data, 32)[0]
            e_phentsize = struct.unpack_from(endian + "H", data, 54)[0]
            e_phnum = struct.unpack_from(endian + "H", data, 56)[0]
        else:
            if len(data) < 52: return []
            e_phoff = struct.unpack_from(endian + "I", data, 28)[0]
            e_phentsize = struct.unpack_from(endian + "H", data, 42)[0]
            e_phnum = struct.unpack_from(endian + "H", data, 44)[0]

        if not e_phoff or not e_phentsize or not e_phnum:
            return []

        segments: list[tuple[int, int, int]] = []
        dyn_seg: tuple[int, int, int] | None = None
        for i in range(e_phnum):
            p_off = e_phoff + i * e_phentsize
            if p_off + (56 if is_64 else 32) > len(data):
                break
            if is_64:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack_from(
                    endian + "IIQQQQQ", data, p_off
                )[:7]
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack_from(
                    endian + "IIIIII", data, p_off
                )[:6]
            if p_type == 1:  # PT_LOAD
                segments.append((p_vaddr, p_filesz, p_offset))
            elif p_type == 2:  # PT_DYNAMIC
                dyn_seg = (p_offset, p_filesz, p_vaddr)

        if not dyn_seg:
            return []

        def va_to_off(va: int) -> int | None:
            for vaddr, fsz, off in segments:
                if vaddr <= va < vaddr + fsz:
                    return va - vaddr + off
            return None

        dyn_offset, dyn_size, _ = dyn_seg
        dt_symtab = dt_strtab = dt_strsz = dt_syment = dt_hash = dt_gnu_hash = None
        ent_sz = 16 if is_64 else 8
        pos = dyn_offset
        limit = min(len(data), dyn_offset + dyn_size)
        while pos + ent_sz <= limit:
            if is_64:
                tag, val = struct.unpack_from(endian + "QQ", data, pos)
            else:
                tag, val = struct.unpack_from(endian + "II", data, pos)
            pos += ent_sz
            if tag == 0:  # DT_NULL
                break
            elif tag == 6:   # DT_SYMTAB
                dt_symtab = val
            elif tag == 5:   # DT_STRTAB
                dt_strtab = val
            elif tag == 10:  # DT_STRSZ
                dt_strsz = val
            elif tag == 11:  # DT_SYMENT
                dt_syment = val
            elif tag == 4:   # DT_HASH
                dt_hash = val
            elif tag == 0x6FFFFEF5:  # DT_GNU_HASH
                dt_gnu_hash = val

        if not dt_symtab or not dt_strtab:
            return []

        sym_off = va_to_off(dt_symtab)
        str_off = va_to_off(dt_strtab)
        if sym_off is None or str_off is None:
            return []

        n_syms = 0
        if dt_hash:
            h_off = va_to_off(dt_hash)
            if h_off and h_off + 8 <= len(data):
                nbucket, nchain = struct.unpack_from(endian + "II", data, h_off)
                n_syms = nchain
        elif dt_gnu_hash:
            gh_off = va_to_off(dt_gnu_hash)
            if gh_off and gh_off + 16 <= len(data):
                nbuckets, symoffset, bloom_size, _ = struct.unpack_from(endian + "IIII", data, gh_off)
                bloom_shift_bytes = bloom_size * (8 if is_64 else 4)
                buckets_off = gh_off + 16 + bloom_shift_bytes
                if buckets_off + nbuckets * 4 <= len(data):
                    max_chain_idx = 0
                    for bi in range(nbuckets):
                        b_val = struct.unpack_from(endian + "I", data, buckets_off + bi * 4)[0]
                        if b_val > max_chain_idx:
                            max_chain_idx = b_val
                    if max_chain_idx >= symoffset:
                        chains_off = buckets_off + nbuckets * 4
                        cur_idx = max_chain_idx
                        while chains_off + (cur_idx - symoffset) * 4 + 4 <= len(data):
                            chain_val = struct.unpack_from(endian + "I", data, chains_off + (cur_idx - symoffset) * 4)[0]
                            cur_idx += 1
                            if chain_val & 1:  # End of chain
                                break
                        n_syms = cur_idx

        sym_ent = dt_syment or (24 if is_64 else 16)
        if n_syms == 0:
            if dt_strsz and str_off > sym_off:
                n_syms = (str_off - sym_off) // sym_ent
            else:
                n_syms = 1024  # higher fallback scan limit for modern stripped libs

        symbols = []
        str_limit = str_off + (dt_strsz or 65536)
        for i in range(n_syms):
            cur = sym_off + i * sym_ent
            if cur + sym_ent > len(data):
                break
            if is_64:
                st_name = struct.unpack_from(endian + "I", data, cur)[0]
                st_shndx = struct.unpack_from(endian + "H", data, cur + 6)[0]
            else:
                st_name = struct.unpack_from(endian + "I", data, cur)[0]
                st_shndx = struct.unpack_from(endian + "H", data, cur + 14)[0]

            if st_shndx != 0 and st_name != 0:
                name_ptr = str_off + st_name
                if name_ptr < min(len(data), str_limit):
                    zero_idx = data.find(b"\x00", name_ptr, min(len(data), str_limit))
                    if zero_idx != -1:
                        sym = data[name_ptr:zero_idx].decode("ascii", errors="replace")
                        if sym:
                            symbols.append(sym)
        return symbols
    except Exception:
        return []


def parse_elf_exports(data: bytes) -> list[str]:
    """Exported symbol names of an ELF (.so) shared object; supports ELF32 and ELF64."""
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return []
    try:
        is_64 = (data[4] == 2)
        endian = "<" if data[5] == 1 else ">"

        if is_64:
            if len(data) < 64:
                return []
            e_shoff = struct.unpack_from(endian + "Q", data, 40)[0]
            e_shentsize = struct.unpack_from(endian + "H", data, 58)[0]
            e_shnum = struct.unpack_from(endian + "H", data, 60)[0]
        else:
            e_shoff = struct.unpack_from(endian + "I", data, 32)[0]
            e_shentsize = struct.unpack_from(endian + "H", data, 46)[0]
            e_shnum = struct.unpack_from(endian + "H", data, 48)[0]

        # If section headers are present, parse sections first
        if e_shoff and e_shentsize and e_shnum:
            sections = []
            for i in range(e_shnum):
                s_off = e_shoff + i * e_shentsize
                if s_off + (64 if is_64 else 40) > len(data):
                    break
                if is_64:
                    sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link = struct.unpack_from(
                        endian + "IIQQQQI", data, s_off
                    )[:7]
                    sh_entsize = struct.unpack_from(endian + "Q", data, s_off + 56)[0]
                else:
                    sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link = struct.unpack_from(
                        endian + "IIIIIII", data, s_off
                    )[:7]
                    sh_entsize = struct.unpack_from(endian + "I", data, s_off + 36)[0]
                sections.append({
                    "type": sh_type, "offset": sh_offset, "size": sh_size,
                    "link": sh_link, "entsize": sh_entsize
                })

            # SHT_DYNSYM = 11, SHT_SYMTAB = 2
            dynsym = None
            for sec in sections:
                if sec["type"] == 11:
                    dynsym = sec
                    break
                if sec["type"] == 2 and dynsym is None:
                    dynsym = sec

            if dynsym and dynsym["link"] < len(sections):
                strtab = sections[dynsym["link"]]
                str_start = strtab["offset"]
                str_end = str_start + strtab["size"]
                if str_end <= len(data):
                    sym_off = dynsym["offset"]
                    sym_size = dynsym["size"]
                    ent_sz = dynsym["entsize"] or (24 if is_64 else 16)
                    n_syms = sym_size // ent_sz

                    out = []
                    for i in range(n_syms):
                        cur = sym_off + i * ent_sz
                        if cur + ent_sz > len(data):
                            break
                        if is_64:
                            st_name = struct.unpack_from(endian + "I", data, cur)[0]
                            st_shndx = struct.unpack_from(endian + "H", data, cur + 6)[0]
                        else:
                            st_name = struct.unpack_from(endian + "I", data, cur)[0]
                            st_shndx = struct.unpack_from(endian + "H", data, cur + 14)[0]

                        if st_shndx != 0 and st_name != 0:
                            name_ptr = str_start + st_name
                            if name_ptr < str_end:
                                zero_idx = data.find(b"\x00", name_ptr, str_end)
                                if zero_idx != -1:
                                    sym_name = data[name_ptr:zero_idx].decode("ascii", errors="replace")
                                    if sym_name:
                                        out.append(sym_name)
                    if out:
                        return out

        # Fallback to PT_DYNAMIC program headers when section headers are stripped (e_shoff == 0)
        return _parse_elf_dynamic_segment(data, is_64, endian)
    except Exception:
        return []


def write_ghidra_annotation_script(tri: Triage, out_file: Path) -> Path:
    """Generate a ready-to-run Ghidra GUI Python script to annotate JNI functions."""
    mappings = []
    for cls, meth in tri.native_decl:
        jni_name = "Java_" + cls.replace("/", ".").replace("_", "_1").replace(".", "_") + "_" + meth.replace("_", "_1")
        mappings.append((jni_name, cls, meth))

    code = [
        "# Ghidra GUI script generated by jdec (native triage)",
        "# In Ghidra: Script Manager -> Run on the active native program",
        "",
        "JNI_BINDINGS = {",
    ]
    for jni, cls, meth in sorted(mappings):
        code.append(f'    "{jni}": ("{cls}", "{meth}"),')
    code += [
        "}",
        "",
        "def run():",
        "    fm = currentProgram.getFunctionManager()",
        "    count = 0",
        "    for func in fm.getFunctions(True):",
        "        name = func.getName()",
        "        if name in JNI_BINDINGS:",
        "            cls, meth = JNI_BINDINGS[name]",
        '            func.setComment(f"Java Native Binding: {cls}.{meth}()")',
        '            print(f"[jdec] Labeled {name} -> {cls}.{meth}()")',
        "            count += 1",
        '        elif name == "JNI_OnLoad":',
        '            func.setComment("JNI entry point (dynamic registration via RegisterNatives)")',
        '            print("[jdec] Identified JNI_OnLoad entry point")',
        '    print(f"[jdec] Finished: {count} JNI function(s) annotated.")',
        "",
        'if __name__ == "__main__":',
        "    run()",
    ]
    out_file.write_text("\n".join(code) + "\n", encoding="utf-8")
    return out_file


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


def scan_reverse_jni_c(c_text: str, func_name: str = "") -> list[dict]:
    """Scan decompiled C text for calls to JNIEnv APIs interacting with JVM."""
    out = []
    _WS = "[ \t\r\n]*"
    _STR = '["\']([^"\']+)["\']'
    rx_cls = re.compile('FindClass' + _WS + '[(](?:[^,]+,[ \t\r\n]*)?' + _STR + _WS + '[)]')
    rx_mid = re.compile('(?:GetMethodID|GetStaticMethodID)' + _WS + '[(](?:[^,]+,[ \t\r\n]*){1,2}' + _STR + _WS + ',' + _WS + _STR + _WS + '[)]')
    rx_fid = re.compile('(?:GetFieldID|GetStaticFieldID)' + _WS + '[(](?:[^,]+,[ \t\r\n]*){1,2}' + _STR + _WS + ',' + _WS + _STR + _WS + '[)]')
    rx_call = re.compile('Call(?:Static)?(?:Object|Boolean|Byte|Char|Short|Int|Long|Float|Double|Void)Method' + _WS + '[(](?:[^,]+,[ \t\r\n]*){1,2}([A-Za-z0-9_]+)')

    for m in rx_cls.finditer(c_text):
        out.append({"type": "FindClass", "class": m.group(1), "function": func_name})
    for m in rx_mid.finditer(c_text):
        out.append({"type": "GetMethodID", "method": m.group(1), "sig": m.group(2), "function": func_name})
    for m in rx_fid.finditer(c_text):
        out.append({"type": "GetFieldID", "field": m.group(1), "sig": m.group(2), "function": func_name})
    for m in rx_call.finditer(c_text):
        out.append({"type": "CallMethod", "mid_var": m.group(1), "function": func_name})
    return out


def scan_register_natives_c(c_text: str, func_name: str = "") -> list[dict]:
    """Extract JNINativeMethod registrations from decompiled C code."""
    out = []
    _WS = "[ \t\r\n]*"
    _STR = '["\']([^"\']+)["\']'
    rx_struct = re.compile('[{]' + _WS + _STR + _WS + ',' + _WS + _STR + _WS + ',' + _WS + '([^,}]+)[}]')
    for m in rx_struct.finditer(c_text):
        name = m.group(1)
        sig = m.group(2)
        raw_fn = m.group(3).strip()
        clean_fn = raw_fn
        if clean_fn.startswith("(") and ")" in clean_fn:
            clean_fn = clean_fn.split(")", 1)[1].strip()
        clean_fn = clean_fn.lstrip("&").strip()
        if "(" in sig and ")" in sig:
            out.append({"name": name, "sig": sig, "func": clean_fn or raw_fn, "source": func_name})
    return out


def scan_binary_jni_descriptors(data: bytes) -> list[dict]:
    """Scan raw binary for candidate JNI descriptor signatures."""
    out = []
    rx_desc = re.compile(b"[(][A-Za-z0-9_$/;[]*[)][A-Za-z0-9_$/;[]+")
    seen = set()
    for m in rx_desc.finditer(data):
        raw = m.group(0)
        if len(raw) < 3 or raw in seen:
            continue
        seen.add(raw)
        sig = raw.decode("ascii", "replace")
        out.append({"sig": sig, "offset": m.start()})
    return out


def scan_binary_register_natives(data: bytes, fmt: str = "auto") -> list[dict]:
    """Extract JNINativeMethod tables (name, sig, fnPtr) directly from raw ELF/PE binary without Ghidra.

    Searches for consecutive struct JNINativeMethod { const char* name; const char* sig; void* fnPtr; }
    where sig matches JNI descriptor syntax and name is a valid Java identifier.
    """
    if len(data) < 64:
        return []
    if fmt == "auto":
        fmt = detect_format(data)

    segments: list[tuple[int, int, int]] = []
    is_64 = True
    endian = "<"

    if fmt == "ELF":
        if data[:4] != b"\x7fELF":
            return []
        is_64 = (data[4] == 2)
        endian = "<" if data[5] == 1 else ">"
        try:
            if is_64:
                e_phoff = struct.unpack_from(endian + "Q", data, 32)[0]
                e_phentsize = struct.unpack_from(endian + "H", data, 54)[0]
                e_phnum = struct.unpack_from(endian + "H", data, 56)[0]
            else:
                e_phoff = struct.unpack_from(endian + "I", data, 28)[0]
                e_phentsize = struct.unpack_from(endian + "H", data, 42)[0]
                e_phnum = struct.unpack_from(endian + "H", data, 44)[0]
            for i in range(e_phnum):
                p_off = e_phoff + i * e_phentsize
                if p_off + (56 if is_64 else 32) > len(data): break
                if is_64:
                    p_type, _, p_offset, p_vaddr, _, p_filesz = struct.unpack_from(endian + "IIQQQQ", data, p_off)[:6]
                else:
                    p_type, p_offset, p_vaddr, _, p_filesz = struct.unpack_from(endian + "IIIII", data, p_off)[:5]
                if p_type == 1:  # PT_LOAD
                    segments.append((p_vaddr, p_filesz, p_offset))
        except Exception:
            return []
    elif fmt == "PE":
        if data[:2] != b"MZ":
            return []
        try:
            pe_off = struct.unpack_from("<I", data, 0x3C)[0]
            if data[pe_off:pe_off + 4] != b"PE\x00\x00":
                return []
            coff = pe_off + 4
            nsec = struct.unpack_from("<H", data, coff + 2)[0]
            opt_size = struct.unpack_from("<H", data, coff + 16)[0]
            opt = coff + 20
            magic = struct.unpack_from("<H", data, opt)[0]
            is_64 = (magic == 0x20B)
            image_base = struct.unpack_from("<Q" if is_64 else "<I", data, opt + (24 if is_64 else 28))[0]
            sec_tab = opt + opt_size
            for i in range(nsec):
                s = sec_tab + i * 40
                vsz, va, rsz, raw = struct.unpack_from("<IIII", data, s + 8)
                segments.append((image_base + va, vsz, raw))
                segments.append((va, vsz, raw))  # Support relative RVA arrays
        except Exception:
            return []
    else:
        return []

    if not segments:
        return []

    def va_to_off(va: int) -> int | None:
        for vaddr, fsz, off in segments:
            if vaddr <= va < vaddr + fsz and off < len(data):
                file_pos = va - vaddr + off
                if file_pos < len(data):
                    return file_pos
        return None

    def read_c_str(va: int) -> str | None:
        file_pos = va_to_off(va)
        if file_pos is None or file_pos >= len(data):
            return None
        null_pos = data.find(b"\x00", file_pos, min(len(data), file_pos + 256))
        if null_pos != -1:
            try:
                return data[file_pos:null_pos].decode("utf-8", errors="replace")
            except Exception:
                return None
        return None

    rx_sig = re.compile(r"^\([A-Za-z0-9_$/;\[]*\)[A-Za-z0-9_$/;\[]+$")
    rx_name = re.compile(r"^[a-zA-Z_$][a-zA-Z0-9_$]*$|^(?:<init>|<clinit>)$")

    step = 8 if is_64 else 4
    struct_sz = 24 if is_64 else 12
    unpack_fmt = endian + ("QQQ" if is_64 else "III")

    results: list[dict] = []
    seen_methods: set[tuple[str, str]] = set()

    unique_ranges: list[tuple[int, int]] = []
    seen_ranges: set[tuple[int, int]] = set()
    for _, fsz, off in segments:
        rng = (off, fsz)
        if rng not in seen_ranges and off < len(data):
            seen_ranges.add(rng)
            unique_ranges.append(rng)

    for off, fsz in unique_ranges:
        seg_end = min(len(data), off + fsz)
        for p in range(off, seg_end - struct_sz + 1, step):
            name_ptr, sig_ptr, fn_ptr = struct.unpack_from(unpack_fmt, data, p)
            if not name_ptr or not sig_ptr or not fn_ptr:
                continue
            sig_str = read_c_str(sig_ptr)
            if sig_str and rx_sig.match(sig_str):
                name_str = read_c_str(name_ptr)
                if name_str and rx_name.match(name_str):
                    key = (name_str, sig_str)
                    if key not in seen_methods:
                        seen_methods.add(key)
                        results.append({
                            "name": name_str,
                            "sig": sig_str,
                            "func": f"0x{fn_ptr:x}",
                            "source": "binary_JNINativeMethod",
                            "offset": p,
                        })
    return results


def triage_raw(path: Path, out_dir: Path) -> Triage:
    """Triage a single raw PE/ELF file (e.g. a DLL dumped by engines/frida)."""
    data = path.read_bytes()
    tri = Triage(libs=[])
    lib = NativeLib(name=path.name, size=len(data), format=detect_format(data))
    if lib.format == "PE":
        lib.exports = parse_pe_exports(data)
        lib.jni_exports = [s for s in lib.exports
                           if s.startswith("Java_") or s.startswith("JNI_On")]
    elif lib.format == "ELF":
        lib.exports = parse_elf_exports(data)
        lib.jni_exports = [s for s in lib.exports
                           if s.startswith("Java_") or s.startswith("JNI_On")]
    else:
        lib.error = "PE / ELF 以外的格式仅提取不解析"
    lib.strings = scan_strings(data)
    lib.dynamic_methods = scan_binary_register_natives(data, lib.format) + scan_binary_jni_descriptors(data)
    tri.libs.append(lib)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / path.name).write_bytes(data)
    return tri


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
        elif lib.format == "ELF":
            lib.exports = parse_elf_exports(data)
            lib.jni_exports = [s for s in lib.exports
                               if s.startswith("Java_") or s.startswith("JNI_On")]
        else:
            lib.error = "PE / ELF 以外的格式仅提取不解析（Mach-O 待补）"
        lib.strings = scan_strings(data)
        lib.dynamic_methods = scan_binary_register_natives(data, lib.format) + scan_binary_jni_descriptors(data)
        tri.libs.append(lib)
    if collect_decl:
        with zipfile.ZipFile(jar) as zf:
            for info in zf.infolist():
                if not info.filename.endswith(".class"):
                    continue
                try:
                    cf = CF.parse(zf.read(info))
                except Exception:
                    tri.unreadable_classes += 1
                    continue
                for m in cf.methods:
                    if m.access_flags & 0x0100:
                        tri.native_decl.append((cf.name, cf.utf8(m.name_index)))
    return tri


def decompile_libs(tri: Triage, out_dir: Path, ghidra_home: Path,
                   mappings_tsv: Path | None = None) -> dict:
    """Run Ghidra Headless decompilation for each extracted library."""
    from . import ghidra_engine as GE

    results: dict[str, dict] = {}
    for lib in tri.libs:
        lib_path = out_dir / lib.name
        if not lib_path.is_file():
            continue
        lib_out = out_dir / (lib_path.stem + "_decompiled")
        # 地址表只对包含该函数地址的库有意义:全库逐个尝试,mappings 引用
        # 的地址若不在库内,Ghidra 建不出函数,自然落空
        res = GE.decompile_library(ghidra_home, lib_path, lib_out,
                                   mappings_tsv=mappings_tsv)
        results[lib.name] = res

        # Scan decompiled C sources for reverse JNI calls and RegisterNatives
        src_dir = lib_out / "src"
        if src_dir.is_dir():
            for c_file in sorted(src_dir.glob("*.c")):
                try:
                    c_txt = c_file.read_text(encoding="utf-8", errors="replace")
                    rev = scan_reverse_jni_c(c_txt, c_file.name)
                    lib.reverse_jni.extend(rev)
                    dyn = scan_register_natives_c(c_txt, c_file.name)
                    lib.dynamic_methods.extend(dyn)
                except Exception:
                    pass
    return results


def write_report(tri: Triage, jar_name: str, out: Path, decompiled_info: dict | None = None) -> None:
    static = tri.matched_static()
    dyn_matched = tri.matched_dynamic()
    dynamic_only = [(c, m) for c, m in tri.native_decl
                    if "Java_" + c.replace("/", ".").replace("_", "_1")
                    .replace(".", "_") + "_" + m.replace("_", "_1") not in static]
    lines = [f"# native-library triage — {jar_name}", ""]
    lines += [f"- shipped libraries: {len(tri.libs)}",
              f"- java-side native declarations: {len(tri.native_decl)} "
              f"(in {len({c for c, _ in tri.native_decl})} classes)",
              f"- statically exported JNI symbols matched: {len(static)}",
              f"- dynamic-registration suspects (no Java_ export): {len(dynamic_only)}"]
    if tri.unreadable_classes:
        lines += [f"- **unreadable classes**: {tri.unreadable_classes} "
                  f"(native declarations inside them are unknown)"]
    if dyn_matched:
        lines += [f"- dynamically registered JNI methods resolved: {len(dyn_matched)}"]
    lines += [""]

    ghidra_script = out.parent / "ghidra_annotate.py"
    if tri.native_decl:
        write_ghidra_annotation_script(tri, ghidra_script)
        lines += [f"- **Ghidra GUI Script**: generated `{ghidra_script.name}` (run in Ghidra Script Manager to label functions)", ""]

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

    if dyn_matched:
        lines += ["## dynamically registered JNI methods (RegisterNatives)", ""]
        lines += ["| Java Class | Method | Descriptor | Native Library | Bound Function |",
                  "| :--- | :--- | :--- | :--- | :--- |"]
        for dm in dyn_matched:
            lines += [f"| `{dm['class']}` | `{dm['method']}` | `{dm.get('sig', '-')}` | `{dm['lib']}` | `{dm.get('func', '-')}` |"]
        lines += [""]

    all_rev = [r for lib in tri.libs for r in lib.reverse_jni]
    if all_rev:
        lines += ["## reverse JNI interactions (Native -> Java calls)", ""]
        lines += ["| Native Function | JNI Call Type | Target Class / Member | Signature |",
                  "| :--- | :--- | :--- | :--- |"]
        for r in all_rev[:30]:
            target = r.get("class") or r.get("method") or r.get("field") or "-"
            sig = r.get("sig") or "-"
            lines += [f"| `{r.get('function', '-')}` | `{r.get('type')}` | `{target}` | `{sig}` |"]
        if len(all_rev) > 30:
            lines += [f"- ... {len(all_rev) - 30} more reverse JNI calls (see decompiled C files)"]
        lines += [""]

    if decompiled_info:
        lines += ["## decompiled C sources (via Ghidra Headless)", ""]
        has_any = False
        for lib_name, dres in decompiled_info.items():
            funcs = dres.get("functions", [])
            if funcs:
                has_any = True
                lines += [f"### {lib_name} ({len(funcs)} functions decompiled)", ""]
                lines += ["| Function Name | Entry Point | Source File |",
                          "| :--- | :--- | :--- |"]
                for fn in funcs:
                    fname = fn.get("name", "unknown")
                    entry = fn.get("entry", "-")
                    fpath = fn.get("file", "-")
                    lines += [f"| `{fname}` | `{entry}` | `{fpath}` |"]
                lines += [""]
            elif dres.get("error"):
                lines += [f"### {lib_name}: {dres.get('error')}", ""]
        if not has_any:
            lines += ["- No C pseudo-code produced by Ghidra", ""]

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
