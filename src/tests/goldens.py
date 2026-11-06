"""Independent ground truth for the stage-04 acceptance run.

Nothing here imports a jdec analysis module.  Every fact is recomputed from
the container bytes, the class-file structure or the PE/COFF headers, so it
can be compared against a mechanism's own output without the mechanism
certifying itself.  It is a second implementation, not a third-party
oracle: it guards against implementation bugs, not against a shared
misreading of the format.

This is deliberately a SECOND, small implementation: a bug shared with the
production parser would not be an independent check.
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
from pathlib import Path

ACC_NATIVE = 0x0100


def magic_of(path: Path) -> str:
    with Path(path).open("rb") as fh:
        return fh.read(2).hex()


def zip_facts(path: Path) -> dict:
    """Raw zip directory: entry count, class count, per-entry sha256."""
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        digests = {}
        for name in names:
            if name.endswith(".class"):
                digests[name] = hashlib.sha256(z.read(name)).hexdigest()
        return {"entries": len(names),
                "class_count": len(digests),
                "class_sha256": digests,
                "names": names}


# ---------------------------------------------------------------------------
# A minimal, independent class-file reader: constant pool, method table and
# the BootstrapMethods attribute count. No Code disassembly is attempted.
# ---------------------------------------------------------------------------

def _u2(data: bytes, off: int) -> int:
    return struct.unpack_from(">H", data, off)[0]


def _u4(data: bytes, off: int) -> int:
    return struct.unpack_from(">I", data, off)[0]


_CP_FIXED = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4,
             12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}


def _constant_pool(data: bytes) -> tuple[list[str | None], int]:
    count = _u2(data, 8)
    pool: list[str | None] = [None] * count
    off = 10
    i = 1
    while i < count:
        tag = data[off]
        off += 1
        if tag == 1:
            length = _u2(data, off)
            off += 2
            pool[i] = data[off:off + length].decode("utf-8", "replace")
            off += length
        elif tag in (5, 6):
            off += _CP_FIXED[tag]
            i += 1                      # long/double take two slots
        else:
            size = _CP_FIXED.get(tag)
            if size is None:
                raise ValueError(f"unsupported constant-pool tag {tag}")
            off += size
        i += 1
    return pool, off


def _skip_attributes(data: bytes, off: int, pool: list[str | None],
                     *, collect_bsm: bool = False) -> tuple[int, int]:
    n = _u2(data, off)
    off += 2
    bsm = 0
    for _ in range(n):
        name = pool[_u2(data, off)] or ""
        length = _u4(data, off + 2)
        body = off + 6
        if collect_bsm and name == "BootstrapMethods":
            bsm += _u2(data, body)
        off = body + length
    return off, bsm


def class_facts(data: bytes) -> dict:
    """UTF-8 constants, ACC_NATIVE method count and BSM entries of one class."""
    if data[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError("not a class file")
    pool, off = _constant_pool(data)
    off += 6                            # access_flags, this_class, super_class
    interfaces = _u2(data, off)
    off += 2 + 2 * interfaces
    fields = _u2(data, off)
    off += 2
    for _ in range(fields):
        off += 6                        # access, name, descriptor
        off, _ = _skip_attributes(data, off, pool)
    methods = _u2(data, off)
    off += 2
    native = 0
    method_names: list[str] = []
    for _ in range(methods):
        flags = _u2(data, off)
        method_names.append(pool[_u2(data, off + 2)] or "?")
        if flags & ACC_NATIVE:
            native += 1
        off += 6
        off, _ = _skip_attributes(data, off, pool)
    _, bsm = _skip_attributes(data, off, pool, collect_bsm=True)
    return {"utf8": [x for x in pool if x is not None],
            "native": native, "bsm_entries": bsm,
            "methods": method_names}


def jar_facts(path: Path) -> dict:
    """Aggregate independent facts over every class in a jar."""
    with zipfile.ZipFile(path) as z:
        names = [n for n in z.namelist() if n.endswith(".class")]
        utf8: list[str] = []
        native = 0
        bsm = 0
        readable = 0
        for name in names:
            raw = z.read(name)
            if raw[:4] != b"\xca\xfe\xba\xbe":
                continue
            try:
                facts = class_facts(raw)
            except (ValueError, struct.error, IndexError):
                continue
            readable += 1
            utf8.extend(facts["utf8"])
            native += facts["native"]
            bsm += facts["bsm_entries"]
        return {"class_count": len(names), "readable": readable,
                "utf8_count": len(utf8), "unique_utf8": len(set(utf8)),
                "native_methods": native, "bsm_entries": bsm,
                "constants": set(utf8)}


# ---------------------------------------------------------------------------
# Independent PE/COFF export-directory reader for the MZ self-extracting stub.
# ---------------------------------------------------------------------------

def pe_exports(data: bytes) -> dict:
    """Parse the PE export table without using jdec's native_scan."""
    if data[:2] != b"MZ":
        return {"is_pe": False, "exports": []}
    e_lfanew = _u4_le(data, 0x3c)
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return {"is_pe": False, "exports": []}
    coff = e_lfanew + 4
    n_sections = _u2_le(data, coff + 2)
    opt_size = _u2_le(data, coff + 16)
    opt = coff + 20
    magic = _u2_le(data, opt)
    dd_off = opt + (112 if magic == 0x20b else 96)
    export_rva = _u4_le(data, dd_off)
    if not export_rva:
        return {"is_pe": True, "exports": []}
    sec = opt + opt_size
    sections = []
    for i in range(n_sections):
        base = sec + 40 * i
        sections.append((_u4_le(data, base + 12),   # VirtualAddress
                         _u4_le(data, base + 8),    # VirtualSize
                         _u4_le(data, base + 20),   # PointerToRawData
                         _u4_le(data, base + 16)))  # SizeOfRawData

    def rva_to_off(rva: int) -> int:
        for va, vsize, praw, sraw in sections:
            if va <= rva < va + max(vsize, sraw):
                return praw + (rva - va)
        return -1

    exp = rva_to_off(export_rva)
    if exp < 0 or exp + 40 > len(data):
        return {"is_pe": True, "exports": []}
    n_names = _u4_le(data, exp + 24)
    names_rva = _u4_le(data, exp + 32)
    table = rva_to_off(names_rva)
    out = []
    if table >= 0:
        for i in range(min(n_names, 4096)):
            ptr = rva_to_off(_u4_le(data, table + 4 * i))
            if ptr < 0:
                continue
            end = data.find(b"\0", ptr, min(ptr + 512, len(data)))
            if end > ptr:
                out.append(data[ptr:end].decode("ascii", "replace"))
    return {"is_pe": True, "exports": out}


def _u2_le(data: bytes, off: int) -> int:
    if off + 2 > len(data):
        return 0
    return struct.unpack_from("<H", data, off)[0]


def _u4_le(data: bytes, off: int) -> int:
    if off + 4 > len(data):
        return 0
    return struct.unpack_from("<I", data, off)[0]


def native_facts(path: Path) -> dict:
    """Exports of the embedded PE, or of the file itself when it is a PE."""
    with Path(path).open("rb") as fh:
        data = fh.read()
    result = pe_exports(data)
    # A self-extracting exe has a zip appended; the PE parser above already
    # reads the leading stub, which is exactly what native_scan extracts.
    result["export_count"] = len(result["exports"])
    return result


_NATIVE_EXTS = (".dll", ".so", ".dylib", ".jnilib")


def des_markers(path: Path) -> dict:
    """Counts of the constants that would justify a ZKM/DES attribution.

    Read from the constant-pool strings, so an attribution that has no such
    marker in the corpus is a false positive by construction.
    """
    constants = jar_facts(path)["constants"]
    return {k: sum(1 for c in constants if k.lower() in c.lower())
            for k in ("DESKeySpec", "DES/CBC", "zelix", "$CodePool")}


def native_libs_facts(path: Path) -> dict:
    """Every native library inside a jar, parsed here rather than by jdec.

    This is the Maven `natives` classifier layout: the main jar declares the
    native methods and a second jar carries the libraries. Summing the exports
    independently is what makes "52 JNI exports matched" checkable.
    """
    libs: dict[str, dict] = {}
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        return {"libs": {}, "lib_count": 0, "total_exports": 0,
                "total_jni": 0, "max_exports": 0}
    with zf as z:
        for info in z.infolist():
            if not info.filename.lower().endswith(_NATIVE_EXTS):
                continue
            data = z.read(info.filename)
            facts = pe_exports(data)
            libs[info.filename.rsplit("/", 1)[-1]] = {
                "exports": len(facts["exports"]),
                "jni": sum(1 for e in facts["exports"]
                           if e.startswith("Java_")),
                "bytes": len(data),
            }
    return {
        "libs": libs,
        "lib_count": len(libs),
        "total_exports": sum(v["exports"] for v in libs.values()),
        "total_jni": sum(v["jni"] for v in libs.values()),
        "max_exports": max((v["exports"] for v in libs.values()), default=0),
    }


# ---------------------------------------------------------------------------
# Independent Minecraft / loader metadata facts.
# ---------------------------------------------------------------------------

def mc_facts(path: Path) -> dict:
    texts: list[str] = []
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        for name in names:
            low = name.lower()
            if (low.endswith("mcmod.info") or low.endswith("mods.toml")
                    or low.endswith("manifest.mf") or "forge" in low
                    and low.endswith(".json")):
                try:
                    texts.append(z.read(name).decode("utf-8", "replace"))
                except (OSError, RuntimeError):
                    pass
    blob = "\n".join(texts).lower()
    return {"has_mcmod": any("mcmod.info" in n.lower() for n in names),
            "mentions_forge": "forge" in blob,
            "mentions_189": "1.8.9" in blob,
            "metadata_files": [n for n in names
                               if n.lower().endswith(("mcmod.info", "mods.toml"))]}


def is_blob_literal(text: str) -> bool:
    """Second implementation of the encrypted-blob test (no jdec import).

    Deliberately different in structure from strings._encrypted_blob: it
    decodes first, then applies entropy/printability and internal-name tests.
    """
    import base64
    import math
    import re
    if len(text) < 48:
        return False
    if re.fullmatch(r"[0-9A-Za-z_$][\w$]*(?:/[A-Za-z_$][\w$]*){2,}", text):
        return False
    raw = None
    if len(text) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text):
        try:
            raw = base64.b64decode(text, validate=True)
        except ValueError:
            raw = None
    elif len(text) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", text):
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            raw = None
    if raw is None or len(raw) < 32:
        return False
    printable = sum(1 for b in raw if 32 <= b < 127) / len(raw)
    if printable >= 0.9:
        return False
    counts = {}
    for b in raw:
        counts[b] = counts.get(b, 0) + 1
    entropy = -sum((n / len(raw)) * math.log2(n / len(raw)) for n in counts.values())
    return entropy >= 4.0


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def methods_of(path: Path, internal_name: str) -> list[str]:
    """Method names of one class, read independently from the zip entry."""
    entry = internal_name + ".class"
    with zipfile.ZipFile(path) as z:
        raw = z.read(entry)
    return class_facts(raw)["methods"]


# ------------------------------------------------------------- BSM facts
# A second, independent BootstrapMethods reader. It resolves each entry's
# bootstrap MethodHandle back to its owner class and collects every static
# UTF8 argument, so bsm.py's per-site bookkeeping can be compared against
# something that never imports it.

_CP_TAGGED_FIXED = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4,
                    12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}


def _cp_tagged(data: bytes) -> tuple[list[tuple[int, tuple] | None], int]:
    """Constant pool with tags kept, so MethodHandle chains can be resolved."""
    count = _u2(data, 8)
    pool: list[tuple[int, tuple] | None] = [None] * count
    off = 10
    i = 1
    while i < count:
        tag = data[off]
        off += 1
        if tag == 1:
            length = _u2(data, off)
            off += 2
            pool[i] = (tag, (data[off:off + length].decode("utf-8", "replace"),))
            off += length
        elif tag in (7, 8, 16, 19, 20):
            pool[i] = (tag, (_u2(data, off),))
            off += 2
        elif tag == 15:
            pool[i] = (tag, (data[off], _u2(data, off + 1)))
            off += 3
        elif tag in (9, 10, 11, 12, 17, 18):
            pool[i] = (tag, (_u2(data, off), _u2(data, off + 2)))
            off += 4
        elif tag in (3, 4):
            off += 4
        elif tag in (5, 6):
            off += 8
            i += 1
        else:
            raise ValueError(f"unsupported constant-pool tag {tag}")
        i += 1
    return pool, off


def _utf8_at(pool, idx) -> str | None:
    if idx is None or not 0 <= idx < len(pool):
        return None
    entry = pool[idx]
    return entry[1][0] if entry and entry[0] == 1 else None


def _bsm_owner(pool, ref: int) -> tuple[str | None, str | None]:
    """(owner class, method name) of a bootstrap method handle."""
    entry = pool[ref] if 0 <= ref < len(pool) else None
    if not entry or entry[0] != 15:
        return None, None
    target = pool[entry[1][1]] if 0 <= entry[1][1] < len(pool) else None
    if not target or target[0] not in (10, 11):
        return None, None
    cls_idx, nat_idx = target[1]
    cls = pool[cls_idx] if 0 <= cls_idx < len(pool) else None
    nat = pool[nat_idx] if 0 <= nat_idx < len(pool) else None
    owner = _utf8_at(pool, cls[1][0]) if cls and cls[0] == 7 else None
    name = _utf8_at(pool, nat[1][0]) if nat and nat[0] == 12 else None
    return owner, name


def bsm_facts(path: Path) -> dict:
    """Entries, owner histogram and static UTF8 payloads of every class.

    Payloads are the literal strings a bootstrap carries: the StringConcatFactory
    recipe (``\u0001`` placeholders included) and the ObjectMethods component
    list. Comparing them against what the tool reports is a real cross-check,
    because a fabricated value cannot appear in the constant pool.
    """
    entries = 0
    owners: dict[str, int] = {}
    payloads: list[str] = []
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if not info.filename.endswith(".class") or info.file_size == 0:
                continue
            data = z.read(info.filename)
            if data[:4] != b"\xca\xfe\xba\xbe":
                continue
            try:
                pool, off = _cp_tagged(data)
            except (ValueError, struct.error, IndexError):
                continue
            utf8 = [e[1][0] if e and e[0] == 1 else None for e in pool]
            off += 6                     # access_flags, this, super
            off += 2 + 2 * _u2(data, off)          # interfaces
            for _ in range(2):                      # fields, methods
                n = _u2(data, off)
                off += 2
                for _ in range(n):
                    off += 6
                    off, _ = _skip_attributes(data, off, utf8)
            n = _u2(data, off)
            off += 2
            for _ in range(n):
                name = utf8[_u2(data, off)]
                length = _u4(data, off + 2)
                body = off + 6
                if name == "BootstrapMethods":
                    count = _u2(data, body)
                    o = body + 2
                    for _ in range(count):
                        ref = _u2(data, o)
                        nargs = _u2(data, o + 2)
                        o += 4
                        owner, _m = _bsm_owner(pool, ref)
                        entries += 1
                        if owner:
                            owners[owner] = owners.get(owner, 0) + 1
                        for k in range(nargs):
                            arg = pool[_u2(data, o + 2 * k)]
                            if arg and arg[0] == 8:
                                text = _utf8_at(pool, arg[1][0])
                                if text is not None:
                                    payloads.append(text)
                        o += 2 * nargs
                off = body + length
    return {"entries": entries, "owners": owners,
            "payload_count": len(payloads),
            "payloads": sorted(set(payloads))}
