"""OPS (PhantomShield) string-pool static decryptor.

Algorithm 100% source-verified against study/OpenPhantomShield
(transformer/impl/StringEncryption.java, 2026-10-05):

Build time (per class):
  data = concat over strings of [len_le16][utf8]
  data += SHA-256(data)                       (32B integrity)
  data = DES/CBC/PKCS5-encrypt(data, key=8B random, IV=8x00)   [key embedded]
  data[i] = swp[data[i] & 0xFF]               (random permutation)
  blob stored as ISO-8859-1 LDC String (data), key as second LDC String,
  swp inverse embedded as a 256-case tableswitch in <clinit>.

Decrypt time (this module, no JVM needed):
  data[i] = swpInv[data[i] & 0xFF]  ->  DES/CBC/PKCS5 decrypt (zero IV)
  -> SHA-256 verify  ->  split [len_le16][utf8] records.

DES through the pure-Python `jdec/jdec/_des.py` module (intentional: jdec is
zero-dependency stdlib-only, and CNG/ctypes would be Windows-only anyway).

Scan strategy: brute-force byte scan (no linear bytecode walk — immune to
instruction-length table bugs). Every 0xAA byte is probed as a tableswitch
(low=0/high=255 and all 256 targets = const-push + goto => validated);
every 0x12/0x13 is probed as an LDC String constant. Candidates that fail
SHA-256 are rejected, so false probes only cost time, never correctness.
"""

from __future__ import annotations

import hashlib
import struct

__all__ = ["decrypt_payload", "decrypt_class", "scan_jar"]

_SIGNED = tuple(range(0x02, 0x09))  # iconst_m1..iconst_5


# ------------------------------------------------------------ classfile walk

def _utf8(cf, idx: int) -> str | None:
    if idx <= 0 or idx >= len(cf.cp):
        return None
    e = cf.cp[idx]
    if e and e[0] == 1:
        return e[1].decode("utf-8", "replace")
    return None


def _all_method_code(cf):
    """Yield (method_name, code_bytes) for every method with a Code attr."""
    for m in cf.methods:
        name = _utf8(cf, m.name_index)
        blob = m.attrs_blob
        try:
            (n_attrs,) = struct.unpack_from(">H", blob, 0)
        except Exception:
            continue
        off = 2
        for _ in range(n_attrs):
            (name_idx,) = struct.unpack_from(">H", blob, off)
            off += 2
            (attr_len,) = struct.unpack_from(">I", blob, off)
            off += 4
            if _utf8(cf, name_idx) == "Code":
                (code_len,) = struct.unpack_from(">I", blob, off + 4)
                yield name, blob[off + 8: off + 8 + code_len]
            off += attr_len


def _class_name(cf):
    e = cf.cp[cf.this_class]
    if e and e[0] == 7:
        u = cf.cp[e[1][0]]
        if u and u[0] == 1:
            return u[1].decode("utf-8", "replace")
    return None


def _brute_ldc_strings(code: bytes, cf) -> list[bytes]:
    """Probe every 0x12/0x13 byte as an LDC String constant; keep valid ones
    in bytecode order. False probes resolve to garbage/cp-miss and are
    dropped — harmless for our size-based selection."""
    out = []
    i = 0
    n = len(code)
    while i < n - 1:
        op = code[i]
        idx = -1
        if op == 0x12 and i + 1 < n:
            idx = code[i + 1]
            step = 2
        elif op == 0x13 and i + 2 < n:
            idx = struct.unpack_from(">H", code, i + 1)[0]
            step = 3
        else:
            i += 1
            continue
        if 0 < idx < len(cf.cp):
            e = cf.cp[idx]
            if e and e[0] == 8:
                u = cf.cp[e[1][0]]
                if u and u[0] == 1:
                    # constant pool stores modified-UTF8; decode to the
                    # char sequence (byte-oriented callers latin-1 encode)
                    # modified-UTF8: NUL is stored as C0 80 (invalid in
                    # standard UTF-8) — restore it before decoding
                    raw = u[1].replace(b"\xc0\x80", b"\x00")
                    out.append(raw.decode("utf-8", "replace"))
        i += step
    return out


def _probe_switch_inv(code: bytes, i: int, is_lookup: bool):
    """Validate a 0..255 switch at i whose targets are const-push + goto."""
    n = len(code)
    pad = (4 - ((i + 1) % 4)) % 4
    base = i + 1 + pad
    if is_lookup:
        if base + 8 > n:
            return None
        _default, npairs = struct.unpack_from(">ii", code, base)
        if npairs != 256 or base + 8 + npairs * 8 > n:
            return None
        cases = []
        for k in range(npairs):
            match, rel = struct.unpack_from(">ii", code, base + 8 + k * 8)
            cases.append((match, rel, base + 8 + k * 8))
    else:
        if base + 12 > n:
            return None
        _default, low, high = struct.unpack_from(">iii", code, base)
        if low != 0 or high != 255 or base + 12 + 256 * 4 > n:
            return None
        cases = [(case, struct.unpack_from(">i", code, base + 12 + case * 4)[0],
                  base + 12 + case * 4) for case in range(256)]
    inv = {}
    for case, rel, _off in cases:
        t = i + rel
        if t < 0 or t >= n:
            return None
        op = code[t]
        if op == 0x10 and t + 1 < n:
            val = struct.unpack_from(">b", code, t + 1)[0]
        elif op == 0x11 and t + 2 < n:
            val = struct.unpack_from(">h", code, t + 1)[0]
        elif op in _SIGNED:
            val = op - 0x03
        else:
            return None
        inv[case] = val & 0xFF
    return inv if len(inv) == 256 else None


def _find_switch_inv(cf):
    """Probe every method for a 0..255 table/lookupswitch = swpInv."""
    for name, code in _all_method_code(cf):
        if len(code) < 300:
            continue
        for i in range(len(code)):
            if code[i] == 0xAA:
                r = _probe_switch_inv(code, i, is_lookup=False)
                if r:
                    return r
            elif code[i] == 0xAB:
                r = _probe_switch_inv(code, i, is_lookup=True)
                if r:
                    return r
    return None


# ------------------------------------------------------------ decryption

def decrypt_payload(data_bytes: bytes, key: bytes, swp_inv: dict[int, int]) -> list[str]:
    """Apply embedded inverse substitution, DES-decrypt, verify, split."""
    data = bytes(swp_inv[b & 0xFF] & 0xFF for b in data_bytes)
    from ._des import des_cbc_decrypt
    plain = des_cbc_decrypt(key, data, b"\x00" * 8)
    if len(plain) < 34:                      # 2B len + 32B digest minimum
        raise ValueError("decrypted payload too short")
    body, digest = plain[:-32], plain[-32:]
    if hashlib.sha256(body).digest() != digest:
        raise ValueError("SHA-256 mismatch")
    strings = []
    pos = 0
    while pos < len(body):
        length = body[pos] | (body[pos + 1] << 8)
        pos += 2
        if length == 0 or pos + length > len(body):
            raise ValueError("record overrun")
        strings.append(body[pos:pos + length].decode("utf-8"))
        pos += length
    return strings


def decrypt_class(cf):
    """Full pipeline on one class: returns list[str] or None."""
    ldcs: list[str] = []
    for _name, code in _all_method_code(cf):
        ldcs += _brute_ldc_strings(code, cf)
    if len(ldcs) < 2:
        return None
    # byte-semantic blobs are latin-1 encodable char sequences
    data_str = max(ldcs, key=len)
    try:
        data_bytes = data_str.encode("latin-1")
    except UnicodeEncodeError:
        return None
    if len(data_bytes) < 64 or len(data_bytes) % 8 != 0:
        return None
    inv = _find_switch_inv(cf)
    if inv is None:
        return None
    keys = [k.encode("latin-1") for k in ldcs if len(k) == 8] or [b"\x00" * 8]
    for key in keys:
        try:
            return decrypt_payload(data_bytes, key, inv)
        except Exception:
            continue
    return None


def scan_jar(path: str):
    """Scan a jar for OPS-pattern classes; yield (class_name, strings, entry)."""
    import zipfile
    from . import classfile as cfmod

    out = []
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            if not name.endswith(".class"):
                continue
            try:
                cf = cfmod.parse(zf.read(name))
            except Exception:
                continue
            r = decrypt_class(cf)
            if r:
                out.append((_class_name(cf), r, name))
    return out
