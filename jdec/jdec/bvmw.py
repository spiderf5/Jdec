"""BytecodeVM (nhcm) watermark scanner.

Statically detects and decodes the AES-GCM watermark capsule that
BytecodeVM (https://github.com/NHCM-dev/BytecodeVM) embeds into protected
jars.  Zero third-party dependencies: AES-128 + GCM are implemented here in
pure Python (payloads are tiny, performance is a non-issue).

Format, source-verified against the SDK (study/BytecodeVM,
sdk/.../watermark/{WatermarkCapsule,WatermarkCodec,WatermarkReader}.java):

- marker      : constant-pool CONSTANT_Long == 0x42564D57434F4445
                (ASCII "BVMWCODE") inside some class of the jar
- carrier     : a CONSTANT_String whose UTF8 holds base64( key[16] |
                nonce[12] | ciphertext+16B tag ), AES-128-GCM, key is
                embedded with the ciphertext (self-contained, statically
                decryptable by design)
- payload     : magic u32 0x42564D57 ("BVMW") | version u16 (=1) |
                bodyLen u32 | body | sha256(body) [32B]
- body        : count u32, then count × ( u32 len + utf8 key,
                u32 len + utf8 value )
"""

from __future__ import annotations

import base64
import hashlib
import struct

__all__ = ["find_watermark", "decode_capsule", "decode_payload", "self_test"]

_MARKER = b"BVMWCODE"
_MAGIC = 0x42564D57  # "BVMW"
_VERSION = 1
_KEY = 16
_NONCE = 12
_TAG = 16
_R = 0xE1000000000000000000000000000000  # GCM reduction polynomial


# ---------------------------------------------------------------- AES-128

def _build_sbox() -> list[int]:
    sbox = [0] * 256
    p = q = 1
    while True:
        p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = (q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6))
             ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4)))
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


_SBOX = _build_sbox()


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _key_expansion(key: bytes) -> list[list[int]]:
    words = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    rcon = 1
    for i in range(4, 44):
        t = list(words[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = ((rcon << 1) ^ (0x11B if rcon & 0x80 else 0)) & 0xFF
        words.append([words[i - 4][j] ^ t[j] for j in range(4)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(11)]


# shift rows: output index i (row=i%4, col=i//4) reads old pos with
# row r shifted left by r -> source col (c+r)%4
_SHIFT_SRC = [(i % 4) + 4 * (((i // 4) + (i % 4)) % 4) for i in range(16)]


def _encrypt_block(rk: list[list[int]], block: bytes) -> bytes:
    s = [block[i] ^ rk[0][i] for i in range(16)]
    for rnd in range(1, 11):
        s = [_SBOX[b] for b in s]
        s = [s[_SHIFT_SRC[i]] for i in range(16)]
        if rnd != 10:
            ns = []
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                x = a0 ^ a1 ^ a2 ^ a3
                ns += [a0 ^ x ^ _xtime(a0 ^ a1),
                       a1 ^ x ^ _xtime(a1 ^ a2),
                       a2 ^ x ^ _xtime(a2 ^ a3),
                       a3 ^ x ^ _xtime(a3 ^ a0)]
            s = ns
        s = [s[i] ^ rk[rnd][i] for i in range(16)]
    return bytes(s)


# ---------------------------------------------------------------- GCM

def _gf_mul(x: int, y: int) -> int:
    z = 0
    v = x
    for i in range(127, -1, -1):
        if (y >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z


def _ghash(h: int, aad: bytes, ct: bytes) -> int:
    y = 0

    def blocks(b: bytes):
        for i in range(0, len(b), 16):
            chunk = b[i:i + 16]
            if len(chunk) < 16:
                chunk += b"\x00" * (16 - len(chunk))
            yield int.from_bytes(chunk, "big")

    for blk in blocks(aad):
        y = _gf_mul(y ^ blk, h)
    for blk in blocks(ct):
        y = _gf_mul(y ^ blk, h)
    lens = ((len(aad) * 8) << 64) | (len(ct) * 8)
    return _gf_mul(y ^ lens, h)


def _gcm_decrypt(key: bytes, nonce: bytes, ct_with_tag: bytes) -> bytes:
    ct, tag = ct_with_tag[:-_TAG], ct_with_tag[-_TAG:]
    rk = _key_expansion(key)
    h = int.from_bytes(_encrypt_block(rk, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    pt = bytearray()
    counter = int.from_bytes(j0[12:], "big")
    for off in range(0, len(ct), 16):
        counter = (counter + 1) & 0xFFFFFFFF
        ks = _encrypt_block(rk, j0[:12] + counter.to_bytes(4, "big"))
        chunk = ct[off:off + 16]
        pt += bytes(a ^ b for a, b in zip(chunk, ks))
    s = _ghash(h, b"", ct)
    expected = bytes(a ^ b for a, b in zip(
        s.to_bytes(16, "big"), _encrypt_block(rk, j0)))
    if expected != tag:
        raise ValueError("GCM tag mismatch")
    return bytes(pt)


# ------------------------------------------------------------ capsule format

def decode_payload(plain: bytes) -> dict[str, str]:
    """Decode the decrypted WatermarkCodec.encode payload into key/values."""
    if len(plain) < 10 + 32:
        raise ValueError("payload too short")
    magic, version, blen = struct.unpack_from(">IHI", plain, 0)
    if magic != _MAGIC:
        raise ValueError("bad magic")
    if version != _VERSION:
        raise ValueError(f"unsupported version {version}")
    if len(plain) != 10 + blen + 32:
        raise ValueError("length mismatch")
    body = plain[10:10 + blen]
    if hashlib.sha256(body).digest() != plain[10 + blen:]:
        raise ValueError("sha256 mismatch")
    (count,) = struct.unpack_from(">I", body, 0)
    if count > 256:
        raise ValueError("too many entries")
    off = 4
    values: dict[str, str] = {}
    for _ in range(count):
        (klen,) = struct.unpack_from(">I", body, off)
        off += 4
        k = body[off:off + klen].decode("utf-8")
        off += klen
        (vlen,) = struct.unpack_from(">I", body, off)
        off += 4
        v = body[off:off + vlen].decode("utf-8")
        off += vlen
        values[k] = v
    return values


def decode_capsule(text: str) -> dict[str, str]:
    """Decode one base64 capsule string (carrier constant value)."""
    raw = base64.b64decode(text + "=" * (-len(text) % 4))
    if len(raw) <= _KEY + _NONCE + _TAG:
        raise ValueError("capsule truncated")
    plain = _gcm_decrypt(raw[:_KEY], raw[_KEY:_KEY + _NONCE], raw[_KEY + _NONCE:])
    return decode_payload(plain)


def find_watermark(data: bytes) -> dict[str, str] | None:
    """Scan one class file's bytes for the BytecodeVM watermark.

    Returns the decoded key/value map, or None when absent/undecodable.
    Cheap raw-byte gate first (8 ASCII bytes, ~zero false positives),
    then a constant-pool walk restricted to what the SDK reader uses.
    """
    if _MARKER not in data:
        return None
    from .classfile import parse

    try:
        cf = parse(data)
    except Exception:
        return None
    marker = any(e and e[0] == 5 and e[1][0] == _MARKER for e in cf.cp)
    if not marker:
        return None
    for e in cf.cp:
        # CONSTANT_String -> utf8 index; only these carry the capsule
        if e and e[0] == 8:
            u = cf.cp[e[1][0]]
            if u and u[0] == 1:
                try:
                    return decode_capsule(u[1].decode("utf-8"))
                except Exception:
                    continue
    return None


def self_test() -> None:
    """FIPS-197 C.1 known-answer test for the AES core (the GCM path is
    regression-tested against a real SDK-generated capsule in run_tests)."""
    key = bytes(range(16))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    out = _encrypt_block(_key_expansion(key), pt)
    assert out == bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"), out.hex()
