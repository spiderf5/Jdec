"""Pure-python DES (encrypt/decrypt) — zero-dependency fallback for the OPS
string-pool static decryptor (Windows CNG proved unreliable under sandboxing).

Canonical table-driven implementation (FIPS 46-3 tables). Validated by:
  1. the classic known-answer test (key 133457799BBCDFF1, pt 0123456789ABCDEF
     -> ct 85E813540F0AB405),
  2. cross-check against javax.crypto DES output on real fixture data.
Data volumes here are tiny (a few KB), performance is a non-issue.
"""

from __future__ import annotations

IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
]
FP = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
]
E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
]
P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]
PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
]
PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
]
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
SBOX = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]


def _bytes_to_bits(data: bytes) -> list[int]:
    return [(byte >> (7 - i)) & 1 for byte in data for i in range(8)]


def _bits_to_bytes(bits: list[int]) -> bytes:
    out = bytearray(len(bits) // 8)
    for i, b in enumerate(bits):
        if b:
            out[i // 8] |= 1 << (7 - (i % 8))
    return bytes(out)


def _permute(bits: list[int], table: list[int]) -> list[int]:
    return [bits[i - 1] for i in table]


def _sbox_substitute(bits: list[int]) -> list[int]:
    out = []
    for box in range(8):
        chunk = bits[box * 6:(box + 1) * 6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        val = SBOX[box][(row << 4) | col]
        out += [(val >> (3 - i)) & 1 for i in range(4)]
    return out


def _key_schedule(key: bytes) -> list[list[int]]:
    bits = _permute(_bytes_to_bits(key), PC1)
    left, right = bits[:28], bits[28:]
    rounds = []
    for shift in SHIFTS:
        left = left[shift:] + left[:shift]
        right = right[shift:] + right[:shift]
        rounds.append(_permute(left + right, PC2))
    return rounds


def _f(right: list[int], round_key: list[int]) -> list[int]:
    expanded = _permute(right, E)
    xored = [a ^ b for a, b in zip(expanded, round_key)]
    return _permute(_sbox_substitute(xored), P)


def _crypt_block(block: bytes, rounds: list[list[int]]) -> bytes:
    bits = _permute(_bytes_to_bits(block), IP)
    left, right = bits[:32], bits[32:]
    for rk in rounds:
        new_right = [a ^ b for a, b in zip(left, _f(right, rk))]
        left, right = right, new_right
    return _bits_to_bytes(_permute(right + left, FP))


def _pkcs5_pad(data: bytes) -> bytes:
    n = 8 - (len(data) % 8)
    return data + bytes([n]) * n


def _pkcs5_unpad(data: bytes) -> bytes:
    if not data or not (1 <= data[-1] <= 8):
        raise ValueError("bad padding")
    n = data[-1]
    if data[-n:] != bytes([n]) * n:
        raise ValueError("bad padding bytes")
    return data[:-n]


def des_cbc_decrypt(key: bytes, data: bytes, iv: bytes = b"\x00" * 8) -> bytes:
    """DES-CBC decrypt with PKCS5 unpadding (key must be 8 bytes)."""
    rounds = _key_schedule(key)
    dec_rounds = rounds[::-1]
    out = bytearray()
    prev = iv
    for off in range(0, len(data) - len(data) % 8, 8):
        block = data[off:off + 8]
        dec = _crypt_block(block, dec_rounds)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block
    return _pkcs5_unpad(bytes(out))


def des_cbc_encrypt(key: bytes, data: bytes, iv: bytes = b"\x00" * 8) -> bytes:
    """DES-CBC encrypt with PKCS5 padding (used by the fixture builder)."""
    rounds = _key_schedule(key)
    data = _pkcs5_pad(data)
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 8):
        block = data[off:off + 8]
        enc = _crypt_block(bytes(a ^ b for a, b in zip(block, prev)), rounds)
        out += enc
        prev = enc
    return bytes(out)


def self_test() -> None:
    """Classic DES known-answer test."""
    key = bytes.fromhex("133457799BBCDFF1")
    pt = bytes.fromhex("0123456789ABCDEF")
    ct = _crypt_block(pt, _key_schedule(key))
    assert ct == bytes.fromhex("85E813540F0AB405"), ct.hex()
