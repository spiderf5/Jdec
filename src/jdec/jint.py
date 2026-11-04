"""Java primitive arithmetic emulation — exact JVM semantics in Python.

Every static port of a Java decryptor / mixer / checksum goes through these.
The differences that break naive transliterations:

- Java ``int``/``long`` wrap at 32/64 bits; Python integers are arbitrary
  precision, so results silently drift out of range.
- Java ``>>>`` is an unsigned shift; Python ``>>`` is arithmetic and keeps
  the sign.
- Java operator precedence: ``+`` binds tighter than ``>>`` — a Java
  ``a + b + (x << 6) + (x >>> 2)`` chain must be explicitly grouped in
  Python or the value is wrong (historically: 0/1048 calibration vectors
  passed until the grouping was made explicit).
- Rotate-left has no Python builtin.

All functions are side-effect free and accept/return Python ints.
"""

from __future__ import annotations

__all__ = ["M32", "M64", "i32", "i64", "ushr32", "rotl32"]

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF


def i32(x: int) -> int:
    """Wrap a Python int to Java ``int`` semantics (32-bit two's complement)."""
    x &= M32
    return x - 0x1_0000_0000 if x >= 0x8000_0000 else x


def i64(x: int) -> int:
    """Wrap a Python int to Java ``long`` semantics (64-bit two's complement)."""
    x &= M64
    return x - 0x1_0000_0000_0000_0000 if x >= 0x8000_0000_0000_0000 else x


def ushr32(x: int, k: int) -> int:
    """Java ``x >>> k`` on an ``int`` (unsigned right shift)."""
    return (x & M32) >> k


def rotl32(x: int, k: int) -> int:
    """Rotate a 32-bit value left by ``k`` (Java has no intrinsic; obfuscators
    use the idiom ``x << k | x >>> (32 - k)``)."""
    x &= M32
    k &= 31
    return i32(((x << k) & M32) | (x >> (32 - k))) if k else i32(x)
