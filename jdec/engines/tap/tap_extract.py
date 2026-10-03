"""Extract the static argument pairs of every decode call site.

ZKM 27 inlines a copy of the decryptor into every class that carries
encrypted constants. Every use of an encrypted value is a static call with
hard-coded arguments, visible in the decompiled output as e.g.:

    A.b(16065, 9159572468878193311L)   -> long   (folded constant)
    A.a(7536, 14354)                   -> String (plaintext, cached in w[])

Both compile to constant pushes immediately before an INVOKESTATIC in the
instruction stream. Extracting every call site therefore yields the exact
parameter set the bytecode actually asks for - no guessing, no brute force.

Key insight this replaces: initialising a class does NOT decrypt its strings.
The decryptor is lazy - strings decrypt on first use, inside whatever method
uses them. Class init only builds the ciphertext tables. So "run <clinit>"
captures almost nothing (verified: 0 plaintexts from 3 clean class inits);
calling the decode methods with their static arguments captures everything.

Output: calls.tsv, one call site per line:
    <class>\t<descriptor>\t<arg1>\t<arg2>\t...
Deduplicated per (class, desc, args). The Reflect driver consumes this.
"""

from __future__ import annotations

import struct
import sys
import zipfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from jdec import bytecode as BC  # noqa: E402
from jdec import classfile as CF  # noqa: E402

# opcode constants not named in bytecode.py
BIPUSH, SIPUSH = 0x10, 0x11
ICONST_M1, ICONST_0, ICONST_1, ICONST_2, ICONST_3, ICONST_4, ICONST_5 = range(0x02, 0x09)

_CP_INTEGER = CF.C_INTEGER
_CP_LONG = CF.C_LONG
_CP_STRING = CF.C_STRING


def _cp_load(cf: CF.ClassFile, idx: int):
    """Constant value behind an LDC/LDC2_W argument, tagged by kind."""
    e = cf.cp[idx]
    if not e:
        return None
    tag, payload = e
    if tag == _CP_INTEGER:
        return ("i", struct.unpack(">i", bytes(payload[0]))[0])
    if tag == _CP_LONG:
        return ("l", struct.unpack(">q", bytes(payload[0]))[0])
    if tag == _CP_STRING:
        return ("s", None)  # a string push; breaks the constant pattern
    return ("?", None)


def _params_of(desc: str) -> list[str]:
    """Top-level parameter types of a method descriptor."""
    out, i, cur = [], 1, ""
    depth = 0
    while i < len(desc) and desc[i] != ")":
        ch = desc[i]
        cur += ch
        if ch == "L":
            while desc[i] != ";":
                i += 1
                cur += desc[i]
        elif ch == "[":
            i += 1
            continue  # '[' prefixes the next component without closing one
        out.append(cur)
        cur = ""
        i += 1
    return out


def extract(jar: Path) -> tuple[Counter, dict[str, set]]:
    """One pass over the jar: (call-shape stats, per-class call sites)."""
    shapes: Counter = Counter()
    sites: dict[str, set] = {}
    with zipfile.ZipFile(jar) as zf:
        for info in zf.infolist():
            if not info.filename.endswith(".class"):
                continue
            try:
                cf = CF.parse(zf.read(info))
            except CF.ClassFormatError:
                continue
            self_name = cf.name
            for m in cf.methods:
                try:
                    ci = BC.method_code(cf, m, decode_insns=True)
                except Exception:
                    continue
                if ci is None or ci.error or not ci.insns:
                    continue
                stack: list[tuple[str, object]] = []
                for ins in ci.insns:
                    op = ins.op
                    if op == BIPUSH:            # signed byte; decode() stores it unsigned
                        v = ins.arg if ins.arg < 0x80 else ins.arg - 0x100
                        stack.append(("i", v))
                    elif op == SIPUSH:          # signed short; decode() stores it unsigned
                        v = ins.arg if ins.arg < 0x8000 else ins.arg - 0x10000
                        stack.append(("i", v))
                    elif ICONST_M1 <= op <= ICONST_5:
                        stack.append(("i", op - ICONST_0))
                    elif op in (BC.OP_LDC, BC.OP_LDC_W, BC.OP_LDC2_W):
                        stack.append(_cp_load(cf, ins.arg))
                    elif op == BC.OP_INVOKESTATIC:
                        e = cf.cp[ins.arg] if ins.arg and ins.arg < len(cf.cp) else None
                        if not e or e[0] not in (CF.C_METHODREF,):
                            stack.clear()
                            continue
                        cls_idx, nat_idx = e[1]
                        owner = cf.cp[cls_idx]
                        nat = cf.cp[nat_idx]
                        if not owner or owner[0] != CF.C_CLASS or not nat:
                            stack.clear()
                            continue
                        owner_name = cf.cp[owner[1][0]][1].decode("utf-8", "replace")
                        n_idx, d_idx = nat[1]
                        mname = cf.cp[n_idx][1].decode("utf-8", "replace")
                        desc = cf.cp[d_idx][1].decode("utf-8", "replace")
                        if owner_name != self_name:
                            stack.clear()
                            continue
                        ptypes = _params_of(desc)
                        want = [("i" if p in ("I", "S", "B", "Z", "C") else
                                 "l" if p == "J" else "o") for p in ptypes]
                        if len(stack) < len(want) or any(
                                w == "o" or stack[-len(want) + k][0] != w
                                for k, w in enumerate(want) if w != "o") or any(
                                stack[-len(want) + k][0] == "o"
                                for k, w in enumerate(want) if w == "o") or len(want) == 0:
                            shapes[f"{mname}{desc} [unmatched]"] += 1
                            stack.clear()
                            continue
                        args = [stack[-len(want) + k][1]
                                for k in range(len(want))]
                        del stack[-len(want):]
                        key = (self_name, mname, desc, tuple(args))
                        sites.setdefault(self_name, set()).add(
                            (mname, desc, *args))
                        shapes[f"{mname}{desc}"] += 1
                    else:
                        stack.clear()
    return shapes, sites


def main() -> None:
    jar = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else jar.parent / "calls.tsv"
    shapes, sites = extract(jar)

    print("call shapes (self-calls with constant args):")
    for shape, n in shapes.most_common(10):
        print(f"  {n:6d}  {shape}")

    lines = []
    for cls in sorted(sites):
        for mname, desc, *args in sorted(sites[cls]):
            lines.append("\t".join([cls, mname, desc] + [str(a) for a in args]))
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{sum(len(v) for v in sites.values())} call sites across "
          f"{len(sites)} classes -> {out.name}")


if __name__ == "__main__":
    main()
