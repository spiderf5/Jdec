"""Pick what is safe to initialise, before pointing the tap agent at a jar.

The tap agent captures plaintext when the obfuscator's own code runs, which
means initialising target classes. On a cheat client some classes crash the
JVM in native code the moment their <clinit> loads a shipped library (Myau:
`myau.r` -> 30 MB JrPQMg.lib -> EXCEPTION_ACCESS_VIOLATION), so the batch must
be split before anything runs:

  decryptor  - constant pool references javax.crypto (the string decryptor)
  dangerous  - calls System.load / System.loadLibrary, or has native methods
  encrypted  - statically invokes a decryptor class (has ciphertext to resolve)

Everything else is neither useful to initialise nor dangerous; skip it.
Pure static analysis: one pass over the constant pool, nothing is executed.

Output: targets.json + a console summary, plus the batch lists the driver
consumes (safe.txt = encrypted minus dangerous, risky.txt = dangerous
intersected encrypted).
"""

from __future__ import annotations

import json
import sys
import zipfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from jdec import classfile as CF  # noqa: E402

_CRYPTO_MARKERS = (
    "javax/crypto/Cipher",
    "javax/crypto/spec/SecretKeySpec",
    "javax/crypto/spec/DESKeySpec",
    "javax/crypto/spec/IvParameterSpec",
)


def _cp_strings(cf: CF.ClassFile) -> set[str]:
    """Every UTF8 constant that looks like an internal class name."""
    out = set()
    for e in cf.cp[1:]:
        if e and e[0] == CF.C_UTF8:
            s = e[1].decode("utf-8", "replace")
            if "/" in s and not s.startswith("("):
                out.add(s)
    return out


def _methodrefs(cf: CF.ClassFile) -> list[tuple[str, str, str]]:
    """(owner, name, descriptor) for every Methodref/InterfaceMethodref.

    Payload shapes in classfile.py: UTF8 -> raw bytes; everything else ->
    list of u2 indices (C_CLASS -> [name_index], NAME_AND_TYPE -> [n, d],
    METHODREF -> [class_index, nat_index]).
    """
    out = []

    def utf8(idx: int) -> str:
        e = cf.cp[idx]
        return e[1].decode("utf-8", "replace") if e and e[0] == CF.C_UTF8 else ""

    for e in cf.cp[1:]:
        if e and e[0] in (CF.C_METHODREF, CF.C_INTERFACE_METHODREF):
            cls_idx, nat_idx = e[1]
            owner = cf.cp[cls_idx]
            if not owner or owner[0] != CF.C_CLASS:
                continue
            nat = cf.cp[nat_idx]
            if not nat or nat[0] != CF.C_NAME_AND_TYPE:
                continue
            n_idx, d_idx = nat[1]
            out.append((utf8(owner[1][0]), utf8(n_idx), utf8(d_idx)))
    return out


def scan(jar: Path) -> dict:
    entries = []
    with zipfile.ZipFile(jar) as zf:
        for info in zf.infolist():
            if info.filename.endswith(".class"):
                entries.append((info.filename, zf.read(info)))

    decryptors: set[str] = set()
    per_class_refs: dict[str, list[tuple[str, str, str]]] = {}
    danger: dict[str, str] = {}
    unreadable = 0

    for _, data in entries:
        try:
            cf = CF.parse(data)
        except CF.ClassFormatError:
            unreadable += 1
            continue
        name = cf.name
        strings = _cp_strings(cf)
        refs = _methodrefs(cf)
        per_class_refs[name] = refs

        if any(m in strings for m in _CRYPTO_MARKERS):
            decryptors.add(name)

        if any(m.access_flags & CF.ACC_NATIVE for m in cf.methods):
            danger[name] = "native method"

        for owner, mname, _ in refs:
            if owner == "java/lang/System" and mname in ("load", "loadLibrary"):
                danger[name] = "System.load"

    # who calls the decryptors? (second pass: the set must be complete first)
    encrypted: dict[str, list[str]] = {}
    for name, refs in per_class_refs.items():
        calls = sorted({f"{o}.{n}{d}" for o, n, d in refs if o in decryptors})
        if calls and name not in decryptors:
            encrypted[name] = calls

    # diagnostics: ZKM-style decode entry points are static methods that take
    # the ciphertext string (+ key material ints/longs) and return plaintext.
    # Find every static-looking shape `(Ljava/lang/String;...)Ljava/lang/String;`
    # and rank by caller count - the real entry point stands out.
    shape_callers: Counter = Counter()
    dofinal_callers: dict[str, int] = {}
    for name, refs in per_class_refs.items():
        for owner, mname, desc in refs:
            if (desc.startswith("(Ljava/lang/String;")
                    and desc.endswith(")Ljava/lang/String;")):
                shape_callers[f"{owner}.{mname}{desc}"] += 1
            if owner == "javax/crypto/Cipher" and mname == "doFinal":
                dofinal_callers[name] = dofinal_callers.get(name, 0) + 1

    # ZKM 27 inlines a copy of the decryptor into every class that carries
    # encrypted strings ("rotate cipher setup per class"): each of those
    # classes calls Cipher.doFinal exactly once, in its own <clinit>. So the
    # classes to initialise ARE the doFinal callers, not their callers.
    safe = sorted(n for n in dofinal_callers if n not in danger)
    risky = sorted(n for n in dofinal_callers if n in danger)
    decode_shapes = Counter(
        call for calls in encrypted.values() for call in calls)

    return {
        "jar": str(jar),
        "classes_scanned": len(per_class_refs),
        "unreadable": unreadable,
        "decryptors": sorted(decryptors),
        "dangerous": {k: danger[k] for k in sorted(danger)},
        "encrypted_count": len(encrypted),
        "decode_calls_top": decode_shapes.most_common(8),
        "string_decode_shapes": shape_callers.most_common(12),
        "dofinal_callers": dict(sorted(
            dofinal_callers.items(), key=lambda kv: -kv[1])),
        "safe": safe,
        "risky": risky,
    }


def main() -> None:
    jar = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else jar.parent / "targets.json"
    report = scan(jar)

    out.write_text(json.dumps(report, indent=1), encoding="utf-8")
    safe_txt = out.with_name("safe.txt")
    safe_txt.write_text("\n".join(report["safe"]) + "\n", encoding="utf-8")

    print(f"scanned   : {report['classes_scanned']} classes "
          f"({report['unreadable']} unreadable)")
    print(f"decryptors: {len(report['decryptors'])} "
          f"{report['decryptors'][:6]}")
    print(f"dangerous : {len(report['dangerous'])} "
          f"({sum(1 for v in report['dangerous'].values() if v == 'native method')} native,"
          f" {sum(1 for v in report['dangerous'].values() if v == 'System.load')} System.load)")
    print(f"encrypted : {report['encrypted_count']} classes call a decryptor")
    for call, n in report["decode_calls_top"]:
        print(f"  {n:5d}x {call}")
    print(f"safe batch: {len(report['safe'])} classes -> {safe_txt.name}")
    print(f"risky     : {len(report['risky'])} encrypted-but-dangerous classes")


if __name__ == "__main__":
    main()
