"""Temporary probe: dump codePoolInit$N instruction shapes for set0/set1.

Answers (before extract_pool can be trusted):
  - which streams are chunked (unpackStringInts) / packed-long (unpackInts) /
    plain ldc arrays
  - the chunk keys (ldc ints) so dump layering can be verified numerically
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from jdec import bytecode as bc
from jdec import classfile as cfmod


def load(path: Path):
    import zipfile
    out = {}
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if n.endswith(".class"):
                c = cfmod.parse(z.read(n))
                out.setdefault(c.name, c)
    return out


def utf8(cf, i):
    return cf.utf8(i)


def member(cf, name):
    for m in cf.methods:
        if utf8(cf, m.name_index) == name:
            return m
    return None


def cp_int(cf, idx):
    e = cf.cp[idx]
    if e and e[0] == cfmod.C_INTEGER:
        return struct.unpack(">i", e[1][0])[0]
    return None


def cp_str(cf, idx):
    e = cf.cp[idx]
    if e and e[0] == cfmod.C_STRING:
        return cf.utf8(e[1][0])
    return None


def cp_class(cf, idx):
    e = cf.cp[idx]
    if e and e[0] == cfmod.C_CLASS:
        return cf.utf8(e[1][0])
    return None


NAMES = {0x00: "nop", 0x01: "aconst_null", 0x02: "iconst_m1", 0x03: "iconst_0",
         0x04: "iconst_1", 0x05: "iconst_2", 0x06: "iconst_3", 0x07: "iconst_4",
         0x08: "iconst_5", 0x10: "bipush", 0x11: "sipush", 0x12: "ldc",
         0x13: "ldc_w", 0x14: "ldc2_w", 0x15: "iload", 0x19: "aload",
         0x1a: "iload_0", 0x2a: "aload_0", 0x2b: "aload_1", 0x2c: "aload_2",
         0x2d: "aload_3", 0x32: "aaload", 0x36: "istore", 0x3a: "astore",
         0x4b: "astore_0", 0x4c: "astore_1", 0x4d: "astore_2", 0x4e: "astore_3",
         0x53: "aastore", 0x54: "bastore", 0x55: "castore", 0x56: "sastore",
         0x57: "pop", 0x59: "dup", 0x5a: "dup_x1", 0x5c: "dup2",
         0xbd: "anewarray", 0xbc: "newarray", 0xb1: "return", 0xb2: "getstatic",
         0xb3: "putstatic", 0xb8: "invokestatic", 0xc5: "multianewarray",
         0xc0: "checkcast", 0xbf: "athrow", 0x57: "pop"}


def dump(cf, m, label):
    code = bc.method_code(cf, m)
    print(f"=== {label}  ({utf8(cf, m.name_index)} {utf8(cf, m.descriptor_index)}) "
          f"insns={len(code.insns)}")
    for ins in code.insns:
        nm = NAMES.get(ins.op, f"op{ins.op:02x}")
        extra = ""
        if ins.op in (0x10, 0x11):  # bipush/sipush signed
            v = ins.arg if ins.arg is not None else 0
            extra = f" {v - 256 if v > 127 else v}"
        elif ins.op == 0x12:
            iv = cp_int(cf, ins.arg)
            sv = cp_str(cf, ins.arg)
            cv = cp_class(cf, ins.arg)
            if iv is not None:
                extra = f" int:{iv} (0x{iv & 0xffffffff:08x})"
            elif sv is not None:
                extra = f" str({len(sv)}): {sv!r}"
            elif cv is not None:
                extra = f" class:{cv}"
        elif ins.op == 0x14:
            e = cf.cp[ins.arg]
            if e and e[0] == cfmod.C_LONG:
                extra = f" long:{struct.unpack('>q', e[1][0])[0]}"
        elif ins.op in (0xb2, 0xb3, 0xb8):
            e = cf.cp[ins.arg]
            cls = cf.class_name(e[1][0])
            nt = cf.cp[e[1][1]]
            extra = f" {cls}.{utf8(cf, nt[1][0])}:{utf8(cf, nt[1][1])}"
        elif ins.op == 0xbd:
            extra = f" {cp_class(cf, ins.arg)}"
        elif ins.op == 0xbc:
            extra = f" atype={ins.arg}"
        print(f"  {ins.pc:5d} {nm}{extra}")
    print()


def main():
    jar = Path(sys.argv[1] if len(sys.argv) > 1 else
               Path(__file__).resolve().parent / "calc-bytecodevm.jar")
    classes = load(jar)
    pools = sorted(n for n in classes if "$CodePool" in n)
    print("CodePool classes:", pools)
    for pname in pools:
        cf = classes[pname]
        print(f"\n##### {pname}: static fields:")
        for f in cf.fields:
            print(f"   {utf8(cf, f.descriptor_index)} {utf8(cf, f.name_index)}")
        for m in cf.methods:
            mn = utf8(cf, m.name_index)
            if mn.startswith("codePoolInit$"):
                # only dump init$6/7/8 fully (opcode maps, method keys, flags),
                # list others compactly
                if mn in ("codePoolInit$6", "codePoolInit$7", "codePoolInit$8"):
                    dump(cf, m, f"{pname} {mn}")
                else:
                    code = bc.method_code(cf, m)
                    kinds = {}
                    for ins in code.insns:
                        if ins.op == 0x12:
                            if cp_str(cf, ins.arg) is not None:
                                kinds["str-ldc"] = kinds.get("str-ldc", 0) + 1
                            elif cp_int(cf, ins.arg) is not None:
                                kinds["int-ldc"] = kinds.get("int-ldc", 0) + 1
                        elif ins.op == 0x14:
                            kinds["long-ldc"] = kinds.get("long-ldc", 0) + 1
                        elif ins.op == 0xb8:
                            e = cf.cp[ins.arg]
                            nt = cf.cp[e[1][1]]
                            kinds["call:" + utf8(cf, nt[1][0])] = \
                                kinds.get("call:" + utf8(cf, nt[1][0]), 0) + 1
                    print(f"--- {pname} {mn}: insns={len(code.insns)} kinds={kinds}")


if __name__ == "__main__":
    main()
