"""Decisive experiment: unpack METHOD_KEYS/FEATURE_FLAGS from raw bytecode
chunks and see which "known truth" comes out (dump file vs memory notes)."""
from __future__ import annotations

import struct
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from jdec import classfile as cfmod
from jdec import bvmw_devirt as dv

JAR = Path(__file__).resolve().parent / "calc-bytecodevm.jar"

with zipfile.ZipFile(JAR) as z:
    cf = cfmod.parse(z.read("BytecodeVM/BytecodeVM$0$CodePool.class"))

pool_cf = cf
main_cf = cfmod.parse(zipfile.ZipFile(JAR).read("BytecodeVM/BytecodeVM$0.class")) \
    if False else None

# profile constants from the pool class itself
seed, ra, rb, rc, ma, mb = dv._extract_pool_mix(pool_cf)
salt_array = dv._extract_pool_salt_array(pool_cf)
print(f"mixSeed=0x{seed & 0xffffffff:08x} rounds=({ra},{rb},{rc}) "
      f"muls=({ma},{mb}) saltArray=0x{salt_array & 0xffffffff:08x}")

# minimal profile for mix()
import dataclasses
prof = dv.VMProfile(
    mix_seed=seed, mix_round_a=ra, mix_round_b=rb, mix_round_c=rc,
    mix_mul_a=ma, mix_mul_b=mb,
    salt_layout=0, salt_opcode=0, salt_opcode_map=0, salt_operand=0,
    salt_constant=0, salt_handler=0, salt_array=salt_array, salt_string=0,
    salt_state=0, salt_block=0, dispatch_salt=0, layout_slots=list(range(9)))


def chunk_bytes(cf, mname):
    """Return (chunks, length, key) pushed to unpackStringInts in a method."""
    from jdec import bytecode as bc
    m = dv._member(cf, mname)
    code = bc.method_code(cf, m)
    strs, ints = [], []
    for ins in code.insns:
        if ins.op == 0x12:
            e = cf.cp[ins.arg]
            if e[0] == cfmod.C_STRING:
                strs.append(cf.utf8(e[1][0]))
            elif e[0] == cfmod.C_INTEGER:
                ints.append(struct.unpack(">i", e[1][0])[0])
        elif 0x02 <= ins.op <= 0x08:  # iconst_m1..iconst_5
            ints.append(ins.op - 0x03)
        elif ins.op in (0x10, 0x11):
            v = ins.arg if ins.arg is not None else 0
            ints.append(v - 256 if v > 127 else v)
    return strs, ints


for label, mname in (("METHOD_KEYS", "codePoolInit$7"),
                     ("FEATURE_FLAGS", "codePoolInit$8"),
                     ("OPCODE_MAPS", "codePoolInit$6")):
    strs, ints = chunk_bytes(pool_cf, mname)
    key = ints[-1]
    length = ints[-2] if len(ints) >= 2 else None
    unpacked = dv.unpack_string_ints(prof, strs, length, key)
    packed = [(ord(s[2 * i]) << 16) | ord(s[2 * i + 1])
              for s in strs for i in range(len(s) // 2)]
    print(f"\n{label}: chunks={[repr(s) for s in strs]} "
          f"key=0x{key & 0xffffffff:08x} len={length}")
    print(f"  raw packed: {[f'0x{p & 0xffffffff:08x}' for p in packed]}")
    print(f"  unpacked  : {[f'0x{u & 0xffffffff:08x}' for u in unpacked]}")
