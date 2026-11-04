"""Rebuild a runtime-state PE from a memory dump (Scylla-style).

The on-disk PE is a packed image whose raw sections overlap, so per-section
backfilling corrupts earlier data. Instead we emit the *memory image* itself
as the file body (file[RVA] == mem[RVA]) and only patch the section table:
PointerToRawData := VirtualAddress, SizeOfRawData := VirtualSize, and the
flags get UNINITIALIZED cleared so Ghidra disassembles normally.
"""
import struct
import sys

mem_path, disk_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
mem = open(mem_path, "rb").read()
disk = open(disk_path, "rb").read()

e_lfanew = int.from_bytes(mem[0x3C:0x40], "little")
num_sections = int.from_bytes(mem[e_lfanew + 6:e_lfanew + 8], "little")
opt_size = int.from_bytes(mem[e_lfanew + 20:e_lfanew + 22], "little")
opt_off = e_lfanew + 24
magic = int.from_bytes(mem[opt_off:opt_off + 2], "little")
size_image = int.from_bytes(mem[opt_off + 56:opt_off + 60], "little")
size_headers = int.from_bytes(mem[opt_off + 60:opt_off + 64], "little")
sect_off = opt_off + opt_size

out = bytearray(mem[:size_image])   # whole mapped image becomes the file
print(f"image: {size_image:#x} bytes, headers {size_headers:#x}, "
      f"{num_sections} sections")

for i in range(num_sections):
    s = sect_off + i * 40
    name = mem[s:s + 8].rstrip(b"\x00").decode("ascii", "replace")
    vsize, vaddr = struct.unpack("<II", out[s + 8:s + 16])
    charac = int.from_bytes(out[s + 36:s + 40], "little")
    # normalize flags: clear UNINITIALIZED / IDATA on executable sections
    if charac & 0x20000000:
        charac = (charac | 0x20) & ~0x80 & ~0xC00000
    else:
        charac &= ~0x80
    out[s + 36:s + 40] = struct.pack("<I", charac)
    # memory-layout mapping: file offset == RVA
    out[s + 16:s + 20] = struct.pack("<I", vsize)
    out[s + 20:s + 24] = struct.pack("<I", vaddr)
    state = "ok" if vaddr + vsize <= size_image else "TRUNCATED"
    print(f"  {name:8s} va={vaddr:#x} vsize={vsize:#x} flags={charac:#010x} {state}")

open(out_path, "wb").write(bytes(out))
print(f"written: {out_path} ({len(out)} bytes)")
