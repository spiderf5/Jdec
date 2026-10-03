"""Instruction-level reading of Code attributes.

`classfile` keeps attributes opaque so remapping cannot corrupt them, and
`annotations` reads the annotation blobs. This module goes one step further and
decodes the bytecode itself, which is the only way to answer questions like
"is this control flow one a compiler could have produced?".

Why that matters: the commercial obfuscators worth worrying about (ZKM above
all) ship no runtime library and leave no tell-tale package. What they do leave
is structure - exception handlers that jump backwards, gotos that jump into the
middle of a protected range, decryption loops in <clinit>. None of that is
visible from names or from the constant pool; it needs the instructions.

Read-only, like everything else on the parsing side.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from . import annotations as AN

# opcodes we name, because the detection logic below keys off them
OP_GOTO = 0xA7
OP_GOTO_W = 0xC8
OP_JSR = 0xA8
OP_JSR_W = 0xC9
OP_RET = 0xA9
OP_ATHROW = 0xBF
OP_TABLESWITCH = 0xAA
OP_LOOKUPSWITCH = 0xAB
OP_LDC = 0x12
OP_LDC_W = 0x13
OP_LDC2_W = 0x14
OP_INVOKEDYNAMIC = 0xBA
OP_INVOKESTATIC = 0xB8
OP_ANEWARRAY = 0xBD
OP_NEWARRAY = 0xBC
OP_WIDE = 0xC4
OP_MONITORENTER = 0xC2
OP_IXOR = 0x82
OP_LXOR = 0x83

_BRANCH_OPS = set(range(0x99, 0xA9))          # ifeq..jsr, all s16 relative
_BRANCH_OPS |= {OP_GOTO_W, OP_JSR_W}          # s32 relative
_TERMINATORS = set(range(0xAC, 0xB2)) | {OP_ATHROW, OP_RET}


def _build_lengths() -> dict[int, int]:
    """Instruction size in bytes, 0 for the variable-length ones."""
    L: dict[int, int] = {}
    for op in range(0x00, 0x10):
        L[op] = 1                             # nop .. dconst_1
    L[0x10] = 2                               # bipush
    L[0x11] = 3                               # sipush
    L[0x12] = 2                               # ldc
    L[0x13] = 3                               # ldc_w
    L[0x14] = 3                               # ldc2_w
    for op in range(0x15, 0x1A):
        L[op] = 2                             # iload .. aload
    for op in range(0x1A, 0x2E):
        L[op] = 1                             # iload_0 .. aload_3
    for op in range(0x2E, 0x36):
        L[op] = 1                             # iaload .. saload
    for op in range(0x36, 0x3B):
        L[op] = 2                             # istore .. astore
    for op in range(0x3B, 0x4F):
        L[op] = 1                             # istore_0 .. astore_3
    for op in range(0x4F, 0x57):
        L[op] = 1                             # iastore .. sastore
    for op in range(0x57, 0x84):
        L[op] = 1                             # pop .. lxor
    L[0x84] = 3                               # iinc
    for op in range(0x85, 0x99):
        L[op] = 1                             # i2l .. dcmpg
    for op in range(0x99, 0xA9):
        L[op] = 3                             # ifeq .. jsr
    L[0xA9] = 2                               # ret
    L[OP_TABLESWITCH] = 0
    L[OP_LOOKUPSWITCH] = 0
    for op in range(0xAC, 0xB2):
        L[op] = 1                             # ireturn .. return
    for op in range(0xB2, 0xB9):
        L[op] = 3                             # getstatic .. invokestatic
    L[0xB9] = 5                               # invokeinterface
    L[OP_INVOKEDYNAMIC] = 5
    L[0xBB] = 3                               # new
    L[OP_NEWARRAY] = 2
    L[OP_ANEWARRAY] = 3
    L[0xBE] = 1                               # arraylength
    L[OP_ATHROW] = 1
    L[0xC0] = 3                               # checkcast
    L[0xC1] = 3                               # instanceof
    L[OP_MONITORENTER] = 1
    L[0xC3] = 1                               # monitorexit
    L[OP_WIDE] = 0
    L[0xC5] = 4                               # multianewarray
    L[0xC6] = 3                               # ifnull
    L[0xC7] = 3                               # ifnonnull
    L[OP_GOTO_W] = 5
    L[OP_JSR_W] = 5
    return L


_OP_LEN = _build_lengths()


@dataclass
class Insn:
    pc: int
    op: int
    arg: int | None = None      # constant pool index, or signed branch offset
    length: int = 1
    targets: list[int] = field(default_factory=list)   # absolute pcs for switches

    @property
    def is_branch(self) -> bool:
        return self.op in _BRANCH_OPS or self.op in (OP_TABLESWITCH, OP_LOOKUPSWITCH)

    @property
    def is_goto(self) -> bool:
        return self.op in (OP_GOTO, OP_GOTO_W)

    @property
    def is_terminator(self) -> bool:
        return self.op in _TERMINATORS

    def jump_targets(self) -> list[int]:
        if self.targets:
            return list(self.targets)
        if self.arg is None or not self.is_branch:
            return []
        return [self.pc + self.arg]


class BytecodeError(Exception):
    pass


def decode(code: bytes) -> list[Insn]:
    """Decode a Code array into instructions.

    Instruction sizes come from the opcode alone except for wide and the two
    switches, whose payloads are also aligned to a 4-byte boundary relative to
    the start of the method - getting that padding wrong shifts everything
    after it, so it is handled explicitly.
    """
    out: list[Insn] = []
    o = 0
    n = len(code)
    while o < n:
        pc = o
        op = code[o]
        length = _OP_LEN.get(op)
        if length is None:
            raise BytecodeError(f"unknown opcode 0x{op:02x} at {pc}")

        if op == OP_WIDE:
            if o + 1 >= n:
                raise BytecodeError(f"truncated wide at {pc}")
            sub = code[o + 1]
            length = 6 if sub == 0x84 else 4        # iinc takes an extra u2
            out.append(Insn(pc=pc, op=op, arg=sub, length=length))

        elif op in (OP_TABLESWITCH, OP_LOOKUPSWITCH):
            pad = (4 - ((pc + 1) % 4)) % 4
            p = o + 1 + pad
            if p + 8 > n:
                raise BytecodeError(f"truncated switch at {pc}")
            default = struct.unpack_from(">i", code, p)[0]
            targets = [pc + default]
            if op == OP_TABLESWITCH:
                low = struct.unpack_from(">i", code, p + 4)[0]
                high = struct.unpack_from(">i", code, p + 8)[0]
                q = p + 12
                count = high - low + 1
                if count < 0 or q + 4 * count > n:
                    raise BytecodeError(f"bad tableswitch at {pc}")
                for i in range(count):
                    off = struct.unpack_from(">i", code, q + 4 * i)[0]
                    targets.append(pc + off)
                length = (q + 4 * count) - o
            else:
                npairs = struct.unpack_from(">i", code, p + 4)[0]
                q = p + 8
                if npairs < 0 or q + 8 * npairs > n:
                    raise BytecodeError(f"bad lookupswitch at {pc}")
                for i in range(npairs):
                    off = struct.unpack_from(">i", code, q + 4 * i + 4)[0]
                    targets.append(pc + off)
                length = (q + 8 * npairs) - o
            out.append(Insn(pc=pc, op=op, length=length, targets=targets))

        elif length == 2 and op in (OP_LDC,):
            out.append(Insn(pc=pc, op=op, arg=code[o + 1], length=length))
        elif length == 2:
            out.append(Insn(pc=pc, op=op, arg=code[o + 1], length=length))
        elif length == 3:
            if op in _BRANCH_OPS and op not in (OP_GOTO_W, OP_JSR_W):
                arg = struct.unpack_from(">h", code, o + 1)[0]
            else:
                arg = struct.unpack_from(">H", code, o + 1)[0]
            out.append(Insn(pc=pc, op=op, arg=arg, length=length))
        elif length == 5 and op in (OP_GOTO_W, OP_JSR_W):
            arg = struct.unpack_from(">i", code, o + 1)[0]
            out.append(Insn(pc=pc, op=op, arg=arg, length=length))
        elif length == 5:
            out.append(Insn(pc=pc, op=op,
                            arg=struct.unpack_from(">H", code, o + 1)[0],
                            length=length))
        else:
            out.append(Insn(pc=pc, op=op, length=length))
        o += length
    return out


# --------------------------------------------------------------------------
# Code attribute
# --------------------------------------------------------------------------

@dataclass
class Handler:
    start_pc: int
    end_pc: int
    handler_pc: int
    catch_type: int        # constant pool Class index, 0 = finally

    @property
    def is_finally(self) -> bool:
        return self.catch_type == 0

    def covers(self, pc: int) -> bool:
        return self.start_pc <= pc < self.end_pc

    @property
    def jumps_backwards(self) -> bool:
        """Handler target precedes the range it guards.

        javac never emits this: an exception raised inside the range cannot be
        handled before the range starts. Its presence means somebody built the
        control flow by hand, which is exactly what flow obfuscation does.
        """
        return self.handler_pc < self.start_pc


@dataclass
class CodeInfo:
    max_stack: int
    max_locals: int
    code: bytes
    handlers: list[Handler]
    insns: list[Insn] = field(default_factory=list)
    error: str | None = None

    @property
    def branch_targets(self) -> set[int]:
        out: set[int] = set()
        for i in self.insns:
            out |= set(i.jump_targets())
        return out


def parse_code(payload: bytes, decode_insns: bool = True) -> CodeInfo:
    """Parse a Code attribute payload into instructions and handlers."""
    if len(payload) < 12:            # 8 header + 1 code byte + 2 handler count
        raise BytecodeError("code attribute too short")
    max_stack = struct.unpack_from(">H", payload, 0)[0]
    max_locals = struct.unpack_from(">H", payload, 2)[0]
    code_len = struct.unpack_from(">I", payload, 4)[0]
    o = 8
    if o + code_len > len(payload):
        raise BytecodeError("code array overruns attribute")
    code = payload[o:o + code_len]
    o += code_len
    if o + 2 > len(payload):
        raise BytecodeError("no exception table")
    hcount = struct.unpack_from(">H", payload, o)[0]
    o += 2
    handlers: list[Handler] = []
    for _ in range(hcount):
        if o + 8 > len(payload):
            raise BytecodeError("truncated exception table")
        s, e, h, c = struct.unpack_from(">HHHH", payload, o)
        o += 8
        handlers.append(Handler(s, e, h, c))
    insns: list[Insn] = []
    err = None
    if decode_insns:
        try:
            insns = decode(code)
        except BytecodeError as exc:
            err = str(exc)
    return CodeInfo(max_stack=max_stack, max_locals=max_locals,
                    code=code, handlers=handlers, insns=insns, error=err)


def method_code(cf, member, decode_insns: bool = True) -> CodeInfo | None:
    """CodeInfo for one method, or None when it has no body."""
    attrs = AN.member_attributes(cf, member)
    payload = attrs.get("Code")
    if not payload:
        return None
    try:
        return parse_code(payload, decode_insns=decode_insns)
    except BytecodeError:
        return None
