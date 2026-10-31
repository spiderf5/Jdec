"""Generic JVM bytecode devirtualization and re-translation engine.

Reconstructs virtualized private instruction streams into compliant JVM bytecode,
reassembles control flow via CFG with far jump widening (>32KB), aligns switch jump tables,
reconstructs exception handlers and stack maps, and restores original method bodies into ClassFiles.
"""

from __future__ import annotations

import collections
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import zipfile

from . import bytecode as BC
from . import cfg as CFG
from . import classfile as CF
from .bytecode import Handler

# ---------------------------------------------------------------------------
# Opcs specification table: maps Opcs name -> (jvm_opcode, operand_format)
# Formats:
#   'none'        : 0 operands
#   'var'         : 1 operand (local variable slot)
#   'imm'         : 1 operand (immediate value: bipush, sipush, newarray)
#   'const'       : 1 operand (constant pool index)
#   'type'        : 1 operand (class/type constant pool index)
#   'jump'        : 1 operand (target virtual PC)
#   'iinc'        : 2 operands (var slot, increment)
#   'multi_array' : 2 operands (type constant pool index, dimensions)
#   'field'       : 3 operands (owner, name, desc)
#   'method'      : 4 operands (owner, name, desc, itf)
#   'indy'        : variable operands (name, desc, bsm, bsm_argc, ...bsm_args)
#   'table_switch': variable operands (min, max, dflt_target, count, ...targets)
#   'lookup_switch': variable operands (dflt_target, npairs, ...pairs)
# ---------------------------------------------------------------------------

OPCS_SPECS: dict[str, tuple[int, str]] = {
    "NOP": (0x00, "none"),
    "ACONST_NULL": (0x01, "none"),
    "ICONST_M1": (0x02, "none"),
    "ICONST_0": (0x03, "none"),
    "ICONST_1": (0x04, "none"),
    "ICONST_2": (0x05, "none"),
    "ICONST_3": (0x06, "none"),
    "ICONST_4": (0x07, "none"),
    "ICONST_5": (0x08, "none"),
    "LCONST_0": (0x09, "none"),
    "LCONST_1": (0x0A, "none"),
    "FCONST_0": (0x0B, "none"),
    "FCONST_1": (0x0C, "none"),
    "FCONST_2": (0x0D, "none"),
    "DCONST_0": (0x0E, "none"),
    "DCONST_1": (0x0F, "none"),
    "BIPUSH": (0x10, "imm"),
    "SIPUSH": (0x11, "imm"),
    "LDC": (0x12, "const"),
    "ILOAD": (0x15, "var"),
    "LLOAD": (0x16, "var"),
    "FLOAD": (0x17, "var"),
    "DLOAD": (0x18, "var"),
    "ALOAD": (0x19, "var"),
    "IALOAD": (0x2E, "none"),
    "LALOAD": (0x2F, "none"),
    "FALOAD": (0x30, "none"),
    "DALOAD": (0x31, "none"),
    "AALOAD": (0x32, "none"),
    "BALOAD": (0x33, "none"),
    "CALOAD": (0x34, "none"),
    "SALOAD": (0x35, "none"),
    "ISTORE": (0x36, "var"),
    "LSTORE": (0x37, "var"),
    "FSTORE": (0x38, "var"),
    "DSTORE": (0x39, "var"),
    "ASTORE": (0x3A, "var"),
    "IASTORE": (0x4F, "none"),
    "LASTORE": (0x50, "none"),
    "FASTORE": (0x51, "none"),
    "DASTORE": (0x52, "none"),
    "AASTORE": (0x53, "none"),
    "BASTORE": (0x54, "none"),
    "CASTORE": (0x55, "none"),
    "SASTORE": (0x56, "none"),
    "POP": (0x57, "none"),
    "POP2": (0x58, "none"),
    "DUP": (0x59, "none"),
    "DUP_X1": (0x5A, "none"),
    "DUP_X2": (0x5B, "none"),
    "DUP2": (0x5C, "none"),
    "DUP2_X1": (0x5D, "none"),
    "DUP2_X2": (0x5E, "none"),
    "SWAP": (0x5F, "none"),
    "IADD": (0x60, "none"),
    "LADD": (0x61, "none"),
    "FADD": (0x62, "none"),
    "DADD": (0x63, "none"),
    "ISUB": (0x64, "none"),
    "LSUB": (0x65, "none"),
    "FSUB": (0x66, "none"),
    "DSUB": (0x67, "none"),
    "IMUL": (0x68, "none"),
    "LMUL": (0x69, "none"),
    "FMUL": (0x6A, "none"),
    "DMUL": (0x6B, "none"),
    "IDIV": (0x6C, "none"),
    "LDIV": (0x6D, "none"),
    "FDIV": (0x6E, "none"),
    "DDIV": (0x6F, "none"),
    "IREM": (0x70, "none"),
    "LREM": (0x71, "none"),
    "FREM": (0x72, "none"),
    "DREM": (0x73, "none"),
    "INEG": (0x74, "none"),
    "LNEG": (0x75, "none"),
    "FNEG": (0x76, "none"),
    "DNEG": (0x77, "none"),
    "ISHL": (0x78, "none"),
    "LSHL": (0x79, "none"),
    "ISHR": (0x7A, "none"),
    "LSHR": (0x7B, "none"),
    "IUSHR": (0x7C, "none"),
    "LUSHR": (0x7D, "none"),
    "IAND": (0x7E, "none"),
    "LAND": (0x7F, "none"),
    "IOR": (0x80, "none"),
    "LOR": (0x81, "none"),
    "IXOR": (0x82, "none"),
    "LXOR": (0x83, "none"),
    "IINC": (0x84, "iinc"),
    "I2L": (0x85, "none"),
    "I2F": (0x86, "none"),
    "I2D": (0x87, "none"),
    "L2I": (0x88, "none"),
    "L2F": (0x89, "none"),
    "L2D": (0x8A, "none"),
    "F2I": (0x8B, "none"),
    "F2L": (0x8C, "none"),
    "F2D": (0x8D, "none"),
    "D2I": (0x8E, "none"),
    "D2L": (0x8F, "none"),
    "D2F": (0x90, "none"),
    "I2B": (0x91, "none"),
    "I2C": (0x92, "none"),
    "I2S": (0x93, "none"),
    "LCMP": (0x94, "none"),
    "FCMPL": (0x95, "none"),
    "FCMPG": (0x96, "none"),
    "DCMPL": (0x97, "none"),
    "DCMPG": (0x98, "none"),
    "IFEQ": (0x99, "jump"),
    "IFNE": (0x9A, "jump"),
    "IFLT": (0x9B, "jump"),
    "IFGE": (0x9C, "jump"),
    "IFGT": (0x9D, "jump"),
    "IFLE": (0x9E, "jump"),
    "IF_ICMPEQ": (0x9F, "jump"),
    "IF_ICMPNE": (0xA0, "jump"),
    "IF_ICMPLT": (0xA1, "jump"),
    "IF_ICMPGE": (0xA2, "jump"),
    "IF_ICMPGT": (0xA3, "jump"),
    "IF_ICMPLE": (0xA4, "jump"),
    "IF_ACMPEQ": (0xA5, "jump"),
    "IF_ACMPNE": (0xA6, "jump"),
    "GOTO": (0xA7, "jump"),
    "TABLESWITCH": (0xAA, "table_switch"),
    "LOOKUPSWITCH": (0xAB, "lookup_switch"),
    "IRETURN": (0xAC, "none"),
    "LRETURN": (0xAD, "none"),
    "FRETURN": (0xAE, "none"),
    "DRETURN": (0xAF, "none"),
    "ARETURN": (0xB0, "none"),
    "RETURN": (0xB1, "none"),
    "GETSTATIC": (0xB2, "field"),
    "PUTSTATIC": (0xB3, "field"),
    "GETFIELD": (0xB4, "field"),
    "PUTFIELD": (0xB5, "field"),
    "INVOKEVIRTUAL": (0xB6, "method"),
    "INVOKESPECIAL": (0xB7, "method"),
    "INVOKESTATIC": (0xB8, "method"),
    "INVOKEINTERFACE": (0xB9, "method"),
    "INVOKEDYNAMIC": (0xBA, "indy"),
    "NEW": (0xBB, "type"),
    "NEWARRAY": (0xBC, "imm"),
    "ANEWARRAY": (0xBD, "type"),
    "ARRAYLENGTH": (0xBE, "none"),
    "ATHROW": (0xBF, "none"),
    "CHECKCAST": (0xC0, "type"),
    "INSTANCEOF": (0xC1, "type"),
    "MONITORENTER": (0xC2, "none"),
    "MONITOREXIT": (0xC3, "none"),
    "MULTIANEWARRAY": (0xC5, "multi_array"),
    "IFNULL": (0xC6, "jump"),
    "IFNONNULL": (0xC7, "jump"),
}

# The ordered Opcs declarations matching enum ordinal 0..161
OPCS_ORDINALS: list[str] = [
    "NOP", "ACONST_NULL", "ICONST_M1", "ICONST_0", "ICONST_1", "ICONST_2", "ICONST_3", "ICONST_4", "ICONST_5",
    "LCONST_0", "LCONST_1", "FCONST_0", "FCONST_1", "FCONST_2", "DCONST_0", "DCONST_1",
    "BIPUSH", "SIPUSH", "LDC",
    "ILOAD", "LLOAD", "FLOAD", "DLOAD", "ALOAD",
    "IALOAD", "LALOAD", "FALOAD", "DALOAD", "AALOAD", "BALOAD", "CALOAD", "SALOAD",
    "ISTORE", "LSTORE", "FSTORE", "DSTORE", "ASTORE",
    "IASTORE", "LASTORE", "FASTORE", "DASTORE", "AASTORE", "BASTORE", "CASTORE", "SASTORE",
    "POP", "POP2", "DUP", "DUP_X1", "DUP_X2", "DUP2", "DUP2_X1", "DUP2_X2", "SWAP",
    "IADD", "LADD", "FADD", "DADD", "ISUB", "LSUB", "FSUB", "DSUB",
    "IMUL", "LMUL", "FMUL", "DMUL", "IDIV", "LDIV", "FDIV", "DDIV",
    "IREM", "LREM", "FREM", "DREM", "INEG", "LNEG", "FNEG", "DNEG",
    "ISHL", "LSHL", "ISHR", "LSHR", "IUSHR", "LUSHR",
    "IAND", "LAND", "IOR", "LOR", "IXOR", "LXOR", "IINC",
    "I2L", "I2F", "I2D", "L2I", "L2F", "L2D", "F2I", "F2L", "F2D", "D2I", "D2L", "D2F",
    "I2B", "I2C", "I2S", "LCMP", "FCMPL", "FCMPG", "DCMPL", "DCMPG",
    "IFEQ", "IFNE", "IFLT", "IFGE", "IFGT", "IFLE",
    "IF_ICMPEQ", "IF_ICMPNE", "IF_ICMPLT", "IF_ICMPGE", "IF_ICMPGT", "IF_ICMPLE",
    "IF_ACMPEQ", "IF_ACMPNE", "GOTO",
    "TABLESWITCH", "LOOKUPSWITCH",
    "IRETURN", "LRETURN", "FRETURN", "DRETURN", "ARETURN", "RETURN",
    "GETSTATIC", "PUTSTATIC", "GETFIELD", "PUTFIELD",
    "INVOKEVIRTUAL", "INVOKESPECIAL", "INVOKESTATIC", "INVOKEINTERFACE", "INVOKEDYNAMIC",
    "NEW", "NEWARRAY", "ANEWARRAY", "ARRAYLENGTH", "ATHROW", "CHECKCAST", "INSTANCEOF",
    "MONITORENTER", "MONITOREXIT", "MULTIANEWARRAY", "IFNULL", "IFNONNULL"
]

ORDINAL_BY_NAME: dict[str, int] = {name: i for i, name in enumerate(OPCS_ORDINALS)}
JVM_OPCODE_TO_NAME: dict[int, str] = {spec[0]: name for name, spec in OPCS_SPECS.items()}


@dataclass
class VMInstruction:
    """A decoded virtual instruction."""
    pc: int
    opcode_name: str
    jvm_opcode: int
    fmt: str
    operands: list[Any] = field(default_factory=list)


BVMInstruction = VMInstruction  # backward-compatibility alias


@dataclass
class VMMethod:
    """A virtualized method container extracted from virtual VM structures."""
    code_id: int
    name: str = ""
    desc: str = ""
    is_static: bool = False
    code: list[int] = field(default_factory=list)
    constants: list[Any] = field(default_factory=list)
    exception_handlers: list[int] = field(default_factory=list)
    max_locals: int = 1
    max_stack: int = 2
    opcode_map: list[int] | dict[int, int] | None = None
    # how to read a bare int in `code`: "ordinal" = OPCS ordinal (default),
    # "jvm-opcode" = raw JVM opcode. Threaded through decode/JSON so a pool
    # dumped from a jvm-opcode stream does not silently re-read as ordinals.
    mode: str = "ordinal"


BVMMethod = VMMethod  # backward-compatibility alias


@dataclass
class DevirtualizedResult:
    """The result of devirtualizing a BVMMethod."""
    code_id: int
    name: str
    desc: str
    bytecode: bytes
    handlers: list[Handler]
    max_stack: int
    max_locals: int
    instructions_count: int
    stats: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Virtual instruction stream decoding
# ---------------------------------------------------------------------------

class VMDecoder:
    """Decodes virtual bytecode integer arrays into structured VMInstructions."""

    @classmethod
    def resolve_opcode(cls, mutated: int, mutator_map: list[int] | dict[int, int] | None,
                       mode: str = "ordinal") -> str | None:
        """Resolve a mutated integer opcode to an Opcs name.

        The two interpretation spaces overlap for ints 0..161, so a bare int
        stream is ambiguous by construction — the mode parameter makes the
        reading explicit instead of silently picking one:

          * "ordinal"    - ints are OPCS ordinals (0..len(OPCS_ORDINALS)-1),
                           optionally remapped through `mutator_map`; this is
                           the virtualized-stream default
          * "jvm-opcode" - ints are raw JVM opcodes (0..0xC9), used when the
                           stream carries untranslated JVM bytecode

        When a `mutator_map` is supplied it is authoritative: an int the map
        does not cover resolves to None (the caller raises), never to a
        coincidental ordinal/JVM-opcode reading.
        """
        if mode not in ("ordinal", "jvm-opcode"):
            raise ValueError(f"unknown opcode mode: {mode!r}")

        if mutator_map is not None:
            if isinstance(mutator_map, dict):
                ord_val = mutator_map.get(mutated)
            elif isinstance(mutator_map, list) and 0 <= mutated < len(mutator_map):
                ord_val = mutator_map[mutated]
            else:
                ord_val = None

            if ord_val is not None:
                if isinstance(ord_val, int) and 0 <= ord_val < len(OPCS_ORDINALS):
                    return OPCS_ORDINALS[ord_val]
                elif isinstance(ord_val, str) and ord_val in OPCS_SPECS:
                    return ord_val
            return None  # the map is the truth; no fallback guessing

        if mode == "ordinal":
            if 0 <= mutated < len(OPCS_ORDINALS):
                return OPCS_ORDINALS[mutated]
            return None
        return JVM_OPCODE_TO_NAME.get(mutated)  # mode == "jvm-opcode"

    @classmethod
    def decode(cls, code: list[int], mutator_map: list[int] | dict[int, int] | None = None,
               mode: str = "ordinal") -> list[VMInstruction]:
        """Decode flat list of ints into VMInstruction sequence.

        `mode` is forwarded to resolve_opcode — see there for why the
        interpretation of a bare int stream must be explicit.
        """
        instructions: list[VMInstruction] = []
        pc = 0
        code_len = len(code)

        while pc < code_len:
            insn_pc = pc
            mutated_op = code[pc]
            pc += 1

            opc_name = cls.resolve_opcode(mutated_op, mutator_map, mode)
            if not opc_name or opc_name not in OPCS_SPECS:
                raise ValueError(f"Unknown BytecodeVM mutated opcode {mutated_op} at pc {insn_pc}")

            jvm_op, fmt = OPCS_SPECS[opc_name]
            operands: list[Any] = []

            if fmt == "none":
                pass
            elif fmt in ("var", "imm", "const", "type", "jump"):
                if pc >= code_len:
                    raise ValueError(f"Truncated operand for {opc_name} at pc {insn_pc}")
                operands.append(code[pc])
                pc += 1
            elif fmt in ("iinc", "multi_array"):
                if pc + 1 >= code_len:
                    raise ValueError(f"Truncated operands for {opc_name} at pc {insn_pc}")
                operands.append(code[pc])
                operands.append(code[pc + 1])
                pc += 2
            elif fmt == "field":
                if pc + 2 >= code_len:
                    raise ValueError(f"Truncated field operands for {opc_name} at pc {insn_pc}")
                operands.extend(code[pc:pc + 3])
                pc += 3
            elif fmt == "method":
                if pc + 3 >= code_len:
                    raise ValueError(f"Truncated method operands for {opc_name} at pc {insn_pc}")
                operands.extend(code[pc:pc + 4])
                pc += 4
            elif fmt == "indy":
                if pc + 3 >= code_len:
                    raise ValueError(f"Truncated indy header for {opc_name} at pc {insn_pc}")
                name_idx, desc_idx, bsm_idx, argc = code[pc:pc + 4]
                pc += 4
                if pc + argc > code_len:
                    raise ValueError(f"Truncated indy args for {opc_name} at pc {insn_pc}")
                args = code[pc:pc + argc]
                pc += argc
                operands = [name_idx, desc_idx, bsm_idx, argc] + args
            elif fmt == "table_switch":
                if pc + 3 >= code_len:
                    raise ValueError(f"Truncated tableswitch header at pc {insn_pc}")
                t_min, t_max, dflt, count = code[pc:pc + 4]
                pc += 4
                if pc + count > code_len:
                    raise ValueError(f"Truncated tableswitch labels at pc {insn_pc}")
                labels = code[pc:pc + count]
                pc += count
                operands = [t_min, t_max, dflt, count] + labels
            elif fmt == "lookup_switch":
                if pc + 1 >= code_len:
                    raise ValueError(f"Truncated lookupswitch header at pc {insn_pc}")
                dflt, npairs = code[pc:pc + 2]
                pc += 2
                pair_len = npairs * 2
                if pc + pair_len > code_len:
                    raise ValueError(f"Truncated lookupswitch pairs at pc {insn_pc}")
                pairs = code[pc:pc + pair_len]
                pc += pair_len
                operands = [dflt, npairs] + pairs
            else:
                raise ValueError(f"Unsupported operand format {fmt} for {opc_name}")

            instructions.append(VMInstruction(
                pc=insn_pc,
                opcode_name=opc_name,
                jvm_opcode=jvm_op,
                fmt=fmt,
                operands=operands
            ))

        return instructions


BVMDecoder = VMDecoder  # backward-compatibility alias


# ---------------------------------------------------------------------------
# Constant pool helper for target ClassFile
# ---------------------------------------------------------------------------

class ConstantPoolHelper:
    """Manages constant pool additions for an existing or new ClassFile."""

    def __init__(self, cf: CF.ClassFile):
        self.cf = cf

    def intern_utf8(self, val: str) -> int:
        return self.cf.intern_utf8(val)

    def add_class(self, internal_name: str) -> int:
        return self.cf.add_class(internal_name)

    def add_name_and_type(self, name: str, desc: str) -> int:
        n_idx = self.intern_utf8(name)
        d_idx = self.intern_utf8(desc)
        for i, e in enumerate(self.cf.cp[1:], 1):
            if e and e[0] == CF.C_NAME_AND_TYPE and e[1] == [n_idx, d_idx]:
                return i
        self.cf.cp.append((CF.C_NAME_AND_TYPE, [n_idx, d_idx]))
        return len(self.cf.cp) - 1

    def add_fieldref(self, owner: str, name: str, desc: str) -> int:
        cls_idx = self.add_class(owner)
        nat_idx = self.add_name_and_type(name, desc)
        for i, e in enumerate(self.cf.cp[1:], 1):
            if e and e[0] == CF.C_FIELDREF and e[1] == [cls_idx, nat_idx]:
                return i
        self.cf.cp.append((CF.C_FIELDREF, [cls_idx, nat_idx]))
        return len(self.cf.cp) - 1

    def add_methodref(self, owner: str, name: str, desc: str) -> int:
        cls_idx = self.add_class(owner)
        nat_idx = self.add_name_and_type(name, desc)
        for i, e in enumerate(self.cf.cp[1:], 1):
            if e and e[0] == CF.C_METHODREF and e[1] == [cls_idx, nat_idx]:
                return i
        self.cf.cp.append((CF.C_METHODREF, [cls_idx, nat_idx]))
        return len(self.cf.cp) - 1

    def add_interface_methodref(self, owner: str, name: str, desc: str) -> int:
        cls_idx = self.add_class(owner)
        nat_idx = self.add_name_and_type(name, desc)
        for i, e in enumerate(self.cf.cp[1:], 1):
            if e and e[0] == CF.C_INTERFACE_METHODREF and e[1] == [cls_idx, nat_idx]:
                return i
        self.cf.cp.append((CF.C_INTERFACE_METHODREF, [cls_idx, nat_idx]))
        return len(self.cf.cp) - 1

    def add_string(self, s: str) -> int:
        u_idx = self.intern_utf8(s)
        for i, e in enumerate(self.cf.cp[1:], 1):
            if e and e[0] == CF.C_STRING and e[1] == [u_idx]:
                return i
        self.cf.cp.append((CF.C_STRING, [u_idx]))
        return len(self.cf.cp) - 1

    def add_int(self, val: int) -> int:
        raw = struct.pack(">i", int(val))
        for i, e in enumerate(self.cf.cp[1:], 1):
            if e and e[0] == CF.C_INTEGER and e[1] == [raw]:
                return i
        self.cf.cp.append((CF.C_INTEGER, [raw]))
        return len(self.cf.cp) - 1

    def add_float(self, val: float) -> int:
        raw = struct.pack(">f", float(val))
        for i, e in enumerate(self.cf.cp[1:], 1):
            if e and e[0] == CF.C_FLOAT and e[1] == [raw]:
                return i
        self.cf.cp.append((CF.C_FLOAT, [raw]))
        return len(self.cf.cp) - 1

    def add_long(self, val: int) -> int:
        raw = struct.pack(">q", int(val))
        for i, e in enumerate(self.cf.cp[1:], 1):
            if e and e[0] == CF.C_LONG and e[1] == [raw]:
                return i
        self.cf.cp.append((CF.C_LONG, [raw]))
        idx = len(self.cf.cp) - 1
        self.cf.cp.append(None)  # Long occupies two slots
        return idx

    def add_double(self, val: float) -> int:
        raw = struct.pack(">d", float(val))
        for i, e in enumerate(self.cf.cp[1:], 1):
            if e and e[0] == CF.C_DOUBLE and e[1] == [raw]:
                return i
        self.cf.cp.append((CF.C_DOUBLE, [raw]))
        idx = len(self.cf.cp) - 1
        self.cf.cp.append(None)  # Double occupies two slots
        return idx

    def add_invoke_dynamic(self, bsm_attr_idx: int, name: str, desc: str) -> int:
        nat_idx = self.add_name_and_type(name, desc)
        for i, e in enumerate(self.cf.cp[1:], 1):
            if e and e[0] == CF.C_INVOKE_DYNAMIC and e[1] == [bsm_attr_idx, nat_idx]:
                return i
        self.cf.cp.append((CF.C_INVOKE_DYNAMIC, [bsm_attr_idx, nat_idx]))
        return len(self.cf.cp) - 1

    def add_constant(self, val: Any) -> int:
        """Add arbitrary constant from BytecodeVM constants table."""
        if isinstance(val, str):
            return self.add_string(val)
        elif isinstance(val, bool):
            return self.add_int(1 if val else 0)
        elif isinstance(val, int):
            if -2147483648 <= val <= 2147483647:
                return self.add_int(val)
            else:
                return self.add_long(val)
        elif isinstance(val, float):
            # a float constant is CONSTANT_Float and one slot; add_double here
            # emitted CONSTANT_Double, so every `ldc` of a float grew the
            # operand stack by 2 and FADD/FSTORE met a double at verification
            return self.add_float(val)
        elif isinstance(val, dict):
            # Complex reference representation
            t = val.get("type")
            if t == "class":
                return self.add_class(val.get("name", "java/lang/Object"))
            elif t == "method":
                return self.add_methodref(val["owner"], val["name"], val["desc"])
            elif t == "field":
                return self.add_fieldref(val["owner"], val["name"], val["desc"])
            elif t == "int":
                return self.add_int(int(val.get("value", 0)))
            elif t == "long":
                return self.add_long(int(val.get("value", 0)))
            elif t == "float":
                return self.add_float(float(val.get("value", 0.0)))
            elif t == "double":
                return self.add_double(float(val.get("value", 0.0)))
            elif t == "string":
                return self.add_string(str(val.get("value", "")))
        return self.add_string(str(val))


def compute_interface_args_count(desc: str) -> int:
    """Compute count operand for invokeinterface (1 for receiver + argument slots)."""
    if not desc or "(" not in desc or ")" not in desc:
        return 1
    params_part = desc[desc.find("(") + 1:desc.find(")")]
    count = 1  # receiver 'this'
    i = 0
    while i < len(params_part):
        ch = params_part[i]
        if ch in ("J", "D"):  # long or double take 2 slots
            count += 2
            i += 1
        elif ch in ("B", "C", "F", "I", "S", "Z"):
            count += 1
            i += 1
        elif ch == "L":
            semi = params_part.find(";", i)
            i = (semi + 1) if semi != -1 else (i + 1)
            count += 1
        elif ch == "[":
            while i < len(params_part) and params_part[i] == "[":
                i += 1
            if i < len(params_part) and params_part[i] == "L":
                semi = params_part.find(";", i)
                i = (semi + 1) if semi != -1 else (i + 1)
            elif i < len(params_part):
                i += 1
            count += 1
        else:
            i += 1
            count += 1
    return count


# ---------------------------------------------------------------------------
# max_stack computation (REVIEW-2026-10-07 §1.3)
#
# `max(declared, 8)` was a guess, and a stack of 9 slots came out declared as
# 8 - a VerifyError waiting for the first caller. The real value is a dataflow
# property of the instruction stream, so we compute it: a worklist fixpoint
# over the decoded instructions, merging join points by max (a sound
# over-approximation - an oversized max_stack is legal, an undersized one is
# not). Long/double occupy two slots; exception handler entries start at
# depth 1 (the caught exception). Branch targets are resolved with the same
# clamp translate_method uses, so the analysis covers exactly the code we emit.
# ---------------------------------------------------------------------------

# opcodes that end a basic block (no fall-through)
_TERMINAL_OPS = frozenset({
    "IRETURN", "LRETURN", "FRETURN", "DRETURN", "ARETURN", "RETURN", "ATHROW",
})

# (pop, push) per slot, for the fixed-shape opcodes. Descriptors (invoke*,
# get/putfield) are resolved dynamically in _stack_effect.
_FIXED_EFFECTS: dict[str, tuple[int, int]] = {
    "ICONST_M1": (0, 1), "ICONST_0": (0, 1), "ICONST_1": (0, 1), "ICONST_2": (0, 1),
    "ICONST_3": (0, 1), "ICONST_4": (0, 1), "ICONST_5": (0, 1),
    "LCONST_0": (0, 2), "LCONST_1": (0, 2),
    "FCONST_0": (0, 1), "FCONST_1": (0, 1), "FCONST_2": (0, 1),
    "DCONST_0": (0, 2), "DCONST_1": (0, 2),
    "ACONST_NULL": (0, 1), "BIPUSH": (0, 1), "SIPUSH": (0, 1),
    "POP": (1, 0), "POP2": (2, 0),
    "DUP": (1, 2), "DUP_X1": (2, 3), "DUP_X2": (3, 4),
    "DUP2": (2, 4), "DUP2_X1": (3, 5), "DUP2_X2": (4, 6), "SWAP": (2, 2),
    "INEG": (1, 1), "FNEG": (1, 1), "LNEG": (2, 2), "DNEG": (2, 2),
    "IINC": (0, 0), "NOP": (0, 0), "GOTO": (0, 0),
    "TABLESWITCH": (1, 0), "LOOKUPSWITCH": (1, 0),
    "IRETURN": (1, 0), "FRETURN": (1, 0), "ARETURN": (1, 0),
    "LRETURN": (2, 0), "DRETURN": (2, 0), "RETURN": (0, 0), "ATHROW": (1, 0),
    "NEW": (0, 1), "NEWARRAY": (1, 1), "ANEWARRAY": (1, 1), "ARRAYLENGTH": (1, 1),
    "CHECKCAST": (1, 1), "INSTANCEOF": (1, 1),
    "MONITORENTER": (1, 0), "MONITOREXIT": (1, 0),
    "IFEQ": (1, 0), "IFNE": (1, 0), "IFLT": (1, 0), "IFGE": (1, 0),
    "IFGT": (1, 0), "IFLE": (1, 0), "IFNULL": (1, 0), "IFNONNULL": (1, 0),
    "IF_ICMPEQ": (2, 0), "IF_ICMPNE": (2, 0), "IF_ICMPLT": (2, 0),
    "IF_ICMPGE": (2, 0), "IF_ICMPGT": (2, 0), "IF_ICMPLE": (2, 0),
    "IF_ACMPEQ": (2, 0), "IF_ACMPNE": (2, 0),
    "I2L": (1, 2), "I2F": (1, 1), "I2D": (1, 2),
    "L2I": (2, 1), "L2F": (2, 1), "L2D": (2, 2),
    "F2I": (1, 1), "F2L": (1, 2), "F2D": (1, 2),
    "D2I": (2, 1), "D2L": (2, 2), "D2F": (2, 1),
    "LCMP": (4, 1), "FCMPL": (2, 1), "FCMPG": (2, 1),
    "DCMPL": (4, 1), "DCMPG": (4, 1),
    "IADD": (2, 1), "ISUB": (2, 1), "IMUL": (2, 1), "IDIV": (2, 1), "IREM": (2, 1),
    "FADD": (2, 1), "FSUB": (2, 1), "FMUL": (2, 1), "FDIV": (2, 1), "FREM": (2, 1),
    "IAND": (2, 1), "IOR": (2, 1), "IXOR": (2, 1),
    "ISHL": (2, 1), "ISHR": (2, 1), "IUSHR": (2, 1),
    "LADD": (4, 2), "LSUB": (4, 2), "LMUL": (4, 2), "LDIV": (4, 2), "LREM": (4, 2),
    "LAND": (4, 2), "LOR": (4, 2), "LXOR": (4, 2),
    "LSHL": (3, 2), "LSHR": (3, 2), "LUSHR": (3, 2),
    "DADD": (4, 2), "DSUB": (4, 2), "DMUL": (4, 2), "DDIV": (4, 2), "DREM": (4, 2),
}

_TWO_SLOT_LOADS = frozenset({"LLOAD", "DLOAD"})
_TWO_SLOT_STORES = frozenset({"LSTORE", "DSTORE"})


def _method_shape(desc: str) -> tuple[int, int]:
    """(argument slots, return slots) from a method descriptor."""
    if not desc or "(" not in desc or ")" not in desc:
        return 0, 0
    params = desc[desc.find("(") + 1:desc.find(")")]
    ret = desc[desc.find(")") + 1:]
    slots = 0
    i = 0
    while i < len(params):
        c = params[i]
        if c in "JD":
            slots += 2
            i += 1
        elif c == "L":
            semi = params.find(";", i)
            i = len(params) if semi < 0 else semi + 1
            slots += 1
        elif c == "[":
            while i < len(params) and params[i] == "[":
                i += 1
            if i < len(params) and params[i] == "L":
                semi = params.find(";", i)
                i = len(params) if semi < 0 else semi + 1
            elif i < len(params):
                i += 1
            slots += 1
        else:
            slots += 1
            i += 1
    rslots = 2 if ret[:1] in ("J", "D") else (0 if ret[:1] == "V" else 1)
    return slots, rslots


def _value_slots(desc: str) -> int:
    """Slots occupied by a single value of the given (field) descriptor."""
    return 2 if desc[:1] in ("J", "D") else 1


def _norm_internal(name: object) -> str:
    """Normalise a class reference from the virtual pool to an internal name.

    The dumped pools mix `java.lang.Exception`, `Ljava/lang/Exception;` and
    already-internal `java/lang/Exception`. Array descriptors keep their `[`
    prefix (the element type inside still carries `L...;`).
    """
    s = str(name).replace(".", "/")
    if s.startswith("["):
        return s
    if s.startswith("L") and s.endswith(";"):
        return s[1:-1]
    return s


def _const_is_two_word(val: Any) -> bool:
    """Mirror ConstantPoolHelper.add_constant's routing: is this LDC 2 slots?"""
    if isinstance(val, dict):
        return val.get("type") in ("long", "double")
    if isinstance(val, bool):
        return False
    if isinstance(val, int):
        return not (-2**31 <= val < 2**31)
    if isinstance(val, float):
        # CONSTANT_Float is one slot (add_constant routes it to add_float now);
        # only long/double occupy two
        return False
    return False


def _stack_effect(insn: VMInstruction, vm_method: VMMethod) -> tuple[int, int]:
    """(pop, push) in slots for one decoded virtual instruction."""
    name = insn.opcode_name
    if name in _FIXED_EFFECTS:
        return _FIXED_EFFECTS[name]
    if name in _TWO_SLOT_LOADS:
        return 0, 2
    if name.endswith("LOAD") and insn.fmt == "var":      # ILOAD/FLOAD/ALOAD
        return 0, 1
    if name in _TWO_SLOT_STORES:
        return 2, 0
    if name.endswith("STORE") and insn.fmt == "var":     # ISTORE/FSTORE/ASTORE
        return 1, 0
    if name.endswith("ALOAD"):                           # array element loads
        return 2, (2 if name in ("LALOAD", "DALOAD") else 1)
    if name.endswith("ASTORE"):                          # array element stores
        return 4 if name in ("LASTORE", "DASTORE") else 3, 0
    if name == "LDC":
        c_idx = insn.operands[0] if insn.operands else -1
        val = vm_method.constants[c_idx] if 0 <= c_idx < len(vm_method.constants) else 0
        return 0, (2 if _const_is_two_word(val) else 1)
    if name in ("GETSTATIC",):
        return 0, _value_slots(str(vm_method.constants[insn.operands[2]])
                               if len(insn.operands) > 2 and
                               0 <= insn.operands[2] < len(vm_method.constants) else "I")
    if name in ("PUTSTATIC",):
        return _value_slots(str(vm_method.constants[insn.operands[2]])
                            if len(insn.operands) > 2 and
                            0 <= insn.operands[2] < len(vm_method.constants) else "I"), 0
    if name == "GETFIELD":
        return 1, _value_slots(str(vm_method.constants[insn.operands[2]])
                               if len(insn.operands) > 2 and
                               0 <= insn.operands[2] < len(vm_method.constants) else "I")
    if name == "PUTFIELD":
        return 1 + _value_slots(str(vm_method.constants[insn.operands[2]])
                                if len(insn.operands) > 2 and
                                0 <= insn.operands[2] < len(vm_method.constants) else "I"), 0
    if name in ("INVOKEVIRTUAL", "INVOKESPECIAL", "INVOKEINTERFACE"):
        args, ret = _method_shape(str(vm_method.constants[insn.operands[2]])
                                  if len(insn.operands) > 2 and
                                  0 <= insn.operands[2] < len(vm_method.constants) else "()V")
        return args + 1, ret                             # + receiver
    if name == "INVOKESTATIC":
        args, ret = _method_shape(str(vm_method.constants[insn.operands[2]])
                                  if len(insn.operands) > 2 and
                                  0 <= insn.operands[2] < len(vm_method.constants) else "()V")
        return args, ret
    if name == "INVOKEDYNAMIC":
        args, ret = _method_shape(str(vm_method.constants[insn.operands[1]])
                                  if len(insn.operands) > 1 and
                                  0 <= insn.operands[1] < len(vm_method.constants) else "()V")
        return args, ret
    if name == "MULTIANEWARRAY":
        dims = insn.operands[1] if len(insn.operands) > 1 else 1
        return int(dims), 1
    # Unknown shape: (0, 0) can only understate. Everything in OPCS_SPECS is
    # covered above, so reaching here means the spec table grew without this
    # analysis - fail loudly instead of silently declaring a small stack.
    raise ValueError(f"no stack effect known for opcode {name!r}; "
                     f"extend _FIXED_EFFECTS/_stack_effect")


def compute_max_stack(instructions: list[VMInstruction], vm_method: VMMethod,
                      v_pc_to_idx: dict[int, int]) -> int:
    """Compute the real max_stack (in slots) of a decoded virtual stream.

    Worklist fixpoint: depth is propagated per instruction, join points merge
    by max, exception handler entries start at depth 1. Returns the deepest
    point any executable path reaches - a sound over-approximation of what the
    JVM verifier will demand.
    """
    if not instructions:
        return max(getattr(vm_method, "max_stack", 0), 0)

    depths: dict[int, int] = {0: 0}
    work: collections.deque[int] = collections.deque([0])

    eh = vm_method.exception_handlers
    for i in range(0, len(eh) - 3, 4):
        h_idx = v_pc_to_idx.get(eh[i + 2])
        if h_idx is not None and depths.get(h_idx, -1) < 1:
            depths[h_idx] = 1
            work.append(h_idx)

    peak = 0
    last = len(instructions) - 1
    while work:
        idx = work.popleft()
        d = depths[idx]
        insn = instructions[idx]
        pop, push = _stack_effect(insn, vm_method)
        after = d - pop + push
        peak = max(peak, d, after)
        if after < 0:
            after = 0  # malformed stream: clamp so propagation stays usable

        def reach(target_vpc: int) -> None:
            t_idx = v_pc_to_idx.get(target_vpc, last)
            if after > depths.get(t_idx, -1):
                depths[t_idx] = after
                work.append(t_idx)

        if insn.fmt == "jump":
            reach(insn.operands[0])
            if insn.opcode_name == "GOTO":
                continue                                # no fall-through
        elif insn.fmt == "table_switch":
            count = insn.operands[3]
            reach(insn.operands[2])                     # default
            for vt in insn.operands[4:4 + count]:
                reach(vt)
            continue
        elif insn.fmt == "lookup_switch":
            reach(insn.operands[0])                     # default
            pairs = insn.operands[2:2 + int(insn.operands[1]) * 2]
            for vt in pairs[1::2]:
                reach(vt)
            continue
        if insn.opcode_name in _TERMINAL_OPS:
            continue
        if idx < last:
            if after > depths.get(idx + 1, -1):
                depths[idx + 1] = after
                work.append(idx + 1)
    return peak


# ---------------------------------------------------------------------------
# Virtual to standard JVM bytecode re-translator
# ---------------------------------------------------------------------------

class VMTranslator:
    """Translates decoded VMInstructions into valid JVM bytecode with CFG assembly."""

    @classmethod
    def translate_method(
        cls,
        vm_method: VMMethod,
        cf: CF.ClassFile,
        allow_widening: bool = True
    ) -> DevirtualizedResult:
        """Translate a VMMethod into standard JVM bytecode and reassemble through CFG."""
        instructions = VMDecoder.decode(vm_method.code, vm_method.opcode_map,
                                        mode=getattr(vm_method, "mode", "ordinal"))
        cp_helper = ConstantPoolHelper(cf)

        # 1. Map virtual PC to instruction index
        v_pc_to_idx: dict[int, int] = {}
        for idx, insn in enumerate(instructions):
            v_pc_to_idx[insn.pc] = idx

        # Estimate initial bytecode layout & size
        # We perform an iterative layout calculation
        # Pass 1: generate template instruction buffers with zeroed jump offsets
        raw_insn_bytes: list[bytearray] = []
        insn_lengths: list[int] = []

        for insn in instructions:
            buf = bytearray()
            op = insn.jvm_opcode
            fmt = insn.fmt
            operands = insn.operands

            if fmt == "none":
                buf.append(op)
            elif fmt == "var":
                var_slot = operands[0]
                if var_slot > 255:
                    buf.extend([0xC4, op, (var_slot >> 8) & 0xFF, var_slot & 0xFF])
                else:
                    buf.extend([op, var_slot & 0xFF])
            elif fmt == "imm":
                if op == 0x10:  # BIPUSH
                    buf.extend([op, operands[0] & 0xFF])
                elif op == 0x11:  # SIPUSH
                    sval = operands[0]
                    buf.extend([op, (sval >> 8) & 0xFF, sval & 0xFF])
                elif op == 0xBC:  # NEWARRAY
                    buf.extend([op, operands[0] & 0xFF])
                else:
                    buf.extend([op, operands[0] & 0xFF])
            elif fmt == "iinc":
                var_slot, incr = operands[0], operands[1]
                if var_slot > 255 or not (-128 <= incr <= 127):
                    buf.extend([0xC4, 0x84, (var_slot >> 8) & 0xFF, var_slot & 0xFF,
                                (incr >> 8) & 0xFF, incr & 0xFF])
                else:
                    buf.extend([0x84, var_slot & 0xFF, incr & 0xFF])
            elif fmt == "const":
                c_idx = operands[0]
                c_val = vm_method.constants[c_idx] if c_idx < len(vm_method.constants) else 0
                cpi = cp_helper.add_constant(c_val)
                cp_entry = cf.cp[cpi] if cpi < len(cf.cp) else None
                is_two_word = cp_entry and cp_entry[0] in (CF.C_LONG, CF.C_DOUBLE)
                if is_two_word:
                    buf.extend([0x14, (cpi >> 8) & 0xFF, cpi & 0xFF])  # ldc2_w
                elif cpi > 255:
                    buf.extend([0x13, (cpi >> 8) & 0xFF, cpi & 0xFF])  # ldc_w
                else:
                    buf.extend([0x12, cpi & 0xFF])  # ldc
            elif fmt == "type":
                c_idx = operands[0]
                c_val = vm_method.constants[c_idx] if c_idx < len(vm_method.constants) else "java/lang/Object"
                cpi = cp_helper.add_class(_norm_internal(c_val))
                buf.extend([op, (cpi >> 8) & 0xFF, cpi & 0xFF])
            elif fmt == "field":
                o_idx, n_idx, d_idx = operands[0], operands[1], operands[2]
                owner = _norm_internal(vm_method.constants[o_idx])
                name = str(vm_method.constants[n_idx])
                desc = str(vm_method.constants[d_idx])
                cpi = cp_helper.add_fieldref(owner, name, desc)
                buf.extend([op, (cpi >> 8) & 0xFF, cpi & 0xFF])
            elif fmt == "method":
                o_idx, n_idx, d_idx, itf = operands[0], operands[1], operands[2], operands[3]
                owner = _norm_internal(vm_method.constants[o_idx])
                name = str(vm_method.constants[n_idx])
                desc = str(vm_method.constants[d_idx])
                if op == 0xB9:  # INVOKEINTERFACE
                    cpi = cp_helper.add_interface_methodref(owner, name, desc)
                    argc = compute_interface_args_count(desc)
                    buf.extend([op, (cpi >> 8) & 0xFF, cpi & 0xFF, argc & 0xFF, 0x00])
                else:
                    cpi = cp_helper.add_methodref(owner, name, desc)
                    buf.extend([op, (cpi >> 8) & 0xFF, cpi & 0xFF])
            elif fmt == "indy":
                n_idx, d_idx, b_idx, argc = operands[0], operands[1], operands[2], operands[3]
                name = str(vm_method.constants[n_idx])
                desc = str(vm_method.constants[d_idx])
                cpi = cp_helper.add_invoke_dynamic(b_idx, name, desc)
                buf.extend([0xBA, (cpi >> 8) & 0xFF, cpi & 0xFF, 0x00, 0x00])
            elif fmt == "multi_array":
                t_idx, dims = operands[0], operands[1]
                owner = _norm_internal(vm_method.constants[t_idx])
                cpi = cp_helper.add_class(owner)
                buf.extend([op, (cpi >> 8) & 0xFF, cpi & 0xFF, dims & 0xFF])
            elif fmt == "jump":
                # Reserve 3 bytes initially for 16-bit branch
                buf.extend([op, 0x00, 0x00])
            elif fmt == "table_switch":
                # tableswitch placeholder (pad + min + max + dflt + targets)
                t_min, t_max, dflt, count = operands[0], operands[1], operands[2], operands[3]
                buf.append(op)
                # We align later during PC resolution; reserve max 3 pad bytes
                buf.extend([0x00] * (3 + 4 + 4 + 4 + count * 4))
            elif fmt == "lookup_switch":
                dflt, npairs = operands[0], operands[1]
                buf.append(op)
                buf.extend([0x00] * (3 + 4 + 4 + npairs * 8))

            raw_insn_bytes.append(buf)
            insn_lengths.append(len(buf))

        # Iteratively resolve bytecode PCs and jump offsets
        for _round in range(5):
            cur_bc_pc = 0
            bc_starts: list[int] = []
            for idx in range(len(instructions)):
                bc_starts.append(cur_bc_pc)
                # align switches
                if instructions[idx].fmt in ("table_switch", "lookup_switch"):
                    pad = (4 - ((cur_bc_pc + 1) % 4)) % 4
                    if instructions[idx].fmt == "table_switch":
                        count = instructions[idx].operands[3]
                        raw_insn_bytes[idx] = bytearray([0xAA] + [0x00] * (pad + 12 + count * 4))
                    else:
                        npairs = instructions[idx].operands[1]
                        raw_insn_bytes[idx] = bytearray([0xAB] + [0x00] * (pad + 8 + npairs * 8))
                    insn_lengths[idx] = len(raw_insn_bytes[idx])

                cur_bc_pc += insn_lengths[idx]

            # Patch jump offsets
            for idx, insn in enumerate(instructions):
                if insn.fmt == "jump":
                    v_target = insn.operands[0]
                    target_idx = v_pc_to_idx.get(v_target, len(instructions) - 1)
                    target_bc = bc_starts[target_idx] if target_idx < len(bc_starts) else cur_bc_pc
                    delta = target_bc - bc_starts[idx]
                    if not (-32768 <= delta <= 32767):
                        if insn.jvm_opcode == 0xA7:  # GOTO -> GOTO_W
                            raw_insn_bytes[idx] = bytearray([0xC8, (delta >> 24) & 0xFF, (delta >> 16) & 0xFF, (delta >> 8) & 0xFF, delta & 0xFF])
                            insn_lengths[idx] = 5
                        else:
                            inv_op = CFG._INVERT_BRANCH.get(insn.jvm_opcode, insn.jvm_opcode)
                            goto_w_delta = delta - 3
                            raw_insn_bytes[idx] = bytearray([
                                inv_op, 0x00, 0x08,
                                0xC8, (goto_w_delta >> 24) & 0xFF, (goto_w_delta >> 16) & 0xFF,
                                (goto_w_delta >> 8) & 0xFF, goto_w_delta & 0xFF
                            ])
                            insn_lengths[idx] = 8
                    else:
                        raw_insn_bytes[idx] = bytearray([insn.jvm_opcode, (delta >> 8) & 0xFF, delta & 0xFF])
                        insn_lengths[idx] = 3
                elif insn.fmt == "table_switch":
                    t_min, t_max, v_dflt, count = insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]
                    targets = insn.operands[4:4 + count]
                    base_pc = bc_starts[idx]
                    pad = (4 - ((base_pc + 1) % 4)) % 4

                    dflt_idx = v_pc_to_idx.get(v_dflt, len(instructions) - 1)
                    dflt_bc = bc_starts[dflt_idx] if dflt_idx < len(bc_starts) else cur_bc_pc
                    dflt_delta = dflt_bc - base_pc

                    out = bytearray([0xAA])
                    out.extend([0x00] * pad)
                    out.extend(struct.pack(">iii", dflt_delta, t_min, t_max))
                    for vt in targets:
                        t_idx = v_pc_to_idx.get(vt, len(instructions) - 1)
                        t_bc = bc_starts[t_idx] if t_idx < len(bc_starts) else cur_bc_pc
                        out.extend(struct.pack(">i", t_bc - base_pc))
                    raw_insn_bytes[idx] = out
                    insn_lengths[idx] = len(out)
                elif insn.fmt == "lookup_switch":
                    v_dflt, npairs = insn.operands[0], insn.operands[1]
                    pairs = insn.operands[2:2 + npairs * 2]
                    base_pc = bc_starts[idx]
                    pad = (4 - ((base_pc + 1) % 4)) % 4

                    dflt_idx = v_pc_to_idx.get(v_dflt, len(instructions) - 1)
                    dflt_bc = bc_starts[dflt_idx] if dflt_idx < len(bc_starts) else cur_bc_pc
                    dflt_delta = dflt_bc - base_pc

                    out = bytearray([0xAB])
                    out.extend([0x00] * pad)
                    out.extend(struct.pack(">ii", dflt_delta, npairs))
                    for k in range(0, len(pairs), 2):
                        match_val = pairs[k]
                        vt = pairs[k + 1]
                        t_idx = v_pc_to_idx.get(vt, len(instructions) - 1)
                        t_bc = bc_starts[t_idx] if t_idx < len(bc_starts) else cur_bc_pc
                        out.extend(struct.pack(">ii", match_val, t_bc - base_pc))
                    raw_insn_bytes[idx] = out
                    insn_lengths[idx] = len(out)

        # Assemble linear bytecode payload
        assembled_raw = bytearray()
        for b in raw_insn_bytes:
            assembled_raw.extend(b)

        # Translate exception handlers
        handlers: list[Handler] = []
        eh = vm_method.exception_handlers
        for i in range(0, len(eh), 4):
            if i + 3 < len(eh):
                v_start, v_end, v_handler, c_type = eh[i], eh[i + 1], eh[i + 2], eh[i + 3]
                s_idx = v_pc_to_idx.get(v_start, 0)
                # end_pc is exclusive and may equal the virtual code length,
                # where no instruction starts. Defaulting to "last instruction"
                # dropped the final instruction from the protected range.
                e_idx = v_pc_to_idx.get(v_end)
                h_idx = v_pc_to_idx.get(v_handler, 0)

                s_bc = bc_starts[s_idx] if s_idx < len(bc_starts) else 0
                e_bc = (len(assembled_raw) if e_idx is None
                        else bc_starts[e_idx] if e_idx < len(bc_starts)
                        else len(assembled_raw))
                h_bc = bc_starts[h_idx] if h_idx < len(bc_starts) else 0

                catch_cpi = 0
                if 0 <= c_type < len(vm_method.constants) and vm_method.constants[c_type]:
                    catch_cpi = cp_helper.add_class(
                        _norm_internal(vm_method.constants[c_type]))

                handlers.append(Handler(start_pc=s_bc, end_pc=e_bc, handler_pc=h_bc, catch_type=catch_cpi))

        # -------------------------------------------------------------------
        # CFG Reassembly: automatic 16-bit branch widening (>32KB),
        # inverted conditional branch expansion, and alignment verification.
        # -------------------------------------------------------------------
        cfg = CFG.build_cfg(bytes(assembled_raw), handlers)
        final_code, final_handlers, stats = CFG.assemble_cfg(cfg, allow_widening=allow_widening)
        widened_goto_count = stats.get("widened_goto", 0) + sum(1 for b in raw_insn_bytes if b and b[0] == 0xC8)
        widened_if_count = stats.get("widened_if", 0) + sum(1 for b in raw_insn_bytes if len(b) >= 8 and b[3] == 0xC8)
        stats["widened_goto"] = widened_goto_count
        stats["widened_if"] = widened_if_count

        computed_locals = max(vm_method.max_locals, 1)
        for insn in instructions:
            if insn.fmt == "var":
                slot = insn.operands[0]
                is_two_slot = insn.jvm_opcode in (0x16, 0x18, 0x37, 0x39)
                needed = slot + (2 if is_two_slot else 1)
                computed_locals = max(computed_locals, needed)
            elif insn.fmt == "iinc":
                computed_locals = max(computed_locals, insn.operands[0] + 1)
        if vm_method.desc:
            param_slots = compute_interface_args_count(vm_method.desc)
            if vm_method.is_static:
                param_slots -= 1
            computed_locals = max(computed_locals, param_slots)

        # Real stack-depth dataflow (REVIEW-2026-10-07 §1.3): the declared
        # value stays as a floor (it is input, not a guess), but the computed
        # peak replaces the old `max(declared, 8)` shrug.
        computed_stack = compute_max_stack(instructions, vm_method, v_pc_to_idx)
        max_stack = max(computed_stack, vm_method.max_stack)
        stats["max_stack"] = computed_stack
        stats["max_stack_source"] = "computed"

        return DevirtualizedResult(
            code_id=vm_method.code_id,
            name=vm_method.name,
            desc=vm_method.desc,
            bytecode=final_code,
            handlers=final_handlers,
            max_stack=max_stack,
            max_locals=computed_locals,
            instructions_count=len(instructions),
            stats=stats
        )


BVMTranslator = VMTranslator  # backward-compatibility alias


# ---------------------------------------------------------------------------
# High-level Class & JAR devirtualization pipeline
# ---------------------------------------------------------------------------

class Devirtualizer:
    """Automated JVM bytecode devirtualization engine."""

    @classmethod
    def build_code_attribute(
        cls,
        cf: CF.ClassFile,
        max_stack: int,
        max_locals: int,
        code_bytes: bytes,
        handlers: list[Handler]
    ) -> bytes:
        """Construct a valid JVM Code attribute blob.

        Note: the rebuilt Code carries no sub-attributes — in particular no
        StackMapTable.  Java 7+ JVM verification may reject such classes
        (VerifyError); decompilers recompute the frames themselves, so jdec
        output is unaffected.  The CLI prints this boundary on every run.
        """
        code_attr_idx = cf.intern_utf8("Code")

        ex_buf = bytearray()
        ex_buf += struct.pack(">H", len(handlers))
        for h in handlers:
            ex_buf += struct.pack(">HHHH", h.start_pc, h.end_pc, h.handler_pc, h.catch_type)

        body = bytearray()
        body += struct.pack(">HHI", max_stack, max_locals, len(code_bytes))
        body += code_bytes
        body += ex_buf
        body += struct.pack(">H", 0)  # sub-attributes count (0)

        attr_len = len(body)
        return struct.pack(">HI", code_attr_idx, attr_len) + body

    @classmethod
    def set_code_attribute(cls, cf: CF.ClassFile, method: CF.Member, code_attr: bytes) -> None:
        """Replace or add Code attribute in method, preserving all other attributes (e.g. annotations, signatures)."""
        attrs: list[tuple[int, bytes]] = []
        code_attr_name_idx = cf.intern_utf8("Code")
        has_code = False

        if method.attrs_blob and len(method.attrs_blob) >= 2:
            count = struct.unpack_from(">H", method.attrs_blob, 0)[0]
            p = 2
            for _ in range(count):
                if p + 6 > len(method.attrs_blob):
                    break
                ni = struct.unpack_from(">H", method.attrs_blob, p)[0]
                alen = struct.unpack_from(">I", method.attrs_blob, p + 2)[0]
                p += 6
                if p + alen > len(method.attrs_blob):
                    break
                adata = method.attrs_blob[p:p + alen]
                p += alen

                if ni < len(cf.cp) and cf.utf8(ni) == "Code":
                    new_alen = struct.unpack_from(">I", code_attr, 2)[0]
                    new_adata = code_attr[6:6 + new_alen]
                    attrs.append((code_attr_name_idx, new_adata))
                    has_code = True
                else:
                    attrs.append((ni, adata))

        if not has_code:
            new_alen = struct.unpack_from(">I", code_attr, 2)[0]
            new_adata = code_attr[6:6 + new_alen]
            attrs.append((code_attr_name_idx, new_adata))

        out = bytearray(struct.pack(">H", len(attrs)))
        for ni, adata in attrs:
            out += struct.pack(">HI", ni, len(adata)) + adata
        method.attrs_blob = bytes(out)

    @classmethod
    def devirtualize_class_file(
        cls,
        cf: CF.ClassFile,
        code_pool: dict[int, VMMethod],
        errors: list[str] | None = None,
    ) -> tuple[CF.ClassFile, int]:
        """Devirtualize methods in a ClassFile matching codeId from code_pool."""
        devirtualized_count = 0

        for method in cf.methods:
            # Check if method calls VM.execute or matches by codeId
            code_id = cls.extract_code_id(cf, method, errors)
            if code_id is None:
                continue

            vm_method = code_pool.get(code_id)
            if not vm_method:
                continue

            result = VMTranslator.translate_method(vm_method, cf)
            code_attr = cls.build_code_attribute(
                cf,
                result.max_stack,
                result.max_locals,
                result.bytecode,
                result.handlers
            )

            # Preserve all non-Code attributes (annotations, signatures, exceptions)
            cls.set_code_attribute(cf, method, code_attr)
            devirtualized_count += 1

        return cf, devirtualized_count

    @classmethod
    def extract_code_id(cls, cf: CF.ClassFile, method: CF.Member,
                        errors: list[str] | None = None) -> int | None:
        """Inspect method bytecode to extract the VM execution codeId.

        `errors` (optional) receives malformed-attribute failures; without it a
        broken method is indistinguishable from "this method is not a VM call".
        """
        if not method.attrs_blob or len(method.attrs_blob) < 8:
            return None

        # Parse Code attribute
        try:
            o = 2  # skip attr count
            while o < len(method.attrs_blob):
                name_idx = struct.unpack_from(">H", method.attrs_blob, o)[0]
                attr_len = struct.unpack_from(">I", method.attrs_blob, o + 2)[0]
                o += 6
                if name_idx < len(cf.cp) and cf.utf8(name_idx) == "Code":
                    max_stack, max_locals, code_len = struct.unpack_from(">HHI", method.attrs_blob, o)
                    code_bytes = method.attrs_blob[o + 8:o + 8 + code_len]
                    insns = BC.decode(code_bytes)

                    # Look for: push codeId -> ... -> invokestatic execute
                    pushed_int = None
                    for insn in insns:
                        # integer constant pushes
                        if 0x02 <= insn.op <= 0x08:  # iconst_m1..iconst_5
                            pushed_int = insn.op - 0x03
                        elif insn.op in (0x10, 0x11):  # bipush, sipush
                            pushed_int = insn.arg
                        elif insn.op in (0x12, 0x13):  # ldc, ldc_w
                            cpi = insn.arg if insn.arg is not None else 0
                            if cpi < len(cf.cp) and cf.cp[cpi] and cf.cp[cpi][0] == CF.C_INTEGER:
                                pushed_int = struct.unpack(">i", cf.cp[cpi][1][0])[0]

                        # check for invokestatic calling execute
                        if insn.op == 0xB8 and insn.arg is not None:
                            m_idx = insn.arg
                            if m_idx < len(cf.cp) and cf.cp[m_idx] and cf.cp[m_idx][0] == CF.C_METHODREF:
                                nat_idx = cf.cp[m_idx][1][1]
                                if nat_idx < len(cf.cp) and cf.cp[nat_idx] and cf.cp[nat_idx][0] == CF.C_NAME_AND_TYPE:
                                    m_name = cf.utf8(cf.cp[nat_idx][1][0])
                                    m_desc = cf.utf8(cf.cp[nat_idx][1][1])
                                    # 描述符校验：execute 的第一参数必须是 int，
                                    # 与前面 push 的 codeId 语义一致；只撞名不撞
                                    # 签名的同名方法不算命中（防误报 codeId）
                                    if (m_name == "execute"
                                            and m_desc.startswith("(I")
                                            and pushed_int is not None):
                                        return pushed_int

                o += attr_len
        except Exception as exc:  # noqa: BLE001
            if errors is not None:
                errors.append(f"method name_index={method.name_index}: {exc}")
            return None

        return None

    @classmethod
    def scan_jar_code_pool_ex(
        cls, input_jar: Path
    ) -> tuple[dict[int, VMMethod], dict]:
        """Scan for CodePool tables and report what could not be read.

        A pool scan that fails and a jar that simply has no pool used to look
        identical (both returned {}), so `devirtualize` reported success with
        0 classes.
        """
        from . import clinit_sim as CS
        pool: dict[int, VMMethod] = {}
        stats: dict = {"classes_seen": 0, "classes_parsed": 0, "errors": []}
        try:
            with zipfile.ZipFile(input_jar, "r") as zin:
                for item in zin.infolist():
                    if not item.filename.endswith(".class"):
                        continue
                    if "CodePool" in item.filename or "Program" in item.filename:
                        stats["classes_seen"] += 1
                        try:
                            cf = CF.parse(zin.read(item.filename))
                            stats["classes_parsed"] += 1
                            fields, _ = CS.collect_fields(cf)
                            op_streams = None
                            consts = []
                            for f_name, f_val in fields.items():
                                if "OPCODE" in f_name.upper() or "STREAM" in f_name.upper():
                                    rows = CS.rows_of(f_val)
                                    if rows:
                                        op_streams = rows
                                elif "CONST" in f_name.upper():
                                    c_rows = CS.rows_of(f_val)
                                    if c_rows:
                                        consts = c_rows

                            if op_streams:
                                for idx, row in enumerate(op_streams):
                                    c_list = consts[idx] if idx < len(consts) and isinstance(consts[idx], list) else []
                                    pool[idx] = VMMethod(code_id=idx, code=row, constants=c_list)
                        except Exception as exc:  # noqa: BLE001
                            stats["errors"].append(f"{item.filename}: {exc}")
        except Exception as exc:  # noqa: BLE001
            stats["errors"].append(f"{input_jar.name}: {exc}")
        return pool, stats

    @classmethod
    def scan_jar_code_pool(cls, input_jar: Path) -> dict[int, VMMethod]:
        """Auto-scan JAR for CodePool static initialization tables."""
        pool, _stats = cls.scan_jar_code_pool_ex(input_jar)
        return pool

    @classmethod
    def devirtualize_jar(
        cls,
        input_jar: Path,
        output_jar: Path,
        code_pool: dict[int, VMMethod]
    ) -> dict[str, Any]:
        """Devirtualize an entire JAR archive using provided code_pool."""
        output_jar.parent.mkdir(parents=True, exist_ok=True)
        working_pool = dict(code_pool)
        scan_stats = None
        if not working_pool:
            scanned, scan_stats = cls.scan_jar_code_pool_ex(input_jar)
            if scanned:
                working_pool.update(scanned)
            elif scan_stats["classes_seen"] or scan_stats["errors"]:
                print(f"devirt: code-pool scan found 0 tables in "
                      f"{scan_stats['classes_seen']} candidate class(es)"
                      + (f", {len(scan_stats['errors'])} error(s)"
                         if scan_stats["errors"] else ""))
                for line in scan_stats["errors"][:5]:
                    print(f"  ! {line}")

        total_classes = 0
        devirtualized_classes = 0
        total_methods = 0
        failed: list[str] = []
        code_id_errors: list[str] = []

        with zipfile.ZipFile(input_jar, "r") as zin, zipfile.ZipFile(output_jar, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename.endswith(".class"):
                    total_classes += 1
                    try:
                        cf = CF.parse(data)
                        cf, count = cls.devirtualize_class_file(
                            cf, working_pool, errors=code_id_errors)
                        if count > 0:
                            devirtualized_classes += 1
                            total_methods += count
                            data = cf.serialize()
                    except Exception as exc:  # noqa: BLE001
                        failed.append(f"{item.filename}: {exc}")
                zout.writestr(item, data)

        if code_id_errors:
            print(f"devirt: {len(code_id_errors)} method(s) had malformed Code "
                  f"attributes (codeId unknown): {code_id_errors[0]}")
        if failed:
            limit = 20
            print(f"devirt: {len(failed)}/{total_classes} class(es) failed to "
                  f"devirtualize (written back unchanged):")
            for line in failed[:limit]:
                print(f"  ! {line}")
            if len(failed) > limit:
                print(f"  ! ... and {len(failed) - limit} more")

        return {
            "total_classes": total_classes,
            "devirtualized_classes": devirtualized_classes,
            "devirtualized_methods": total_methods,
            "failed_classes": failed,
            "code_id_errors": code_id_errors,
            "scan": scan_stats,
            "output": output_jar
        }

    @classmethod
    def _normalize_opcode_map(cls, raw: Any, where: str) -> list[int] | dict[int, int] | None:
        """Normalize an opcode_map coming from JSON back into working types.

        JSON object keys are always strings, so a dict opcode_map `{7: 4}`
        round-trips to `{"7": 4}` - and without this normalization
        `resolve_opcode(7, map)` returned None and every pool import silently
        failed to decode (REVIEW-2026-10-07 §1.2). Keys are coerced to int
        and every value is validated instead of trusted.
        """
        if raw is None:
            return None
        if isinstance(raw, list):
            out: list[int] = []
            for i, v in enumerate(raw):
                if v is None:
                    out.append(-1)          # explicit "unmapped" slot
                elif isinstance(v, int) and 0 <= v < len(OPCS_ORDINALS):
                    out.append(v)
                elif isinstance(v, str) and v in OPCS_SPECS:
                    out.append(ORDINAL_BY_NAME[v])
                else:
                    raise ValueError(
                        f"{where}: opcode_map[{i}] = {v!r} is not a valid "
                        f"OPCS ordinal (<{len(OPCS_ORDINALS)}) or mnemonic")
            return out
        if isinstance(raw, dict):
            out_d: dict[int, int] = {}
            for k, v in raw.items():
                try:
                    key = int(k)
                except (TypeError, ValueError):
                    raise ValueError(
                        f"{where}: opcode_map key {k!r} is not an integer") from None
                if isinstance(v, int) and 0 <= v < len(OPCS_ORDINALS):
                    out_d[key] = v
                elif isinstance(v, str) and v in OPCS_SPECS:
                    out_d[key] = ORDINAL_BY_NAME[v]
                else:
                    raise ValueError(
                        f"{where}: opcode_map[{k}] = {v!r} is not a valid "
                        f"OPCS ordinal (<{len(OPCS_ORDINALS)}) or mnemonic")
            return out_d
        raise ValueError(
            f"{where}: opcode_map must be a list, dict or null, got {type(raw).__name__}")

    @classmethod
    def load_code_pool(cls, path: Path) -> dict[int, VMMethod]:
        """Load code pool dictionary from a JSON file."""
        import json
        data = json.loads(path.read_text(encoding="utf-8"))
        res: dict[int, VMMethod] = {}
        items = data.values() if isinstance(data, dict) else data
        for item in items:
            mode = item.get("mode", "ordinal")
            if mode not in ("ordinal", "jvm-opcode"):
                raise ValueError(
                    f"code pool entry {item.get('code_id')!r}: unknown opcode mode {mode!r} "
                    f"(expected 'ordinal' or 'jvm-opcode')")
            method = VMMethod(
                code_id=int(item["code_id"]),
                name=item.get("name", ""),
                desc=item.get("desc", ""),
                is_static=item.get("is_static", False),
                code=[int(c) for c in item.get("code", [])],
                constants=item.get("constants", []),
                exception_handlers=[int(e) for e in item.get("exception_handlers", [])],
                max_locals=item.get("max_locals", 2),
                max_stack=item.get("max_stack", 4),
                opcode_map=cls._normalize_opcode_map(
                    item.get("opcode_map"), f"code pool entry {item.get('code_id')!r}"),
                mode=mode,
            )
            res[method.code_id] = method
        return res

    @classmethod
    def save_code_pool(cls, code_pool: dict[int, VMMethod], path: Path) -> None:
        """Save code pool dictionary to a JSON file."""
        import json
        from dataclasses import asdict
        path.parent.mkdir(parents=True, exist_ok=True)
        out = {str(k): asdict(v) for k, v in code_pool.items()}
        path.write_text(json.dumps(out, indent=2), encoding="utf-8")


BVMDevirtualizer = Devirtualizer  # backward-compatibility alias

