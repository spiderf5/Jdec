"""Generic JVM bytecode devirtualization and re-translation engine.

Reconstructs virtualized private instruction streams into compliant JVM bytecode,
reassembles control flow via CFG with far jump widening (>32KB), aligns switch jump tables,
reconstructs exception handlers and stack maps, and restores original method bodies into ClassFiles.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import zipfile

from . import bytecode as BC
from . import cfg as CFG
from . import classfile as CF
from .bytecode import Insn, Handler

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
            return self.add_double(val)
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
        instructions = VMDecoder.decode(vm_method.code, vm_method.opcode_map)
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
                cls_str = str(c_val).replace(".", "/")
                if cls_str.startswith("L") and cls_str.endswith(";") and not cls_str.startswith("["):
                    cls_str = cls_str[1:-1]
                cpi = cp_helper.add_class(cls_str)
                buf.extend([op, (cpi >> 8) & 0xFF, cpi & 0xFF])
            elif fmt == "field":
                o_idx, n_idx, d_idx = operands[0], operands[1], operands[2]
                owner = str(vm_method.constants[o_idx]).replace(".", "/")
                if owner.startswith("L") and owner.endswith(";") and not owner.startswith("["):
                    owner = owner[1:-1]
                name = str(vm_method.constants[n_idx])
                desc = str(vm_method.constants[d_idx])
                cpi = cp_helper.add_fieldref(owner, name, desc)
                buf.extend([op, (cpi >> 8) & 0xFF, cpi & 0xFF])
            elif fmt == "method":
                o_idx, n_idx, d_idx, itf = operands[0], operands[1], operands[2], operands[3]
                owner = str(vm_method.constants[o_idx]).replace(".", "/")
                if owner.startswith("L") and owner.endswith(";") and not owner.startswith("["):
                    owner = owner[1:-1]
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
                owner = str(vm_method.constants[t_idx]).replace(".", "/")
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
                e_idx = v_pc_to_idx.get(v_end, len(instructions) - 1)
                h_idx = v_pc_to_idx.get(v_handler, 0)

                s_bc = bc_starts[s_idx] if s_idx < len(bc_starts) else 0
                e_bc = bc_starts[e_idx] if e_idx < len(bc_starts) else len(assembled_raw)
                h_bc = bc_starts[h_idx] if h_idx < len(bc_starts) else 0

                catch_cpi = 0
                if 0 <= c_type < len(vm_method.constants) and vm_method.constants[c_type]:
                    catch_cpi = cp_helper.add_class(str(vm_method.constants[c_type]))

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

        return DevirtualizedResult(
            code_id=vm_method.code_id,
            name=vm_method.name,
            desc=vm_method.desc,
            bytecode=final_code,
            handlers=final_handlers,
            max_stack=max(vm_method.max_stack, 8),
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
        code_pool: dict[int, VMMethod]
    ) -> tuple[CF.ClassFile, int]:
        """Devirtualize methods in a ClassFile matching codeId from code_pool."""
        devirtualized_count = 0

        for method in cf.methods:
            # Check if method calls VM.execute or matches by codeId
            code_id = cls.extract_code_id(cf, method)
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
    def extract_code_id(cls, cf: CF.ClassFile, method: CF.Member) -> int | None:
        """Inspect method bytecode to extract the VM execution codeId."""
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
                                    if m_name == "execute" and pushed_int is not None:
                                        return pushed_int

                o += attr_len
        except Exception:
            return None

        return None

    @classmethod
    def scan_jar_code_pool(cls, input_jar: Path) -> dict[int, VMMethod]:
        """Auto-scan JAR for CodePool static initialization tables."""
        from . import clinit_sim as CS
        pool: dict[int, VMMethod] = {}
        try:
            with zipfile.ZipFile(input_jar, "r") as zin:
                for item in zin.infolist():
                    if not item.filename.endswith(".class"):
                        continue
                    if "CodePool" in item.filename or "Program" in item.filename:
                        try:
                            cf = CF.parse(zin.read(item.filename))
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
                        except Exception:
                            pass
        except Exception:
            pass
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
        if not working_pool:
            scanned = cls.scan_jar_code_pool(input_jar)
            if scanned:
                working_pool.update(scanned)

        total_classes = 0
        devirtualized_classes = 0
        total_methods = 0
        failed: list[str] = []

        with zipfile.ZipFile(input_jar, "r") as zin, zipfile.ZipFile(output_jar, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename.endswith(".class"):
                    total_classes += 1
                    try:
                        cf = CF.parse(data)
                        cf, count = cls.devirtualize_class_file(cf, working_pool)
                        if count > 0:
                            devirtualized_classes += 1
                            total_methods += count
                            data = cf.serialize()
                    except Exception as exc:  # noqa: BLE001
                        failed.append(f"{item.filename}: {exc}")
                zout.writestr(item, data)

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
            "output": output_jar
        }

    @classmethod
    def load_code_pool(cls, path: Path) -> dict[int, VMMethod]:
        """Load code pool dictionary from a JSON file."""
        import json
        data = json.loads(path.read_text(encoding="utf-8"))
        res: dict[int, VMMethod] = {}
        items = data.values() if isinstance(data, dict) else data
        for item in items:
            method = VMMethod(
                code_id=int(item["code_id"]),
                name=item.get("name", ""),
                desc=item.get("desc", ""),
                is_static=item.get("is_static", False),
                code=item.get("code", []),
                constants=item.get("constants", []),
                exception_handlers=item.get("exception_handlers", []),
                max_locals=item.get("max_locals", 2),
                max_stack=item.get("max_stack", 4),
                opcode_map=item.get("opcode_map")
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

