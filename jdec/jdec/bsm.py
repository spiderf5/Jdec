"""BootstrapMethods 解析与 invokedynamic 站点枚举。

现代字符串加密（ZKM 27+ / EdNaven 实证）把密文、索引、密钥全部藏进
invokedynamic：每个调用点 = bootstrap 方法 + 动态参数（运行时才算出的
常量表达式）。jdec 原先只有 superblaubeere27 一种专用编码（indy.py），
这里补通用层：

1. 解析类级 BootstrapMethods 属性（BSM 引用 + 静态参数）；
2. 枚举全部 INVOKEDYNAMIC 站点（类 / 方法 / 站点名 / 描述符 / BSM）；
3. 对每个站点向前做表达式恢复：动态参数还原成
   字面量 / 静态字段 / 异或移位运算 的表达式树——这是自洽重放
   （recover 子命令）的输入，运行时字段值代入即可现场求 key。

纪律与 jdec 其余部分一致：只解析，不执行目标代码。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
import zipfile

from . import bytecode as BC
from . import classfile as CF

_I100 = 0x0100  # ACC_NATIVE，这里不直接用，但保持与 analyze 相同的口径

LONG_BIN_OPS = {
    0x61: "ladd", 0x65: "lsub", 0x69: "lmul", 0x79: "lshl", 0x7B: "lshr",
    0x7D: "lushr", 0x7F: "land", 0x81: "lor", 0x83: "lxor",
}
INT_BIN_OPS = {
    0x60: "iadd", 0x64: "isub", 0x68: "imul", 0x78: "ishl", 0x7A: "ishr",
    0x7C: "iushr", 0x7E: "iand", 0x80: "ior", 0x82: "ixor",
}
CONV_OPS = {0x85: "i2l", 0x88: "l2i", 0x75: "lneg", 0x74: "ineg"}
ICONST = range(0x02, 0x09)
OP_GETSTATIC = 0xB2      # bytecode.py 只命名了自己关心的 opcode，这里补齐


# ---------------------------------------------------------------- CP helpers

def _utf8(cf, idx) -> str | None:
    e = cf.cp[idx]
    return e[1].decode("utf-8", "replace") if e and e[0] == CF.C_UTF8 else None


def _cls(cf, idx) -> str | None:
    e = cf.cp[idx]
    return _utf8(cf, e[1][0]) if e and e[0] == CF.C_CLASS else None


def _member(cf, ref_idx):
    e = cf.cp[ref_idx]
    if not e or e[0] not in (CF.C_METHODREF, CF.C_FIELDREF, CF.C_INTERFACE_METHODREF):
        return None, None, None
    cls_idx, nat_idx = e[1]
    nat = cf.cp[nat_idx]
    name = _utf8(cf, nat[1][0])
    desc = _utf8(cf, nat[1][1])
    return _cls(cf, cls_idx), name, desc


def _const(cf, idx):
    """常量池常量 → (kind, value) 树叶节点；非常量返回 ("?", None)。"""
    e = cf.cp[idx]
    if not e:
        return ("?", None)
    tag, payload = e
    if tag == CF.C_INTEGER:
        return ("lit", struct.unpack(">i", bytes(payload[0]))[0])
    if tag == CF.C_LONG:
        return ("lit", struct.unpack(">q", bytes(payload[0]))[0])
    if tag == CF.C_STRING:
        return ("lit", _utf8(cf, payload[0]) or "")
    if tag == CF.C_CLASS:
        return ("cls", _utf8(cf, payload[0]))
    if tag == CF.C_METHOD_HANDLE:
        kind, ref = payload
        owner, name, desc = _member(cf, ref)
        return ("mh", {"kind": kind, "owner": owner, "name": name, "desc": desc})
    if tag == CF.C_METHOD_TYPE:
        return ("mt", _utf8(cf, payload[0]))
    return ("?", None)


def _arity(desc: str) -> int:
    """描述符的参数个数（顶层）。

    D/J 在执行模型里占 2 槽，但在描述符**文本**里仍是 1 个字符——
    这里数的是参数个数，J 后只前进 1 字符。写成 i+=2 会把 ')' 甚至
    返回类型一起吃掉：'(IJ)String' 被数成 3（EdNaven 1213 个字符串
    站点的 idx 槽被 null 顶掉的根因，2026-10-04 实证）。"""
    n, i = 0, 1
    while i < len(desc) and desc[i] != ")":
        if desc[i] in "DJ":
            i += 1
        elif desc[i] == "L":
            i = desc.index(";", i) + 1
        elif desc[i] == "[":
            i += 1
            while desc[i] in "[":
                i += 1
            if desc[i] == "L":
                i = desc.index(";", i) + 1
            else:
                i += 1
        else:
            i += 1
        n += 1
    return n


# ------------------------------------------------------------ BootstrapMethods

@dataclass
class BsmEntry:
    index: int
    kind: int              # 1-9, 见 JVMS 5.4.3.5
    owner: str
    name: str
    desc: str
    args: list = field(default_factory=list)   # _const() 叶节点


def _class_attrs(cf):
    blob = cf.attrs_blob
    if len(blob) < 2:
        return
    try:
        n = struct.unpack_from(">H", blob, 0)[0]
        o = 2
        for _ in range(n):
            if o + 6 > len(blob):
                return
            ni = struct.unpack_from(">H", blob, o)[0]
            ln = struct.unpack_from(">I", blob, o + 2)[0]
            o += 6
            if o + ln > len(blob):
                return
            yield _utf8(cf, ni), blob[o:o + ln]
            o += ln
    except (struct.error, IndexError):
        return


def parse_bsm(cf) -> list[BsmEntry]:
    try:
        for name, data in _class_attrs(cf):
            if name != "BootstrapMethods":
                continue
            if len(data) < 2:
                continue
            cnt = struct.unpack_from(">H", data, 0)[0]
            o = 2
            out = []
            for i in range(cnt):
                if o + 4 > len(data):
                    break
                ref = struct.unpack_from(">H", data, o)[0]
                nargs = struct.unpack_from(">H", data, o + 2)[0]
                o += 4
                if o + nargs * 2 > len(data):
                    break
                args = [_const(cf, struct.unpack_from(">H", data, o + k * 2)[0])
                        for k in range(nargs)]
                o += nargs * 2
                mh = cf.cp[ref] if 0 <= ref < len(cf.cp) else None
                kind = mh[1][0] if mh and mh[0] == CF.C_METHOD_HANDLE else 0
                owner, mname, mdesc = _member(cf, mh[1][1]) if mh and mh[0] == CF.C_METHOD_HANDLE \
                    else (None, None, None)
                out.append(BsmEntry(index=i, kind=kind, owner=owner,
                                    name=mname or "?", desc=mdesc or "?", args=args))
            return out
    except (struct.error, IndexError, KeyError):
        return []
    return []



# ---------------------------------------------------------------- site 枚举

@dataclass
class IndySite:
    cls: str
    method: str
    name: str              # 调用点名称（ZKM 系是单字符 tag）
    desc: str
    bsm: BsmEntry
    dynargs: list = field(default_factory=list)  # 表达式树，见 _const/组合节点


STORE_OPS = {0x36: ("i", None), 0x37: ("l", None)}       # istore/lstore
STORE_N = {0x3B: ("i", 0), 0x3C: ("i", 1), 0x3D: ("i", 2), 0x3E: ("i", 3),
           0x3F: ("l", 0), 0x40: ("l", 1), 0x41: ("l", 2), 0x42: ("l", 3)}
LOAD_OPS = {0x15: ("i", None), 0x22: ("l", None)}
LOAD_N = {0x1A: ("i", 0), 0x1B: ("i", 1), 0x1C: ("i", 2), 0x1D: ("i", 3),
          0x1E: ("l", 0), 0x1F: ("l", 1), 0x20: ("l", 2), 0x21: ("l", 3)}
ALOAD_N = {0x2A: 0, 0x2B: 1, 0x2C: 2, 0x2D: 3}


def _walk_bsm(cf, bsm_cache):
    if "bsm" not in bsm_cache:
        bsm_cache["bsm"] = parse_bsm(cf)
    return bsm_cache["bsm"]


def enum_sites(cf, bsm_cache: dict | None = None) -> list[IndySite]:
    cache = bsm_cache if bsm_cache is not None else {}
    bsm = _walk_bsm(cf, cache)
    sites = []
    # 局部变量建模：ZKM 的 key 链普遍经过 lstore/lload（EdNaven 实证：
    # long l = a ^ 常量 的字段值会被存进局部槽再取用）
    for m in cf.methods:
        try:
            ci = BC.method_code(cf, m, decode_insns=True)
        except Exception:
            continue
        if ci is None or ci.error or not ci.insns:
            continue
        mname = cf.utf8(m.name_index)
        stack: list = []
        locals_: dict = {}
        for ins in ci.insns:
            op = ins.op
            if op in (BC.OP_LDC, BC.OP_LDC_W, BC.OP_LDC2_W):
                stack.append(_const(cf, ins.arg))
            elif op in ICONST:
                stack.append(("lit", op - 0x03))
            elif op == 0x10:  # bipush
                v = ins.arg if ins.arg < 0x80 else ins.arg - 0x100
                stack.append(("lit", v))
            elif op == 0x11:  # sipush
                v = ins.arg if ins.arg < 0x8000 else ins.arg - 0x10000
                stack.append(("lit", v))
            elif op == OP_GETSTATIC:
                owner, name, desc = _member(cf, ins.arg)
                if desc == "J":
                    stack.append(("fld", owner + "." + name))
                else:
                    stack.append(("?", None))
            elif op in STORE_OPS or op in STORE_N:
                kind, slot = STORE_OPS.get(op) or STORE_N[op]
                if stack:
                    locals_[(kind, slot)] = stack.pop()
            elif op in LOAD_OPS or op in LOAD_N:
                kind, slot = LOAD_OPS.get(op) or LOAD_N[op]
                v = locals_.get((kind, slot))
                stack.append(v if v is not None else ("?", None))
            elif op in ALOAD_N or op == 0x19:
                stack.append(("o", None))          # 对象引用（this 等）：运行时值
            elif op == 0x01:                       # aconst_null
                stack.append(("null", None))
            elif op == 0x57:                       # pop
                if stack: stack.pop()
            elif op == 0x58:                       # pop2（long 占一格：弹 1）
                if stack: stack.pop()
            elif op == 0x59:                       # dup
                if stack: stack.append(stack[-1])
            elif op == 0x5C:                       # dup2（long 视角：再压一份）
                if stack: stack.append(stack[-1])
            elif op in LONG_BIN_OPS or op in INT_BIN_OPS:
                b = stack.pop() if stack else ("?", None)
                a = stack.pop() if stack else ("?", None)
                tag_name = LONG_BIN_OPS.get(op) or INT_BIN_OPS[op]
                stack.append(("op", tag_name, a, b))
            elif op in CONV_OPS:
                a = stack.pop() if stack else ("?", None)
                stack.append(("op", CONV_OPS[op], a))
            elif op == BC.OP_INVOKEDYNAMIC:
                e = cf.cp[ins.arg]
                if not e or e[0] != CF.C_INVOKE_DYNAMIC:
                    stack.clear()
                    continue
                bsm_idx, nat_idx = e[1]
                nat = cf.cp[nat_idx]
                name = _utf8(cf, nat[1][0]) or "?"
                desc = _utf8(cf, nat[1][1]) or "?"
                na = _arity(desc)
                # 短栈 = 开头的对象参数（this / new 实例）被前面的对象操作
                # 清掉——用 null 占位补齐；bootstrap 真读它们时该站点会
                # 失败并如实记录，忽略则照常解密
                if len(stack) >= na:
                    dynargs = stack[len(stack) - na:]
                else:
                    dynargs = [("null", None)] * (na - len(stack)) + stack
                entry = bsm[bsm_idx] if bsm_idx < len(bsm) else None
                sites.append(IndySite(cls=cf.name, method=mname, name=name,
                                      desc=desc, bsm=entry, dynargs=dynargs))
                if len(stack) >= na:
                    del stack[len(stack) - na:]
                else:
                    stack.clear()
                stack.append(("o", None))
            else:
                # 保守：任何其他指令都视为打断表达式链
                stack.clear()
    return sites


def scan_jar(jar: Path, limit: int = 0) -> dict:
    """整个 jar 的 indy 站点普查：统计 + 逐类站点。"""
    stats = {"classes": 0, "classes_with_bsm": 0, "classes_with_sites": 0,
             "sites": 0, "bsm_total": 0}
    per_owner: dict[str, int] = {}
    per_name: dict[str, int] = {}
    out = []
    with zipfile.ZipFile(jar) as zf:
        for info in zf.infolist():
            if not info.filename.endswith(".class"):
                continue
            try:
                cf = CF.parse(zf.read(info))
            except Exception:
                continue
            stats["classes"] += 1
            bsm = parse_bsm(cf)
            if bsm:
                stats["classes_with_bsm"] += 1
                stats["bsm_total"] += len(bsm)
            sites = enum_sites(cf, {"bsm": bsm})
            if not sites:
                continue
            stats["classes_with_sites"] += 1
            stats["sites"] += len(sites)
            for s in sites:
                owner = s.bsm.owner if s.bsm else "?"
                per_owner[owner] = per_owner.get(owner, 0) + 1
                per_name[s.name] = per_name.get(s.name, 0) + 1
            if limit and len(out) < limit:
                out.append((cf.name, sites))
    return {"stats": stats, "per_owner": per_owner, "per_name": per_name,
            "sample": out}
