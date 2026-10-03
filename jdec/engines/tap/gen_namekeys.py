# -*- coding: utf-8 -*-
"""生成 s3 名字映射表的候选 key 清单。

s3 的三个 key 构造（来自反编译源码，f = "\b"）：
  类  key = internalName + f                          （a(String)）
  字段 key = ownerInternal + f + fieldName             （c(Class,String)）
  方法 key = ownerInternal + f + method + f + (p + f)* （b(String,Class,Class[])，
            p = 参数类型的 "getName().replace('.','/')" 形态）
方法/字段的 owner 还会沿继承链重试（a(Class,String) 的 fallback），
所以对每个祖先 owner 都生成一份变体。
"""
import sys
import zipfile

sys.path.insert(0, r"D:/MC/Workbuddy/deobf/jdec")
from jdec import classfile as CF

JAR = r"D:/MC/samples/Myau0729-obf.jar"
OUT = r"D:/MC/Workbuddy/deobf/jdec/engines/tap/namekeys.txt"

PRIM = {"B": "byte", "Z": "boolean", "S": "short", "C": "char",
        "I": "int", "J": "long", "F": "float", "D": "double"}


def parse_desc_params(desc: str):
    """方法描述符 -> 参数类型 key 形态（s3.a(Class) 单参版的返回值语义）。

    a(Class): 基本类型 -> "I" 等；否则 getName().replace('.','/')。
    getName(): String -> java.lang.String（点）；String[] -> [Ljava.lang.String;；
              int[] -> [I。replace 点->斜杠后净效果 = 描述符形态。
    """
    params = []
    i = 1
    while desc[i] != ")":
        dims = 0
        while desc[i] == "[":
            dims += 1
            i += 1
        c = desc[i]
        if c == "L":
            j = desc.index(";", i)
            internal = desc[i + 1:j]          # myau/Foo
            i = j + 1
            form = ("[" * dims + "L" + internal + ";") if dims else internal
        else:
            # 基本类型（或数组的元素字母）——i 必须前进，否则死循环吃光内存
            # （本次 SIGTERM 之谜的真凶：缺这一行，带 I/J/Z 参数的方法描述符
            # 会让 params 无限 append，最终被环境 OOM 击杀）
            form = ("[" * dims + c) if dims else PRIM[c]
            i += 1
        params.append(form)
    return params


def ancestors(cls_name: str, sup: dict, depth=8):
    """自身 + 递归父类/接口（模拟 b(Class,list,set) 的顺序）。"""
    out = []
    seen = set()
    stack = [cls_name]
    while stack and len(out) < 40:
        cur = stack.pop(0)
        if cur in seen:
            continue
        seen.add(cur)
        out.append(cur)
        info = sup.get(cur)
        if info:
            stack.append(info[0])
            stack.extend(info[1])
    return out[:depth]


def main():
    sup = {}       # internal -> (super, [interfaces])
    zf = zipfile.ZipFile(JAR)
    classes = sorted(n for n in zf.namelist() if n.endswith(".class"))
    # 注意：不能把 ClassFile 缓存在字典里——723 个类（含 spongepowered 巨类）
    # 的常量池常驻内存会触发 OOM（进程被 SIGTERM，零输出）。两趟各自流式解析。
    for cn in classes:                        # 第一趟：只建继承链（字符串，KB 级）
        cf = CF.parse(zf.read(cn))
        sup[cf.name] = (cf.super_name, cf.interface_names)
    print(f"  parse done: {len(sup)} classes", flush=True)
    keys = []
    for cn in classes:                        # 第二趟：流式生成 key（继承链已全）
        cf = CF.parse(zf.read(cn))
        name = cf.name
        keys.append((name, "C", name + "\b"))     # 类 key
        for m in cf.methods:
            ps = parse_desc_params(cf.utf8(m.descriptor_index))
            # f + method + f + (p + f)*；无参数时就是 f+method+f
            mk = "\b" + cf.utf8(m.name_index) + "\b" + "".join(p + "\b" for p in ps)
            for anc in ancestors(name, sup):
                keys.append((anc, "M", anc + mk))
        for f_ in cf.fields:
            for anc in ancestors(name, sup):
                keys.append((anc, "F", anc + "\b" + cf.utf8(f_.name_index)))
        if len(keys) % 2000 < 60:
            print(f"  {len(keys)} keys @ {name}", flush=True)
    with open(OUT, "w", encoding="utf-8", newline="") as fh:
        for kind, typ, key in keys:
            fh.write(f"{typ}\t{key}\n")
    print(f"{len(classes)} classes, {len(keys)} candidate keys -> {OUT}")


if __name__ == "__main__":
    main()
