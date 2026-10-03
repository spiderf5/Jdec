# -*- coding: utf-8 -*-
"""对 decoded_final.tsv 做可读性定性：多少是真明文，多少疑似第二层密文/垃圾。

判定规则（从宽到严三档）：
  clean    : 纯可打印 ASCII（或大部分可打印），长度 >= 2，且「像 Java 字符串」
             （命中常见词/标识符风格/已知协议词 任一）
  suspect  : 可打印但无语义（伪随机串），或不可打印字节占比高 —— 疑似第二层密文
  empty/   : 空串或单字符
另：对超长串单独统计（tamper 垃圾 / 密文表常驻密文的典型形态）。
"""
import struct
import sys
from collections import Counter, defaultdict

TAP = r"D:/MC/Workbuddy/deobf/jdec/engines/tap"

# 常见英文词 / Java / 混淆语境的判定片段
TOKENS = (
    "java", "lang", "net.minecraft", "myau", "the ", "ing ", "tion", "Exception",
    "Error", "java/", "org/", "com/", "invoke", "method", "class", "field",
    "String", "Object", "get", "set", "put", "add", "load", "init", "false",
    "true", "null", "this", "void", "int", "long", "render", "player", "world",
    "click", "gui", "chat", "packet", "event", "http", "://", ".com", ".net",
    ".json", ".txt", "config", "server", "client", "connect", "socket",
    "Disable", "Enable", "Mode", "bind", "key", "aura", "kill", "aim", "reach",
    "fly", "speed", "esp", "sprint", "velocity", "timer", "nametags",
)

def printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if 0x20 <= ord(c) < 0x7F or c in "\t\n\r")
    return ok / len(s)

def looks_semantic(s: str) -> bool:
    low = s.lower()
    if any(t in low for t in TOKENS):
        return True
    # 标识符风格：不含空格、含下划线或大小写混合、无连续非字母
    if s.isidentifier():
        return True
    # 路径/包风格
    if "/" in s or "." in s and " " not in s and len(s) > 6:
        return True
    # 高字母占比 + 空格分隔的多词句
    words = s.split()
    if len(words) >= 3 and sum(w.isalpha() for w in words) / len(words) > 0.6:
        return True
    return False

def classify(s: str):
    if s == "":
        return "empty"
    pr = printable_ratio(s)
    if pr >= 0.95:
        if len(s) >= 2 and looks_semantic(s):
            return "clean"
        return "suspect"   # 可打印但无语义：伪随机 / 第二层密文
    if pr >= 0.7:
        return "suspect"
    return "garbage"       # 不可打印占多数：解密失败/二进制

def main():
    strings = []          # (cls, method, args, value) 返回 String 的
    longs = Counter()     # (cls) -> count，返回 J 的
    by_class_str = Counter()
    by_class_clean = Counter()
    kind_counter = Counter()
    longstrings = []      # 超长串样本
    for line in open(f"{TAP}/decoded_final.tsv", encoding="utf-8", errors="replace"):
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 5:
            continue
        cls, meth, desc, args, val = parts[0], parts[1], parts[2], parts[3], "\t".join(parts[4:])
        if desc.endswith("J"):
            longs[cls] += 1
            kind_counter["long_const"] += 1
            continue
        kind_counter["string"] += 1
        k = classify(val)
        kind_counter[k] += 1
        by_class_str[cls] += 1
        if k == "clean":
            by_class_clean[cls] += 1
        if len(val) > 300:
            longstrings.append((cls, meth, args, len(val), val[:80]))

    print("== 产出构成 ==")
    for k, v in kind_counter.most_common():
        print(f"  {k:12s} {v}")
    total_str = kind_counter["string"]
    print(f"\n== 字符串含金量 ==")
    print(f"  total strings : {total_str}")
    print(f"  clean         : {kind_counter['clean']} ({kind_counter['clean']*100//max(total_str,1)}%)")
    print(f"  suspect       : {kind_counter['suspect']} ({kind_counter['suspect']*100//max(total_str,1)}%)")
    print(f"  garbage       : {kind_counter['garbage']} ({kind_counter['garbage']*100//max(total_str,1)}%)")
    print(f"  empty         : {kind_counter['empty']}")
    print(f"\n== long 常量 ==")
    print(f"  total         : {sum(longs.values())}  across {len(longs)} classes")

    print("\n== clean 最多的类 (top 20) ==")
    for cls, n in by_class_clean.most_common(20):
        print(f"  {n:5d}  {cls}")

    print(f"\n== 超长串 (>300 chars) 共 {len(longstrings)} 条，按类分布 ==")
    lc = Counter(x[0] for x in longstrings)
    for cls, n in lc.most_common(10):
        print(f"  {n:5d}  {cls}")
    print("\n  样本前 5 条（截断 80 字符）：")
    for cls, meth, args, ln, head in longstrings[:5]:
        print(f"    [{cls} {meth} {args}] len={ln}: {head!r}")

if __name__ == "__main__":
    main()
