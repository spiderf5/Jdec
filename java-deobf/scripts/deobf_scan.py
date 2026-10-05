#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扫描 Java jar / class 目录，输出混淆指纹与工具链建议。

只做静态读取：解析常量池与类名，不执行目标代码、不加载类、不修改任何文件。

用法:
    python deobf_scan.py <jar 文件或目录> [--text] [--max-classes 500]

退出码: 0 = 成功；2 = 参数或目标错误。
"""

import argparse
import io
import json
import re
import struct
import sys
import zipfile
from pathlib import Path

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

JAVA_MAJOR = {
    45: "1.1", 46: "1.2", 47: "1.3", 48: "1.4", 49: "5", 50: "6", 51: "7",
    52: "8", 53: "9", 54: "10", 55: "11", 56: "12", 57: "13", 58: "14",
    59: "15", 60: "16", 61: "17", 62: "18", 63: "19", 64: "20", 65: "21",
    66: "22", 67: "23", 68: "24",
}

# 常量池各 tag 的定长负载（Utf8 单独处理，Long/Double 占两个槽）
TAG_SIZES = {
    3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4,
    15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2,
}

# 已知混淆器指纹：命中关键词 -> (展示名, 建议工具)
BUILTIN_OBFUSCATORS = [
    ("Allatori", ["allatori"], "java-deobfuscator"),
    ("Zelix KlassMaster (ZKM)", ["zelix", "zkm", "klassmaster"],
     "Threadtear / java-deobfuscator（ZKM 27 起带 flow / indy 混淆，需专门的 transformer）"),
    ("Stringer", ["stringer"], "Threadtear / java-deobfuscator"),
    ("DashO", ["dasho", "preemptive"], "java-deobfuscator"),
    ("ProGuard / R8", ["proguard", "android/tools/r8"], "官方 retrace / 重映射"),
    ("DexGuard", ["dexguard"], "java-deobfuscator"),
    ("ClassGuard", ["classguard"], "java-deobfuscator（类加密，AES 密钥常在 native 库里）"),
    ("Smoke", ["smoke"], "java-deobfuscator"),
    ("SkidSuite2", ["skidsuite"], "java-deobfuscator"),
    ("Radon", ["radon"], "java-deobfuscator / narumii（部分）"),
    ("Obzcure", ["obzcure", "spigotprotect"], "java-deobfuscator"),
    ("superblaubeere27 / JObf", ["superblaubeere", "sb27"], "narumii Deobfuscator"),
    ("Paramorphism", ["paramorphism"], "narumii Deobfuscator（会利用 jar 重复条目与假目录）"),
    ("Caesium", ["caesium"], "narumii Deobfuscator（带 HTML 注入，注意工具解析风险）"),
    ("Skid / qProtect", ["qprotect"], "narumii（非最新版）"),
    ("Scuti", ["scuti"], "narumii Deobfuscator（会把类打包成 XOR 加密的 blob）"),
    ("HsGuard", ["hsguard"], "narumii Deobfuscator"),
    ("CheatBreaker", ["cheatbreaker"], "narumii Deobfuscator"),
    ("Bozar", ["bozar"], "narumii Deobfuscator"),
    ("Monsey", ["monsey"], "narumii Deobfuscator"),
    ("RakSzild", ["rakszild"], "narumii Deobfuscator"),
    ("HP888", ["hp888"], "narumii Deobfuscator"),
    ("Skidfuscator", ["skidfuscator"], "narumii（部分）；三代控制流混淆较难"),
    ("Branchlock", ["branchlock"], "narumii（部分）"),
    ("Eskid", ["eskid"], "Ackerun 的 Eskid transformer"),
    ("Binsecure", ["binsecure"], "narumii（部分）"),
    ("Colonial", ["colonial"], "narumii（部分）"),
    ("Sentinel", ["sentinel"], "无公开 transformer，需手工分析"),
    ("XenonGuard", ["xenonguard"], "无公开 transformer（基于 CheatBreaker，可先试 CheatBreaker transformer）"),
    ("Grunt", ["grunt"], "手工分析（常带 mixin / Forge 模组结构）"),
    ("MyJ2C", ["myj2c"], "Allatori 系 transformer 部分可用"),
    ("Phantom Shield X", ["phantomshield", "fl0wowp4rty"],
     "无公开 transformer；Java 侧只能还原到 loader 边界，native 部分需配合 IDA / Ghidra"),
]

# ---------------------------------------------------------------- 可外部维护的指纹库
#
# 混淆器关键词、HTML 注入标记、indy bootstrap 白名单、native 库扩展名、检测阈值，
# 全部放在同目录的 fingerprints.json 里 —— 加混淆器、调阈值不用改代码。
# 文件缺失或损坏时回退到内置默认值，保证脚本永远能跑。

CONFIG_PATH = Path(__file__).resolve().parent / "fingerprints.json"

BUILTIN_NATIVE_LIB_EXT = {".dll", ".so", ".dylib", ".lib", ".jnilib"}
BUILTIN_HTML_MARKERS = ["<html", "<font", "<b>", "<img ", "&lt;html"]
BUILTIN_BOOTSTRAP = ["LambdaMetafactory", "StringConcatFactory", "ObjectMethods",
                     "RecordBootstrap", "SwitchBootstraps"]
BUILTIN_THRESHOLDS = {
    "min_instructions_for_flow_check": 200,
    "goto_density_high": 0.15,
    "switch_density_high": 0.01,
    "goto_density_with_switch": 0.08,
    "exception_ratio_high": 0.8,
    "member_ratio_high": 0.7,
    "encrypted_like_high": 20,
    "indy_encoded_min": 3,
}


def _load_config():
    """加载 fingerprints.json；任何问题都回退到内置默认配置。"""
    data = {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            data = {}
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        sys.stderr.write("提示：fingerprints.json 读取失败（%s），改用内置默认配置\n" % exc)
    thresholds = dict(BUILTIN_THRESHOLDS)
    extra = data.get("thresholds")
    if isinstance(extra, dict):
        thresholds.update(extra)
    obfs = data.get("obfuscators")
    if not isinstance(obfs, list) or not obfs:
        obfs = BUILTIN_OBFUSCATORS
    return {
        "obfuscators": obfs,
        "html_markers": data.get("html_markers") or BUILTIN_HTML_MARKERS,
        "normal_bootstrap": data.get("normal_bootstrap") or BUILTIN_BOOTSTRAP,
        "native_lib_exts": set(data.get("native_lib_exts") or BUILTIN_NATIVE_LIB_EXT),
        "thresholds": thresholds,
    }


CONFIG = _load_config()
OBFUSCATOR_SIGNATURES = [
    (o.get("name", "未知"), list(o.get("keywords") or []), o.get("tool", ""))
    for o in CONFIG["obfuscators"] if isinstance(o, dict)
] or BUILTIN_OBFUSCATORS
# 出现 java/lang/invoke 却一个正常 bootstrap 工厂都没有时，多半是 indy 混淆
NORMAL_BOOTSTRAP = CONFIG["normal_bootstrap"]
NATIVE_LIB_EXT = CONFIG["native_lib_exts"]
HTML_INJECTION_MARKERS = CONFIG["html_markers"]
THRESHOLDS = CONFIG["thresholds"]

MC_TRACES = [
    "net/minecraft", "net/minecraftforge", "com/mojang",
    "org/spongepowered", "mcp/", "launchwrapper", "net/minecraftlaunchwrapper",
]
MC_NAMED_MARKERS = ["net/minecraft/client/Minecraft", "net/minecraft/client/entity"]

DYNAMIC_KEYS = {
    "reflection": ["java/lang/reflect", "getDeclaredMethod", "getDeclaredField",
                   "getMethod", "setAccessible", "Method.invoke", "MethodHandle"],
    "dynamic_invocation": ["java/lang/invoke", "LambdaMetafactory", "invokeExact"],
    "custom_classloader": ["defineClass", "URLClassLoader", "ClassLoader"],
    # 只搜方法调用，不搜库扩展名：在常量池里拿 ".so" 做子串匹配会命中任何
    # 含该子串的普通文本（also / resolve / socket…），实测 vanilla 1.20.4
    # 22597 个条目里 0 个 .so 文件却报了 native。native 库只看 jar 条目名。
    "native": ["System.loadLibrary", "Runtime.loadLibrary", "loadLibrary",
               "System.load("],
}

BASE64_LIKE = re.compile(r"^[A-Za-z0-9+/=]{20,}$")
HEX_LIKE = re.compile(r"^[0-9a-fA-F]{20,}$")
NAME_SOUP = re.compile(r"^[Il1O0]{4,}$")
PURE_DIGITS = re.compile(r"^\d+$")


def _opcode_len(code, off):
    """返回从 off 开始的指令字节数。变长指令（switch / wide）需要实际解析。"""
    op = code[off]
    if op in (0xAA, 0xAB):                      # tableswitch / lookupswitch
        pad = (4 - ((off + 1) % 4)) % 4
        base = off + 1 + pad
        if op == 0xAA:
            low, high = struct.unpack_from(">ii", code, base + 4)
            return 1 + pad + 12 + (high - low + 1) * 4
        npairs = struct.unpack_from(">i", code, base + 4)[0]
        return 1 + pad + 8 + npairs * 8
    if op == 0xC4:                              # wide
        return 6 if code[off + 1] == 0x84 else 4
    if op in (0xB9, 0xBA, 0xC8, 0xC9):          # invokeinterface / invokedynamic / goto_w / jsr_w
        return 5
    if op in (0xC5,):                           # multianewarray
        return 4
    if op in (0x10, 0x12, 0xBC) or 0x15 <= op <= 0x19 or 0x36 <= op <= 0x3A or op == 0xA9:
        return 2                                # bipush / ldc / newarray / *load / *store / ret
    if op in (0x11, 0x13, 0x14, 0x84) or 0x99 <= op <= 0xA8 or 0xB2 <= op <= 0xB8 \
            or op in (0xBB, 0xBD, 0xC0, 0xC1, 0xC6, 0xC7):
        return 3
    return 1


def _analyze_code(data, pos, utf8, acc):
    """解析 Code 属性并累加控制流指标。解析失败静默跳过，不影响其他指标。

    另外收集两个**二值指纹**（javac 绝不生成，因此可以定性，不只是密度筛查）：
      backward_handlers  异常处理器的 handler_pc 落在它所保护的区间之前
      irreducible_gotos  跳转目标落进某个受保护区间的中段（不可约控制流）
    """
    try:
        code_len = struct.unpack_from(">I", data, pos + 4)[0]
        start = pos + 8
        code = data[start:start + code_len]
        if not code:
            return
        targets = []
        off = 0
        while off < len(code):
            op = code[off]
            length = _opcode_len(code, off)
            if length <= 0 or off + length > len(code):
                break
            acc["instructions"] += 1
            if op in (0xAA, 0xAB):
                acc["switches"] += 1
            elif op in (0xA7, 0xC8):
                acc["gotos"] += 1
            elif op in (0xA8, 0xA9, 0xC9):
                acc["jsrs"] += 1
            elif op == 0xBF:
                acc["athrow"] += 1
            elif (0x99 <= op <= 0xA6) or op in (0xC6, 0xC7):
                acc["branches"] += 1
            if 0x99 <= op <= 0xA7 or op in (0xC6, 0xC7):
                targets.append(off + struct.unpack_from(">h", code, off + 1)[0])
            elif op == 0xC8:
                targets.append(off + struct.unpack_from(">i", code, off + 1)[0])
            off += length

        ex_start = start + code_len
        ex_len = struct.unpack_from(">H", data, ex_start)[0]
        acc["exception_entries"] += ex_len
        ranges = []
        for i in range(ex_len):
            s_pc, e_pc, h_pc = struct.unpack_from(">HHH", data, ex_start + 2 + i * 8)
            if h_pc < s_pc:
                # 范围内抛出的异常不可能在范围开始之前就被处理 —— javac 绝不生成
                acc["backward_handlers"] += 1
            if e_pc > s_pc:
                ranges.append((s_pc, e_pc))
        for t in targets:
            for s_pc, e_pc in ranges:
                if s_pc < t < e_pc:   # 跳进区间中段；跳到起点是合法的「循环体包着 try」惯用法
                    acc["irreducible_gotos"] += 1
                    break
        acc["code_bytes"] += code_len
    except (struct.error, IndexError, ValueError):
        return


def _skip_attributes(data, pos):
    """跳过 attribute_info 数组：每项是 u2 name_index + u4 length + 内容。"""
    count = struct.unpack_from(">H", data, pos)[0]
    pos += 2
    for _ in range(count):
        length = struct.unpack_from(">I", data, pos + 2)[0]
        pos += 6 + length
    return pos


def parse_class(data):
    """解析 class：常量池 + 方法/字段数 + native 方法数。

    结构解析失败时仍返回已拿到的常量池信息（有些类故意被构造得难以解析，
    不该因为结构读不动就丢掉全部线索）。
    """
    try:
        if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
            return None
        major = struct.unpack_from(">H", data, 6)[0]
        count = struct.unpack_from(">H", data, 8)[0]
        pos = 10
        utf8 = {}
        name_indexes = []
        idx = 1
        while idx < count and pos < len(data):
            tag = data[pos]
            pos += 1
            if tag == 1:
                length = struct.unpack_from(">H", data, pos)[0]
                pos += 2
                utf8[idx] = data[pos:pos + length].decode("utf-8", errors="replace")
                pos += length
            elif tag == 12:
                name_indexes.append(struct.unpack_from(">H", data, pos)[0])
                pos += 4
            elif tag in TAG_SIZES:
                pos += TAG_SIZES[tag]
            else:
                return None
            if tag in (5, 6):
                idx += 1
            idx += 1
        members = [utf8.get(i, "") for i in name_indexes]
    except (struct.error, IndexError, ValueError):
        return None

    result = {
        "major": major,
        "strings": list(utf8.values()),
        "members": members,
        "method_count": 0,
        "field_count": 0,
        "native_methods": 0,
    }

    # 继续走 access_flags / interfaces / fields / methods
    try:
        pos += 6                                   # access_flags, this_class, super_class
        ifc = struct.unpack_from(">H", data, pos)[0]
        pos += 2 + 2 * ifc                         # interfaces
        fcount = struct.unpack_from(">H", data, pos)[0]
        pos += 2
        for _ in range(fcount):
            pos += 6
            pos = _skip_attributes(data, pos)
        mcount = struct.unpack_from(">H", data, pos)[0]
        pos += 2
        native = 0
        acc = {"instructions": 0, "switches": 0, "gotos": 0, "jsrs": 0, "athrow": 0,
               "branches": 0, "exception_entries": 0, "code_bytes": 0,
               "backward_handlers": 0, "irreducible_gotos": 0}
        for _ in range(mcount):
            flags = struct.unpack_from(">H", data, pos)[0]
            pos += 6
            acount = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            for _ in range(acount):
                attr_name = utf8.get(struct.unpack_from(">H", data, pos)[0], "")
                attr_len = struct.unpack_from(">I", data, pos + 2)[0]
                pos += 6
                if attr_name == "Code":
                    _analyze_code(data, pos, utf8, acc)
                pos += attr_len
            if flags & 0x0100:                      # ACC_NATIVE
                native += 1
        result.update(field_count=fcount, method_count=mcount, native_methods=native,
                      code_metrics=acc)
    except (struct.error, IndexError, ValueError):
        pass                                        # 结构读不动就保留常量池结果

    return result


# jar 里的常规条目扩展名。不在其中、内容又像二进制的，多半是被加密打包的类。
# 必须包含 Minecraft 自己的资源格式，否则 .nbt 结构文件会被当成
# Scuti / ClassGuard 风格的加密类（实测 vanilla 1.20.4 一次报了 10 个）。
KNOWN_ENTRY_EXT = {
    ".class", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".wav", ".ogg",
    ".mp3", ".txt", ".json", ".properties", ".xml", ".yml", ".yaml", ".mf",
    ".sf", ".dsa", ".rsa", ".html", ".css", ".js", ".lang", ".mcmeta",
    # Minecraft 资源
    ".nbt", ".dat", ".snbt", ".mcstructure", ".vcd", ".gz", ".sig", ".sha1",
}
# jar 里的 native 库：出现它们就说明逻辑可能已经不在 Java 侧
# （扩展名清单已从 fingerprints.json 的 native_lib_exts 加载）
# indy 混淆（superblaubeere27 / JObf 系在 MC 社区最常见）会把调用目标编码成
# "owner:member:desc"，并用尾部空格的个数标记操作类型：1=static 2=virtual
# 3=field getter 4=static getter 5=setter 6=static setter
INDY_ENCODED_REF = re.compile(r"^[A-Za-z0-9_$/]+:[A-Za-z0-9_$<]+:[^\s]{1,40} {1,6}$")

# Caesium 往类名/字符串塞 HTML 标签这件事，由 fingerprints.json 的 html_markers 负责


def jar_anomalies(target):
    """检测 jar 结构层面的混淆痕迹。只有 jar/zip 输入才有意义，其他输入返回 None。"""
    path = Path(target)
    if not (path.is_file() and path.suffix.lower() in (".jar", ".zip")):
        return None
    out = {"duplicate_entries": [], "binary_blobs": [], "native_libs": []}
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            seen, dups = set(), set()
            for name in names:
                if name in seen:
                    dups.add(name)
                seen.add(name)
            out["duplicate_entries"] = sorted(dups)[:10]
            for name in names:
                if name.endswith("/") or name.startswith("META-INF/"):
                    continue
                if Path(name).suffix.lower() in KNOWN_ENTRY_EXT:
                    continue
                if Path(name).suffix.lower() in NATIVE_LIB_EXT:
                    out["native_libs"].append(name)
                    continue
                try:
                    with zf.open(name) as fh:   # 只读头部，别把整个文件拉进内存
                        head = fh.read(512)
                except (OSError, KeyError, zipfile.BadZipFile):
                    continue
                if not head:
                    continue
                # 判据用「可打印字符占比低」而不是「控制字符占比高」：
                # 均匀分布的类加密数据只有约 10% 是控制字符，按控制字符判会漏检
                printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
                if printable / len(head) < 0.7:
                    out["binary_blobs"].append(name)
            out["binary_blobs"] = out["binary_blobs"][:10]
            out["native_libs"] = out["native_libs"][:10]
    except (OSError, zipfile.BadZipFile):
        return None
    return out


def collect_classes(target, max_classes):
    """返回 ({类名: 字节}, coverage)；coverage 记录总量/截断/嵌套 jar。

    统计数字会被当成全量事实使用——静默截断曾让 native 方法数少报 112 个
    （EdNaven：525 类、上限 500，末尾 25 类里的 native 全部失踪）。
    截断必须显式上报，让读者知道数字是部分数据。
    """
    path = Path(target)
    out = {}
    cov = {"total_seen": 0, "truncated": False, "nested_jars": []}

    def _seen_and_full():
        cov["total_seen"] += 1
        return len(out) >= max_classes

    try:
        if path.is_dir():
            for f in sorted(path.rglob("*.class")):
                if _seen_and_full():
                    cov["truncated"] = True
                    continue
                out[str(f.relative_to(path)).replace("\\", "/")] = f.read_bytes()
            return out, cov
        if path.is_file():
            if path.suffix.lower() == ".class":
                out[path.name] = path.read_bytes()
                cov["total_seen"] = 1
                return out, cov
            if path.suffix.lower() in (".jar", ".zip"):
                with zipfile.ZipFile(path) as zf:
                    for item in zf.infolist():
                        if not item.filename.lower().endswith(".class"):
                            continue
                        if _seen_and_full():
                            cov["truncated"] = True
                            continue
                        out[item.filename] = zf.read(item)
                    # fat-jar 打包（Fabric/Forge 的 META-INF/jars/）里的类
                    # 与主 jar 同属一个运行体，不扫是结构性盲区
                    for item in zf.infolist():
                        nm = item.filename.lower()
                        if not (nm.startswith("meta-inf/jars/") and nm.endswith(".jar")):
                            continue
                        try:
                            with zipfile.ZipFile(io.BytesIO(zf.read(item))) as nz:
                                cov["nested_jars"].append(item.filename)
                                for ni in nz.infolist():
                                    if not ni.filename.lower().endswith(".class"):
                                        continue
                                    if _seen_and_full():
                                        cov["truncated"] = True
                                        break
                                    out[item.filename + "!/" + ni.filename] = nz.read(ni)
                        except (OSError, KeyError, zipfile.BadZipFile):
                            continue
                return out, cov
    except (OSError, zipfile.BadZipFile):
        return None
    return None


def short_name(path):
    name = path[:-6] if path.lower().endswith(".class") else path
    return name.split("/")[-1].split(".")[-1]


def is_suspicious(name):
    """判断一个类名/成员名是否像混淆产物。"""
    if not name or name in ("<init>", "<clinit>"):
        return False
    if NAME_SOUP.match(name) or PURE_DIGITS.match(name):
        return True
    if len(name) <= 2 and name.isalpha():
        return True
    if any(ord(c) > 127 or ord(c) < 32 for c in name):
        return True
    return False


def analyze(target, classes):
    names, members, all_strings, majors = [], [], [], []
    total_native = total_methods = total_fields = 0
    code_acc = {"instructions": 0, "switches": 0, "gotos": 0, "jsrs": 0,
                "athrow": 0, "branches": 0, "exception_entries": 0, "code_bytes": 0,
                "backward_handlers": 0, "irreducible_gotos": 0}
    for path, data in classes.items():
        parsed = parse_class(data)
        if not parsed:
            continue
        names.append(short_name(path))
        members.extend(m for m in parsed["members"] if m not in ("<init>", "<clint>", "<clinit>"))
        all_strings.extend(parsed["strings"])
        majors.append(parsed["major"])
        total_native += parsed.get("native_methods", 0)
        total_methods += parsed.get("method_count", 0)
        total_fields += parsed.get("field_count", 0)
        cm = parsed.get("code_metrics")
        if cm:
            for key in code_acc:
                code_acc[key] += cm.get(key, 0)

    sample_members = [m for m in members if is_suspicious(m)][:8]
    sample_classes = [n for n in names if is_suspicious(n)][:8]

    def ratio(items):
        if not items:
            return 0.0
        return round(sum(1 for i in items if is_suspicious(i)) / len(items), 3)

    packages = {}
    for path in classes:
        pkg = "/".join(path.split("/")[:-1]) or "(默认包)"
        packages[pkg] = packages.get(pkg, 0) + 1
    top_packages = sorted(packages.items(), key=lambda kv: -kv[1])[:10]

    blob = "\n".join(list(classes.keys()) + all_strings).lower()

    hints = []
    for label, keys, tool in OBFUSCATOR_SIGNATURES:
        hit = [k for k in keys if k in blob]
        if hit:
            hints.append({"obfuscator": label, "evidence": hit, "suggested_tool": tool})

    mc_hits = [t for t in MC_TRACES if t in blob]
    mc_named = any(m.lower() in blob for m in MC_NAMED_MARKERS)

    dynamic = {}
    for label, keys in DYNAMIC_KEYS.items():
        hit = [k for k in keys if k.lower() in blob]
        if hit:
            dynamic[label] = hit

    long_b64 = sum(1 for s in all_strings if BASE64_LIKE.match(s))
    long_hex = sum(1 for s in all_strings if HEX_LIKE.match(s))
    indy_encoded = [s for s in all_strings if INDY_ENCODED_REF.match(s)]

    # indy 混淆会把调用目标藏进 bootstrap：能观察到 java/lang/invoke，
    # 却找不到编译器该生成的那些正常工厂类名
    invoke_present = "java/lang/invoke" in blob
    known_bootstrap = [b for b in NORMAL_BOOTSTRAP if b.lower() in blob]
    suspicious_indy = bool(invoke_present and not known_bootstrap)

    anomalies = jar_anomalies(target)
    html_hits = [m for m in HTML_INJECTION_MARKERS if m.lower() in blob]
    if anomalies:
        anomalies["html_injection"] = bool(html_hits)
    elif html_hits:
        anomalies = {"duplicate_entries": [], "binary_blobs": [],
                     "native_libs": [], "html_injection": True}

    native_libs = (anomalies or {}).get("native_libs", [])

    instr = max(code_acc["instructions"], 1)
    branches = max(code_acc["branches"], 1)
    code_metrics = {
        "instructions": code_acc["instructions"],
        "switches": code_acc["switches"],
        "gotos": code_acc["gotos"],
        "jsr_ret": code_acc["jsrs"],
        "athrow": code_acc["athrow"],
        "branches": code_acc["branches"],
        "exception_entries": code_acc["exception_entries"],
        "backward_handlers": code_acc["backward_handlers"],
        "irreducible_gotos": code_acc["irreducible_gotos"],
        "switch_density": round(code_acc["switches"] / instr, 4),
        "goto_density": round(code_acc["gotos"] / instr, 4),
        "exception_ratio": round(code_acc["exception_entries"] / branches, 3),
    }

    return {
        "target": str(target),
        "suspicious_indy": suspicious_indy,
        "jar_anomalies": anomalies,
        "code_metrics": code_metrics,
        "native_methods": total_native,
        "method_count": total_methods,
        "field_count": total_fields,
        "class_count_scanned": len(classes),
        "class_count_parsed": len(majors),
        "java_target": JAVA_MAJOR.get(max(majors), "未知") if majors else "未知",
        "packages": [{"name": n, "count": c} for n, c in top_packages],
        "naming": {
            "suspicious_class_ratio": ratio(names),
            "suspicious_member_ratio": ratio(members),
            "sample_classes": sample_classes,
            "sample_members": sample_members,
            "avg_class_name_len": round(sum(len(n) for n in names) / len(names), 2) if names else 0,
        },
        "strings": {
            "total_constants": len(all_strings),
            "long_base64_like": long_b64,
            "long_hex_like": long_hex,
            "indy_encoded_refs": len(indy_encoded),
            "indy_encoded_samples": indy_encoded[:3],
        },
        "obfuscator_hints": hints,
        "minecraft": {
            "detected": bool(mc_hits),
            "traces": mc_hits,
            "vanilla_already_named": mc_named,
        },
        "dynamic_features": dynamic,
        "recommendations": build_recommendations(hints, bool(mc_hits), mc_named,
                                                 ratio(members), long_b64 + long_hex,
                                                 suspicious_indy, anomalies, html_hits,
                                                 dynamic, total_native, native_libs,
                                                 indy_encoded, code_metrics),
    }


def build_recommendations(hints, mc, mc_named, member_ratio, encrypted_like,
                          suspicious_indy=False, anomalies=None, html_hits=None,
                          dynamic=None, native_methods=0, native_libs=None,
                          indy_encoded=None, code_metrics=None):
    dynamic = dynamic or {}
    native_libs = native_libs or []
    indy_encoded = indy_encoded or []
    cm = code_metrics or {}
    t = THRESHOLDS
    recs = []
    if mc and mc_named:
        recs.append("原版符号已是命名形态（或该版本本身未混淆）：原版部分可直接反编译，"
                    "客户端自身代码通常仍是混淆的，两件事分开处理")
    elif mc:
        recs.append("检测到 MC 痕迹但未映射：先用 Tiny Remapper 套对应版本映射还原原版符号"
                    "（1.13.2 及以下用 Legacy Yarn，1.14+ 用 Mojang / Yarn），再处理客户端自身的混淆")
    if hints:
        for h in hints[:3]:
            recs.append("疑似 %s → 优先用 %s" % (h["obfuscator"], h["suggested_tool"]))
    else:
        recs.append("未识别到已知混淆器：先确认是不是单纯的名称混淆 + 字符串加密，"
                    "用 Recaf 看字节码结构，再用 AutoRenamer 做批量重命名")
    if encrypted_like > t["encrypted_like_high"]:
        recs.append("存在较多长 base64/hex 常量（%d 个），多半有字符串加密："
                    "找出解密方法后用 transformer 批量还原，不要手工一个个解" % encrypted_like)
    if member_ratio > t["member_ratio_high"]:
        recs.append("成员名混淆比例 %.0f%%：重命名时按「行为命名」而不是猜原意，"
                    "拿不准的保留原名并加注释" % (member_ratio * 100))
    if anomalies:
        if anomalies.get("duplicate_entries"):
            recs.append("jar 里有重复条目名（%d 个：%s）—— Paramorphism 这类混淆器的典型手法，"
                        "普通解压工具会丢文件或报错，取条目时要保留重复项"
                        % (len(anomalies["duplicate_entries"]),
                           ", ".join(anomalies["duplicate_entries"][:3])))
        if anomalies.get("binary_blobs"):
            recs.append("有非常规二进制条目（%s）—— 可能是被加密打包的类（Scuti / ClassGuard 风格），"
                        "先把解密后的 class dump 出来，再走正常流程"
                        % ", ".join(anomalies["binary_blobs"][:3]))
    if html_hits:
        recs.append("常量池里出现 HTML 标签片段（%s）—— Caesium 的 HTML 注入特征，"
                    "会把解析 HTML 的逆向工具搞坏，先清理再处理" % ", ".join(html_hits[:3]))
    if "custom_classloader" in dynamic:
        recs.append("存在自定义 ClassLoader 痕迹：类可能在运行时才被解密/加载（Scuti、PhantomShield X 等风格）。"
                    "静态分析看不到真实逻辑，需要先 dump 出解密后的 class，或在受控环境里动态抓取")
    if "native" in dynamic:
        recs.append("有 native 相关痕迹：可能存在 JNI 或 native obfuscation（PhantomShield X 的 native 模式、"
                    "ClassGuard 的 native 密钥等）。Java 侧只能还原到边界，关键逻辑要看 native 层（IDA / Ghidra）")
    if native_methods:
        recs.append("共 %d 个 native 方法（ACC_NATIVE）—— 逻辑很可能已被搬进 native 库，"
                    "这是 JNIC 一类 native obfuscation 的典型形态。先把 native 库 dump 出来，"
                    "再用 Ghidra / IDA 找 JNI_OnLoad 与 Java_* 导出符号" % native_methods)
    if native_libs:
        recs.append("jar 内含 native 库（%s）：确认平台与加载方式（System.loadLibrary / load），"
                    "跨平台保护往往一个 jar 里塞多份" % ", ".join(native_libs[:3]))
    # 二值指纹优先：它们零误报、能定性，不需要任何规模门槛
    if cm.get("backward_handlers"):
        recs.append("发现 %d 处「异常处理器向后跳」（handler_pc < start_pc）—— javac 绝不生成这种结构，"
                    "是控制流被故意打乱的直接证据。这条零误报（实测 vanilla 1.20.4 的 444 个处理器里 0 处），"
                    "可以直接定性，不必再等密度指标" % cm["backward_handlers"])
    if cm.get("irreducible_gotos"):
        recs.append("另有 %d 处跳转落进了受保护区间的中段（不可约控制流）。这条**不能单独用来指认厂商** —— "
                    "实测 vanilla 1.20.4 的 300 个类里也有 7 例，其中大多是 goto 跳到区间起点"
                    "（合法的 try 惯用法）。只作症状参考" % cm["irreducible_gotos"])
    # 控制流混淆判定。必须带规模门槛：javac 生成的 switch 与循环在小方法里 goto 占比天然就高
    # （实测 42 条指令里 5 个 goto 就是 11.9%），只看比率必然误报。
    instr_count = cm.get("instructions", 0)
    goto_d = cm.get("goto_density", 0)
    switch_d = cm.get("switch_density", 0)
    if cm.get("jsr_ret"):
        recs.append("出现 %d 处 jsr/ret —— 老式（Java 6 之前）控制流混淆的标志，"
                    "现代混淆器多用异常表与 switch 平坦化" % cm["jsr_ret"])
    if instr_count >= t["min_instructions_for_flow_check"] and (
            goto_d > t["goto_density_high"]
            or (switch_d > t["switch_density_high"] and goto_d > t["goto_density_with_switch"])):
        recs.append("疑似控制流平坦化（样本 %d 条指令：goto 密度 %.1f%%、switch 密度 %.2f%%）—— "
                    "注意正常 switch 密集代码也能到这个量级（实测 76 指令可达 14.5%%），"
                    "所以这是启发式提示而非定论，理想情况是拿同项目未混淆版本做基线对比。"
                    "确认后处理路径：java-deobfuscator 的 PeepholeOptimizer + DeadCodeRemover（多 pass），"
                    "再上 Recaf 的 opaque predicate 化简与 goto 内联；反编译器崩了先修文件合法性"
                    % (instr_count, goto_d * 100, switch_d * 100))
    if instr_count >= t["min_instructions_for_flow_check"] and \
            cm.get("exception_ratio", 0) > t["exception_ratio_high"]:
        recs.append("异常表条目 / 条件分支 = %.2f（正常 <0.2）—— 很可能用 try-catch 当跳转"
                    "（DashO 系风格）。还原靠模式匹配 dispatcher 序列，成本高，评估是否值得手工处理"
                    % cm["exception_ratio"])
    if suspicious_indy:
        recs.append("出现 invokedynamic 却没有常见的 bootstrap 工厂（LambdaMetafactory / StringConcatFactory 等），"
                    "疑似 indy 混淆：调用目标被藏进 bootstrap，需要专门的 indy transformer 还原")
    if len(indy_encoded) > t["indy_encoded_min"]:
        recs.append("常量池里有 %d 条 `owner:member:desc` + 尾部空格的编码串（样例: %r）—— "
                    "这是 indy 混淆的典型痕迹（superblaubeere27 / JObf 系在 MC 社区最常见）："
                    "调用目标被编码进静态 String[]，尾部空格个数标记操作类型。"
                    "还原路径是找到 bootstrap 方法，离线执行它的解密逻辑（参数是常量池里的静态值，不依赖运行时）"
                    % (len(indy_encoded), indy_encoded[0]))
    if any("Zelix" in h["obfuscator"] or "ZKM" in h["obfuscator"] for h in hints):
        recs.append("ZKM 27 常把控制流混淆（flow）与 indy 混淆叠在一起：直接反编译大概率崩溃或输出不可读，"
                    "先用 flow / indy transformer 处理，再反编译")
    recs.append("反编译器首选 Vineflower（FernFlower 的活跃分支，对 Java 16+ 新语法支持最好）；"
                "CFR / Procyon 作为交叉验证")
    recs.append("反混淆后必须验证：能重新编译通过 + 行为与原始一致，不能只看到「读得懂」就交付")
    return recs


def to_text(info):
    lines = ["目标: %s" % info["target"],
             "扫描 class: %d 个（解析成功 %d 个）" % (info["class_count_scanned"], info["class_count_parsed"]),
             "编译目标: Java %s" % info["java_target"]]
    cov = info.get("coverage") or {}
    if cov.get("nested_jars"):
        lines.append("嵌套 jar: %d 个（META-INF/jars/）已并入扫描" % len(cov["nested_jars"]))
    if cov.get("truncated"):
        lines.append("  ! 已截断：达到 --max-classes 上限，目标共 %d 个 class，"
                     "上面的统计只覆盖了前 %d 个——数字是部分数据，"
                     "加 --max-classes N 提升上限后重跑"
                     % (cov["total_seen"], info["class_count_scanned"]))
    n = info["naming"]
    lines.append("命名特征: 类名可疑比例 %.1f%% / 成员名可疑比例 %.1f%% / 类名平均长度 %s"
                 % (n["suspicious_class_ratio"] * 100, n["suspicious_member_ratio"] * 100,
                    n["avg_class_name_len"]))
    if n["sample_classes"]:
        lines.append("  类名样例: %s" % ", ".join(n["sample_classes"]))
    if n["sample_members"]:
        lines.append("  成员名样例: %s" % ", ".join(n["sample_members"]))
    s = info["strings"]
    lines.append("常量池: 字符串 %d 个，其中长 base64 型 %d 个 / 长 hex 型 %d 个 / indy 编码串 %d 条"
                 % (s["total_constants"], s["long_base64_like"], s["long_hex_like"],
                    s.get("indy_encoded_refs", 0)))
    lines.append("方法: 共 %d 个，其中 native 方法 %d 个；字段 %d 个"
                 % (info.get("method_count", 0), info.get("native_methods", 0),
                    info.get("field_count", 0)))
    cm = info.get("code_metrics") or {}
    if cm.get("instructions"):
        lines.append("控制流: 指令 %d｜goto %d(%.1f%%)｜switch %d(%.2f%%)｜条件分支 %d｜"
                     "异常表 %d(比值 %.2f)｜jsr/ret %d｜athrow %d"
                     % (cm["instructions"], cm["gotos"], cm["goto_density"] * 100,
                        cm["switches"], cm["switch_density"] * 100, cm["branches"],
                        cm["exception_entries"], cm["exception_ratio"],
                        cm["jsr_ret"], cm["athrow"]))
        lines.append("二值指纹: 异常处理器后跳 %d（javac 造不出来，>0 即强证据）｜不可约跳转 %d（只作症状参考）"
                     % (cm.get("backward_handlers", 0), cm.get("irreducible_gotos", 0)))
    if info["obfuscator_hints"]:
        lines.append("混淆器指纹:")
        for h in info["obfuscator_hints"]:
            lines.append("  - %s（证据: %s）→ 建议 %s"
                         % (h["obfuscator"], ", ".join(h["evidence"]), h["suggested_tool"]))
    else:
        lines.append("混淆器指纹: 未命中已知特征")
    mc = info["minecraft"]
    if mc["detected"]:
        lines.append("Minecraft: 是（痕迹: %s）%s"
                     % (", ".join(mc["traces"]),
                        "，原版符号已命名" if mc["vanilla_already_named"] else "，原版未映射"))
    if info["dynamic_features"]:
        lines.append("动态特征:")
        for k, v in info["dynamic_features"].items():
            lines.append("  - %s: %s" % (k, ", ".join(v)))
    if info.get("suspicious_indy"):
        lines.append("疑似 indy 混淆: 是（有 java/lang/invoke，但缺少编译器正常的 bootstrap 工厂）")
    if info.get("jar_anomalies"):
        a = info["jar_anomalies"]
        lines.append("jar 结构异常:")
        lines.append("  重复条目: %s" % (", ".join(a["duplicate_entries"]) or "无"))
        lines.append("  非常规二进制条目: %s" % (", ".join(a["binary_blobs"]) or "无"))
        lines.append("  native 库: %s" % (", ".join(a.get("native_libs", [])) or "无"))
        lines.append("  HTML 注入痕迹: %s" % ("是" if a.get("html_injection") else "无"))
    if info["packages"]:
        lines.append("主要包（前 10）:")
        for p in info["packages"]:
            lines.append("  %-60s %d" % (p["name"], p["count"]))
    lines.append("建议:")
    for r in info["recommendations"]:
        lines.append("  - %s" % r)
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="扫描 Java 目标的混淆指纹并给出工具链建议")
    ap.add_argument("target", help="jar 文件、class 文件，或包含 class 的目录")
    ap.add_argument("--max-classes", type=int, default=500, help="最多解析的 class 数，默认 500")
    ap.add_argument("--text", action="store_true", help="输出人类可读摘要，而非 JSON")
    args = ap.parse_args()

    target = Path(args.target).expanduser()
    if not target.exists():
        sys.stderr.write("错误：目标不存在 -> %s\n" % target)
        return 2

    classes, cov = collect_classes(target, args.max_classes)
    if classes is None:
        sys.stderr.write("错误：无法读取目标（不是 jar/zip/class，或文件损坏） -> %s\n" % target)
        return 2
    if not classes:
        sys.stderr.write("错误：目标里没有找到任何 .class 文件 -> %s\n" % target)
        return 2

    info = analyze(str(target), classes)
    info["coverage"] = cov
    print(to_text(info) if args.text else json.dumps(info, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
