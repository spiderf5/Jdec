"""recover 子命令：自洽重放，解出 indy 字符串/常量加密。

方法论（真实样本实证，见 references/string-encryption.md）：
解密器有跨类全局状态，"静态重放求 key" 必错；但**同一轮 JVM 内自洽**——
初始化目标类 → 反射读本轮真字段值 → 现场求 key → 调用目标类自己的
bootstrap。本模块把该流程产品化：

1. bsm.py 枚举 invokedynamic 站点，动态参数还原为表达式树（字节码级，
   比 CFR 文本正则稳）；
2. 生成规格 TSV（类 / BSM / 站点 + 后缀表达式栈）；
3. 写出并编译 RecoverDriver.java，在 --cp 提供的可运行 classpath 上
   执行目标类自己的 bootstrap 机器；
4. 收割明文。只执行目标代码的解密路径——与 jdec 其余部分同一纪律。

classpath 由调用者提供（remap 到同命名空间的 MC + 依赖库 + stub），
见 SKILL/references 的 runbook。
"""

from __future__ import annotations

import base64
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
import zipfile

from . import bsm as BM

DRIVER_JAVA = (Path(__file__).parent / "recover_driver_template.java").read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# 失败归因。真实样本双管线对标（2026-10-04）的教训：failed 清单禁止用一句统一
# 叙事（如"结构性边界"）解释掉一批失败——11 个失败类里 4 个只是 classpath
# 少了一罐 lwjgl 常量 jar。按根因自动分桶，每桶给可执行的处置建议。
# --------------------------------------------------------------------------

@dataclass
class FailBucket:
    key: str
    title: str
    remediation: str
    entries: list[tuple[str, str, str]] = field(default_factory=list)  # (fqcn, tag, cause)


_FAIL_BUCKETS: list[tuple[str, str, str, str]] = [
    # (key, 根因正则 re.I|re.S, 标题, 处置建议)；顺序即优先级，首中即停
    ("native", r"UnsatisfiedLinkError",
     "缺真实 native 库",
     "该类 clinit 真调了 native 方法：单独认输，或补真实 native 后重跑。"
     "不要因此把整个依赖族剔出 classpath——真实样本实测：全剔 lwjgl 错杀 4 个只摸常量的类"),
    ("lwjgl-constants", r"(?:NoClassDefFoundError|ClassNotFoundException):\s*org[./]lwjgl",
     "缺 lwjgl 常量类",
     "GLFW/GL 系**常量类加载是安全的**（加载 ≠ 调 native）：把 lwjgl-api jar 加回 "
     "classpath 重跑；只有 clinit 真调 native 的类才需要认输"),
    ("missing-class", r"NoClassDefFoundError|ClassNotFoundException",
     "缺依赖类",
     "按目标版本 version json 的 libraries 清单补齐 classpath 后重跑"),
    ("needs-instance", r"(NullPointerException|IllegalStateException).{0,300}(minecraft|getInstance)",
     "需要真实游戏实例",
     "Minecraft.getInstance() 等运行时解引用：结构性失败，除非真机或注入实例桩"),
    ("needs-bootstrap", r"(IllegalStateException|ExceptionInInitializerError|RuntimeException)"
                       r".{0,300}(bootstrap|registry)",
     "注册表/引导未完成",
     "试无头引导：SharedConstants 版本探测 + Bootstrap 静态布尔置位，或注册表 stub；"
     "真 bootStrap() 深处可能藏 System.exit，别直接调"),
    ("signature", r"NoSuchMethodException|WrongMethodTypeException|IllegalAccessException",
     "签名/访问不符",
     "站点签名与解密器不一致：查 spec 提取的参数形状（int/long 装箱、重载），"
     "或对 seed 空间做暴力枚举"),
    ("clinit-chain", r"ExceptionInInitializerError",
     "clinit 深链失败",
     "cause 已取最深一层；仍解不动就人工看初始化链里引用了什么"),
    ("other", r"", "未归类", "逐条人工看根因；新形态命中多了就升级成独立的桶"),
]


def _exc_of(cause: str) -> str:
    m = re.search(r"([A-Za-z][A-Za-z0-9]*(?:Error|Exception))", cause)
    return m.group(1) if m else "?"


def triage_failures(fail_lines: list[str]) -> list[FailBucket]:
    """把 driver 的 FAIL 行按根因分桶。纯函数，便于单测。"""
    buckets = [FailBucket(key=key, title=title, remediation=rem)
               for key, _rx, title, rem in _FAIL_BUCKETS]
    by_key = {b.key: b for b in buckets}
    for line in fail_lines:
        q = line.split("\t", 3)
        if len(q) < 4:
            continue
        fqcn, tag, cause = q[1], q[2], q[3]
        for key, rx, _t, _r in _FAIL_BUCKETS:
            if not rx or re.search(rx, cause, re.I | re.S):
                by_key[key].entries.append((fqcn, tag, cause))
                break
    return [b for b in buckets if b.entries]


def write_failed_triage(out_dir: Path, buckets: list[FailBucket],
                        n_skip: int) -> Path | None:
    """失败归因报告（硬输出）：分桶统计 + 每桶处置建议 + 类清单。"""
    if not buckets:
        return None
    n_sites = sum(len(b.entries) for b in buckets)
    n_cls = len({e[0] for b in buckets for e in b.entries})
    L = ["# recover 失败归因（自动分桶）", ""]
    L.append(f"FAIL 站点 {n_sites} 个，涉及 {n_cls} 个类；另有 {n_skip} 个 SKIP"
             f"（多为类级失败的连带 no-bsm）。**每桶先看处置建议，"
             f"不要用统一叙事解释一批失败。**")
    L.append("")
    L.append("| 桶 | 站点 | 类数 | 典型异常 |")
    L.append("|---|---|---|---|")
    for b in buckets:
        excs = sorted({_exc_of(e[2]) for e in b.entries})
        L.append(f"| {b.key} | {len(b.entries)} | "
                 f"{len({e[0] for e in b.entries})} | {', '.join(excs[:3])} |")
    L.append("")
    for b in buckets:
        cls = sorted({e[0] for e in b.entries})
        L.append(f"## {b.key} — {b.title}")
        L.append("")
        L.append(f"处置：{b.remediation}")
        L.append("")
        for c in cls[:15]:
            n_i = sum(1 for e in b.entries if e[0] == c)
            cause0 = next(e[2] for e in b.entries if e[0] == c)
            L.append(f"- `{c}` ×{n_i} — {cause0[:120]}")
        if len(cls) > 15:
            L.append(f"- ... {len(cls) - 15} more classes")
        L.append("")
    p = out_dir / "failed_triage.md"
    p.write_text("\n".join(L) + "\n", encoding="utf-8")
    return p


def _esc(s: str) -> str:
    return (s.replace("\\", "\\\\").replace("\t", "\\t")
             .replace("\n", "\\n").replace("\r", "\\r"))


def _stack_of(tree) -> str | None:
    """表达式树 → 后缀栈串；不可恢复节点返回 None。"""
    kind = tree[0]
    if kind == "lit":
        v = tree[1]
        return f"lit:{v}" if isinstance(v, int) else None
    if kind == "fld":
        return "fld:" + tree[1]
    if kind in ("o", "null"):
        return "null"
    if kind == "op":
        a = _stack_of(tree[2])
        b = _stack_of(tree[3]) if len(tree) > 3 else None
        if a is None or b is None:
            return None
        return f"{a} {b} {tree[1]}"
    if kind == "i2l" or kind == "l2i" or kind == "lneg" or kind == "ineg":
        a = _stack_of(tree[2])
        return None if a is None else f"{a} {kind}"
    return None


def _bsm_static_args(entry: BM.BsmEntry):
    """BSM 静态参数编码；不可编码的返回 None。"""
    out = []
    for kind, v in entry.args:
        if kind == "cls":
            out.append("c:" + v)
        elif kind == "mt":
            out.append("mt:" + _esc(v))
        elif kind == "lit" and isinstance(v, str):
            out.append("s:" + _esc(v))
        elif kind == "lit" and isinstance(v, int):
            out.append(("i:" if -2**31 <= v < 2**31 else "l:") + str(v))
        elif kind == "mh":
            m = v
            if m.get("owner") is None or m.get("kind") not in (5, 6, 7):
                return None
            out.append("mh:%d:%s:%s:%s"
                       % (m["kind"], m["owner"], m["name"], m["desc"]))
        else:
            return None
    return out


def build_spec(jar: Path, out_dir: Path, limit: int = 0):
    classes = []
    n_unreadable = 0
    with zipfile.ZipFile(jar) as zf:
        seen = set()
        for info in zf.infolist():
            if not info.filename.endswith(".class"):
                continue
            try:
                cf = BM.CF.parse(zf.read(info))
            except Exception:
                # "0 sites" and "the class could not be read" are different
                # answers; the caller reports the second one now
                n_unreadable += 1
                continue
            if cf.name in seen:
                continue
            seen.add(cf.name)
            bsm = BM.parse_bsm(cf)
            sites = BM.enum_sites(cf, {"bsm": bsm})
            # vanilla 引导（lambda / 字符串拼接）不是混淆，排除
            sites = [s for s in sites if not (s.bsm and
                     (s.bsm.owner or "").startswith("java/lang/invoke/"))]
            if not sites:
                continue
            if limit and len(classes) >= limit:
                break
            classes.append((cf, bsm, sites))

    # 形态分型（真实样本 2026-10-04 实证）：
    # - REF 型（成员引用隐藏）：同一个三参 BSM 被**多种返回类型**的站点共用
    #   （字段 getter/setter、方法引用全部走它），站点 desc 尾部固定两个 long
    #   = 加密成员引用。driver 对它**不能执行**目标方法，只能解引用。
    # - STR 型（字符串解密）：BSM 只服务单一返回类型（通常 (IJ)String），
    #   类内有私有 DES 解密器，调 bootstrap 才是正解。
    BSM3 = ("(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
            "Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;")
    ret_by_bsm: dict = {}
    for cf, bsm, sites in classes:
        for s in sites:
            if s.bsm is not None:
                ret_by_bsm.setdefault((cf.name, s.bsm.index), set()).add(
                    s.desc.split(")")[-1])

    def _kind(cf_name: str, e, desc: str) -> str:
        rets = ret_by_bsm.get((cf_name, e.index), set())
        tail_jj = desc.split(")")[0].endswith("JJ")
        if e.desc == BSM3 and len(rets) >= 3 and tail_jj:
            return "REF"
        return "STR"

    spec = []
    n_sites = n_skip = 0
    for cf, bsm, sites in classes:
        spec.append("C\t" + cf.name.replace("/", "."))
        for e in bsm:
            sa = _bsm_static_args(e)
            if sa is None:
                # 不可编码的 BSM 留空:其站点会 SKIP(no-bsm),不产生 FAIL 噪音
                continue
            spec.append("\t".join(
                ["B", str(e.index), (e.owner or "?").replace("/", "."),
                 e.name, e.desc] + sa))
        for s in sites:
            na_desc = BM._arity(s.desc)
            stacks = [_stack_of(a) for a in s.dynargs]
            # 提取短栈（开头的对象参数被清）→ 前端补 null 占位到真实 arity
            while len(stacks) < na_desc:
                stacks.insert(0, "null")
            if any(x is None for x in stacks):
                n_skip += 1
                continue
            idx = s.bsm.index if s.bsm else -1
            kind = (_kind(cf.name, s.bsm, s.desc)
                    if s.bsm is not None else "STR")
            spec.append("	".join(
                ["S", str(idx), s.name, s.desc, str(len(stacks)), kind]
                + stacks))
            n_sites += 1
    spec_path = out_dir / "recover_spec.tsv"
    spec_path.write_text("\n".join(spec) + "\n", encoding="utf-8")
    return spec_path, n_sites, n_skip, n_unreadable


def code_mask(txt: str) -> list[bool]:
    """Java 源码词法区域标记：逐字符标记是否处于"代码区"。

    行注释 //、块注释 /* */、字符串 "..."、字符 '...' 内的字符一律
    False（含转义序列与结尾定界符）。供源码改写器（recover/pool）跳过
    注释与字面量——注释里的示例调用、字符串里恰好同形的文案都不是
    真实调用点，替换它们会污染源码并让 verify 统计虚高。

    限制：不处理 Java 15+ text block（三引号），反编译器输出中罕见；
    遇到未闭合注释/字符串时把剩余字符全部标 False（保守方向正确）。
    """
    n = len(txt)
    mask = [True] * n
    i = 0
    state = "code"  # code | line_c | block_c | str | char
    while i < n:
        c = txt[i]
        nxt = txt[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line_c"
                mask[i] = mask[i + 1] = False
                i += 2
                continue
            if c == "/" and nxt == "*":
                state = "block_c"
                mask[i] = mask[i + 1] = False
                i += 2
                continue
            if c == '"':
                state = "str"
                mask[i] = False
                i += 1
                continue
            if c == "'":
                state = "char"
                mask[i] = False
                i += 1
                continue
            i += 1
        elif state == "line_c":
            mask[i] = False
            if c == "\n":
                state = "code"
            i += 1
        elif state == "block_c":
            mask[i] = False
            if c == "*" and nxt == "/":
                mask[i + 1] = False
                state = "code"
                i += 2
                continue
            i += 1
        elif state == "str":
            mask[i] = False
            if c == "\\":
                if i + 1 < n:
                    mask[i + 1] = False
                i += 2
                continue
            if c == '"':
                state = "code"
            i += 1
        else:  # char
            mask[i] = False
            if c == "\\":
                if i + 1 < n:
                    mask[i + 1] = False
                i += 2
                continue
            if c == "'":
                state = "code"
            i += 1
    return mask


def java_escape(s: str) -> str:
    """把明文转成 Java 字符串字面量的内容（不含首尾引号）。

    反斜杠一律用 chr(92) 构造——实证某些传输链路会把手写的反斜杠
    改写成斜杠，chr() 拼接免疫。
    编码卫生（真实样本对标教训）：除 \t\n\r 外的所有控制字符与全部非 ASCII
    一律转义成 uXXXX 形式——裸控制/高位字节会让下游 grep/diff 把文件判成
    binary，静默漏统计（实测 6902 被少算成 3221）。
    """
    bs = chr(92)
    out = []
    for ch in s:
        o = ord(ch)
        if ch == bs:
            out.append(bs + bs)
        elif ch == '"':
            out.append(bs + '"')
        elif ch == "\n":
            out.append(bs + "n")
        elif ch == "\r":
            out.append(bs + "r")
        elif ch == "\t":
            out.append(bs + "t")
        elif o < 0x20 or o > 0x7E:
            out.append(bs + "u%04x" % o)
        else:
            out.append(ch)
    return "".join(out)


def java_unescape(s: str) -> str:
    """java_escape 的逆变换——verify 用：字面量反转义后须与明文一致。"""
    bs = chr(92)
    simple = {"n": chr(10), "r": chr(13), "t": chr(9),
              "b": chr(8), "f": chr(12)}
    out = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == bs and i + 1 < len(s):
            n = s[i + 1]
            if n == "u" and i + 5 < len(s):
                try:
                    out.append(chr(int(s[i + 2:i + 6], 16)))
                    i += 6
                    continue
                except ValueError:
                    pass
            out.append(simple.get(n, n))
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def decode_plain_field(raw: str) -> str:
    """把 recovered.tsv 的明文列解码（支持 b64:... 及兼容 legacy esc 格式）。"""
    if raw.startswith("b64:"):
        try:
            return base64.b64decode(raw[4:]).decode("utf-8", errors="surrogateescape")
        except Exception:
            pass
    # legacy esc() 格式：反转义 \\t, \\n, \\r, \\\\ 防止二次转义
    out = []
    i = 0
    while i < len(raw):
        if raw[i] == "\\" and i + 1 < len(raw):
            n = raw[i + 1]
            if n == "t":
                out.append("\t")
            elif n == "n":
                out.append("\n")
            elif n == "r":
                out.append("\r")
            elif n == "\\":
                out.append("\\")
            else:
                out.append(n)
            i += 2
        else:
            out.append(raw[i])
            i += 1
    return "".join(out)


# Re-exported: `pool` imports this name from here, and moving it silently
# would be a compatibility break for anything outside this package.
from .toolchain import norm_classpath  # noqa: E402,F401


class ReplayNotAllowed(RuntimeError):
    """动态重放被安全闸门拒绝（默认拒绝，需显式 allow_exec）。"""


def run_replay(cmd: list[str], timeout: int, **popen_kw) -> subprocess.CompletedProcess:
    """Run a replay JVM; on timeout kill the WHOLE process tree.

    subprocess.run(只杀直接子进程) leaves grandchildren alive when the JVM
    spawned helpers; the replay executes untrusted target code, so the kill
    must cover the tree. Returns CompletedProcess with a `timed_out` attribute.
    """
    popen_kw.setdefault("stdout", subprocess.PIPE)
    popen_kw.setdefault("stderr", subprocess.PIPE)
    proc = subprocess.Popen(cmd, **popen_kw)
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True)
        else:
            try:
                os.killpg(os.getpgid(proc.pid), 9)  # SIGKILL the group
            except Exception:
                proc.kill()
        try:
            out, err = proc.communicate(timeout=30)
        except Exception:
            out, err = b"", b""
    r = subprocess.CompletedProcess(cmd, 1 if timed_out else proc.returncode,
                                    out if out is not None else "",
                                    err if err is not None else "")
    r.timed_out = timed_out  # type: ignore[attr-defined]
    return r


def ingest_frida_tsv(tsv_path: Path) -> dict[tuple[str, str], str]:
    """把外部 Frida 动态转储 TSV 吸收为 (cipher, seed) -> plain 映射。

    支持：
    - 6 列 recovered 格式: OK \\t fqcn \\t site \\t cipher \\t seed \\t raw_plain
    - 3 列通用格式: cipher \\t seed \\t plain
    - Frida jnitrace TSV: tid \\t NewStringUTF \\t plain
    - 5/6 列 pool harvest 格式: R \\t fqcn \\t meth \\t idx \\t seed \\t b64_plain
    """
    out: dict[tuple[str, str], str] = {}
    if not tsv_path.exists():
        return out
    for line in tsv_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if parts[0] == "OK" and len(parts) >= 6:
            cipher, seed, raw_plain = parts[3], parts[4], parts[-1]
            plain = decode_plain_field(raw_plain)
            if cipher != "-" and seed != "-":
                out[(cipher, seed)] = plain
        elif len(parts) >= 3 and parts[1] == "NewStringUTF":
            plain = parts[2]
            out[(plain, "0")] = plain
        elif parts[0] == "R" and len(parts) >= 6:
            idx, seed, raw_plain = parts[3], parts[4], parts[5]
            try:
                plain = base64.b64decode(raw_plain).decode("utf-8", errors="replace")
                out[(str(idx), str(seed))] = plain
            except Exception:
                pass
        elif len(parts) == 3 and parts[0] not in ("R", "E"):
            cipher, seed, raw_plain = parts[0], parts[1], parts[2]
            plain = decode_plain_field(raw_plain)
            out[(cipher, seed)] = plain
    return out


def rewrite_sources(src_dir: Path, tsv_path: Path | None = None,
                    from_frida: Path | None = None) -> dict:
    """把 recovered.tsv 与/或 Frida 转储的解密明文回填进反编译源码。

    匹配源码里 indy 被还原成的 BSM 调用形态:
        Cls.method("siteName", "cipher", seed)
    匹配键 = (cipher, seed)。支持吸收 Frida TSV 联合回填。
    """
    plain_map: dict = {}
    conflicts = 0

    if tsv_path and tsv_path.exists():
        for line in tsv_path.read_text(encoding="utf-8").splitlines():
            parts = line.split("\t")
            if len(parts) < 6 or parts[0] != "OK":
                continue
            cipher, seed, raw_plain = parts[3], parts[4], parts[-1]
            plain = decode_plain_field(raw_plain)
            if cipher == "-" or seed == "-":
                continue
            if plain.startswith("[L") or re.search(r"@[0-9a-f]{4,}$", plain):
                continue
            key = (cipher, seed)
            if key in plain_map:
                if plain_map[key] != plain:
                    conflicts += 1
                continue
            plain_map[key] = plain

    if from_frida:
        fmap = ingest_frida_tsv(Path(from_frida))
        for key, plain in fmap.items():
            if key in plain_map:
                if plain_map[key] != plain:
                    conflicts += 1
                continue
            plain_map[key] = plain

    # 空白类含 CR/LF：CFR 之外的引擎（vineflower/procyon）会把长参数折行
    WS = "[ \t\r\n]*"
    pat = re.compile(
        "[A-Za-z0-9_]+[.][A-Za-z0-9_]+[(]" + WS
        + '"([A-Za-z0-9+/=]{1,60})"' + WS + "," + WS
        + '"([A-Za-z0-9+/=]{1,8192})"' + WS + "," + WS
        + "(-?[0-9]+)" + WS + "[)]")

    n_files = replaced = missed = residual = 0
    lits_written: list[str] = []
    for path in sorted(src_dir.rglob("*.java")):
        # surrogateescape keeps undecodable bytes alive and newline="" keeps
        # the file's own line endings: errors="ignore" silently dropped bytes
        # and write_text() flipped every LF to CRLF on Windows
        with open(path, "r", encoding="utf-8", errors="surrogateescape",
                  newline="") as f:
            txt = f.read()
        if not pat.search(txt):
            continue
        n_files += 1
        mask = code_mask(txt)

        def sub(m: "re.Match", mask=mask) -> str:
            nonlocal replaced, missed
            if not mask[m.start()]:
                # 匹配起点落在注释/字符串内：不是真实调用点，原样保留
                # （不计 replaced 也不计 missed，residual 同口径跳过）
                return m.group(0)
            key = (m.group(2), m.group(3))
            if key in plain_map:
                replaced += 1
                plain = plain_map[key]
                lit = java_escape(plain)
                # verify：字面量转义必须可逆（抓 java_escape 的 bug）
                if java_unescape(lit) != plain:
                    raise RuntimeError("literal round-trip mismatch: "
                                       + repr(lit[:60]))
                lits_written.append(lit)
                return '"' + lit + '"'
            missed += 1
            return m.group(0)

        new = pat.sub(sub, txt)
        # residual verify 只看代码区（对 new 重算 mask：替换会改变长度偏移）
        new_mask = code_mask(new)
        residual += sum(1 for m in pat.finditer(new)
                        if new_mask[m.start()]
                        and (m.group(2), m.group(3)) not in plain_map)
        if new != txt:
            with open(path, "w", encoding="utf-8", errors="surrogateescape",
                      newline="") as f:
                f.write(new)
    # 可执行断言（编码卫生）：本次写入的字面量必须无裸控制字节——
    # 裸字节会让下游 grep/diff 判 binary 静默漏统计（实测 6902→3221）
    for lit in lits_written:
        bad = [ch for ch in lit if ord(ch) < 0x20
               and ch not in (chr(9), chr(10), chr(13))]
        if bad:
            raise RuntimeError(
                f"rewritten literal has {len(bad)} raw control byte(s) - "
                f"escaping broken, must be " + chr(92) + "uXXXX form")
    return {"files": n_files, "replaced": replaced, "missed": missed,
            "residual": residual, "conflicts": conflicts,
            "map_size": len(plain_map)}


def recover(jar: Path, out_dir: Path, cp: str = "", java: str = "java",
            limit: int = 0, stop_on_error: bool = False,
            cp_file: Path | None = None, timeout: int = 1800,
            with_stubs: bool = True, from_frida: Path | None = None,
            allow_exec: bool = False, sandbox: bool = True) -> int:
    """自洽重放解密。allow_exec=False（默认）只做静态分析：生成 spec 即停，
    不启动任何 JVM。重放会**真实执行目标 jar 里的代码**，所以在 allow_exec
    之外默认再套一层 Java 沙箱（sandbox=True）：写入限制在 out_dir，网络、
    进程执行、native 库和 System.exit 被拒。沙箱约束不了 native 代码本身
    （loadLibrary 默认拒绝，进不去）；OS 级隔离仍需要容器或专用用户。

    返回码：0=有产出；1=跑过但无明文；3=被安全闸门拦下（仅静态部分完成）。
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    sep = ";" if os.name == "nt" else ":"
    agent_jvm_arg = ""
    native_jvm_arg = ""
    prep_warnings: list[str] = []
    if with_stubs:
        try:
            from . import stubs
            stub_jar = stubs.ensure_stubs_jar()
            cp = str(stub_jar) + (sep if cp else "") + cp
            agent_jar = stubs.ensure_mock_agent_jar()
            # JPLIS cannot attach once the sandbox is installed; the stub
            # jar still goes on the classpath, the instrumentation agent does
            # not. A target that needs the agent needs --no-sandbox.
            if agent_jar.is_file() and not sandbox:
                agent_jvm_arg = f"-javaagent:{norm_classpath(str(agent_jar))}\n"
            elif agent_jar.is_file():
                prep_warnings.append(
                    "agent: mock agent not attached under the sandbox")
        except Exception as exc:  # noqa: BLE001
            # silently continuing here used to turn "stubs never loaded" into
            # "the target needs a real game instance" in the failure report
            prep_warnings.append(f"stubs: {type(exc).__name__}: {exc}")

    # 提取目标 Native 库并挂载 -Djava.library.path
    try:
        from . import native_scan
        natives_dir = out_dir / "natives"
        found_libs = native_scan.extract_libs(jar, natives_dir)
        if found_libs or any(natives_dir.glob("*")):
            native_jvm_arg = f"-Djava.library.path={norm_classpath(str(natives_dir))}\n"
    except Exception as exc:  # noqa: BLE001
        prep_warnings.append(f"natives: {type(exc).__name__}: {exc}")

    for warning in prep_warnings:
        print(f"WARNING  : replay prep: {warning}")

    if cp_file:
        extra = Path(cp_file).read_text(encoding="utf-8")
        cp = cp + (sep if cp and not cp.endswith(sep) else "") + extra.strip()
    spec_path, n_sites, n_skip, n_unreadable = build_spec(jar, out_dir, limit=limit)
    print(f"spec      : {n_sites} sites ({n_skip} skipped: args not statically "
          f"recoverable) -> {spec_path.name}")
    if n_unreadable:
        print(f"            ! {n_unreadable} class(es) unreadable and skipped")

    if not allow_exec:
        print("NOTICE    : dynamic replay EXECUTES code from the target jar; "
              "a Java sandbox (write root, no network/exec/native/exit) is "
              "installed by default unless sandbox=False.")
        print("            Default is static analysis only: spec written, no "
              "JVM started. Pass --execute (CLI) or allow_exec=True to run it.")
        return 3

    src = out_dir / "RecoverDriver.java"
    src.write_text(DRIVER_JAVA, encoding="utf-8")
    from . import toolchain as TC
    try:
        r = TC.run_javac(["-d", str(out_dir), str(src)],
                         purpose="compiling the replay driver")
    except TC.ToolchainError as exc:
        print(str(exc))
        return 1
    if r.returncode != 0:
        print("javac failed:\n" + str(r.stderr or r.stdout or "")[-2000:])
        return 1

    if java == "java":
        try:
            java = TC.require_java("running the replay driver")
        except TC.ToolchainError as exc:
            print(str(exc))
            return 1

    sandbox_args = ""
    sandbox_entry = None
    if sandbox:
        from . import sandbox as SBX
        try:
            sandbox_root = out_dir
            sandbox_args = SBX.argfile_lines(
                sandbox_root, java=java, drivers=("RecoverDriver",),
                tmp=out_dir / "_sandbox")
            sandbox_entry = SBX.classpath_entry(java=java)
        except SBX.SandboxError as exc:
            print(f"sandbox : {exc}")
            return 1
        print(f"sandbox : java-level isolation under {sandbox_root} "
              f"(writes confined; network/exec/native/exit denied)")

    target_for_cp = jar
    if sandbox:
        from . import sandbox as SBX
        try:
            target_for_cp = SBX.plain_jar(jar, out_dir / "_sandbox_input")
        except Exception:  # noqa: BLE001 - keep the original path
            target_for_cp = jar
    entries = [str(out_dir)]
    if sandbox_entry is not None:
        entries.append(str(sandbox_entry))
    if cp:
        entries.append(cp)
    entries.append(str(target_for_cp))
    classpath = sep.join(entries)
    classpath = norm_classpath(classpath)
    # Windows 命令行 ~32K 上限装不下几百个库的 classpath，用 @argfile
    argsfile = out_dir / "java_args.txt"
    cp_line = classpath.replace('"', '\\"')
    head = "-XX:+ShowMessageBoxOnError\n" if stop_on_error else ""
    argsfile.write_text(
        sandbox_args + head + agent_jvm_arg + native_jvm_arg + f'-Xverify:none\n-cp "{cp_line}"\nRecoverDriver\n"{spec_path.as_posix()}"\n',
        encoding="utf-8")
    # 每站点真解密的代价可能远超默认 30 分钟（6516 站点实测 ~35min）。
    # 超时不扔掉已产出：kill（含整个进程树）后把部分输出照常收割，
    # 调用方按需加大 --timeout。
    r = run_replay([java, "@" + str(argsfile)], timeout=timeout,
                   text=True, errors="replace")
    if getattr(r, "timed_out", False):
        print(f"WARNING  : driver killed at {timeout}s timeout "
              f"(whole process tree terminated; partial output kept; "
              f"rerun with --timeout N)")
    (out_dir / "driver.log").write_text(r.stderr[-4000:], encoding="utf-8")

    ok, fail, skip, ref = 0, 0, 0, 0
    values = []
    fail_lines = []
    for line in r.stdout.splitlines():
        q = line.split("\t", 4)
        if q[0] == "OK":
            ok += 1
            values.append(line)
        elif q[0] == "REF":
            ref += 1
        elif q[0] == "FAIL":
            fail += 1
            fail_lines.append(line)
    tsv_content = r.stdout
    if from_frida and Path(from_frida).is_file():
        frida_map = ingest_frida_tsv(Path(from_frida))
        if frida_map:
            extra_lines = []
            for (c, s), p in frida_map.items():
                b64 = "b64:" + base64.b64encode(p.encode("utf-8")).decode("ascii")
                extra_lines.append(f"OK\tfrida\tfrida\t{c}\t{s}\t{b64}")
                values.append(extra_lines[-1])
            if extra_lines:
                tsv_content = tsv_content + ("\n" if tsv_content and not tsv_content.endswith("\n") else "") + "\n".join(extra_lines) + "\n"
                ok += len(extra_lines)
    (out_dir / "recovered.tsv").write_text(tsv_content, encoding="utf-8")
    # 失败归因（硬输出）：分桶 + 每桶处置建议，见 failed_triage.md
    buckets = triage_failures(fail_lines)
    triage_path = write_failed_triage(out_dir, buckets, skip)
    # 可执行断言：有 FAIL 就必须有归因产出——格式坏了要炸出来，不许静默
    if fail_lines and not buckets:
        raise RuntimeError(
            f"{len(fail_lines)} FAIL line(s) parsed into zero triage buckets "
            f"- driver FAIL 行格式变了，修 triage_failures 再跑")
    if fail_lines:
        # `assert` would vanish under `python -O`, and this guard exists to
        # stop a malformed driver report from being read as "no failures".
        if triage_path is None or not triage_path.exists():
            raise RuntimeError(
                "fail_lines present but failed_triage.md missing")
    # 文本值去重：剔除数组/对象 toString（"[Lxxx;@hash"、"xxx@hash"）
    uniq = set()
    for v in values:
        parts = v.split("\t")
        if len(parts) < 4:
            continue
        s = decode_plain_field(parts[-1])
        if s.startswith("[L") or re.search(r"@[0-9a-f]{4,}$", s):
            continue
        uniq.add(s)
    print(f"recovered : {ok} str-sites ({len(uniq)} unique plaintexts), "
          f"{ref} ref-sites resolved, {fail} failed, {skip} skipped")
    if buckets:
        print("fail triage: " + " ".join(f"{b.key}={len(b.entries)}"
                                         for b in buckets)
              + (f" -> {triage_path.name}" if triage_path else ""))
    print(f"output    : {out_dir / 'recovered.tsv'}")
    tail = r.stderr.strip().splitlines()[-1] if r.stderr.strip() else ""
    if tail:
        print(tail)
    return 0 if ok else 1
