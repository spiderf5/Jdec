"""pool 子命令：字符串池加密（无 indy 形态）的自洽重放与回填。

形态（lf21 实证，见 references/string-encryption.md 池 replay 节）：
池类 clinit 把 packed 载体串切分 + XOR 建密文池；访问器
`static String a(int idx, int seed)` 用类内常数定址 + 密文首字节查
key 表 + seed 派生滚动 key——逐类常数全不同，静态移植不现实。
正解是 JVM replay：真类加载（触发 clinit）→ 反射调访问器 → 逐站点收明文。

三段（CLI: jdec.py pool scan|harvest|apply）：
1. scan    扫反编译源：识别访问器定义（static/... String x(int,long) 形状）
           与调用点（qualified Cls.a(n,n) / 池类文件内 bare a(n,n)）→ spec.tsv
2. harvest 生成并编译 PoolDriver.java，在调用者提供的 classpath 上真类
           加载逐站点求明文 → harvest.tsv（R=明文 base64 / E=根因行）
3. apply   回填明文进源码（uXXXX 转义落盘）+ verify（字面量自洽、
           可解站点零残留、无裸控制字节）+ E 行进失败八桶归因

环境工程见 references/string-encryption.md：lwjgl-api 常量 jar 要带上
（加载 ≠ 调 native），真崩的类进 failed 集合单独认输。
"""

from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path

from .recover import (java_escape, java_unescape, norm_classpath,
                      triage_failures, write_failed_triage)

DRIVER_JAVA = (Path(__file__).parent / "pool_driver_template.java").read_text(
    encoding="utf-8")

# 零反斜杠纪律：chr() 拼接构造，免疫传输链路对反斜杠的改写
_BS = chr(92)
_TAB, _LF, _CR = chr(9), chr(10), chr(13)
_WS = "[" + _TAB + _LF + _CR + " ]*"
_ID = "[A-Za-z_$][A-Za-z0-9_$]*"
_HEX = "[0-9A-Fa-f]"
# Java 整数字面量：十进制 / 0x 十六进制 / 前导 0 八进制，可选 L 后缀
_NUM = "(?:0[xX]" + _HEX + "+[Ll]?|[0-9]+[Ll]?)"   # _HEX 自带方括号,勿再包一层
_SNUM = "(-?[ ]*" + _NUM + ")"

# 访问器定义：static（可带 public/private/... 前缀）String name(两参)
_ACC_DEF = re.compile(
    "(?<![A-Za-z0-9_$.])(?:(?:public|protected|private|final|static)" + _WS
    + ")+(?:java[.]lang[.])?String" + _WS + "(" + _ID + ")" + _WS + "[(]([^)]*)[)]")
# 访问器参数形状：两个 int/long（final 可选）
_PARAM_II = re.compile("(?:final" + _WS + ")?(?:int|long)" + _WS + _ID + "[ ]*")
# qualified 调用：Cls.a(n, n) 或 pkg.Cls.a(n, n)
_CALL_Q = re.compile(
    "(?<![A-Za-z0-9_$.])(" + _ID + "(?:[.]" + _ID + ")*)[.](" + _ID + ")" + _WS + "[(]"
    + _SNUM + _WS + "," + _WS + _SNUM + _WS + "[)]")
# bare 调用：a(n, n) —— 只在池类自己的文件里、名字在白名单内才认
_CALL_BARE = re.compile(
    "(?<![A-Za-z0-9_$.])(" + _ID + ")" + _WS + "[(]"
    + _SNUM + _WS + "," + _WS + _SNUM + _WS + "[)]")
_PKG = re.compile(
    "(?<![A-Za-z0-9_$.])package" + _WS + "([A-Za-z0-9_.]+)" + _WS + ";")


def norm_int(s: str) -> int:
    """Java 整数字面量 → 值（0x/八进制/L 后缀/一元负号）。”"""
    s = s.strip().rstrip("Ll").strip()
    neg = s.startswith("-")
    core = s.lstrip("-").strip()
    if core.lower().startswith("0x"):
        v = int(core, 16)
    elif len(core) > 1 and core.startswith("0") and core.isdigit():
        v = int(core, 8)  # Java 八进制字面量
    else:
        v = int(core)
    return -v if neg else v


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="surrogateescape", newline="")


def _write(p: Path, s: str) -> None:
    p.write_text(s, encoding="utf-8", errors="surrogateescape", newline="")


def _fqcn_of(f: Path, txt: str) -> str:
    m = _PKG.search(txt)
    pkg = m.group(1) if m else ""
    return (pkg + "." + f.stem) if pkg else f.stem


def _acc_params_ok(params: str) -> bool:
    ps = [p.strip() for p in params.split(",") if p.strip()]
    if len(ps) != 2:
        return False
    return all(_PARAM_II.fullmatch(p) for p in ps)


# --------------------------------------------------------------------------
# 1. scan
# --------------------------------------------------------------------------

def scan_spec(src_dir: Path, spec_path: Path) -> dict:
    """扫反编译源 → spec.tsv（S\tfqcn\tmeth\tidx\tseed）。"""
    files = sorted(src_dir.rglob("*.java"))
    acc: dict[str, set] = {}
    acc_sig_bad: list[tuple[str, str]] = []
    parsed = []
    for f in files:
        txt = _read(f)
        fq = _fqcn_of(f, txt)
        names = set()
        for m in _ACC_DEF.finditer(txt):
            name, params = m.group(1), m.group(2)
            if _acc_params_ok(params):
                names.add(name)
            else:
                acc_sig_bad.append((fq, name))
        if names:
            acc[fq] = names
        parsed.append((f, fq, txt))

    simple: dict[str, str] = {}
    ambiguous: set[str] = set()
    for fq in acc:
        s = fq.rsplit(".", 1)[-1]
        if s in simple:
            ambiguous.add(s)  # 同名池类：qualified 匹配保守跳过
        else:
            simple[s] = fq

    sites: set[tuple] = set()
    files_with_sites: dict[str, int] = defaultdict(int)
    for f, own_fq, txt in parsed:
        own_names = acc.get(own_fq, set())
        for m in _CALL_Q.finditer(txt):
            cls_raw, meth = m.group(1), m.group(2)
            cls = cls_raw.split(".")[-1]
            fq = cls_raw if cls_raw in acc else simple.get(cls)
            if fq is None or (cls in ambiguous and cls_raw not in acc) or meth not in acc[fq]:
                continue
            sites.add((fq, meth, norm_int(m.group(3)), norm_int(m.group(4))))
            files_with_sites[f.name] += 1
        if own_names:
            for m in _CALL_BARE.finditer(txt):
                meth = m.group(1)
                if meth not in own_names:
                    continue
                sites.add((own_fq, meth, norm_int(m.group(2)),
                           norm_int(m.group(3))))
                files_with_sites[f.name] += 1

    spec_path.parent.mkdir(parents=True, exist_ok=True)
    with open(spec_path, "w", encoding="utf-8", newline="") as w:
        for fq, meth, idx, seed in sorted(sites):
            w.write("S" + _TAB + fq + _TAB + meth + _TAB + str(idx) + _TAB
                    + str(seed) + _LF)
    return {
        "files": len(files), "pool_classes": len(acc),
        "accessors": sum(len(v) for v in acc.values()),
        "sig_bad": len(acc_sig_bad), "sites": sum(files_with_sites.values()),
        "unique": len(sites), "files_with_sites": len(files_with_sites),
        "ambiguous_simple_names": sorted(ambiguous),
        "spec": spec_path,
    }


# --------------------------------------------------------------------------
# 2. harvest
# --------------------------------------------------------------------------

def harvest(spec_path: Path, out_tsv: Path, work_dir: Path, cp: str = "",
            cp_file: Path | None = None, java: str = "java",
            timeout: int = 3600, with_stubs: bool = True) -> dict:
    """生成/编译 PoolDriver，真类加载逐站点求明文 → out_tsv（R/E 行）。"""
    work_dir.mkdir(parents=True, exist_ok=True)
    src = work_dir / "PoolDriver.java"
    src.write_text(DRIVER_JAVA, encoding="utf-8")
    from . import stubs as SB
    javac_cmd = SB._find_javac("javac")
    r = subprocess.run([javac_cmd, "-d", str(work_dir), str(src)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("javac failed: " + (r.stderr or r.stdout or "")[-2000:])

    if java == "java":
        from . import engines as EN
        java = EN.find_java() or java

    sep = ";" if os.name == "nt" else ":"
    if with_stubs:
        try:
            from . import stubs
            stub_jar = stubs.ensure_stubs_jar()
            cp = str(stub_jar) + (sep if cp else "") + cp
        except Exception:
            pass
    if cp_file:
        extra = Path(cp_file).read_text(encoding="utf-8")
        cp = cp + (";" if cp and not cp.endswith(";") else "") + extra.strip()
    classpath = sep.join([str(work_dir), cp]) if cp else str(work_dir)
    classpath = norm_classpath(classpath)
    argsfile = work_dir / "java_args.txt"
    argsfile.write_text(
        "-Xverify:none" + _LF
        + '-cp "' + classpath.replace('"', _BS + '"') + '"' + _LF
        + "PoolDriver" + _LF
        + '"' + spec_path.resolve().as_posix() + '"' + _LF
        + '"' + out_tsv.resolve().as_posix() + '"' + _LF,
        encoding="utf-8")
    log_path = work_dir / "driver.log"
    out_tsv.parent.mkdir(parents=True, exist_ok=True)
    timed_out = False
    # stdout 直落盘：LF21 实战教训，管道缓冲+大输出会假死假象
    with open(out_tsv, "wb") as fo, open(log_path, "wb") as fe:
        try:
            rc = subprocess.run([java, "@" + str(argsfile)],
                                stdout=fo, stderr=fe,
                                timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            # 超时保部分输出；调用方按需加大 --timeout 重跑
            timed_out = True
            rc = 1

    ok = err = 0
    fail_lines: list[str] = []
    for line in out_tsv.read_text(encoding="utf-8",
                                  errors="replace").splitlines():
        q = line.split(_TAB)
        if q and q[0] == "R" and len(q) >= 6:
            ok += 1
        elif q and q[0] == "E" and len(q) >= 6:
            err += 1
            # E 行 → recover 八桶归因的 FAIL 行格式（tag=方法名）
            fail_lines.append("FAIL" + _TAB + q[1] + _TAB + q[2] + _TAB + q[5])
    buckets = triage_failures(fail_lines)
    triage_path = write_failed_triage(work_dir, buckets, 0)
    if fail_lines and not buckets:
        raise RuntimeError("E lines parsed into zero triage buckets")
    return {
        "ok": ok, "err": err, "timed_out": timed_out, "returncode": rc,
        "buckets": buckets, "triage": triage_path, "log": log_path,
        "harvest": out_tsv,
    }


# --------------------------------------------------------------------------
# 3. apply（回填 + verify）
# --------------------------------------------------------------------------

def _check_lit(lit: str, plain: str) -> None:
    """字面量三重自检：转义可逆、无裸控制字节、无裸高位字节。"""
    if java_unescape(lit) != plain:
        raise RuntimeError("literal round-trip mismatch: "
                           + repr(lit[:60]))
    bad = [ch for ch in lit if ord(ch) < 0x20
           and ch not in (_TAB, _LF, _CR)]
    if bad:
        raise RuntimeError(
            f"literal contains {len(bad)} raw control byte(s) - "
            f"escaping broken (must be " + _BS + "uXXXX form)")


def apply(src_dir: Path, harvest_path: Path, out_dir: Path) -> dict:
    """回填明文进源码副本（out_dir），替换 + verify + 失败归因。"""
    plain: dict[tuple, str] = {}
    fail_lines: list[str] = []
    for line in harvest_path.read_text(encoding="utf-8",
                                       errors="replace").splitlines():
        q = line.split(_TAB)
        if q and q[0] == "R" and len(q) >= 6:
            plain[(q[1], q[2], int(q[3]), int(q[4]))] = \
                base64.b64decode(q[5]).decode("utf-8", errors="replace")
        elif q and q[0] == "E" and len(q) >= 6:
            fail_lines.append("FAIL" + _TAB + q[1] + _TAB + q[2] + _TAB + q[5])

    if out_dir.exists():
        shutil.rmtree(out_dir)
    shutil.copytree(src_dir, out_dir)

    # 回填侧访问器识别与 scan 同口径（窄匹配），保证调用点对得上
    parsed = []
    acc: dict[str, set] = {}
    for f in sorted(out_dir.rglob("*.java")):
        txt = _read(f)
        fq = _fqcn_of(f, txt)
        names = {m.group(1) for m in _ACC_DEF.finditer(txt)
                 if _acc_params_ok(m.group(2))}
        if names:
            acc[fq] = names
        parsed.append((f, fq, txt))
    simple: dict[str, str] = {}
    ambiguous: set[str] = set()
    for fq in acc:
        s = fq.rsplit(".", 1)[-1]
        if s in simple:
            ambiguous.add(s)
        else:
            simple[s] = fq

    stat = defaultdict(int)
    sample: list[str] = []
    for f, own_fq, txt in parsed:
        orig = txt
        own_names = acc.get(own_fq, set())

        def repl_q(m: "re.Match") -> str:
            cls_raw, meth = m.group(1), m.group(2)
            cls = cls_raw.split(".")[-1]
            fq = cls_raw if cls_raw in acc else simple.get(cls)
            if fq is None or (cls in ambiguous and cls_raw not in acc) or meth not in acc[fq]:
                return m.group(0)
            key = (fq, meth, norm_int(m.group(3)), norm_int(m.group(4)))
            if key in plain:
                lit = java_escape(plain[key])
                _check_lit(lit, plain[key])
                stat["repl_q"] += 1
                if len(sample) < 10:
                    sample.append(plain[key][:40])
                return '"' + lit + '"'
            stat["miss_q"] += 1
            return m.group(0)

        def repl_b(m: "re.Match") -> str:
            meth = m.group(1)
            if meth not in own_names:
                return m.group(0)
            key = (own_fq, meth, norm_int(m.group(2)), norm_int(m.group(3)))
            if key in plain:
                lit = java_escape(plain[key])
                _check_lit(lit, plain[key])
                stat["repl_bare"] += 1
                return '"' + lit + '"'
            stat["miss_bare"] += 1
            return m.group(0)

        txt = _CALL_Q.sub(repl_q, txt)
        if own_names:
            txt = _CALL_BARE.sub(repl_b, txt)
        if txt != orig:
            _write(f, txt)

    # verify：回填后的树里，可解站点的调用形态残留必须为 0
    residual = 0
    residual_samples: list[str] = []
    for f, own_fq in [(f, fq) for f, fq, _ in parsed]:
        txt = _read(f)
        own_names = acc.get(own_fq, set())
        for m in _CALL_Q.finditer(txt):
            cls, meth = m.group(1), m.group(2)
            fq = simple.get(cls)
            if fq is None or cls in ambiguous or meth not in acc[fq]:
                continue
            key = (fq, meth, norm_int(m.group(3)), norm_int(m.group(4)))
            if key in plain:
                residual += 1
                if len(residual_samples) < 5:
                    residual_samples.append(f.name)
        if own_names:
            for m in _CALL_BARE.finditer(txt):
                meth = m.group(1)
                if meth not in own_names:
                    continue
                key = (own_fq, meth, norm_int(m.group(2)),
                       norm_int(m.group(3)))
                if key in plain:
                    residual += 1
    if residual:
        raise RuntimeError(
            f"verify failed: {residual} decodable call site(s) left after "
            f"rewrite (e.g. {residual_samples}) - replacement regex与扫描口径不一致")

    buckets = triage_failures(fail_lines)
    triage_path = write_failed_triage(out_dir, buckets, 0)
    return {
        "replaced": stat["repl_q"] + stat["repl_bare"],
        "repl_q": stat["repl_q"], "repl_bare": stat["repl_bare"],
        "missed": stat["miss_q"] + stat["miss_bare"],
        "unique_plain": len(plain), "residual": residual,
        "sample": sample, "buckets": buckets, "triage": triage_path,
        "out": out_dir,
    }
