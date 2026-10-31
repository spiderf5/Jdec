"""pool 子命令：字符串池加密（无 indy 形态）的自洽重放与回填。

形态（真实样本实证，见 references/string-encryption.md 池 replay 节）：
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
import re
import shutil
from collections import defaultdict
from pathlib import Path

from .recover import (ReplayNotAllowed, code_mask, java_escape,
                      java_unescape, norm_classpath, run_replay,
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


def _collect_accessors(parsed):
    """_ACC_DEF 扫描 → (acc, sig_bad)。

    acc: fq -> name -> [签名列表]，签名 = (参1类型, 参2类型)。
    scan / apply 回填 / apply verify 三处共用，保证口径一致。
    """
    acc: dict[str, dict[str, list]] = {}
    sig_bad: list[tuple[str, str]] = []
    for _f, fq, txt in parsed:
        for m in _ACC_DEF.finditer(txt):
            kinds = _acc_param_kinds(m.group(2))
            if kinds:
                acc.setdefault(fq, {}).setdefault(m.group(1), []).append(kinds)
            else:
                sig_bad.append((fq, m.group(1)))
    return acc, sig_bad


def _resolve_fq(cls_raw: str, acc: dict, simple: dict[str, str],
                ambiguous: set[str]) -> str | None:
    """_CALL_Q 调用点的类名解析口径（回填与 verify 共用）。

    全限定名直接认访问器表；否则退回简单名表，简单名歧义时放弃。
    两处口径必须一字不差——verify 曾经只看简单名，全限定调用点在
    校验阶段漏检，造成"校验通过、实际没回填干净"的假零残留。
    """
    cls = cls_raw.split(".")[-1]
    if cls_raw in acc:
        return cls_raw
    if cls in ambiguous:
        return None
    return simple.get(cls)


def _overload_ok(acc, fq: str, meth: str, lit_idx: str, lit_seed: str) -> str:
    """调用点重载分派（三态）。

    "ok"       分派到返回 String 的同名访问器（按实参字面量类型）；
    "overload" 有同名 String 访问器但参数类型不匹配——另一套池
               （int/long 常量池）的调用点，必须剔除；
    "none"     该类没有同名 String 访问器（本来就不是池类）。
    """
    sigs = acc.get(fq, {}).get(meth)
    if not sigs:
        return "none"
    return "ok" if (_lit_kind(lit_idx), _lit_kind(lit_seed)) in sigs \
        else "overload"


def _read(p: Path) -> str:
    # open(), not Path.read_text(newline=...): that keyword only exists on
    # Python 3.13+, while this package supports 3.9+ (CI runs 3.10-3.12).
    with open(p, "r", encoding="utf-8", errors="surrogateescape", newline="") as f:
        return f.read()


def _write(p: Path, s: str) -> None:
    with open(p, "w", encoding="utf-8", errors="surrogateescape", newline="") as f:
        f.write(s)


def _fqcn_of(f: Path, txt: str) -> str:
    m = _PKG.search(txt)
    pkg = m.group(1) if m else ""
    return (pkg + "." + f.stem) if pkg else f.stem


def _acc_param_kinds(params: str):
    """访问器参数表 → (类型, 类型)（"int"/"long"）；形状不合返回 None。

    2026-10-05 真实样本实测教训：一个池类里 String a(int,int) 与
    int a(int,long) 两套池共存（字符串池 + int 常量池），名字级白名单会把
    int 池的调用点也扫进 spec，driver 按字符串池语义传 idx → AIOOBE
    （Index 31158 = 772^0x7AB2）。签名级分派是唯一可靠判据。
    """
    ps = [p.strip() for p in params.split(",") if p.strip()]
    if len(ps) != 2:
        return None
    kinds = []
    for p in ps:
        if not _PARAM_II.fullmatch(p):
            return None
        kinds.append("long" if "long" in p else "int")
    return tuple(kinds)


_INT_MIN, _INT_MAX = -0x80000000, 0x7FFFFFFF


def _lit_kind(s: str) -> str:
    """整数字面量的静态类型：L/l 后缀或超 int 范围 → "long"，否则 "int"。

    Java 重载分派阶段 1 不做 long→int 隐式窄化，所以 a(1, 2L) 恒调
    a(int, long)——字面量后缀就是分派依据（norm_int 会剥掉 L，必须
    在剥之前看原文）。"""
    t = s.strip()
    if t[-1:] in ("L", "l"):
        return "long"
    v = norm_int(s)
    return "int" if _INT_MIN <= v <= _INT_MAX else "long"


# --------------------------------------------------------------------------
# 1. scan
# --------------------------------------------------------------------------

def scan_spec(src_dir: Path, spec_path: Path) -> dict:
    """扫反编译源 → spec.tsv（S\tfqcn\tmeth\tidx\tseed）。

    acc 结构：fq -> name -> [签名列表]；签名 = (参1类型, 参2类型)。
    调用点按实参字面量类型分派同名重载（见 _lit_kind），只有分派到
    返回 String 的访问器才进 spec——int/long 常量池的重载调用点剔除。
    """
    files = sorted(src_dir.rglob("*.java"))
    parsed = []
    for f in files:
        txt = _read(f)
        fq = _fqcn_of(f, txt)
        parsed.append((f, fq, txt))
    acc, acc_sig_bad = _collect_accessors(parsed)

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
    overload_skipped = 0

    def _accept(fq: str, meth: str, lit_idx: str, lit_seed: str) -> bool:
        verdict = _overload_ok(acc, fq, meth, lit_idx, lit_seed)
        if verdict == "overload":
            nonlocal overload_skipped
            overload_skipped += 1
        return verdict == "ok"

    for f, own_fq, txt in parsed:
        own_sigs = acc.get(own_fq, {})
        for m in _CALL_Q.finditer(txt):
            cls_raw, meth = m.group(1), m.group(2)
            cls = cls_raw.split(".")[-1]
            fq = cls_raw if cls_raw in acc else simple.get(cls)
            if fq is None or (cls in ambiguous and cls_raw not in acc):
                continue
            if not _accept(fq, meth, m.group(3), m.group(4)):
                continue
            sites.add((fq, meth, norm_int(m.group(3)), norm_int(m.group(4))))
            files_with_sites[f.name] += 1
        if own_sigs:
            for m in _CALL_BARE.finditer(txt):
                meth = m.group(1)
                if meth not in own_sigs:
                    continue
                if not _accept(own_fq, meth, m.group(2), m.group(3)):
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
        "overload_skipped": overload_skipped,
        "ambiguous_simple_names": sorted(ambiguous),
        "spec": spec_path,
    }


# --------------------------------------------------------------------------
# 2. harvest
# --------------------------------------------------------------------------

def harvest(spec_path: Path, out_tsv: Path, work_dir: Path, cp: str = "",
            cp_file: Path | None = None, java: str = "java",
            timeout: int = 3600, with_stubs: bool = True,
            allow_exec: bool = False) -> dict:
    """生成/编译 PoolDriver，真类加载逐站点求明文 → out_tsv（R/E 行）。

    安全闸门：harvest 的全部工作都是 JVM replay——**会真实执行目标 jar
    里的代码**（clinit / 解密器以本进程权限运行）。默认 allow_exec=False
    直接拒绝；CLI 需 --execute，pipeline 需 allow_replay=True。
    """
    if not allow_exec:
        raise ReplayNotAllowed(
            "pool harvest runs the replay JVM, which EXECUTES code from the "
            "target jar (initializers/decryptors run with this process's "
            "permissions); pass --execute (CLI) or allow_exec=True to enable")
    work_dir.mkdir(parents=True, exist_ok=True)
    src = work_dir / "PoolDriver.java"
    src.write_text(DRIVER_JAVA, encoding="utf-8")
    from . import toolchain as TC
    r = TC.run_javac(["-d", str(work_dir), str(src)],
                     purpose="compiling the pool driver")
    if r.returncode != 0:
        raise RuntimeError("javac failed: " + (r.stderr or r.stdout or "")[-2000:])

    if java == "java":
        java = TC.require_java("running the pool driver")

    sep = TC.path_sep()
    agent_jvm_arg = ""
    native_jvm_arg = ""
    prep_warnings: list[str] = []
    if with_stubs:
        try:
            from . import stubs
            stub_jar = stubs.ensure_stubs_jar()
            cp = str(stub_jar) + (sep if cp else "") + cp
            agent_jar = stubs.ensure_mock_agent_jar()
            if agent_jar.is_file():
                agent_jvm_arg = "-javaagent:" + norm_classpath(str(agent_jar)) + _LF
        except Exception as exc:  # noqa: BLE001
            prep_warnings.append(f"stubs: {type(exc).__name__}: {exc}")
    if cp_file:
        extra = Path(cp_file).read_text(encoding="utf-8")
        cp = cp + (sep if cp and not cp.endswith(sep) else "") + extra.strip()
    classpath = sep.join([str(work_dir), cp]) if cp else str(work_dir)
    classpath = norm_classpath(classpath)

    # 提取目标 Native 动态库并挂载 -Djava.library.path
    try:
        from . import native_scan
        natives_dir = work_dir / "natives"
        for cp_part in classpath.split(sep):
            cp_p = Path(cp_part.strip())
            if cp_p.is_file() and cp_p.suffix.lower() == ".jar":
                native_scan.extract_libs(cp_p, natives_dir)
        if any(natives_dir.glob("*")):
            native_jvm_arg = "-Djava.library.path=" + norm_classpath(str(natives_dir)) + _LF
    except Exception as exc:  # noqa: BLE001
        prep_warnings.append(f"natives: {type(exc).__name__}: {exc}")

    for warning in prep_warnings:
        print(f"WARNING  : replay prep: {warning}")

    argsfile = work_dir / "java_args.txt"
    argsfile.write_text(
        agent_jvm_arg
        + native_jvm_arg
        + "-Xverify:none" + _LF
        + '-cp "' + classpath.replace('"', _BS + '"') + '"' + _LF
        + "PoolDriver" + _LF
        + '"' + spec_path.resolve().as_posix() + '"' + _LF
        + '"' + out_tsv.resolve().as_posix() + '"' + _LF,
        encoding="utf-8")
    log_path = work_dir / "driver.log"
    out_tsv.parent.mkdir(parents=True, exist_ok=True)
    # stdout 直落盘：真实样本实战教训，管道缓冲+大输出会假死假象
    # 超时终止整个进程树（run_replay），部分输出保留
    with open(out_tsv, "wb") as fo, open(log_path, "wb") as fe:
        cp_res = run_replay([java, "@" + str(argsfile)], timeout=timeout,
                            stdout=fo, stderr=fe)
        rc = cp_res.returncode
        timed_out = getattr(cp_res, "timed_out", False)

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
        "harvest": out_tsv, "warnings": prep_warnings,
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


def apply(src_dir: Path, harvest_path: Path | None, out_dir: Path,
          from_frida: Path | None = None) -> dict:
    """回填明文进源码副本（out_dir），替换 + verify + 失败归因。

    输出目录会被整体重建，所以先拒绝任何会吃掉输入的写法：`-o src`、
    `-o ..`、`-o .`（CWD）以及把输出放进 src 里面。没有这层护栏时
    `pool apply -i src -o src` 会先删掉源码树再复制，源码不可恢复。
    """
    src_p = Path(src_dir).resolve()
    out_p = Path(out_dir).resolve()
    if out_p == src_p or out_p in src_p.parents or out_p == Path.cwd().resolve():
        raise ValueError(
            f"refusing to write into the source tree: output {out_p} is the "
            f"input directory, its parent, or the current directory; pass a "
            f"fresh directory such as {src_p.parent / (src_p.name + '_pool')}")
    if src_p in out_p.parents:
        raise ValueError(
            f"refusing to write inside the source tree: output {out_p} is "
            f"under input {src_p}")

    plain: dict[tuple, str] = {}
    fail_lines: list[str] = []
    if harvest_path and Path(harvest_path).is_file():
        for line in Path(harvest_path).read_text(encoding="utf-8",
                                           errors="replace").splitlines():
            q = line.split(_TAB)
            if q and q[0] == "R" and len(q) >= 6:
                plain[(q[1], q[2], int(q[3]), int(q[4]))] = \
                    base64.b64decode(q[5]).decode("utf-8", errors="replace")
            elif q and q[0] == "E" and len(q) >= 6:
                fail_lines.append("FAIL" + _TAB + q[1] + _TAB + q[2] + _TAB + q[5])

    if from_frida and Path(from_frida).is_file():
        for line in Path(from_frida).read_text(encoding="utf-8",
                                               errors="replace").splitlines():
            q = line.strip().split(_TAB)
            if q and q[0] == "R" and len(q) >= 6:
                try:
                    plain[(q[1], q[2], int(q[3]), int(q[4]))] = \
                        base64.b64decode(q[5]).decode("utf-8", errors="replace")
                except Exception:
                    pass
            elif len(q) >= 5 and q[0] not in ("OK", "R", "E"):
                try:
                    plain[(q[0], q[1], int(q[2]), int(q[3]))] = q[4]
                except Exception:
                    pass

    if out_dir.exists():
        shutil.rmtree(out_dir)
    shutil.copytree(src_dir, out_dir)

    # 回填侧访问器识别与 scan 同口径（含重载分派），保证调用点对得上
    parsed = []
    for f in sorted(out_dir.rglob("*.java")):
        txt = _read(f)
        parsed.append((f, _fqcn_of(f, txt), txt))
    acc, _sig_bad = _collect_accessors(parsed)
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
        own_acc = acc.get(own_fq, {})
        # 词法 mask：注释/字符串里的同形调用点不是真调用，跳过
        mask = code_mask(txt)

        def repl_q(m: "re.Match") -> str:
            if not mask[m.start()]:
                return m.group(0)
            cls_raw, meth = m.group(1), m.group(2)
            fq = _resolve_fq(cls_raw, acc, simple, ambiguous)
            if fq is None:
                return m.group(0)
            if _overload_ok(acc, fq, meth, m.group(3), m.group(4)) != "ok":
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
            if not mask_b[m.start()]:
                return m.group(0)
            meth = m.group(1)
            if meth not in own_acc:
                return m.group(0)
            if _overload_ok(acc, own_fq, meth,
                            m.group(2), m.group(3)) != "ok":
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
        if own_acc:
            # _CALL_Q 的替换会改变长度偏移，bare 正则须对新文本重算 mask
            mask_b = code_mask(txt)
            txt = _CALL_BARE.sub(repl_b, txt)
        if txt != orig:
            _write(f, txt)

    # verify：回填后的树里，可解站点的调用形态残留必须为 0
    # （verify 与替换同口径：只看代码区，注释/字符串里的同形不算）
    residual = 0
    residual_samples: list[str] = []
    for f, own_fq in [(f, fq) for f, fq, _ in parsed]:
        txt = _read(f)
        own_acc = acc.get(own_fq, {})
        vmask = code_mask(txt)
        for m in _CALL_Q.finditer(txt):
            if not vmask[m.start()]:
                continue
            cls_raw, meth = m.group(1), m.group(2)
            fq = _resolve_fq(cls_raw, acc, simple, ambiguous)
            if fq is None:
                continue
            if _overload_ok(acc, fq, meth, m.group(3), m.group(4)) != "ok":
                continue
            key = (fq, meth, norm_int(m.group(3)), norm_int(m.group(4)))
            if key in plain:
                residual += 1
                if len(residual_samples) < 5:
                    residual_samples.append(f.name)
        if own_acc:
            for m in _CALL_BARE.finditer(txt):
                if not vmask[m.start()]:
                    continue
                meth = m.group(1)
                if meth not in own_acc:
                    continue
                if _overload_ok(acc, own_fq, meth,
                                m.group(2), m.group(3)) != "ok":
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
