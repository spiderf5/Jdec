"""recover 子命令：自洽重放，解出 indy 字符串/常量加密。

方法论（EdNaven 实证，见 references/string-encryption.md）：
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

import re
import subprocess
from pathlib import Path
import zipfile

from . import bsm as BM

DRIVER_JAVA = (Path(__file__).parent / "recover_driver_template.java").read_text(encoding="utf-8")


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
    with zipfile.ZipFile(jar) as zf:
        seen = set()
        for info in zf.infolist():
            if not info.filename.endswith(".class"):
                continue
            try:
                cf = BM.CF.parse(zf.read(info))
            except BM.CF.ClassFormatError:
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

    # 形态分型（EdNaven 2026-10-04 实证）：
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
                spec.append(f"B\t{e.index}\t?\t?\t?\t0")
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
    return spec_path, n_sites, n_skip


def java_escape(s: str) -> str:
    """把明文转成 Java 字符串字面量的内容（不含首尾引号）。

    反斜杠一律用 chr(92) 构造——实证某些传输链路会把手写的反斜杠
    改写成斜杠，chr() 拼接免疫。
    """
    bs = chr(92)
    out = []
    for ch in s:
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
        else:
            out.append(ch)
    return "".join(out)


def rewrite_sources(src_dir: Path, tsv_path: Path) -> dict:
    """把 recovered.tsv 的解密明文回填进反编译源码（CFR/其他引擎的 .java）。

    匹配源码里 indy 被还原成的 BSM 调用形态:
        Cls.method("siteName", "cipher", seed)
    匹配键 = (cipher, seed)——driver 的 OK 行已携带这两个静态参数。
    适用条件: BSM 静态参数为 (String cipher, 整数 seed) 的字符串解密家族；
    REF 型（成员引用）与其他参数布局不在范围内。

    正则用零反斜杠的字符类写法（[.] [(] 等）——传输链路会改写反斜杠，
    字符类写法免疫。返回统计 dict。
    """
    plain_map: dict = {}
    conflicts = 0
    for line in tsv_path.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) < 6 or parts[0] != "OK":
            continue
        cipher, seed, plain = parts[3], parts[4], parts[-1]
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

    # 空白类含 CR/LF：CFR 之外的引擎（vineflower/procyon）会把长参数折行
    WS = "[ \t\r\n]*"
    pat = re.compile(
        "[A-Za-z0-9_]+[.][A-Za-z0-9_]+[(]" + WS
        + '"([A-Za-z0-9+/=]{1,60})"' + WS + "," + WS
        + '"([A-Za-z0-9+/=]{1,8192})"' + WS + "," + WS
        + "(-?[0-9]+)" + WS + "[)]")

    n_files = replaced = missed = residual = 0
    for path in sorted(src_dir.rglob("*.java")):
        txt = path.read_text(encoding="utf-8", errors="ignore")
        if not pat.search(txt):
            continue
        n_files += 1

        def sub(m: "re.Match") -> str:
            nonlocal replaced, missed
            key = (m.group(2), m.group(3))
            if key in plain_map:
                replaced += 1
                return '"' + java_escape(plain_map[key]) + '"'
            missed += 1
            return m.group(0)

        new = pat.sub(sub, txt)
        residual += sum(1 for m in pat.finditer(new)
                        if (m.group(2), m.group(3)) not in plain_map)
        if new != txt:
            path.write_text(new, encoding="utf-8")
    return {"files": n_files, "replaced": replaced, "missed": missed,
            "residual": residual, "conflicts": conflicts,
            "map_size": len(plain_map)}


def recover(jar: Path, out_dir: Path, cp: str = "", java: str = "java",
            limit: int = 0, stop_on_error: bool = False,
            cp_file: Path | None = None, timeout: int = 1800) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    if cp_file:
        extra = Path(cp_file).read_text(encoding="utf-8")
        cp = cp + (";" if cp and not cp.endswith(";") else "") + extra.strip()
    spec_path, n_sites, n_skip = build_spec(jar, out_dir, limit=limit)
    print(f"spec      : {n_sites} sites ({n_skip} skipped: args not statically "
          f"recoverable) -> {spec_path.name}")

    src = out_dir / "RecoverDriver.java"
    src.write_text(DRIVER_JAVA, encoding="utf-8")
    r = subprocess.run(["javac", "-d", str(out_dir), str(src)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("javac failed:\n" + str(r.stderr or r.stdout or "")[-2000:])
        return 1

    sep = ";" if __import__("os").name == "nt" else ":"
    classpath = sep.join([str(out_dir), cp, str(jar)]) if cp else \
        sep.join([str(out_dir), str(jar)])
    # java @argfile 把反斜杠当转义符；MSYS 风格路径 java 也不认——
    # 全部归一成 Windows 正斜杠形式（/d/x -> D:/x）
    classpath = classpath.replace("\\", "/")
    classpath = re.sub(r"(^|;)/(\w)/", r"\1\2:/", classpath)
    # Windows 命令行 ~32K 上限装不下几百个库的 classpath，用 @argfile
    argsfile = out_dir / "java_args.txt"
    cp_line = classpath.replace('"', '\\"')
    head = "-XX:+ShowMessageBoxOnError\n" if stop_on_error else ""
    argsfile.write_text(
        head + f'-Xverify:none\n-cp "{cp_line}"\nRecoverDriver\n"{spec_path.as_posix()}"\n',
        encoding="utf-8")
    try:
        r = subprocess.run([java, "@" + str(argsfile)], capture_output=True,
                           text=True, errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired as e:
        # 每站点真解密的代价可能远超默认 30 分钟（6516 站点实测 ~35min）。
        # 超时不扔掉已产出：kill 后把部分输出照常收割，调用方按需加大 --timeout。
        print(f"WARNING  : driver killed at {timeout}s timeout "
              f"(partial output kept; rerun with --timeout N)")
        r = subprocess.CompletedProcess(e.cmd, 1,
                                        stdout=e.stdout or "",
                                        stderr=e.stderr or "")
        if isinstance(r.stdout, bytes):
            r.stdout = r.stdout.decode("utf-8", "replace")
        if isinstance(r.stderr, bytes):
            r.stderr = r.stderr.decode("utf-8", "replace")
    (out_dir / "driver.log").write_text(r.stderr[-4000:], encoding="utf-8")

    ok, fail, skip, ref = 0, 0, 0, 0
    values = []
    for line in r.stdout.splitlines():
        q = line.split("\t", 4)
        if q[0] == "OK":
            ok += 1
            values.append(line)
        elif q[0] == "REF":
            ref += 1
        elif q[0] == "FAIL":
            fail += 1
        elif q[0] == "SKIP":
            skip += 1
    (out_dir / "recovered.tsv").write_text(r.stdout, encoding="utf-8")
    # 文本值去重：剔除数组/对象 toString（"[Lxxx;@hash"、"xxx@hash"）
    uniq = set()
    for v in values:
        parts = v.split("\t")
        if len(parts) < 4:
            continue
        s = parts[-1]
        if s.startswith("[L") or re.search(r"@[0-9a-f]{4,}$", s):
            continue
        uniq.add(s)
    print(f"recovered : {ok} str-sites ({len(uniq)} unique plaintexts), "
          f"{ref} ref-sites resolved, {fail} failed, {skip} skipped")
    print(f"output    : {out_dir / 'recovered.tsv'}")
    tail = r.stderr.strip().splitlines()[-1] if r.stderr.strip() else ""
    if tail:
        print(tail)
    return 0 if ok else 1
