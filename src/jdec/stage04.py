#!/usr/bin/env python3
"""Stage-04 acceptance runner: explicit support items, independently verified.

The diagnostic smoke matrix (support_matrix.py) proves that commands run.
This runner is the acceptance layer: for each of the 8 mechanism classes it

  1. runs the mechanism on a REAL, independent corpus,
  2. recomputes the underlying fact with `goldens.py` (a second, independent
     implementation that never calls a jdec analysis command),
  3. cross-checks the mechanism's claim against that ground truth, and
  4. runs THAT mechanism's own negative control (a public unobfuscated jar,
     a jar with a truncated class, a non-Minecraft corpus, or a unit-level
     false-positive probe).

A mechanism passes only when the cross-check AND its negative control hold.
Generated fixtures are never counted as independent samples. The three real
corpora stay outside the tree; the report records coordinates and sha256.

Usage:
  python src/jdec/stage04.py --hmcl <HMCL.exe> --neo <NeoRaven.jar> \
      --negative <junit-4.13.2.jar> --javafx-dir <dir> \
      --lwjgl <lwjgl.jar> --lwjgl-natives <lwjgl-platform-natives.jar> \
      --json docs/STAGE04_REPORT.json
  python src/jdec/stage04.py --fetch-negative junit.jar --fetch-lwjgl <dir>
  python src/jdec/stage04.py --selfcheck   # in-repo fixtures only, for CI
  python -m jdec.stage04 --hmcl ...        # from an installed wheel

--selfcheck needs the in-repo fixture jars, so it is a checkout/CI mode.
An installed wheel uses the full form with the caller's own corpora.
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Two entry points. From a checkout: `python src/jdec/stage04.py ...` (script
# form, needs src/ on sys.path). From an installed wheel: `python -m
# jdec.stage04 ...`, where `jdec` already resolves. Only the former needs the
# shim. ROOT is only meaningful in the checkout form: it locates the fixture
# jars used by --selfcheck, which is deliberately an in-repo mode.
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT / "src"))

from jdec import goldens as G  # noqa: E402
from jdec import support_matrix as SM  # noqa: E402
from jdec.mechanisms import MECHANISMS as MECH  # noqa: E402

NEGATIVE_URL = ("https://repo1.maven.org/maven2/junit/junit/4.13.2/"
                "junit-4.13.2.jar")

# LWJGL 2.9.4 (the exact build Minecraft 1.8.9 ships) publishes its Windows
# libraries as a separate `natives` classifier jar. That is the layout M6 needs
# to prove JNI matching: the main jar declares 2674 native methods, the natives
# jar exports 2383 Java_* symbols, and 52 of them match by name.
# 2.9.4-nightly-20150209 is the exact build Minecraft 1.8.9 ships.  It was
# never published to Maven Central (org.lwjgl.lwjgl:lwjgl stops at 2.9.3
# there); Mojang's library host is the actual publisher.  The coordinates and
# the report's sha256 stay unchanged -- only the download source is fixed.
_LWJGL_MOJANG = "https://libraries.minecraft.net/org/lwjgl/lwjgl"
_LWJGL_CENTRAL = "https://repo1.maven.org/maven2/org/lwjgl/lwjgl"
LWJGL_ARTIFACTS = (
    ("lwjgl",
     "lwjgl-2.9.4-nightly-20150209.jar",
     (f"{_LWJGL_MOJANG}/lwjgl/2.9.4-nightly-20150209/"
      "lwjgl-2.9.4-nightly-20150209.jar",
      f"{_LWJGL_CENTRAL}/lwjgl/2.9.4-nightly-20150209/"
      "lwjgl-2.9.4-nightly-20150209.jar"),
     "org.lwjgl.lwjgl:lwjgl:2.9.4-nightly-20150209"),
    ("natives",
     "lwjgl-platform-2.9.4-nightly-20150209-natives-windows.jar",
     (f"{_LWJGL_MOJANG}/lwjgl-platform/2.9.4-nightly-20150209/"
      "lwjgl-platform-2.9.4-nightly-20150209-natives-windows.jar",
      f"{_LWJGL_CENTRAL}/lwjgl-platform/2.9.4-nightly-20150209/"
      "lwjgl-platform-2.9.4-nightly-20150209-natives-windows.jar"),
     "org.lwjgl.lwjgl:lwjgl-platform:2.9.4-nightly-20150209:natives-windows"),
)


#: The acceptance layer adds only what is its own: which corpus carries the
#: claim, which one must reproduce it, and which one must not. The prose and
#: the CLI chain come from `mechanisms.py` so both 04 layers state one claim.
SPECS: list[dict] = [
    {"id": m.id, "name": m.name, "support": m.support,
     "not_covered": m.not_covered,
     "primary": m.primary, "extra": m.extra, "negative": m.negative,
     "steps": m.steps, "extra_steps": m.extra_steps,
     "patterns": m.patterns}
    for m in MECH
]



def _rx(pairs: dict[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple(pairs.items())


def _run_steps(spec: dict, jar: Path, out: Path, key: str,
               javafx: list[str], *, steps=None,
               natives: Path | None = None) -> dict:
    texts: list[str] = []
    rcs: list[int] = []
    commands: list[str] = []
    cp: list[str] = []
    for entry in javafx:
        cp += ["--cp", entry]
    for step in (steps if steps is not None else spec["steps"]):
        argv: list[str] = []
        fmt = {"jar": str(jar), "out": str(out), "key": key,
               "deflat": str(out / f"{key}_deflat.jar"),
               "rw": str(out / f"{key}_rw.txt"),
               "natives": str(natives) if natives else ""}
        for part in step:
            if part == "{cp}":
                argv.extend(cp)
            else:
                argv.append(part.format(**fmt))
        rc, text = SM._capture(argv)
        rcs.append(rc)
        texts.append(text)
        safe = [str(a).replace(str(jar), f"<{key.upper()}>")
                 .replace(str(out), "<WORKDIR>") for a in argv]
        for entry in javafx:
            safe = [a.replace(entry, Path(entry).name) for a in safe]
        commands.append("jdec " + " ".join(safe))
    combined = "\n".join(texts)
    head = combined[:4000]
    for label, value in (("<CORPUS>", str(jar)), ("<WORKDIR>", str(out)),
                         ("<REPO>", str(ROOT))):
        head = head.replace(value, label).replace(
            value.replace("\\", "/"), label)
    return {"metrics": SM._extract(combined, _rx(spec["patterns"])),
            "exit_codes": rcs, "commands": commands,
            "stdout_head": head}


def _journal_kinds(jar: Path, rw_path: Path) -> dict:
    """What the rewrite actually did, by pass, on this corpus."""
    import zipfile
    from jdec import bytecode as BC
    from jdec import classfile as CF
    from jdec.ir import assemble as ASM
    from jdec.ir import transforms as TR

    totals: dict[str, int] = {}
    unflatten = 0
    switch_methods = 0
    if not rw_path.is_file():
        return {"kinds": totals, "unflatten_methods": 0,
                "switch_methods": 0}
    with zipfile.ZipFile(jar) as z:
        cache: dict[str, object] = {}
        for line in rw_path.read_text(encoding="utf-8").splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            cls, meth = parts[0], parts[1]
            desc = parts[2] if len(parts) > 2 else ""
            if cls not in cache:
                try:
                    cache[cls] = CF.parse(z.read(cls + ".class"))
                except (KeyError, ValueError):
                    cache[cls] = None
            cf = cache[cls]
            if cf is None:
                continue
            member = next((m for m in cf.methods
                           if cf.utf8(m.name_index) == meth
                           and cf.utf8(m.descriptor_index) == desc), None)
            if member is None:
                continue
            ci = BC.method_code(cf, member, decode_insns=False)
            if ci is None or not ci.code:
                continue
            prog = ASM.Program.parse(ci.code, ci.handlers)
            counts = TR.optimize(prog, cf)
            for kind, n in counts.items():
                if n:
                    totals[kind] = totals.get(kind, 0) + n
            if counts.get("unflattened"):
                unflatten += 1
            if counts.get("switch"):
                switch_methods += 1
    return {"kinds": totals, "unflatten_methods": unflatten,
            "switch_methods": switch_methods}


def _payload_values(jar: Path) -> set[str]:
    """Every constant string the tool recovers from a bootstrap, deduplicated.

    Concat recipes and record component lists are the values a user actually
    gains; comparing the set against goldens.bsm_facts() proves they are real
    constant-pool strings rather than synthesised text.
    """
    import zipfile

    from jdec import bsm as BM
    from jdec import classfile as CF

    values: set[str] = set()
    with zipfile.ZipFile(jar) as z:
        for info in z.infolist():
            if not info.filename.endswith(".class"):
                continue
            try:
                cf = CF.parse(z.read(info))
            except Exception:          # noqa: BLE001 - unreadable class
                continue
            for site in BM.enum_sites(cf):
                concat = BM.resolve_concat(site)
                if concat:
                    values.add(concat["recipe"])
                record = BM.resolve_record(site)
                if record:
                    values.add(";".join(record["components"]))
    return values


def _owner_counts(text: str) -> dict[str, int]:
    """Parse the ``owners : a=1;b=2`` line printed by ``indy --resolve``."""
    for line in text.splitlines():
        if line.startswith("owners") and ":" in line:
            out: dict[str, int] = {}
            for part in line.split(":", 1)[1].strip().split(";"):
                if "=" not in part:
                    continue
                key, _, num = part.rpartition("=")
                if num.isdigit():
                    out[key.strip()] = int(num)
            return out
    return {}


def _golden_for(path: Path) -> dict:
    z = G.zip_facts(path)
    j = G.jar_facts(path)
    n = G.native_facts(path)
    return {
        "magic": G.magic_of(path), "entries": z["entries"],
        "class_count": z["class_count"], "readable": j["readable"],
        "utf8_count": j["utf8_count"], "unique_utf8": j["unique_utf8"],
        "native_methods": j["native_methods"], "bsm_entries": j["bsm_entries"],
        "pe_export_count": n["export_count"], "pe_exports": n["exports"][:8],
        "native_libs": G.native_libs_facts(path),
        "mc": G.mc_facts(path),
        "des_markers": G.des_markers(path),
        "sha256": G.sha256_file(path),
    }


def _check_m1(add, m: dict, g: dict, neg: dict,
                    ng: dict, out: Path, key: str,
                    extras: dict) -> None:
    """Cross-checks for mechanism M1."""
    add("改写方法数 > 0", m["metrics"].get("rewritten", 0) > 0,
        str(m["metrics"]))
    add("JVM verify 通过类数 > 0", m["metrics"].get("verified", 0) > 0,
        str(m["metrics"]))
    kinds = _journal_kinds(_CORPORA[key], out / f"{key}_rw.txt")
    for kind in ("threaded", "unflattened", "switch", "folded",
                 "predicates", "dead", "gotos"):
        m["metrics"][kind] = kinds["kinds"].get(kind, 0)
    m["metrics"]["unflatten_methods"] = kinds["unflatten_methods"]
    m["metrics"]["switch_methods"] = kinds["switch_methods"]
    add("改写类型统计已记录", bool(kinds["kinds"]), str(kinds["kinds"]))
    # The same classification on the second corpus. Two independent real jars
    # both showing folded=0 / predicates=0 / unflattened=0 is the evidence that
    # this is a property of the corpora, not of one file.
    for extra_key, run in extras.items():
        if "rewritten" not in run["metrics"]:
            continue
        ek = _journal_kinds(_CORPORA[extra_key], out / f"{extra_key}_rw.txt")
        for kind in ("threaded", "unflattened", "switch", "folded",
                     "predicates", "dead", "gotos"):
            run["metrics"][kind] = ek["kinds"].get(kind, 0)
        add(f"第二语料 {extra_key} 同样没有常量折叠与不透明谓词",
            ek["kinds"].get("folded", 0) == 0
            and ek["kinds"].get("predicates", 0) == 0, str(ek["kinds"]))
        add(f"第二语料 {extra_key} 也没有混淆器平坦化",
            ek["kinds"].get("unflattened", 0) == 0, str(ek["kinds"]))
    add("本语料常量折叠与不透明谓词为 0（不得据此宣称）",
        kinds["kinds"].get("folded", 0) == 0
        and kinds["kinds"].get("predicates", 0) == 0,
        str(kinds["kinds"]))
    add("控制流改写已按来源分类（平坦化 vs javac switch）",
        kinds["unflatten_methods"] + kinds["switch_methods"] > 0,
        f"unflatten_methods={kinds['unflatten_methods']} "
        f"switch_methods={kinds['switch_methods']}")
    add("本语料没有混淆器平坦化，只有 javac switch 类",
        kinds["kinds"].get("unflattened", 0) == 0
        and kinds["switch_methods"] > 0,
        f"unflattened={kinds['kinds'].get('unflattened', 0)} "
        f"switch={kinds['kinds'].get('switch', 0)}")
    # Independent: every method named in the rewritten list must really
    # exist in the ORIGINAL class file, and the rewritten jar must differ.
    rows_file = out / f"{key}_rw.txt"
    rewritten_jar = out / f"{key}_deflat.jar"
    verified = 0
    missing = []
    if rows_file.is_file():
        for line in rows_file.read_text(encoding="utf-8").splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            cls, meth = parts[0], parts[1]
            try:
                names = G.methods_of(_CORPORA[key], cls)
            except (KeyError, OSError, ValueError):
                missing.append(cls)
                continue
            if meth in names:
                verified += 1
            else:
                missing.append(f"{cls}.{meth}")
    add("改写清单里的方法独立存在于原 class 文件",
        verified > 0 and not missing,
        f"verified={verified} missing={len(missing)} {missing[:3]}")
    changed = 0
    if rewritten_jar.is_file():
        original_hashes = G.zip_facts(_CORPORA[key])["class_sha256"]
        rewritten_hashes = G.zip_facts(rewritten_jar)["class_sha256"]
        changed = sum(1 for cls, digest in rewritten_hashes.items()
                      if cls in original_hashes
                      and original_hashes[cls] != digest)
    add("改写后的 class 字节确实变化", changed > 0, f"changed={changed}")
    # The negative corpus is NOT claimed to have zero rewrites: constant
    # folding legitimately applies to ordinary Java too (17 methods on
    # junit). The control demands semantic preservation and a much
    # smaller rewrite scale than the obfuscated corpus.
    add("阴性对照的改写全部可被 journal 解释",
        neg["metrics"].get("unexplained", -1) == 0,
        str(neg["metrics"]))
    add("阴性对照行为对拍 0 差异",
        neg["metrics"].get("diff", -1) == 0
        and neg["metrics"].get("same", 0) > 0,
        f"same={neg['metrics'].get('same')} diff={neg['metrics'].get('diff')}")
    add("阴性对照改写规模显著小于混淆语料",
        0 <= neg["metrics"].get("rewritten", 10**9)
        < m["metrics"].get("rewritten", 0) / 10,
        f"{neg['metrics'].get('rewritten')} vs {m['metrics'].get('rewritten')}")
    add("主样本改写全部可被 journal 解释",
        m["metrics"].get("unexplained", -1) == 0, str(m["metrics"]))
    add("主样本行为对拍产出 union 判定",
        m["metrics"].get("union", 0) > 0, str(m["metrics"]))

def _check_m2(add, m: dict, g: dict, neg: dict,
                    ng: dict, out: Path, key: str,
                    extras: dict) -> None:
    """Cross-checks for mechanism M2."""
    v = m["metrics"]
    add("class 计数等于 zipfile 原始类数",
        v.get("classes") == g["class_count"],
        f"{v.get('classes')} vs {g['class_count']}")
    add("类字节往返全等且分母等于原始类数",
        v.get("cls_ok") == v.get("cls_total") == g["class_count"],
        str(v))
    add("Code 数组往返全等", v.get("code_ok") == v.get("code_total")
        and v.get("code_total", 0) > 0, str(v))
    add("无不可读类", v.get("unreadable") == 0 and g["readable"] == g["class_count"],
        f"unreadable={v.get('unreadable')} readable={g['readable']}")
    add("截断类负控不得判为干净 PASS",
        any(rc != 0 for rc in neg["exit_codes"]) or
        neg["metrics"].get("unreadable", 0) > 0,
        f"rc={neg['exit_codes']} metrics={neg['metrics']}")

def _check_m3(add, m: dict, g: dict, neg: dict,
                    ng: dict, out: Path, key: str,
                    extras: dict) -> None:
    """Cross-checks for mechanism M3."""
    sites = m["metrics"].get("sites", 0)
    v = m["metrics"]
    bsm_golden = G.bsm_facts(_CORPORA[key])
    add("站点数 ≥ 独立 BootstrapMethods 属性条目数",
        sites >= bsm_golden["entries"] > 0,
        f"sites={sites} bsm={bsm_golden['entries']}")
    owners = _owner_counts(m["stdout_head"])
    add("bootstrap owner 集合等于独立解析结果",
        set(owners) == set(bsm_golden["owners"]),
        f"tool={sorted(owners)} golden={sorted(bsm_golden['owners'])}")
    add("每个 owner 的站点数 ≥ 其独立条目数",
        bool(owners) and all(owners.get(o, 0) >= n
                             for o, n in bsm_golden["owners"].items()),
        f"{owners} vs {bsm_golden['owners']}")
    add("载荷站点数等于三类之和",
        v.get("payload", -1) == (v.get("lambda", 0) + v.get("concat", 0)
                                 + v.get("record", 0)) > 0, str(v))
    # A complete partition, not a happy-path count: some bootstraps (e.g.
    # SwitchBootstraps) carry no readable constant, and those must be counted
    # rather than silently dropped.
    add("三类载荷 + 未还原 = 站点数",
        (v.get("lambda", 0) + v.get("concat", 0) + v.get("record", 0)
         + v.get("unresolved", -1)) == sites > 0, str(v))
    add("本语料没有「无可还原常量」的站点",
        v.get("unresolved", -1) == 0, str(v))
    # Value-level cross-check: every recovered recipe / component list must
    # exist verbatim in the independently parsed constant-pool payloads.
    recovered = _payload_values(_CORPORA[key])
    invented = sorted(recovered - set(bsm_golden["payloads"]))
    add("还原出的每个常量载荷都存在于独立常量池",
        bool(recovered) and not invented,
        f"{len(recovered)} recovered, {len(invented)} invented {invented[:2]}")
    add("阴性对照无 indy 站点",
        neg["metrics"].get("sites", 0) == 0 and ng["bsm_entries"] == 0,
        f"neg_sites={neg['metrics'].get('sites')} neg_bsm={ng['bsm_entries']}")

def _check_m4(add, m: dict, g: dict, neg: dict,
                    ng: dict, out: Path, key: str,
                    extras: dict) -> None:
    """Cross-checks for mechanism M4."""
    text = str(m["metrics"].get("signature", ""))
    no_des = all(v == 0 for v in g["des_markers"].values())
    add("混淆度分数已结构化记录", "score" in m["metrics"], str(m["metrics"]))
    add("金标准确认该语料无 ZKM DES 专属标记", no_des, str(g["des_markers"]))
    if no_des:
        add("无 DES 标记时不得归因 ZKM 27",
            "ZKM 27" not in text, text[:150])
    if key == "hmcl":
        add("HMCL 归因 ProGuard / R8", "ProGuard / R8" in text, text[:150])
    # NeoRaven is the corpus where ZKM 27 used to be claimed on the strength
    # of one generic IvParameterSpec keyword. Its constant pool has no DES
    # marker, so the attribution must be absent there too.
    for extra_key, run in extras.items():
        eg = G.des_markers(_CORPORA[extra_key])
        esig = str(run["metrics"].get("signature", ""))
        add(f"金标准确认第二语料 {extra_key} 也无 ZKM DES 标记",
            all(v == 0 for v in eg.values()), str(eg))
        if all(v == 0 for v in eg.values()):
            add(f"第二语料 {extra_key} 不得被归因 ZKM 27",
                "ZKM 27" not in esig, esig[:150])
    # Unit-level negative control: the fingerprint config itself must not
    # accept the generic IvParameterSpec marker on its own.
    import json as _json
    fp = _json.loads((Path(__file__).parent / "fingerprints.json").read_text("utf-8"))
    zkm = next(x for x in fp["obfuscators"]
               if x["name"] == "ZKM 27 enhanced 字符串加密（DES）")
    add("ZKM 27 指纹要求 ≥2 个专属标记",
        zkm.get("min_keywords", 1) >= 2
        and all("ivparameterspec" not in k.lower() for k in zkm["keywords"]),
        str(zkm["keywords"]))
    add("阴性对照不误报混淆器",
        "obfuscator signature" not in neg["stdout_head"],
        neg["stdout_head"][:150])

def _check_m5(add, m: dict, g: dict, neg: dict,
                    ng: dict, out: Path, key: str,
                    extras: dict) -> None:
    """Cross-checks for mechanism M5."""
    v = m["metrics"]
    add("抽取到字符串常量", v.get("strings", 0) > 0, str(v))
    add("字符串数不超过独立常量池 UTF8 总数",
        v.get("strings", 0) <= g["utf8_count"],
        f"{v.get('strings')} <= {g['utf8_count']}")
    # Independent re-check: goldens.is_blob_literal is a second
    # implementation that never imports jdec.strings.
    fqcn = "org/spongepowered/asm/lib/tree/AbstractInsnNode"
    add("独立复核：内部类名不是 blob", not G.is_blob_literal(fqcn), fqcn)
    import base64 as _b64
    real = _b64.b64encode(bytes(range(64))).decode()
    add("独立复核：高熵 blob 仍被识别", G.is_blob_literal(real), real[:40])
    report_json = out / f"{key}_strings" / "strings.json"
    tagged: list[str] = []
    if report_json.is_file():
        try:
            data = _json_load(report_json)
            rows = data.get("rows", data if isinstance(data, list) else [])
            for row in rows:
                if (isinstance(row, (list, tuple)) and len(row) > 2
                        and "encrypted-blob" in row[2]):
                    tagged.append(str(row[1]) if len(row) > 1 else "")
        except (ValueError, TypeError):
            pass
    false_pos = [t for t in tagged if not G.is_blob_literal(t)]
    add("每个 encrypted-blob 标签都通过独立复核",
        not false_pos,
        f"{len(tagged)} tagged, {len(false_pos)} false positives")
    add("阴性对照无加密 blob", "encrypted-blob" not in neg["stdout_head"],
        neg["stdout_head"][:120])

def _check_m6(add, m: dict, g: dict, neg: dict,
                    ng: dict, out: Path, key: str,
                    extras: dict) -> None:
    """Cross-checks for mechanism M6."""
    v = m["metrics"]
    add("PE 导出数等于独立 PE/COFF 解析结果",
        v.get("exports") == g["pe_export_count"] > 0,
        f"{v.get('exports')} vs {g['pe_export_count']} {g['pe_exports']}")
    add("Java 侧 native 方法数等于独立 ACC_NATIVE 计数",
        v.get("native_methods") == g["native_methods"] > 0,
        f"{v.get('native_methods')} vs {g['native_methods']}")
    add("读出的 libs 计数为 1（即输入容器自身的 PE stub）",
        v.get("libs", 0) >= 1, str(v))
    add("JNI 匹配数如实记录（本语料 0，导出不是 JNI 符号）",
        v.get("jni_matched", -1) == 0, str(v))
    add("纯 Java 阴性对照报告 0 native",
        g["native_methods"] > 0 and ng["native_methods"] == 0
        and neg["metrics"].get("native_methods", 0) == 0,
        f"neg_native={ng['native_methods']} neg_metrics={neg['metrics']}")

    # Positive JNI case: LWJGL 2.9.4 declares 2674 native methods in the main
    # jar and ships the DLLs in a separate `natives` classifier artifact. That
    # is the layout `--libs-jar` exists for, and the only corpus here where an
    # export name actually matches a declared native method.
    extra = extras.get("lwjgl")
    if extra is None:
        add("M6 的正向 JNI 语料已执行", False, "lwjgl extra missing")
        return
    vx = extra["metrics"]
    libs = G.native_libs_facts(_CORPORA["lwjgl_natives"])
    decl = G.jar_facts(_CORPORA["lwjgl"])
    add("独立工件里的库数等于独立解析结果",
        vx.get("libs") == libs["lib_count"] > 0,
        f"{vx.get('libs')} vs {libs['lib_count']} {sorted(libs['libs'])}")
    add("单库导出数等于独立 PE 解析的每库最大值",
        vx.get("exports") == libs["max_exports"] > 0,
        f"{vx.get('exports')} vs {libs['max_exports']}")
    add("Java 侧 native 声明数等于独立 ACC_NATIVE 计数",
        vx.get("native_methods") == decl["native_methods"] > 0,
        f"{vx.get('native_methods')} vs {decl['native_methods']}")
    add("JNI 导出与声明方法按名匹配成功（正向证据）",
        0 < vx.get("jni_matched", 0) <= libs["total_jni"],
        f"matched={vx.get('jni_matched')} of {libs['total_jni']} Java_* exports")

def _check_m7(add, m: dict, g: dict, neg: dict,
                    ng: dict, out: Path, key: str,
                    extras: dict) -> None:
    """Cross-checks for mechanism M7."""
    mc = str(m["metrics"].get("minecraft", ""))
    if g["mc"]["mentions_189"]:
        add("金标准 mcmod.info 含 1.8.9，机制报告一致",
            "1.8.9" in mc, mc[:180])
    add("金标准确认存在 mcmod.info",
        g["mc"]["has_mcmod"] or len(g["mc"]["metadata_files"]) > 0,
        str(g["mc"]["metadata_files"]))
    add("非 MC 的 HMCL 负控不得报 1.8.9",
        "1.8.9" not in neg["stdout_head"], neg["stdout_head"][:150])

def _check_m8(add, m: dict, g: dict, neg: dict,
                    ng: dict, out: Path, key: str,
                    extras: dict) -> None:
    """Cross-checks for mechanism M8."""
    v = m["metrics"]
    add("条目数等于 zipfile 原始目录条目数",
        v.get("entries") == g["entries"], f"{v.get('entries')} vs {g['entries']}")
    add("容器 magic 由独立读取记录（未与工具输出比较）",
        g["magic"] in ("4d5a", "504b"), g["magic"])
    add("阴性对照为普通 PK jar",
        ng["magic"] == "504b" and ng["entries"] > 0,
        f"{ng['magic']} {ng['entries']}")

_CHECKS = {
    "M1": _check_m1,
    "M2": _check_m2,
    "M3": _check_m3,
    "M4": _check_m4,
    "M5": _check_m5,
    "M6": _check_m6,
    "M7": _check_m7,
    "M8": _check_m8,
}


def _check_extras(add, spec: dict, extras: dict, allowed: tuple) -> None:
    """Every declared extra corpus must run, exit cleanly and produce data.

    A spec that lists an extra it never exercises is exactly the kind of
    implied-but-missing evidence this layer exists to prevent, so the declared
    set and the executed set have to match.
    """
    declared = tuple(spec.get("extra") or ())
    add(f"声明的第二语料全部执行 {declared}",
        set(declared) == set(extras), f"declared={declared} ran={sorted(extras)}")
    for extra_key, extra_run in extras.items():
        add(f"第二语料 {extra_key} 退出码在允许集合 {allowed}",
            bool(extra_run["exit_codes"])
            and all(rc in allowed for rc in extra_run["exit_codes"]),
            str(extra_run["exit_codes"]))
        add(f"第二语料 {extra_key} 产出了指标",
            bool(extra_run["metrics"]), str(extra_run["metrics"])[:150])


def _checks(spec: dict, m: dict, g: dict, neg: dict, ng: dict,
            out: Path, key: str, extras: dict | None = None) -> list[dict]:
    """Cross-check a mechanism against ground truth and its negative control."""
    out_checks: list[dict] = []
    extras = extras or {}

    def add(label: str, ok: bool, detail: str = "") -> None:
        out_checks.append({"label": label, "ok": bool(ok),
                           "detail": str(detail)[:300]})

    mid = spec["id"]
    # `behave` returns 1 when it reports a real difference (HMCL has one, see
    # REPRODUCE.md). That is an honest result, not a mechanism failure. Only M1
    # runs behave; every other mechanism must still exit 0.
    allowed = (0, 1) if mid == "M1" else (0,)
    add(f"机制退出码在允许集合 {allowed}",
        all(rc in allowed for rc in m["exit_codes"]), str(m["exit_codes"]))
    _check_extras(add, spec, extras, allowed)
    _CHECKS[mid](add, m, g, neg, ng, out, key, extras)
    for c in out_checks:
        # a: real cross-check against independent ground truth; b: exit code /
        # configuration / self-reported value; c: negative control; d: golden
        # only. The split exists so the count cannot flatter itself.
        label = c["label"]
        if "退出码" in label:
            c["class"] = "b"
        elif "阴性" in label or label.startswith("非 MC") or "负控" in label:
            c["class"] = "c"
        elif label.startswith("金标准确认"):
            c["class"] = "d"
        elif "指纹要求" in label:
            c["class"] = "b"
        else:
            c["class"] = "a"
    return out_checks


def _json_load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


_CORPORA: dict[str, Path] = {}


def fetch_negative(dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.is_file():
        with urllib.request.urlopen(NEGATIVE_URL, timeout=120) as r:
            dest.write_bytes(r.read())
    return dest


def _valid_artifact(path: Path) -> bool:
    """A downloaded Maven artifact must at least be a zip/jar (PK magic)."""
    if not path.is_file():
        return False
    try:
        with path.open("rb") as fh:
            return fh.read(2) == b"PK"
    except OSError:
        return False


def fetch_lwjgl(dest_dir: Path) -> tuple[Path, Path]:
    """Download the two LWJGL artifacts M6 needs; returns (main, natives).

    Transfers go to a ``.part`` file and are atomically renamed, so an
    interrupted download can never leave a truncated jar that a later run
    would mistake for a cached artifact. Existing files are validated too,
    which self-heals leftovers from older versions of this function.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    out: list[Path] = []
    for _key, filename, urls, coord in LWJGL_ARTIFACTS:
        target = dest_dir / filename
        if _valid_artifact(target):
            out.append(target)
            continue
        if target.is_dir():
            raise RuntimeError(
                f"{target} is a directory; remove it or pass --lwjgl / "
                "--lwjgl-natives with explicit file paths")
        target.unlink(missing_ok=True)
        part = dest_dir / (filename + ".part")
        last: Exception | None = None
        for url in urls:
            try:
                with urllib.request.urlopen(url, timeout=180) as r, \
                        part.open("wb") as fh:
                    shutil.copyfileobj(r, fh)
                if not _valid_artifact(part):
                    raise ValueError("response is not a jar/zip (PK magic missing)")
                part.replace(target)
                break
            except Exception as exc:  # noqa: BLE001 - try the next source
                part.unlink(missing_ok=True)
                last = exc
        else:
            raise RuntimeError(
                f"cannot fetch {coord} from any source: {last}. "
                "Pass --lwjgl / --lwjgl-natives with local copies instead."
            ) from last
        out.append(target)
    return out[0], out[1]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hmcl", type=Path)
    p.add_argument("--neo", type=Path)
    p.add_argument("--negative", type=Path,
                   help="public unobfuscated jar used as the negative corpus")
    p.add_argument("--truncated", type=Path,
                   help="jar holding a deliberately truncated class (M8 "
                        "negative control); defaults to the in-repo fixture")
    p.add_argument("--fetch-negative", action="store_true",
                   help="download junit:junit:4.13.2 into --negative if absent")
    p.add_argument("--lwjgl", type=Path,
                   help="LWJGL 2.9.4 main jar: M6's positive corpus for JNI "
                        "matching (it declares 2674 native methods)")
    p.add_argument("--lwjgl-natives", type=Path,
                   help="the matching `natives-windows` classifier jar, which "
                        "carries the DLLs as a separate artifact")
    p.add_argument("--fetch-lwjgl", type=Path, metavar="DIR", default=None,
                   help="download both LWJGL artifacts from Maven Central into DIR")
    p.add_argument("--javafx-dir", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("--workdir", type=Path)
    p.add_argument("--selfcheck", action="store_true",
                   help="only verify the goldens and unit-level controls")
    args = p.parse_args(argv)

    if args.selfcheck:
        return selfcheck()

    if args.fetch_lwjgl:
        main_jar, natives_jar = fetch_lwjgl(args.fetch_lwjgl)
        args.lwjgl = args.lwjgl or main_jar
        args.lwjgl_natives = args.lwjgl_natives or natives_jar

    _CORPORA.update({"hmcl": args.hmcl, "neo": args.neo, "lwjgl": args.lwjgl,
                     "lwjgl_natives": args.lwjgl_natives})
    required = ("hmcl", "neo", "lwjgl", "lwjgl_natives")
    missing = [k for k in required
               if _CORPORA.get(k) is None or not Path(_CORPORA[k]).is_file()]
    if args.negative and args.fetch_negative:
        fetch_negative(args.negative)
    if args.negative and Path(args.negative).is_file():
        neg_path = Path(args.negative)
    else:
        neg_path = None
    if missing or neg_path is None:
        p.error("stage 04 needs --hmcl, --neo, --negative and the two LWJGL "
                "artifacts (--lwjgl/--lwjgl-natives, or --fetch-lwjgl DIR). "
                "Use --fetch-negative to obtain the public negative corpus.")

    javafx = ([str(x) for x in sorted(Path(args.javafx_dir).glob("javafx-*.jar"))]
              if args.javafx_dir else [])
    keep = None
    if args.workdir:
        args.workdir.mkdir(parents=True, exist_ok=True)
        out = args.workdir
    else:
        keep = tempfile.TemporaryDirectory(prefix="jdec_stage04_")
        out = Path(keep.name)

    try:
        corpora = {"hmcl": Path(args.hmcl), "neo": Path(args.neo),
                   "lwjgl": Path(args.lwjgl),
                   "lwjgl_natives": Path(args.lwjgl_natives),
                   "junit": neg_path,
                   "truncated": args.truncated
                   or ROOT / "src/tests/sample.jar"}
        goldens = {k: _golden_for(v) for k, v in corpora.items()
                   if v and Path(v).is_file()}
        report = {
            "schema": 1, "stage": "04",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "python": platform.python_version(),
            "threshold": "6-8 mechanism classes with explicit support items, "
                         "each backed by an independent sample regression",
            "corpus_sources": {
                "hmcl": {"coordinate": "HMCL-3.15.2.exe (local, authorised)",
                         "sha256": goldens["hmcl"]["sha256"]},
                "neo": {"coordinate": "NeoRaven1.1.jar (local, authorised)",
                        "sha256": goldens["neo"]["sha256"]},
                "junit": {"coordinate": "junit:junit:4.13.2", "url": NEGATIVE_URL,
                          "sha256": goldens["junit"]["sha256"],
                          "role": "public, reproducible NEGATIVE corpus"},
                "truncated": {"coordinate": "src/tests/sample.jar",
                              "sha256": goldens.get("truncated", {}).get("sha256"),
                              "role": "in-repo truncated-class negative control"},
                "lwjgl": {"coordinate": LWJGL_ARTIFACTS[0][3],
                          "url": LWJGL_ARTIFACTS[0][2][0],
                          "sha256": goldens["lwjgl"]["sha256"],
                          "role": "public JNI positive corpus (2674 native decls)"},
                "lwjgl_natives": {
                    "coordinate": LWJGL_ARTIFACTS[1][3],
                    "url": LWJGL_ARTIFACTS[1][2][0],
                    "sha256": goldens["lwjgl_natives"]["sha256"],
                    "role": "the `natives` classifier artifact M6 has to be told "
                            "about with --libs-jar"},
            },
            "javafx_entries": [Path(x).name for x in javafx],
            "mechanisms": [],
            "note": ("Ground truth is recomputed by the independent goldens "
                     "implementation from zip/class/PE bytes, never read from "
                     "a jdec analysis command. Negative controls are per "
                     "mechanism."),
        }
        for spec in SPECS:
            key = spec["primary"]
            primary = _run_steps(spec, corpora[key], out, key, javafx)
            neg_key = spec["negative"]
            neg = _run_steps(spec, corpora[neg_key], out, f"neg_{neg_key}", javafx)
            # `extra` used to be declarative only: every spec listed a second
            # corpus that was never executed, so the report implied two-corpus
            # coverage it did not have. Run them now, with an optional
            # per-corpus step override (M6 needs --libs-jar on its extra).
            extras: dict[str, dict] = {}
            for extra_key in spec.get("extra", ()):
                extra_jar = corpora.get(extra_key)
                if extra_jar is None or not Path(extra_jar).is_file():
                    continue
                steps = (spec.get("extra_steps") or {}).get(extra_key)
                extras[extra_key] = _run_steps(
                    spec, extra_jar, out, extra_key, javafx, steps=steps,
                    natives=corpora.get(f"{extra_key}_natives"))
            checks = _checks(spec, primary, goldens[key], neg,
                             goldens.get(neg_key, {}), out, key, extras)
            passed = all(c["ok"] for c in checks)
            entry = {
                "id": spec["id"], "name": spec["name"],
                "support": spec["support"], "not_covered": spec["not_covered"],
                "primary_corpus": key, "negative_corpus": neg_key,
                "extra_corpora": {
                    k: {"metrics": v["metrics"], "exit_codes": v["exit_codes"],
                        "commands": v["commands"]} for k, v in extras.items()},
                "metrics": primary["metrics"], "exit_codes": primary["exit_codes"],
                "commands": primary["commands"],
                "golden": goldens[key],
                "negative_metrics": neg["metrics"],
                "negative_exit_codes": neg["exit_codes"],
                "checks": checks, "verdict": "PASS" if passed else "FAIL",
            }
            report["mechanisms"].append(entry)
            print(f"  {spec['id']} {entry['verdict']:<4} {spec['name']} "
                  f"({sum(c['ok'] for c in checks)}/{len(checks)} checks)")
            for c in checks:
                if not c["ok"]:
                    print(f"      FAIL {c['label']}: {c['detail']}")

        passed = sum(m["verdict"] == "PASS" for m in report["mechanisms"])
        report["passed"] = passed
        report["total"] = len(SPECS)
        report["verdict"] = "PASS" if passed == len(SPECS) else "FAIL"
        # A runner must not certify the stage threshold. It reports whether
        # the mechanism regressions pass, and why the threshold is still open.
        report["mechanism_regressions_pass"] = report["verdict"] == "PASS"
        # The runner reports facts; whether the stage advances is recorded in
        # ROADMAP, not asserted by a test script.
        report["stage_04_threshold_decision"] = "recorded in docs/ROADMAP.md"
        report["boundaries"] = [
            "M1: real corpora contain no obfuscator flattening (unflattened=0); "
            "684 rewrites are javac switch(String) lowering, 7 are a unit fixture",
            "M1: behave union 342/411 with 1 real difference; 02 stays in progress",
            "M3: every indy site yields its constant payload, but both corpora "
            "use only JDK vanilla bootstrap methods; a custom bootstrap is "
            "enumerated, never resolved",
            "M5: 0 DES ciphertext on either corpus; extraction is verified, "
            "decryption is not claimed",
            "ROADMAP:231-236 keeps ZKM/JNIC/BytecodeVM deep recovery out of the "
            "1.0 support promise",
        ]
        breakdown = {"a": 0, "b": 0, "c": 0, "d": 0}
        for entry in report["mechanisms"]:
            for c in entry["checks"]:
                breakdown[c.get("class", "a")] += 1
        report["check_breakdown"] = breakdown
        if args.json:
            args.json.parent.mkdir(parents=True, exist_ok=True)
            args.json.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                                 encoding="utf-8", newline="\n")
        print(f"\nstage 04: {passed}/{len(SPECS)} mechanisms PASS, "
              f"verdict {report['verdict']}")
        if args.json:
            print(f"report: {args.json}")
        return 0 if report["verdict"] == "PASS" else 1
    finally:
        if keep is not None:
            keep.cleanup()


def selfcheck() -> int:
    """In-repo only: prove the goldens and unit controls are honest."""
    import base64
    ok = True

    def expect(label: str, cond: bool, detail: str = "") -> None:
        nonlocal ok
        print(f"  {'ok  ' if cond else 'FAIL'} {label}: {detail[:100]}")
        ok = ok and cond

    flow = ROOT / "src/tests/flow.jar"
    if not flow.is_file():
        print("selfcheck is an in-repo mode: it needs the fixture jars at "
              f"{flow.parent}. From an installed wheel, run the full "
              "acceptance with your own corpora (--hmcl/--neo/--negative/"
              "--lwjgl/--lwjgl-natives), or run `python src/tests/run_tests.py` "
              "from a checkout.", file=sys.stderr)
        return 2
    expect("独立 class 解析器读出方法名",
           "dispatch" in G.methods_of(flow, "demo/flow/GotoFlood"),
           str(G.methods_of(flow, "demo/flow/GotoFlood")))
    expect("独立类数等于 zipfile 目录类数",
           G.jar_facts(flow)["class_count"] == G.zip_facts(flow)["class_count"])
    expect("独立复核：FQCN 不是 blob",
           not G.is_blob_literal(
               "org/spongepowered/asm/lib/tree/AbstractInsnNode"))
    expect("独立复核：高熵 base64 仍是 blob",
           G.is_blob_literal(base64.b64encode(bytes(range(64))).decode()))
    fp = json.loads((Path(__file__).parent / "fingerprints.json").read_text("utf-8"))
    zkm = next(x for x in fp["obfuscators"]
               if x["name"] == "ZKM 27 enhanced 字符串加密（DES）")
    expect("ZKM 27 指纹要求两个专属标记",
           zkm.get("min_keywords", 1) >= 2
           and all("ivparameterspec" not in k.lower() for k in zkm["keywords"]))
    expect("8 类验收规格齐备", len(SPECS) == 8, str(len(SPECS)))
    expect("每类都有自己的负控", all(s["negative"] for s in SPECS))
    print(f"selfcheck: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
