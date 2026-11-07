"""The mechanism registry shared by both 04 layers.

One row per mechanism class, and one place for the claim the product makes.

Why this file exists: the diagnostic layer (`support_matrix.py`) and the
acceptance layer (`stage04.py`) each carried their own copy of the same eight
mechanism names, descriptions and CLI recipes. They drifted. After M1 was
reclassified as "javac switch lowering vs obfuscator flattening", the
diagnostic copy still advertised goto-flood rewriting, and the acceptance copy
described indy as "enumerate the sites" after it had learned to recover the
constant payload. A reader could not tell which sentence was the claim.

So the prose, the corpus roles and the CLI chains live here. Each layer adds
only what is its own: `support_matrix` adds the pass/fail rules that make it a
smoke matrix, `stage04` adds the independent cross-checks that make it
acceptance.

`_R` is the text contract with the CLI. Both layers read the same stdout, so
they must read it with the same pattern; keeping two copies let one layer's
pattern go stale without the other noticing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# The CLI's human-readable output, as parsed by both layers.
# --------------------------------------------------------------------------
_R: dict[str, str] = {
    "rewritten": r"deflat\s+: (\d+) method\(s\) rewritten",
    "verified": r"verify\s+: (\d+) class\(es\) pass",
    "classes": r"classes\s+: (\d+)",
    "unreadable": r"classes\s+: \d+ \((\d+) unreadable\)",
    "cls_ok": r"class\s+: (\d+)/\d+ byte-identical",
    "cls_total": r"class\s+: \d+/(\d+) byte-identical",
    "code_ok": r"method\s+: (\d+)/\d+ Code arrays byte-identical",
    "code_total": r"method\s+: \d+/(\d+) Code arrays byte-identical",
    "sites": r"(?m)^indy sites\s+: (\d+)",
    "lambda": r"lambda targets\s+: (\d+)",
    "concat": r"concat templates\s+: (\d+)",
    "record": r"record components\s+: (\d+)",
    "payload": r"payload recovered\s+: (\d+)",
    "unresolved": r"unresolved\s+: (\d+)",
    "entries": r"entries\s+: (\d+)",
    "strings": r"strings\s+: (\d+) total",
    "tagged": r"tagged\s+: (\d+) literal",
    "encrypted_blob": r"encrypted-blob: (\d+)",
    "libs": r"libs\s+: (\d+) extracted",
    "exports": r"exports=(\d+)",
    "native_methods": r"(\d+) native method\(s\) in \d+ class",
    "jni_matched": r"(\d+) JNI exports matched",
}


@dataclass(frozen=True)
class Mechanism:
    """Everything both runners need to agree on about one mechanism class."""

    id: str
    name: str
    support: str
    not_covered: str
    #: acceptance roles: the corpus that carries the claim, the second real
    #: corpus it must also hold on, and a control that must not reproduce it
    primary: str
    extra: tuple[str, ...]
    negative: str
    #: acceptance CLI chain; `{jar} {out} {key} {deflat} {rw} {cp} {natives}`
    #: are filled by the runner
    steps: tuple[tuple[str, ...], ...]
    #: per-corpus step overrides (M6 needs --libs-jar on its natives artifact)
    extra_steps: dict[str, tuple[tuple[str, ...], ...]] = field(default_factory=dict)
    #: label -> regex, a superset of what either layer reads
    patterns: dict[str, str] = field(default_factory=dict)
    #: diagnostic layer: which corpora it can actually run, and its shorter
    #: smoke chain (it proves the command works, not that the claim holds)
    diag_corpora: tuple[str, ...] = ()
    diag_steps: tuple[tuple[str, ...], ...] = ()


def _p(*keys: str) -> dict[str, str]:
    return {k: _R[k] for k in keys}


MECHANISMS: tuple[Mechanism, ...] = (
    Mechanism(
        id="M1", name="控制流去平坦化 / 常量折叠 / 不透明谓词",
        primary="hmcl", extra=("neo",), negative="junit",
        steps=(("deflat", "{jar}", "-o", "{deflat}",
                "--rewritten", "{rw}", "{cp}"),
               ("reasons", "{jar}", "{deflat}"),
               ("behave", "{jar}", "{deflat}", "--derive", "--from", "{rw}",
                "--execute", "--engine", "both", "{cp}")),
        diag_corpora=("hmcl", "neo"),
        diag_steps=(("deflat", "{jar}", "-o", "{out}/{key}_deflat.jar",
                     "--rewritten", "{out}/{key}_rw.txt", "{cp}"),),
        patterns={
            **_p("rewritten", "verified"),
            "justified": r"justified : (\d+) of",
            "unexplained": r"pair\s+: (\d+) rewritten",
            "same": r"(?m)^same\s+: (\d+)",
            "diff": r"(?m)^diff\s+: (\d+)",
            "union": r"(?m)^union\s+: (\d+)/",
        },
        support="区分两类控制流来源并分别产出指令级改写（均过 JVM "
                "-Xverify:all）：混淆器平坦化（while + switch 状态机）与 "
                "javac switch(String) 降级；产出改写清单供行为对拍",
        not_covered="真实语料只有 javac switch 类（87 个方法、684 次改写），"
                    "混淆器平坦化仅单元 fixture（7 次）；常量折叠与不透明谓词"
                    "在真实语料为 0；行为对拍 342/411、1 个真实差异",
    ),
    Mechanism(
        id="M2", name="字节级往返与坏类隔离",
        primary="hmcl", extra=("neo",), negative="truncated",
        steps=(("ircheck", "{jar}", "--limit", "2"),),
        diag_corpora=("hmcl", "neo"),
        diag_steps=(("ircheck", "{jar}", "--limit", "2"),),
        patterns=_p("classes", "unreadable", "cls_ok", "cls_total",
                    "code_ok", "code_total"),
        support="逐类 parse→重汇编→逐字节比对，报告类与 Code 数组相等数；"
                "不可读类被隔离而不是拖垮整批",
        not_covered="不做语义等价证明；jsr/ret 与不可解码类按边界拒绝",
    ),
    Mechanism(
        id="M3", name="invokedynamic / BootstrapMethods 站点枚举",
        primary="hmcl", extra=("neo",), negative="junit",
        steps=(("indy", "{jar}", "--resolve"),),
        diag_corpora=("hmcl", "neo"),
        diag_steps=(("indy", "{jar}"),),
        patterns=_p("sites", "lambda", "concat", "record", "payload",
                    "unresolved"),
        support="枚举 indy 站点并按 bootstrap owner 归类，然后还原每个站点"
                "携带的常量载荷：LambdaMetafactory 的调用目标、"
                "StringConcatFactory 的格式模板（含常量片段）、"
                "ObjectMethods 的 record 组件名；站点数与 owner 直方图经独立 "
                "BootstrapMethods 解析交叉验证",
        not_covered="不执行 bootstrap；SwitchBootstraps 等引导没有可读常量，"
                    "计入未还原而不是猜测；自定义引导（非 JDK vanilla）的站点"
                    "只是被枚举，没有还原语义；两个独立语料都没有非 vanilla "
                    "BSM，因此该路径只有单元级证据",
    ),
    Mechanism(
        id="M4", name="混淆器结构指纹归因",
        primary="hmcl", extra=("neo",), negative="junit",
        steps=(("probe", "{jar}"),),
        diag_corpora=("hmcl", "neo"),
        diag_steps=(("probe", "{jar}"),),
        patterns={"score": r"obfuscation\s+: (\d+)/100",
                  "signature": r"signatures\s+: (.+)",
                  "structure": r"structure\s+: (.+)"},
        support="按结构阈值与专属关键词归因，命中必须带证据；"
                "ZKM 27 需 ≥2 个专属标记，避免 AES-CBC 的 IvParameterSpec 误报",
        not_covered="归因词表不等于支持该混淆器的全部机制；不承诺还原；"
                    "对不含混淆器标记的真实 jar 必须如实报告未识别",
    ),
    Mechanism(
        id="M5", name="字符串常量抽取与威胁标签",
        primary="hmcl", extra=("neo",), negative="junit",
        steps=(("strings", "{jar}", "-o", "{out}/{key}_strings"),),
        diag_corpora=("hmcl", "neo"),
        diag_steps=(("strings", "{jar}", "-o", "{out}/{key}_strings"),),
        patterns=_p("strings", "tagged", "encrypted_blob"),
        support="抽取常量池字符串并按 url / path / credential / exec / "
                "class-loading 等分类；encrypted-blob 需通过 base64 解码与 "
                "内部类名排除，标签经独立复核无假阳性",
        not_covered="标签是启发式；抽取不等于解密 ZKM 池；两语料经金标准确认"
                    "无 DES 密文，故 encrypted-blob 为 0 属正确结果而非能力证明",
    ),
    Mechanism(
        id="M6", name="native 分诊与 PE/JNI 库提取",
        primary="hmcl", extra=("lwjgl",), negative="junit",
        steps=(("natives", "{jar}", "-o", "{out}/{key}_natives"),
               ("analyze", "{jar}", "-o", "{out}/{key}_analyze")),
        extra_steps={"lwjgl": (
            ("natives", "{jar}", "-o", "{out}/{key}_natives",
             "--libs-jar", "{natives}"),
            ("analyze", "{jar}", "-o", "{out}/{key}_analyze"))},
        diag_corpora=("hmcl",),
        diag_steps=(("natives", "{jar}", "-o", "{out}/{key}_natives"),
                    ("analyze", "{jar}", "-o", "{out}/{key}_analyze")),
        patterns=_p("libs", "exports", "native_methods", "jni_matched"),
        support="从 MZ 自解压容器读出 PE、解析导出表；`--libs-jar` 读 Maven "
                "natives 独立工件；统计 Java 侧 ACC_NATIVE 方法，并把 "
                "`Java_*` 导出按名与声明方法 1:1 匹配（LWJGL 2.9.4：2674 个"
                "声明、2383 个 JNI 导出全部按名命中）",
        not_covered="不反编译 native 函数体；不还原 RegisterNatives 动态绑定；"
                    "只做名字匹配，不做签名校验；无 native 的纯 Java jar 必须"
                    "报告 0",
    ),
    Mechanism(
        id="M7", name="Minecraft 元数据与 Mixin hook 识别",
        primary="neo", extra=(), negative="hmcl",
        steps=(("probe", "{jar}"),
               ("analyze", "{jar}", "-o", "{out}/{key}_analyze")),
        diag_corpora=("neo",),
        diag_steps=(("probe", "{jar}"),
                    ("analyze", "{jar}", "-o", "{out}/{key}_analyze")),
        patterns={"minecraft": r"minecraft\s+: (.+)",
                  "mixin_note": r"(no mixin config[^\n]*|mixin[^\n]*)"},
        support="从 mcmod.info / 注解独立识别 MC 版本与加载器，"
                "扫描 Mixin hook 并在无映射时保留目标名",
        not_covered="映射表外置，离线不解析 hook 最终符号；非 MC 语料"
                    "必须报告未识别，不得误报版本",
    ),
    Mechanism(
        id="M8", name="容器分类与截断类隔离",
        primary="hmcl", extra=("neo",), negative="junit",
        steps=(("probe", "{jar}"),),
        diag_corpora=("hmcl", "neo"),
        diag_steps=(("probe", "{jar}"),),
        patterns={"entries": _R["entries"],
                  "classes": r"classes (\d+)",
                  "file": r"file\s+: (.+)"},
        support="按文件 magic 区分 MZ 自解压 stub 与 PK jar，"
                "条目数经 zipfile 原始目录独立核对",
        not_covered="不处理加密容器；multi-release 条目按同一基类备选排除",
    ),
)

BY_ID: dict[str, Mechanism] = {m.id: m for m in MECHANISMS}
