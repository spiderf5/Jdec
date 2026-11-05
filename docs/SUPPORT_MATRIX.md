# 04 支持矩阵（草案 · 未达成）

> **状态：草案。未达成 04 门槛，不写入 `docs/ROADMAP.md` 状态列，不用于主张
> 商业 1.0 或任何「通用恢复」承诺。**
>
> 2026-11-04 用户拍板：04 的验收**坚持真实独立语料口径**（沿用 03 先例），
> 不把生成式 fixture 折算成「独立样本」，不改写门槛，不把独立研究线机制凑进
> 1.0 默认支持项。本文件按该口径如实记录「已有什么、差什么」。

## 1. 术语工作定义（草案，未获拍板，不构成门槛修订）

`docs/ROADMAP.md` 里「机制类 / 支持项 / 支持矩阵 / 离线交付」四个词**全仓无定义**，
只在 `:18-19`、`:210`、`:219`、`:226-227`、`:236` 作为计数、来源或附带条件出现。
为让本表可读，先给出工作定义；这些定义**只是草案**，没有写回 ROADMAP，
也没有改变 `:19` 的门槛。

| 术语 | 草案工作定义 |
| --- | --- |
| 机制类 | 一种可辨识的混淆 / 保护变换家族，有独立的输入形状与可测的输出 |
| 支持项 | 对该机制类的一条**有边界的能力承诺**：输入条件、产出、已知不覆盖项 |
| 支持矩阵 | 机制类 × 支持项 × 证据等级 × 回归用例 × 缺口的对照表 |
| 离线交付 | 无需公网即可获得并校验全部反编译引擎的能力（不含 Ghidra） |

## 2. 证据等级与门槛

| 等级 | 含义 |
| --- | --- |
| E0 | 仅有实现，无回归 |
| E1 | 生成式 fixture（机制**形状的诚实近似**，只证明管线连通；**不是独立样本**） |
| E2 | 仓库内 fixture + 负控 + 0 差异，第三方可一键重跑 |
| E3 | **真实外置独立语料 + 授权 + 0 差异**（03 先例：HMCL 3.15.2 / MC 1.8.9 / Flux） |

`docs/ROADMAP.md:19` 门槛是「6–8 类机制的明确支持项」，`:226-227` 要求
「每类机制的支持项必须配独立样本回归」。按拍板坚持的口径，即
**每类机制至少一个 E3 支持项**。

`docs/REPRODUCE.md:16-17` 与 `src/tests/run_tests.py:4023` 明确：生成式基准
「不是 411 全集的替代品，不能用来声明能力上限，更不能用来主张门槛达标」，
「Recall can only be proven on a real sample; the fixtures prove the rest」。
所以 E1/E2 **不能**升级成 E3，本表也不做这种折算。

## 3. 机制表

「已具备的实现」一列只描述代码存在，不代表「支持」；每行最后一列的缺口
必须非空。证据等级按仓库内可复现的最高档填写。

| # | 机制类 | 已具备的实现 | 主要文件 | 证据 | `run_tests.py` 用例 | 与门槛的缺口 |
| --- | --- | --- | --- | --- | --- | --- |
| ① | 控制流去平坦化 · 常量折叠 · 不透明谓词 | 指令级改写、帧重算、改写日志独立重放 | `src/jdec/deflat.py`、`ir/transforms.py`、`cfg.py`、`ir/reasons.py` | E2（03 三语料另属外置证据） | `test_decompiler_trap_pruning`、`test_ir_transforms`、`test_deflat_output_loads`、`test_reason_replay_and_rollback` | 03 的三个语料只覆盖本机制类的子集且外置需授权；无一份 E3 独立样本可第三方复现 |
| ② | 通用 VM 反虚拟化 | VM 指令流重翻译、纯 Python JVMS 解释器 | `src/jdec/devirt.py`、`bvm_devirt.py`、`interp/` | E2（`:219` 明写「仅 fixture 级证据」） | `test_devirt_output_loads`、`test_devirt_behaviour`、`test_devirt_realistic_vm`、`test_interp_engine_semantics` | BytecodeVM 专属实现已从产品树删除；真实自定义 VM 标本外置，无 E3 |
| ③ | indy / BSM 与字符串解密重放（静态部分） | BootstrapMethods 解析、调用目标编码、spec 生成与失败归因 | `src/jdec/indy.py`、`bsm.py`、`recover.py` | E2（`:219` 同上） | `test_bsm_scan_and_parse_resilience`、`test_indy_encoding`、`test_recover_spec_generation_and_quarantine` | 仓库内**没有一条**测试真跑过目标 jar 的 bootstrap 解密；`recover --execute` 需外置 classpath / lwjgl 常量 jar，无 E3 |
| ④ | 字符串池（三段流水线 + 单参池静态 DES） | scan / harvest / apply、OPS 池、clinit 符号求值、Java 原语算术 | `src/jdec/pool.py`、`ops_pool.py`、`clinit_sim.py`、`jint.py`、`_des.py` | E2（`:219` 同上） | `test_pool_roundtrip`（真 JVM harvest）、`test_ops_pool`、`test_clinit_sim`、`test_jint` | 算法来源是外置 `study/OpenPhantomShield`（永不入库）；无真实 PhantomShield 样本，无 E3 |
| ⑤ | native 分诊与 Ghidra 集成 | PE/ELF 导出表、反向 JNI、RegisterNatives、报告集成 | `src/jdec/native_scan.py`、`ghidra_engine.py`、`nativedb.py` | E1 | `test_native_reporting`、`test_ghidra_integration`（mock）、`test_native_elf_and_ghidra_annotate` | Ghidra 只有 mock，`nativedb` 零回归，Frida / tap 捕获端零回归且证据全外置；无 E3 |
| ⑥ | Minecraft 映射与 Mixin 元数据 | proguard / tiny v2 / tsrg / tsrg2 / official-srg / yarn compose | `src/jdec/mappings.py`、`mcmod.py`、`analyze.py` | E2 | `test_yarn_compose`、`test_official_srg_compose`、`test_mixin_fixture`、`test_multimodule_enhancements` | 真实映射表与 MC 客户端外置（`--with-mc` 默认跳过、CI 从不执行），无 E3 |
| ⑦ | ZKM 大小写孪生类 | 冲突组分桶、percent-encode 输出路径、逐类评分 | `src/jdec/decompile.py`、`score.py`、`probe.py` | E2 | `test_case_colliding_class_names`、`test_iso_buckets`、`test_scoring_sees_obfuscated_names` | 真实 ZKM 27 样本外置（`JDEC_SAMPLE_DIR` / `Myau0729-obf.jar`），缺样本即 skip，无 E3 |

## 4. 独立研究线隔离区（不计入 6–8 类）

`docs/ROADMAP.md:231-236` 原文：

> 自定义 VM 与 native 深度还原（BytecodeVM 复现、frida→Ghidra native 线、
> JNIC 容器还原等）：**按具体机制单独验证与报价**，永不并入"通用恢复"承诺。
> 已验证战绩（样本 723 类全还原、lf21 99.9%、Elowen 365/366 类）属于此类，
> 只作为能力证据，不构成 1.0 的默认支持项。

因此 **BytecodeVM 复现 / frida→Ghidra native 线 / JNIC 容器还原** 不参与上表
凑数，也不得写成本矩阵的「默认支持项」。`:226` 括号里点名的 ZKM / JNIC /
BytecodeVM / OPS 恰有部分落在此区，这是一条必须如实记录的口径冲突。

## 5. 来源与口径缺口

- `:226` 指定「以 `study/` 标本馆的机制笔记为机制清单来源」。**本仓库没有
  `study/`**，且 `.gitignore:71-73` 以「外部研究材料（含 DMCA 敏感源码），
  永不入库」明确排除。本表的来源只能是仓库内实现与回归，**与指定来源不符**，
  这本身是缺口，不是替代方案。
- `src/jdec/fingerprints.json` 的 36 项是**混淆器厂商归因词表**
  （`name` + `keywords` + `tool`），`probe` 命中关键词不等于支持该机制，
  不能充当机制清单。
- `docs/README.md:706` 表里 03 三语料的 90.0% / 91.2% / 87.9% 是**另一套
  judged union 口径**，不是 02 的 83.0%，也不是 04 的达标证据；本表不引用。
- CI 从不带 `--with-mc`，从不引用 `JDEC_SAMPLE_DIR`；`study/`、HMCL、
  MC 客户端、ZKM 27、Flux 均不得进 CI（授权与 DMCA 边界）。

## 6. 结论

- 已具备实现的机制类为 7 类，但**最高证据等级只有 E2**，没有任何一类
  配得上「真实外置独立语料 + 授权 + 0 差异」的 E3 回归。
- 按拍板坚持的口径，**6–8 类明确支持项的门槛未验**。
- **`docs/ROADMAP.md:19` 的 04 状态列保持「未开始」，不标 ✅，不推进。**
- 本表的用途是让缺口可见、可逐条补齐；补齐条件是「每类一份真实外置
  独立语料 + 授权 + 记录回归数字」，不是增加 fixture 或改写措辞。

## 7. 离线交付（本轮交付物）

按拍板采用「离线引擎包 + 断网 CI 门禁」，引擎 jar **不进 wheel**。
实现与验证步骤见 `docs/OFFLINE.md`。这是 04 两项交付中的一项；
**它不使 04 门槛达标**，也不改变上表任何一行的证据等级。
