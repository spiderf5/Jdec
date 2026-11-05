# 04 支持矩阵（正式交付，2026-11-05）

**结论：04 已完成。** `docs/ROADMAP.md:19` 的 04 状态列按修订纪律推进为
「✅ 已达成」，依据是本文件、`docs/STAGE04_REPORT.json` 的实测证据与
`run_tests.py` 的 1247 条断言 / 146 个用例。

本文件取代 11-04 的草案与 11-05 21:48 的撤回说明；两版历史结论保留在
`docs/ROADMAP.md` 的补记里，不改写原文。

## 1. 门槛逐条对照

`ROADMAP:19` 硬条件 =「6–8 类机制的明确支持项」；`:226` 备注 =「每类机制的
支持项必须配独立样本回归」。

| 门槛条款 | 满足方式 | 证据 |
| --- | --- | --- |
| 6–8 类机制 | 8 类（M1–M8），每类写明支持项与已知不覆盖 | 本文件第 3 节；`src/tests/stage04.py:SPECS` |
| 「明确」支持项 | 每类有输入条件、产出、边界，边界经负样本验证 | `stage04.py` 的 `support` / `not_covered` |
| 独立样本回归 | 每类一个真实独立语料上的可执行回归 + 该类自己的负控 | `docs/STAGE04_REPORT.json`：8/8 PASS、45 项交叉检查 |
| 清单来源 `:226` | `docs/mechanisms/` 的 9 份合规机制形态笔记 | 见第 5 节，来源差异如实标注 |
| 交付「支持矩阵」 | 本文件 + 两份机器可读报告 | `SUPPORT_MATRIX_REPORT.json` / `STAGE04_REPORT.json` |
| 交付「离线交付」 | `docs/OFFLINE.md` + 断网 CI job | 见第 7 节 |

**关键区别**：11-05 21:40 那版 8/8 PASS 只是「8 条已有命令跑通」，判据是
命令自己输出的数字（`stage_04_threshold_met=false`）。本版每类机制的结论都
要过 `src/tests/goldens.py` —— 一份**不调用任何 jdec 分析命令**的第二实现，
直接从 zip 条目、class 常量池/方法表、PE/COFF 头、容器 magic 重算底层事实，
再与机制声明交叉验证；并且每类都跑自己的负控。

## 2. 独立语料

| 语料 | 形态 | sha256（前 12） | 角色 |
| --- | --- | --- | --- |
| `HMCL-3.15.2.exe` | MZ stub + zip，ProGuard/R8，3740 类 | `632c2d8873f5` | 主样本，沿用 03 既有用户授权前提 |
| `NeoRaven1.1.jar` | PK，MC 1.8.9 / Forge，1534 类 | `57f294cb4374` | 第二独立样本 |
| `junit:junit:4.13.2` | 公开、未混淆，350 类 | `8e495b634469` | **公开可复现的阴性对照**，坐标与 URL 写在报告里 |
| `src/tests/sample.jar` | 仓库内故意截断类 | `b844b1b93d05` | M2 的坏类负控 |

外置语料不入库。阴性对照来自 Maven Central，任何人可用报告里的坐标 +
sha256 取到同一文件，比外置授权样本更可复现。生成式 fixture 只用于
`run_tests.py` 与 CI 的单元级负控，**不折算为独立样本**。

## 3. 8 类机制的明确支持项与实测

数字来自 `docs/STAGE04_REPORT.json`（HotSpot 21 / manager 后端 / JavaFX 21-win）。

| ID | 支持项 | 独立金标准 | 该类自己的负控 | 实测 |
| --- | --- | --- | --- | --- |
| M1 去平坦化 / 常量折叠 / 不透明谓词 | 产出指令级改写、重算 StackMapTable、全部类过 JVM `-Xverify:all`、改写清单可重放 | 独立 class 解析器核对清单里每个方法确实存在于原 class；`zipfile` 逐类 sha256 确认改写后字节变化 | junit：17 个合法常量折叠，`reasons` 17/17 可解释、`behave` 12 same / **0 diff**，规模 < 主样本 1/10 | 411 改写、3693 类 verify、411/411 justified、0 unexplained、`behave` union 342/411（1 个真实差异，见 `REPRODUCE.md`） |
| M2 字节级往返 / 坏类隔离 | 逐类 parse→重汇编→逐字节比对，报告类与 Code 数组相等数 | `zipfile` 原始类数与逐条 sha256 | 截断类 `sample.jar` 不得判为干净 PASS | 3740/3740 类、29395/29395 Code、0 unreadable |
| M3 indy / BSM 站点枚举 | 枚举站点并按 bootstrap owner 归类 | 独立解析 `BootstrapMethods` 属性条目数 | junit 必须报 0 站点（金标准 0 BSM） | HMCL 6245 站点 ≥ 5420 BSM 条目；Neo 150 ≥ 149 |
| M4 混淆器结构指纹归因 | 按结构阈值与专属关键词归因，命中带证据 | 独立常量池扫描 `DESKeySpec` / `DES-CBC` / `zelix` / `$CodePool` | junit 不得误报任何混淆器签名 | HMCL→ProGuard/R8；两语料均不报 ZKM 27（金标准 DES 标记全 0） |
| M5 字符串抽取与威胁标签 | 抽常量池字符串并分类标注；blob 需 base64 解码 + 内部类名排除 | 独立常量池 UTF8 总数 + 对标签逐条复核 | FQCN 不得标 blob；高熵 blob 仍须标出；junit 0 blob | 15839 / 9315 条，406 / 101 标签，**0 encrypted-blob** |
| M6 native 分诊 / PE 提取 | 提取内嵌 PE、解析导出表、统计 Java 侧 native 方法 | 独立 PE/COFF 导出目录解析 + 独立 `ACC_NATIVE` 计数 | junit 必须 0 库 / 0 导出 / 0 native | 1 PE、2 导出、69 native 方法，三项与金标准逐一相等 |
| M7 MC 元数据 / Mixin | 从 `mcmod.info` 与注解识别版本与加载器 | 独立读 `mcmod.info` / manifest | HMCL（非 MC）不得报 1.8.9 | Neo 识别 1.8.9 / Forge |
| M8 容器分类 / 截断类隔离 | 按 magic 区分 MZ stub 与 PK jar，条目数可核对 | `open().read(2)` + `zipfile.namelist()` | junit 必须识别为普通 PK | HMCL `4d5a` / 4248 条目；Neo `504b` / 1767 条目 |

**合计 45 项交叉检查全部通过（8/8 PASS）。** 每项的 `checks[].detail` 写明了
比对双方的数值，可逐条复核。

## 4. 本轮纠正的三处事实错误

之前写进文档和已入库报告的数字有三处是错的，本轮用独立金标准核实并修正，
两份报告都已重跑：

1. **「NeoRaven 是 ZKM 27 enhanced DES 字符串加密」是误报**。`probe.py` 的
   关键词首中即停命中了 `javax/crypto/spec/ivparameterspec` —— AES-CBC 客户端
   同样使用 `IvParameterSpec`。独立扫描 1534 个类的常量池：`DESKeySpec`=0、
   `DES/CBC/PKCS5Padding`=0、`zelix`=0，只有 1 处 `AES/CBC/PKCS5Padding` 与
   3 个客户端自有 AES 类。修法：ZKM 27 指纹改要求 ≥2 个专属关键词，
   `probe.py` 支持 `min_keywords`。修后 NeoRaven 如实报告「未识别」。
2. **「8 个 encrypted-blob」全是假阳性**。`strings.py` 的
   `^[A-Za-z0-9+/]{48,}$` 字符类含 `/`，把 `org/spongepowered/asm/...` 这类
   内部类名当密文；另混入 ASM Frame 描述串与 RSA hex。修法：排除内部类名、
   要求 base64 可解码且解码后可打印字节 < 90%、hex 长度 ≥64 且为偶数。
   修后两语料 encrypted-blob = 0，标签数 409→406、107→101。
3. **junit 被自动归因为 "Sentinel"**。`Sentinel` 指纹只有一个通用英文词
   `sentinel`，在普通库里就会出现，却输出 `obfuscator signature: Sentinel`
   （同时混淆度 0/100，自相矛盾）。该词条 `tool` 本就写「无公开 transformer，
   需手工分析」，属研究笔记。修法：标记 `auto_attribute=false`，`probe.py`
   跳过自动归因；HMCL 的 ProGuard/R8 归因不受影响。

这三点说明：11-05 21:40 那版的 8/8 里，M4 与 M5 是**靠误报通过的**。
本轮把判据从「必须报 ZKM 27 / 必须报 ≥1 个 blob」改成「不得误报」，
并补上独立金标准，才使回归真正验证正确性。

## 5. 机制清单来源与 `:226` 的差异

`ROADMAP:226` 指定 `study/` 标本馆的机制笔记为清单来源，但
`.gitignore:71-73` 以「含 DMCA 敏感源码，永不入库」把 `study/` 整个排除，
目录不存在。本轮建立 `docs/mechanisms/`（`README.md` + `M1.md`…`M8.md`）
作为**合规替代**：只写机制的可观测形态、支持项、已知不覆盖、独立金标准与
负控，**不含任何第三方源码、反编译片段或混淆器实现代码**。

这是一条**保留的来源差异**，不是「按原来源验收」：清单由这 9 份笔记 +
仓库内实现 + 三个真实语料的回归共同确定。若要求严格按 `study/` 原件验收，
需要用户另行提供合规材料并重新拍板，当前状态列不依赖该前提。

## 6. 独立研究线边界

`ROADMAP:231-236` 的独立研究线（BytecodeVM 复现、frida→Ghidra native 线、
JNIC 容器还原）**永不并入通用恢复承诺、不构成 1.0 默认支持项**，本矩阵的
8 类没有把它们凑数。两个独立语料经金标准确认**不含** ZKM DES 密文、非
vanilla indy BSM、`$CodePool`，所以 M3/M4/M5 的相关目标数为 0；这些机制的
支持项是「识别并如实报告 0」，**不是「已攻克该机制」**。深度还原仍按具体
机制单独验证与报价。

## 7. 离线交付

`docs/OFFLINE.md` + 断网 CI job `offline-smoke`：离线引擎包、
`--offline/--from-dir/--verify-only`、sha1 完整性校验与篡改负控、
断网安装后 `ircheck` / `verify` PASS。引擎 jar 不进 wheel、不入库。

## 8. 已知不覆盖（诚实边界）

- **只有 M1 是恢复级**（改写 + JVM 校验 + `reasons` 可重放 + `behave` 行为
  对拍）。M2–M8 是「准确观测 + 独立金标准 + 负控」，不承诺还原能力。
- M1 的 `behave` 在 HMCL 上是 342/411、1 个真实差异，属 02 的未达门槛，
  **不是 0 差异**。04 不宣称改写语义完全等价。
- 两个语料都没有非 vanilla BSM / ZKM DES / VM code pool；若需要这些机制的
  正向恢复证据，必须另备真实独立语料。当前语料上的「0 目标」只能证明
  **不误报**，不能证明能还原。
- `docs/README.md` 里 03 三语料的 90.0% / 91.2% / 87.9% 是另一套 judged
  union 口径，与本矩阵无关。
- CI 不持有授权语料：`support-matrix` job 只跑诊断层负控，
  `stage04.py --selfcheck` 只验证独立金标准与单元级负控。完整验收由有授权者
  在本地执行，报告入库、样本不入库。
- 换 JDK、换隔离后端或换 JavaFX 版本会改变部分数字，重测须重新记录。

## 9. 历史留痕

| 时间 | 结论 |
| --- | --- |
| 2026-11-04 | 只交支持矩阵草案 + 离线交付，判定 04 门槛未验 |
| 2026-11-05 21:40 | `f0488d4` 把 8 条诊断命令的 8/8 PASS 标为 04 达成 |
| 2026-11-05 21:48 | 用户质疑「04 这么快？」，复核后撤回达标声明（`98ddd26`），列出 9 条理由 |
| 2026-11-05 22:xx | 代码体检修 11 个工程缺陷（`d8b72cc` / `6c8836b`），仍未推进 04 |
| 2026-11-05 本次 | 修误报、建合规清单、加独立金标准与每类负控、8/8 PASS × 45 项交叉检查，按修订纪律推进 04 |

`src/tests/support_matrix.py` 保留为**诊断层冒烟回归**（CI 可跑，报告里
`stage_04_threshold_met=false` 明确它不是门槛证据）；
`src/tests/stage04.py` 是**验收层**。两者职责不同，不互相替代。
