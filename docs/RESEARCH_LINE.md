# 独立研究线立项书（2026-11-07 拍板）

> **定位**：本文件是「独立研究线」的立项记录与工作章程，**不是阶段状态判定**。
> 按 `ROADMAP.md:233-238`，本领域永不并入 1.0 通用承诺，按具体机制单独验证与报价。
> 主线状态列、02 门槛与分母、独立研究线边界、修订纪律本身全部未改；
> 本文件不推进任何状态列、不产生达成标记。

## 0. 本轮拍板

| 事项 | 结论 | 依据与处置 |
| --- | --- | --- |
| 02 建设改写底座 | **收口，不再推 90%** | 用户确认「02 到上限了，我试过很多次了」。实测 `union 342/411 = 83.2%`、1 个真实差异、`--union-gate 90` 退出 1，需 ≥370/411 尚差 28 个判定（`ROADMAP.md:289-293`、`REACHABILITY_02.md:9-15`）。状态列保持「进行中」，90% 门槛与 411 分母不改；`:179-181` 的历史收口与 `:257-259` 的重启决定均保留原文。收口只表示停止投入，**不表示门槛达标** |
| 05 成熟化运营 | **不启动** | 用户确认「05 本身没有代码任务」；其交付是版本维护、诊断与回归、持续客户验证（`ROADMAP.md:20`、`:230-231`），依赖真实用户而非代码。状态列保持「未开始」 |
| 独立研究线 | **深挖后正式立项** | 范围取 `ROADMAP.md:235` 的三条：自定义 VM 复现、frida→Ghidra native 线、JNIC 容器还原。以本文件为章程，按 §4 优先级推进 |

## 1. 立项对象与不可协商的边界

三条线并非等距：`frida→Ghidra` 与 `JNIC 容器还原` 是同一条 native 证据链的**前后段**
——运行时抓 `RegisterNatives` 全表 → 内存 PE 重建 → Ghidra 反编译 → 反向 JNI
调用图 → 伪 Java 回填；自定义 VM 是字节码侧的独立分支。为便于单独验证与报价，
仍按三个机制类立 case，但前两类共用一条工具链。

1. **永不并入**「通用恢复」/ 1.0 默认支持项（`ROADMAP.md:235-238`、
   `SUPPORT_MATRIX.md:33-34`、`docs/mechanisms/M1–M8.md` 各篇边界节）。
2. **按具体机制单独验证与报价**：一个 case = 一个授权语料 + 一份独立金标准 +
   一组负控 + 一份报告；生成式 fixture 只做负控，不折算独立样本
   （`SUPPORT_MATRIX.md:66`、`ROADMAP.md:255-256`）。
3. **授权与合规红线**：仅自有或已获书面授权；不绕过未授权商业软件、联网反作弊、
   DRM / 授权 / 许可证校验，不改客户端取服务端权限，不移除第三方遥测计费；
   dump 不外泄牟利，任一为否即停
   （`java-deobf/references/dynamic-analysis.md:167-172`）。
4. **材料隔离**：`study/` 含 DMCA 敏感第三方源码，永不入库（`.gitignore:72-73`）；
   转储、`mappings*.tsv`、`config/`、`native/` 工作区全部 local-only
   （`.gitignore:64-70`），外部工作区不进版本库。git 历史只查提交主题与文件清单，
   不恢复内容。
5. **运行安全**：`behave` / `recover` / `pool harvest` 真跑目标代码；Java
   SecurityManager 加进程级两层隔离都**不是** OS/容器边界，native 载荷在 Java
   沙箱之外（`sandbox.py:17-18`、`docs/README.md:782-783`）→ 不可信样本一律
   容器或低权限用户。
6. **判据诚实**：目标数为 0 如实报 0，不算「攻克」；只枚举不等于还原，只比名
   不等于校验签名（`mechanisms.py:187-189`、`SUPPORT_MATRIX.md:101-106`）。

## 2. 深挖结论：现有家底

| 线 | 已能端到端跑 | 仅 fixture 级 / 明确断点 |
| --- | --- | --- |
| native 链 | `jdec natives <jar\|DLL> --decompile --ghidra ...`（PE/ELF 导出表、JNI 名字 1:1 匹配、`native-triage.md`、`ghidra_annotate.py`、反编译 C + `decompiled_summary.json`）；`jdec nativedb --build/--search/--strings`；`jdec opspool`（纯 Python DES-CBC + swp 逆，零 JVM）；`jdec recover --execute / --from-frida`；`jdec pool scan\|harvest\|apply`；`trace2java.py`；`pe_rebuild.py`；`recover.ingest_frida_tsv`（`recover.py:444-480`，认 4 种 TSV 形态） | Ghidra 只有 mock 安装 + 假 DLL（`src/tests/suites/tooling.py:552-607`），**无真实 headless 端到端**；`engines/frida/` 与 `engines/tap/` 全部文件**零自动化覆盖**；地址表链格式错配（§3）；Mach-O 只提取不解析（`native_scan.py:3-10`）；内嵌 payload 静态解密需先逆 loader 算法，现走内存 dump（`engines/frida/README.md:50-52`） |
| 自定义 VM | `jdec devirt\|bvm`（`devirt.py`：VM 解码 / 翻译 / StackMapTable / `-Xverify:all` 回滚）；`src/jdec/interp/`（JVMS 双槽差分引擎）；`jint.py`、`clinit_sim.py`、`_des.py`、`opspool`；`probe` 的 BytecodeVM 指纹（`fingerprints.json`） | `interp/values.py:13-22` 自述「不是 JVM / 不是 verifier」，**不是 VM 复现器**；BytecodeVM 专属实现（`bvmw.py` / `bvmw_ops.py` / `bvmw_devirt.py` / `bvmw` CLI / `tests/bvmw`）已于 2026-10-07 移出产品树，方法论留在 `java-deobf/references/bytecode-vm.md:74-82`；`devirt --pool` 自动发现仅适配 `CodePool/Program` 模板（`devirt.py:1403-1424`）；`trace2java.py:62-64` 自承按序近似；`HarnessTemplate.java:32-40` 调用点全注释 |

> **状态注记（2026-11-07）**：上表是**立项时点**的家底，保留原文。其中
> 「Ghidra 无真实 headless 端到端」与「地址表链格式错配」两项已修复并补了
> 真实冒烟，见 §10.1 / §10.2 与 §11；`engines/frida/` 与 `engines/tap/`
> 目录级 / 端到端仍无自动化覆盖（现有 `test_trace2java_dead_condition`
> 只是函数级断言），Mach-O 与自定义 VM 的边界也未变。

可复用组件：`native_scan.py` 的 PE/ELF 导出表与 `JNINativeMethod` 定位、
`Triage.matched_static`、`scan_reverse_jni_c` / `scan_register_natives_c`；
`ghidra_engine.py` + `ghidra_worker.java`；`pe_rebuild.py`；
`recover.ingest_frida_tsv`；`jint.py` / `_des.py` / `clinit_sim.py`；
`interp/` 的差分底座；`sandbox.py`。

方法论家底在 `java-deobf/references/bytecode-vm.md`：4 套 HIGH fixture、
395 静态 slot + 1713 运行时事件对拍，layout 9 列求解、`mix(a=vpc, b=slot)`、
clinit 5 种注册变体、BVMTrace 四层对拍（§1–§5）；§7 仍开放 handler
operand / constant 的逐 seed 语义化。

**历史战绩的证据状态（必须写清）**：

- `723 类`：ZKM 27 样本，有逐项表格（`docs/README.md:39/435/677-682`、
  `references/control-flow.md:33`、`src/jdec/obf.py:42/65`、
  `src/tests/suites/integration.py:2133`）。
- `lf21 99.9%`、`Elowen 365/366`：**当前仅** `ROADMAP.md:237` 一句；详细记录
  随去样本化提交（`7af3cf7` / `d7ec0f4` / `3f8b024`）移出工作树，现无复现材料。

→ 立项要求：后两项在补齐复现证据前只作为**能力线索**，不写入任何交付承诺，
不得以 git 历史中的第三方源码或样本充当证据。

## 3. 立项首个发现：地址表链是断的（P0）

深挖查出的真实断点，不是推测。四方契约互不一致：

| 位置 | 契约 |
| --- | --- |
| `cli_args.py:246-248` | `--mappings` 说明明写接受「frida regnatives TSV (`cls, method, sig, ptr, [base, module]`)」 |
| `engines/frida/dump_mappings.py:298-300` | 实际输出 `cls ⇥ method ⇥ sig ⇥ ptr [⇥ base ⇥ mod]`，即 4/6 列，**ptr 在第 4 列、base 在第 5 列** |
| `ghidra_engine.py:179` | docstring 写的是「每行 `name ⇥ runtimePtr(hex)`」，与上游不同 |
| `ghidra_engine.py:193-196` / `native_scan.py:806-807` | 原样复制文件，**无任何列转换** |
| `ghidra_worker.java:58-66` | 按 `pp[1]` 解析 hex 指针、`pp[2]` 解析 base；解析失败 `catch` 后静默忽略 |

后果：把 `regnatives.js` + `dump_mappings.py` 产出的 TSV 直接喂给
`jdec natives --mappings` 时，`pp[1]` 是方法名而非 hex 指针，
`Long.parseLong` 抛 `NumberFormatException` 被 `:66` 吞掉，`addrEntries` 为空
→ 动态注册目标一个函数都建不出，**且没有任何报错**。这恰好卡在 M6 明确
不覆盖的 291 个 `RegisterNatives` 动态注册上（`SUPPORT_MATRIX.md:105-106`）。

修复方向（本轮不实施）：在 `ghidra_engine.py` 落盘前做一次显式格式归一化
（或让 worker 同时认两种形态），统一成 `name ⇥ runtimePtr(hex) ⇥ runtimeBase(hex)`；
补「格式错配必须报错而非静默通过」的负控；再补一条真实 Ghidra headless
冒烟（当前只有 mock）。判据见 §5。

> **状态注记（2026-11-07）**：本节是立项时查出的原始证据，保留原文。该断点
> 已修复（§10.1），真实 Ghidra headless 冒烟已通过（§10.2 / §11）；深度复审
> 后追加的正确性与安全加固见 §11。

## 4. 范围与优先级

| 优先级 | 工作包 | 输入 → 产出 | 不承诺 |
| --- | --- | --- | --- |
| **P0** | 打通 native 地址表证据链 | §3 修复 + 单元/集成回归 + 负控；真实 Ghidra headless 冒烟 | 不承诺 native 函数体还原率 |
| **P1** | JNIC / native 容器 case | 授权样本 → `dump_mappings`（regnatives / jnitrace）→ `dump_payload` + `pe_rebuild` → Ghidra 反编译 C → 反向 JNI / `RegisterNatives` 图 → `trace2java` 伪 Java + `--from-frida` 回填 | 不逆 loader 做静态解密（走内存 dump）；不承诺 C→Java 等价 |
| **P2** | 自定义 VM case | 同构未知 VM 样本 → `probe` 归因 → 按 `bytecode-vm.md §1–§5` 缩减尝试面（layout 9 列 / 派发路由 / clinit 变体）→ 路由对拍 → 语义化 | 不承诺通用 VM 复现；不把已移出的专属工具搬回产品树 |
| **P3** | 交付与报价单元 | 每 case 一份交付包：报告 + 产物 + 复现命令 + 边界声明 | 本文件不写金额；不并入 1.0 支持矩阵 |

P1 / P2 都要求先有授权样本；**P0 不依赖外部样本**，是立项后第一个可开工项。

> **状态注记（2026-11-07）**：P0 已完成并经两轮加固（§10 / §11 / §12）；
> P1–P3 仍待授权样本，未启动。本表保留立项时的优先级原文。

## 5. 验收与证据纪律

每个 case 单独验收，以下条件全部满足才算 PASS：

1. **独立语料**：真实、授权，坐标 + sha256 入报告；生成式 fixture 只做负控，
   不折算独立样本。
2. **独立金标准**：沿用 `goldens.py:1-14` 的纪律——第二套实现从 zip / class /
   PE 字节重算事实，不 import 任何 jdec 分析模块；被测命令不得自证。
3. **负控**：改一字节 / 改一个常数必被检出；未混淆公开 jar（junit 4.13.2）
   必须 0 命中；截断类必须判坏；**格式错配必须报错而非静默通过**。
4. **完整命令与环境**：Python / JDK / frida / frida-tools / Ghidra 版本、
   隔离后端、git commit、`--cp` 清单、stdout 全文。
5. **结论口径**：只写实测数字与逐条归因，不写「攻克」；0 命中如实报 0；
   「单独验证与报价」= 一个 case 一个计价单元，报告即验收单。
6. **状态**：独立研究线不进五阶段状态表、不产生达成标记；本文件与每 case
   报告是唯一记录载体。
7. **基线数字**：回归断言数 / 用例数以 `python src/tests/run_tests.py` 的
   实际输出为**唯一来源**。文档只记带日期的时点快照，不写「当前值」；
   新增或删除测试**不需要**同步修改文档数字，避免反复失步。

## 6. 环境与资源（2026-11-07 本机实测）

| 已具备 | 需补 |
| --- | --- |
| Python 3.13.14；`JAVA_HOME=D:\java21`（java / javac 可用） | 4 个引擎 jar（`python jdec.py engines`）；fixture jar（`python src/tests/build_fixtures.py`） |
| `python -m ruff check .` 全过；`jdec 0.2.0`；工作树干净 | Ghidra Headless（`engines/ghidra/` 未装，走 `--with-ghidra` 或 `GHIDRA_HOME`） |
| `HMCL-3.15.2.exe` 与 `NeoRaven1.1.jar` 在 `D:/MC/HMCL/` | frida 16.7.19 + frida-tools 13.7.1（`engines/frida/README.md:39`）；JavaFX 21-win 三 jar |
| 方法论文档、工具代码、指纹表均在库 | JNIC / MyJ2C / PhantomShield / 同构 VM 的**授权样本**；仓库外 local-only 工作区 |

授权是所有动态捕获的前置；样本、转储、mappings、config 一律放仓库外。

## 7. 风险

- **合规**：`study/` 与历史提交含第三方敏感材料，只查提交主题与文件清单；
  §1.3 的红线是停止条件，不是建议。
- **安全**：native 载荷在 Java 沙箱外；目标存活窗口可能仅约 2s、JS 定时器
  不触发需 Python 泵驱动、frida 17.x 的 attach 时序经验值需重测
  （`engines/frida/README.md:33-49`）。
- **技术**：Ghidra 无真实端到端回归〔立项时点；已补齐，见 §10.2 / §11〕；
  `devirt` 池自动发现只适配一个模板；
  Mach-O 只提取不解析；`trace2java` 是近似回填。
- **证据**：`lf21` / `Elowen` 详细记录已去样本化、无法复跑；外部工作区不进
  版本库，换机器须重备并在报告重记 sha256。

## 8. 与 ROADMAP 的关系

本文件为立项记录。`ROADMAP.md` 主线状态列、02 的 90% 门槛与 411 分母、
独立研究线边界（`:233-238`）、修订纪律（`:240-245`）**全部未改**；状态列是否
推进仍需另行拍板。本轮三条拍板以「补记（七）」在 `ROADMAP.md` 留痕，同样
不改状态列。

## 9. 第一个交付

> **状态注记（2026-11-07）**：本节是立项时的开工要求，保留原文。实际完成、
> 深度加固与返工复核分别见 §10 / §11 / §12。

P0：修 §3 的格式错配 + 加负控 + 跑通
`python jdec.py engines` / `python src/tests/build_fixtures.py` /
`python src/tests/run_tests.py` / `python -m ruff check .`。

判据：① 6 列 regnatives TSV 经 `--mappings` 能落成 `addrEntries`（构造 TSV
单元断言）；② 错配格式必报错、不静默吞掉；③ 全套回归与 lint 不退化。
开工前不改动任何阶段状态与门槛。

## 10. 实施记录（2026-11-07）

本节是**实测记录**，不是阶段判定；不产生达成标记，不推进任何状态列。
本轮用户拍板范围：真缺陷 + 可完成项；02 维持收口；允许联网装齐公开依赖；
用本机 HMCL / NeoRaven 复跑 04。刻意设计边界、02 全部、`docs/ROADMAP.md`
状态列与 90% 门槛 / 411 分母均未改动。

### 10.1 修复项

| 项 | 改动 | 实测 |
| --- | --- | --- |
| P0 地址表错配 | `src/jdec/ghidra_engine.py` 新增 `normalize_mappings()`，落盘前把 4/6 列 Frida TSV 归一为 3 列 `name⇥ptr⇥base`；docstring 契约同步；TSV 校验提前到任何 Ghidra 依赖之前 | 6/4/3 列转换、坏行抛 `ValueError` 带行号、`decompile_library` 返回显式错误而非静默空结果 |
| worker 静默吞错 | `src/jdec/ghidra_worker.java` 对列数不足 / 非 hex 行打印 `bad mapping line` 并计数，写入 `decompiled_summary.json` 的 `bad_mapping_lines`；`ghidra_engine.py` 回传该字段 | 真实 Ghidra headless 冒烟：`bad_mapping_lines = 0` |
| README 离线链接 | 根 `README.md` 表格改本地相对路径，另设「在线阅读」入口保留 `blob/HEAD/docs/*.md` 绝对链接（兼顾 PyPI 与 `core.py:822-842` 的链接断言） | `test_readme_doc_links` 全过，7 个绝对链接均可解析 |
| trace2java 死条件 | `engines/frida/trace2java.py:73` 的 `or True` 移除，v1 按序近似语义与输出逐字不变 | 构造 markers/ops 断言 `segment()` 输出与清理前一致 |
| 导出证据梯 | `project.verify_compilation` 加可选 `classes_out`（默认仍丢弃产物）；`project` / `export` 加 `--evidence {none,jvm,behave}` 与 `--evidence-from`，默认 `none`；接线 `verify.py` / `behave.py`，产出 `evidence.md`；`repair-log.md` 文案与 `integration.py:949-951` 断言同步 | `flow.jar` 端到端：`--evidence jvm` → `JVM-verified`（4/4 类过 `-Xverify:all`）；`--evidence behave` 缺 spec → 记录 `JVM-verified` + `Why not higher`，缺 spec 时**不执行目标代码**〔§10 时点结论；§11.1 修复 2 已补 `--execute` 授权闸，给 spec 后必须显式授权才会执行〕 |
| 附带发现：`fetch_lwjgl` 404 | `src/jdec/stage04.py` 的 `2.9.4-nightly-20150209` 从未发布到 Maven Central（该坐标最新只到 2.9.3），改为主源 Mojang `libraries.minecraft.net` + Central 备选，多源失败给明确错误；坐标与 sha256 不变，报告 `url` 字段的类型与取值见 §11.1 修复 1 及 §12 | 两个工件下载成功，04 复跑 M6 13/13 PASS |

### 10.2 环境与真实 Ghidra 冒烟

装齐：`pip install -e .`、frida 16.7.19 + frida-tools 13.7.1、4 个引擎 jar
（sha1 校验）、Ghidra 11.0.3、5 个 fixture jar、JavaFX 21-win 三 jar。
JavaFX 版本 / classifier / sha1 记在仓库外
`D:/MC/Jdec/rerun/javafx-21-win/javafx_manifest.json`。

`test_ghidra_headless_smoke` 以 `JDEC_GHIDRA_SMOKE=1` + `GHIDRA_HOME` 真跑，
公开 PE 取 LWJGL `natives-windows` 工件内的 DLL（未装 / 未下载则 skip，CI 恒不红）。
本次实测 5 条断言全过：worker 收到 3 列地址表、ptr/base 取自 Frida 的第 4/5 列、
headless 日志落盘、零行被拒绝、summary 含 `bad_mapping_lines`。

### 10.3 04 复跑（新报告，不覆盖权威存档）

脚本形式 `python src/jdec/stage04.py ...`（仓库根的 `jdec.py` shim 会让
`-m jdec.stage04` 解析到 shim，故不用）。报告落仓库外
`D:/MC/Jdec/rerun/STAGE04_REPORT_2026-11-07.json`；
`docs/STAGE04_REPORT.json` 的 `git diff` 为空。

实测：**8/8 PASS、verdict PASS、87 项检查**（a=58 / b=16 / c=10 / d=3），
M1 19、M2 9、M3 12、M4 12、M5 10、M6 13、M7 5、M8 7。
关键数字与权威存档一致：411 改写、6245 indy 载荷、3740 类、15839 字符串。
环境口径：Python 3.13.14 / HotSpot 21 / JavaFX 21-win 三 jar
（`base, controls, graphics`，与历史记录的列举顺序不同，内容一致）；
HMCL 与 NeoRaven 的 sha256 与存档逐字相同。本次是**同口径复跑**，
数字未漂移，不硬凑、不宣称新门槛达成、不改动 02 结论。

### 10.4 全量验证

| 门禁 | 结果 |
| --- | --- |
| `python -m ruff check .` | 全树通过 |
| `python src/tests/run_tests.py` | **1326 断言 / 0 失败**（原 1302 / 152 用例，新增 4 个用例、24 条断言） |
| `python -m pip wheel . -w dist --no-deps` + 解包自查 | 77 条目，无禁用路径、8 个必需 package-data / 04 模块齐备 |
| `stage04.py --selfcheck` | PASS |
| `support_matrix.py --selfcheck --json` | PASS、`stage_04_threshold_met is False`、2 个负控 |
| `git diff --check` | 干净 |
| `git diff -- docs/STAGE04_REPORT.json` | 空 |

### 10.5 仍开放（不在本轮范围）

- `docs/ROADMAP.md:516` 仍写 LWJGL 两坐标「都在 Maven Central」，与 10.1
  的实测不符；该文件按 `:240-245` 修订纪律只在用户拍板时修改，本轮未动。
- P1 / P2 的 JNIC / MyJ2C / ZKM / 同构 VM 授权样本未到位，端到端仍不可验；
  本轮只做了单元 / 负控与公开 PE 冒烟，不宣称攻克。
- `--evidence behave` 需调用方提供 `--evidence-from` case spec 才会真跑差分
  （且会执行目标代码）；缺 spec 明确记 `partial`。
- `docs/README.md` 与 PyPI 渲染下的相对/绝对链接取舍已用并存方案规避，
  若将来移除在线入口，必须同步改 `core.py:822-842`。

## 11. 深度优化记录（2026-11-07 第二轮）

对 §10 的实现做了一轮边界复审，查出 9 处问题，其中前 6 处是**上一轮实现自身
引入的**（含 1 处安全红线）。历史原文一律保留，不改写 §2 / §3 / §7 / §10 的
时点结论，只在对应位置加了注记。

### 11.1 修复清单

| # | 问题 | 修复 | 证据 |
| --- | --- | --- | --- |
| 1 | **报告 schema 退化**：`LWJGL_ARTIFACTS[*][2]` 改成 URL 元组后，`corpus_sources.*.url` 被序列化成数组，与 `docs/STAGE04_REPORT.json` 的字符串契约矛盾（坐标未变，变的是报告 `url` 字段） | 报告构造取 `urls[0]`（主源字符串），多源仍保留在代码里 | 优化前后报告实测 `url: list → str`；8 类 metrics、87 项检查、HMCL/NeoRaven sha256 逐字不变；但 `url` 值改为 Mojang 源，与权威存档的 Maven Central 值不同，见 §12 |
| 2 | **安全红线**：`--evidence behave` 未要求 `--execute` 就调用 `behave.compare` 执行目标 jar 代码，绕过了 `behave` / `recover` / `pool` 一致遵循的显式授权 | 新增 `--execute`（默认 False）与 `--no-sandbox`；未授权时**任何** JVM 检查都不跑，直接记 `partial` | 断言未授权时 `evidence.md` 含 `--execute` 且无 `## JVM verification` 段 |
| 3 | **hex 语义不一致**：`int(s,16)` 放行 `+1` / `-1` / `1_000` / `0x0x1`，Java `Long.parseLong(s,16)` 拒绝 → 归一化"成功"而 worker 丢行，等于绕过 P0 承诺 | 正则 `(?:0[xX])?[0-9a-fA-F]+` 全匹配；补空类名/方法名、BOM、表头（≥2 个表头词才识别） | 11 组 hex 边界 + 3 组非法行断言 |
| 4 | **流式与副作用**：整份读 TSV 产生 4~5 份全量副本；失败时留下 `_filter_symbols.txt`；`get_headless_cmd` 失败抛未捕获异常；`bad_mapping_lines` 只在一个返回分支存在；summary 解析失败被静默 `pass` | 新增 `normalize_mappings_file()` 流式逐行写（生产路径）；`_failed()` 统一清理与返回；所有分支带 `bad_mapping_lines`；解析失败打 stderr 告警；`_addr_mappings.tsv` 保留为可审计产物 | 流式与内存版输出逐字一致、BOM 不残留；真实冒烟 6 条全过 |
| 5 | **下载不可自愈**：`fetch_lwjgl` 直接 `write_bytes`，中断后留下残片且下次 `is_file()` 直接跳过；HTTP 200 的 HTML 错误页也会当有效 jar | `.part` + `shutil.copyfileobj` + PK 魔数校验 + 原子 `replace`；启动时校验已有文件并自愈 | 构造残片 + mock 下载，断言替换、无 `.part` 泄漏、有效缓存不再联网 |
| 6 | **`_run_evidence` 落盘 / 幂等 / 产物**：`evidence.md` 写失败会让整个导出抛 traceback；`repair-log.md` 每次追加同一行；`classes_out` 连 `sources.txt` 一起复制且不清空陈旧类 | 落盘与 repair-log 更新包 `OSError` 降级为 warning；marker 行覆盖式更新；`classes_out` 先清空且只复制 `*.class`；一次 `rglob` 复用；新增 `--evidence-timeout` | 目录占用 `evidence.md`、重复运行、陈旧 `Stale.class` 三条负控全过 |
| 7 | Java worker `trim()` + `split("\t")` 丢尾随空列 → `name⇥ptr⇥` 静默把 base 变成 -1 | 改 `split("\t", -1)` + 逐列 `strip()`，坏行计入 `bad_mapping_lines` | 与归一化后的 3 列契约一起被真实 headless 冒烟覆盖 |
| 8 | **假阳性冒烟**：未检查 `decompile_library` 返回值，3 条断言只证明 Python 归一化；硬编码 `D:/MC/Jdec/rerun/lwjgl` | 断言 `res["ok"] is True`、从返回值取 `bad_mapping_lines`、日志断言条件化；路径支持 `JDEC_NATIVES_DIR` | 本轮真实冒烟 6 条全过 |
| 9 | 大文件魔数：`cmd_natives` 用 `raw.read_bytes()[:2]` 把整个输入（可达数百 MB）读进内存只为看 2 字节 | `raw.open("rb").read(2)`，O(S) → O(1) | `natives` 相关回归无退化 |

### 11.2 明确不做的大规模重构

复审另找到几处**产品原有**热点：`native_scan.extract_libs` 一次把全部 native
条目解压成 bytes 列表且每字节扫 5 遍、`project.export_project` 对同一 jar 开两次
`ZipFile`、`verify_compilation` 每个 pass 重读全部 `.java`。改动面大且缺真实大
语料基准，按「不交付未经验证的半成品」口径本轮不动，仅记录为后续候选。
`web.py:244` 的 `timeout=15` 与同类 1800s 相差 120 倍，同属需基准后评估项。

### 11.3 复验

| 门禁 | 结果 |
| --- | --- |
| `python -m ruff check .` | 全树通过 |
| `run_tests.py`（`JDEC_GHIDRA_SMOKE=1` + `GHIDRA_HOME`） | **1357 断言 / 0 失败 / 158 用例**（§10.4 的 1326 / 156 是上一轮时点值） |
| 真实 Ghidra headless 冒烟 | 6 条全过，含「headless 确实跑完」与 `bad_mapping_lines = 0` |
| 04 完整复跑 | **8/8 PASS / 87 项**；报告 `url` 恢复为字符串类型，8 类 metrics 与 sha256 逐字不变；`url` 取值与权威存档不同，见 §12 |
| wheel 解包自查 / 两个 selfcheck / `git diff --check` | 全过；`docs/STAGE04_REPORT.json` 未改 |

README 的回归基线、`docs/SUPPORT_MATRIX.md` 的当前值注记、§2 / §3 / §7 的
时点标注已同步。`docs/ROADMAP.md` 仍未改动（修订纪律），其 `:516` 的 Maven
Central 表述与本轮实测不符，仍待用户拍板。

## 12. 返工复核记录（2026-11-07 第三轮）

用户要求「再返工一次，防止出错」。本轮不新增能力，改为**对抗性复审 + 兼容性
验证**：以找 bug 为目标独立审查前两轮 diff，并补干净安装 / 跨版本检查。

### 12.1 复审发现并修复

| # | 问题 | 修复 | 证据 |
| --- | --- | --- | --- |
| 1 | **`0X` 前缀残留**（P1）：Python 正则接受大写 `0X`，Java worker 的 `replace("0x","")` 只剥小写，`Long.parseLong("0X1a",16)` 抛异常 → 行被静默丢弃，正是 P0 要消灭的失败；上一轮测试还把 `0X1a` 断言成「Java 可解析」，把错误契约固化 | 归一化漏斗新增 `_canon_hex()`，输出前把 `0X` 规范成 `0x`；worker 改 `replaceFirst("(?i)^0x","")` 双保险；测试改为断言规范化结果且输出无 `0X` | 新增 2 条断言；真实 Ghidra headless 冒烟复验 |
| 2 | **假 behaviour-parity**（P1）：`BH.compare` 把 classpath 追加到**两侧** loader，而 `_run_evidence` 把原始 jar 也放进去；重编译 jar 缺类时 right loader 回退到原实现 → 判 `same` → 错误升级证据等级 | 拆成 `verify_cp = [raw] + libs`（需要解析父类型）与 `libs_cp`（compare 专用，不含 raw）；新增 mock 测试断言 compare 的 classpath 不含 raw、仍含 libs | `test_evidence_compare_classpath_excludes_original` 4 条断言 |
| 3 | `fetch_lwjgl` 遇同名目录时 `unlink()` 抛未捕获 `IsADirectoryError` | `_valid_artifact` 先 `is_file()`；目录给明确 `RuntimeError` 而非 traceback | 新增同名目录负控 |
| 4 | 冒烟测试硬编码 `D:/` 本机路径、缓存断言是同一路径自比恒真 | `JDEC_NATIVES_DIR` 改为显式必填；用下载计数器断言「两个工件各下一次、命中缓存后不再下载」 | 新增 2 条有效断言 |
| 5 | README 引导语把 GitHub 与 PyPI 并列不准（GitHub 相对链接有效，PyPI 才 404） | 措辞改为区分两者 | `test_readme_doc_links` 保持全绿 |

### 12.2 口径纠偏（文档，不改代码）

- §10.1 曾写「坐标与报告 sha256 不变」、§11.1 写「与 §10.1 坐标不变矛盾」，
  均不精确：**坐标与 sha256 确实不变，变的是报告 `url` 字段的类型（数组→字符串）
  与取值（Maven Central → Mojang 源）**。新报告与权威存档并非逐字一致，已在
  §10.1 / §11.1 / §11.3 分别加注。
- §10.1 的「缺 spec 不执行目标代码」是时点结论；§11.1 补的 `--execute`
  授权闸已加注，避免读者低估风险。
- §2 的「frida 目录零覆盖」收窄为「目录级 / 端到端仍无覆盖」（现有函数级断言）；
  §4 / §9 补完成状态注记，历史原文保留。

### 12.3 防失步纪律

根 `README.md` 与 `docs/SUPPORT_MATRIX.md` 不再写死「当前」回归数字，改为**以
`run_tests.py` 输出为唯一来源**（§5 新增第 7 条纪律）。此前两轮每次加测试都要
同步三处数字，已实际发生过一次失步；现在文档只保留带日期的时点快照。

### 12.4 兼容性核查（无问题）

- Python 3.10 语法 / API：`Path.open(newline=)`、`Path.replace`、`unlink(missing_ok)`、
  局部注解 `X | None` 均可用，无 `removeprefix` / `tomllib` / `except*` / `match`
  等 3.11+ 特性；`pyproject.toml` 的 target-version 已是 py310。
- Ghidra 11.0.3 需 JDK 17，`isBlank()` / `strip()` / `stripLeading()` 为 Java 11 API，
  CI 的 JDK 21 满足。
- CI 五 job 未写死用例数；`MECHANISMS==8` / `negative_controls==2` 与本轮正交；
  无新增模块，wheel 白名单仍覆盖；`test_stage04_lwjgl_fetch_hardening` 的
  `mock.patch` 在串行测试内退出即恢复，不污染同进程。
- `docs/ROADMAP.md` 相对 HEAD 仍只有补记（七）+24 行，状态列 / 02 门槛 / 411 分母 /
  独立研究线边界 / 修订纪律未动；`docs/STAGE04_REPORT.json` 未改。

### 12.5 仍开放

- 〔已处理 2026-11-07，用户拍板〕`docs/ROADMAP.md:516` 的 Maven Central 表述
  已由「补记（八）」作事实修正（历史原文保留，仅加一条指向注记）；`:353-354`
  的「当前 1302/152」确认为 11-06 时点快照，按 §5.7 不再维护「当前值」。
- 〔已处理 2026-11-07〕`docs/RESEARCH_LINE.md` 已 `git add` 纳入版本库，不再是
  未跟踪文件；本轮仍不代为提交。
- `JDEC_GHIDRA_SMOKE` / `JDEC_NATIVES_DIR` 未设置时，冒烟用例跳过且 0 断言——
  这是**有意**的可选门禁（CI 恒不红），代价是该用例在 CI 里空转，已在 §10.2 说明。
- P1 / P2 授权样本仍缺，端到端不可验；§11.2 列出的大重构仍未做（缺基准）。

### 12.6 本轮复验（时点快照，按 §5.7 以运行器输出为准）

- 全套回归（`JDEC_GHIDRA_SMOKE=1` + `JDEC_NATIVES_DIR` + `GHIDRA_HOME`）：
  **1365 断言 / 0 失败 / 159 用例**，含真实 Ghidra headless 冒烟 6 条全过
  （worker 改 `replaceFirst` 后复验）。
- 04 完整复跑：**8/8 PASS / 87 项**，报告 `url` 仍为字符串；
  `docs/STAGE04_REPORT.json` 的 `git diff` 为空。
- 干净 venv 从 wheel 安装：`normalize_mappings_file` / `_canon_hex` /
  `_valid_artifact` / `_run_evidence` 均可导入，`0X` 规范化在安装包里生效，
  `jdec.stage04` / `jdec.support_matrix` 的 `--help` 正常。
- Python 3.10 语法兼容 67 个文件；无 Ghidra 的 CI skip 路径 0 失败；
  ruff、wheel 解包自查、两个 selfcheck、`git diff --check` 全过。
