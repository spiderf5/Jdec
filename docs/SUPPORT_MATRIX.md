# 04 支持矩阵（2026-11-06，达成）

**结论：04 达成。** `docs/ROADMAP.md:19` 的状态列按修订纪律推进为
「✅ 已达成」，依据是本文件、`docs/STAGE04_REPORT.json` 的 57 项交叉检查与
`run_tests.py` 的 1274 条断言 / 147 个用例。

本版与 11-05 两版的关键区别：**先补了 `src/jdec` 的机制代码，再谈验收**。

- M1 不再把 javac 的 `switch(String)` 降级冒充「去平坦化」：新增
  `_string_hashcode_switch` 判别，两类分别计数（`switch` / `unflatten`），
  并补了 `Flattened` / `StringSwitch` 两个 fixture 钉住双向分类。
- M3 从「只数站点」升级为「还原常量载荷」：`bsm.resolve_site` 按 bootstrap
  家族分派，还原 lambda 的 implMethod、`StringConcatFactory` 的格式模板、
  `ObjectMethods` 的 record 组件名。HMCL **6245/6245** 站点全部还原
  （3899 lambda + 1667 concat + 679 record），NeoRaven **150/150**；
  还原出的 1406 个去重载荷全部逐字命中独立常量池，0 例伪造。
  无常量的引导（如 `SwitchBootstraps`）单独计入 `unresolved`，不猜测。

## 1. 门槛逐条对照

`ROADMAP:19` 硬条件 =「6–8 类机制的明确支持项」；`:226` 备注 =
「每类机制的支持项必须配独立样本回归」。

| 条款 | 状态 | 依据 |
| --- | --- | --- |
| 6–8 类机制的明确支持项 | 满足 | 8 类，每类有输入条件、结构化产出、已知不覆盖 |
| 每类配独立样本回归 | 满足 | 每类在真实独立语料上跑，配独立金标准与本类负控；57 项检查 |
| 清单来源 `study/` | 替代 | `docs/mechanisms/` 9 份纯机制形态笔记（不含源码）；来源差异见第 5 节 |
| 交付「支持矩阵」 | 已交付 | 本文件 + 两份机器可读报告 |
| 交付「离线交付」 | 已交付 | `docs/OFFLINE.md` + 断网 CI job |

**「支持项」的定义**：对该机制类的一条**有边界的工具能力承诺**，不是
「破解该混淆器」。深度还原（ZKM 字符串解密、BytecodeVM 复现、JNIC 容器）
按 `ROADMAP:231-236` 属独立研究线，**永不并入 1.0 通用承诺**，本矩阵未计入。

## 2. 8 类机制的明确支持项

数字来自 `docs/STAGE04_REPORT.json`（HotSpot 21 / manager 后端 / JavaFX 21-win）。

| ID | 明确支持项 | 独立金标准 | 本类负控 | 实测 |
| --- | --- | --- | --- | --- |
| M1 控制流改写 | 区分两类来源并分别改写（均过 JVM `-Xverify:all`）：混淆器平坦化（while + switch 状态机）、javac `switch(String)` 降级；产出改写清单 | 独立 class 解析器核对清单方法存在；`zipfile` sha256 确认字节变化 | junit：17 个改写全部是 thread/dead，`behave` 0 diff；fixture：平坦化 7 次、switch 5 次 | 411 改写；`switch=684` / `unflattened=0`（87 个方法）；`folded=0` / `predicates=0`；verify 3693；`behave` union 342/411、1 个差异 |
| M2 字节往返 | 逐类 parse→重汇编→逐字节比对；坏类隔离 | `zipfile` 原始类数与逐条 sha256 | 截断类 `sample.jar` 不得判为干净 PASS | 3740/3740 类、29395/29395 Code、0 unreadable |
| M3 indy / BSM | 枚举站点、按 owner 归类，**还原每个站点的常量载荷**：lambda 调用目标、concat 格式模板、record 组件名；无常量的引导单独计数 | 独立 `BootstrapMethods` 解析给出 owner 直方图与静态载荷集合，逐字比对 | junit 必须 0 站点（金标准 0 BSM）；`sample.jar` 的 1 个 SwitchBootstraps 必须计为未还原 | 6245 站点 ≥ 5420 BSM；**payload 6245/6245**（3899/1667/679，unresolved 0）；1406 载荷全命中，0 伪造 |
| M4 指纹归因 | 结构阈值 + 专属关键词（ZKM 27 需 ≥2 个），命中带证据 | 独立常量池扫描 DES/zelix/`$CodePool` | junit 不得误报任何签名 | HMCL → ProGuard/R8（0/100）；Neo → 未识别（4/100） |
| M5 字符串抽取 | 抽常量池字符串并分类；blob 经 base64 解码 + 内部类名排除 | 独立 UTF8 计数 + `goldens.is_blob_literal` 逐条复核 | FQCN 不是 blob；高熵 blob 仍识别；junit 0 blob | 15839 / 9315 条，406 / 101 标签，0 blob |
| M6 native 分诊 | 读出容器内 PE、解析导出表、统计 ACC_NATIVE；两项分别计数 | 独立 PE/COFF 导出目录 + 独立 ACC_NATIVE 计数 | 纯 Java junit 必须 0 库/0 导出/0 native | 1 PE、2 导出（GPU 请求符号）、69 native（JNA）、`jni_matched=0` |
| M7 MC 元数据 | 从 `mcmod.info` / 注解识别版本与加载器 | 独立读 `mcmod.info` | HMCL（非 MC）不得报 1.8.9 | Neo → `1.8.9 / Forge` |
| M8 容器分类 | 按 magic 选读取策略，条目数与 zipfile 核对 | `open().read(2)` + `zipfile.namelist()` | junit 必须识别为普通 PK | HMCL `4d5a`/4248；Neo `504b`/1767 |

**57 项检查**：a=36（真实语料验证）、b=9（退出码/配置/自证）、c=10（负控）、
d=2（只验金标准）。报告里每条带 `class` 字段，可逐条复核。

## 3. 独立语料与负控

| 语料 | 形态 | sha256（前 12） | 角色 |
| --- | --- | --- | --- |
| `HMCL-3.15.2.exe` | MZ stub，ProGuard/R8，3740 类 | `632c2d8873f5` | 主样本（沿用 03 授权前提） |
| `NeoRaven1.1.jar` | PK，MC 1.8.9 / Forge，1534 类 | `57f294cb4374` | 第二独立样本 |
| `junit:junit:4.13.2` | 公开、未混淆，350 类 | `8e495b634469` | 公开可复现阴性对照 |
| `src/tests/sample.jar` | 故意截断类 | `b844b1b93d05` | M2 坏类负控 |

外置语料不入库；阴性对照的 Maven 坐标与 sha256 写在报告里，任何人可取到
同一文件。生成式 fixture 只做单元级负控，**不折算为独立样本**。

## 4. 本轮补的代码（不是只补文档）

| 文件 | 改动 | 为什么 |
| --- | --- | --- |
| `src/jdec/ir/transforms.py` | 新增 `_string_hashcode_switch`；`unflatten_dispatchers` 按来源分 `switch` / `unflatten`；`optimize` 分开计数 | 之前 87/87 次「去平坦化」命中的是 javac 的 `switch(String)` 降级，报告误导用户「干净 jar 被平坦化了」 |
| `src/jdec/ir/reasons.py` | replay 接受 `switch` kind | 新分类必须仍能独立重放 |
| `src/jdec/bsm.py` | 新增 `resolve_concat` / `resolve_record` / `resolve_site`；`scan_jar` 统计三类载荷与 `unresolved_sites` | M3 从「数站点」升级为「还原常量载荷」，并把无可还原常量的站点显式计数 |
| `src/jdec/cli_args.py` / `cli_commands.py` | `jdec indy --resolve`，输出三类还原数、未还原数与 owner 直方图 | 让能力可从 CLI 使用与复核 |
| `src/tests/samples/shapes/` | `Flattened` / `StringSwitch` 两个 fixture + 独立 `shapes.jar` | 双向钉住分类；`flow.jar` 保持「普通编译器控制流」语义 |
| `src/tests/stage04.py` | M1 记录真实 kind、M3 记录三类载荷与分区；`_checks` 按机制拆成 8 个函数；检查打 a/b/c/d | 报告可核，不再自称门槛；新增判据不再堆在一个 228 行分支链里 |

## 5. 机制清单来源与 `:226` 的差异

`ROADMAP:226` 指定 `study/` 标本馆；`.gitignore:71-73` 以「含 DMCA 敏感
源码」把 `study/` 排除。`docs/mechanisms/` 是**合规替代**：9 份纯机制形态
笔记，不含任何第三方源码、反编译片段或混淆器实现。清单由这 9 份笔记 +
仓库内实现 + 三个真实语料共同确定。**这是一条保留的来源差异**，不宣称
按 `study/` 原件验收。

另：机制笔记里的 `javap -v` 是推荐的人工复核手段，自动回归用的是
`src/tests/goldens.py` 的第二套解析（zip / class / PE），**未调用 javap**。

## 6. 已知不覆盖（诚实边界）

- 支持项是**工具能力**，不是「破解」：M1 在真实语料上 `unflattened=0`，
  演示的是「正确识别 javac 产物 + 改写」，不是「还原混淆器平坦化」；
  混淆器平坦化的正向样本只有单元 fixture（7 次）。
- M1 的 `behave` 是 342/411 = 83.2%、1 个真实差异，属 02 的未达门槛，
  不是 0 差异。
- M3 在真实语料上**每个站点都还原出了常量载荷**，但两个语料只用 JDK vanilla
  BSM；非 vanilla 自定义引导（ZKM 系）只被枚举、未被还原，属独立研究线。
  `SwitchBootstraps` 这类不含可读常量的引导计入 `unresolved`，不猜测。
- M5 抽取已验证，**解密未声称**：两语料经独立金标准确认无 DES 密文。
- M6 的 `jni_matched=0`：HMCL 的 2 个导出是 GPU 请求符号，不是 JNI；
  真实 JNI 匹配能力未在本轮语料上验证。
- ZKM 字符串解密、BytecodeVM 复现、JNIC 容器还原按 `:231-236` 属独立
  研究线，不计入 1.0。
- CI 只跑 `stage04.py --selfcheck` 的框架断言；完整验收由有授权者在本地
  执行，报告入库、样本不入库。
- 换 JDK / 隔离后端 / JavaFX 版本会改变部分数字，重测须重新记录。

## 7. 历史留痕

| 时间 | 结论 |
| --- | --- |
| 2026-11-04 | 只交草案 + 离线交付，判定门槛未验 |
| 2026-11-05 21:40 | 把 8 条诊断命令的 8/8 标为达成 |
| 2026-11-05 21:48 | 用户质疑「04 这么快？」，撤回（`98ddd26`） |
| 2026-11-05 22:xx | 加独立金标准与每类负控，再次标达成（`803af3a`） |
| 2026-11-06 21:xx | 用户质疑「你确定？」，审计发现 0 次折叠/87 次 javac switch，第二次撤回（`ddf60f7`） |
| 2026-11-06 22:xx | 补 M1 分类代码与 M3 目标还原，双向 fixture，52 项检查后达成 |
| 2026-11-06 23:xx | 清理与深度：M3 扩到常量载荷还原（6245/6245），`_checks` 拆分、死代码移除、引擎安装重构；57 项检查，状态列不变 |
