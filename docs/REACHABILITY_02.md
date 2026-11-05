# 02 的 90% 可达性重评估（2026-11-04）

本文件回答「做完 04 有没有希望做完 02」。结论按**实测**给出，不用推测填数字。
门槛 90% 与分母 411 全程未改；`docs/ROADMAP.md` 的 02 状态列仍为「进行中」，
04 已于 2026-11-05 完成（但对 02 无直接帮助，见第 1 节）。

## 0. 结论（2026-11-04 实测，非推测）

**按当前证据，04 做完并验收后，02 仍然没有希望达标。** 带齐 JavaFX `--cp` 的 HMCL 411
方法重测得到 `union 342/411 = 83.2%`（`union nodeny 341/411 = 83.0%`），
`--union-gate 90` 阈值未达、退出码 1、且有 1 个真实差异。需要 ≥370/411，
**还差 28 个判定**（nodeny 口径差 29）。与 2026-10-31 第五轮的 83.0% 相比，
本轮 A 类改动在真实语料上**净增 0 个判定**；04 的两项交付也没有产生任何
新判定（理由见第 1 节）。命中第 5 节的**分支 C**：未达标，02 仍「进行中」，
不标 ✅，状态列不推进。

## 1. 先说结论：04 的交付不提供 02 所需的实质条件

| 04 交付 | 对 02 的作用 |
| --- | --- |
| 离线引擎包 / 断网 CI | **无直接帮助**。它管的是 CFR / Vineflower / Procyon 三个反编译 jar；`behave` 用的是自编译 `JdecBehaveDriver` 与纯 Python `src/jdec/interp/`，两条路径不相交。断网 CI 只跑 `engines` / `ircheck` / `verify`，不跑 `behave` |
| 支持矩阵（已完成，8 类机制 + 双独立语料回归 8/8 PASS） | 间接有用：把「机制 → 支持项 → 样本 → 用例 → 证据等级」显式化，正好是剩余 70 个方法逐条归因所需的结构。但它本身不产生任何 `behave` 判定，因此不改变 342/411 |
| 03 备注措辞修正 | **关闭了一条路径**：ROADMAP `:200-203` 里「03 的沙箱先把那 71+46 个方法变成可执行」不再成立，因为 03 实际交付的是 Java 级 SecurityManager，用户/容器级边界明确未纳入。02 不能靠它达标 |

实质条件只有两个：**解释器 / 重放能力改造**（本文件第 3 节）与
**HMCL + JavaFX 的 `--union-gate 90` 重测**（第 6 节）。

## 2. 算术与既有归因

- 411 × 0.9 = 369.9 → 达标需 **union ≥ 370/411**；
  2026-10-31 第五轮为 **341/411 = 83.0%**，净增 **≥ 29**，且必须 0 个真实差异。
- 剩余 70 个（ROADMAP `:175-181`）：17 个定义上不可测
  （ctor / `<clinit>` / 抖动 / native / JNA）、20 个硬环境
  （GUI 框架态 / 网络 / 线程）、约 9 个贵深层（gson / javafx 深解析）、
  约 24 个理论可榨（上限约 30）。
- 当时评估：过线需 29 个新判定且几乎全中，**概率 10–20%，02 内不可达**。
- 02 文档反复写「再往上需要 03 的真实沙箱或 JavaFX 运行时」
  （`:152-153`、`:172`）。其中 JavaFX 是 HMCL 语料 `--cp` 上的外部依赖，
  属测量口径而非阶段交付；03 的沙箱路径已在第 1 节关闭。

## 3. 本轮 A 类改动（仓库内实测）

| 改动 | 仓库内证据 |
| --- | --- |
| 解释器普通实例方法改用确定性 stand-in 接收者（原来 `receiver=None`，任何 `aload_0` 都判不了） | `src/tests/benchmark.py` 生成 fixture 加入实例方法后，**14/14 判定、0 差异、负控检出 DIFF** |
| `cases.MAX_ARITY` 8 → 10 | 只增加可派生用例数；`test_union_denominator_guard` 断言 `coverage()` 仍按 `(class, method)` 去重、union 分母仍来自 interp rows、门禁仍与 `args.union_gate` 比较 |
| `benchmark.py --union-gate` 可配（默认 0） | 使 90% 重测与内置基准共用同一套门禁与负控 |
| 离线引擎包 + 断网 CI | 本地断网等价验证：三引擎 available、ircheck/verify PASS、篡改负控 exit 1；回归新增 8 条断言 |
| 分母护栏 / 03 措辞 / 支持矩阵 / 复现文档 | `git diff --check` 干净；ROADMAP 只改 `:223-225` + 新增节 |

**回归 1176 断言 / 0 失败**，ruff F/E9/B、skill self-test、干净 venv wheel 门禁全过。
这些是**门禁自身的回归证据**，按 ROADMAP `:226-227`、
`docs/REPRODUCE.md:16-17` 与 `src/tests/run_tests.py:4023`，
**不得用来主张 02 门槛达标**；内置 100% 与 411 全集分母不同，不可互相替代。

## 4. 未完成的技术路径（如实列出，不粉饰）

计划中列过但本轮**未实现**，因此不声称它们带来了任何新判定：

- 解释器读取 `--cp` jar 的**只读第三方父类链**（对应约 9 个贵深层方法）。
  需要一个只提供类型信息、绝不执行第三方字节码的 `Universe` 路径；
  若顺手建模第三方库行为，「0 差异」会退化成模型自证，违反
  `src/jdec/interp/values.py` 的 Opaque 污染纪律。
- `interp/models.py` 的 Files 深层 API（`find` / `walkFileTree` / 属性视图）、
  Stream / Optional / Collections 面扩容，以及 `behave.py` 的 `DRIVER_JAVA`
  接收者构造深度与参数 token 扩充。
- `sandbox.py` 的只读白名单与每方法级超时。
- `benchmark.py` external 模式的外置负控（需 B 类改写产物）。

原因：这些改动覆盖面大、需要逐个负控，而**没有 HMCL + JavaFX 重测就无法
衡量收益**；与其交付未经验证的半成品，不如把边界写清楚。

## 5. 条件式三分支

| 条件 | 结论 |
| --- | --- |
| B 类材料未到位 / 基线校准失败 | 02 达标与否**不可判定**，状态列保持「进行中」 |
| 重测 `union ≥ 370/411`、0 差异、`--union-gate 90` 退出 0、负控全绿 | 达标；记录数字与文档，**状态列是否推进仍需另行拍板**（修订纪律 `:240`） |
| 重测 `< 370/411` | 用实测剩余清单更新归因，写明还差几个、卡在哪个 API；02 仍「进行中」，不标 ✅ |

**本轮命中第三分支**。达标判据逐项：union 342 < 370 ✗；0 差异 ✗（实测 1）；
`--union-gate 90` 退出 0 ✗（实测 1，diff 优先于门槛的 5）；负控全绿 ✓
（内置基准）；分母 411 未改 ✓。

## 6. 实测记录（重测后回填）

| 项 | 值 |
| --- | --- |
| JavaFX | 21 / `win`；`javafx-base-21-win.jar` (754314 B, sha1 `a7e334fbb619…`)、`javafx-graphics-21-win.jar` (5918786 B, `8083d97ea236…`)、`javafx-controls-21-win.jar` (2585101 B, `76e295d84578…`)；完整 sha1/sha256 与 URL 见仓库外 `jdec_javafx/javafx_manifest.json` |
| HMCL | `D:/MC/HMCL/HMCL-3.15.2.exe`，沿用 03 阶段既有用户授权前提，不入库 |
| 环境 | HotSpot 21 / manager 隔离后端 / git `035ba13` |
| `deflat --rewritten` | **411 个改写方法，3693 类，verify 全过**；分母与 ROADMAP 完全一致。另报 32 个类型不在 classpath（`com/sun/javafx/.../skin/*`），帧合并时退化为 `Object`，但 0 拒绝 |
| 基线校准 | `union nodeny 341/411 = 83.0%`，与 2026-10-31 第五轮**逐字复现**；`union 342/411 = 83.2%` 多出的 1 个是 denied-only（沙箱拒绝证据） |
| JVM / 解释器 | coverage `301/411 = 73.2%`；interp `216/411 = 52.6%`（87 value / 129 throw） |
| `behave --engine both` union | **342/411 = 83.2%**；`union value 143/411 = 34.8%` |
| 真实差异 | **1 个**（`org.jackhuang.hmcl...DataPack.installPack` 两侧抛不同异常；另解释器侧 `RadialGradientSpec.resolve` 报 throw-vs-return）。与历史「0 差异」不符，原因未定位（可能是 JavaFX 版本差异或类加载顺序抖动），**不宣称 0 差异** |
| `--union-gate 90` 退出码 | **1**（`union gate : 342/411 = 83.2% (threshold 90%)`；因有 diff，退出 1 而非门槛的 5） |
| 报告 | 仓库外 `jdec_hmcl/hmcl_bench.json`（含完整命令、环境、stdout 全文）；`jdec_hmcl/baseline.txt` |
| 结论分支 | **分支 C：未达标**，净增 0 |

**口径纪律**：JavaFX 版本/classifier 从未在历史文档写死，是口径的一部分；
若带齐 `--cp` 仍复现不出 83.0% 基线，必须如实记录差异并标注，
不得硬凑；`docs/README.md` 里 03 三语料的 90.0% / 91.2% / 87.9% 是另一套
judged union 口径，**不得**拿来宣称 02 达标；换隔离后端的数字不可直接比较。

## 7. 本次重测给出的剩余归因（比 ROADMAP 更具体）

`interp` 侧 195 个 inconclusive 不再是「Files 深层 API / 环境未知量」这类
粗分类，而是可以直接照着补模型面的 API 清单（节选，完整输出在
`jdec_hmcl/baseline.txt` 与 `hmcl_bench.json`）：

| 次数 | 卡点 |
| --- | --- |
| 17 | `static state depends on an unmodelled call` |
| 12 | `result depends on an unmodelled call` |
| 4+2+1 | `cannot append this value to a StringBuilder`（Opaque 拼接） |
| 3 | `java/lang/String.contains` 返回 Opaque 却用于分支 |
| 2 | `javafx/scene/input/KeyCode.values()` 未建模 |
| 2+2 | `java/nio/file/spi/FileSystemProvider.installedProviders` 未建模 |
| 2 | `java/lang/Runtime$Version.feature` 返回 Opaque |
| 2 | `java/lang/Boolean.booleanValue()` 返回 Opaque |
| 2 | `java/util/ArrayDeque.isEmpty()` 返回 Opaque |
| 72 | 原版自身两次跑都不一致，被稳定基线丢弃（定义上不可判定） |

另有 `instance method on an abstract type` 等派生侧拒绝。这些是**下一步
具体该补什么**的证据；但按 ROADMAP `:175-181` 的评估，即便把它们全补上，
仍需 29 个新判定几乎全中，且必须先解决那 1 个真实差异，
所以「02 内可达」的结论没有被本次重测推翻。
