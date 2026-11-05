# 复现基准与口径

本文档只做一件事：把「数字是怎么来的」写成别人能执行的命令。它**不改变任何
结论**——`docs/ROADMAP.md` 的阶段状态、门槛与分母按 2026-10-31 的拍板保持原样。

## 为什么需要一份复现说明

`docs/README.md` 里几组头条数字（HMCL 3.15.2 的 411 个改写方法、原版 MC 1.8.9、
Flux）来自**外置且需授权**的语料，仓库里不放样本。第三方无法直接重跑，只能阅读
口径。为此提供两层：

1. **内置生成式基准**：一键、无外置样本、带负控，任何人都能验证门禁本身工作。
2. **外部语料模式**：把 83.0% 那条测量所需的输入与 classpath 逐项列清楚，
   有授权样本的人可以照着复现，报告里会记录完整命令与环境。

内置基准**不是** 411 全集的替代品：它是门禁的确定性冒烟回归，不能用来声明
能力上限，更不能用来主张 02 门槛达标。

## 一、内置生成式基准

需要 JDK 9+（`javac` 在 `PATH` 或 `JAVA_HOME`）。脚本内嵌 Java 源码，编译两份
jar（原版 / 只改了一个常量的负控版），从 class 文件解析出全部方法作为改写清单，
再跑与线上完全相同的 `behave --engine both` 门禁：

```bash
python src/tests/benchmark.py                       # 打印摘要
python src/tests/benchmark.py --json bench.json    # 附完整报告
python src/tests/benchmark.py --workdir out/bench  # 保留生成的 fixture
```

当前基线（HotSpot 21 / manager 后端）：14 个生成方法（含 1 个实例方法，
验证解释器的 stand-in 接收者），union 14/14 判定、
0 差异；负控必须报 DIFF。**100% 是设计结果**，因为 fixture 全是纯函数——它证明
的是管线连通与门禁不恒真，不是「能判定任意字节码」。

两次比较的语义：

| 比较 | 期望 | 若失败说明什么 |
| --- | --- | --- |
| 原版 vs 原版 | exit 0、0 差异、union 判定数 > 0 | 门禁或引擎坏了 |
| 原版 vs 负控版（改了一个常量） | exit 1、有差异 | 门禁恒真，所有「相同」都不可信 |

`--json` 报告记录：Python / JDK 版本、隔离后端、git commit、完整命令行、
两次比较的 stdout 全文、union / union value / diff 数、负控是否检出、verdict。
`src/tests/run_tests.py` 的 `test_benchmark_is_reproducible` 会把它跑一遍并断言
这些不变量，所以基准本身受回归保护。

## 二、外部语料：83.0% 的逐字口径

这一节描述 `docs/ROADMAP.md`「02 的判据与实测」第五轮（2026-10-31）的数字，
**不是** `docs/README.md` 表格里 03 专项试用版的 90.0% / 91.2% / 87.9%
（那是另一套 judged union 口径与语料）。

- 语料：HMCL 3.15.2（自解压 exe，需自备并确认授权）
- 分母：**411 个改写方法**（`deflat` 的 `--rewritten` 清单，不是全 jar 方法数）
- 结果：JVM 判定 251 + 解释器判定 252，**并集 341/411 = 83.0%**，0 个真实差异
- 环境：HotSpot 21、`behave --engine both`、manager 隔离后端
- **classpath 是口径的一部分**：必须带 JavaFX 依赖。漏带 `--cp` 会复现出
  76.4%；带齐 `javafx-base` / `javafx-graphics` / `javafx-controls` 才逐字
  复现 83.0%。这不是可调参数，是 `Hierarchy` 能否见到库父类的前提。

复现命令（`;` 在 Windows 上用 `;` 作 classpath 分隔符，POSIX 用 `:`）：

```bash
python jdec.py deflat HMCL-3.15.2.exe -o hmcl_deflat.jar \
    --rewritten rw.txt --cp "<javafx 依赖，按平台分隔符>"

python jdec.py behave HMCL-3.15.2.exe hmcl_deflat.jar \
    --derive --from rw.txt --execute --engine both \
    --cp javafx-base.jar --cp javafx-graphics.jar --cp javafx-controls.jar
```

或者直接让基准脚本生成同样的报告（外部模式不做负控，也不修改输入）：

```bash
python src/tests/benchmark.py \
    --original HMCL-3.15.2.exe --rewritten hmcl_deflat.jar --from rw.txt \
    --cp javafx-base.jar --cp javafx-graphics.jar --cp javafx-controls.jar \
    --json hmcl_bench.json
```

注意 `--derive` **必须**带 `--from`：`cases.derive()` 只处理清单里点名的方法，
传 `None` 会得到 0 个用例、退出码 4「没有结论」，而不是「全 jar 派生」。
需要整 jar 清单时用 `src/tests/benchmark.py:method_rows()`。

## 三、90% 门槛：2026-10-31 收口，2026-11-04 重启冲刺

**历史结论（保留）**：02 自定的硬门槛是「限定转换的行为对拍并集 ≥ 90%」。
2026-10-31 对剩余 70 个未判定方法做过逐条归因（17 个定义上不可测、20 个硬环境、
约 9 个贵深层、约 24 个理论可榨），结论是过线需 29 个新判定且几乎全中，概率
10–20%，当时判为「02 内不可达」并拍板「接受 83.0% 收口进 03，不修改门槛与分母」。

**本轮变更（2026-11-04 用户拍板）**：推翻上述**收口决定**，改为实际去推 90%；
但 **90% 门槛与 411 分母一律不变**，不采纳 ROADMAP `:200-203` 里「改写成可调用
集合 ≥90%」那条备选。`docs/ROADMAP.md` 的修订纪律仍适用：该文件只在用户拍板时
修改，本轮授权的是「推 90%」与「修正 03 备注措辞」，不是「标达成」。

不变量（重启后同样成立）：

- 本仓库**不宣称** 02 达标，状态列仍为「进行中」，除非实测达标且另行拍板；
- 内置基准的 100% 与 411 全集的 83.0% 分母不同，不可互相替代或对比；
- `docs/README.md` 表格里 03 三语料的 90.0% / 91.2% / 87.9% 是**另一套 judged
  union 口径**，不得拿来宣称 02 达标；
- 换隔离后端会改变 `denied` 与 union 口径（见 `docs/README.md` 的隔离章节），
  上表数字均来自 manager 后端（HotSpot 21），换后端后必须重新测量，不能直接引用。

## 四、02 的 90% 重测（命令与判据；数字待回填）

**口径前提**：固定 HotSpot 21 / manager 后端（本机 JDK 21）；411 分母来自
`deflat --rewritten` 清单；三个 JavaFX jar 必须齐备且记录在案。**JavaFX 的版本与
平台 classifier 从未写死，是口径的一部分**：从 Maven Central 下载后须把版本、
classifier、sha1、下载路径写入报告。第一步先按上一节命令校准基线——带齐 `--cp`
应逐字复现 83.0%；若因版本差异复现不出，如实记录差异，后续数字标注该口径，
**不硬凑、不用内置 100% 或 03 语料 90.0% 代填**。

HMCL 3.15.2 沿用 03 阶段既有的用户授权前提，文件不入库（`docs/README.md:735`
只分析自有或已授权程序）。

重测命令（在上节 `--cp` 基础上加 `--union-gate 90`）：

```bash
python jdec.py behave HMCL-3.15.2.exe hmcl_deflat.jar \
    --derive --from rw.txt --execute --engine both \
    --cp javafx-base.jar --cp javafx-graphics.jar --cp javafx-controls.jar \
    --union-gate 90

python src/tests/benchmark.py \
    --original HMCL-3.15.2.exe --rewritten hmcl_deflat.jar --from rw.txt \
    --cp javafx-base.jar --cp javafx-graphics.jar --cp javafx-controls.jar \
    --json hmcl_bench.json
```

**达标判据（全部满足才算）**：`union N/411 且 N ≥ 370`（411×0.9 = 369.9）、
0 个真实差异、`--union-gate 90` 退出码 **0**（不是 1/4/5）、负控全绿
（改常数必 DIFF、原版×原版必 same、污染必 inconclusive）、分母来自 `--from`
清单且未改动。

**收尾**：达标则把 N/411、完整命令、环境、commit、json 路径写回本节与
ROADMAP 新增节，**状态列是否推进仍需另行拍板**；未达标则保留退出 5，记录实测
百分比与更新后的剩余归因，`docs/REACHABILITY_02.md` 给出条件式结论，02 仍
「进行中」；04 为部分交付、状态列「进行中」，不改变 02 结论。

**实测记录（2026-11-04，HotSpot 21 / manager 后端 / git `035ba13`）**：
JavaFX 21-`win` 三个 jar（sha1 见仓库外 `jdec_javafx/javafx_manifest.json`）；
`deflat` 产出 411 个改写方法、3693 类 verify 全过；
`union 342/411 = 83.2%`、`union nodeny 341/411 = 83.0%`（与历史基线一致）、
`union value 143/411 = 34.8%`；**1 个真实差异**；
`--union-gate 90` 打印 `342/411 = 83.2% (threshold 90%)`，退出码 **1**
（diff 优先于门槛的 5）。**未达标**，还差 28 个判定，且本轮能力改造净增 0。
完整报告见仓库外 `jdec_hmcl/hmcl_bench.json`（含命令、环境、stdout 全文），
归因与结论见 `docs/REACHABILITY_02.md`。因版本/classifier 与历史记录
（从未写死）可能不同，且出现 1 个差异，本次结果标注为该口径下的实测值，
**不宣称「0 差异」，也不宣称 02 达标**。
