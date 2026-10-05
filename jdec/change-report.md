# 变更报告：修复大小写重名类被合并 + 局部失败被误判为整类失败

日期：2026-10-03
范围：`D:\MC\OpenCode\deobf\jdec`
工作流：backend-code-writer skill，Mode A（写代码）

## 任务目标

修两个在真实样本上被实测确认的缺陷：

1. ZKM 生成的只靠大小写区分的类名（`myau/A` 与 `myau/a`）在 Windows 上被合并，
   导致 86 个类丢失源码却被记为已恢复
2. 引擎只搞砸类内个别方法时，整个类被判为 `failed`

## 根因

### 缺陷 1：输出路径即身份

`_produced_set()` 用输出路径反推类名（`rel[:-5]`）。在大小写不敏感的文件系统上，
`myau/A.java` 与 `myau/a.java` 是同一个文件：

- 引擎写第二个时覆盖第一个 —— 源码在**引擎输出目录**里就已经丢了，`_collect`
  之后再怎么改都无法恢复
- 幸存的那份被同时记到两个类名下，被覆盖的类"凭空恢复"

实测：`Myau0729-obf.jar` 723 个类里有 **84 组冲突、170 个类（23.5%）**，
84 组字节**全都不同**（确实是不同的类）。修复前磁盘上只有 637 个独立源文件。

vanilla `client_1.20.4_deobf.jar`（7787 类）**0 组冲突** —— 原版混淆名几乎全小写。
所以这个 bug 只打 ZKM 这类混淆器，而 Linux 上不会复现（大小写敏感），这也是它
一直没被发现的原因。

### 缺陷 2：`hard_error` 是文本匹配，被当成整类失败

`score.py` 用正则找 `could not be decompile` 等字样，命中即 −45 分；
`decompile.py` 再把 `hard_error` 直接映射成 `failed`。但引擎把这行注释写在
**它搞砸的那一个方法**上：

```java
/*
 * This method has failed to decompile.  When submitting a bug report, ...
 */
public void X(...) { ...
```

`myau/Jz` 1474 行里只有 2 处这种注释、15 个方法签名全部还原，却因这两行注释
被整类判死。`unbalanced` 同理用绝对值（`abs(opens-closes) > 2`），
`myau/Jc` 570/574 的差异只是单个方法被截断。

## 改动清单

| 文件 | 改动 |
|---|---|
| `jdec/decompile.py` | 新增 `_case_collisions()` / `_safe_rel()`；冲突类从批量 pass 中排除，改为每类独立输出目录；状态判定改用 `class_level_failure` |
| `jdec/score.py` | 新增 `_hard_error_spans()`；`Quality` 增加 `class_level_failure` / `damaged_fraction`；`hard_error` 改为按覆盖比例扣分；`unbalanced` 改为按占比（>2%）判断 |
| `tests/run_tests.py` | 新增 3 个测试函数、17 条断言 |
| `tests/build_fixtures.py` | 新增 `_build_collide()` / `ensure_collide_jar()` |
| `tests/samples/collide_upper/demo/collide/Widget.java` | 新增（大小写孪生 fixture 之一） |
| `tests/samples/collide_lower/demo/collide/widget.java` | 新增（同上） |
| `README.md` | 补"大小写重名的类不会被合并"一节，修正判分粒度描述 |

未改动：`classfile.py`（round-trip 字节级一致断言不受影响）、`mappings.py`、
`probe.py`、`obf.py`、`analyze.py`。

### 关键设计决定

**输出路径用百分号编码大写字母**：`myau/A` → `myau/%41.java`。
`%` 不可能出现在 Java 标识符里，所以这个编码无歧义、可逆，且只作用于真正冲突的
类 —— 其余 553 个类的输出路径保持自然名字，不破坏既有产物。

**隔离而不是合并**：冲突组内每个类单独跑一次引擎。170 个类 = 170 次额外 JVM
调用，实测整轮仍为 174.6s（基线 130s，主要开销在 170 次 JVM 启动）。
换来的是类到文件的映射被显式携带，而不是从路径反推。

## 执行的命令与结果

| 命令 | 结果 |
|---|---|
| `python tests/run_tests.py` | 83 → **100 passed, 0 failed** |
| `python tests/run_tests.py --with-mc` | 99 → **116 passed, 0 failed** |
| `python jdec.py decompile Myau0729-obf.jar -o myau_fixed2 --verify-all -j 4` | **723 clean, 0 partial, 0 failed**，100% 成员覆盖，174.6s |

真实样本前后对比：

| 指标 | 修复前 | 修复后 |
|---|---|---|
| ok | 693 | **723** |
| partial | 27 | **0** |
| failed | 3 | **0** |
| 磁盘独立 .java | 637 | **723** |
| 成员覆盖率 | — | **100.0%** |

### 独立验证（不依赖 jdec 自己的评分）

- 84 个冲突组，两两 sha256 **全部不同**（`conflated: 0`）
- 抽查每个孪生对的源码对**自己**的字节码命中率：`A=17/17 a=26/26`、
  `D=48/48 d=12/12`、`F=10/10 f=13/13` —— 全部 100%
- 无任何类 score < 40

## 修复轮次

| 轮 | 内容 |
|---|---|
| 1 | 写失败测试（2 类 fixture）→ 复现：`Widget` 拿到 `widget` 的 body，2 条断言失败 |
| 2 | 实现隔离 + 编码路径 → fixture 转绿 |
| 3 | 全量 723 类：发现 failed 3→26。**排查后确认不是回归** —— 那 25 个类分数前后完全相同（58.2→58.2），只是首次被对上了自己的 body，从而暴露出内含的 give-up 注释 |
| 4 | 修缺陷 2（方法级归因 + 比例化括号）→ 723/0/0 |

第 3 轮是本次的关键判断：如果只看 failed 数字上升就回滚，会把一个**暴露既有缺陷**
的修复误判为引入缺陷。分数不变这一点是决定性证据。

## 自查发现的问题

**必修（已修）**

1. 我最初用 `Showcase$Rect` 写测试，coverage 恒为 0 —— 它是 record，
   `equals/hashCode/toString` 被 `synthesized` 排除，剩下 `h`/`w` 单字母成员
   又被自适应门槛过滤。**这是 fixture 写错，不是代码错**；改用 `demo/modern/Showcase`
   （7 个真实方法名）后通过。
2. 括号测试最初阈值设在 2%，而我的样本只有 7 个方法、1 个括号偏差 = 12.5%，
   必然失败。改为把类重复 20 遍构造大文件，让 1/N 成为真实噪声量级。

**说明**

3. 我的验证脚本一度报 26 个类 `MISSING FILE` —— 是我读了 `report.json` 里
   不存在的 `rel` 字段（该字段未被序列化），不是 jdec 的问题。改用与
   `_safe_rel` 相同的规则自行推导路径后确认文件都在。
4. 早先误判"坏类抢救有价值"，实测 9257 个真实类 parse 失败数为 **0**
   （唯一 1 个是我们自造的 `demo/broken/Truncated.class`）。该项从待办划掉。

## 遗留风险与未做的事

1. **Linux/macOS 行为已正确但未实机验证** —— 本次只在 Windows 上跑。修复在所有
   平台生效（隔离逻辑与文件系统无关），但 macOS 尤其值得复跑一次确认。
2. **170 次额外 JVM 启动带来约 45s 开销**（130s → 175s）。对混淆样本可接受，
   但如果遇到冲突类极多的 jar 需要考虑批量化。
3. **冲突类的输出路径不再等于类名**（`myau/%41.java`）。对阅读无影响，但若有
   外部工具按路径反查类名会失效。README 已说明。
4. **控制流去混淆、字符串加密解密**仍未做。前者与 `classfile.py` 的 round-trip
   硬约束冲突，需先论证；后者记忆里已结论需执行引擎。
5. 未提交 git —— 项目不是 git 仓库，且用户未要求。

## 回滚方式

删除以下新增内容即可完全回到修复前状态：

- `jdec/decompile.py`：移除 `_case_collisions()`、`_safe_rel()`，
  恢复 `parts = _chunks(good, jobs)`，删除 isolated 块，
  恢复 `if q.hard_error or q.coverage < 0.9: o.status = ...`
- `jdec/score.py`：移除 `_hard_error_spans()` 与 `Quality` 的两个新字段，
  恢复 `hard_error` 扣分与 `unbalanced` 绝对值判断
- `tests/`：移除 3 个测试函数与 `build_fixtures.py` 的 collide 部分
- 删除 `tests/collide.jar`

无数据迁移、无配置变更，回滚是纯删除操作。

---

# 变更报告 2：Myau 运行时捕获全链路（tap）+ 文档沉淀

- 日期：2026-10-03（同日第二批）
- 模式：backend-code-writer / Mode B（修 bug 推进）→ 自主探索收尾
- 范围：`jdec/engines/tap/`（运行时捕获工具链）+ 三份文档；**未触碰** jdec 主流程代码

## 任务目标

1. 完成 batch 解密结果的内容质量验收（判定乱码是第二层密文还是垃圾，提取有价值明文）。
2. 沉淀文档（README / MEMORY / 当日日志）并产出变更报告。

## 最终结论（一段话）

tap 工具链四层全走通：纯解密器重放 13144 条 → NoExit agent 破解 30 个 native 毒类
（40/40 通过）→ s3 名字表撞表 101 条（两代混淆名翻译）→ 真实 Forge 1.8.9 环境
+ 破解包 agent.dll + DumpAgent 倾倒 **58 个实名模块**；随后发现游戏自己写出的
`config/Myau/default.json` 供出 **59 模块 / 358 设置项全表**，并与 dump 交叉验证：
58/59 模块一致、设置项逐一对上。定性：BedWars 向作弊客户端。

## 文件级变更

### 新增（tap 工具链）

| 文件 | 作用 |
|---|---|
| `tap/quality_check.py` | 明文可读性三档分类（clean/suspect/garbage）+ TOKENS 语义启发 |
| `tap/gen_namekeys.py` | 两趟流式生成 s3 撞表候选 key（34714 条） |
| `tap/DumpTable.java` | JVM 内反射调 s3 私有查表函数 → `table_dump.tsv`（101 命中） |
| `tap/NoExit.java` | 字节码手术 agent：antiLeak* 全桩化 / myau* 只桩 native |
| `tap/ModuleCrack.java` | 裸 JVM 实例化读模块名（真环境方案的前身） |
| `tap/DumpAgent.java` | 真环境 premain：枚举 V 子类 → registry 空则主动实例化 → 读名字+设置 → TSV |
| `tap/bisect_run.py`（改） | CP 补 log4j/launchwrapper/vineflower；java 命令挂双 agent |
| 数据产物 | `decoded_final.tsv`（13144）、`table_dump.tsv`（101）、`dump_modules.tsv`、`tap/config/Myau/default.json`（59 模块/358 设置）、`namekeys.txt`（34714）、`todo_round4/5.txt` |

### 文档

- `jdec/README.md`：新增「运行时捕获：不用懂密钥的那条路（已走通）」整节，
  四层实录 + 第五份证据（default.json 交叉验证）。
- `.workbuddy/memory/MEMORY.md`：重写 tap 结论段（四层 + default.json 拿全表的做法）。
- `.workbuddy/memory/2026-10-03.md`：追加批次十一（全链路）、批次十二（交叉验证收尾）。

## 修复轮次（Mode B：证据 → 复现 → 根因 → 最小修复）

| # | 症状 | 根因 | 最小修复 |
|---|---|---|---|
| 1 | gen_namekeys.py 三次 SIGTERM 零输出 | 描述符解析基本类型分支漏 `i+=1` → 死循环撑爆内存 | 补一行 `i += 1`，回归通过 |
| 2 | NoExit 重建类 `Incompatible magic value` | 重建字节丢了 class 头部 | 重排为 头部+CP+接口+字段 原样 + 重建方法区 + 类属性原样 |
| 3 | `VerifyError: Constructor must call super()` | 构造器桩没有超类调用 | `ctorStub`：aload_0 + invokespecial super.<init> + return |
| 4 | `VerifyError: Method expects a return value` | 桩统一 return，无视返回类型 | `minimalReturn` 按描述符造零值桩（V/L/[]/J/D） |
| 5 | `Invalid Signature attribute length` | native 方法属性区被逐个替换 | native 整个属性区换成唯一 Code 桩 |
| 6 | 解密全返回 `#const 1`、`d: null` | **误伤**：myau 全部方法被桩化，`<clinit>` 变 return | `stubAll` 语义修正：antiLeak 全桩、myau 只桩 native |
| 7 | 真环境 `UnsatisfiedLinkError: myau.o.e97…` | 发行版要破解包 JVMTI agent 过授权校验 | 加 `-agentpath:agent.dll` |
| 8 | 第一次 dump registry-dumped=0 | 100s 时 FML 还没填 registry | 延迟 240s + registry 空时主动实例化 fallback |

## 执行的关键命令与结果

- `bisect_run.py` 第五轮：`ok todo_round5: 40 classes / poison 0`（毒类全破）
- `DumpTable.java`：`table_dump.tsv` 101 命中（非原始名，诚实记录）
- 真环境（52 jar CP + JRE8 + agent.dll + dumpagent.jar）：`registry-dumped=58`
- 收尾：diff_summary.py（20 文件变更）；default.json ↔ dump_modules.tsv
  交叉验证：模块 58/59 一致、358 设置项全对上、唯一差异 ESP（仅 json 有）
- jdec 主流程校验：本会话未改 `jdec/` 主代码（tap 是独立运行时工具），
  报告 1 的 100/116 测试基线不受影响。

## 自查

- ✅ 现场已还原：mods/ 目录清空、游戏进程已停（TaskStop 两次确认）
- ✅ 「看似成功实则垃圾」陷阱已在文档中重点标注（myau 多桩 → 桩常数假象）
- ✅ s3 撞表内容如实定性为"两代混淆名翻译"，未夸大为原始名还原
- ✅ 模块全表结论改为以 default.json 为准（59），dump 作为独立验证路径

## 遗留风险

1. `ESP` 模块只在 json 出现，其 registry 类名字未读出——不影响功能清单完整性。
2. `decoded_final.tsv` 里 3112 条字符串多为机器常量，人读价值有限（已定性）。
3. dumpagent `halt(0)` 未生效，需手动停游戏进程（已记录，不影响数据产出）。
4. `tap/config/` 等运行产物留在 tap 目录下（保留作为证据，未清理）。

## 回滚方式

- `tap/` 下新增文件均为独立工具/数据，直接删除即可回滚，不影响 jdec 主流程。
- 文档三件套按本报告表格逐节还原；MEMORY.md 与日志为追加式，可按批次段删除。

---

# 变更报告 3：遗留事项清理（git 基线 + rel 路径映射 + 冲突类分桶批量化）

- 日期：2026-10-03（同日第三批）
- 模式：backend-code-writer / Mode A + Mode B（回归修复）
- 范围：git 仓库初始化、`jdec/decompile.py`、`tests/run_tests.py`、`README.md`；未触碰 tap 与其余主流程模块

## 任务目标

对既有遗留事项逐项评估（哪些值得做、哪些明确不做）后，执行用户批准的四项：
git 基线、report.json 补 rel、冲突类 JVM 批量化、大小写敏感目录回归（最后一项
本机不可行，见遗留）。

## 文件级变更

| 文件 | 改动 | 理由 |
|---|---|---|
| `.gitignore`（新增） | 忽略 pycache、引擎/fixture jar、tests 下历史运行输出（`dbg*`/`mc*`/`mcout`/`out*`/`demo_*`）、`.workbuddy` | 首次 `git add` 曾达 21009 个文件，控制后 82 个 |
| `jdec/decompile.py` | payload 序列化 `rel`；新增 `_iso_buckets()`；隔离循环改为分桶批跑；`_run_chunks` 按提交顺序返回 | 分别见提交 baf7460 / 027d8ae / 14d94c9 |
| `jdec/tests/run_tests.py` | +2 条 report.json 断言、+`test_iso_buckets`（5 条断言）、相应导入 | 覆盖新行为与分桶不变式 |
| `jdec/README.md` | 分桶描述、report.json 输出说明 | 文档同步 |
| `change-report.md` / `MEMORY.md` | 本报告 + 分桶后约定更新 | 沉淀 |

git 提交序列：`0b43ad7` 基线（82 文件 / 13946 行）→ `baf7460` rel →
`027d8ae` 分桶 → `14d94c9` 顺序修复。

## 执行的命令与结果

| 命令 | 结果 |
|---|---|
| `python tests/run_tests.py` | 100 → **107 passed, 0 failed** |
| `python tests/run_tests.py --with-mc` | 116 → **123 passed, 0 failed** |
| `python jdec.py decompile Myau0729-obf.jar --verify-all -j 4` | **723 clean / 0 partial / 0 failed，成员覆盖 100%，89.2s**（逐类隔离基线 174.6s，**-49%**） |
| 独立核验（不依赖 jdec 评分） | 磁盘 723 个 .java；report.json 723 条 rel 全非空且互不相同；`myau/%41.java` 等编码路径在盘 |
| `fsutil file setCaseSensitiveInfo` | **0x5 拒绝访问（需管理员特权），沙箱内外各试一次** —— 本机无法做大小写敏感目录回归 |

## 修复轮次

| 轮 | 内容 |
|---|---|
| 1 | 分桶实现后真实样本回归：**553 clean / 170 failed**。根因：`_run_chunks` 用 `as_completed` 按完成顺序返回，合并代码按提交顺序 `zip`，桶与引擎输出错位，类名查找全部落空 |
| 2 | `_run_chunks` 改为 `results[i] ↔ inputs[i]`（pass 1 的合并是集合式、与顺序无关，行为不变）→ **723 / 0 / 0** |

经验：单类桶的 fixture 碰上完成顺序一致而漏过——「位置配对」类竞态只能靠
多样本回归或确定性配对抓；真实样本回归（MEMORY 铁律）再次证明不可省。

## 自查发现的问题

- 说明：collide fixture 测试对完成顺序竞态不敏感（两桶各 1 类），分桶的
  纯函数不变式（桶数/桶内互异/全覆盖）由 `test_iso_buckets` 独立覆盖；
  端到端由真实样本回归兜底。
- 分桶后真实样本出现 3 桶（84 组中含 2 个三成员组），`_iso_buckets` 的
  "桶数跟随最大组"断言正好覆盖该形态。

## 遗留风险与未做的事

1. **macOS/Linux 实机回归仍未做**。NTFS 目录级大小写敏感需要管理员特权，
   本机 shell 无法提权。替代证据：Windows 大小写不敏感（更严苛——合并真实
   发生）下 123 项测试 + 真实样本 723/0/0 + 路径逻辑审计无大小写折叠。
   建议将来在 WSL 或 macOS 各跑一次 `python tests/run_tests.py`（一条命令）。
2. 分桶依赖「不同组之间不撞名」；若未来出现桶内仍撞名的新混淆形态，
   `test_iso_buckets` 的不变式会先红。
3. git 提交身份是仓库级临时配置（`33503 / 33503@local`，本机无全局 git 身份），
   推送远端前应改成真实身份：`git config user.name/user.email` 后
   `git commit --amend --reset-author`。
4. 评估后**明确不做**（长期视角）：控制流去混淆静态还原（与 round-trip
   硬约束冲突 + ZKM 逐版本变形的无底洞维护 + 反编译器已容忍 goto 链）；
   字符串加密静态还原（tap 已证明运行时出口是正解）；ESP 补名与
   dumpagent halt 修复（真实 Forge 环境成本 > 边际信息）。

## 回滚方式

- `git revert` 对应提交即可；基线提交 `0b43ad7` 是完整还原点。
- `.gitignore` 为纯新增文件，删除即回到无版本控制状态（连 `.git/` 一起删亦可）。
- `_iso_buckets` / 分桶循环 / `_run_chunks` 顺序语义各自独立成提交，可单独回退。

---

# 变更报告 4：skill 改名重构（backend-code-writer → java-deobf）

- 日期：2026-10-04
- 范围：skill 目录改名、SKILL.md 重写、死重删除、junction 与用户级拷贝同步；jdec 主流程零改动

## 任务目标

skill 的实际工作形态是混淆 Java 分析而非后端编码：探测/校验脚本对本项目
天然失灵、Mode A/B 仪式过重、Mode C 通用建议被 jdec 取代、触发描述与正文
长期错位（deobf 关键词堆在描述末尾，触发了却帮不上忙）。按用户决定：
改名、以 Mode C 为主线、删 A/B 死重、有用部分并入统一流程、不再分 mode。

## 文件级变更

| 变更 | 内容 |
|---|---|
| 目录改名 | `backend-code-writer/` → `java-deobf/`（git mv，保留历史） |
| SKILL.md 重写 | 450 行 → 139 行；frontmatter name/description 以反混淆为主、显式排除普通后端编码；正文 = 定位 + 铁律 8 条 + 实战 runbook（probe → strings → analyze → decompile → 深挖 → 沉淀）+ 降级路径 + 修 jdec 规约 + 变更报告 |
| 删除（9 个） | `detect_project.py`、`run_checks.py`、`backend-stacks.md`、`testing-playbook.md`、`debug-playbook.md`、`review-checklist.md`、`security-checklist.md`、`plan-template.md`、`pr-description-template.md` |
| 保留 | `deobf_scan.py`、`fingerprints.json`（33 混淆器）、`self_test.py`、`diff_summary.py`；`java-deobf/control-flow/string-encryption/dynamic-analysis/git-workflow.md`；`change-report-template.md` |
| junction | 旧联接已删，新建 `C:\Users\33503\.zcode\skills\java-deobf` → 项目目录 |
| 用户级拷贝 | `C:/Users/33503/.workbuddy/skills/`：旧目录删除、新结构已同步（双写约定照旧） |

A/B 中被删内容的理由与去向：变更报告纪律与证据先行进铁律 4/8 与报告节；
敏感信息处理进铁律 7（分析中发现的凭据只定性不外传）；安全/评审清单的
去混淆对应物是铁律 6 的交付标准（可重编译 + 行为一致）。

## 验证

- `self_test.py`：33 个混淆器指纹、9 项阈值加载正常
- `deobf_scan.py` 冒烟（flow.jar）：正确报出 6 条 indy 编码串、无指纹误报
- junction 经新路径读 SKILL.md：UTF-8 正常、frontmatter name 正确
- diff 比对确认用户级旧拷贝与改前项目一致后才替换（无独有内容丢失）

## 遗留风险

1. 触发效果未实测：skill-creator 建议的 2-3 条真实 test prompt 需要新会话验证
   （本会话加载的仍是旧内容）；首次实战时留意它是否在该触发时触发。
2. 依赖旧 skill 名的外部引用（如有）会失效；项目内历史文档提到旧名属
   历史记录，不回改。
3. `git-workflow.md` 暂留——若今后确认 deobf 流程用不上可再删。

## 回滚方式

`git revert` 本次提交恢复目录与文件；junction 用两条命令重建：
`rmdir` 旧联接 + `mklink /J` 指回原目录名。用户级拷贝重新 cp 一份即可。


---

# 变更报告 5（2026-10-04/05）：Fabric 映射修复 + native/indy/recover 三命令 + deobf_scan 补强

## 任务目标

EdNaven 3.4（Fabric 1.21.11 付费外挂，ZKM+JNIC 双层）实战踩出的缺口补齐：
Fabric hook 全 0 解析、native 只报数不给出路、BootstrapMethods 无通用解析、
自洽重放（字符串解密）从一次性脚本收编为正式能力；外加 deobf_scan 两处
结构性盲区。

## 提交清单

| 提交 | 内容 |
|---|---|
| `dbf252d` | skill 触发描述 v2（英文锚词 / Forge-Fabric / jdec 绝对路径与 cwd 约定） |
| `c0fe4b1` | jdec：yarn 组合修成员 owner 命名空间 + 官方/中介名双索引；auto 映射按 loader 选 yarn；probe 读 fabric.mod.json 补 flavor/版本 |
| `88692ba` | 指纹库 +JNIC（EdNaven 实证） |
| 本轮 | `fix(scan)` deobf_scan：--max-classes 静默截断改显式警告（coverage 元数据）；META-INF/jars/ 嵌套 jar 并入扫描；`feat(natives)` 新子命令：提取 native 库 + PE 导出表解析 + JNI 符号/Java 声明匹配 + Ghidra 任务清单；`feat(bsm)` BootstrapMethods 解析 + invokedynamic 站点枚举（动态参数表达式树，建模局部变量 store/load/dup）+ `indy` 子命令；`feat(recover)` 自洽重放子命令：规格生成 → 生成/编译 RecoverDriver → 单 JVM 内读真字段值现场求 key → 调目标类自己的 bootstrap 收割明文 |

## 每处改动的理由

- **截断显式上报**：599/711 对账实证——--max-classes 默认 500，EdNaven 525 类
  静默丢 112 个 native。统计数字被当全量事实用时必须声明覆盖范围。
- **auto 按 loader 选映射**：Fabric mod 注解是 Yarn 中介名，mojang 映射
  永远 0 解析（hook 0/167 根因之一）。
- **yarn 组合双索引**：成员 yarn 名查询原拿 official owner 查中介 keyed
  映射，永远 miss（组合循环死变量为证）；Fabric mod 的 hook 翻译必须
  用中介名查。
- **recover 自洽重放**：解密器有跨类全局状态——静态重放值 ≠ 运行时值
  （实测差一倍），两段式必败；单 JVM 内"初始化→反射读真值→现场求
  key→调类自己的 bootstrap"是唯一自洽路径（221 条实证解密）。
- **natives**：jdec 字节码侧到"711 方法在 DLL"为止；提取 + PE 导出表 +
  声明匹配把"接下来做什么"变成可执行清单（EdNaven：sayori 0 导出 =
  动态注册 → 从 JNI_OnLoad 找 RegisterNatives）。

## 执行的命令与结果

- `python tests/run_tests.py` → **116 passed, 0 failed**（107 基线 + 新增 9）
- EdNaven 真实样本回归：hook 解析 0/167 → **158/167**（yarn/1.21.11+build.6）；
  `--deobf` 后 103 文件全 yarn 名、class_310 残留 0
- deobf_scan 全量（--max-classes 20000）：1488 类（含 9 嵌套 jar）、
  native 6150（主 jar 711 与 analyze 对账一致）；截断警告在 500 上限时正确出现
- `natives`：4 库提取，sayori_auth_native.dll 0 导出 = 动态注册，报告给出
  JNI_OnLoad→RegisterNatives 路线
- `indy`：43851 站点 / 447 类 / 1858 BSM；38215 站点路由 dispatcher、
  1038 LambdaMetafactory（vanilla，已过滤）
- `recover`：端到端跑通（规格→编译→执行→收集）；真实明文验证见
  D:/MC/samples/ednaven-analysis/readable/src（221 条字符串内联交付来自
  同机制的 decap 原型）

## 修复轮次

yarn 组合 owner 命名空间 bug（成员值退化成中介名）→ 1 轮；
recover 驱动 6 轮（Method.invokeWithArguments 不存在 → bootstrap/dynamic
参数混传 → "null" 令牌 → l2i 压栈 → 变量遮蔽 → 静态参数装箱）。

## 遗留风险

1. recover 对 (Object,long,long) 系引导形态（hideAccess 分发）仍按
   右对齐 + null 占位猜测调用——部分站点 FAIL；各形态调用约定需逐个
   对着 fallback 源码确认（诚实清单见 references/string-encryption.md）。
2. 重映射 MC 的接口桥方法偶发缺失（30/385 AbstractMethodError）——
   remap 对 bridge/synthetic 的处理待查。
3. deobf_scan 嵌套 jar 计入总数后，--max-classes 500 的默认值对 fat-jar
   更容易截断（已有警告，无静默错误）。

## 回滚方式

`git revert <对应提交>`；deobf_scan 行为变化集中在 collect_classes/返回
值结构（调用方仅 main），revert 即回旧行为；新子命令为纯新增，无兼容
影响。junction/双写拷贝已同步。

---

## 2026-10-05 晚：BytecodeVM 水印静态解码 + 指纹库迭代（study/ 标本馆第一批落地）

### 任务目标

用 study/ 七仓（保护器源码/族谱）迭代 jdec：BytecodeVM 水印情报通道 + 指纹库扩充 + 真实样本回归。

### 文件级变更

- **新增 `jdec/bvmw.py`**：BytecodeVM 水印扫描/解码。常量池 Long `0x42564D57434F4445`("BVMWCODE") 标记 + CONSTANT_String 载体（base64(key16|nonce12|ct+tag16)）→ 纯 stdlib AES-128-GCM 解密（自实现 AES 核心经 FIPS-197 C.1 向量验证）+ payload（magic/version/len/body/sha256 + count×(len+key,len+value)）。格式逐字节对照 study/BytecodeVM SDK 源码（WatermarkCapsule/WatermarkCodec/WatermarkReader）。
- **`jdec/probe.py`**：全类单遍扫描（头读改全量读，一次 open）接入 `find_watermark`；`JarProfile.watermark` 字段 + summary `watermark:` 行 + 归因 "BytecodeVM"（仅当无其他归因）+ signature 行。
- **`jdec/jdec/fingerprints.json`**（33→36）：+BytecodeVM（nhcm/bytecodevm、$CodePool）、+native-obfuscator (radioegor146)（by/radioegor146）；Phantom Shield X 增 tech/skidonion 关键词 + tool 字段按源码重写（NativeObfuscation=字节码直译 C、单参访问器池、jphantom、验证服务端协议）。
- **`jdec/tests/run_tests.py`**：+`test_bvmw_watermark`（FIPS 向量 + 真 SDK 胶囊常量回归 + javac 现 fixture 走 profile_jar 端到端），main 注册。
- **`.gitignore`**：+`study/`（外部研究材料含 DMCA 敏感源码，永不入库）。

### 执行的命令与结果

- `python tests/run_tests.py` → **390 passed / 0 failed**（本轮 +5 checks）。
- 回归：probe jnic-3.7.0.jar=98(JNIC)、myj2c.jar=0(MyJ2C)、Elowen=94(ZKM) 全部与改前一致；水印扫描三样本零误报。
- 端到端：javac 编译 SDK 真 Watermark* 类生成真胶囊 → `bvmw.decode_capsule` 解出 owner/artifactId/builtAtUtc ✓。

### 修复轮次

1. 首版测试胶囊串凭记忆截断→发现后立即用真全文替换（教训：base64 密文材料绝不能手抄片段）。

### 遗留风险 / 待办

- pool.py 单参访问器（OPS 形态 `(C)Ljava/lang/Object;`）**未适配**——需先建 OPS 保护 fixture 再动 spec/driver/apply 三处口径，本轮刻意不动（防盲改）。
- BytecodeVM 全量构建被 gradle 分发 TLS 代理拦断（腾讯镜像 8.14.3 bin.zip 已下载 /tmp/gradle.zip，可用其直接跑 gradle 绕 wrapper）——完整 protect fixture 的端到端留待下轮。
- ZKM27 源码深读（flow/ReferenceObfuscator 2482/3976 行）刚开箱：StringEncryptionTechnique 七形态已确认（三已知形态全对上 + LOCAL_ARRAY_AND_INDEX 为工具树盲区），逐条对照 fingerprints/control-flow 结论待下轮。
- README.md/change-report.md 再次出现编辑器 `\*\*` 转义+表格线污染，已 git restore（批次五同款）。

### 回滚

`git revert` 单提交即可；bvmw.py 独立新文件可整体删除，probe.py 改动集中在 watermark 块与 summary 行。
