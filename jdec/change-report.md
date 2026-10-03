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
