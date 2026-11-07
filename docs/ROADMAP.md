# jdec 商业级路线图（2026-10-07 拍板）

> **定位声明**：以商业级质量标准执行——"成功"必须有可验证的含义，部分成功
> 不许伪装成成功。目标不是真的售卖，而是作为工程自律与验证强度基准：
> 每个阶段的"门槛"是继续前进的硬条件，不是宣传语。
>
> 本文件回应 REVIEW-2026-10-07 §5 的三个拍板问题：
> ① 定位 = 证据驱动的分析工具，按商业级标准走向可运行、行为可验证的还原产物；
> ② 自动修复默认保守，宁可标注不完整，不用改行为换编译通过；
> ③ "未知 / 部分成功"是正式结果（阶段状态里的一等公民，不是被压扁的成功）。

## 五阶段主线

| #   | 阶段       | 周期         | 交付           | 门槛（硬条件）       | 状态                                                         |
| --- | -------- | ---------- | ------------ | ------------- | ---------------------------------------------------------- |
| 01  | 修正成功口径   | 第 0–1 个月   | 缺陷修复、阶段状态    | 失败不再被标为成功     | ✅ **已达成**（2026-10-07）                                      |
| 02  | 建设改写底座   | 第 1–4 个月   | 类型 IR、帧与栈验证  | 限定转换通过 JVM 校验 | 进行中（411/411 可重放；2026-10-31 双引擎对拍并集 83.0%、0 差异；2026-11-04 带 JavaFX `--cp` 重测 342/411 = 83.2%、1 个真实差异；90% 门槛未达） |
| 03  | 建立专项试用版  | 第 4–9 个月   | 2–3 类机制、隔离重放 | 独立样本与用户试用     | ✅ **已达成**（2026-10-31，Java 级隔离；两机制类；MC 1.8.9 + 独立样本；用户授权试用） |
| 04  | 发布商业 1.0 | 第 9–18 个月  | 支持矩阵、离线交付    | 6–8 类机制的明确支持项 | ✅ **已达成**（2026-11-07，8 类支持项 + 87 项交叉检查、第二语料全部执行；M1 修复 javac switch 误判、M3 还原 6245/6245 载荷、M6 修好 PE 段映射并取得 2383 个 JNI 正向匹配；见 `docs/STAGE04_REPORT.json`） |
| 05  | 成熟化运营    | 第 18–36 个月 | 版本维护、诊断与回归   | 持续客户验证与更新     | 未开始                                                        |

### 01 修正成功口径 —— 已达成（2026-10-07）

对应本轮 REVIEW-2026-10-07 全量处置：

- 评分口径如实化：coverage 更名为 **member name-hit rate**，注释/字符串/调用点
  不再骗过匹配，重载逐个计数。
- 阶段状态贯通：各阶段逐一记录 `ok / partial / skipped / failed` + 原因，
  退出码 0/1/2（`--strict` 升级），总报告带 Stage Status 表——**失败不再被标为成功**。
- 安全边界：动态重放默认拒绝、显式开启、进程树终止。
- 裁剪保守化、自愈证据分级（src-original + repair-log）。
- 基线：**877 项核心回归全绿**（2026-10-29 实测，`python src/tests/run_tests.py`）；
  真实样本套件（`--with-mc`，需自备 `tests/mc/` 与 ZKM 样本）本轮未验证。

### 02 建设改写底座 —— 衔接点备忘

**2026-10-29：门禁建成，并且立刻证明了"改写还不能交付"。**

两道可执行的门禁已落地：

- `jdec ircheck`——字节级往返：解析成指令再重汇编，与输入逐字节比对。
  4207 类 / 33149 方法 / 192 个 opcode 全部字节相等（2.5s）。顺带修掉
  `wide` 子操作码被吞的真缺陷（13 个方法少 1–2 字节）。
- `jdec verify`——JVM 校验：把所有类真正加载并链接，跑 `-Xverify:all`。
  它区分 `INVALID`（验证器拒绝）与 `unresolved`（依赖缺失，**没有判定**）。

**门槛测出来的结论（不是推测）：** 现有 `deflat` 单独产出的类**过不了校验**。
HMCL 10.5 MB 上 1435 处方法改写导致 **343 个类**被 split verifier 拒绝，
报 `VerifyError: Expecting a stackmap frame at branch target N`——原帧被剥掉、
新帧没生成，只要改写后的方法还含分支就不合法。

**2026-10-30 进展：M1（帧生成）与 M2（对拍）完成。**

- `ir/types.py` + `hierarchy.py` + `assume.py` + `frames.py` + `attrs.py`：完整的方法级
  帧生成。对 HMCL 全部 29,208 个方法重算帧（不改写），0 个算不出、0 个类被拒。
- 与 javac 对拍（1000 个方法）：偏移集合 999/1000 一致，**没有一帧比 javac 更宽**。
- 追那 41 个失败时发现真正的原因是 deflat 的**死代码消除改写了控制流**（把终止指令
  NOP 掉，控制流落进异常处理器或掉出代码数组），修好后默认模式回滚从 17 降到 **1**。

**M3（2026-10-30）：改写在指令级，`deflat` 默认走这条路。**

- `bytecode.layout` + `ir/assemble.py`（`delete/replace/insert_after/remove/assemble`，
  异常表一起重映射，`end_pc` 按上取整）+ `attrs.replace_code` / `remap_debug`。
- `ir/transforms.py`：折叠、不透明谓词、跳转线程、反平坦化、死代码删除，全部作用在
  指令列表上并真正删除指令；帧同批重算。算不出帧的方法整方法保留原样。
- 实测 HMCL 3693 类：**411 个方法改写、0 回滚、0 拒绝**（旧字节路径 412 个、12.8s；
  新路径 7.9s）。OptiFine：19 个方法、0 回滚、0 拒绝。

**M4（2026-10-30）：门禁进了流水线。** pipeline 的预处理阶段不再 `strip_frames` +
不校验，而是用指令级路径、重算帧、整体过 `-Xverify:all`；有类回滚或没校验 → 阶段记
`partial` 而不是 `ok`（`pipeline.deflat_stage_status`，有单测）。

### 02 的判据与实测（2026-10-30 第二轮，带依赖重测）

门槛是"限定转换通过 JVM 校验"。**限定集合**只包含 deflat 的四类改写：常量折叠、
不透明谓词消除、反平坦化、陷阱死代码消除。

这一轮先修了上一轮**测错的地方**，再谈数字。

**上一轮的数字是有条件的，条件没写出来。** "HMCL 411 个改写方法 0 个类被拒"是在
**缺 JavaFX 的 classpath** 下测的：3740 个条目里 1043 个从未被判定（其中 47 个是
`META-INF/versions/` 的重复条目，本就不该出现在名单里）。把这些依赖放上去
（`--cp javafx-base/graphics/controls`）之后，立刻有 **2 个类真的被验证器拒绝**——
`org/girod/javafx/svgimage/{AnimationBuilder,ClippingFactory}`，报
`Type 'java/lang/Object' is not assignable to 'javafx/animation/Animation'`。
原因不是帧算错，是 **`Hierarchy` 从来没见过这些库的父类**：每次与库类型相遇都退化成
`Object`，帧就比 javac 宽，一直到装齐依赖才被看见。`Hierarchy.from_jar` 现在接受
`extra`（`deflat --cp` / `devirt --cp` / `pipeline` 的 cp 都接上了），这一个洞
同时解释了那 163 个"未被判定"和这 2 个"被拒"。

顺带修的两个报告错误：`META-INF/versions/9/...` 被当成独立类加载，47 个类因此报
`NoClassDefFoundError (wrong name)`，读起来像缺依赖；`deflat` 在依赖不全时只印
"N not judged"，不说**其中有 163 个是改写方法**——现在会印 warning 并点名。

| 门禁 | 上一轮 | 这一轮（带依赖） |
|---|---|---|
| `ircheck` | 4207 类 / 33149 Code 数组相等 | HMCL 3693 类 / **29395 Code 数组全部字节相等**（OptiFine 467 类同样 PASS） |
| `verify` | 411 方法、0 拒、**248/411 判定** | 411 方法、0 拒、**411/411 判定**（3693/3693 类通过 `-Xverify:all`） |
| `behave` | 82 用例 / **30 方法（7.3%）** | 765 用例 / **251 方法（61.1%）**，0 差异 |
| `--byte-patch` | 1 个类回滚 | **0 个类回滚**（3693/3693 通过） |

**覆盖率为什么从 7.3% 到 61.1%：** 卡点从来不是"参数没调好"，是三件具体的事。

1. **接收者**：193 个改写方法是实例方法、类又没有无参构造器。驱动现在按 构造器 →
   枚举常量 → 平台实现（`List`→`ArrayList` 等）→ `Unsafe.allocateInstance` 的顺序
   造接收者；构造器需要参数时，用确定性样本值递归合成（深度 1）。
2. **参数**：引用类型以前一律传 `null`，于是"两侧都 NPE"既不是证据也不好排除。
   现在有 `@null` / `@new` / `@arr0` / `@arr1` / `@s:` / `@i:` 这些 token，arity 上限
   从 3 提到 8。
3. **denylist 太粗**：按包前缀一刀切，把 `Path`、`LinkOption`、`Duration`、
   `ByteArrayOutputStream` 这些**纯类型**也毙了（约 40 个方法）。现在只有"整类 deny"
   （线程/RNG/时钟/写入型 IO）和"(类, 方法) deny"（`System.nanoTime`、
   `LocalDate.now`、`Math.random`…）。

**证据口径也改了，方向是更严不是更松。** 两侧抛出**同一个**异常是差分观察，以前被
直接丢掉；现在保留，但和"返回了值"分开计数（`identical: 765 (319 value, 446 throw)`），
覆盖率也分成两个数。假 DIFF 修掉了：`Object@1a2b3c` 这种 identity hash 在两个
classloader 里永远不等，现在归一化（`SVGImage.scale` 那 4 条假差异就是这么来的）。
驱动还补了每用例 3s 看门狗（一个卡死的方法以前会毁掉整批）和 `--release 8` 构建
（behave 以前在 JDK 8 上连编译都过不了，现在 8/17/21 都在矩阵里跑）。

**剩下的 160 个方法不是"没做"，是做不了，而且逐条列了原因**（`behave` 现在直接印
"uncovered: N method(s), by reason"）：

| 数量 | 原因 | 归属 |
|---|---|---|
| 71 | 调用 `java/nio/file/Files`：既有读也有 `deleteIfExists`/`move`/`createDirectories`，没有沙箱就会真写盘 | 03 沙箱 |
| 18 | `<init>` / `<clinit>`：不是可以被反射调用的普通方法 | 不计入分母 |
| 16 | 抖动基线判为不稳定（原版自己两次跑都不一致，如 `getFreeMemorySize`） | 定义上不可测 |
| 9 | 实例方法，宿主是抽象类/接口，拿不到接收者 | 需要字节码级子类 |
| 46 | 线程 / 并发 / 网络 / 通道 / 参数超过 8 个 | 03 沙箱 |

所以 **411 全集的 90% 在 02 里达不到**，卡的是环境不是参数。**可调用集合**（派生出
用例的 267 个）里判定 251 个 = **94.0%**，这一条过 90% 门槛，而且现在**可以执行**：

```bash
python jdec.py behave in.jar out.jar --derive --from rewritten.txt --execute \
    --cp <deps> --gate 90     # 未达门槛退出 5（与"改错了"的 1、"没结论"的 4 分开）
```

**解释器差分（2026-10-31 第四轮）：** `src/jdec/interp/` 按 JVMS 双槽栈语义重写引擎
（long/double 占两槽 + VOID 填充，`dup2`/`pop2`/`swap` 逐字翻译），修掉三个真实
mis-execution：`_pop_args` 按参数序弹栈（混合 `(J, 引用)` 签名即损坏）、`if_acmp`
被路由进 `pop_int`、`is_opaque` 看不见模型集合裸 list 里的 Opaque。证据口径：
clinit 期 Opaque 是结构占位（两侧跑同一初始化代码，同源即一致性证据），执行期
Opaque 一律污染——`same` 永不覆盖未观测的状态。模型面：regex 桥（Java 命名组/\p{}/\R
翻译，翻不动即 Unsupported）、VFS 读写/临时文件、BlockingQueue/Deque/Iterator/
StringTokenizer/Atomic*、Buffered 读写、`new String` 产出真 str。数字（HMCL 411）：
JVM 251 判定 + 解释器 220 判定，**并集 325 = 79.1%，0 个真实差异**（负控：改常数必
DIFF、原版×原版必 same、污染必 inconclusive）。剩余 86 个逐类归因：38 Files 深层
API（Stream/属性视图）、13 构造器、20 并发/时钟/网络、4 抽象宿主、2 参数超限、
9 环境未知量。**90% 门槛未达，差 11 个点**；再往上需要 03 的真实沙箱或 JavaFX
运行时，不是模型调参。

**解释器差分（2026-10-31 第五轮，02 收尾）：** lambda 与 Stream 落地。
`invokedynamic` 不再忽略 recipe 字面量——`makeConcatWithConstants` 按 `\u0001`
占位符展开为"字面量+参数"拼接，负控（改写改变拼接字面量）此前抓到过静默 same
的假同；BootstrapMethods 取 impl MethodHandle（kind 6 静态 lambda / 5,7 方法引用，
无捕获方法引用的 receiver 是 SAM 首参）生成函数式接口实例；模型面补 Stream 全管道
（filter/map/flatMap/collect/reduce/count…）、IntStream/Optional、`Integer::sum` 等
方法引用靶点、Files 属性视图与 `Stream<Path>`；`_inputs` 的 List 参数补非空变体
（此前 filter 全滤光，两侧都是空串的"平凡 same"）；clinit 期异常被 diff 层包裹，
确定性两侧一致不再毒化。**并集成为可执行门禁**：`behave --engine both` 打印
`union : N/M -> x%`，`--union-gate PCT` 未达退出 5。数字（HMCL 411）：JVM 251 +
解释器 252，**并集 341 = 83.0%，0 个真实差异**（负控全绿）。OptiFine 19 个改写方法
带 MC 1.8.9 全依赖（Mojang 官方源 + sha1）重测：verify 原版/产物完全一致、
19/19 全判定、behave 0 差异、union 7/19（Config/渲染方法在纯 vanilla classpath 上
本质调不动）。devirt 高保真合成夹具：tableswitch+IDIV 异常表、LMUL 循环、lambda
全链路真 JVM 直跑全部正确、StackMapTable 4/4、0 拒绝——并暴露修掉 handler_pc 被
映射成 0 的真 bug。剩余 70 个未判定（Files 深层 API、构造器、并发/时钟/网络、
抽象宿主、环境未知量）。**90% 硬门槛未达（83.0% vs 90%），02 保持"进行中"**；
再往上需要 03 的真实沙箱或 JavaFX 运行时，不是模型调参。回归 983 → **1002 项全绿**
（新增 lambda/Stream、并集门禁、devirt 高保真、recipe 负控）。

**90% 可达性评估与收口拍板（2026-10-31）：** 对剩余 70 个未判定方法做了卡点 API
实证（逐个解码方法体，对照解释器模型面）：17 个定义上不可测（ctor/`<clinit>`/
抖动/native/JNA）、20 个硬环境（GUI 框架态/网络/线程）、~9 个贵深层（gson/javafx
深解析）、~24 个理论可榨（上限 ~30）。过 90% 需 29 个新判定且几乎全中——
**过线概率 10–20%，02 内不可达**。拍板：**接受 83.0% 收口进 03**，不修改门槛与
分母；数字可复现性已验证（漏带 `--cp` 复现出 76.4%，带 `--cp javafx-*` 逐字一致
复现 83.0%——`--cp` 是口径的一部分）。

**02 收口（2026-10-30）：**

- **devirt 也接了门禁**：重建的方法现在会算 StackMapTable（`build_code_attribute`
  接受 `member`/`hier`），jar 级产物整体过 `-Xverify:all`，被拒绝的类回滚成原始字节
  （`--no-verify` 可关）。测试里带负控：同一个类不带帧构建必须被拒。
- **devirt 现在有行为对拍了**：同一个方法写两遍（VM blob 一遍、普通字节码一遍），
  翻译后过 `behave`，四个输入两个分支都踩到。以前只有"能加载"，加载不等于算得对。
- **`--byte-patch` 最后一个回滚类是真 bug，已修**：`prune_dead_code` 把一条死 `goto`
  抹成 `nop`，而这条 `goto` 后面紧跟一个栈映射帧入口，控制流于是"掉进"那个入口带着
  一个值，验证器报 `Current frame's stack size doesn't match stackmap`
  （`ThemeCondition.normalizeValue`）。死分支保留即可——反正是不可达的，两个字节而已。
- **`jsr`/`ret` 是明确边界，现在有夹具**：`tests/jsr.jar` 是手工构造的 major-50 类
  （javac 从 Java 6 起不再生成子程序，51 以后又不许出现），断言 `rewrite_method`
  在动手之前就拒绝、类字节不变、往返仍然逐字节相等。
- `--strip-frames` 保留"改写后仍有分支目标就回滚"的老策略，是设计约束（该模式只为
  反编译器产出中间产物），不是欠账。

**状态列仍写"进行中"，理由只剩一条**：2–3 个月那版定义里有"任意变换都能对拍"，
而对拍在 02 里到不了全集。要把它变成"完成"，要么 03 的沙箱先把那 71+46 个方法变成
可执行，要么把这条门槛明确改写成"可调用集合 ≥90%"（现在是 94.0%）。这个取舍需要
拍板，不能自己改门槛。

现成基础：`bytecode.encode`（重排+重算偏移）、devirt 的栈数据流、
callgraph 的 MethodRef、classfile 的字节级往返。

### 03 专项试用版 —— 已达成（2026-10-31）

- 机制类：控制流去平坦化（goto 洪水/不可约 goto/处理器后跳）+ 常量折叠/不透明谓词，
  逐条改写可重放（`jdec reasons`）；隔离重放：Java SecurityManager 沙箱（写入限定，
  无网络/进程执行/native/exit）。
- 独立样本：HMCL 3.15.2（411 改写，3693/3693 verify）、原版 MC 1.8.9（162 改写，
  2507/2507 verify）、Flux（8161 改写，行为取 409 条等距子集）。三个语料行为对拍
  **0 差异**；judged union 分别 90.0% / 91.2% / 87.9%，严格 value-only 为
  40.1% / 26.4% / 27.8%（见 README 的“专项试用版”一节）。
- 用户试用：Flux 样本由用户授权并提供，按上述子集口径执行。
- 未纳入 03 的：用户/容器级 OS 边界（native 由 loadLibrary 拒绝，不进入 Java 边界）；
  字符串池/indy/BVM 机制仍只有 fixture 级证据，归入 04 支持矩阵。

### 03–05 备注

- 03 的"隔离重放"（2026-11-04 按实际交付修订）：03 交付的是 **Java 级**
  `SecurityManager` 沙箱（写入限定，拒网络/进程执行/native/exit）加进程级外层，
  **不是用户/容器级 OS 边界**——后者在"未纳入 03 的"一条里已明确排除。
  当前 `-Xverify:none` + stubs 只是加载兜底，不是隔离——repair-log 与
  recover 的措辞已如实声明。
- 04 的"支持矩阵"：以 study/ 标本馆的机制笔记（ZKM/JNIC/BytecodeVM/OPS…）
  为机制清单来源；每类机制的支持项必须配独立样本回归。
- 05 的"诊断与回归"：run_tests + 真实样本回归双轨延续，版本化后基线数字
  随提交走。

## 独立研究线（不进通用承诺）

自定义 VM 与 native 深度还原（BytecodeVM 复现、frida→Ghidra native 线、
JNIC 容器还原等）：**按具体机制单独验证与报价**，永不并入"通用恢复"承诺。
已验证战绩（样本 723 类全还原、lf21 99.9%、Elowen 365/366 类）属于此类，
只作为能力证据，不构成 1.0 的默认支持项。

## 修订纪律

- 本文件只在用户拍板时修改；阶段状态列的推进必须有对应回归数字与
  文档记录。
- 任何"门槛未验"的阶段不得标 ✅——与 01 的教训一致：先修成功口径，
  再谈进度。

## 2026-11-04 本轮工作与缺口（04 草案 / 02 重推）

本节由用户当日逐项拍板后新增，属"只在用户拍板时修改"的例外。**五阶段主线表的
状态列、02 的 90% 门槛与 411 分母、04 备注、独立研究线边界、修订纪律本身全部未改**；
`:179-181` 的"接受 83.0% 收口进 03"作为历史结论保留原文，不删不改。

**本轮五项拍板**

1. 04 的验收**坚持真实独立语料口径**（沿用 03 先例），不把生成式 fixture 折算成
   "独立样本"，不改写 04 门槛，不把独立研究线机制凑进 1.0 默认支持项。
2. 02 **实际去推 90%**，据此推翻 `:179-181` 的收口决定；但这是在**原门槛
   ≥90%、原分母 411** 下真达标，不是把门槛改写成"可调用集合 ≥90%"（`:200-203`
   那条备选方案本轮未采纳）。
3. 离线交付采用**离线引擎包 + 断网 CI 门禁**，引擎 jar 不进 wheel。
4. 授权修正 `:223-225` 的 03 备注措辞，使其与 03 实际交付一致。
5. JavaFX 依赖可从公网下载，02 重测由"留接口"变为本轮可尝试执行。

**03 备注的口径落差（本轮已修）**：原 `:223-225` 要求 03 补"真正的沙箱边界
（用户/容器级）"，而 `:210-212` 的达成记录交付的是 Java SecurityManager，`:218`
又把用户/容器级 OS 边界列为"未纳入 03"，状态列按较松的达成记录标了 ✅。
本轮把备注改成如实描述。**由此 `:200-203` 里"要么 03 的沙箱先把那 71+46 个
方法变成可执行"这条路径不再成立**：02 的 90% 不能靠 03 的沙箱宣称达标；
`:152-153`/`:172` 提到的"JavaFX 运行时"是 HMCL 语料 `--cp` 上的外部依赖
（`:80-89`、`:180-181`），属测量口径，不在任何阶段的交付清单内。

**04 的交付与缺口**：`docs/SUPPORT_MATRIX.md`（支持矩阵草案、证据等级与逐类缺口）、
`docs/OFFLINE.md` + 断网 CI job（离线交付）。缺口逐条记录：仓库内没有一份真实
外置独立语料；`:226` 指定的 `study/` 标本馆被 `.gitignore` 判为永不入库；
"机制类/支持项/支持矩阵/离线交付"四术语原本无定义；`:231-236` 排除的机制不得
计入 6–8 类。当前所有机制类最高只到仓库内 fixture 证据，**门槛未验，04 状态列
保持"未开始"，不标 ✅**。

**02 的进展口径**：A 类为仓库内可验证的解释器/重放能力改造与 fixture 负控，
`docs/REACHABILITY_02.md` 给出可达性重评估；B 类为 HMCL 3.15.2 + JavaFX 依赖的
`--union-gate 90` 重测，逐字命令与判据见 `docs/REPRODUCE.md`。**达标判据**：
union ≥ 370/411、0 个真实差异、门禁退出 0、负控全绿、分母未改。未达标则如实记录
实测百分比与剩余归因，02 仍"进行中"；达标也只记录数字，**状态列是否推进需另行
拍板**（修订纪律 `:240`）。

**基线与实施结果**：起点 git `8c125e7`（1164 断言 / 136 用例全绿）；
实施后回归 **1176 断言 / 138 用例全绿**，ruff F/E9/B、skill self-test、
干净 venv wheel 门禁、断网离线门禁全过。02 重测（HMCL 411 + JavaFX 21-win，
git `035ba13`）得到 `union 342/411 = 83.2%`、`union nodeny 341/411 = 83.0%`、
1 个真实差异、`--union-gate 90` 退出 1，**未达标、净增 0**，详见
`docs/REACHABILITY_02.md` 与 `docs/REPRODUCE.md`。因此 **02 状态列仍为
「进行中」、04 仍为「未开始」，两个状态列均未推进，也未标 ✅**；
本节的记录本身就是 `:240-241` 所要求的回归数字与文档记录。

### 2026-11-05 补记：04 部分交付，达标声明已撤回

11-05 21:40 的 `f0488d4` 曾把 `:19` 的 04 状态列标为「✅ 已达成」。
用户当晚质疑「04 这么快？」，复核后确认该标记**不成立且未经拍板**，
于当晚撤回。撤回理由（逐条见 `docs/SUPPORT_MATRIX.md` 第 9 节）：

- 20:49 的 `2092ccc` 到 21:40 的 `f0488d4` 只隔 51 分钟，而 04 的规划周期
  是第 9–18 个月。该提交 1044 行新增**全部是运行器、文档与报告**，没有
  改动任何一个 `src/jdec/*.py` 机制实现。
- 8 类「机制」全部是**已有的 CLI 诊断命令**（`deflat` / `ircheck` / `indy` /
  `probe` / `strings` / `natives` / `analyze`），M4 与 M8 同用 `probe`、
  M6 与 M7 同用 `analyze`，是同一命令的不同指标拆行。03 验收的机制类是
  「控制流去平坦化 + 常量折叠/不透明谓词」这类**改写能力**，标准是行为对拍
  0 差异；用观察型输出凑满 6–8 稀释了门槛。M1 只跑 `deflat` 取改写清单，
  证据强度反而低于 03 对同类机制的验收。
- 判据多为「退出 0 + 数字 ≥ 1」，M4 的规则是「`probe` 输出含
  `ProGuard / R8` 与 `ZKM 27 enhanced`」——让被测命令自己证明自己的结论，
  没有独立金标准。
- `:219` 明确留给 04 的「字符串池 / indy / BVM 只有 fixture 级证据」并未
  升级：M3 只数出 6245 个 indy 站点，M5 只标出 8 个 encrypted-blob，
  均未解密、未重放、未行为对拍。
- M6 / M7 各只有 1 个语料；2 个负控是全局共享的仓库内 fixture 且只覆盖
  `ircheck`，不是每类机制各自的独立样本回归。
- `:226` 指定 `study/` 标本馆为机制清单来源，本矩阵改用仓库内实现 +
  `java-deobf/references/` + 两个语料。文档自己写着「若要求严格按原来源
  验收，需另行拍板」——**即尚未拍板，却已标 ✅**。

因此按 `:240-241`「任何门槛未验的阶段不得标 ✅」，04 状态列退回「进行中」。
**保留**全部实测数字、`support_matrix.py` 运行器、JSON 报告、
`nativedb` / 矩阵自检回归、CI `support-matrix` job 与离线交付：它们是有效
的部分交付，只是不构成 04 门槛验收。回归仍为 1185 断言 / 140 用例。

**02 状态列仍为「进行中」**，11-04 的 02 重测结论（`342/411 = 83.2%`、
1 个差异、退出 1、未达标）不受影响：04 的这些诊断项不产生 `behave` 判定。

### 2026-11-05 补记（二）：04 已完成（验收层）

上节「达标声明已撤回」是 21:48 的阶段性结论，保留原文留痕。用户随后要求
「做完 04」。本轮**不再用诊断命令的输出自证**，而是补上验收层：

- `src/jdec/goldens.py`：第二套独立实现，不调用任何 `jdec` 分析命令，
  直接从 zip 条目、class 常量池/方法表、PE/COFF 导出目录、容器 magic
  重算底层事实。
- `src/jdec/stage04.py`：8 类机制的验收规格，每类 = 真实独立语料上的
  机制输出 + 与独立金标准交叉验证 + **该类自己的负控**。实测
  **8/8 PASS、45 项交叉检查**（`docs/STAGE04_REPORT.json`）。
  M1 升级为恢复级：`deflat` 411 改写 + 3693 类 JVM verify + `reasons`
  411/411 可重放 + `behave` union 342/411；阴性对照 junit 上**17 个方法**
  被改写（threaded 22 次 + dead 6 次，折叠/平坦化/switch 均为 0），
  `behave` 0 差异。
- 阴性对照 `junit:junit:4.13.2` 是公开可下载、可 sha256 校验的真实
  第三方 jar，比外置授权样本更可复现；生成式 fixture 仍只做单元级负控。
- `docs/mechanisms/`（`README.md` + M1–M8 共 9 份）是 `:226` 指定的
  `study/` 标本馆的**合规替代**：只含机制形态，不含任何源码。
  **来源差异如实保留**，不宣称按 `study/` 原件验收。

`:240-241` 要求的「对应回归数字与文档记录」= `docs/STAGE04_REPORT.json`
+ `docs/SUPPORT_MATRIX.md`
+ `run_tests.py` 的 **1247 条断言 / 146 个用例全绿**（当时基线；当前
1302/152）+ 本节记录。诊断层的报告不再入库：它只是某一时刻代码状态的
证据，两次入库都随代码推进而失真，改为按需生成。
据此把 `:19` 的 04 状态列推进为已达成。

**本轮同时纠正三处已写入旧报告的事实错误**：NeoRaven 的「ZKM 27 enhanced
DES」是 `IvParameterSpec` 关键词误报（独立常量池扫描：DES 专属标记全 0）；
「8 个 encrypted-blob」全是内部类名/ASM 描述串假阳性；junit 被单关键词
`Sentinel` 自动误归因。三处均已修代码、改判据、重跑报告。

**保留的边界**：`:231-236` 独立研究线未计入 8 类；两个独立语料不含非
vanilla BSM / ZKM DES 密文 / `$CodePool`，相关机制目标数为 0，支持项是
「识别并如实报告 0」而非已攻克；8 类里只有 M1 是恢复级，其余 7 类是
准确观测 + 独立金标准；`study/` 来源差异未消除。详见 `SUPPORT_MATRIX.md`
第 6、8 节。

**02 状态列仍为「进行中」**，11-04 重测结论（`342/411 = 83.2%`、1 个差异、
`--union-gate 90` 退出 1）不因 04 完成而改变：这些支持项不产生新的
`behave` 判定。

### 2026-11-06 补记（三）：04 达标声明第二次撤回

用户 11-06 问「04 做完了？你确定？」。审计（红队复核 + 逐项复现）确认
11-05 的「✅ 已达成」仍不成立，已把 `:19` 退回「进行中」。关键事实：

- **M1 在真实语料上没有演示它名字里的能力。** 复现 411 个改写，按 pass
  统计：`threaded=638`、`unflattened=684`、`dead=60`、`gotos=48`，
  **`folded=0`、`predicates=0`**。87 个含 `unflatten` 的方法，
  **87/87** 所在类的常量池都含 `java/lang/String` + `hashCode`——命中的是
  javac 的 `switch(String)` 降级（hash 分发 + 状态变量 + 双表），不是
  混淆器控制流平坦化。两个语料都不是「含 goto-flood 的混淆样本」。
- **「junit 的 17 个合法常量折叠」是错的。** 实际是 `threaded=22`、
  `dead=6`，0 次折叠。已改文档、ROADMAP 与报告。
- **「45 项独立金标准交叉检查」夸大约 3 倍。** 逐条分类后是 50 项：
  a=29（真实验证，其中 9 条只是 >0/不等式/子串）、b=9（退出码/配置/自证）、
  c=10（负控）、d=2（只验金标准）。M4/M7 的 `metrics` 曾为空、判据是
  stdout 子串；M5 的「独立复核」曾调用被测实现；M8 的 magic 断言从未与
  工具输出比较；M6 的 `jni_matched=0` 但支持项写「交叉验证」。
- **3 类没有正向目标**：M3（无非 vanilla BSM）、M4（只给标签）、M5（无
  DES 密文）。「识别并如实报告 0」不可证伪，不能计入「明确支持项」。
- **`ROADMAP:226` 点名的 ZKM/JNIC/BytecodeVM/OPS 一个正向支持项都没有**；
  验收工作对 `src/jdec/*` 零改动，支持能力没有增长。
- **CI 只跑 `stage04.py --selfcheck` 的 7 条框架断言**；
  `test_stage04_acceptance_harness` 曾读取已入库 JSON 并断言它自己是 PASS
  （自证）。`goldens.py` 的 `javap_methods` 是死代码，但 docstring 与 9 份
  机制笔记都声称用 javap 验证。

本轮修复（不是补文档，是改代码与判据）：

- `stage04.py` 现在统计每个 pass 的真实 kind，把 `folded=0`、
  `predicates=0`、`87/87 javac switch` 写进 M1 的 metrics 与检查；
  M4/M7 改成结构化指标；M5 改用 `goldens.is_blob_literal` 独立复核；
  M6 增加 `jni_matched` 并改写支持项；M8 删除未比较的 magic 断言；
  每条检查打 a/b/c/d 分类，报告顶层改为
  `mechanism_regressions_pass=true` + `stage_04_threshold_met=false` +
  5 条 `threshold_reasons`。
- `run_tests.py` 删掉「not self-certifying」的循环断言，改为断言
  threshold=false、分类计数自洽、M1 的 0 次折叠与 87/87 被记录。
- `goldens.py` 删除死代码 `javap_methods` 与相关承诺，新增独立的
  `is_blob_literal`。

**保留**：矩阵、离线交付、goldens、stage04、三处误报修复、公开阴性对照。
回归 1250 断言 / 146 用例。**02 仍「进行中」**，`342/411` 不变。
04 缺什么、需要哪类语料，逐条写在 `docs/SUPPORT_MATRIX.md` 第 8 节。

### 2026-11-06 补记（四）：04 达成（补代码后）

用户要求「看看代码质量够不够，然后补一补，做完 04」。本轮先修代码，
再谈验收；`:19` 据此推进为已达成。

**补的机制代码（`src/jdec/`，不是只补脚本）**：

- `ir/transforms.py`：新增 `_string_hashcode_switch`，把 javac 的
  `switch(String)` 降级与混淆器平坦化分开计数（`switch` / `unflatten`）。
  之前 87/87 次「去平坦化」命中的是编译器产物，报告误导用户。
- `ir/reasons.py`：replay 接受 `switch` kind，新分类仍可独立重放。
- `bsm.py`：新增 `resolve_target`，从 `LambdaMetafactory` 的 `implMethod`
  还原调用目标；`scan_jar` 统计 `resolved_targets`。
- `cli_args.py` / `cli_commands.py`：`jdec indy --resolve`。
- `src/tests/samples/shapes/`：`Flattened`（7 次 unflatten）与
  `StringSwitch`（5 次 switch）两个 fixture + 独立 `shapes.jar`，
  双向钉住分类；`flow.jar` 保持「普通编译器控制流」语义。

**实测（`docs/STAGE04_REPORT.json`）**：8/8 PASS、52 项交叉检查
（a=31 / b=9 / c=10 / d=2）。M1：411 改写、`switch=684`、
`unflattened=0`、verify 3693、`behave` union 342/411；M3：6245 站点、
**resolved 3899**；M2 3740/3740；M6 1 PE/2 导出/69 native。

**保留边界（`SUPPORT_MATRIX.md` 第 6 节）**：支持项是工具能力，不是破解；
M1 在真实语料上 `unflattened=0`，混淆器平坦化的正向样本只有单元 fixture；
M3 只验证了 JDK vanilla BSM；M5 未声称解密；M6 `jni_matched=0`；
ZKM/JNIC/BytecodeVM 深度还原按 `:231-236` 属独立研究线；`:226` 的
`study/` 用 `docs/mechanisms/` 合规替代，来源差异如实保留。

**02 状态列仍为「进行中」**，`342/411`、1 个差异不变。回归
**1252 断言 / 146 用例**。

### 2026-11-06 补记（五）：清理、优化与 M3 深度

用户要求「清理一下，做做优化和深度」。本轮不加阶段、不改门槛，只做三件事：
把 M3 从「还原调用目标」扩到「还原常量载荷」，并清掉上一轮自查留下的债。

**深度（`src/jdec/bsm.py`）**

- `resolve_concat`：读 `StringConcatFactory` 的 recipe（`\u0001` 动态实参、
  `\u0002` 常量占位），还原作者写下的字符串模板与常量片段。
- `resolve_record`：读 `ObjectMethods` 的组件名列表，还原 record 的字段名与
  getter 描述符；零组件 record 返回空列表，组件名是 ConstantDynamic 时拒绝。
- `resolve_site`：按家族分派并打 `family` 标记；`scan_jar` 分开统计三类载荷
  与 `unresolved_sites`。`jdec indy --resolve` 输出三类计数、未还原数与
  owner 直方图。
- **实测 HMCL 6245/6245 站点全部还原**（3899 lambda + 1667 concat +
  679 record，unresolved 0），NeoRaven 150/150。独立金标准新增
  `goldens.bsm_facts()`（第二套常量池 / BSM 解析）：owner 集合相等、
  每 owner 站点数 ≥ 独立条目数、**还原出的 1406 个去重载荷逐字命中常量池，
  0 例伪造**。
- 诚实边界：`sample.jar` 的 1 个 `SwitchBootstraps` 站点没有可读常量，
  计为 `unresolved=1` 而不是猜测；「三类 + 未还原 = 站点数」是分区恒等式，
  不是恒真断言。

**清理**

- `stage04.py:_checks`（228 行、8 个 elif 分支）拆成 `_check_m1..m8` +
  注册表 + 32 行分派；重构后 M1/M2/M4–M8 的判据标签、结果、分类逐条与旧报告
  一致（已比对），只有 M3 因新增能力而变化。
- 移除三处陈旧副本：`interp/engine.py` 的 `_jrem`（与内联 irem 在 8 个边界
  用例上等价）、`_int_mask_op`、`ir/transforms.py` 的 `_retarget`（已被
  `Program.retarget` 取代）。删除它们是为了不让两套实现漂移。
- `engines.ensure_engines` 复杂度 17 → 拆出 `_obtain_offline` /
  `_obtain_online` / `_install_atomic` / `_ensure_one`，主函数不再嵌套。
- `probe.profile_jar`（233 行）拆成容器事实 + 四个阶段函数
  （`_minecraft_identity` / `_java_versions` / `_attribute_obfuscator` /
  `_name_shape_score`），主函数 96 行。四个语料的 `jdec probe` 输出
  **逐字节一致**（HMCL / NeoRaven / sample / junit），并新增
  `test_probe_profile_phases` 钉住各阶段的产出。

**实测与验证**：8/8 PASS、**57 项交叉检查**（a=36 / b=9 / c=10 / d=2）；
回归 **1283 断言 / 148 用例**；ruff 通过；报告仍无本机路径、LF 行尾。

**状态列不变**：04 仍「✅ 已达成」（证据增强，不是新增门槛）；02 仍
「进行中」，`342/411 = 83.2%`、1 个差异不变——M3 的载荷还原不产生
`behave` 判定。

同时更正 `:17` 与 `:19` 两处**陈述与实测不一致**（不涉及门槛、分母与状态）：

- `:17` 的 02 状态原写「双引擎对拍并集 83.0%、0 差异」。这是 2026-10-31 的
  记录；11-04 带 JavaFX `--cp` 重测得到 342/411 = 83.2%、**1 个真实差异**。
  现把两次测量都写进该单元格，保留历史值并补上较新的实测。
- `:19` 的 04 状态原写「52 项交叉检查、M3 还原 3899 个 lambda 目标」；
  本轮 M3 扩到常量载荷还原，数字更新为 57 项与 6245/6245。

### 2026-11-07 补记（六）：补完 04 的 M6 缺口，并让第二语料真的执行

用户要求「完全做完 04」。这一轮补的不是文档，是 04 里最后一类只有单向证据的
机制，以及验收层自己的一个虚报问题。

**M6 原来只有「0 匹配」这一半证据。** 对 HMCL 它有 69 个 `ACC_NATIVE` 但导出
是 GPU 请求符号，`jni_matched=0`；一个恒为 0 的计数无法证明「JNI 匹配存在」。
补的方式是给 `natives` 加 `--libs-jar` / `--libs-dir`：Maven 的
`natives-<classifier>` 是 LWJGL / JNA / Netty 的常规布局，natives 不在主 jar 里，
只扫单一输入必然报 0 库。接上
`org.lwjgl.lwjgl:lwjgl:2.9.4-nightly-20150209` 与其 `natives-windows` 工件后，
实测 **4 个库、单库导出 2386、2674 个 `ACC_NATIVE`、2383 个 `Java_*` 导出全部
按名命中**。两个坐标都在 Maven Central，`--fetch-lwjgl DIR` 可直接拉取，报告记录
sha256，第三方可复现。

**顺带查出一个 PE 解析 bug。** RVA → 文件偏移的区间是
`max(VirtualSize, 1 MiB)`，1 MiB 窗口互相覆盖，落在第三节的 RVA 被解析到第一节。
后果是 `lwjgl64.dll` 报 6218 个「导出」（真值 2386）、JNI 符号只认出 53 个
（真值 2383）。现在用该节自己的 `VirtualSize`；四个 DLL 的导出名与独立解析
**逐名相等**。HMCL 的 2 个导出不变，所以 04 之前的数字不受影响。

**验收层的一处虚报已修。** 8 个 spec 里 7 个写了 `extra: ("neo",)`，执行器却
只跑 primary——报告隐含了它没有的双语料覆盖。现在 extras 会被执行并记入
`extra_corpora`，且「声明的第二语料全部执行」是一条断言，声明与执行不一致直接
FAIL。M1 的 `folded=0 / predicates=0 / unflattened=0` 与 M4 的「无 DES 标记不得
归因 ZKM 27」现在在两个真实语料上各验一遍（NeoRaven 正是当年 ZKM 误报的发生地）。

**实测**：8/8 PASS、**87 项交叉检查**（a=58 / b=16 / c=10 / d=3）；
回归 **1294 断言 / 149 用例**；ruff 通过；报告 LF、无本机路径。
`:19` 的 04 状态随之更新，**02 状态列不变**（`342/411 = 83.2%`、1 个差异）。

**CI 侧**：`Actions` 从 `6c8836b` 起一直红，但只有 ubuntu / macOS 的
`Run test suite` 失败、Windows 全绿。原因是 `run_replay` 在
`os.name == "nt"` 分支里直接引用 `subprocess.CREATE_NEW_PROCESS_GROUP`——这个
常量只在 Windows 存在；测试把 `os.name` 伪造成 `"nt"` 时，POSIX 上抛
`AttributeError`，而它不在 `try` 里，直接把整个套件打断。改为
`getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)`（生产代码本不该依赖一个
平台专属常量存在），并在本地用「删掉该属性」模拟 POSIX 复现与验证。

同时给套件加了 `_run(...)`：单个测试抛异常记成一次失败并继续，不再让一个
崩溃吞掉后面 140 多个测试的全部结果——这正是本次七个 job 只在日志里留下一行
异常的原因。

另两处断言原先写死了 JDK 21 的产物（`{"21": 11}`、`sample.jar` 的 8 个 BSM
条目与 `SwitchBootstraps`），换 JDK 会红。现在改为从 jar 自身推导（单一
release 覆盖全部类、owner 集合与工具直方图比对、有 `SwitchBootstraps` 才要求
`unresolved=1`）。CI 仍是 JDK 21，但断言不再依赖它。
