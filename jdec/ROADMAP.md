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

| # | 阶段 | 周期 | 交付 | 门槛（硬条件） | 状态 |
| --- | --- | --- | --- | --- | --- |
| 01 | 修正成功口径 | 第 0–1 个月 | 缺陷修复、阶段状态 | 失败不再被标为成功 | ✅ **已达成**（2026-10-07） |
| 02 | 建设改写底座 | 第 1–4 个月 | 类型 IR、帧与栈验证 | 限定转换通过 JVM 校验 | 进行中（理由 411/411 可重放；双引擎对拍并集 83.0%、0 差异；90% 门槛未达，2026-10-31） |
| 03 | 建立专项试用版 | 第 4–9 个月 | 2–3 类机制、隔离重放 | 独立样本与用户试用 | 未开始 |
| 04 | 发布商业 1.0 | 第 9–18 个月 | 支持矩阵、离线交付 | 6–8 类机制的明确支持项 | 未开始 |
| 05 | 成熟化运营 | 第 18–36 个月 | 版本维护、诊断与回归 | 持续客户验证与更新 | 未开始 |

### 01 修正成功口径 —— 已达成（2026-10-07）

对应本轮 REVIEW-2026-10-07 全量处置（详见 change-report.md 第五篇）：

- 评分口径如实化：coverage 更名为 **member name-hit rate**，注释/字符串/调用点
  不再骗过匹配，重载逐个计数。
- 阶段状态贯通：九阶段逐一记录 `ok / partial / skipped / failed` + 原因，
  退出码 0/1/2（`--strict` 升级），总报告带 Stage Status 表——**失败不再被标为成功**。
- 安全边界：动态重放默认拒绝、显式开启、进程树终止。
- 裁剪保守化、自愈证据分级（src-original + repair-log）。
- 基线：**877 项核心回归全绿**（2026-10-29 实测，`python jdec/tests/run_tests.py`）；
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

**解释器差分（2026-10-31 第四轮）：** `jdec/interp/` 按 JVMS 双槽栈语义重写引擎
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

### 03–05 备注

- 03 的"隔离重放"：在 01 的进程树终止之上补真正的沙箱边界（用户/容器级），
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
  change-report 记录。
- 任何"门槛未验"的阶段不得标 ✅——与 01 的教训一致：先修成功口径，
  再谈进度。
