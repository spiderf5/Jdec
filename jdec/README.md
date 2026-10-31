# jdec

多引擎 Java 反编译驱动，面向 Minecraft 这类混淆过的 jar。

自己写反编译引擎没有意义——CFR、Vineflower、Procyon 已经比手写的强得多。  
jdec 的价值在引擎之外：**调度、验证、反混淆**。

## 它强在哪

1. **多引擎择优，而不是赌一个引擎**  
   三个引擎（CFR 0.152 / Vineflower 1.11.1 / Procyon 0.6.0）各有盲区。CFR 对  
   现代语法最准，Vineflower 泛型注解更好，Procyon 常常是唯一能啃动 Java 6-8  
   混淆字节码的那个。jdec 先用一个引擎批量跑完，再把**没跑出来的和有报错  
   标记的**类交给所有引擎重跑，谁的结果好就用谁的。
2. **用字节码当标准答案，而不是靠猜**  
   "哪个引擎反编译得更好"不能靠行数或文件大小判断。jdec 直接解析 class 文件  
   拿到真实的字段/方法签名，检查它们有没有出现在反编译结果里。一个方法被  
   引擎丢掉，它就不会出现在源码中——这是可测量的事实。  
   成员名的长度门槛是**自适应**的：混淆目标里几乎所有名字都是 `a`/`b`/`c`，  
   用固定门槛会把它们全过滤掉，反而让还原最差的类拿最高分。

   判分是**按类**做的，但"引擎放弃"是按**方法**发生的。引擎会把搞不定的那个  
   方法包进 `/* This method has failed to decompile */` 注释——一个 15 方法的类  
   丢 2 个，剩下 13 个是好的。所以注释覆盖的比例超过一半才算整类失败，否则按  
   比例扣分。花括号同理按占比判断：6000 行里少一个右括号不是失败。
3. **大小写重名的类不会被合并**  
   ZKM 这类混淆器会生成只靠大小写区分的类名（`pkg/A` 和 `pkg/a` 是两个不同  
   的类）。zip 大小写敏感，但 Windows 和 macOS 的文件系统不敏感——两个类写进  
   同一个输出目录时后者会覆盖前者，而按输出路径反推类名会把幸存的那份**同时  
   记到两个类头上**，被覆盖的那个类凭空"恢复"了。

   jdec 会先检出这些冲突组，按**组内序号**分桶：第 i 个桶拿所有组的第 i 个  
   成员，各桶一个独立输出目录、一次引擎跑完整个桶——同组类永不与同桶其他类  
   撞名，隔离开销也从每类一次 JVM 降到每桶一次。结果再写到不会撞名的路径下  
   （大写字母做百分号编码，`pkg/A` → `pkg/%41.java`）。在一组真实的 ZKM 27  
   混淆样本（723 类，其中 84 组是孪生类）上，723 个类产出 723 个互不覆盖的  
   源文件，而不是 637 个。
4. **坏类隔离**  
   Vineflower 遇到一个读不了的类会让整次运行崩溃。jdec 预先校验每个类，  
   读不了的隔离掉，不让它拖垮其余 7786 个类。
5. **Minecraft 反混淆**  
   `brc` → `CreeperEntity`。支持 Mojang 官方映射（1.14+）、Fabric  
   Intermediary+Yarn、旧版 MCP/tsrg（1.7-1.12）、现代 Forge TSRG v2（含命名空间与多级参数过滤）
     
   以及 modern Forge (1.16+) 的 `official-srg` 双命名空间组合映射。
     
   重映射在字节码层完成，声明处和**所有调用点**一起改名，产出的 jar 类名与路径一致，能被 JVM 加载。

## 安装

需要 JDK 9+（已在 Zulu 21 上验证）。java/javac 按 **`JAVA_HOME` → `PATH` → 常见安装目录**
的顺序查找——只配 `JAVA_HOME` 不配 `PATH` 也能用（`java` 装在 `D:\java21` 这类非标准
位置时推荐这种方式）。引擎 jar 自动从 Maven Central 下载：

```bash
python jdec.py engines
```

## 用法

### 一键全自动端到端分析（推荐）

一条命令全自动执行完整逆向分析流程：指纹探测 $\rightarrow$ 字节码平坦化消除 $\rightarrow$ 符号重映射 $\rightarrow$ 多引擎择优反编译 $\rightarrow$ 动态重放解密 $\rightarrow$ Native与行为审计 $\rightarrow$ 输出总览报告并可选启动 Web 工作台：

```bash
python jdec.py auto client.jar -o out --web
```

---

### 分步执行命令

先看一眼对面是什么，不反编译：

```bash
python jdec.py probe client.jar
```

普通反编译（检测到混淆的 Minecraft 会自动尝试反混淆）：

```bash
python jdec.py decompile client.jar -o out
```

常用参数：

| 参数                                                    | 作用                                       |
| ----------------------------------------------------- | ---------------------------------------- |
| `-j N`                                                | 并行 JVM 数，默认按 CPU 自动                      |
| `--memory 4g`                                         | 每个 JVM 的堆                                |
| `--verify-all`                                        | 逐个类对照字节码打分，出完整报告（慢一些）                    |
| `--limit 300`                                         | 只处理前 N 个类，快速试跑                           |
| `--mappings f.txt`                                    | 映射文件（proguard / tiny / tsrg 自动识别）        |
| `--mapping-set mojang\|yarn\|mcp\|official-srg\|none` | 自动下载哪套映射（official-srg 专用于现代 Forge 1.16+） |
| `--mc-version 1.20.4`                                 | jar 里读不出版本时手动指定                          |
| `-e cfr,vineflower`                                   | 指定引擎顺序                                   |
| `--clean-work`                                        | 结束后删除中间产物目录（可能有上千个文件，所以默认不删）             |

### 改写底座门禁：`ircheck`

`ircheck` 不解包、不反编译。它把每个类解析成指令再重新汇编回去，与输入逐字节
比对——这是类型 IR 的前置条件：如果连“原样重建”都做不到，任何基于 IR 的改写
都会在看不见的地方损坏类文件。

```bash
python jdec.py ircheck client.jar                 # 0 = 全部字节相等
python jdec.py ircheck client.jar --json ir.json --limit 50
```

退出码：**0** 全部相等，**1** 有差异，**2** 没有任何可检查的类。Code 属性无法
解码的方法单独记 `undecodable`——“没检查到”和“检查过没问题”是两件事，不合并。

实测（2026-10-29）：4207 个类 / 33149 个方法，含 192 个不同 opcode
（tableswitch / lookupswitch / wide / multianewarray / invokeinterface /
invokedynamic），全部字节相等，耗时约 2.5s。

### JVM 门禁：`verify`

`ircheck` 证明"能原样重建"，`verify` 证明"改完之后 JVM 愿意加载"。它启动一次
JVM，把每个类加载并**链接**（用 `getDeclaredMethods()` 触发 link，不执行
`<clinit>`，所以不会跑目标里的代码），逐类给三种结论：

| 结论 | 含义 |
|---|---|
| verified | 通过 `-Xverify:all` |
| INVALID | 验证器拒绝（`VerifyError` / `ClassFormatError`）——改写弄坏了它 |
| unresolved | 依赖不在 classpath，**没有判定过**，不算通过 |

```bash
python jdec.py verify rewritten.jar --cp original.jar
python jdec.py verify rewritten.jar --cp original.jar --allow-unresolved
```

退出码：0 全部通过 / 1 有类被拒绝或有类没判定 / 2 没有任何类可检查。

`deflat` 默认带这道门禁，而且改写在**指令级**做：折叠出来的表达式被真正删除、
死块被真正移除，重排后重算 StackMapTable，最后整体过 `-Xverify:all`。

| 模式 | 做法 | 用在 |
|---|---|---|
| 默认 | 删指令 → 重排 → 重算帧 → JVM 校验；算不出帧的方法整方法保留原样 | 要交给别人跑的产物 |
| `--byte-patch` | 旧的字节补丁：等长 NOP 填充，保留原 StackMapTable | 对照 / 回退 |
| `--strip-frames` | 剥帧，不保证可加载 | `auto` 喂给反编译器的中间产物 |

改写默认按类并行：`-j N`（默认 auto，最多 4 个 worker；`-j 1` 关闭）。
HMCL 3693 类实测 6.6s → 3.9s（4 worker），改写数、回滚数与产物字节完全一致。

实测（2026-10-30，HotSpot 21）。**带依赖**这一列是把目标自己的库放上 classpath
（`--cp`）之后的结果——依赖不全时"0 拒绝"是有条件的，见下：

| 语料 | 改写方法 | 回滚 | 产物校验（不带依赖） | 产物校验（带依赖） | 耗时 |
|---|---|---|---|---|---|
| HMCL / 3693 类 | 411 | 0 | 2697 通过 / 996 未判定 / 0 拒绝 | **3693 通过 / 0 未判定 / 0 拒绝** | 9.0s |
| OptiFine / 467 类 | 19 | 0 | 252 通过 / 215 未判定 / 0 拒绝 | （缺 Minecraft，未跑） | 2.3s |

**为什么一定要给 `--cp`：** 帧的类型合并需要真实的父类。库类型不认识时，每次合并
都会退化成 `java/lang/Object`，帧就比 javac 宽，而 `verify` 在同一个不完整 classpath
上跑，看不见这个问题。把 JavaFX 放上去之后，HMCL 立刻有 2 个类被验证器拒绝
（`Type 'java/lang/Object' is not assignable to 'javafx/animation/Animation'`）。
`deflat` 现在会在这种时候打一行 warning 并点名"有 N 个改写方法从未被判定"。

两条路径在 HMCL 上改的方法数几乎相同（字节路径 412、指令级 411）。差的 1 个是
`MultiMCModpackInstallTask$MMCInstancePatchesAssembleTask.execute`：有一条
`goto 下一条指令` 是多余的，但它是另一条 `ifeq` 的跳转目标。字节路径可以把这条
`goto` 抹成 `nop`（偏移不变，跳转落在 `nop` 上继续往下走），指令级路径是**真删**
并重排，删掉一个分支目标就得顺带改所有指向它的跳转——它不做这件事，于是整方法保留。
方向是更保守，不是更激进。

字节路径的产物里是一长串 `nop`，正确性还依赖"改写恰好等长"这个巧合；它保留下来是
为了对照，以及在没有 javac 的环境里给反编译器喂输入。

`verify` 认类文件版本：类比 JVM 新时记 **SKIP**（没被读过），而不是 INVALID。

```bash
python jdec.py verify out.jar --java D:/JAVA17/bin/java --focus rewritten.txt
```

`--focus` 报的是 `unjudged_rewritten`——**改写方法里有多少落在从未被判定的类上**。
这个数字比"0 个类被拒绝"有用得多：HMCL 上不带依赖时，411 个改写方法里有 163 个
所在类缺依赖，"0 拒绝"实际只覆盖 248 个；补上 JavaFX 之后是 **411/411**。

`devirt` 走同一条规矩：重建的 Code 现在带 StackMapTable（`build_code_attribute` 接受
方法本身，才拿得到隐式初始帧），jar 级产物整体过 `-Xverify:all`，被拒绝的类回滚成
原始字节（`--no-verify` 可关，有回滚时退出码 1）。

### 行为对拍：`behave`

`verify` 只证明"能加载"，不证明"算得一样"。`behave` 用同一组用例分别调用原始 jar
与改写后的 jar，比对返回值或抛出的异常：

```bash
python jdec.py behave original.jar rewritten.jar --spec cases.txt --execute
```

```
# class|method|argTypes|argValues
demo/legacy/OldStyle|pick|java.lang.String|hello
demo/legacy/OldStyle|pick|java.lang.String|
```

- 静态方法和实例方法都支持。实例方法的接收者按 构造器（需要参数时用确定性样本值
  合成）→ 枚举常量 → 平台实现（`List`→`ArrayList` 等）→ `Unsafe.allocateInstance`
  的顺序构造，所以**不要求有无参构造器**
- 参数类型：`int` / `long` / `boolean` / `double` / `float` / `short` / `byte` /
  `char` / 全限定类名。引用参数除了字面量，还可以用控制 token：`@null`、`@new`
  （造一个实例）、`@arr0` / `@arr1`（空数组 / 一个元素）、`@s:文本`、`@i:5` 等
- 每条用例跑在自己的线程里，3 秒没结果记该用例不可用，不会拖死整批
- 会**执行目标代码**（`Class.forName(..., true)` 会跑 `<clinit>`，字符串解密器就在
  这一步），所以必须显式 `--execute`，否则退出码 3
- 重放 JVM 默认套 Java 沙箱（`jdec/sandbox.py`）：写入只允许在本次运行目录内，
  网络、进程执行、native 库加载和 `System.exit` 被拒；`--no-sandbox` 显式关闭。
  JDK 24+ 已移除 SecurityManager，需要 JDK 9–23。native 代码不受 Java 沙箱约束，
  `loadLibrary` 默认拒绝，所以它进不了这层边界。`recover` / `pool harvest` 同样
  默认开启同一沙箱。沙箱下 mock agent 不注入（JPLIS 无法在 SecurityManager 下
  attach），stub 类仍在 classpath；需要该 agent 的目标用 `--no-sandbox`。

退出码：0 全部一致 / 1 有差异 / 2 参数错 / 3 未授权执行 / **4 没有结论**
（`PARTIAL`：部分用例调不起来；`NO VERDICT`：一条都没判定）/ **5 覆盖率门槛未达**。
4 和 0 的区别很重要——"没证明"和"证明相同"不是一回事；5 和 1 也一样——"没看够"
不是"改错了"。

```bash
python jdec.py behave in.jar out.jar --derive --from rewritten.txt --execute \
    --cp deps/javafx-controls.jar --gate 90
```

`--gate` 的分母是**可调用集合**（派生出用例的方法数），不是全部改写方法：一个要写盘、
要起线程的方法在这里本来就调不起来，把它算进分母会让门槛取决于目标恰好做什么。

**双引擎对拍与并集覆盖率**（`--engine both`）：JVM 引擎（真 JVM 反射调用）覆盖不动的
方法，解释器引擎（`jdec/interp/`，纯 Python 按 JVMS 语义执行）往往能补上——两台
"机器"看得见的故障模式不同，**并集**才是对拍强度。两引擎各跑同一组用例，各出一份
判定，最后打印：

```
jvm    : 251/411 judged by either engine -> 61.1%
interp : 252/411 judged by either engine -> 61.3%
union  : 341/411 judged by either engine -> 83.0%
```

`--union-gate PCT` 让并集成为硬门槛：未达 PCT 退出 5（与"改错了"的 1、"没结论"的
4 分开）。分母是全部改写方法。解释器不知道的方法（如深 `Files` API）会诚实记
inconclusive，绝不拿 `same` 覆盖没观测到的状态；拼接 recipe 的字面量也在比对范围内
（`makeConcatWithConstants` 按 `\u0001` 占位符展开，改写若动了字面量必 DIFF）。

**用例可以自动派生**（`--derive`）：从改写清单出发，为可反射调用的方法生成固定输入。

```bash
python jdec.py deflat in.jar -o out.jar --rewritten rewritten.txt
python jdec.py behave in.jar out.jar --derive --from rewritten.txt --execute
```

派生只剔除**观测不可靠**的方法：抽象 / native、`<init>` / `<clinit>`、以及方法体
自己引用了线程、RNG、时钟、写入型 IO 的（按"整类 deny + (类, 方法) deny"判定，
不再按包前缀一刀切——那会把 `Path`、`Duration` 这种纯类型也算进去）。随后跑
**抖动基线**：`原始 × 原始` 在两个独立 JVM 里各跑一次，两次不一致的丢掉。

两侧抛出**同一个**异常会保留：同一个输入在两个 jar 上产生同样的可观测结果，这是
证据，只是比"返回了值"弱，所以分开计数（`identical: 765 (319 value, 446 throw)`）。

它是**回归工具，不是等价性证明**：覆盖多少取决于能派生出多少可调用方法。HMCL 上
411 个改写方法里 251 个拿到判定（61.1%，其中 132 个返回了值）；剩下 160 个逐条列了
原因（71 个要文件系统沙箱、18 个是构造器、16 个自身结果不稳定、9 个宿主是抽象类、
46 个是线程/网络/通道）。**能调用的 267 个里判定 251 个 = 94.0%。** 加上解释器引擎
后并集 **341/411 = 83.0%**（0 差异）；90% 硬门槛未达，差的是 03 的沙箱与运行时
依赖，不是参数。这些数字每次都打印，不藏。

输出：

```
out/
  src/         反编译后的源码，按包组织
  report.md    人类可读报告（哪些类没还原干净）
  report.json  机器可读，含每个类的状态、分数与输出路径 rel
               （冲突类的 rel 经百分号编码，不等于类名，外部工具从这里反查）
```

退出码：**0** 全部还原干净，**1** 有失败或部分还原，**2** 一个类都没还原出来
（或没有可用引擎 / 找不到 java）。找不到 java 时会在下载引擎之前就直接报错退出，
不会先下载再逐类失败。`auto` 的 0/1/2 看的是**阶段状态**（任一阶段 failed → 2），
与 `decompile` 的"还原了多少类"不是同一把尺子，两者不要互相套用。

深挖与进阶分析命令（字符串/控制流/native 保护撞墙时用）：

```bash
python jdec.py indy client.jar                 # indy 站点普查：4 万级站点、
                                               # 每个站点的 bootstrap 与参数表达式
python jdec.py natives client.jar -o nat/      # 提取 native 库 + PE/ELF 导出表 + 动态 RegisterNatives 识别 +
                                               # 反向 JNI 调用图 (FindClass/GetMethodID) + Ghidra 逆向脚本
                                               # （加 --decompile 可自动调用内置 Ghidra 输出 C 伪代码）
python jdec.py deflat client.jar -o deflat.jar # 字节码控制流平坦化消除、不透明谓词剔除与反编译器陷阱死代码消除
python jdec.py reach client.jar --prune slim.jar # 入口可达性分析、最短触发调用链回溯与死代码裁剪
python jdec.py recover client.jar -o rec/      # 自洽重放：内置自动挂载 mc_stubs.jar 单例桩，
                                               # 消除 needs-instance / needs-bootstrap 连坐失效
python jdec.py web out/                        # 启动本地多引擎交互式 Web 工作台 (代码对比/搜索/Hook浏览器)
python jdec.py project client.jar -o proj/ --compile # 一键生成 IDE 可直接构建的完整 Gradle 工程并运行自愈编译验证循环
python jdec.py engines --with-ghidra           # 一键自动下载并配置内置 Ghidra Headless 引擎
```

`recover` 和 `pool` 默认自动生成并挂载合成桩 `mc_stubs.jar`（提供非空单例 `Minecraft.getInstance()`、`SharedConstants`、`Bootstrap`、`BuiltInRegistries` 等），无需启动真游戏环境即可跑过 90% 的初始化依赖门禁；若需要原生无桩环境可传入 `--no-stubs`。
  
方法论与覆盖边界见 skill `references/string-encryption.md` 的
  
「自洽重放」节——**解密器有跨类全局状态，静态重放求 key 必错，
  
必须单 JVM 内初始化→读真值→现场求 key**。

## 分析：它改了游戏哪里

反编译回答「代码长什么样」，分析回答「它想干什么」——后者往往更值钱，  
而且**不受混淆影响**：注解值是常量池常量，JDK 调用改不了名。

```bash
python jdec.py analyze client.jar -o out --mc-version 1.20.4
```

不加 `--mc-version` 也能跑，只是 hook 目标保持原样不翻译。产出 `out/analysis.md`：

- **它改了游戏哪里**：按被 patch 的类聚合的 hook 清单（`@Mixin` / `@Inject` /  
  `@Overwrite` / `@Redirect`），目标类与方法自动过一遍映射  
  （`brc` → `CreeperEntity`），并归类成玩家 / 渲染 / 世界 / 网络等区域。  
  名字被改成 `a.b.c` 也不影响，因为注解里的目标是常量。
- **信号**：`reflection` / `native-library` / `jni` / `process-exec` /  
  `network` / `crypto` / `self-integrity` / `anti-debug` /  
  `machine-fingerprint` / `encrypted-strings`，按类统计，并列出  
  「值得先看的类」。

读的是 Fabric 的 `fabric.mod.json`、Quilt 的 `quilt.mod.json`、Forge/NeoForge 的 `META-INF/mods.toml` 与 `META-INF/neoforge.mods.toml`、  
旧版的 `mcmod.info`，以及它们声明的 `*.mixins.json`。若缺少 loader 文件，自动识别 Java Agent 与 FML 启动桩。元数据被删了也没关系：  
扫不到配置就全量扫注解，照样能找出来。

**refmap 也会读**。Fabric 构建时会把 `@Inject(method = "...")` 改写成 intermediary 名  
（`method_1234`），真实名字留在 `refmap.json` 里。顺序必须是先 refmap 再 MC 映射——  
反过来的话没有任何映射认识 `method_1234`。报告里会同时显示两个名字：

| patched class                    | hooks | kinds         | methods                   |
| -------------------------------- | ----- | ------------- | ------------------------- |
| `net/minecraft/client/Minecraft` | 2     | Inject, Mixin | `runTick` ← `method_9012` |

## indy 调用目标编码：MC 上最常见的一类

superblaubeere27 / JObf 这一系（MC 社区最常见）把每个调用点改写成 `invokedynamic`，  
真实目标藏在 bootstrap 里，**目标本身以文本形式停在静态 `String[]` 中，  
尾部空格的个数就是操作类型**：

```
net/minecraft/client/Minecraft:runTick:()V··      2 空格 → 虚方法调用
com/example/Api:getToken:()Ljava/lang/String;·    1 空格 → 静态调用
net/minecraft/client/Minecraft:fps:Ljava/lang/String;···   3 空格 → 实例字段读
com/example/LicenseManager:serial:Ljava/lang/String;····  4 空格 → 静态字段读
```

jdec 直接把它解出来，**不需要执行任何东西、不需要加载类**：

| target                                                   | operation        | table in |
| -------------------------------------------------------- | ---------------- | -------- |
| `net.minecraft.entity.PlayerEntity.tick()V`              | virtual-call     | `a/b/C`  |
| `com.example.LicenseManager.serial : Ljava/lang/String;` | static-field-get | `a/b/C`  |

这等于拿到了**字节码里已经看不到的调用图**——在分析外挂客户端时，这是最直接的  
「它到底调用了什么」。编码串达到 3 条即判定确认（低于 3 条只作提示）。  
注意别误判：普通 lambda 也是 `invokedynamic`，但没有编码表——vanilla 1.20.4  
实测有 19024 个 indy 调用点、编码串 0 条。

## 混淆器识别

按包名认混淆器只对一半工具有效：Allatori、Stringer、Dash-O 会留下自己的运行时包，  
**Zelix KlassMaster 不会** —— 它是纯字节码到字节码变换，混淆后的 jar 里没有任何一个  
字节属于它。所以 jdec 靠结构指纹判断，且**按命中类占比判定**（10% 门槛）：

| 指纹                           | vanilla 1.20.4 命中 | ZKM 27 命中          | 权重   |
| ---------------------------- | ----------------- | ------------------ | ---- |
| `clinit-decryptor`           | **0.0%**          | **43.6%**          | 0.30 |
| `goto-flood`（方法级 goto ≥ 10%） | 3.1%              | **46.9%**          | 0.35 |
| `irreducible-goto`           | 2.0%              | 28.9%              | 0.18 |
| `long-constant-array`        | 0.9%              | 23.4%              | 0.10 |
| `char-xor-loop`              | 低                 | 高                  | 0.15 |
| `reflect-lookup`             | 低                 | 高                  | 0.20 |
| `indy-long`                  | 0.8%              | 12.9%              | 0.06 |
| `param-object-array`         | 0.1%              | 0.7%               | 0.10 |
| `handler-backjump`           | 0                 | **0 —— ZKM 27 不用** | 0.45 |

实测数据来自一对真实样本（Forge 1.7-1.12 模组，722 / 723 类，同一份代码混淆前后）。

**三个反直觉的实测结论：**

- **ZKM 27 不用异常表后跳。** 三份样本（vanilla / 弱混淆 / 强混淆）的  
  `handler-backjump` 全是 0。它把线性代码拆成 goto 链 —— 13.9% 的指令是 goto，  
  vanilla 只有 1.34%。
- **`fake-sourcefile` 和 `overload-collision` 方向是反的**：vanilla 官方 jar 的  
  SourceFile 属性被剥掉了，100% 不匹配、方法重载 34%；ZKM 样本只有 0.1% 和 3.7%。  
  它们只报告，不参与归因。
- **javac 造不出 goto 洪水。** 三次尝试都被折叠成 switch（0 个 goto）：连续值的  
  if 链、近似连续的返回值、大跨度返回值 —— 全变成 tableswitch / lookupswitch。  
  javac 的最坏情况是嵌套循环 + break/continue，实测 7.3%。goto 洪水只可能来自  
  字节码改写器。

多个指纹用 noisy-OR 合并，归因门槛是**类覆盖率**：每个指纹命中的类数达到
抽样/全库类数的 10% 才算在场；合并置信度必须**严格高于** 0.35 才给厂商结论
（恰好 0.35 不判；单条 goto-flood 的权重即 0.35，单独在场只报「未知」）——
宁可说「未知」，也不把弱迹象说成 Positive identification。

## 字符串：混淆之后还能读的线索

代码可以全被改名，但程序总得和外界说话——连的 URL、写的文件、执行的命令、  
校验的 token。这些字面量在常量池里，是混淆器改不掉的东西。

```bash
python jdec.py strings client.jar -o out
python jdec.py strings client.jar --suspicious      # 威胁特征标签（webhook / telegram / c2-staging / crypto / 加密 blob / url / ip / 路径 / 凭据 / 命令 / 机器码）
python jdec.py strings client.jar --grep api         # 只留含某个词的
```

产出 `out/strings.tsv`（`类名 → 字符串 → 标签`）和 `strings.json`。  
最便宜的一步分析：不用执行、不用改写，扫一遍就出结果——真实客户端抽样  
数百个类，即可捞出 Realms 购买入口、账号 UUID 字段这类线索。

### 运行时捕获：不用懂密钥的那条路

静态还原强混淆（如 ZKM 27 的三层链：indy 引导 session key → 常量折叠引擎 →  
DES）逐版本易变，不划算。原则：**让混淆器自己解，只盯着出口**。按成本  
递增分四层；`engines/tap/` 覆盖第一层（解密器重放）与运行时捕获挂钩  
（StringsSpy 家族），更深层的 agent 按目标适配（方法论见 skill  
`references/dynamic-analysis.md`）：

**第一层：纯解密器重放（零环境）。**

- 常量池静态分类：解密器 / 危险类（native、System.load）/ 安全类；
- 解码指令流，抽取每个调用点 `A.a(int,int)` / `b(int,long)` 的硬编码参数  
  （注意 BIPUSH/SIPUSH 的 arg 存无符号值，需手动符号回绕）；
- 同 JVM 内 `getDeclaredMethod` + `invoke` 按类分组重放，逐条落盘。  
  裸 JVM 缺依赖就补 classpath——很多"本质限制"其实只是缺 jar。

**第二层：毒类桩化。**

native 保护壳类（`<clinit>` 里注册 natives、做完整性校验、验不过即静默  
退出或 native 崩溃）由加载期 agent 改写字节码：

- 壳类**全部方法**桩化为按描述符返回零值（native 去 native 化；构造器补  
  `aload_0; invokespecial super.<init>()V; return` 过验证器）；
- 业务类**只桩化 native 方法**——解密逻辑是纯 Java 时桩化必须止步于此，  
  否则 `<clinit>` 不执行、密文表全 null、解密器返回垃圾。
- 验证纪律：`attribute_length` 是 u4 不是 u2；"看似解密成功"可能全是桩  
  返回的常数，必须抽查对拍。

**第三层：反射名映射表（撞表）。**

混淆器的反射名翻译层若把解码算法留在 `<clinit>`（盐、分隔符明文），可用  
jar 里全部类/方法/字段名生成候选 key，在 JVM 里反射调用其私有查表函数——  
零语义偏差。命中结果可能是"上一代混淆名 → 本代混淆名"而非原始名，撞表  
链路本身值得复用。

**第四层：真环境倾倒（终点）。**

密文表由 native 经 JNI 填充时，静态解密到此为止。让目标在真实运行环境里  
自己解：延迟启动的 agent（等加载器 + 混淆器去重）枚举已加载类、主动触发  
注册、读出功能名全表后 halt。与目标自身序列化写出的配置文件做**双路径  
交叉验证**（agent 反射读字段 vs 目标自己的配置序列化）。注意：`--gameDir`  
下 mods/ 目录不存在会静默不加载；native 完整性校验必须真环境过，第二层  
的桩化 agent 在真环境反而会坏事。

复用顺序建议：先 1（零环境），再 2（毒类），4 才是拿"给人看的功能名"的终点。

## 原生代码：拿不到源码的那部分

如果目标用了 JNIC 这类**虚拟化保护**——把方法体编译成 x86 机器码、方法只留  
`native` 声明——那部分代码根本不在字节码里，任何反编译器都还原不出来。  
jdec 把这种情况**单独说清楚**，而不是让它混在「没还原干净」里让你白花时间：

```
## native code
- 412 native method(s) in 87 class(es)
- verdict: native/virtualised - method bodies live in the shipped library ...
- libraries shipped in the jar:
  - `windows/x86_64/protect.dll` (2311 KB)
- virtualisation interpreter classes: `VNTable`, `VNInstruction`, ...

These methods keep their signature but have no bytecode, so no decompiler can
recover them:
| class | native methods |
```

`decompile` 的报告也会单列 native 方法数，不计入还原失败。剩下的路是把 jar 里的  
`.dll` / `.so`  dump 出来当原生代码分析——Java 侧只能给你签名和调用关系。

撞上 native 墙后的三条路（按成本排序）：

1. **静态侧榨干**：`recover` 把字节码层能解的字符串/常量全收掉（native
     
   门控的除外）；`natives` 产出给 Ghidra 分析师的任务清单。成本最低。
2. **真机运行时捕获**：真跑游戏 + agent 挂钩收出口明文，覆盖最全
     
   （native 填的表、运行期解的密都能拿到）；前提是目标能激活、
     
   授权校验必须真过，且捕获工具链要适配当前加载器/版本。
3. **native 反汇编**：Ghidra/IDA 分析 DLL 本体——虚拟化保护下是按周
     
   计的手工活，只在确需 native 内部算法时上。

### 原生深度分析：动态注册与反向 JNI 调用图

针对现代 Native 加壳（如使用 `JNI_OnLoad` + `RegisterNatives` 隐藏真实符号）：

- **动态方法映射识别 (`RegisterNatives`)**：自动解析 Ghidra 反编译的 C 代码或二进制数据段，提取 `JNINativeMethod` 结构体，将哈希名/数字名的 Java native 方法与底层 C 函数指针关联。
- **反向 JNI 调用图 (Native -> Java)**：静态挖掘 C 伪代码中的 `FindClass`、`GetMethodID`、`GetFieldID`、`Call<Type>Method` 等跨语言调用点，精确查明原生库内部在操纵哪些 Java 类、反射读取哪些敏感字段。
- **Ghidra 自动化注解脚本**：自动输出 `ghidra_annotate.py`，导入 Ghidra 即可一键恢复所有 JNI 函数名和数据类型。

## 控制流平坦化消除与反编译器陷阱剔除 (CFG De-flattening & Trap Pruning)

商业混淆器（如 ZKM、Allatori、Dash-O、Stringer、Smoke）广泛部署多层底层字节码陷阱：

1. **控制流平坦化 (Control Flow Flattening)**：将方法体拆解为状态机循环，基本块由 `tableswitch` / `lookupswitch` 调度分发，导致反编译器输出死循环或大面积嵌套 goto；
2. **不透明谓词 (Opaque Predicates)**：插入运行时恒真/恒假的代数恒等式（如 `v == v`、`null != null`、`iconst_0 == 0`）作为跳转守卫；
3. **反编译器崩溃陷阱 (Anti-Decompiler Traps)**：在不可达死代码分支内填充非法操作码、不平衡操作数栈、或恶意 `athrow` 故意导致 CFR / Vineflower 解析崩溃；
4. **畸形异常表 (Malformed Exception Tables)**：构造 `start == end` 的零长度异常处理器或越界 handler 干扰反编译器控制流重构。

```bash
python jdec.py deflat input.jar -o input_deflat.jar
```

`deflat` 在**指令级**做收敛级优化（`ir/transforms.py`）：不是把不要的字节改成 `nop`，
而是把指令从方法里删掉，再重排、重算帧、过 JVM 校验。

1. **常量折叠 (`fold_constants`)**：`[iconst a][iconst b][iadd]` → `[iconst a+b]`，两个操作数被删除。
2. **不透明谓词消除 (`prune_predicates`)**：
   - 恒真跳转塌缩成一条 `goto`，恒假跳转连同前序压栈一起删除；
   - 覆盖单目整数、双目整型比较、局部变量自等性（`iload_x == iload_x`）与引用判空。
3. **冗余跳转与跳转线程 (`drop_redundant_goto` / `thread_jumps`)**：跳向紧邻后继的 `goto` 直接删除；
   串起来的 `goto A → goto B` 收敛成 `goto B`（只绕过跳转，栈形状不变，所以目标帧仍然成立）。
4. **状态分发器重构 (`unflatten_dispatchers`)**：分析 switch 状态转移表，把每个 case 末尾
   跳回分发器的 `goto` 直接重定向到下一个目标基本块。所有转移都改掉之后分发器没有前驱，
   于是被死代码消除整块删掉——这是"反平坦化"真正生效的地方。
5. **可达性分析与死代码删除 (`drop_dead_code`)**：从第一条指令与真实异常入口做可达性推演，
   不可达的代码（反编译器陷阱）直接删除。落在异常表边界上的块不动：缩短保护区要重写异常表，
   半截的保护区比一条不可达指令更糟。
6. **异常表净化**：保护区里已经没有活指令的处理器会被丢弃，`end_pc` 按"上取整"重映射
   （它是排他的，所以删掉正好压在它上面的那条指令只是缩短了一段从不执行的保护区）。

## 交互式 Web 工作台与语义命名恢复

```bash
python jdec.py web out/
```

- **零依赖 Web 逆向工作台**：单命令启动内置本地 Web 服务（纯标准库实现，无 node/pip 依赖），暗色专业研判界面：
  - **类目录树与即时过滤**：支持包名/类名模糊检索，以及 `All / Tagged / Suspects` 快速标签筛选。
  - **多引擎统一差异比对 (`Engine Diff`)**：支持在 Final (Winner)、CFR、Vineflower、Procyon 之间任意切换并排比对源码，自动生成 unified diff，精准高亮增加/删除差异行及区块变更统计。
  - **交互式研判笔记与标记 (`Audit & Notes`)**：
    - 支持为类添加研判标签：`benign` (正常/绿色)、`suspect` (存疑/黄色)、`threat` (威胁/红色)、`core` (核心/蓝色)、`net` (通信/紫色)、`hook` (挂钩/青色)。
    - 侧边栏与类信息栏实时呈现高对比度彩色标签；提供富文本研判备忘录录入，支持 `Ctrl+S` 快捷保存，数据持久化存储于 `audit_notes.json`。
  - **一键式 AI 语义重命名助手 (`AI Semantic Rename Prompt`)**：
    - 一键提取当前类的 Mixin 注解、敏感字符串特征、参数签名及源码片段，生成结构化大模型 Prompt 弹窗；
    - 支持一键复制至剪贴板，提示词直接引导 LLM 输出标准 ProGuard / TSV 格式的语义重命名规则。
  - **Mixin Hook 目标注入点快速定位**：直接查看 `@Inject` / `@Overwrite` 的原版目标与参数。
  - **威胁字符串与本地 C 伪代码内嵌查看**：无缝浏览 `strings.tsv` 恶意特征及 JNI 逆向报告。

```bash
python jdec.py rename out/src/ -o llm_mappings.txt --prompt-out prompt.json
```

- **批量语义反混淆与 LLM 映射生成**：通过静态扫描类结构、常量池字面量、参数与返回类型以及 Mixin 注解信息，提取混淆成员的语义线索，输出标准 JSON 格式提示词供大模型批量推导可读名字，并直接写出标准 ProGuard 重命名映射表。

## 入口可达性分析与调用图精简 (Reachability & Call Graph)

```bash
python jdec.py reach client.jar
python jdec.py reach client.jar --target "demo/mixin/Licence"
python jdec.py reach client.jar --prune client_pruned.jar
python jdec.py reach client.jar --dot callgraph.dot --json reach.json -o reach_report.md
```

- **全自动入口点深度挖掘**：自动从 `fabric.mod.json`、`quilt.mod.json`、`mods.toml`、`@Mod` 类、`MANIFEST.MF`（Main-Class / Premain / Agent-Class）以及所有 `@Mixin` 类（`@Inject` / `@Overwrite` / `@Redirect`）提取真实生命周期入口。
- **方法级字节码调用图与正向推演**：从入口点出发遍历全量方法调用（解析 `invokestatic`、`invokevirtual`、`invokespecial`、`invokeinterface`、`invokedynamic` 并处理多态虚分发），精确分离真正可能执行的代码与死代码/第三方冗余依赖。
- **最短触发调用链回溯 (`--target`)**：逆向分析师指定可疑类或方法后，自动回溯输出从模组入口或 Hook 点到该目标的最短调用链路与调用指令（如 `ClientEntry.onInitializeClient() --(invokestatic)--> Licence.decode()`）。
- **死代码与膨胀依赖裁剪 (`--prune`)**：一键生成剔除无用死代码与臃肿嵌入式依赖后的瘦身 jar 包，保留所有资源与可达类，大幅缩小逆向分析与二次构建开销。
- **Web 工作台实时联动**：在 Web 工作台选中任意类，实时查看入向调用者 (Callers)、出向被调用者 (Callees)、可达性标签 (`reachable` / `unreachable`) 以及端到端触发路径。

## 金标准还原：一键生成 IDE 可编译工程 (Project Export & Recompilability)

检验逆向与反混淆工具的**终极金标准**，是能否将一个闭源混淆的 Jar 包**完整还原为一个可以直接放入 IntelliJ IDEA / Eclipse 构建并重新编译的工程**。

由于 JVM 字节码规范与 Java 语言规范 (JLS) 之间存在天然鸿沟，普通反编译器导出的源码丢进 IDE 往往会遭遇海量红字：

1. **合成桥接方法 (Synthetic Bridge Methods)**：泛型擦除产生的 `ACC_BRIDGE` 方法与主方法签名只差返回值类型，在 Java 源码中会导致 `method is already defined in class` 冲突报错；
2. **混淆器关键字保留字重用**：将变量名或形参名命名为 `goto`、`default`、`const` 等 Java 保留字；
3. **未类型化的 null 重载歧义**：多重载方法调用传入裸 `null`，导致 JLS 报告 `reference to ... is ambiguous`；
4. **缺失构建脚手架与运行时环境**：缺乏 `build.gradle`、`settings.gradle`，且缺乏游戏核心单例依赖导致上千处 `cannot find symbol`。

```bash
# 一键导出为完整可编译 Gradle 工程（包含脚手架、单例桩库、资源提取与语法修复）
python jdec.py project client.jar -o client_project/

# 导出并运行自愈式 javac 编译验证循环
python jdec.py project client.jar -o client_project/ --compile
```

### 核心能力与自动化机制：

- **开箱即用的 Gradle 工程脚手架 (`generate_gradle_scaffold`)**：
  - 自动根据目标字节码版本匹配现代 Java 工具链（Java 8 / 17 / 21）；
  - 自动生成支持 Minecraft 仓库、Mixin、Guava、Gson、Netty、Log4j 的 `build.gradle`；
  - 自动绑定 `libs/*.jar` 依赖树与编码参数 (`-encoding UTF-8 -Xlint:none`)；
  - 自动附带 `README.md`，提供 IntelliJ IDEA 与 VS Code 导入指引。
- **关键字与标识符安全转义 (`sanitize_keyword_identifiers`)**：
  - 全局识别形参、局部变量及字段声明中的非法保留字并自动转义（如 `int goto` → `int goto_`、`String default` → `String default_`、`const` → `const_`），避免 IDE 语法解析器阻断。
- **合成桥接方法智能剔除 (`prune_duplicate_bridge_methods`)**：
  - 自动识别由于泛型协变返回类型生成的合成桥接方法，精准注释或折叠只含 `return this.xxx()` 转发的重复声明，消除重复方法定义。
- **自适应 javac 编译验证与自愈循环 (`verify_compilation`)**：
  - 调用本地 `javac`（自动追加 `-J-Duser.language=en` 实现跨语言跨系统诊断解析）；
  - 针对编译报错进行多轮闭环自愈修复：自动注释重名符号、智能根据 javac 候选类型将歧义 `null` 参数补全强转（如 `pick((String) null)`），直到达到最佳可编译状态并输出诊断报告。
- **Web 工作台一键集成**：
  - 在 Web 工作台标题栏提供「Export IDE Project」按钮，一键从浏览器导出可以直接用 IDEA 打开的工程。

## 实测

Minecraft 1.20.4 客户端（7787 个类，Java 17，官方混淆）：

| 步骤  | 结果                                |
| --- | --------------------------------- |
| 探测  | 混淆度 88/100，识别出 Minecraft 1.20.4   |
| 反混淆 | 7763/7787 类改名，耗时 5.3s，混淆度降到 0/100 |
| 反编译 | 4 进程并行，4 分 14 秒，5055 个源文件         |
| 重试  | 仅 10 个类需要换引擎                      |

`env` → `com.mojang.blaze3d.audio.Channel`，字段 `a/b/c` → `LOGGER/source`。

真实 ZKM 27 混淆样本（723 类，其中 84 组是只靠大小写区分的孪生类）：

| 指标     | 结果                                                  |
| ------ | --------------------------------------------------- |
| 反编译    | **723 clean / 0 partial / 0 failed**，成员覆盖 100%，175s |
| 冲突类    | 孪生类各自独立还原，磁盘上 723 个源文件互不覆盖（修复前 637 个）               |
| 逐类独立验证 | 84 组冲突两两 sha256 全不同；抽查命中率 100%；无任何类 score < 40      |

## 测试

```bash
python jdec/tests/run_tests.py             # 核心
python jdec/tests/run_tests.py --with-mc   # 额外跑真实 MC jar（需要 jdec/tests/mc/ 样本）
```

**真实样本外置**：工具树里不放真实混淆样本。`--with-mc` 里的 ZKM 归因测试
会依次在 `JDEC_SAMPLE_DIR` 环境变量、jdec 上一级目录、`D:/MC/samples/` 找
指定的真实 ZKM 27 样本 jar（文件名见 `jdec/tests/run_tests.py`）；单个 ZKM 用例
缺样本会跳过。但 `tests/mc/client_1.20.4.jar` 与 `mojang_1.20.4.txt` 缺失时，
`--with-mc` 会**先跑完核心套件并打印汇总**，再以退出码 2 说明缺哪两个文件——
它不会静默地"只少跑几项"。

关键断言：parse→serialize 字节级一致（否则重映射会静默损坏每个类）、  
重映射后的类仍能被 javap 读取、调用点随声明一起改名、  
mixin 注解里的目标能被提取并过映射翻译、  
所有方法都能解码到指令流末尾、ZKM 结构指纹该报的报、不该报的不报。

mixin / flow / collide 相关的用例依赖 `jdec/tests/mixin.jar`、`jdec/tests/flow.jar`、  
`jdec/tests/collide.jar`，由 `jdec/tests/samples/` 下的源码编出来（只用 javac，不依赖  
Mixin 库——注解的*形状*才是 jdec 要读的东西）。collide 是一对只靠大小写  
区分的孪生类，验证 Windows 上 `Widget` 不会拿到 `widget` 的内容：

```bash
python jdec/tests/build_fixtures.py     # 重新编译 fixture jar
```

`jdec/tests/flow.jar` 里有两个角色：`Decryptor` 照着 ZKM 字符串加密的形状写，  
javac 能诚实地编出来；`Guarded` 是普通 try/catch，测试会**故意把它的异常处理器  
改成向后跳**——javac 不生成这种形状，要验证检测器只能自己造证据。

跑测试时 jar 不存在会自动构建（javac 按 `JAVA_HOME` → `PATH` → 常见安装目录查找）；
连 `sample.jar` 都构建不出来时整个套件会**直接中止并说明原因**——它是其余用例的前置，
不是可以跳过的单项（mixin / flow / collide 那三个才是能跳过的）。

## 边界

- C/C++ 原生程序不在射程内，那个只能到汇编和伪代码。
- 反混淆只能还原**名字**，控制流混淆、字符串加密还原不了。
- Minecraft 26.1 起官方不再混淆，新版本不需要映射表。
- 只用于分析你自己拥有或已授权的程序。
