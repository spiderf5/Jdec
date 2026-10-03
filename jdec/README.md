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
   ZKM 这类混淆器会生成只靠大小写区分的类名（`myau/A` 和 `myau/a` 是两个不同  
   的类）。zip 大小写敏感，但 Windows 和 macOS 的文件系统不敏感——两个类写进  
   同一个输出目录时后者会覆盖前者，而按输出路径反推类名会把幸存的那份**同时  
   记到两个类头上**，被覆盖的那个类凭空"恢复"了。

   jdec 会先检出这些冲突组，把组内每个类**单独**跑一次引擎（各自独立的输出  
   目录），再把结果写到不会撞名的路径下（大写字母做百分号编码，`myau/A` →  
   `myau/%41.java`）。因此 `Myau0729-obf.jar` 的 723 个类能产出 723 个互不覆盖  
   的源文件，而不是 637 个。
4. **坏类隔离**  
   Vineflower 遇到一个读不了的类会让整次运行崩溃。jdec 预先校验每个类，  
   读不了的隔离掉，不让它拖垮其余 7786 个类。
5. **Minecraft 反混淆**  
   `brc` → `CreeperEntity`。支持 Mojang 官方映射（1.14+）、Fabric  
   Intermediary+Yarn、旧版 MCP/tsrg（1.7-1.12）。重映射在字节码层完成，  
   声明处和**所有调用点**一起改名，产出的 jar 类名与路径一致，能被 JVM 加载。

## 安装

需要 JDK 9+（已在 Zulu 21 上验证）。引擎 jar 自动从 Maven Central 下载：

```bash
python jdec.py engines
```

## 用法

先看一眼对面是什么，不反编译：

```bash
python jdec.py probe client.jar
```

反编译（检测到混淆的 Minecraft 会自动尝试反混淆）：

```bash
python jdec.py decompile client.jar -o out
```

常用参数：

| 参数                                      | 作用                                |
| --------------------------------------- | --------------------------------- |
| `-j N`                                  | 并行 JVM 数，默认按 CPU 自动               |
| `--memory 4g`                           | 每个 JVM 的堆                         |
| `--verify-all`                          | 逐个类对照字节码打分，出完整报告（慢一些）             |
| `--limit 300`                           | 只处理前 N 个类，快速试跑                    |
| `--mappings f.txt`                      | 映射文件（proguard / tiny / tsrg 自动识别） |
| `--mapping-set mojang\|yarn\|mcp\|none` | 自动下载哪套映射                          |
| `--mc-version 1.20.4`                   | jar 里读不出版本时手动指定                   |
| `-e cfr,vineflower`                     | 指定引擎顺序                            |
| `--clean-work`                          | 结束后删除中间产物目录（可能有上千个文件，所以默认不删）      |

输出：

```
out/
  src/         反编译后的源码，按包组织
  report.md    人类可读报告（哪些类没还原干净）
  report.json  机器可读，含每个类的状态、分数与输出路径 rel
               （冲突类的 rel 经百分号编码，不等于类名，外部工具从这里反查）
```

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

读的是 Fabric 的 `fabric.mod.json`、Forge/NeoForge 的 `META-INF/mods.toml`、  
旧版的 `mcmod.info`，以及它们声明的 `*.mixins.json`。元数据被删了也没关系：  
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

多个指纹用 noisy-OR 合并，**低于 0.35 一律不给厂商结论** —— 宁可说「未知」，  
也不把弱迹象说成 Positive identification。

## 字符串：混淆之后还能读的线索

代码可以全被改名，但程序总得和外界说话——连的 URL、写的文件、执行的命令、  
校验的 token。这些字面量在常量池里，是混淆器改不掉的东西。

```bash
python jdec.py strings client.jar -o out
python jdec.py strings client.jar --suspicious      # 只留 url / ip / 路径 / 凭据 / 命令 / 机器码
python jdec.py strings client.jar --grep api         # 只留含某个词的
```

产出 `out/strings.tsv`（`类名 → 字符串 → 标签`）和 `strings.json`。  
最便宜的一步分析：不用执行、不用改写，扫一遍就出结果。在真实 MC 客户端上  
抽样 400 个类就捞出了 `https://aka.ms/BuyJavaRealms`、`worldOwnerUuid` 这类线索。

### 运行时捕获：不用懂密钥的那条路（已走通）

静态还原 ZKM 27 的字符串要跨三层（indy 引导的 session key → 常量折叠引擎 →
DES），逐版本易变，不划算。`engines/tap/` 是独立实验：**让混淆器自己解，我们只
盯着出口**。整条链路最终全部打通，按演进顺序：

**第一层：纯解密器重放（119/136 类）。**
- `scan_targets.py` — 常量池静态分类：解密器 / 危险类（native、System.load）/ 安全类。
- `tap_extract.py` — 解码指令流，抽取每个调用点 `A.a(int,int)` / `b(int,long)` 的
  硬编码参数 → `calls.tsv`（14216 调用点 / 315 类）。关键坑：BIPUSH/SIPUSH 的
  arg 存的是无符号值，要手动符号回绕。
- `Reflect.java` — 按类分组重放：`getDeclaredMethod` + `invoke`，逐条落盘。
  裸 JVM 缺依赖就补：loom 缓存的 `minecraft-srg.jar`（1.8.9 notch→SRG 已重映射）
  + log4j 2.0-beta9 + launchwrapper + vineflower。log4j 一补，
  56 个 "Could not initialize class net.minecraft.client.Minecraft" 连坐失败
  一次性消失——很多"本质限制"其实只是缺 jar。

**第二层：毒类之谜 = native 保护壳（noexit agent）。**
27 个类让 JVM 三秒静默退出（exit 127）或 native 崩溃，且无 hs_err——每个都有
SHA1 哈希名的 native 方法（如 `3f343b3c87f0…`），`<clinit>` 里经
`antiLeak-…/Loader.registerNativesForClass` 绑定并做完整性校验。
`NoExit.java` agent 在加载期改写字节码：
- `antiLeak*` 类**全部方法**桩化为按描述符返回零值（native 去 native 化；
  构造器补 `aload_0; invokespecial super.<init>()V; return` 过验证器）；
- `myau/*` 类**只桩化 native 方法**——解密逻辑是纯 Java，桩化必须止步于此，
  否则 `<clinit>` 不执行、密文表全 null、解密器返回垃圾。
结果：40 个毒类一个 JVM 全过，零毒类。myau 覆盖 124/136 类，
13144 条独立解密结果（3112 字符串 + 10032 long 常量）。
坑：`attribute_length` 是 u4 不是 u2；myau 类全桩化会让 `<clinit>` 变 `return`
——看起来"解密成功"其实全是桩返回的常数。

**第三层：s3 名字映射表（撞表）。**
s3 是 ZKM 的反射名翻译层：11 条 16KB base36 blob =
`SHA-512(key) → XOR(SHA-512(key+"SHA-512"), 名字)`，key 就是混淆名本身，
盐 `"SHA-512"`、分隔符 `\b` 全在 `<clinit>` 里明文。`gen_namekeys.py` 用 jar 里
全部类/方法/字段名生成 34714 个候选 key，`DumpTable.java` 在 JVM 里反射调 s3
自己的私有查表函数——零语义偏差。101 条命中：**映射的是"上一代混淆名 → 本代
混淆名"（myau/A → myau/KO），不是原始名**。撞表链路本身值得复用。

**第四层：真环境倾倒（最终答案）。**
模块名的密文表由 native 经 JNI 填充（putstatic 只有 `a`/`d` 是 Java 做的），
静态解密到此为止。终极方案：**在真实 Forge 1.8.9 里跑 mod**——
发行版要加载破解包自带的 `agent.dll`（JVMTI，骗过授权校验），我们的
`DumpAgent.java`（`--release 8` 重编）定时醒来：枚举已加载的 myau.V 子类 →
registry 为空就主动实例化 → 读模块名 + 全部设置项名 → halt。
240 秒延迟（等 FML + 混淆器去重）。产出 `dump_modules.tsv`：
**58 个模块全名 + 设置项全表**（KillAura/Velocity/Scaffold/BedNuker/Xray…，
含每项设置的名字）。坑：`--gameDir` 下 mods/ 目录不存在会静默不加载；
native 校验必须真环境过，noexit 在真环境反而会坏事。

**意外的第五份证据（交叉验证）。** 游戏运行时在 `--gameDir` 下自己序列化写出了
`config/Myau/default.json`——**59 个模块、358 个设置项的名字与默认值**，
是客户端亲手写的全量配置。与反射 dump 交叉验证：**58/59 模块一致，全部共有
模块的 358 个设置项名字逐一对上**（两条独立路径：DumpAgent 反射读 Java 字段
vs 游戏 Gson 序列化设置对象）。唯一差异 `ESP`：json 里有、registry dump 里
没有（对应 dump 头 `modules=59` 与实名 58 的差 1，该模块名字未读出）。
**模块全表以 default.json 的 59 个为准**（AimAssist…Xray：BedWars 向作弊客户端，
含 KillAura 38 项、BedNuker 12 项、Xray 26 项等完整默认参数）。

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

## 实测

Minecraft 1.20.4 客户端（7787 个类，Java 17，官方混淆）：

| 步骤  | 结果                                |
| --- | --------------------------------- |
| 探测  | 混淆度 88/100，识别出 Minecraft 1.20.4   |
| 反混淆 | 7763/7787 类改名，耗时 5.3s，混淆度降到 0/100 |
| 反编译 | 4 进程并行，4 分 14 秒，5055 个源文件         |
| 重试  | 仅 10 个类需要换引擎                      |

`env` → `com.mojang.blaze3d.audio.Channel`，字段 `a/b/c` → `LOGGER/source`。

真实 ZKM 27 样本 `Myau0729-obf.jar`（723 类，其中 84 组是只靠大小写区分的
孪生类）：

| 指标       | 结果                                            |
| -------- | --------------------------------------------- |
| 反编译      | **723 clean / 0 partial / 0 failed**，成员覆盖 100%，175s |
| 冲突类      | 孪生类各自独立还原，磁盘上 723 个源文件互不覆盖（修复前 637 个）          |
| 逐类独立验证   | 84 组冲突两两 sha256 全不同；抽查命中率 100%；无任何类 score < 40 |

## 测试

```bash
python tests/run_tests.py             # 核心
python tests/run_tests.py --with-mc   # 额外跑真实 MC jar（需要 tests/mc/ 样本）
```

**真实样本外置**：工具树里不放真实混淆样本。`--with-mc` 里的 ZKM 归因测试
会依次在 `JDEC_SAMPLE_DIR` 环境变量、jdec 上一级目录、`D:/MC/samples/` 找
`Myau0729-obf.jar`；都不在则该项跳过（其余 115 项照常），放回去即恢复。

关键断言：parse→serialize 字节级一致（否则重映射会静默损坏每个类）、  
重映射后的类仍能被 javap 读取、调用点随声明一起改名、  
mixin 注解里的目标能被提取并过映射翻译、  
所有方法都能解码到指令流末尾、ZKM 结构指纹该报的报、不该报的不报。

mixin / flow / collide 相关的用例依赖 `tests/mixin.jar`、`tests/flow.jar`、  
`tests/collide.jar`，由 `tests/samples/` 下的源码编出来（只用 javac，不依赖  
Mixin 库——注解的*形状*才是 jdec 要读的东西）。collide 是一对只靠大小写  
区分的孪生类，验证 Windows 上 `Widget` 不会拿到 `widget` 的内容：

```bash
python tests/build_fixtures.py     # 重新编译 fixture jar
```

`tests/flow.jar` 里有两个角色：`Decryptor` 照着 ZKM 字符串加密的形状写，  
javac 能诚实地编出来；`Guarded` 是普通 try/catch，测试会**故意把它的异常处理器  
改成向后跳**——javac 不生成这种形状，要验证检测器只能自己造证据。

跑测试时 jar 不存在会自动构建；构建不了（没 javac）就跳过这几项而不是判失败。

## 边界

- C/C++ 原生程序不在射程内，那个只能到汇编和伪代码。
- 反混淆只能还原**名字**，控制流混淆、字符串加密还原不了。
- Minecraft 26.1 起官方不再混淆，新版本不需要映射表。
- 只用于分析你自己拥有或已授权的程序。
