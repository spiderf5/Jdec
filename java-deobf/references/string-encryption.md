# 字符串加密：识别与批量还原

「长 base64/hex 常量」只是入口，真正的判定要看**调用点形态**与**解密器指纹**。

## 六种实现形态

1. **全局共享解密器** —— `ldc "长base64"` + `invokestatic X.ᔆ(Ljava/lang/String;)Ljava/lang/String;`
   Allatori / Stringer / DashO 属此类
2. **带附加工参数** —— DashO 是 `(int, String)` 组合；Smoke 是 `(String, I)`，伴随
   `GETSTATIC/PUTSTATIC [Ljava/lang/String;`；参数常由 `length() ^ 常数 * 常数` 现算
3. **字符异或循环** —— 解密器内 `charAt` + `IXOR` 循环 + `new String(char[])`。
   Allatori 判据是 `charAt` / `length` / `String.<init>` + `IXOR`≥2 + `NEWARRAY`≥1；
   DashO 判据是 `IXOR` + `ISHL` + `toCharArray` 各 ≥1。密钥常是 `static final long` 字段
4. **密文拆整数数组 + 索引查表** —— `bipush 217` + 查表调用，`<clinit>` 里 `ANEWARRAY` + `AASTORE`。
   特征是一串小整数紧邻 `aaload`，而不是长字符串常量
5. **同方法内 switch 多态** —— 一个 `decrypt(int, String)` 按首字节分派不同算法。
   此时「唯一解密方法」假设失效，只能靠执行来解
6. **真·对称加密** —— Zelix 在 Java 7+ 开启 Method Parameter Changes 时用 DES + invokedynamic
   （可用 `ZKM_STRING_ENCRYPT_DES` / `ZKM_STRING_ENCRYPT_INDY` 关闭）。
   AES/DES 的特征不是密文，而是解密器引用了 `javax/crypto/Cipher`、`javax/crypto/spec/*`。
   ClassGuard 则是 RSA+AES 加密**整个 class**，密钥在 native 库按硬编码 offset 取

**每类一个 vs 全局共享**：Zelix / Smoke 倾向每类一个解密器（`invokestatic <本类>.ᔆ`）；
Allatori / DashO / Stringer 倾向全局单例。

## 静态识别：三条件同时满足才动手

1. **调用点集中** —— 绝大多数 `LDC String` 后面紧跟同一条 `INVOKESTATIC`，
   owner + name + desc 三元组完全一致
2. **密文形态异常** —— 大量长 base64/hex、多个 `static final long` 密钥字段、或一个大 `String[]`
3. **解密器指纹** —— 上面各形态的指令特征

只满足一条容易误报：正常业务代码里同样有 `Cipher`、`charAt`。

## transformer 对照（java-deobfuscator）

| 配置项 | 行为要点 |
|---|---|
| `allatori.StringEncryptionTransformer` | 匹配栈顶恰来自单个 `LDC String` 的调用；执行解密后直接改 `ldc.cst` 并删调用；`cleanup` 默认删掉已无引用的解密方法 |
| `dasho.StringEncryptionTransformer` | 用 `ConstantPropagatingSourceFinder` 求栈参常量共识，能穿透常量传播与算术 |
| `stringer.StringEncryptionTransformer` | `LDC + INVOKESTATIC (Object;)String`；把指令克隆进临时 `MethodNode` 交给 JavaVM 执行 |
| `smoke.StringEncryptionTransformer` | `(String;I)String` + 静态 `String[]` |
| `skidsuite2.StringEncryptionTransformer` | `([CLjava/lang/String;I)`；用 `MethodAnalyzer` 重建 `char[]`，解完删掉解密方法 |
| `zelix.StringEncryptionTransformer` / `zelix.v9.*` | 多模式状态机（数组 / legacy 带参 / singleton / 直接调用），并顺带修 flow 混淆；v9 走 JavaVM |

顺序敏感（README 明确 *Order does matter*）。

## Recaf 的另一条路

Recaf 不逐个解密，而是**模拟执行内联**：`Analysis > Deobfuscation` 里的 *Call result inlining*
（目标静态方法可模拟且参数已知时，把调用替换为结果，官方举例 `rot13("uryyb")` → `"hello"`）、
*Static value inlining*（模拟 `<clinit>` 后内联常量字段）。
强一些的解密例程需要手工补一点工作。配套：*Opaque constant folding*、*Variable folding*、*Goto inlining*。
注意 *Enum name restoration* 必须先清掉字符串加密才能用。

## 自写 transformer 的三个切入层级

- **指令级** —— `InstructionPattern` + `InstructionMatcher`（OpcodeStep / CapturingStep / MultiStep…）
- **数据流级** —— ASM `Analyzer<SourceValue>` + `SourceInterpreter`，或项目自研 `MethodAnalyzer`
  的自定义 Frame 体系，再用 `SourceFinder.findSource(...).consensus()` 取常量
- **执行级** —— `MethodExecutor.execute(...)` 或 `JavaVM`（连 native 与 indy 都能跑）。
  替换动作恒为 `modifier.replace(m, new LdcInsnNode(plaintext))`

批量还原的干净做法：枚举全 jar 的解密调用点，逐个用 VM 求值替换成 `LDC`，最后删掉解密方法
—— 这正是 Allatori / SkidSuite2 的 `cleanup` 逻辑。

## 五个常见的坑

1. **解密器有内部状态**（计数器、滚动密钥、一次性初始化标志）→ 必须按原始调用顺序执行。
   java-deobfuscator 的做法是「同一个解密方法只执行一次」，隐含假设**解密无状态或状态自复位** ——
   遇到有状态解密器这条路直接失效
2. **`<clinit>` 初始化顺序** —— 不先跑会拿到 0/null；先跑又可能触发反调试
   （Allatori 用 `getStackTrace` + `getClassName` 双探测抛异常）。
   标准解法是 Stringer v3 那种 `beforeCallHooks` 拦截 `forName0` 把 initialize 置 false
3. **反射 / `Class.forName` 型解密器**静态不可跟随，必须走 JavaVM 或运行期 hook
4. **加密器自身被混淆** —— Zelix 把密钥藏进 Method Parameter Changes，与增强字符串加密叠加后
   「much more resistant」。**必须先解开外层混淆（flow、参数改写、hideaccess）再解字符串**
5. **栈效应等价** —— 解密后删调用必须让 `LDC` 恰好抵消，否则要重建栈帧；
   大量字符串时注意 `-Xmx`、`--add-opens` 与 classpath 完整（缺 rt.jar 会大面积执行失败）

## ZKM 27+ indy 表驱动形态：jdec recover 的自洽重放（EdNaven 实证）

形态：每类内联一份 indy bootstrap `b(Lookup,String,MethodType)` +
fallback `b(Lookup,MutableCallSite,String,Object[])` + 私有解密器
`b(int idx, long key)`。站点字节码 = 动态参数 (idx, key)；
`n2 = idx ^ (int)(key & 0x7FFF) ^ 0x15D2` 定位**每类**密文表 c[]，
DES/CBC/PKCS5（key = 全 64 位 key，IV 全零）解出 UTF-8。
MutableCallSite 首次调用后记忆化——**重放必须每站点新建 CallSite**。

### 决定性结论：解密器有跨类全局状态

同一 (seeds, lookupClass) 的长常量解密调用，静态重放的值 ≠ 任何运行时
值（EdNaven 实测：重放 114073492997383 vs 运行时 54701035319862）。
**"静态重放求 key → 再解密"的两段式必然全错**。唯一可行的是单 JVM 自洽：

1. `Class.forName(目标类, true, cl)` 让 <clinit> 自己算出真字段值；
2. 反射读静态 long 字段（本轮真值）；
3. 按 key 表达式（lit ^ 字段）现场求 key；
4. 调用目标类**自己的** bootstrap，取 CallSite target 用动态参数.invoke。

jdec 命令：`python jdec.py recover X.jar -o out --cp-file <classpath文件>`
（辅助：`indy` 子命令普查 indy 站点，`natives` 子命令提取 native 库）。

### 自洽重放的 classpath 工程（Windows 实证）

- MC 客户端：拿启动器实例的 vanilla jar（官方混淆名），用 jdec 自身
  remap 到目标版本 intermediary（`--mapping-set` 逻辑或 parse_tiny 直用），
  **必须剥 META-INF 签名**（*.SF/*.RSA）否则 SHA 校验炸。
- 依赖库：启动器实例 version.json 的 libraries 全量；嵌套 fat-jar 的
  META-INF/jars/*.jar 是 mod 自带精确版本，一并上 classpath。
- 缺什么补什么：slf4j-api（MC 1.21.11 的 json 不带但类要）、
  空 stub（gen 思路：扫 jar 常量池的外部类，emit 空类）垫底。
- `-Xverify:none` 必开（stub 破坏类型层级，StackMap 校验必炸）。
- java @argfile 传超长 classpath（Windows 命令行 ~32K 上限）；
  **@argfile 里反斜杠是转义符**——所有路径统一正斜杠。
- 库多版本同灶时按"构件名去重保最新"，否则旧 log4j-api 抢先加载。

### 覆盖边界（诚实清单）

- 引导参数里含运行时对象（this/新实例）的站点：驱动侧传 null 占位，
  bootstrap 忽略该参数则解密成功，真读则失败——成败如实记录。
- 解密 init 方法的参数来自 native 的（EdNaven dispatcher 6666 条）：
  静态不可达，须真机 attach。
- 混淆目标编译期 intermediary 与运行时版本不一致（跨版本 mod 常见）时，
  classpath 需按"cheat 引用什么名字"准备对应版本的映射产物。

## 解密器"变体家族"：Python 硬编码不可行，直接上 recover（JadeOffline 实证 2026-10-04）

同一位私有混淆器会给**每个类生成一个专属 BSM**（一行 indy 统计里表现为
几十个 owner 各 ~140 站点）。这些解密器是同一算法模板的**常数随机化变体**：
TABLE 相同、雪崩结构相同、但乘数/加数/移位量/索引公式逐类不同
（实测 A 型 `seed ^ i*73244475` vs B 型 `seed-1640531527-i*5+2` 索引）。

教训链：

1. Python 抄算法离线重放**只覆盖显式分析过的变体**（本例 2080/6516），
   其余全是 BAD——除非愿意逐类逆向常数，否则别走这条路；
2. 解密器若是**纯函数**（ConstantCallSite(constant(String))、无全局状态），
   recover 自洽重放**零 classpath 开箱即用**，对全部变体通吃
   （6516/6516，0 skip——goto 洪水不一定毁表达式栈，本样本 0 个）；
3. 判定顺序：先看反编译源码里 BSM 是不是 `ConstantCallSite + constant(String)`
   纯常量替换、有无静态可变字段——纯函数 → recover 一把梭；
   有跨类全局状态 → 走上一节的自洽 classpath 工程；
4. BSM 静态参数 (String cipher, int seed) 挂在 **BsmEntry.args**（bootstrap
   条目级），站点数 ≈ BSM 条目数（6822 vs 6811），基本 1:1；
5. 解密产物可能不是普通字符串而是**嵌套容器**（"JVM\x01" 魔数 + 自定义
   序列化 → loader107 字节码解释器）：按可读性过滤，容器另案处理。

## 回填：recover --rewrite-src 一条龙出零残留源码（2026-10-04 并入）

收了明文只算一半——**最后一公里是把明文写回反编译源码**，否则读源码的人
满屏 `Xxx.decrypt("Q2ZnbA==", 42)`。现在一条命令完成：

```bash
python jdec.py decompile X.jar -o out          # 先出干净 src/
python jdec.py recover X.jar --output out/recover \
        --rewrite-src out/src --timeout 7200    # 收割 + 回填，一条命令
```

- 匹配键 = `(cipher, seed)`（BSM 条目静态参数），driver 的 OK 行自带这两列；
- rewrite 的正则按 CFR/其他引擎产出的 BSM 调用形态
  `Cls.method("site", "cipher", seed)` 匹配，空白类含 CR/LF（长参数折行）；
- 残留 = FAIL/SKIP 站点 + 非三参形态，如实报告不硬凑。

### 坑一：BSM 静态参数按"方法签名"做键会被同类条目互相覆盖（大坑）

同一个解密器方法会被**同一使用类的多个站点**引用，而每个站点的
BootstrapMethods 条目携带**各自的** `(cipher, seed)`。driver 若按
`bsmKey(方法)` 做键存静态参数，类内条目互相覆盖——全部站点拿到
**最后一个条目**的参数：

- 解密结果错（产出 `'/'`、`'"'` 这类短垃圾，看着像字符串，极具迷惑性）；
- OK 行的键与源码字面量错位 → 回填大量 miss（实测 2730/6516）；
- 识别特征：**唯一键数远小于站点数**（3735 键 vs 6516 站点；健康时
  键≈站点数）、同一键出现在多个类、单站点类全对而多站点类全错。

修复 = 按 **B 行条目 idx** 做键（S 行本来就带 bsmIdx），换类时清空。
判案过程见 jade-out 诊断：先用"残留站点 siteName 是否在 OK 行里"定位到
"站点有 OK 行但键错位"，再抽点比对锁定覆盖模式——比纯读代码猜快得多。

### 坑二：修复覆盖后，运行时长会暴增到 30 分钟以上

覆盖时同类 140 个站点共用一组参数，解密器内部的静态缓存让后面 139 个
站点秒回；修复后**每站点真解密**，6516 站点实测 ~35 分钟。默认
`timeout=1800s` 会截杀且当时全部输出作废——现在 `--timeout` 可配，
超时也会保留部分输出（但请直接给够，比如 7200）。

### 明文正确性终验

用独立实现交叉验证：硬抄算法的 Python 解密器（哪怕只覆盖部分变体）
按 `(fqcn, seed)` 与 recovered.tsv 对齐比对 plain。纯函数家族两边必须
完全一致；不一致 = driver 还有键位 bug。

## 路线分岔：ZKM 字符串池（无 indy）→ JVM replay

recover 的 bootstrap 重放只覆盖 indy 形态。ZKM 还有一种**无 indy 的字符串池**
形态（lf21 1.20.1 实战），识别特征与打法完全不同：

### 形态识别

- 反编译源里大量 `Cls.a(<int>, <int>)` 单字母双 int 参调用（一个池类
  动辄几百个调用点，散布全库）；池类本体有
  `private static String a(int n, int n2)` + `static String[] b/e` + `static {}`。
- clinit：一条**packed 载体串**（长串字面量），按"长度前缀"切片 +
  7 项小 key 表 XOR → 密文池 `b[]`（每类条目数不同，`new String[N]` 可见）。
- 访问器：`idx ^ 常数 & 0xFFFF` 定址；**按密文首字节查 256 项 key 表**
  取 base key；seed（调用点第二参）派生奇偶双滚动 key，滚动更新**喂明文**
  (`k = (ror3(k) ^ plain) & 0xFF`)。**逐类常数/key 表全不同**——静态移植
  每类一套，不现实。
- 另有少量**内联单串**形态：clinit 里 `"密文".toCharArray()` + `i % N`
  小表 XOR + intern，直接赋 static final String（模块名等短串）。这个可以
  纯静态解：声明↔intern 按**块内顺序配对**（CFR 会把数组变量改名，
  别按变量名配）。

### replay 路线（真类加载替代算法移植）

**已工具化（2026-10-04，lf21 池形态实战沉淀）**：
`python jdec.py pool scan <src> -o spec.tsv` → `pool harvest spec.tsv -o
harvest.tsv --cp-file libs.txt` → `pool apply <src> --harvest harvest.tsv
-o src_pool` 三步覆盖本节全部流程：访问器/调用点扫描（int/long 形状自适应、
0x/八进制/L 后缀）、PoolDriver 反射重放（类初始化失败缓存、四种参数组合、
E 行带最深 cause）、回填（\u 转义 + 字面量 round-trip 校验 + 可解站点零
残留 verify）+ E 行进失败八桶归因。手写脚本只剩环境组装（下面三件套）。

1. **spec**：扫反编译源，收集 `(池类, 访问器名, idx, seed)` 全部调用点
   （类限定 + 池类文件内裸调用两种都要；idx/seed 注意 0x 十六进制字面量）。
2. **driver**：`Class.forName(init=true)` 触发 clinit（池数组就位）→
   `getDeclaredMethods` 按"名字+2参+返回String"找访问器 → `invoke` 逐站点
   收明文 → TSV（明文 base64，避免编码问题）。类初始化失败缓存进 failed
   集合快速跳过；**结束时 System.exit(0)**。
3. **classpath 是成败关键**（见下节）。回填 = 源码里把调用表达式替换成
   Java 字面量（json.dumps 的 \uXXXX 转义直接可用）。

### replay 的环境工程三件套（lf21 实测坑）

- **自造匹配命名系的 MC jar**：mod 字节码引用"官方类名+SRG成员"（FG dev
  命名）。FG 缓存的 minecraft_repo client.jar 是 `net/minecraft/src/C_NNNN_`
  中间态，**不能直接用**；要下原始 client.jar（version.json 里有 URL+sha1），
  用 jdec mappings **组合映射**：成员名取 mcp_config joined.tsrg
  （m_/f_），类名取 Mojang ProGuard client.txt（官方名）——两个 Mapping
  拼 classes+members 即可。7436 类重映射约 9 秒。
- **lwjgl 全家要不要剔——按失败归因逐类取舍，别一刀切**（lf21 对标实测：
  全剔错杀 4 个只摸常量的池类；带上 lwjgl-api 仅 1 类真崩）。规则修订版：
  **加载 ≠ 调 native**——GLFW/GL 系**常量类**（纯 static final 常量）
  加载是安全的；clinit 里真调 native 函数的类才会 `EXCEPTION_ACCESS_VIOLATION`
  崩 JVM（hs_err: lwjgl_opengl.dll）。打法：classpath **带上 lwjgl-api**
  （纯常量 jar，无 natives），真崩的类进 failed 集合单独认输——recover 的
  failed_triage.md 会把 NCDFE/CNFE 且 `:\s*org[./]lwjgl` 的归进
  lwjgl-constants 桶给出处置。宁可多崩一两个类，不要错杀一片。
  `-Xverify:none` 另可救"被动签名引用卡验证器"的类。
- **MSYS/Git Bash 五坑**（全部实测踩过）：
  ① 长多 jar classpath 里 `/c/...` 混 `;` 会被路径转换搅坏——用
  `cygpath -w` 转 Windows 路径 + `MSYS2_ARG_CONV_EXCL="*"`；
  ② 但 EXCL="*" 会把 **TSV 参数**的转换也禁掉——java 收到 `/d/...`
  找不到文件**静默崩**（输出文件根本没被重写，数字看着像跑过了）——
  参数一律写 `D:/...` 风格；
  ③ cwd 不持久，命令链里相对路径读文件读空气——工具文件一律绝对路径；
  ④ **grep 把含裸控制字节的文件判成 binary**，`-o` 模式静默不输出——
  统计（数 m_ 调用、数残留站点）凭空少一大截（lf21 实测 6902 被算成
  3221）。一律 `grep -a`（--binary-files=text）；回填写盘统一 `\uXXXX`
  转义，不落裸字节，从根上消灭 binary 判定；
  ⑤ `awk -F:` 吃掉 Windows 盘符冒号（`D:/...` 被切成 `D` 和 `/...`），
  求和/计数全变 0——用 `$NF` 取末字段或进树内用相对路径。
  另：对单行 classpath 文件做 `grep -iv lwjgl` 会把整行删掉，先 `tr ";" "\n"`
  分行再过滤再 paste 回去。

### 收益与边界

lf21: 4567 唯一键恢复 4434（97.2%）+ 内联 31 处全解。残留 = 池类 clinit
真调 MC 运行时（`Minecraft.getInstance()` 解引用、authlib API 版本差、
forge eventbus 缺包）——没有真游戏进程就到头了，属结构性边界。

**失败清单必须逐类归因，禁止统一叙事**（lf21 对标实测教训：把 11 个失败
类一句"结构性边界"带过，实际其中 4 个是 lwjgl 常量类错杀、可修——另 7 个
才是真边界）。每批失败都要问：是同一根因吗？有哪几个换个环境/换个小补丁
就能救？recover 已内置自动归因：跑完输出 `failed_triage.md`（native /
lwjgl-constants / missing-class / needs-instance / needs-bootstrap /
signature / clinit-chain / other 八桶，各带处置建议）——拿到失败清单先读
它，别先写结论。

**回填的编码卫生**：替换字面量统一 `\uXXXX` 转义（json.dumps 默认行为），
不要把原始字符或 surrogateescape 裸字节写进源码——裸控制字节会让下游所有
grep/diff 把文件判成 binary，静默漏统计、对不上账（见上面 MSYS 第④坑）。

## 第三形态：clinit 内联切片解密 → static 字段（Elowen 2026-10-05）

ZKM 字符串加密的第三种实战形态（前两种：indy 加密→recover；访问器池→pool）。

**形态识别**：clinit 里 `new String[N]` 局部数组 + packed 载体串 +
`substring(v1, v1+len)` 切片循环 + 解密 helper（CFR 重组后是
`while(true){...break blockN}` 交错）→ 结果写 `static final String[]`
与 `static final String` 字段。**无自定义 indy bootstrap**（indy 普查全为
LambdaMetafactory/StringConcatFactory）。pool scan 零命中（没有两参访问器）
就是此形态的信号。

**收割法（不需要写解密器，也不需要 jdec 工具）**：明文在类加载后直接躺在
static 字段里——JDK 真类加载触发 clinit + 反射读字段即全收。FieldDump.java
（~60 行）：逐类 `Class.forName(cn)`（默认初始化）→ `getDeclaredFields()`
过滤 static String/String[] → base64 落 TSV（S/A 行），失败单行 FAIL 留归因。

### Java 版本硬约束

样本 Java 25 字节码（class v69）→ **replay 必须真 JDK 25 运行时**，
Java 21 加载即 UnsupportedClassVersionError。Temurin 25 从清华 Adoptium
镜像 20 秒到手；`api.adoptium.net` 会重定向 GitHub（实测 8KB/s，不可用）：
`https://mirrors.tuna.tsinghua.edu.cn/Adoptium/25/jdk/x64/windows/`。

### MSYS 坑复烧（全部实证）

1. **含分号混合盘符长 classpath 被路径转换搅坏**：现象是 365/366 假
   ClassNotFoundException（单类短 classpath 加载即正常）。~~根治：JDK
   `@argfile`~~ **（2026-10-05 修正：argfile 对超长 cp 会静默假应用——
   6.6KB 的 cp 写进 argfile 后部分 jar 失效/`-XshowSettings` 里
   java.class.path 直接为空，运行不报错、结果半真半假最骗人）**。
   **真根治：`CLASSPATH` 环境变量**——MSYS 不转换 CLASSPATH env，实测
   6.9KB cp 全量生效；类名参数（非路径）可安全走命令行/argfile。
2. `/tmp` 会被转换成 `D://tmp`（当前盘符根）——java 的输出目录/参数一律
   写 Windows 风格相对或绝对路径。
3. `javac` 不带 `-d` 时 .class 落在当前目录，classpath 记得对上。

### 收益与边界（Elowen 实测）

196/366 类加载成功，收 254 条明文（覆盖 47 类）。失败 170 类分桶：
102 摸 MC 运行时（需对应版本 Fabric 全家桶）、47 连坐（依赖前桶失败类）、
21 缺独立库（gson/joml/skija/fabric-api，补 jar 即救）。jar 常量池
可疑串=0 时优先怀疑此形态——解密类 clinit 纯字符串操作，最小 classpath
（样本 jar + log4j）就能收走大半。

### 全量收割配方（Elowen 2026-10-05 续：196/366 → 365/366）

裸最小 classpath 只能收大半；全量收割 = 组装目标运行时全家桶 + driver 预引导。

**classpath 组装（Fabric 新版 / mojmap 直读时代）**：
- MC 客户端：piston-meta `version_manifest_v2.json` → 版本 json →
  `downloads.client.url`（sha1 校验）。**26.x 起官方 jar 即 mojmap 名，
  无需重映射**（hook/引用直接对上）。
- libraries：版本 json `libraries[].downloads.artifact` 全量下载、剔
  `natives-` 平台包（类加载不需要 native）；joml/gson/brigadier/fastutil
  都在这里，不用单独找。
- fabric-loader（maven.fabricmc.net）+ fabric-api（`+26.3` 后缀版本）；
  **asm 五件套（asm/-tree/-analysis/-commons/-util）必补**——loader
  ClassTweaker 硬依赖，缺了初始化链全断（现象：loader jar 在 cp 上却
  NCDFE org/objectweb/asm/ClassVisitor）。
- 样本 `META-INF/jars/*` 嵌套 jar（skija 三件套等）解出来直接上 cp——
  版本就是作者实测的那份。

**driver preinit 三件套（FieldDump.main 开头，全部 try/catch 降级）**：
1. **FabricLoader gameDir 注入**：样本 clinit 会真调
   `FabricLoader.getInstance().getGameDir()`——裸 JVM loader 已初始化但
   gameDir 未设置 → `IllegalStateException: invoked too early?`。反射设
   `FabricLoaderImpl.INSTANCE` 的私有 `gameDir`/`configDir` 字段。
2. **MC 引导**：`SharedConstants.tryDetectVersion()` +
   `Bootstrap.bootStrap()`（官方单测同款）——不做则
   Blocks/BuiltInRegistries/LivingEntity 等注册表系 clinit 全炸并连坐。
3. **gamedir 目录预创建**：样本 clinit 可能真开文件
   （`Elowen-NextGen/antibots.log` 的 FileWriter）——目录不存在 =
   FileNotFoundException 连坐。顺便：**clinit 开的文件名就是免费情报**。

**访问标志补丁（hideAccess 形态反噬）**：ZKM 剥过 MC private 字段的访问
检查 → 裸 jar 上 `IllegalAccessError`。用 jdec classfile 模块
（parse → 改 `field.access_flags` private→public → serialize 字节级保真）
重打包 client.jar 副本。**rezip 必须剔 `META-INF/*.SF|*.RSA|*.DSA`**——
改了签名条目后 JVM 校验 digest 直接 SecurityException 杀类加载。

**死代码判定法（网络定性收尾）**：全量解密后 0 URL/IP ≠ 完，还要查
"有网络能力但没接线"——对可疑网络类做**字节码常量池 xref**（扫全 jar 的
Methodref/Fieldref 指向它的引用数）：0 引用 = 孤儿类（死代码/为未来版本
预留），配合"反编译树零调用点 + 解密串零类名反射串"三证齐才下结论。
Elowen 的伪造 Firefox UA HTTP 客户端即此结局。

**成绩对照**：最小 cp 196/366（254 条）→ 全量配方 365/366（1203 行/
917 唯一），唯一剩 1 类 = clinit 取 mod 单例（`Elowen.S()` 为 null，
需真机 mod 初始化，结构性）。
