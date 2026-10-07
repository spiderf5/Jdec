# 字符串加密：分类、识别与批量还原

「长 base64/hex 常量」只是入口，真正的判定依据是**调用点形态**与**解密器
指纹**。本文给出实现形态的分类学、静态识别准则、还原路线及工程化要点。

## 1. 实现形态分类

| # | 形态 | 典型特征 | 代表产品 |
|---|------|----------|----------|
| 1 | 全局共享解密器 | `ldc "长base64"` + `invokestatic X.m(String)String` | Allatori / Stringer / DashO |
| 2 | 带附加工参数 | `(int, String)` / `(String, int)` 组合，伴随 `GETSTATIC/PUTSTATIC [Ljava/lang/String;`，参数常由 `length() ^ c1 * c2` 现算 | DashO / Smoke |
| 3 | 字符异或循环 | `charAt` + `IXOR` 循环 + `new String(char[])`；密钥常为 `static final long` | Allatori / DashO |
| 4 | 密文拆整数数组 + 索引查表 | `bipush N` 紧邻 `aaload`；`<clinit>` 内 `ANEWARRAY` + `AASTORE` | 多家 |
| 5 | 同方法 switch 多态 | 单个 `decrypt(int, String)` 按首字节分派算法——"唯一解密方法"假设失效 | 少数 |
| 6 | 真对称加密 | 解密器引用 `javax/crypto/Cipher` 与 `javax/crypto/spec/*` | Zelix（DES + indy）/ ClassGuard（RSA+AES 加密整个 class） |

**作用域维度**：Zelix / Smoke 倾向每类一个解密器（`invokestatic <本类>.m`）；
Allatori / DashO / Stringer 倾向全局单例。

## 2. 静态识别：三条件同时满足才动手

1. **调用点集中**——绝大多数 `LDC String` 后紧跟同一条 `INVOKESTATIC`，
   owner + name + desc 三元组一致；
2. **密文形态异常**——大量长 base64/hex、多个 `static final long` 密钥
   字段、或一个大 `String[]`；
3. **解密器指纹**——第 1 节所列指令特征。

单条件易误报：正常业务代码同样出现 `Cipher`、`charAt`。

## 3. 开源 transformer 与自写层级

### 3.1 java-deobfuscator 对照

| 配置项 | 行为要点 |
|---|---|
| `allatori.StringEncryptionTransformer` | 匹配栈顶恰来自单个 `LDC String` 的调用；解密后改写 `ldc.cst` 并删调用；`cleanup` 删除无引用的解密方法 |
| `dasho.StringEncryptionTransformer` | `ConstantPropagatingSourceFinder` 求栈参常量共识，可穿透常量传播与算术 |
| `stringer.StringEncryptionTransformer` | `LDC + INVOKESTATIC (Object;)String`；指令克隆进临时 `MethodNode` 交 JavaVM 执行 |
| `smoke.StringEncryptionTransformer` | `(String;I)String` + 静态 `String[]` |
| `skidsuite2.StringEncryptionTransformer` | `([CLjava/lang/String;I)`；`MethodAnalyzer` 重建 `char[]`，解完删方法 |
| `zelix.StringEncryptionTransformer` / `v9` | 多模式状态机（数组 / legacy 带参 / singleton / 直接调用），顺带修 flow；v9 走 JavaVM |

顺序敏感（官方文档注明 *Order does matter*）。

### 3.2 Recaf 路线

不逐个解密，而是**模拟执行内联**：*Call result inlining*（目标静态方法可
模拟且参数已知时替换调用为结果）、*Static value inlining*（模拟 `<clinit>`
后内联常量字段）。配套 *Opaque constant folding* / *Variable folding* /
*Goto inlining*。注意 *Enum name restoration* 必须先清除字符串加密。

### 3.3 自写 transformer 的三个层级

- **指令级**：`InstructionPattern` + `InstructionMatcher`（OpcodeStep /
  CapturingStep / MultiStep）；
- **数据流级**：ASM `Analyzer<SourceValue>` + `SourceInterpreter`，或自研
  Frame 体系 + `SourceFinder.findSource(...).consensus()`；
- **执行级**：`MethodExecutor.execute(...)` 或 `JavaVM`（可执行 native 与
  indy）。替换动作恒为：以明文 `LdcInsnNode` 替换调用，最后删除解密方法
  （即 Allatori / SkidSuite2 的 `cleanup` 语义）。

### 3.4 通用陷阱

1. **解密器有内部状态**（计数器、滚动密钥、初始化标志）→ 必须按原始调用
   顺序执行；"同一解密方法只执行一次"的常见隐含假设此时失效；
2. **`<clinit>` 初始化顺序**——不先跑得 0/null；先跑可能触发反调试
   （如 `getStackTrace` + `getClassName` 双探测）。标准对策是拦截
   `Class.forName0` 将 initialize 置 false（Stringer v3 的 beforeCallHooks
   模式）；
3. **反射 / `Class.forName` 型解密器**静态不可跟随，必须走 JavaVM 或
   运行期 hook；
4. **解密器自身被外层混淆**——必须先剥离外层（flow、参数改写、hideAccess）
   再解字符串；
5. **栈效应等价**——删调用必须让 `LDC` 恰好抵消，否则重建栈帧；大批量时
   注意 `-Xmx`、`--add-opens` 与 classpath 完整性。

## 4. 形态 A：invokedynamic bootstrap（自洽重放）

### 4.1 形态

每类内联一份 indy bootstrap `b(Lookup, String, MethodType)` + fallback
`b(Lookup, MutableCallSite, String, Object[])` + 私有解密器
`b(int idx, long key)`。站点字节码 = 动态参数 `(idx, key)`；定位式
`n = idx ^ (int)(key & 0x7FFF) ^ C` 索引每类密文表；DES/CBC/PKCS5
（key 为完整 long，IV 全零）解出 UTF-8。MutableCallSite 首次调用后记忆化
——重放必须每站点新建 CallSite。

### 4.2 决定性判定：解密器有跨类全局状态

若解密引用可变静态字段（滚动密钥等），同一静态参数的**静态重放值 ≠ 任何
运行时值**，"静态求 key → 再解密"的两段式必然全错。唯一可行路径是
**单 JVM 自洽重放**：

1. `Class.forName(目标类, true, cl)` 使 `<clinit>` 自行算出真字段值；
2. 反射读取静态字段（真值）；
3. 按 key 表达式（字面量 ^ 字段值）现场求 key；
4. 调用目标类**自身的** bootstrap，取 CallSite target 以动态参数 invoke。

jdec 命令：`python jdec.py recover X.jar -o out --cp-file <classpath文件>`
（辅助：`indy` 子命令普查站点）。

### 4.3 自洽重放的 classpath 工程

- 平台客户端：取原始 client jar（version.json 提供 URL + sha1），先 remap
  到所需命名系——`python jdec.py decompile client.jar --deobf --mc-version <v>
  --mapping-set <set>` 会在 [0/5] 阶段产出 `client_deobf.jar`，后续步骤一律
  用它；**必须剥离 META-INF 签名**（*.SF/*.RSA），否则
  digest 校验失败；
- 依赖库：平台 version json 的 libraries 全量；目标 jar `META-INF/jars/*`
  嵌套 jar 是作者锁定的精确版本，直接上 classpath；
- 缺失项补齐：日志门面、空 stub（扫描常量池外部类后生成空类）垫底；
- `-Xverify:none` 必开（stub 破坏类型层级，StackMap 校验会失败）；
- 超长 classpath 经 `CLASSPATH` 环境变量传递（见第 12 节坑 6）；
- 同名多版本构件按"保最新"去重，避免旧版本抢先加载。

### 4.4 覆盖边界

- 引导参数含运行时对象（this / 新实例）的站点：驱动侧传 null 占位，
  bootstrap 忽略则成功，真读则失败——成败如实记录；
- 解密初始化参数来自 native 层的：静态不可达，须真机 attach；
- 编译期与运行时命名系不一致（跨版本组件常见）时，classpath 需按目标
  引用的名字准备对应映射产物。

## 5. 变体家族：硬编码重放不可行

同一私有混淆器常为**每个类生成专属 BSM**（统计上表现为数十个 owner 各含
大量站点），解密器是同一算法模板的**常数随机化变体**：表结构相同、雪崩
结构相同，但乘数/加数/移位量/索引公式逐类不同。

1. Python 抄算法离线重放只覆盖显式分析过的变体（个案中约 1/3），其余
   全错——除非逐类逆向常数，否则不走这条路；
2. **判定顺序**：反编译确认 BSM 是否 `ConstantCallSite + constant(String)`
   纯常量替换、有无静态可变字段——纯函数 → 自洽重放开箱即用，对全部
   变体通吃；有跨类全局状态 → 走第 4.2 节的 classpath 工程；
3. BSM 静态参数挂在 BootstrapMethods 条目级，站点数 ≈ 条目数（基本 1:1）；
4. 解密产物可能是嵌套容器（魔数 + 自定义序列化 → 内嵌解释器）：按可读性
   过滤，容器另案处理。

## 6. 源码回填（recover --rewrite-src）

```bash
python jdec.py decompile X.jar -o out          # 先出干净 src/
python jdec.py recover X.jar --output out/recover \
        --rewrite-src out/src --timeout 7200    # 收割 + 回填
```

- 匹配键 = BSM 条目静态参数；driver OK 行自带键列；rewrite 按反编译器
  产出的调用形态匹配（容忍 CR/LF 折行）；残留 = 失败站点 + 非标准形态，
  如实报告。

### 6.1 键位覆盖缺陷（高危）

同一解密方法被同类的多个站点引用，而每个站点的 BootstrapMethods 条目
携带**各自的**静态参数。若 driver 按"方法"做键存参数，类内条目互相覆盖，
全部站点拿到**最后一个**条目：

- 解密产出短垃圾（形似合法字符串，极具迷惑性）；
- OK 行键与源码字面量错位 → 回填大量 miss；
- 识别特征：**唯一键数远小于站点数**（健康时键 ≈ 站点数）、单站点类全对
  而多站点类全错。

修复 = 按 BootstrapMethods **条目 idx** 做键，换类清空。定位手段：以
"残留站点是否在 OK 行"入手，再抽样比对锁定覆盖模式——比读代码猜测快。

### 6.2 运行时预算

修复键位覆盖后，静态缓存失效，**每站点真解密**，耗时可达数十分钟；默认
timeout 会截杀且输出作废——给足预算（如 7200s）。

### 6.3 正确性终验

用独立实现交叉验证：硬抄算法的解密器（哪怕只覆盖部分变体）按
`(fqcn, seed)` 与 recovered 输出对齐比对。纯函数家族必须完全一致；不一致
= driver 仍有键位缺陷。

## 7. 形态 B：访问器池（双参）— scan / harvest / apply

recover 的 bootstrap 重放只覆盖 indy 形态。无 indy 的**访问器池**形态：

### 7.1 形态识别

- 反编译源大量 `Cls.a(<int>, <int>)` 单字母双整参调用（单池类数百个调用点）；
  池类含 `private static String a(int, int)` + `static String[]` + `<clinit>`；
- clinit：packed 载体串按长度前缀切片 + 小 key 表 XOR → 密文池（`new String[N]`）；
- 访问器：`idx ^ C & 0xFFFF` 定址，按密文首字节查 256 项 key 表取 base key，
  seed 派生双滚动 key，滚动更新喂明文。**逐类常数与 key 表全不同**——静态
  移植每类一套，成本不可行；
- 另有少量**内联单串**形态：`"密文".toCharArray()` + 小表 XOR + intern 直接
  赋 static final String——可纯静态解：声明与 intern 按**块内顺序配对**
  （反编译器会重命名数组变量，勿按变量名配对）。

### 7.2 三步工具流

```
python jdec.py pool scan  <src> -o spec.tsv
python jdec.py pool harvest spec.tsv -o harvest.tsv --cp-file libs.txt
python jdec.py pool apply <src> --harvest harvest.tsv -o src_pool
```

覆盖：访问器/调用点扫描（int/long 形状自适应、hex/octal/L 后缀）、PoolDriver
反射重放（初始化失败缓存、多参组合、失败行带最深 cause）、回填（\uXXXX
转义 + 字面量 round-trip 校验 + 可解站点零残留 verify）+ 失败八桶归因。

### 7.3 环境工程三件套

1. **自造匹配命名系的平台 jar**：组件字节码引用"官方类名 + 中间成员名"
   时，以原始 client jar（version.json 提供 URL+sha1）为底，组合两套映射
   （类名一套、成员名一套）重映射；
2. **native 依赖的取舍按失败归因逐类定**：`加载 ≠ 调 native`——纯常量类
   加载安全，clinit 真调 native 函数的类才会崩 JVM。classpath 带上纯常量
   jar，真崩的类进 failed 集合单独认输，不错杀一片；
3. **`-Xverify:none`** 可解"被动签名引用卡验证器"的类。

### 7.4 失败归因八桶

recover 自动输出 failed_triage.md：native / lwjgl-constants / missing-class /
needs-instance / needs-bootstrap / signature / clinit-chain / other，各带
处置建议。每批失败必问：是否同一根因？哪些换个环境即可救？

### 7.5 编码卫生

回填字面量统一 `\uXXXX` 转义（json.dumps 默认行为），不落原始字符或
surrogateescape 裸字节——裸控制字节使下游 grep/diff 判为 binary，静默漏
统计。

## 8. 形态 C：clinit 切片 → static 字段（类加载 + 反射收割）

### 8.1 形态识别

clinit 内 `new String[N]` + packed 载体串 + `substring` 切片循环 + 解密
helper（反编译呈现为 `while(true){...break blockN}` 交错）→ 写入
`static final String[]` / `static final String`。**无自定义 indy
bootstrap**（indy 普查全为标准 Lambda/StringConcat 工厂），pool scan 零
命中即此形态信号。

### 8.2 收割法

明文在类加载后驻留于 static 字段：逐类 `Class.forName(cn)`（默认初始化）→
`getDeclaredFields()` 过滤 static String/String[] → base64 落 TSV
（S 行 = 单串，A 行 = 数组元素），失败单行 FAIL 留归因。driver ~60 行。

### 8.3 class 版本硬约束

class v69（Java 25）目标必须以真实 JDK 25 运行时加载。发行渠道注意：
部分镜像速度远优于官方重定向链路。

### 8.4 最小 → 全量收割配方

最小 classpath（目标 jar + 日志门面）即可收大半；全量收割 =
**目标运行时全家桶 + driver 预引导**：

- 平台客户端：官方元数据渠道取 client jar（校验 sha1）；新版本线官方 jar
  即正式名，无需重映射；
- libraries：版本元数据的 artifact 全量（剔除 `natives-` 平台包——类加载
  不需要）；
- 模块加载器/组合 API 全家：**ASM 家族必须补齐**（加载器 ClassTweaker 硬
  依赖，缺失时初始化链整体断裂）；
- 目标 jar 内嵌 `META-INF/jars/*` 解出直接使用（作者锁定的版本）。

**driver preinit 三件套**（全部 try/catch 降级）：

1. **加载器路径注入**：目标 clinit 若真调 `Loader.getInstance().getDir()`
   类 API，裸 JVM 下 loader 已初始化但路径字段未设——反射写入
   loader 单例的私有路径字段；
2. **平台引导**：`tryDetectVersion()` + `bootStrap()`（官方单测同款），
   否则注册表系类 clinit 失败并级联；
3. **目录预创建**：clinit 可能真开文件——目录不存在即级联失败。同时，
   **clinit 打开的文件名本身就是免费情报**。

### 8.5 访问标志补丁

混淆器剥除平台 private 字段的访问检查时，裸平台 jar 上会抛
IllegalAccessError。用 classfile 模块改写字段 access_flags 后重打包副本；
**rezip 必须剔除 `META-INF/*.SF|*.RSA|*.DSA`**——签名条目被修改后 JVM
digest 校验直接 SecurityException。

### 8.6 死代码判定（网络定性收尾）

全量解密后 0 URL/IP 还不够：需排除"有网络能力但未接线"。对可疑网络类做
**常量池交叉引用统计**（全 jar Methodref/Fieldref 指向它的引用数）：0 引用
= 孤儿类（死代码或为后续版本预留）；配合"反编译树零调用点 + 解密串零类名
反射串"三证齐备方可下结论。

## 9. 形态 D：单参池（静态解密，无需 JVM）

某家族（Transformer 套件型保护器）的字符串池：

- 访问器 `(C)Ljava/lang/Object;` = `GETSTATIC pool; ILOAD idx; AALOAD; ARETURN`；
- 加密序：`[len_le16][utf8]...` 拼接 → 追加 SHA-256(32B) → DES/CBC/PKCS5
  （key = 随机 8B **内嵌为第二个 LDC**，IV = 8×0x00）→ 随机置换 swp[256]
  正向替换 → ISO-8859-1 大 LDC；
- 解密序（clinit 内生成的 Java）：data/key 两个 LDC → `getBytes("ISO_8859_1")`
  → **256-case tableswitch = swp 逆置换**（静态可抓）→ 逆置换 → DES 解密 →
  SHA-256 校验（XOR 归零比较）→ 按 len 切分入 Object[] 池。

**完整静态解密配方**：抓 clinit 两个大 LDC + switch 表 → 逆置换 → DES →
校验 → 切分。jdec 实现：`python jdec.py opspool X.jar`（DES 走自带纯 python
实现；无 JVM、无第三方依赖）。

## 10. ZKM 技术到字节码映射（源码级，七技术）

`StringEncryptionTechnique` 枚举给出全部技术；发射逻辑集中于单一 switch：

| 技术 | 发射序列 | 还原覆盖 |
|---|---|---|
| LOCAL_ARRAY_AND_INDEX | `aload N` [+ idx, aaload]——明文在**方法局部数组** | 静态三路全盲（无 static 字段、无访问器、无 indy） |
| FIELD_ARRAY_AND_INDEX | `getstatic field` [+ idx, aaload] | 形态 C 收割法 ✓ |
| SEPARATE_METHODS | `invokestatic a; invokestatic b` 双解密器链 | 池近亲 |
| LABEL_JUMP | `jsr/goto` 至解密块 | 内联单串可静态解 |
| LOOKUP_METHOD_AND_INDEX(_DES) | `push idx^key` [+ long key, l2i] `invokestatic` | pool ✓ |
| INDY_ENTRY_AND_INDEX | `push idx^key` + long key + invokedynamic | recover ✓ |

所有技术经 `addSplitCodeInsertions`：**参数常量拆成两半分开插入**（flow
交联）——这是控制流混淆中"参数拆半"现象的机制来源。int/long 常量加密
同构（StorageKind 五种）。三路全空时优先排查 LOCAL_ARRAY_AND_INDEX：
特征 = 方法内 aload 局部 Object[] + 索引 aaload + clinit/方法头批量解密
循环。

## 11. 跨领域环境坑（字符编码与路径）

1. **常量池是 modified-UTF-8**：NUL 编码为 `C0 80`（标准 UTF-8 非法序列）。
   以 `decode("utf-8")` 直接解码字节向字符串会产生 U+FFFD 并改变长度——
   先还原 `C0 80 → 00` 再解码；
2. MSYS/Git Bash 环境：混合盘符长 classpath 会被路径转换搅坏（现象：
   大面积假 ClassNotFoundException，单类短 classpath 正常）；**超长
   classpath 一律走 `CLASSPATH` 环境变量**——MSYS 不转换 env；注意
   argfile 对超长 cp 可能静默假应用（`-XshowSettings` 可核查
   java.class.path）；java 参数一律 Windows 风格；
3. `grep` 把含裸控制字节的文件判为 binary，`-o` 模式静默无输出——统计
   一律 `grep -a`；回填写盘统一 `\uXXXX` 转义从根上消除；
4. `awk -F:` 吃掉 Windows 盘符冒号——用 `$NF` 取末字段或改相对路径；
5. classpath 内单行过滤需先 `tr ";" "\n"` 分行再过滤再拼回。

## 12. 收益与边界的一般规律

- 最小环境可收大半；全量收割的边际成本集中在环境组装与 preinit；
- 残留失败集中于：真依赖平台运行时的 clinit、参数来自 native 的初始化、
  需要真实实例状态的单例访问——属结构性边界，如实报告；
- 归因纪律见第 7.4 节：先读自动分桶，再下结论。
