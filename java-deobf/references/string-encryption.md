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
