# Java 反混淆手册（含 Minecraft 客户端）

Mode C 的参考资料。核心认知：**Minecraft 客户端里其实是两套混淆叠在一起**，必须分开处理。

## 前提：只处理你有权处理的代码

反混淆用于分析自己的项目、已获授权的安全研究、学习与安全评估。

Minecraft 官方的立场也是明确的：按其许可**允许反编译**（模组、服务端插件是许可的预期用途），
但不要发布反编译代码，更不要发布包含其精确副本的产物。
**不做的事**：绕过授权或许可校验、移除版权与作者信息、制作并分发破解版本。
遇到包含许可证校验的目标，分析到此为止，不要把「绕过它」当作任务目标。

## 两套混淆，分开打

| | 原版（vanilla） | 客户端自身 |
|---|---|---|
| 来源 | Mojang 官方发布时的名称混淆 | 客户端作者用的商业/自研混淆器 |
| 表现 | `class_1234` / `method_5678` 或老版本的 `ave` / `bmz` | `IlIlIl` / `a.b.c`、字符串加密、控制流平坦化、反射 |
| 解法 | **映射重映射**（Tiny Remapper / SpecialSource） | **去混淆工具**（java-deobfuscator / narumii / Threadtear）+ 手工 |
| 顺序 | 先做 | 后做 |

先还原原版符号，客户端代码对原版的调用点才会露出来；顺序反了会得到一堆对不上号的方法。

## 映射体系怎么选（按版本）

| 版本 | 映射 | 状态 |
|---|---|---|
| 1.14.4 及以上 | Mojang 官方映射 | 首选，官方维护 |
| 1.14 ~ 1.21.11 | Yarn（Fabric 社区） | **1.21.11 之后已弃用**，老版本仍可用 |
| 1.3 ~ 1.13.2 | Legacy Yarn（Legacy Fabric） | 老版本唯一现实选择，配 Tiny Remapper 用 |
| 1.16.5 以下（Forge 老工程） | MCP | **1.16.5 之后失效**（Forge 转 Mojang 映射），仅历史工程需要 |
| 任意 | Parchment | 补参数名与 Javadoc，非符号映射 |

**Minecraft 26.1 起官方不再混淆** —— 这个版本及以后原版部分可以直接反编译，映射环节可省；
客户端自身的代码仍然是混淆的，两套混淆的区分依然成立。

## 工具链

**反编译**（先反编译看结构，再决定怎么去混淆）
- **Vineflower** —— 首选。FernFlower 的活跃分支，也是 JetBrains 反编译插件的引擎，对 Java 16+（record、switch 表达式、sealed）支持最好
- CFR / Procyon —— 交叉验证用，同一段代码两家输出不一致时说明这里有坑
- FernFlower（原版）—— 已过时，仅老工程兼容
- Krakatau —— 字节码级，反编译器都崩的时候用它看指令

**重映射**
- Tiny Remapper —— 主流选择，吃 tiny 格式映射
- SpecialSource —— 老 Forge 工程与 Mojang 官方映射的常用选择

用 SpecialSource 套 Mojang 官方映射（`client.txt`）：

```bash
java -jar SpecialSource-1.11.0-shaded.jar -i client.jar -o client-remapped.jar -m client.txt --kill-lvt
```

- **`--kill-lvt` 必须加**：Mojang 映射不含局部变量名，不加会出错
- Mojang 给的是 ProGuard 格式，SpecialSource 要的是 TSRG —— DecompilerMC 会自动转换
- 用非 shaded 版时要拼 classpath：PowerShell 里写作 `"SpecialSource-1.10.0.jar;*;."`（分隔符是分号，Linux/macOS 用冒号）
- 一键替代：DecompilerMC / MinecraftDecompiler（MaxPixelStudios），自动取文件、转换映射、反编译

**去混淆（商业混淆器）**
- `java-deobfuscator` —— 商业混淆器主力：Zelix、Stringer、Allatori、DashO、DexGuard、ClassGuard、Smoke、SkidSuite2
- `narumii/Deobfuscator` —— **专门针对 MC 付费客户端**
- Threadtear —— ZKM、Stringer 的另一选项

### java-deobfuscator 实操

先让它自己判断用了什么，再按结果挑 transformer：

```yaml
# detect.yml
input: input.jar
detect: true
```

```bash
java -Xss128m -jar deobfuscator.jar --config detect.yml
```

然后写 `config.yml`（名字可省 `com.javadeobfuscator.deobfuscator.transformers` 前缀）：

```yaml
input: input.jar
output: output.jar
transformers:
  - zelix.StringEncryptionTransformer
  - general.peephole.DeadCodeRemover
  - normalizer.ClassNormalizer: {}
```

| transformer | 作用 |
|---|---|
| `allatori.StringEncryptionTransformer` | 解 Allatori 字符串加密 |
| `dasho.StringEncryptionTransformer` / `dasho.FlowObfuscationTransformer` | 解 DashO 字符串 / 控制流 |
| `stringer.StringEncryptionTransformer` | 解 Stringer 字符串 |
| `stringer.InvokedynamicTransformer` | 还原 Stringer 的 indy 调用（v3.0.0 以下） |
| `stringer.ReflectionObfuscationTransformer` | 还原 Stringer 的反射调用 |
| `zelix.StringEncryptionTransformer` | 解 ZKM 字符串 |
| `zelix.ReflectionObfuscationTransformer` | 还原 ZKM 反射调用 |
| `general.peephole.DeadCodeRemover` | 移除无效代码 |
| `general.peephole.RedundantGotoRemover` | 简化跳转 |
| `general.remover.LocalVariableRemover` | 清理注入的局部变量（对 superblaubeere 系特别有效） |
| `normalizer.ClassNormalizer` / `MethodNormalizer` / `FieldNormalizer` / `PackageNormalizer` | 批量重命名为 Class / Method / Field / Package |

要点：
- **顺序有意义**：transformer 按给定顺序执行，有的变换依赖另一个还没被移除的特征，顺序错了会失败
- `-path` 必须给全依赖（几乎总要加 `rt.jar`），否则报 "Could not locate a class file"
- 栈溢出加 `-Xss128m`
- **名字恢复不了**：官方明确说明类名 / 方法名的重命名不可逆。normalizer 只是换成统一的规整名字，不是还原原名

### narumii/Deobfuscator 实操

支持 superblaubeere27 / JObf / sb27、Paramorphism 2.1.2_9、Caesium、Monsey、
Skid / qProtect（非最新）、Scuti、CheatBreaker、Bozar、RakSzild、HP888；
部分支持 Binsecure、Radon、Branchlock、Skidfuscator、Colonial、Sentinel。

和 java-deobfuscator 不同的三点：
- **没有 GUI 也没有配置文件**，要放进 IDE 跑，改 `Loader` 类来选 transformer
- 作者声明产出只保证「人能读」，**别指望能直接跑起来**
- 基于 Java 11 构建

### 混淆器速查（MC 社区常见）

| 混淆器 | 特征 | 处理 |
|---|---|---|
| Scuti | 类打包成 XOR 加密的二进制 blob，靠 ClassLoader 加载 | narumii；先 dump 出解密后的 class |
| Paramorphism | 利用 jar 重复条目名与假目录，普通解压工具会丢文件 | narumii；取条目时保留重复项 |
| Caesium | 往类名 / 字符串塞 HTML 标签，破坏解析 HTML 的逆向工具 | narumii；先清理 HTML 片段 |
| ClassGuard | 类加密，AES 密钥硬编码在 native 库 | java-deobfuscator；native 层可用 IDA / Ghidra |
| Skidfuscator | SSA/CFG 变换，三代控制流混淆 | 部分支持，偏难 |
| CheatBreaker | 与 Caesium 相似 | narumii / java-deobfuscator |
| XenonGuard | 基于 CheatBreaker，号称「免费版 ZKM」 | **无公开 transformer**，可先试 CheatBreaker 的 |
| Sentinel | MC 社区常见，已停维护 | **无公开 transformer**，手工分析 |
| Grunt | Kotlin 编写，支持 mixin / Forge 模组 | 手工；注意 mixin 结构 |
| Phantom Shield X | 名称重命名 + 字符串加密 + 控制流混淆；可选把 Java 转成 C 再本地编译（native + 虚拟化）；带自定义 loader 与水印 | **无公开 transformer**；Java 侧还原到 loader 边界，native 部分用 IDA / Ghidra |
| JObf / sb27 | MC 社区（尤其中日 anarchy 客户端）常见，较老 | narumii / java-deobfuscator，好处理 |

多个混淆器可以叠加，一层处理完要**重新跑一次 detect**，确认没有残留。

**编辑与重命名**
- **Recaf** —— 主力工具：字节码编辑、多反编译器、搜索、映射导入导出，支持 CLI 与脚本化
- Bytecode-Viewer、JByteMod —— 备选
- **AutoRenamer** —— 批量重命名混淆名，解决「一万个 IlIlIl 怎么起名」的问题

## 流程

1. **扫指纹**：`deobf_scan.py <目标>` —— 拿命名特征、字符串加密迹象、混淆器线索、MC 痕迹、反射密度。
2. **备份原始文件**：任何改动前先留一份原始 jar / class，重命名和打补丁都可能不可逆。
3. **分离原版与客户端**：按包名把 `net/minecraft` 等原版部分与客户端自身代码分开处理。
4. **映射还原原版**：Tiny Remapper + 版本匹配的映射。版本不匹配会静默产生错误的符号，务必核对版本。
5. **去混淆客户端代码**：按指纹选工具；没有现成工具时，用 Recaf 看字节码结构，自己写 transformer。
6. **反编译**：Vineflower 出源码，CFR 交叉验证可疑段落。
7. **重命名**：按**行为**命名（`decryptConfig` 而不是猜 `loadHackSettings`），拿不准的保留原名并加注释。
8. **验证**：能重新编译通过 + 行为与原始一致（对照运行/输出比对）。读得懂 ≠ 还原正确。

## 常见手法与对策

| 手法 | 识别 | 对策 |
|---|---|---|
| 名称混淆 | `IlIlIl` / `lllIIl` / 单字母 / 纯数字 | 映射或 AutoRenamer 批量重命名 |
| 字符串加密 | 大量长 base64 / hex 常量 + 一处解密方法 | 定位解密方法，写 transformer 批量还原；别手工一个个解 |
| 控制流平坦化 | 大 switch + 状态变量 + 大量 goto | 依赖去混淆工具；手工还原成本极高，先评估值不值 |
| 反射 / invokedynamic 隐藏调用 | `Class.forName` / `getDeclaredMethod` / `MethodHandle` | 静态解析出目标类名，反编译后手工标注调用关系 |
| 自定义 ClassLoader + 类加密 | `defineClass` / 运行时解密字节 | 需要 dump 出解密后的 class，再走正常流程 |
| 反调试 / 完整性校验 | 检测调试器、校验自身哈希 | 研究用途下分析其逻辑即可，**不要把它当障碍去绕过** |
| 无用代码注入 | 永不执行的分支、空循环 | 可安全删除，但删除前确认真的不可达 |
| native 混淆（JNIC） | 逻辑编译进 `.dll` / `.so`，Java 侧只剩 loader 和 native 方法 | 到此为止，转 Ghidra / IDA；Java 侧没什么可看的 |

## 成对样本差分：验证检测器唯一可靠的办法

如果能拿到同一份代码**混淆前 / 混淆后**的两个 jar，先做差分再谈别的。
它能同时回答三件事：检测器准不准、这一轮混淆改了什么、哪些东西混淆器根本碰不到。

实测（ZKM 27，Forge 1.7-1.12 模组，722 → 723 类）：

| 指标 | 原件 | 混淆后 | 读法 |
|---|---|---|---|
| `clinit-decryptor` | 75 | 315 | 字符串加密被大幅加强（4.2×） |
| `long-constant-array` | 1263 | 4326 | 整数 / 长整型加密加强 |
| `overload-collision` | 568 | 137 | 名字变了，重载分布随之变 |
| 被标记的类集合 | 142 | 352 | 类名被重命名（`myau/J` → `myau/A`） |
| **mixin hook 目标** | **123** | **123** | **一个都没变** |
| native 方法 / indy 站点 | 101 / 1716 | 101 / 1716 | 二次混淆不再处理这两项 |

最后两行是重点：
- **混淆器重命名了类、把字符串加密翻了几倍，但注解里的 hook 目标完全没动。**
  注解值是常量池常量，这是它碰不到的。凡是靠名字建立的映射（MC 官方映射、
  Yarn、MCP）必须先做，混淆器不认识它们。
- 检测器的召回率可以直接验：拿被标记的类反编译，看结构是否真的对得上。
  实测抽查 ZKM 标记的解密器类，反编译出来确实是 DES 解密循环 —— 不是误报。

脚本上很容易做：两份 `analysis.json` 逐字段相减即可，不必重新扫描。

## Zelix KlassMaster（ZKM）专项

ZKM 是商业混淆器，27 版本起强度明显提升，特征是**叠加使用**：

- **flow（控制流）混淆** —— 用异常表、虚假分支与跳转把线性逻辑打散
- **indy 混淆** —— 把方法调用改写成 `invokedynamic`，目标藏进 bootstrap method
- 字符串加密、名称混淆 —— 常规项目

**后果**：直接丢给反编译器大概率崩溃，或者吐出无法阅读的代码。
顺序必须是**先跑 flow / indy transformer，再反编译**，反过头来等于白做。

### ZKM 27 enhanced 模式的实测形态

一份 Forge 1.7-1.12 模组（722 类）上的实测结果，`deobf_scan.py` 报 `clinit-decryptor`
315 处、`long-constant-array` 4326 处、`indy-long` 190 处。解密方法反编译后长这样：

```java
private static String b(int n, long l) {
    int n2 = n ^ (int)(l & 0x7FFF) ^ 0x100A;          // 索引
    Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");
    byte[] key = new byte[8];
    key[0] = (byte)(l >>> 56);
    for (int i = 1; i < 8; i++) key[i] = (byte)(l << i * 8 >>> 56);
    c.init(DECRYPT_MODE, new DESKeySpec(key), new IvParameterSpec(new byte[8]));
    f[n2] = b(c.doFinal(e[n2].getBytes("ISO-8859-1")));   // 解密 + UTF-8 解码
    return f[n2];
}
```

要点：

- **调用形态是 `(String, int, long)`，第一个参数是标记**（实测见过 `"o"` 与 `"y"` 两种），
  后面两个是索引与被 session key 异或过的 long。找解密方法时按这个签名搜。
- **密文表本身也是加密的**：`<clinit>` 里先用一个 session key 把表项解出来，
  每个调用点再用各自的 key 解出最终明文 —— **两层，不是一层**。
- session key 由 `indy` 引导方法生成，形如
  `ls.a(7937575481569766320L, -2564101769422216487L, <Class>).a(248257488143136L)`，
  这是 method parameter change 与 indy 混淆叠在一起的结果。
- 结论：**纯静态解密要跨三层**（还原 indy 引导返回值 → 算 session key → 两层 DES）。
  性价比通常不如直接上 `zelix.StringEncryptionTransformer`（它用执行引擎绕开前面几层）。
  静态还原只有在目标禁止执行、或需要批量集成到流水线时才值得做。

识别线索：常量池里有 `java/lang/invoke` 相关项，却找不到编译器该生成的正常 bootstrap 工厂
（`LambdaMetafactory` / `StringConcatFactory` / `ObjectMethods` 等）—— 那多半就是 indy 混淆。
`deobf_scan.py` 会把这条标为「疑似 indy 混淆」。注意反过来：**存在 `LambdaMetafactory` 属于正常 lambda，不要误判**。

处理工具：Threadtear（对 ZKM 支持较好）、java-deobfuscator。

## JNIC / native 虚拟化 —— 反编译的边界

这类方案把 Java 字节码转成 C/C++ 再编译成本地库，运行时由 native 代码解释执行原逻辑。
结果是**逻辑根本不在 Java 侧**。这不是工具不够好，是分析路径到此为止。

形态特征（`deobf_scan.py` 会逐条报出来）：

- jar 里类数极少，通常只剩一个 loader
- 附带 native 库：Windows `.dll`、Linux `.so`、macOS `.dylib`；跨平台保护常在一个 jar 里塞多份
- class 里有 `native` 方法（ACC_NATIVE）—— **最硬的信号**
- 出现 `System.loadLibrary` / `System.load`
- native 库导出 `JNI_OnLoad` 与大量 `Java_<包_类_方法>` 符号

处理流程：

1. **先把 native 库 dump 出来**。开源工具 `JNIC-Virtualization`（带 LICENSE）可以从 JNIC 保护的 jar 里
   静态 dump 出 native 库并补一个兼容的 loader，用法是 `java -jar JNIC-Virtualization.jar <jar> [dumpDll]`
2. 用 Ghidra / IDA 分析导出的 `Java_*` 符号，它们与原 Java 方法一一对应
3. 从 `JNI_OnLoad` 和初始化函数入手，字符串常量与注册表往往能给出整体结构的线索
4. Java 侧那个 loader 只负责加载与转发，价值有限，不必深挖

MC 客户端里 JNIC 出现得很早（1.8 一代客户端常见）。看到「类很少 + 一个大二进制 + 全是 native 方法」
这个组合，就别再在 Java 侧找了。

## invokedynamic 混淆 —— MC 社区最常见的一类

indy 混淆把方法调用与字段访问改写成 `invokedynamic`，真正的目标藏进 bootstrap 方法。
MC 社区最常见的就是 superblaubeere27 / JObf / sb27 这一系。

**静态特征**：`deobf_scan.py` 报的「indy 编码串」。它把每个调用目标编码成字符串，放进静态 `String[]`：

```
a/b/C:methodName:()V··      ← 尾部 2 个空格 = 虚方法调用（findVirtual）
a/b/C:other:()I·            ← 1 个空格 = 静态调用（findStatic）
x/Y:field:I···              ← 3 个空格 = 实例字段读（findGetter）
p/Q:method:(...)V····       ← 4 个空格 = 静态字段读
```

（上面用 `·` 表示尾部的一个空格。）字段类型另有一个静态 `Class[]` 数组存着。
**尾部空格的个数就是操作类型标记** —— 这是这一系混淆最好认的指纹。
统计上，indy 编码串超过 3 条就基本可以确定。

**还原方法**：

1. 找到 bootstrap 方法（`invokedynamic` 的 BSM 指向它）
2. 读它的解密逻辑 —— bootstrap 的参数是**常量池里的静态值，不依赖运行时**
3. 离线执行这段逻辑（翻译成脚本，或用 ASM 跑），解出每个调用点的真实目标
4. 把 `InvokeDynamicInsnNode` 替换成真实的静态调用 / 虚调用 / 字段访问

关键点：**indy 的解密是纯函数式的** —— 不需要跑起来、不需要 dump 内存，可以完全静态还原。
批量处理时把每个调用点的 bootstrap 参数解一遍，整片混淆调用点就一次性清掉了。

**变种**：InDy Obfuscator 这类开源实现把 bootstrap 方法本身用 C 写成 native 库，
那就又回到 JNIC 那条边界了 —— 静态分析到此为止。

## 一个必须分清的界限

处理「**被 ZKM 混淆过的代码**」是正当的分析工作，用上面那些开源工具就够了 —— 这一步不需要 ZKM 本体。

但**不要去找 ZKM 的破解版 / 泄露版源码**。这类仓库（例如把授权校验 patch 掉的「开源版」）
普遍在被 DMCA 下架，来源本身不合法，用它们既没有技术必要，也会把整个分析工作的合规性搭进去。
工具链里只列开源去混淆工具，不列任何需要绕过授权才能拿到的东西。

## 陷阱

- **别在常量池里搜库扩展名**：`.dll` / `.so` 当子串匹配会命中任何含该串的普通文本
  （`also`、`resolve`、`socket`…）。实测 vanilla 1.20.4 的 22597 个条目里**没有任何
  `.so` 文件**，却因为常量池里有含 "so" 的字符串而报了 native 痕迹。
  库文件只看 **jar 条目名**；常量池里只搜 `System.loadLibrary` 这类方法调用。
- **Minecraft 自己的资源格式要进白名单**：`.nbt`（结构文件）、`.dat`、`.snbt`
  不在「常规条目扩展名」表里时，会被判成 Scuti / ClassGuard 风格的加密类 ——
  实测 vanilla 一次报了 10 个 `data/minecraft/structures/.../*.nbt`。
- **控制流指标要看命中占比，不能看有没有**。`deobf_scan.py` 的 JSON 字段
  `backward_handlers` / `irreducible_gotos` 是二值指纹，但**实测 ZKM 27 的
  `backward_handlers` 恒为 0** —— 它用 goto 洪水（13.9% vs vanilla 1.34%）而不是
  异常表后跳。别把「公开分析里的 4265 处后跳」当成 ZKM 的通用特征。
  另外 `fake-sourcefile` 和 `overload-collision` 在 vanilla 上分别是 100% 和 34%，
  在 ZKM 样本上只有 0.1% 和 3.7% —— **方向是反的**，只能报告不能当证据。
  详见 `control-flow.md`。
- **反编译结果不是源码**：变量名、注释、泛型信息大部分已丢失，不要把它当原始代码引用。
- **重编译经常失败**：尤其遇上去混淆不彻底的字节码，能编译通过才是阶段完成的标志。
- **映射版本必须精确**：错一个版本就会对上错误的方法，而且不会报错。
- **存在对抗反编译器的 class**：故意构造非法字节码让工具崩溃，这时换工具或用 Krakatau 看指令。
- **别追求 100% 还原**：目标是「读懂关键逻辑」，不是恢复原始工程结构。
- **反编译器版本本身也有坑**：Vineflower 1.10.1 在部分较新版本上会报错，要切到 `develop/1.11.0`
  分支自行构建。看到「反编译器崩了」，先确认版本，再怀疑目标做了对抗。
- **混淆器会攻击工具链本身，这是常态**：yGuard 的 `error-checking: best` 会生成让反编译器误解的名称，
  某些名字在 Windows 上甚至无法解压；Caesium 往字符串里塞 HTML 片段，专门破坏会解析 HTML 的逆向工具；
  还有构造非法字节码让工具崩溃的。**遇到「工具莫名崩溃 / 解压失败」，先怀疑目标在对抗工具，而不是工具坏了。**
- **检测工具自己也会误报，阈值救不了你**：子串匹配是最容易踩的坑 —— 拿 `.so` 在常量池里搜会命中
  `also` / `resolve` / `socket`，实测 vanilla 1.20.4 的 22597 个条目里 0 个 `.so` 文件却报了 native。
  库扩展名要看 **jar 条目名**，不要在常量池里搜。同理要把项目自己的资源格式（`.nbt` / `.dat` / `.snbt`）
  加进「已知条目」白名单，否则 Minecraft 的结构文件会被当成加密类（一次报了 10 个）。
  任何启发式都该先在**未混淆的真实目标**上跑一遍确认零误报，再拿去用。

## 不做什么

- 不移除或绕过许可证验证、账号校验
- 不删除版权与作者署名
- 不产出可分发副本
- 对方明确禁止分析时停止
