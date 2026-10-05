# 动态分析：运行时捕获与 native 联调

静态分析看不到只在运行时存在的东西：解密后的类、运行时生成的类、被 JNI
动态加载的库。**本文只讨论自有或已获书面授权的目标。**

## 1. 三条 class dump 路线

| 路线 | 机制 | 适用 |
|---|---|---|
| retransform 快照 | 注册可重转换 transformer，在 `transform` 里把 `classfileBuffer` 落盘、**返回 null**（不改字节），再 `retransformClasses` | 首选。Arthas 的 `dump` 即此实现 |
| premain 全量旁路 | `-javaagent` 在 main 之前注册，命中即写盘 | 目标为自有构建时最方便 |
| 堆 dump 提取 | `jcmd <pid> GC.heap_dump` / `jmap -dump` | 适合取字符串、密钥等对象，非 dump class 首选 |

**关键**：`transform` 返回 `null` 表示只旁路读取、不改字节——对完整性校验
的影响最小。

## 2. Instrumentation 的硬限制

- `retransform` / `redefine` **不得**增删字段或方法、不得改签名与继承关系，
  否则抛 `UnsupportedOperationException` / `UnmodifiableClassException`；
- lambda 代理类（`Xxx$$Lambda$nn/0x...`）的 `isModifiableClass` 返回 **false**；
- JDK 21 起（JEP 451）动态 attach 打 stderr 警告；
  `-XX:+EnableDynamicAgentLoading` 可抑制；`-XX:+DisableAttachMechanism`
  可直接关闭 attach；
- JDK 17+（JEP 403）反射 `sun.misc.Unsafe` 抛 `InaccessibleObjectException`；
- 多 agent 并挂易 `VerifyError` 且顺序不可控——调试前先 `removeTransformer`
  并重新 retransform 还原；
- 目标若经 JVMTI `ClassFileLoadHook` 解密 class，该 hook 在 Java transformer
  **之前**——Java 层拿到的已是解密后字节。

## 3. 现成工具

- **Arthas**：`dump [-d dir] <pattern>`；`sc -d`；`jad --source-only`；`vmtool`；
- **jattach**：无 JDK 环境的 attach（`jattach <pid> load instrument false
  "agent.jar=opts"`），支持容器；
- **Recaf 4**：attach 运行中进程，dump 后做字节码编辑与多反编译器比对；
- **JADX**：CLI 支持 `--mappings-path`（tiny v1/v2、Enigma）与 `--deobf`，
  适合"dumped class + 映射还原"一体化；
- **CFR**：现代特性支持好，明确支持 multi-release JAR。

## 4. 内存分析

Eclipse MAT（OQL、Path to GC Roots）、VisualVM。**生成 dump 的 JDK 版本
必须 ≥ 分析工具版本**，否则 `Unsupported hprof version`。

## 5. 平台特有难点（以 Minecraft 为例）

- **启动器包装 + 自定义 ClassLoader**：1.13+ 用 Knot（classpath 隔离，非
  平台/非模组第三方库不经变换直接委派父加载器）；1.13 以下 LaunchWrapper。
  dump 出的类按 classLoaderHash 定位归属；
- **Mixin 注入**：变换流水线为 entrypoint → loader → **Mixin**；dump 必须在
  Mixin 之后，否则是半成品；同一目标类可能被多来源多次变换叠加；
- **side stripping**：dev 环境移除 `@Environment` 不匹配侧的成员——生产与
  dev 的 dump 不同，记录开关状态；
- **类版本跨度**：平台版本决定最低 JVM（如 17 / 21 / 25），低版本反编译器
  读高版本 class 会失败；
- **映射不改运行时**：JVM 跑的仍是中间名，dump 出的 class 必须 remap 才可读。

## 6. 反调试场景（授权研究）

常见检测：启动参数查 `-agentlib:jdwp`、计时检查（`System.nanoTime` /
`ThreadMXBean`）、class 字节完整性校验、ClassLoader 链比对、`/proc/self/status`
的 TracerPid、Frida 痕迹（默认端口等）。

正当应对：

- **优先静态挂载**：`-javaagent` 替代 attach，避开动态 attach 收紧与
  jdwp 类检测；
- **自建产物**：自有构建关掉完整性校验，或使用无检测的构建变体；
- **旁路读取**：优先 transformer 返回 `null` 路线，不改字节；
- **不改平台核心类**：改 `java.*` 的风险收益比极差。

## 7. native 完整性保护类（"毒类"）的处理

保护壳（native 校验 + 哈希名 native 方法 + RegisterNatives 绑定）会把部分
类变成"毒类"：任何未通过完整性校验的加载方式都会被拒绝。处理原则：

### 7.1 死因判定先行

| 现象 | 判定 |
|---|---|
| 秒级退出、零 CPU、无 hs_err、exit code 异常 | native 内主动 `exit`——桩化校验方法后可过 |
| JVM 直接崩溃、无 Java 异常 | native 崩溃——只能**二分批次隔离**（bisect），每批结果即时落盘 |
| 有 hs_err 或 Java 异常 | 环境问题，按异常定位 |

口诀：**崩了先看有没有 hs_err 和异常；都没有 = 主动拒绝，不是缺依赖。**

### 7.2 字节码手术 agent 的四条规则

1. **桩化范围必须精确**：保护壳自身的类全桩化（它们只做校验），目标包
   **只桩 native 方法**。多桩一行 `<clinit>` → 变 `return` → 字段全 null、
   解密器返回桩常数——**看似成功实则垃圾**，比失败更危险；以探针类实测
   解密值确认真假；
2. 重建 class 保留头部 + 常量池 + 接口 + 字段原样，只重建方法区；
   `attribute_length` 是 u4；
3. 构造器桩补 `aload_0; invokespecial super.<init>()V; return`，否则
   VerifyError；
4. 方法桩按返回描述符造零值（V→return；L/[]→aconst_null+areturn；J/D 占
   2 槽）；native 方法整个属性区替换为唯一 Code 桩（逐属性替换会撞
   Signature 长度错误）。

### 7.3 递进式捕获阶梯（成本从低到高）

1. **静态提取 + 反射重放**：解密器调用点参数为硬编码常量 → 静态扫描 →
   裸 JVM 反射重放。覆盖多数类，但产出常只有机器常量（库名/自类名/密钥），
   功能性字符串往往不在这一层；
2. **毒类桩化**：agent 桩化让校验类放行，全部类在同一 JVM 内通过；
3. **内部表命中**：以混淆名为 key、盐在 `<clinit>` 明文的查表函数，可枚举
   全部候选 key 反射调用其私有查表函数（零语义偏差）。注意**命中 ≠ 还原**：
   表内容可能是"上一代混淆名 → 本代混淆名"翻译，语义需抽样验证；
4. **真实环境倾倒**：由 native 经 JNI 回填的表（putstatic 扫描可反证 Java
   侧无赋值）静态不可达，只能真实运行 + agent 定时枚举/实例化目标类。
   注意：**授权校验必须真过**（发行版自带的 JVMTI agent 是依赖不是障碍）；
   **金矿提示：此类程序常在游戏目录下自写配置 JSON（模块/设置项全量默认
   值），比反射 dump 更全——先看 config，反射只是验证手段**。

### 7.4 其他教训

- **进程被 SIGTERM 零输出 ≠ 外部杀手**：先查自身死循环（如描述符解析漏
  递增 → 内存爆炸）；内联测试全过而脚本必死时，捕获 MemoryError 拿行号；
- 低版本目标必须 `javac --release <N>` 重编 agent；目标锁定 jar 时先停
  进程再重编；
- premain 里 `System.halt(0)` 不一定终止目标 JVM，备好手动停止手段。

## 8. Frida native 捕获管线（engines/frida）

对 native 化家族（JNIC / MyJ2C / native-obfuscator / PhantomShield 系——
字节码直译 C）的运行时捕获，jdec 提供 `engines/frida/`（详细用法见该目录
README）：

- **regnatives.js**：hook JNIEnv 表槽 215（RegisterNatives），dump 类名 /
  方法名 / 签名 / 函数指针全表——方法 ↔ native 地址的对应表，是 Ghidra
  定点分析的路标；
- **jnitrace.js**：trace FindClass / GetMethodID / GetFieldID /
  GetStaticMethodID / NewStringUTF / GetStringUTFChars——生成器直译 C 的
  "IO 骨架"与原字节码的类/字段/方法/字符串操作几乎一一对应。**极限**：
  纯算术不经 JNI，trace 给结构 + IO，不给完整语义；
- **dump_mappings.py**（泵驱动采集）+ **trace2java.py**（trace → 伪 Java）
  + **HarnessTemplate.java**（ENTER/EXIT 打点切段）；
- **dump_payload.js**：hook `CreateFileW/A`，捕获 loader 解密落盘的
  native 库（库文件转储后可直接进入 natives 分诊流程）。

### 8.1 环境与实现硬约束（全部经验证）

1. **frida 必须用 16.x**：17 将 Java 桥从脚本运行时剥离（桥需自行打包）；
2. **frida-java-bridge 在 JDK 21+ 拒绝初始化**（"Java API only partially
   available"，缺 `VMThread::execute` 等 Hotspot 内部符号）→ **弃桥**：
   经 `jvm.dll` 的 `JNI_GetCreatedJavaVMs` + `AttachCurrentThread` 获取
   JNIEnv。指针纪律：
   - `vm` 是 C++ JavaVM 对象，其**首字段**才是 JNIInvokeInterface_ 表指针
     （直接按 vm 偏移读槽位会错位/读空）；
   - `AttachCurrentThread` 写出的是 `JNIEnv*`，指向**每线程 JNIEnv 变量**，
     函数表需 `env.readPointer()` 再解一层；JNI 调用的第一个参数传 `env`
     本身（不是表指针）；
3. **JS 定时器（setInterval）在这类目标内不触发**（顶级代码与 rpc 均正常）
   → 安装动作由 python 侧以 rpc 泵驱动；rpc 方法名用全小写（frida 的
   python↔JS 名字转换规则不一致，全小写最稳）；
4. VM 启动中途 jvm.dll 已映射但 VM 对象半初始化——获取例程全防御化
   （表槽位非空校验），任何怀疑返回 null 下一轮重试，杜绝 access violation；
5. 短命目标（如缺编译器的引擎数秒即退）→ 热循环只对已知 pid 泵驱动
   （~20ms 节奏），重量级进程枚举降频；
6. 保护器 jar 常随包发布 `jni.h` / 算法头文件——C 生成模板的官方参照；
7. **校准方法论**：使用补丁版引擎（社区移除了 license/完整性检查的构建）
   保护自有 fixture——原字节码在手，trace 恢复率可量化。这是配对样本
   差分法向 native 侧的推广。

## 9. 红线

不绕过未授权的商业软件、他人产品、联网游戏反作弊；不绕过 DRM、授权或许可
证校验；不修改客户端以获取服务端未授权权限；不移除第三方遥测与计费。
判断标准：目标是否自有或已获书面授权？dump 出的数据是否会外泄或牟利？
任一为否即停。
