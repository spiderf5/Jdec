# 动态分析：dump 出运行时解密后的 class

静态分析看不到只在运行时出现的东西：解密后的类、运行时生成的类、被 JNI 动态加载的类。
**本文只讨论自有或已获书面授权的目标。**

## 三条 dump 路线

| 路线 | 机制 | 适用 |
|---|---|---|
| retransform 快照 | 注册可重转换 transformer，在 `transform` 里把 `classfileBuffer` 落盘、**返回 null**（不改字节），再 `retransformClasses` | 首选。Arthas 的 `dump` 命令就是这个实现 |
| premain 全量旁路 | `-javaagent` 在 main 之前注册，命中即写盘 | 目标是自己构建的，最方便 |
| 堆 dump 提取 | `jcmd <pid> GC.heap_dump` / `jmap -dump` | 更适合取字符串、密钥等对象，不是 dump class 的首选 |

**关键**：`transform` 返回 `null` 表示不修改字节码、只旁路读取 —— 对完整性校验的影响最小。

## Instrumentation 的硬限制

- `retransform` / `redefine` **不得**增删字段或方法、不得改签名与继承关系，否则
  抛 `UnsupportedOperationException` / `UnmodifiableClassException`
- lambda 代理类（`Xxx$$Lambda$nn/0x...`）的 `isModifiableClass` 返回 **false**，改不了
- JDK 21 起（JEP 451）动态 attach 加载 agent 会打 stderr 警告；
  `-XX:+EnableDynamicAgentLoading` 可抑制，`-XX:+DisableAttachMechanism` 可直接关掉 attach
- JDK 17+（JEP 403）反射 `sun.misc.Unsafe` 会抛 `InaccessibleObjectException`
- 多个 agent 同时挂容易 `VerifyError`，且执行顺序不可控 —— 调试前先 `removeTransformer`
  并重新 retransform 还原
- 如果目标用 `-agentpath:xxx.so` 走 JVMTI 的 `ClassFileLoadHook` 解密 class，
  该 hook 在 Java transformer **之前**，Java 层拿到的已经是解密后的字节

## 现成工具

- **Arthas**（阿里）—— 最成熟的动态方案：`dump [-d dir] <pattern>` 落盘 class；
  `sc -d` 看 classLoader 与 hashcode；`jad --source-only` 直接看反编译源码；`vmtool` 强制转换
- **jattach** —— 无 JDK 环境时的 attach（`jattach <pid> load instrument false "agent.jar=opts"`），支持 Linux 容器
- **Recaf 4** —— 支持 attach 到运行中进程，dump 之后用它做字节码编辑与多反编译器比对
- **JADX** —— CLI 接受 jar/class，支持 `--mappings-path`（tiny v1/v2、Enigma）与 `--deobf`，
  适合「dumped class + MC 映射还原」的一体化流程
- **CFR** —— 现代特性支持好，明确支持 multi-release JAR

## 内存分析

Eclipse MAT（OQL、Path to GC Roots）、VisualVM。
铁律：**生成 dump 的 JDK 版本要 ≥ 分析工具的版本**，否则报 `Unsupported hprof version`。

## Minecraft 客户端的额外难点

- **启动器包装 + 自定义 ClassLoader**：1.13+ 用 Knot（有 class path isolation，
  非 MC、非 mod 的第三方库类不经过变换，直接委派父加载器）；1.13 以下用 LaunchWrapper。
  dump 出来的类要按 classLoaderHash 定位归属
- **Mixin 注入**：Fabric 的变换流水线是 entrypoint → Fabric → **Mixin**。
  dump 必须在 Mixin 之后才有意义，否则拿到半成品；同一目标类可能被多次、多来源变换叠加
- **side stripping**：dev 环境会整段移除 `@Environment` 不匹配侧的方法字段，并把包级私有改成
  public —— 生产环境 dump 的类与 dev 环境不同，记录开关状态
- **类版本跨度大**：1.17 要 Java 16、1.18–1.20.4 要 17、1.20.5+ 要 21。低版本反编译器读高版本 class 会失败
- **Fabric 会 remap**：非开发环境把 MC jar remap 到 intermediary，缓存在
  `${gameDir}/.fabric/remappedJars/`。dump 到的是混淆态，仍需 remap
- **映射不改运行时**：JVM 跑的还是混淆码，所以 dump 出来的 class 也必须 remap 才可读

## 遇到反调试时（授权研究场景）

常见检测：启动参数查 `-agentlib:jdwp`、计时检查（`System.nanoTime` / `ThreadMXBean`）、
class 字节完整性校验、ClassLoader 链比对、读 `/proc/self/status` 的 TracerPid、
Frida 痕迹（27047 端口等）。

正当应对思路：

- **优先静态挂载**：`-javaagent` 替代 attach，既避开 JEP 451 的收紧，也避开 jdwp 类检测
- **自建产物**：自己的构建里关掉完整性校验，或用无检测的 dev 版本
- **旁路读取**：优先 transformer 返回 `null` 的路线，不改字节
- **不改 JDK 核心类**：改 `java.*` 的风险收益比极差

## 实战记录：native 完整性校验毒类（2026-10 实测，授权研究）

样本：Forge 1.8.9 作弊客户端，30 个"毒类"带 SHA1 哈希名 native 方法
（antiLeak 保护壳，`Loader.registerNativesForClass` 绑定 + 完整性校验）。
以下结论全部实测验证过。

### 毒类的真实死因（先分清，别瞎修）

- **exit 127**：3 秒退出、零 CPU、无 hs_err —— native 里主动调了 exit，字节码手术桩化前必现
- **native 崩**：JVM 直接死、无 Java 异常 —— 只能**二分批次隔离**（bisect），每条结果即时落盘
- 判定口诀：**崩了先看有没有 hs_err 和异常，都没有 = native 主动拒绝，不是环境缺依赖**

### 字节码手术 agent（NoExit）四条硬经验

1. **桩化范围必须精确**：antiLeak* 全桩化（它们只做校验），目标包**只桩 native 方法**。
   多桩一行 `<clinit>` → 变 `return` → 字段全 null、解密器返回桩常数——
   **看似成功实则垃圾**，比失败更危险。用探针类实测解密值才能确认真假。
2. 重建 class 必须保留头部+常量池+接口+字段原样，只重建方法区；`attribute_length` 是 u4 非 u2
3. 构造器桩要补 `aload_0; invokespecial super.<init>()V; return`，否则 VerifyError
4. 方法桩按返回描述符造零值（V→return；L/[]→aconst_null+areturn；J/D 占 2 槽）；
   **native 方法整个属性区换成唯一 Code 桩**（逐属性替换会撞上 Signature 长度错）

### 四层捕获策略（递进，成本从低到高）

1. **静态提取 + 反射重放**：解密器调用点参数是硬编码常量（`a(II)`/`a(IJ)`）→
   静态扫出 → 裸 JVM 里反射重放解密器。覆盖率 124/136 类，但产出几乎全是
   机器常量（DES 名/自类名/随机 key），功能字符串不在这层
2. **毒类桩化**：NoExit agent 让 40 个毒类一个 JVM 全过
3. **撞解密表**：名字映射表 key=混淆名本身、盐在 `<clinit>` 明文 → 生成全部候选 key
   反射调它自己的私有查表函数（零语义偏差）。**撞上 ≠ 还原**：实测内容是
   "上一代混淆名→本代混淆名"翻译，语义要抽样验证，不能想当然
4. **真环境倾倒（终点）**：native 经 JNI 填的表（putstatic 扫描反证 Java 侧无赋值）
   静态不可达，只能在真实运行环境跑 + premain agent 定时枚举/实例化目标类读字段。
   坑：授权校验必须真过（发行版自带的 JVMTI agent 是依赖不是障碍）；
   **意外金矿：程序常在 `--gameDir` 下自己写 config JSON——59 模块/358 设置项
   全量默认值，比反射 dump 还全**。拿设置全表先看 config，反射只是验证手段

### 其他实测教训

- **进程被 SIGTERM 零输出 ≠ 外部杀手，先查自己的死循环**（描述符解析漏 `i+=1` →
  内存爆炸被环境击杀；-c 内联测试全过、脚本必死时，用 exec 环境抓 MemoryError 拿行号）
- Java 8 目标必须 `javac --release 8` 重编 agent；游戏锁定 jar 时先停进程再重编
- premain 里 `System.halt(0)` 不一定杀得掉游戏 JVM，备好手动停止手段

## 红线

不绕过未授权的商业软件、他人产品、联网游戏反作弊；不绕过 DRM、授权或许可证校验；
不修改客户端以获取服务端未授权权限；不移除第三方遥测与计费。
判断标准：目标是不是你自己的、或有书面授权？dump 出的数据会不会外泄或牟利？任一为否即停。
