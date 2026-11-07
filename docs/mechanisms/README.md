# 04 机制笔记总纲（study/ 标本馆的合规替代）

本目录是 `docs/ROADMAP.md:226` 指定的 `study/` 标本馆机制笔记的**合规替代**：  
`study/` 被 `.gitignore:71-73` 以「含 DMCA 敏感源码，永不入库」排除，目录  
既不存在于工作树、也永不提交。本目录**只描述机制的形态**——名称、字节码 /  
容器层面的可观测特征、工具支持项边界、验证方法与独立金标准——**不含任何  
第三方源码、反编译片段、混淆器实现代码或受版权保护的内容**。机制清单的  
ID 与名称严格对应 `src/jdec/mechanisms.py` 的 `MECHANISMS` 注册表。  

`study/` 永不入库的原因如实说明：其中的标本含 DMCA 敏感的第三方反编译 /  
混淆源码，再分发会带来版权风险，故按 `.gitignore` 规则整目录排除，既不在  
工作树也不进版本库。本目录以纯形态描述替代「标本」，使 04 有一份可入库、  
可评审的机制清单来源；它是清单来源的合规替代，**不是对 DMCA 敏感材料的  
复制或规避**。  

## 术语工作定义（草案，用户拍板前）

下表六个术语是**草案口径**，仅用于本目录笔记，标注为用户正式拍板前的说明；  
不写回 `docs/ROADMAP.md`，不构成门槛修订，也不覆盖 `docs/SUPPORT_MATRIX.md`  
第 1、2 节已有的工作定义。  

| 术语 | 工作定义（草案） |
| --- | --- |
| 机制类 | 一种可辨识的字节码 / 容器变换家族，有稳定的可观测形态、独立输入形状与可测输出；以 `MECHANISMS` 的 ID 为唯一标识 |
| 明确支持项 | 对该机制类的一条有边界的能力承诺：写清输入条件、产出物与已知不覆盖；不把识别、枚举、「如实报告 0」写成「已攻克 / 已还原」 |
| 独立样本 | 与被测命令实现无关、来源可追溯、不入库的真实文件（或公开可下载的阴性对照），每类机制各自配对；生成式 fixture 只作负控，不折算为独立样本 |
| 独立金标准 | 不取被测命令自身输出的真值来源，如 `zipfile` 原始条目字节、独立 class 解析的常量池/方法表、PE 头解析、容器 magic；`javap -v` 是推荐的人工复核手段，**尚未纳入自动回归**。回答「工具报的对不对」而非「工具报了没」 |
| 负控 | 每类机制自己构造的、故意不含（或故意含一处）目标形态的输入，预期工具必须给出「未命中 / 拒绝 / 隔离」的结果，证明门禁不恒真、不把阴性误报成阳性 |
| 证据等级 | 沿用 `docs/SUPPORT_MATRIX.md` 第 2 节的 E0–E3 草案；E3 = 真实外置独立语料 + 授权前提 + 可执行回归 + 记录数字。当前语料上目标数为 0 的机制，只到「识别并如实报告 0」，不得记为已攻克 |

## 8 类机制笔记索引

| ID | 名称 | 链接 | 支持项（一句话） | 已知不覆盖（一句话） |
| --- | --- | --- | --- | --- |
| M1 | 控制流去平坦化 / 常量折叠 / 不透明谓词 | [M1.md](M1.md) | 对含 goto-flood / irreducible-goto 的真实 jar 产出可重放指令级改写、重算 StackMapTable、全类过 `-Xverify:all` 并出改写清单 | 不还原任意自定义 VM；jsr/ret 明确拒绝；改写保持语义但不证明等价 |
| M2 | 字节级往返与坏类隔离（改写底座） | [M2.md](M2.md) | 整 jar 逐类 parse→重汇编→逐字节比对，报告类与 Code 数组相等数，坏类隔离不拖垮整批 | 不做语义等价证明；jsr/ret 与不可解码类按边界拒绝 |
| M3 | invokedynamic / BootstrapMethods 站点与常量载荷还原 | [M3.md](M3.md) | 枚举 BSM 与 indy 站点并按 owner 归类，再还原 LambdaMetafactory 调用目标、StringConcatFactory 模板、ObjectMethods 组件名；HMCL 6245/6245、NeoRaven 150/150 站点全部还原 | 不执行 bootstrap；无常量的引导（如 SwitchBootstraps）计入未还原；非 vanilla 自定义 BSM 目标数为 0，不承诺还原 |
| M4 | 混淆器结构指纹归因 | [M4.md](M4.md) | 基于 ≥2 个专属关键词 + 结构阈值做厂商归因、命中须带证据，对 NeoRaven 如实报未命中 ZKM 专属指纹 | 旧「ZKM 27 enhanced DES」是 ivparameterspec 关键词误报；词表不等于支持全部机制，不承诺还原 |
| M5 | 字符串常量抽取与加密/威胁标签 | [M5.md](M5.md) | 抽取常量池字符串并按 url/path/credential/encrypted-blob/machine-id/class-loading 标注，encrypted-blob 须 base64 解码与 FQCN 排除复核 | 标签是启发式、抽取不等于解密；本语料不存在 ZKM DES 池，不据旧结论标注 |
| M6 | native 分诊与 PE/JNI 库提取 | [M6.md](M6.md) | 从 MZ stub 自解压 PE / ELF 与 jar 资源提取 native 库，解析导出表与 JNINativeMethod，报告 Java 侧 native 方法与匹配 | 不反编译 native 函数体；不承诺 RegisterNatives 动态绑定还原 |
| M7 | Minecraft 元数据与 Mixin hook 识别 | [M7.md](M7.md) | 识别 MC 版本 / 加载器、Mixin 配置或注解 hook，无映射时如实保留 hook 目标名 | 映射表本身外置；无映射时不解析 hook 目标的最终符号 |
| M8 | 容器分类与多版本/截断类隔离 | [M8.md](M8.md) | 按 magic 识别 MZ stub + zip 自解压容器、普通 PK jar 与目录；ircheck 对不可读类隔离而非整批判失败 | 不处理加密容器；multi-release 条目按同一基类的备选排除 |

## 独立语料（外置，不入库）

| 键 | 语料 | 形态 / 用途 | sha256 / 来源坐标 |
| --- | --- | --- | --- |
| `hmcl` | `HMCL-3.15.2.exe` | MZ stub + zip 自解压 PE、ProGuard / R8、约 3740 类 | `632c2d8873f5a11dd2ffd8418564174995c6a248de5206668c6be114e943e372` |
| `neo` | `NeoRaven1.1.jar` | PK zip、MC 1.8.9 / Forge、约 1534 类；常量池**无** ZKM 专属指纹 | `57f294cb4374861c7ee1c68e887f0bdcd09c0182545f80412ed2091a3ff6e022` |
| `neg` | 一个公开可下载的、未混淆的普通 jar（阴性对照，例：`junit:junit:4.13.2`，Maven Central） | 无 goto-flood / 非 vanilla BSM / native 库 / MC 元数据 / 加密容器 / 厂商专属指纹 | 来源坐标如上；sha256 在取用当次记入报告 |

三份语料都**样本不入库**：本体留在仓库外、不进 CI、不随 wheel 分发；报告  
与笔记**只记 sha256 与来源坐标**，不复制任何样本字节。HMCL 沿用 03 既有的  
用户授权前提，NeoRaven 同为用户本地自有样本；阴性对照 jar 为公开可下载，  
按坐标获取并当次记哈希。生成式 fixture 只用于负控，不计入独立样本。  

两个真实语料都没有非 vanilla 的 indy BSM（全是 `LambdaMetafactory` /  
`StringConcatFactory` / `ObjectMethods`），也没有 BytecodeVM `$CodePool`；  
经独立金标准核实，NeoRaven 常量池没有 `DESKeySpec`、`DES/CBC/PKCS5Padding`、  
`zelix`、`$CodePool`。相关机制的「目标数为 0」必须按事实记录，不写成已攻克。  

## 独立研究线边界（ROADMAP:231-236）

`docs/ROADMAP.md:231-236` 的独立研究线——BytecodeVM 复现、frida→Ghidra  
native 深度线、JNIC 容器还原——**永不并入「通用恢复」承诺**，按具体机制  
单独验证与报价，只作为能力证据。本清单**不把它们算作 1.0 默认支持项**：  
M1 的自定义 VM、M3 的非 vanilla / VM 级 indy、M5 的字符串池解密重放、  
M6 的 native 函数体反编译与 RegisterNatives 还原均属此线。当前独立语料上  
这些机制的目标数为 0，支持项只是识别与**如实报告 0**，不承诺还原，更不能  
记为已攻克该机制。  
