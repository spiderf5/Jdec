\---  
name: java-deobf
  
description: 面向混淆 Java（含 Minecraft 客户端与 Forge / Fabric 模组）的反编译、反混淆与行为分析工作流，主力工具是 jdec（多引擎反编译驱动）。覆盖：混淆度探测与混淆器识别（ZKM / Allatori / Stringer / DashO / superblaubeere27 / JObf / JNIC 等）、Mojang / Yarn / MCP 映射反混淆、Mixin hook 提取与 refmap 还原、indy 调用目标解码、字符串加密的静态与动态还原、native / 虚拟化保护判定、运行时捕获（agent 桩化 / payload dump）。凡用户提到反编译 / decompile、反混淆 / deobfuscate / deobf、逆向工程 / reverse engineering、混淆的 jar / class / 字节码、还原类名方法名、字符串解密、MC 客户端或模组分析、可疑 jar 分析，或丢来一个 jar 问"这里面是什么 / 它想干什么"，都使用本 skill；也覆盖 jdec 本身的开发、测试与 bug 修复。普通后端业务代码的编写与调试不在此列。  
\---

# java-deobf

## 1. 定位与范围

本 skill 处理两类问题：

1. **还原**：把经混淆器处理的 Java 字节码恢复到可读、可编译、行为等价的形态；
2. **定性**：回答"这个 jar 是什么、改了系统的哪些行为、有哪些外部通信面"。

主力工具 jdec（多引擎反编译驱动：CFR / Vineflower / Procyon 择优、映射反混淆、
  
混淆器指纹归因、Mixin 分析、字符串导出、native 分诊、运行时捕获）。本 skill
  
提供流程编排、判定准则与 jdec 未覆盖的降级路径；工具的命令行细节见 jdec 的
  
`README.md`。

约定：正文中的 `scripts/`、`references/`、`assets/` 均指本 skill 目录内的
  
文件（加载时给出 base directory）。runbook 命令默认在 jdec 所在的工作区根
  
目录执行；jdec 不可用时才走第 7 节的降级路径。

## 2. 方法论原则

以下原则从反复出现的失败模式中归纳，效力等同操作规程。

**授权与安全**

1. 仅分析有明确授权的代码；权利方禁止时停止。
2. 动手前备份原始制品。重命名与字节码改写基本不可逆。

**证据与验证**

1. 先探测后动手：混淆器归因必须来自结构指纹而非文件名或包名——纯字节码
     
   变换型混淆器（如 ZKM）不留运行时痕迹。
2. 结论必须可复现（附真实命令输出）。判定类逻辑的修改必须经真实样本回归；
     
   仅用 fixture 验证不可靠——编译器会优化掉人造特征（如 if 链折叠为
     
   switch，无法构造 goto 洪水）。
3. 跨实现交叉验证是校准翻译/解密类代码的首选手段：以被逆向实现自身
     
   （或其衍生实现）的输出为真值，对拍逐字节比较。
4. 交付标准：可重新编译且行为与原始一致。"可读"不是正确性的充分条件。

**最小作用域**

1. 修工具不做顺手重构。还原命名必须有证据（注解明文、行为对应）；无证据
     
   时保留原名并加注释。

**信息处置**

1. 敏感信息（URL、凭据、机器码）只定性不扩散：报告说明存在与用途，不原样
     
   复制。

**知识沉淀**

1. 新验证的结论回写指纹库与 references；只写验证过的，不写推测；不删除
     
   既有条目，除非确认有误并附证据。修改指纹库后运行 `self_test.py`。

**失败分析**

1. 失败清单必须逐类归因分桶，禁止以单一叙事带过。经验上，报告为失败的
     
   条目中相当比例（实践中常见 ~30%）属 classpath 组装错杀等可修复类，
     
   统一叙事会把可救的与不可救的混在一起。

## 3. 分析不变量

形态识别、工具与流程都是捷径而非前提；套路失效时回到问题的物理本质重新
  
推导。五条核心不变量：

1. **解密的目的在于使用**——明文必然在某一时刻以明文形态存在于内存
     
   （常量池、静态字段、数组、intern 表）。因此"在出口处收集"（运行时
     
   捕获）总是可行；静态模拟只是降低成本的手段。
2. **字节码是事实标准**。反编译输出是近似；验证、评分与回填对账一律以
     
   字节码为准。
3. **混淆不改变两类信息**：注解中的常量、对 JDK / 平台 API 的调用点。
     
   分析优先覆盖这两类。
4. **环境是前提**：class 文件版本（v69 需 JDK 25）、依赖库、路径转换，
     
   任何一项错误都会使结果全假或全空。先验证环境，再怀疑工具。
5. **先确定"数据此刻在哪、以什么形态存在"，再选择手段**。形态不明时先做
     
   探测与普查，观察解密产物落在哪个存储，收集方案自然浮现。

## 4. 分析管线

按成本递增排序；前两步通常足以决定投入策略。

```bash
# 环境（一次）：JDK 9+，反编译引擎自动从 Maven Central 获取
python jdec.py engines
```

### 4.1 probe — 指纹与画像

```bash
python jdec.py probe X.jar
```

产出：混淆度评分、目标平台版本、结构指纹采样、native 方法计数。
  
native 方法密集意味着部分逻辑不在字节码内，任何反编译器都无法直接还原。

### 4.2 strings — 低成本情报面

```bash
python jdec.py strings X.jar -o out --suspicious   # URL/IP/路径/凭据/命令/机器码
python jdec.py strings X.jar -o out --grep 关键词
```

外部通信面（URL、写盘路径、执行的命令、校验 token）位于常量池，混淆不
  
改变其存在性；无需执行即可采集。

### 4.3 analyze — 行为面

```bash
python jdec.py analyze X.jar -o out --mc-version <ver>
```

Mixin hook 清单（目标经映射翻译）+ 行为信号（JNI / 网络 / 加密 / 反调试 /
  
机器指纹）。注解中的 hook 目标是常量池常量，混淆不改写——这是行为面分析
  
比源码还原更稳定的原因。Fabric refmap 必须先于 MC 映射还原，顺序颠倒时
  
任何映射都无法识别 `method_NNNN` 形态的中间名。

### 4.4 decompile — 源码与逐类评分

```bash
python jdec.py decompile X.jar -o out --verify-all
```

两趟多引擎择优，以字节码为基准逐类评分。产物：`src/`、`report.md`（未
  
还原干净的类）、`report.json`（含每类 `rel` 输出路径——大小写冲突类的路径
  
经百分号编码，与类名不同，需由此反查）。native 方法单列，不计入还原失败。

### 4.5 深挖（按需；先读对应 reference）

| 症状                                      | 去处                                                                           |
| --------------------------------------- | ---------------------------------------------------------------------------- |
| 混淆器归因存疑；工具链与映射体系                        | `references/java-deobf.md`                                                   |
| 控制流混淆指标的解读与阈值                           | `references/control-flow.md`                                                 |
| 字符串加密：形态识别与还原路线                         | `references/string-encryption.md`                                            |
| 毒类、agent 桩化、运行时 dump、Frida 捕获           | `references/dynamic-analysis.md`                                             |
| indy 调用目标普查                             | `python jdec.py indy X.jar`；`references/string-encryption.md`                |
| 字符串解密回填源码（零残留）                          | `python jdec.py recover X.jar --output out/recover --rewrite-src out/src`    |
| 访问器池形态：`Cls.a(idx, seed)`               | `python jdec.py pool scan\|harvest\|apply`                                   |
| 单参池形态：`(C)Ljava/lang/Object;`           | `python jdec.py opspool X.jar`（纯静态 DES 解密）                                   |
| native 方法体在 PE/ELF 内                    | `python jdec.py natives X.jar -o out`；裸 DLL 可直接作为输入                          |
| dumped 库的结构化查询                          | `python jdec.py nativedb <lib> --build <dir>`；`nativedb <dir> --search <kw>` |
| BytecodeVM 类虚拟化器：静态反虚拟化方法论（提取→解码→路由） | `references/bytecode-vm.md`（专属工具已移出产品树，方法可迁移至同构 VM） |
| 字节码级 VM 派发对拍（运行时 trace vs 静态 decode）  | ASM 注入 + 候选集校验，方法见 `references/bytecode-vm.md` §5                        |
| 提交 / PR / 变更报告规范                        | `references/git-workflow.md`（校验命令见其「提交前自检」）           |

### 4.6 收尾核查

1. 失败清单是否已按桶归因，并逐桶回答"成因 / 可否修复 / 是否值得修复"；
2. MANIFEST / 模块描述符元数据是否已并入定性结论（vendor、Premain 声明、
     
   标识符异常）；
3. 回填字面量是否全部转义（产出树中裸控制字节计数应为 0；统计与检索
     
   需按二进制安全方式进行，否则对账数字静默漏计）；
4. 是否产出 scorecard 并与上一轮对比（无法回答"比上轮好多少"即未完成）；
5. 新结论是否已按第 2 节第 9 条沉淀；
6. 报告对未解部分给出的是分桶证据还是统一叙事。

### 4.7 沉淀

识别新混淆器：向 `scripts/fingerprints.json` 的 `obfuscators` 追加
`name` / `keywords` / `tool`，运行 `scripts/self_test.py` 验证。keywords
一律小写——匹配前会统一转小写，含大写字母的条目永不命中（self_test
会拒绝并做常量池命中端到端校验）。`jdec/jdec/fingerprints.json` 是包内
回退副本，必须与本副本逐字节一致（self_test 自动比对）；jdec 的
`probe` 优先读本副本。控制流阈值与目标生态相关，应以同源未混淆制品
建立基线后再调整。

## 5. 无 jdec 时的降级路径

```bash
python scripts/deobf_scan.py <jar/class/目录> --text
```

仅解析 class 结构与 jar 目录，不执行目标代码：命名可疑度、字符串加密
  
迹象、混淆器线索、native 方法、结构异常、反射与动态调用特征，并给出
  
推荐工具链。开源工具链选择见 `references/java-deobf.md`；原则：字符串
  
加密先定位解密方法再批量还原，不做逐串手工解密。

## 6. jdec 的维护

- 校验命令唯一：`python jdec/tests/run_tests.py`（基线随功能演进由运行器
    
  打印；`--with-mc` 含真实样本用例，样本缺失自动跳过）。
- 缺陷修复流程：复现（失败测试或命令）→ 最小修复 → 真实样本回归。
    
  位置/配对类并发缺陷 fixture 可能无法捕获（单桶完成顺序恰好一致）。
- 修改 `classfile.py` 后必须运行 round-trip 断言：parse→serialize 字节级
    
  一致，否则重映射会静默损坏所有类。
- fixture jar 由 `jdec/tests/build_fixtures.py` 经 javac 构建（含 sample.jar）；缺失时自动
    
  构建，构建失败跳过该组测试而非计为失败。

## 7. 变更报告

修改 jdec 或本 skill 后，按 `assets/change-report-template.md` 生成
  
`change-report.md`（追加式）。内容必须包含：任务目标、文件级变更、每处
  
修改的理由、执行的命令与结果、修复轮次、遗留风险、回滚方式。
