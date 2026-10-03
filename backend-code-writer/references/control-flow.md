# 控制流混淆：识别与还原

还原成本最高的一类混淆。`deobf_scan.py` 会给出 goto / switch / 异常表三个密度指标作为筛查入口。

## 常见手法与字节码表现

| 手法 | 表现 | 静态特征 |
|---|---|---|
| switch 平坦化 | dispatcher 变量 + `TABLESWITCH`/`LOOKUPSWITCH` + 回跳 | 单方法 switch 密度高；case 内只写状态变量后 GOTO 回 dispatcher；case 间无 fallthrough |
| opaque predicate | 恒真/恒假的算术条件 | 条件可常量折叠：`ICONST; IXOR; IXOR`、`x*x >= 0`、`x%2==0 \|\| x%2!=0` |
| junk code | 插入 POP 序列与不可达块 | ASM `Analyzer<BasicInterpreter>` 算出 frame 为 null 的指令 |
| 异常表滥用 | 用 try-catch 当跳转 | 异常表条目 / 条件分支比值高；handler 声明的异常在 `throws` 里根本不存在 |
| goto 增强 | 冗余 GOTO、块顺序打乱 | goto 密度高 |
| jsr/ret | Java 6 之前的老式流混淆 | 出现 jsr/ret 指令 |

## 二值指纹：异常处理器向后跳

上面那些指标都是**密度**，密度只能筛查。有一个是**二值**的、编译器造不出来的：

> **异常处理器的 `handler_pc` 落在它所保护的区间 `[start_pc, end_pc)` 之前。**

```python
h.start_pc <= pc < h.end_pc      # 这个处理器保护这段
h.handler_pc < h.start_pc       # 却跳回这段之前  ← javac 绝不生成
```

理由是自明的：范围内抛出的异常不可能在范围开始之前就被处理。
**`deobf_scan.py` 已经在算这个指标，JSON 字段叫 `backward_handlers`**（`--text`
输出里没显示，别因为终端没打印就说它没有 —— 我犯过这个错）。

## 但它对 ZKM 27 不成立：实测三份样本

| 指标 | vanilla 1.20.4（7787 类） | ZKM 27 弱（723 类） | ZKM 27 强（723 类） |
|---|---|---|---|
| `backward_handlers` | 0 | **0** | **0** |
| `irreducible_gotos` | 234 (2.0%) | 2754 (28.9%) | 4977 (46.9%) |
| goto 密度（字节） | **1.34%** | 2.7% | **13.92%** |
| `clinit-decryptor`（`<clinit>` 解密循环） | 0 | 315 (43.6%) | 315 (43.6%) |

**ZKM 27 三份样本的 `backward_handlers` 全是 0。** 公开分析里那种「4265 处后跳」
是别的版本或别的混淆器。ZKM 27 的 flow 混淆实际是**把线性代码拆成 goto 链**
（switch → 状态机），不是拿异常表当跳转。

所以归因要靠这几条，而它们必须**按命中类占比**判定，不是看有没有命中：

| 指纹 | vanilla 命中占比 | ZKM 27 命中占比 |
|---|---|---|
| `clinit-decryptor` | 0.0% | 43.6% |
| `goto-flood`（方法级 goto ≥ 10%） | 3.1% | 46.9% |
| `irreducible_gotos` | 2.0% | 28.9% |
| `long-constant-array` | 0.9% | 23.4% |

**10% 的占比门槛**能把两侧都分开（vanilla 最高 3.1%），也不需要额外调参。

### 两条方向相反的假证据

| 指纹 | vanilla | ZKM 27 样本 |
|---|---|---|
| `fake-sourcefile`（SourceFile 与类名不符） | **100%** | 0.1% |
| `overload-collision`（同名方法 ≥ 4） | **34%** | 3.7% |

**Minecraft 官方 jar 的 SourceFile 属性是被剥掉的**，所以 100% 不匹配 ——
拿它当混淆器证据是反的。方法重载密度同理：官方混淆比商业混淆器更密。
这两个只能报告，绝不能参与归因。

## 想用 javac 造一个 goto 洪水？造不出来

三次尝试都被 javac 折叠掉，值得记住：

- `if (x == 1) ... if (x == 2) ...`（连续值）→ 整个链条变成**一个 tableswitch，0 个 goto**
- 返回值连续（101/103/107…）→ 变成 **lookupswitch，0 个 goto**
- 把值改成 3 / 1013 / 2003 这种大跨度 → 仍是 **lookupswitch，0 个 goto**

javac 永远会把「对同一个变量比较、返回常量」的 if 链折成 switch。
**goto 洪水只可能来自字节码改写器** —— 这正是所有 flow 混淆器的共同前提。
javac 能达到的最坏情况是嵌套循环 + break/continue，实测 goto 密度 **7.3%**，
可以作为阈值参考（ZKM 是 13.9%）。

## 指纹会互相污染，要用阈值

弱证据叠加成结论时必须有下限，否则会把正常客户端判成重度混淆。
实测教训：最初的版本把「不可约 goto」和「indy + long」也算进 ZKM 权重，
结果 vanilla 1.20.4 拿到 0.43 的 ZKM 置信度 —— 两条指纹在正常代码里都常见。
修正后：不可约 goto 降为只报告不参与归因，indy 要求同方法内 indy 与 ldc2_w
各 ≥2，最后加「低于 0.35 不给厂商结论」的硬下限。同一份 vanilla 随即回到「未知」。

**只有「语言破坏型」变换才有杀伤力**：生成非结构化（unstructured）控制流的变换，会让反编译器的
结构化算法直接失效（Kumar & Kurian 2018 评测 13 个混淆器后的分类结论）。
厂商还会故意插入自己的死代码 —— 这反而成了识别该工具的指纹。

## 指标怎么读

- **goto 密度**：正常代码多数低于 3%，但**正常的 switch 密集代码也能到 14%**（实测 76 条指令 14.5%）。
  所以这个指标只在样本足够大时才有意义（本工具门槛 200 条指令），且要拿同项目未混淆版本做基线对比。
- **switch 密度**：正常接近 0，持续偏高说明存在 dispatcher。
- **异常表 / 条件分支**：正常低于 0.2，DashO 系风格会超过 1。
- **jsr/ret**：非零即老式流混淆。

## 还原顺序（顺序本身就是关键）

1. **先修文件合法性**。混淆器会构造非法注解、非法签名、非法可变参数、未知属性来让反编译器崩。
   先跑 `general.remover.*`（IllegalSignature / IllegalVarargs / SyntheticBridge / LineNumber）
   与 Recaf 的对应 transformer。**不修这步，后面全白做。**
2. **清栈帧**：`Stack frame removal`。junk 栈帧会让后续工具出错。
3. **常量折叠 + 谓词化简**：`general.peephole.ConstantFolder`、Recaf 的 *Opaque constant folding*。
   **必须多 pass** —— 折叠一次会暴露新的可折叠谓词。
4. **死代码与跳转清理**：`DeadCodeRemover`（基于 ASM `Analyzer<BasicInterpreter>` 找 frame==null）、
   `GotoRearranger`、Recaf 的 *Goto inlining* 与 *Redundant try-catch removal*。
5. **兜底开关**：CFR 的 `--lenient`、`--allowmalformedswitch`、`--forceexceptionprune`、`--antiobf`。
6. **最后才反编译**出源码，人工比对。

java-deobfuscator 的 `general.peephole.PeepholeOptimizer` 是第 2–4 步的聚合入口
（内部注册 NopRemover / RedundantTrapRemover / GotoRearranger / DeadCodeRemover /
LdcSwapInvokeSwapPopRemover / ConstantFolder）。给它配 `-Xss128m` 和完整 `-path`（含 rt.jar）即可。

## 什么时候该放弃自动化

- dispatcher 变量被**跨方法拆散**（过程间数据流增强）
- 谓词依赖运行时状态（时间、随机数、反射）
- 目标从「读懂逻辑」升级为「精确原始语义」

这三种情况自动化还原不现实，直接转人工。控制流平坦化后的程序可能存在多个合法 CFG，
静态无法证明哪个是「原始的」—— 恢复 CFG 不是唯一解问题。

## 一个常见的错误认知

被广泛引用的 `ControlFlowDeobfuscator`、`transformers.controlflow.GotoGotoRemover`
在 java-deobfuscator 仓库里**查不到**；`PeepholeOptimizer` 的 static 块是唯一权威注册点。
写自定义规则走 `InstructionPattern`（见仓库的 CUSTOMTRANSFORMER.md）。
