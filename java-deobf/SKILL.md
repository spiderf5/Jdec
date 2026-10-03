---
name: java-deobf

description: 面向混淆 Java（含 Minecraft 客户端与 Forge / Fabric 模组）的反编译、反混淆与行为分析工作流，主力工具是 jdec（多引擎反编译驱动，位于 D:\MC\Workbuddy\deobf\jdec）。覆盖：混淆度探测与混淆器识别（ZKM / Allatori / Stringer / DashO / superblaubeere27 / JObf / JNIC 等）、Mojang / Yarn / MCP 映射反混淆、Mixin hook 提取与 refmap 还原、indy 调用目标解码、字符串情报导出、native / 虚拟化保护判定、运行时捕获（agent 桩化 / dump）。凡用户提到反编译 / decompile、反混淆 / deobfuscate / deobf、逆向工程 / reverse engineering、混淆的 jar / class / 字节码、还原类名方法名、字符串解密、MC 客户端或模组分析、外挂 / 作弊客户端 / 可疑 jar 分析，或丢来一个 jar 问"这里面是什么 / 它想干什么"，都使用本 skill；也覆盖 jdec 本身的开发、测试与 bug 修复。普通后端业务代码的编写与调试不在此列。
---

# java-deobf

## 定位

把混淆过的 Java 还原到**读得懂、可验证**的形态，并回答"它想干什么"。

主力工具是 jdec（多引擎反编译驱动，位于 `D:\MC\Workbuddy\deobf\jdec\`）：
多引擎择优、MC 反混淆、混淆器归因、Mixin 分析、字符串导出、native 判定
都已做成代码。本 skill 负责
**流程编排、判定纪律，以及 jdec 覆盖不了的部分**（无 jdec 环境的降级路径、
运行时捕获、知识沉淀）。工具用法细节读
`D:\MC\Workbuddy\deobf\jdec\README.md`，不在这里重复。

本 skill 是用户级安装，任何工作区都可能触发。runbook 里的命令默认在
`D:\MC\Workbuddy\deobf` 下执行，其他工作区先 `cd` 过去再用；jdec 不可用时
（别的机器、路径被移走）才走降级路径。本文中的 `scripts/`、`references/`、
`assets/` 一律指本 skill 目录下的文件（加载本 skill 时会给出 base
directory），不是当前工作区的。

## 铁律

1. **只分析有权分析的代码**——自有项目、已授权的研究或学习。对方明确禁止时停止。
2. **动手前先备份原始 jar**。重命名与字节码打补丁基本不可逆。
3. **先探测再动手**。`jdec probe` 或 `deobf_scan.py` 拿到混淆度、版本与指纹，
   不凭文件名或包名猜混淆器——ZKM 这类纯字节码变换的工具不留任何运行时痕迹，
   包名认混淆器只对一半工具有效。
4. **结论必须有证据**（真实命令输出）。"跑通不等于完成"：判定类逻辑改完必须用
   **真实样本回归**——fixture 会骗人，javac 会把你想造的特征优化掉（if 链折叠成
   switch，造不出 goto 洪水）。
5. **最小 diff**。修 jdec 本身不顺手重构；还原命名按**行为**命名，拿不准的
   保留原名加注释，批量重命名交给 AutoRenamer。
6. **交付标准**：可重新编译 + 行为与原始一致。**读得懂不等于还原正确**。
7. **敏感信息只定性不外传**：分析中发现的 URL、凭据、机器码，报告里说明
   存在与用途即可，不原样扩散。
8. **沉淀**：本次新验证的结论回写 `fingerprints.json` / `references/`
   （工作区如有长期记忆文件也同步）。只写验证过的，不写猜测；不删旧条目，
   除非确认是错的并注明证据。改完指纹库跑 `self_test.py` 验证。

## 实战 runbook

按成本从低到高走，前两步就能决定要不要继续投入：

```bash
# 0. 环境（一次）：JDK 9+（Zulu 21 已验证），引擎 jar 自动从 Maven Central 下载
python jdec.py engines
```

### 1. probe — 先看对面是什么

```bash
python jdec.py probe X.jar
```

混淆度评分、MC 版本、结构指纹采样、native 方法数。产出决定后续投入与预期：
native 密集意味着部分代码不在字节码里，任何反编译器都还原不出来。

### 2. strings — 最便宜的情报

```bash
python jdec.py strings X.jar -o out --suspicious   # 只留 url/ip/路径/凭据/命令/机器码
python jdec.py strings X.jar -o out --grep 关键词
```

程序总得和外界说话——URL、写的文件、执行的命令、校验的 token 在常量池里，
**混淆器改不掉**。不用执行、不用改写，扫一遍就出结果。

### 3. analyze — 它改了游戏哪里

```bash
python jdec.py analyze X.jar -o out --mc-version 1.20.4
```

Mixin hook 清单（目标自动过映射翻译，`brc` → `CreeperEntity`）+ 行为信号
（JNI / 网络 / 加密 / 反调试 / 机器指纹）。**注解里的目标是常量池常量，
混淆改不了**——这是分析比反编译更稳的原因。Fabric refmap 会先于 MC 映射还原
（顺序反了没有任何映射认识 `method_1234`）。

### 4. decompile — 源码与逐类评分

```bash
python jdec.py decompile X.jar -o out --verify-all
```

两趟多引擎择优（CFR / Vineflower / Procyon），以**字节码为标准答案**逐类打分，
不做行数猜测。产出 `src/`、`report.md`（哪些类没还原干净）、`report.json`
（含每类的 `rel` 输出路径——大小写孪生类的路径经百分号编码，不等于类名，
从这里反查）。native 方法单列，不计入还原失败。

### 5. 深挖（按需，先读对应 reference 再动手）

| 症状 | 去处 |
|---|---|
| 混淆器归因存疑、想看工具链与映射体系 | `references/java-deobf.md` |
| 控制流混淆（goto 洪水、不可归约循环）指标怎么读 | `references/control-flow.md` |
| 字符串加密：静态还原三层不划算时改走运行时出口 | `references/string-encryption.md` |
| 毒类（静默退出 / native 崩）、agent 桩化、运行时 dump | `references/dynamic-analysis.md` |
| indy 编码调用图（superblaubeere27 / JObf 系） | `jdec/README.md` 对应节 |

运行时捕获的核心思路：**让混淆器自己解密，我们只盯着出口**。优先级是
零环境的纯重放 → 字节码手术 agent → 真实环境倾倒；真环境里授权校验必须
真过，桩化 agent 反而会坏事。

### 6. 沉淀

按铁律 8 执行。识别到新混淆器：往 `scripts/fingerprints.json` 的
`obfuscators` 加 `name` / `keywords` / `tool`，然后
`python scripts/self_test.py <刚扫的目标>` 验证；控制流阈值因项目而异，
拿同源未混淆 jar 跑出基线再调。

## 无 jdec 时的降级路径

```bash
python scripts/deobf_scan.py <jar/class/目录> --text
```

只解析 class 结构与 jar 目录，不执行目标代码：命名可疑比例、字符串加密迹象、
混淆器线索、native 方法、jar 结构异常、反射与动态调用特征，附推荐工具链。
之后按 `references/java-deobf.md`：java-deobfuscator（Allatori / Stringer /
ZKM / DashO 系）、narumii-Deobfuscator（superblaubeere27 / Paramorphism /
Caesium 系）、Threadtear；Vineflower 出源码、CFR 交叉验证可疑段落、
反编译器全崩时用 Krakatau 看指令、Recaf 看字节码结构后自写 transformer。
字符串加密先定位解密方法再批量还原，不要手工一个个解。

## 修 jdec 本身

- 唯一校验命令：`python tests/run_tests.py`（2026-10-03 基线 107 项；
  `--with-mc` 123 项，真实样本外置于 `D:/MC/samples/`，缺失自动跳过）。
- 自动探测工具识别不出这个项目（无标准标记文件），校验直接用上面的命令。
- 修 bug 三步：先复现（失败测试或命令）→ 最小修复 → **真实样本回归**。
  位置配对类并发 bug fixture 抓不住（单类桶完成顺序碰巧一致）。
- 改 `classfile.py` 后必跑 round-trip 断言：parse→serialize 字节级一致，
  否则重映射会静默损坏每个类。
- fixture jar 由 `python tests/build_fixtures.py` 用 javac 编出；跑测试时
  jar 缺失会自动构建，构建不了就跳过而不是判失败。

## 变更报告

改动 jdec 或本 skill 后，按 `assets/change-report-template.md` 生成
`change-report.md`（jdec 的报告文件，历次报告追加式），行数统计用
`scripts/diff_summary.py`。报告必须包含：任务目标、文件级变更、每处改动
的理由、执行的命令与结果、修复轮次、遗留风险、回滚方式。
