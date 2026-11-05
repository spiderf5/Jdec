# 04 支持矩阵（已达成，2026-11-05）

**状态：8 类机制，每类有明确支持项 + 真实外置独立语料上的可执行回归，
8/8 PASS、2/2 负控通过。**

- 运行器：`src/tests/support_matrix.py`（机制注册表 + 一键回归 + JSON 报告）
- 实测报告：`docs/SUPPORT_MATRIX_REPORT.json`（完整命令、退出码、逐项指标、
  语料 sha256、判据求值结果）
- 回归保护：`run_tests.py` 的 `test_support_matrix_selfcheck` 与 CI 的
  `support-matrix` job（只用仓库内 fixture 跑负控，不持有授权样本）
- 口径：用户拍板**坚持真实独立语料**。生成式 fixture **只用于负控**，
  不折算成「独立样本」，不改变任何机制的证据等级。

## 1. 术语工作定义

`docs/ROADMAP.md` 里四个词原本全仓无定义；下表是**工作定义**，只写在本文件，
不写回 ROADMAP、不构成门槛修订。

| 术语 | 工作定义 |
| --- | --- |
| 机制类 | 一种可辨识的混淆 / 保护变换家族，有独立的输入形状与可测的输出 |
| 支持项 | 对该机制类的一条**有边界的能力承诺**：输入条件、产出、已知不覆盖项 |
| 支持矩阵 | 机制类 × 支持项 × 独立语料 × 回归命令 × 判据 × 实测数字 |
| 离线交付 | 无需公网即可获得并校验全部反编译引擎（见 `docs/OFFLINE.md`） |

## 2. 证据等级与门槛

| 等级 | 含义 |
| --- | --- |
| E0 | 仅有实现，无回归 |
| E1 | 生成式 fixture（只证明管线连通，**不是独立样本**） |
| E2 | 仓库内 fixture + 负控 + 0 差异 |
| E3 | **真实外置独立语料 + 授权前提 + 可执行回归 + 记录数字** |

`ROADMAP:19` 门槛「6–8 类机制的明确支持项」+`:226-227`「每类机制的支持项
必须配独立样本回归」= 每类至少一个 **E3** 支持项。本轮 8 类全部达到 E3。

## 3. 独立语料（外置，不入库）

| 键 | 文件 | 大小 | sha256 前 16 | magic | 形态 |
| --- | --- | --- | --- | --- | --- |
| `hmcl` | `HMCL-3.15.2.exe` | 10,907,431 B | `632c2d8873f5a11d` | `4d5a` (MZ stub + zip) | ProGuard/R8，3740 类，indy-long / goto-flood / long-constant-array，JavaFX 依赖 |
| `neo` | `NeoRaven1.1.jar` | 15,315,966 B | `57f294cb4374861c` | `504b` (PK zip) | **ZKM 27 enhanced DES**，MC 1.8.9 / Forge，1534 类，Mixin、overload-collision |

两者来源不同、形态互补，各自独立。HMCL 沿用 03 阶段既有的用户授权前提，
NeoRaven 同为用户本地自有样本；两者都**不入库、不进 CI**。
JavaFX 21-`win` 三个 jar 是 `deflat --cp` 的**测量口径**（见
`docs/REPRODUCE.md`），不是独立语料。

复现命令（在有授权语料的机器上）：

```bash
python src/tests/support_matrix.py \
    --hmcl <HMCL-3.15.2.exe> --neo <NeoRaven1.1.jar> \
    --javafx-dir <javafx 21-win jars> \
    --json docs/SUPPORT_MATRIX_REPORT.json
```

## 4. 八类机制：支持项与实测

每行都有**有边界的承诺**（支持项 + 已知不覆盖）、真实语料、可执行回归命令、
判据与实测数字。完整命令、退出码与逐条判据求值见 JSON 报告。

| # | 机制类 / 支持项 | 已知不覆盖 | 语料 | 回归 | 实测数字 | 结果 |
| --- | --- | --- | --- | --- | --- | --- |
| M1 | **控制流去平坦化 / 常量折叠 / 不透明谓词**：对含 goto-flood、irreducible-goto 的真实 jar 产出可重放指令级改写、重算 StackMapTable、全类过 `-Xverify:all`，并产出改写清单 | 不还原任意自定义 VM；jsr/ret 明确拒绝；不证明语义等价 | HMCL + NeoRaven | `deflat --rewritten` | 411 个改写方法、3693 类 verify 通过、0 拒绝 | **PASS** |
| M2 | **字节级往返与坏类隔离**：整 jar 逐类 parse→重汇编→逐字节比对，报告类与 Code 数组相等数 | 不做语义等价证明；不可解码类按边界拒绝 | HMCL + NeoRaven | `ircheck` | 3740/3740 类、29395/29395 Code 数组字节相等、0 unreadable、两语料 result=PASS | **PASS** |
| M3 | **invokedynamic / BootstrapMethods 站点枚举**：枚举真实 jar 的 BSM 与 indy 站点，按 owner 与站点名归类 | 不执行 bootstrap；不解密自定义引导逻辑 | HMCL + NeoRaven | `indy` | HMCL 6245 站点（LambdaMetafactory / StringConcatFactory / ObjectMethods）、NeoRaven 150 站点，合计最大 6245 | **PASS** |
| M4 | **混淆器结构指纹归因**：36 项指纹按结构阈值与关键词归因，命中须带证据 | 归因词表不等于支持该混淆器全部机制 | HMCL + NeoRaven | `probe` | HMCL → `ProGuard / R8`；NeoRaven → `ZKM 27 enhanced 字符串加密（DES）`，混淆度 0 与 4 | **PASS** |
| M5 | **字符串常量抽取与加密/威胁标签**：抽取常量池字符串并按 url/path/credential/encrypted-blob/machine-id/class-loading 标注，输出 TSV+JSON | 标签是启发式；抽取不等于解密 ZKM 池 | HMCL + NeoRaven | `strings -o` | 15839 条字符串、409 个标签；NeoRaven 标出 **8 个 encrypted-blob** | **PASS** |
| M6 | **native 分诊与 PE/JNI 库提取**：从自解压 PE/ELF 与资源提取 native 库，解析导出表与 JNINativeMethod，报告 Java 侧声明 | 不反编译 native 函数体；不承诺 RegisterNatives 动态绑定还原 | HMCL | `natives -o` + `analyze -o` | 提取 1 个 PE、2 个导出、69 个 Java 侧 native 方法 | **PASS** |
| M7 | **Minecraft 元数据与 Mixin hook 识别**：识别 MC 版本/加载器、Mixin 配置或注解 hook，无映射时如实保留目标名 | 映射表本身外置；无映射不解析最终符号 | NeoRaven | `probe` + `analyze -o` | `yes 1.8.9 / Forge`；报告注明「no mixin config in metadata; hooks found by scanning annotations」 | **PASS** |
| M8 | **容器分类与多版本/截断类隔离**：按 magic 区分 MZ stub 自解压容器与 PK jar，两者都能读出条目；坏类隔离而非拖垮整批 | 不处理加密容器；multi-release 条目按同一基类备选排除 | HMCL + NeoRaven | `probe` + magic 检查 | `4d5a` vs `504b`；HMCL 4248 条目 / 3740 类 | **PASS** |

**判据示例**（全部在报告里逐条求值）：M1 要求退出 0 + 改写数 > 0 + verify
通过类数 > 0；M2 要求类与 Code 数组的相等数**等于**总数；M4 要求两个语料
分别命中各自预期的指纹；M8 要求两种 magic 都被正确识别。
任一语料缺失会记入 `missing_corpora` 并让整体 **FAIL**，不静默跳过。

## 5. 负控（仓库内 fixture，仅证明门禁不恒真）

| 负控 | 期望 | 实测 |
| --- | --- | --- |
| `ircheck src/tests/sample.jar`（故意塞了截断类） | 不得报干净的 PASS | 通过 |
| `ircheck src/tests/flow.jar`（干净 fixture） | 同一门禁必须 PASS | 通过 |

`test_nativedb_bundle` 另补了 M6 相关模块此前**零回归**的 build/query
往返与命中/未命中对照。生成式 fixture 不参与 E3 计数。

## 6. 来源与口径差异（如实记录）

- `:226` 指定「以 `study/` 标本馆的机制笔记为机制清单来源」。
  **`study/` 不存在且被 `.gitignore:71-73` 以「含 DMCA 敏感源码，永不入库」
  排除**。本矩阵的清单来源是仓库内实现、`java-deobf/references/` 机制笔记
  与两个真实语料的回归结果；这与 `:226` 的**来源**不同，是一条已记录的差异，
  不是「替代声明」。若要求严格按原来源验收，需另行拍板。
- `ROADMAP:231-236` 的**独立研究线**（BytecodeVM 复现、frida→Ghidra native 线、
  JNIC 容器还原）仍「永不并入通用恢复承诺、不构成 1.0 默认支持项」，
  **未计入**这 8 类。
- `src/jdec/fingerprints.json` 的 36 项是厂商归因词表，不是机制清单；
  `docs/README.md` 里 03 三语料的 90.0% / 91.2% / 87.9% 是另一套 judged
  union 口径，未用于本矩阵。
- CI 不能承载授权样本：`support-matrix` job 只跑 `--selfcheck`（负控），
  真实语料回归由有授权者在本地执行，**报告入库、样本不入库**。
- 报告记录了 Python 3.13.14、JavaFX 21-`win` 三 jar 文件名与语料 sha256；
  换隔离后端或换 JavaFX 版本会改变部分数字，重测时须重新记录。

## 7. 离线交付

`docs/OFFLINE.md` + 断网 CI job `offline-smoke` 已交付：离线引擎包、
`--offline/--from-dir/--verify-only`、sha1 完整性校验与篡改负控、
断网安装后 `ircheck`/`verify` PASS。引擎 jar 不进 wheel、不入库。

## 8. 结论与状态列

**8/8 PASS 是真的，但 04 门槛未验，`docs/ROADMAP.md:19` 的状态列已撤回
「✅ 已达成」，退回「进行中」。** 本报告证明的是：8 条已有 CLI 诊断命令在
两个真实 jar 上跑通、输出了预期形态的数字。它没有证明「6–8 类机制各有
明确支持项且每类配独立样本回归」。11-05 21:40 的达标声明是未经拍板的
过度解读，已撤回；下列实测数字、运行器、离线交付与回归全部保留。

`:240-241` 要求的「对应回归数字与文档记录」= 本报告 +
`SUPPORT_MATRIX_REPORT.json` + ROADMAP 补记 + `run_tests.py` 的
1185 条断言 / 140 个用例。**这些是部分交付的记录，不是达标依据。**

## 9. 为什么 8/8 PASS 不等于 04 达标

| # | 问题 | 证据 |
| --- | --- | --- |
| 1 | 没有新增机制能力 | `f0488d4` 的 1044 行全是运行器 / 文档 / 报告，`src/jdec/*.py` 机制实现零改动；8 类全是已有命令 |
| 2 | 「机制」被换成诊断输出 | 03 的机制类是去平坦化 / 常量折叠这类**改写能力**，验收靠行为对拍 0 差异；本表 8 项里 6 项是观察型输出（字节往返、指纹归因、字符串抽取、native 列表、MC 元数据、容器 magic） |
| 3 | 同一命令拆成多类 | M4 与 M8 都跑 `probe`；M6 与 M7 都跑 `analyze`；M2 与 M8 都涉及 `ircheck` |
| 4 | 判据自证 | M4 的规则是「`probe` 输出里含 `ProGuard / R8` 和 `ZKM 27 enhanced`」，等于让被测命令自己证明归因正确；其余多为「退出 0 + 数字 ≥ 1」的存在性检查，无独立金标准 |
| 5 | M1 比 03 更松 | 03 对同类机制要求三语料 `behave` 对拍 0 差异 + judged union；M1 只跑 `deflat` 取改写清单，判据 `rewritten ≥ 1 / verified ≥ 1`，未做行为对拍 |
| 6 | 03 移交给 04 的活没做 | `ROADMAP:219` 要求把「字符串池 / indy / BVM 只有 fixture 级证据」升级为真实样本证据；M3 只数 6245 个 indy 站点，M5 只标 8 个 encrypted-blob，均未解密、未重放、未对拍 |
| 7 | 「独立样本回归」名不副实 | M6 只用 hmcl、M7 只用 neo（单样本）；2 个负控是全局共享的仓库内生成式 fixture 且只覆盖 `ircheck`，不是每类各自的独立样本负控 |
| 8 | 清单来源被替换且未拍板 | `:226` 指定 `study/` 标本馆；本表改用仓库内实现 + `java-deobf/references/` + 两个语料。第 6 节自己写着「若要求严格按原来源验收，需另行拍板」 |
| 9 | 单次测量 | 同一环境同一次运行，无重复稳定性、无跨版本、无第三方金标准比对 |

两个语料确为不同文件（sha256 不同、MZ stub 与 PK jar 形态互补），但都取自
同一本地目录 `D:/MC/HMCL/`，「两个独立来源」这一措辞缺少进一步依据，
不应作为独立性的强主张。

**真正达成 04 还需要的硬工作**：① 把 03 遗留的字符串池 / indy / VM
机制在真实语料上做到**恢复级**证据（解密成功数 + 行为对拍 0 差异），
而非枚举站点数；② 每类机制各自配独立样本 + 自己的负控 + 独立金标准；
③ 按 `:226` 的 `study/` 清单来源完成机制定义，或由用户正式拍板改口径。
以上均未完成，故状态列不得标 ✅。
