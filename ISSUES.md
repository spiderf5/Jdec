# jdec 遗留问题清单（交接文档）

> **生成时间**：2026-10-07  
> **来源**：静态代码审计（3 路并行审计 + 主执行者逐条复核行号）  
> **实测基线**：`python jdec/tests/run_tests.py` → **477 passed, 0 failed**（JDK 21.0.9，2026-10-07 本机实测）  
> **处理顺序**：§1 P0 → §2 P1 → §3 P2。每条含「现象 / 证据（file:line）/ 根因 / 建议改法 / 验收方式」。  
> **纪律**：动手前必读 §5。这个仓库有自己的工程约定，违反会导致返工。

---

## 0. 环境与基线（先跑这一步）

```powershell
cd D:\MC\Workbuddy\deobf
java -version                       # 需要 JDK 9+，本机实测 21.0.9（Zulu/Temurin 均可）
python jdec/tests/run_tests.py      # 期望：477 passed, 0 failed
```

注意事项：

- **引擎 jar 自动下载**：`jdec/engines/*.jar` 被 gitignore，首次运行会从 Maven Central 拉取 CFR 0.152 / Vineflower 1.11.1 / Procyon 0.6.0（`jdec/jdec/engines.py:23`）。本机已存在。
- **真实样本外置**：`D:\MC\samples\`（如 `Myau0729-obf.jar`）。`--with-mc` 还需要 `jdec/tests/mc/client_1.20.4.jar`（本机有）。找不到时相关用例自动跳过，不是失败。
- **fixture jar**：`jdec/tests/{mixin,flow,collide}.jar` 缺失时会由 `jdec/tests/build_fixtures.py` 用 javac 自动构建；**`sample.jar` 不会**（见 P0-1）。
- **执行环境注意**：本清单在 DSH 会话中生成，其文件沙箱在 read-only 模式下会拒绝访问 `D:` 盘（`SetNamedSecurityInfoW failed (Win32 5)`），需放开到 full-access 后命令行才可用。若你的执行环境有同类限制，先确认能读写工作区再动手。

---

## 1. P0：阻塞级

### P0-1　CI 在干净检出上必然失败（fixture 不入库且无人构建）

**现象**：`.github/workflows/ci.yml` 配置的 3 OS × 4 Python 矩阵，在任何干净检出（含 CI 自身 checkout）上都会以退出码 2 失败，永远显示红灯。

**证据**：

| 事实                                                                 | 位置                                                                |
| ------------------------------------------------------------------ | ----------------------------------------------------------------- |
| CI 只跑一条命令，不构建 fixture                                              | `.github/workflows/ci.yml:42-44`                                  |
| 缺 `tests/sample.jar` 时直接 `return 2`                                | `jdec/tests/run_tests.py:2739-2741`                               |
| `build_fixtures.py` 只生成 mixin/flow/collide，**没有 sample.jar 的构建路径** | `jdec/tests/build_fixtures.py:25,29,38`；全树 `grep sample.jar` 无生成方 |
| `.jar` 被 gitignore                                                 | `.gitignore:21`（`jdec/tests/*.jar`）                               |
| **全仓库无任何 jar 被跟踪**（实测）                                             | `git ls-files '*.jar'` → 空输出                                      |

源码是在的：`jdec/tests/samples/demo/{legacy,modern,obf}/`，且 `jdec/tests/build/{modern,legacy,obf}/` 有编译产物 —— 说明 sample.jar 曾被手工构建过，但构建脚本没进仓库。

**建议改法**（推荐 (a)+(c)）：

- (a) 在 `build_fixtures.py` 中新增 `build_sample_jar()`，复用现有 `_compile()`（`build_fixtures.py:55`）编译 `samples/demo/` 三个子树并用 `zipfile` 打包为 `tests/sample.jar`；
- (c) 在 `run_tests.py` 里按 `ensure_mixin_jar()`（`run_tests.py:2783`）的既有模式调用它 —— 缺 jar 时先尝试构建，构建失败才跳过；
- (b) 备选：`git add -f jdec/tests/sample.jar` 强制入库（不推荐，二进制 fixture 会随提交膨胀）。

**验收**：删除 `jdec/tests/sample.jar` 后 `python jdec/tests/run_tests.py` 仍得到 `477 passed, 0 failed`；CI 全矩阵转绿。

### P0-2　POSIX 上 classpath 分隔符被硬编码为 `;`

**现象**：Linux / macOS 上 Procyon 引擎不可用、CFR/Vineflower 的额外 classpath 失效；CI 矩阵包含 ubuntu-latest 与 macos-latest，即使 P0-1 修好，这两个平台也过不了。

**证据**：

| 位置                         | 代码                                                  | 影响                                                                   |
| -------------------------- | --------------------------------------------------- | -------------------------------------------------------------------- |
| `jdec/jdec/engines.py:107` | `return ";".join(parts)`                            | 该返回值用于 `:250` 的 `-cp` —— ProcyonBridge 的 classpath 在 POSIX 上变成单一无效路径 |
| `jdec/jdec/engines.py:261` | `"--extraclasspath", ";".join(extra_cp)`            | CFR 额外 classpath 失效                                                  |
| `jdec/jdec/engines.py:263` | `f"-e={';'.join(extra_cp)}"`                        | Vineflower 额外 classpath 失效                                           |
| `jdec/jdec/recover.py:524` | `cp + (";" if cp and not cp.endswith(";") else "")` | 追加 `--cp-file` 内容时用 `;` 拼接                                           |

**同仓已有正确写法可对照**：`jdec/jdec/pipeline.py:363`、`jdec/jdec/pool.py:261`、`jdec/jdec/project.py:690` 都做了平台判断 —— 说明这是漏改，不是设计。

**建议改法**：在 `engines.py` 增加单一helper（如 `def _cp_sep() -> str: return ";" if os.name == "nt" else ":"`），`classpath()` 与两处 `extra_cp` 拼接、以及 `recover.py:524` 全部改走它。注意 `recover.py` 内部已有 `sep` 概念（同函数附近），优先复用而不是再造一个。

**验收**：新增单测断言分隔符随平台切换（可在测试中 monkeypatch `os.name` 或直接断言 helper）；有条件的话在 WSL/Linux 上跑一次 `--cp-file` 路径。

---

## 2. P1：静默错误（会产出"看起来成功"的错误结果）

> 这一类比 P0 危险：不报错、不崩溃，但结果是错的。修改后**必须**做真实样本回归（§5）。

### P1-1　skill 侧指纹库大小写敏感 → 至少 3 条指纹永不命中

**现象**：`java-deobf/scripts/deobf_scan.py` 对混淆器关键词做**大小写敏感**匹配，而待匹配文本已被小写化，于是所有含大写字母的关键词成为死条目。

**证据**：

```python
# java-deobf/scripts/deobf_scan.py
523:    blob = "\n".join(list(classes.keys()) + all_strings).lower()
...
527:        hit = [k for k in keys if k in blob]        # ← 缺 .lower()
```

同文件 `:536`（`k.lower() in blob`）与 `:547`（`b.lower() in blob`）写法正确 —— 是 `:527` 漏写。

**受影响条目**（`java-deobf/scripts/fingerprints.json`）：

| 条目                               | 行          | 永不命中的关键词                                                                |
| -------------------------------- | ---------- | ----------------------------------------------------------------------- |
| BytecodeVM                       | `:255-261` | `$CodePool`                                                             |
| ZKM 27 enhanced 字符串加密（DES）       | `:22-29`   | `DES/CBC/PKCS5Padding`、`DESKeySpec`、`javax/crypto/spec/IvParameterSpec` |
| native-obfuscator (radioegor146) | `:263-269` | `nativeobfuscator/Native`                                               |

`scripts/self_test.py:49-61` 只校验 schema（keywords 非空数组），**结构上无法发现这类缺陷**。

**建议改法**：`:527` 改为 `k.lower() in blob`；并在 `self_test.py` 增加一条"关键词表不得含大写（或匹配必须大小写无关）"的断言 + 一条端到端用例（构造常量池含 `$CodePool` 的最小 class/jar，断言归因命中）。

**验收**：`python java-deobf/scripts/self_test.py` 通过；端到端用例对 `$CodePool` 命中。

### P1-2　同一份指纹库、两个消费者、两套搜索域（且文档说的是第三种）

**现象**：`fingerprints.json` 的注释声称关键词匹配"jar 内条目名**与 class 常量池字符串**"，但两个消费方各只覆盖一半：

| 消费方                                    | 搜索域                                        | 后果                                 |
| -------------------------------------- | ------------------------------------------ | ---------------------------------- |
| `jdec/jdec/probe.py:136,142,236`       | **仅 zip 条目名**（`joined = "\n".join(names)`） | 只存在于常量池的指纹（如 `DESKeySpec`）**永不命中** |
| `java-deobf/scripts/deobf_scan.py:523` | 条目名 + 常量池字符串                               | 受 P1-1 影响，大写关键词全灭                  |
| `jdec/jdec/fingerprints.json:3`        | 文档声称两者皆有                                   | 与上面两处都不符                           |

**附带的同步缺陷**：`jdec/jdec/probe.py:37-49` 优先读**包内**副本，仅当包内文件不存在才回退到 `java-deobf/scripts/fingerprints.json`。而 `java-deobf/SKILL.md:161-163` 的沉淀规程只要求改 skill 副本并跑 `self_test.py` —— 按规程操作对 jdec 主的 `probe` **静默无效**，且没有任何测试会发现两份分叉。（当前两份 303 行/36 条内容一致，属"还没分叉"而非"不会分叉"。）

**建议改法**（择一，推荐 1）：

1. 让 `probe.py` 的搜索域与 `deobf_scan.py` 对齐（probe 已在 `:274-283` 解析抽样类，顺手收集常量池字符串即可，代价低）；同时把两份 `fingerprints.json` 收敛成单一来源（打包时复制，或 probe 只读 skill 副本）。
2. 保持现状但修正 `fingerprints.json:3` 的注释，明确"jdec 侧只看条目名"，并在 `self_test.py` 加两份文件一致性校验。

**验收**：新增测试断言"两份指纹库内容一致"；`probe` 对常量池特征样本能命中。

### P1-3　重映射失败被静默吞掉，产出半改名的 jar

**现象**：`jdec/jdec/mappings.py` 的 `remap_jar` 在单个类重映射抛异常时 `pass`，该类以**原始字节、原始名字**写入输出 jar，只计入 `total` 不计入 `changed`。调用方只看到计数差，没有任何告警 —— 结果是一个"部分类已改名、部分没改"的 jar，其类名与路径不一致。

**证据**：

```python
# jdec/jdec/mappings.py:423-433
if name.endswith(".class"):
    total += 1
    try:
        new, new_name, n = remap_class_bytes(data, mapping)
        ...
    except Exception:
        pass                      # ← 失败=原样写回，无记录
```

**注意**：`new_name` 只在成功路径被使用（`if new_name:` 在同一 try 内），所以不会跨类串味 —— 问题是**静默**，不是数据污染。

**建议改法**：累计失败类名列表，结束时 `print` 汇总（并写入报告）；提供 `--strict-remap` 让调用方可选地直接失败。同一函数 `:438-439` 的 `except Exception: zout.writestr(name, data)` 兜底也建议一并记账。

**验收**：新增用例——构造一个故意损坏的 class，断言产生"1 个类未重映射"的告警/计数，而不是静默通过。

### P1-4　`devirt` 操作码解析优先级错误 → 静默错译

**现象**：`jdec/jdec/devirt.py` 的 `resolve_opcode` 在没有 `mutator_map` 时，**先**把整数当 ordinal（0..161）解释，**再**才尝试按 JVM 操作码解释。由于常见 JVM 操作码几乎都落在 0..161，第二个分支形同虚设，原始 JVM 操作码会被当成 ordinal 索引翻译。

**证据**：

```python
# jdec/jdec/devirt.py:298-304
# If mutated is an ordinal directly (0..161)
if 0 <= mutated < len(OPCS_ORDINALS):
    return OPCS_ORDINALS[mutated]
# If mutated is already a direct JVM opcode
if mutated in JVM_OPCODE_TO_NAME:
    return JVM_OPCODE_TO_NAME[mutated]
```

`OPCS_ORDINALS` 长度由 `len()` 决定（`:293,299`）；JVM 操作码取值到 0xC9(201)，因此 0..161 区间内两个解释空间**重叠**且 ordinal 永远优先。

**建议改法**：不要静默兜底 —— `mutator_map` 为 `None` 时要么 `return None`（由调用方决定），要么把解释口径显式化为参数（`mode="ordinal" | "jvm-opcode"`），并在 docstring 写明歧义。

**验收**：新增单测——传入 `0x2E`（JVM `iaload`）断言不被解析为 `OPCS_ORDINALS[46]`。

### P1-5　`pool.py` 的 verify 与 repl 解析口径不一致 → 假"零残留"

**现象**：回填阶段与校验阶段用的类名解析方式不同，**全限定调用点在校验阶段被漏检**，残留计数偏小；而残留数正是"是否报错"的判据（`pool.py:483-486` 残留 >0 直接抛错），所以会出现"校验通过、实际没回填干净"。

**证据**：

```python
# repl（回填）—— pool.py:412-415
cls_raw, meth = m.group(1), m.group(2)
cls = cls_raw.split(".")[-1]
fq = cls_raw if cls_raw in acc else simple.get(cls)     # ← 先认全限定名

# verify（校验）—— pool.py:459-463
cls, meth = m.group(1), m.group(2)
fq = simple.get(cls)                                    # ← 只看简单名
if fq is None or cls in ambiguous:
    continue
```

**建议改法**：抽出统一的 `_resolve_fq(cls_raw, acc, simple, ambiguous)`，两处共用。

**验收**：新增 fixture 含一个全限定调用点，断言 verify 能识别其为残留（修复前应漏检，修复后计数正确）。

### P1-6　`deflat` / `devirt` 主动丢弃 StackMapTable → 产出类不可验证

**现象**：两条字节码改写链都会写出**没有 StackMapTable** 的 `Code` 属性。对 class 文件版本 ≥50（Java 6+）的方法，这类输出在默认校验下会 `VerifyError` —— 即"工具报告成功，产物却跑不起来"。

**证据**：

```python
# devirt.py:876-880  —— 重建 Code 属性，子属性计数写死 0
body += ex_buf
body += struct.pack(">H", 0)  # sub-attributes count (0)

# deflat.py:727-730 —— _strip_stackmaps 的 docstring 自认"原帧全部失效（原地改写不更新帧）"
```

**建议改法**（按成本递增）：① 至少在 CLI 输出显式告警"产物不含栈映射帧，JVM 7+ 下可能无法验证"；② 提供保留/重建开关；③ 用现成的 `jdec/jdec/cfg.py` 重建帧。

**验收**：对 deflat/devirt 的产物跑 `javap -v` 确认有无 `StackMapTable`；若短期不重建，则验收标准是"告警存在且文档写明边界"。

### P1-7　归因阈值是刀刃，且 `hits` 的语义在调用方被混用

**现象 A（阈值边界）**：判据是 `conf < 0.35 → None`（`obf.py:358`），即**恰好 0.35 就点名 ZKM**。而 `goto-flood` 单条权重就是 0.35（`obf.py:49`），四个弱信号叠加 = 1 − 0.85×0.90×0.94×0.90 = **0.353**（`obf.py:53,54,55,56`）也越线。README 的表述"低于 0.35 一律不给厂商结论"字面成立，但实际是"单个指纹即可定名"。

**现象 B（`hits` 语义混用）**：`attribute()` 的 docstring 写明 `hits` 是"该指纹命中的**类数**"（`obf.py:341-348`），闸门是 `hits >= 0.10 × classes_scanned`（`:350-351`）。但 `inspect_method` 对部分指纹累加的是**出现次数**（`:197-199` `hits["handler-backjump"] = backjump`、`:213` `+= 1`），而 `probe.py:282-283` 把每类的返回值**求和**后传给 `attribute`（`probe.py:322`），分母却是抽样类数 `len(picked)`。对次数型指纹，10% 闸门因此被稀释。

**建议改法**：① 把 `:` 改 `<=` 或在文档中明确"达到 0.35 即判定"，并为"单指纹成案"加一条显式注释/测试；② 让 `inspect_method` 对每类每指纹只产出 0/1（或改名 `hits`→`occurrences` 并同步调整闸门口径）；③ `probe`/`analyze` 侧改为按类计数。

**验收**：新增两条负向用例——只有 `goto-flood` 一项命中的 jar **不得**被归因；只有四个弱信号命中的 jar **不得**被归因。（若判定维持现状，则用例改为断言"边界值行为符合文档"，并把文档写死。）

---

## 3. P2：工程与文档（逐条已核到行号）

| #     | 问题                                                                                                                                        | 位置                                                                                          | 建议                                                                  |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| P2-1  | 报错指引用户运行**不存在的** `--install-engines`（全树仅此一处出现）                                                                                            | `jdec/jdec/decompile.py:273`                                                                | 改为 `python jdec.py engines`                                         |
| P2-2  | 引擎 jar "可用性"只判 `存在 && >10KB`，截断下载被永久采信；且下载**无校验和/签名**                                                                                     | `jdec/jdec/engines.py:166`、`:171-173`                                                       | 记录并校验 SHA-256；或至少校验 jar 可被 `zipfile` 打开                             |
| P2-3  | Ghidra 包 `urlretrieve` + `extractall`，无完整性校验（~410MB）                                                                                      | `jdec/jdec/ghidra_engine.py:131,136`                                                        | 加 SHA-256 固定值校验                                                     |
| P2-4  | `_GENERIC_KEYS` **重复定义且全仓无人引用**（死代码）                                                                                                      | `jdec/jdec/obf.py:79` 与 `:103`                                                              | 删除其一；若本意是"排除出权重表"，补上使用点或删净                                          |
| P2-5  | `fingerprints.json` 的 BytecodeVM 条目仍指导用户使用**已删除的** `jdec/bvmw.py` 解码水印                                                                    | `jdec/jdec/fingerprints.json:260`                                                           | 删除该句或改为"已移除，见 skill `references/bytecode-vm.md`"                    |
| P2-6  | 括号平衡检查统计**字符串/注释里的** `{` `}` → 误扣 25 分                                                                                                    | `jdec/jdec/score.py:176-180`                                                                | 先剥离字符串字面量与注释再计数                                                     |
| P2-7  | 近分决胜用"行数多者胜"，可能偏好更啰嗦而非更准确的结果                                                                                                              | `jdec/jdec/score.py:227-234`                                                                | 改为比较 coverage/issue 数，或仅在分数完全相等时用行数                                 |
| P2-8  | 写回常量池用**标准 UTF-8**，而读取用 modified UTF-8（`decode_mutf8`）；`encode()` 对孤立代理项会抛异常                                                              | `jdec/jdec/classfile.py:236-240,258-259` vs `:69-115`                                       | 补 `encode_mutf8()` 并在写入路径统一使用（影响面：含 NUL/辅助平面字符的名字）                  |
| P2-9  | `probe` 与 `project` 的临时目录从不清理                                                                                                             | `jdec/jdec/cli.py:45-46`、`:697`（全函数内无 `rmtree`；`rmtree` 仅出现在 `:168,:607`）                   | 用 `try/finally` 清理，或复用 `--keep-work` 语义                             |
| P2-10 | `except (ClassFormatError, Exception)` —— 冗余（前者本就是后者子类）                                                                                   | `jdec/jdec/probe.py:278`                                                                    | 简化为 `except Exception`                                              |
| P2-11 | 模块 docstring 声称"DES via Windows CNG(bcrypt.dll) through ctypes"，实际走纯 Python `_des`；`import ctypes`(29) 与 `_BCRYPT_BLOCK_PADDING`(35) 是死代码 | `jdec/jdec/ops_pool.py:18` vs `:177`                                                        | 改文档 + 删死代码（**注意**：纯 Python 是有意为之的零依赖设计，不要"按文档"改回 ctypes）            |
| P2-12 | 文档路径漂移：`tests/run_tests.py`、`tests/build_fixtures.py` 已迁至 `jdec/tests/`                                                                   | `jdec/README.md:453-476`、`java-deobf/SKILL.md:178,184`                                      | 全量替换为 `jdec/tests/...`                                              |
| P2-13 | `control-flow.md` 称 `--text` 不显示 `backward_handlers`，但代码在 text 模式明打该指标                                                                    | `java-deobf/references/control-flow.md:28-29` vs `java-deobf/scripts/deobf_scan.py:756-757` | 以代码为准改文档                                                            |
| P2-14 | 提到不存在的 `jdec remap` 子命令（`remap` 仅内部模块）                                                                                                    | `java-deobf/references/string-encryption.md:106`                                            | 改为实际命令或去掉                                                           |
| P2-15 | `git-workflow.md` 引用的 `run_checks.py`、`assets/pr-description-template.md` 不存在；该 reference 本身也未被 SKILL.md 收录（孤儿文档）                         | `java-deobf/references/git-workflow.md:55,60`                                               | 两个文件可从 git `37f1647^` 取回；或删除悬空引用 / 收录进 SKILL.md                     |
| P2-16 | `.gitignore:60` 的 `jdec/tests/bvmw/_*` 指向已删除目录                                                                                            | `.gitignore:60`                                                                             | 删该行（`bvmw` 线已移除）                                                    |
| P2-17 | `study/`、`.workbuddy/` 被整目录 gitignore → 笔记零版本控制保护（`study/NOTES.md` 曾因此丢失，10-07 才从第三方 IDE 记忆库取证还原）                                         | `.gitignore:2,71`                                                                           | **需用户决策**：对 `study/*.md` 反向放行（`!study/*.md`，DMCA 敏感的源码仍忽略），或另建私有笔记仓 |


## 5. 仓库纪律（动手前必读）

1. **零第三方依赖**。jdec 是纯 Python 标准库实现（`pyproject.toml:37` `dependencies = []`）。不要引入 ASM/requests/rich 之类。
2. **不许加构建系统**。`pyproject.toml` 是 PEP 621 打包用的，不要再加 tox/Makefile/CI 之外的框架。
3. **唯一校验命令**：`python jdec/tests/run_tests.py`（当前基线 **477 passed, 0 failed**）。改完必须复跑并与基线对比。
4. **改 `jdec/jdec/classfile.py` 后必须跑 round-trip 断言**：parse→serialize 字节级一致（`jdec/tests/run_tests.py:73-101`）。这是硬约束 —— 破坏它会让重映射静默损坏所有类。
5. **判定类逻辑（指纹、阈值、评分）的修改必须做真实样本回归**，不能只用 fixture。样本在 `D:\MC\samples\`（如 `Myau0729-obf.jar`）；`JDEC_SAMPLE_DIR` 可指定目录，找不到时用例自动跳过。
6. **修工具不做顺手重构**；还原命名必须有证据。
7. **每次改动写变更报告**：按 `java-deobf/assets/change-report-template.md` 追加到 `jdec/change-report.md`，内容须含：任务目标 / 文件级变更 / 每处修改的理由 / 执行的命令与结果 / 修复轮次 / 遗留风险 / 回滚方式。
8. **skill 双写**：`java-deobf/` 有仓库副本与用户级副本，改完要同步（仓库副本为主）。
9. **真实样本与 DMCA 材料不入库**：`study/`、`jdk25/`、`.workbuddy/` 保持 gitignore。
10. **活体调试纪律**：长跑/试错全程沙箱自跑，不要拿用户当测试员；交付以产出为准，调试过程不外露。

---

## 6. 已完成 / 不要重复处理

- **`study/NOTES.md`（1766 行）与 `study/ZKM-FINAL-REPORT.md`（89 行）是 2026-10-07 取证还原的资产**。正文与原件逐字节一致（SHA-256 记录在 `.workbuddy/recovery/2026-10-07/RECOVERY.md`），前置说明块标明来源。**不要"整理格式"、不要重写正文**；如需移动位置，同时更新 `study/README.md` 与 `.workbuddy/memory/MEMORY.md` 的指针。
- **另有 40 个文件已从 git 删除但可无损恢复**（bvmw 线 27 / 旧 backend-code-writer 10 / 插桩工具 3），清单与恢复命令见 `.workbuddy/recovery/2026-10-07/RECOVERY.md` §3。回盘 `bvmw` 线涉及"去样本化"决策，**先问用户**。
- **以下是既有设计，不是 bug，别改**：
  - `decompile` 默认**不删** `_work` 目录（几千个中间文件），只有 `--clean-work` 才删 —— 这是防止误删用户数据的刻意选择；
  - 引擎对单个方法放弃 ≠ 整类失败（按放弃注释的**覆盖比例**判定，`score.py:158-173`）；
  - 大小写孪生类走 `%41.java` 百分号编码 + 按组内序号分桶（`decompile.py:143-190`）；
  - 归因宁可说"未知"也不误报厂商（`obf.py:59-61`）；
  - 归因命中率闸门 10%、权重表、`_MIN_HIT_RATIO` 等常量是**实测校准值**（`obf.py:63-86` 有 vanilla / ZKM 27 对照数据），调整前先读那段注释。

---

## 7. 建议的处理顺序

1. **P0-1 + P0-2**（半天）→ CI 转绿，跨平台可用。这两条是"其他一切验证的前提"。
2. **P1-1 + P1-2**（半天）→ 指纹库恢复有效性 + 两份副本收敛，顺手补上能发现分叉的测试。
3. **P1-3 ~ P1-7**（1~2 天）→ 静默错误。每条都必须配一条能复现原缺陷的测试。
4. **P2 批量清理**（半天）→ 文档与死代码，其中 P2-17 需用户先拍板。
5. 每完成一组，跑一次 `python jdec/tests/run_tests.py` 并把变更报告追加到 `jdec/change-report.md`。

**交付判定**：基线不回退（≥477 passed / 0 failed）、新增测试能复现原缺陷、`change-report.md` 有对应条目、跨平台路径经过实测或有明确说明。
