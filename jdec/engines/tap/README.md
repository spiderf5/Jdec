# engines/tap — 运行时字符串捕获（"盯出口"路线）

原则：强混淆（如 ZKM 27 的 indy 引导 session key → 常量折叠引擎 → DES
三层链）静态还原逐版本易变；让混淆器自己的代码跑解密，只在明文出口捕获。
配套方法论：skill `references/string-encryption.md`（形态分型）、
`references/dynamic-analysis.md`（捕获阶梯、毒类桩化规则、红线）。

## 工具

| 文件 | 作用 |
|---|---|
| `scan_targets.py` | 常量池静态分类：`decryptor` / `dangerous` / `encrypted` / 跳过——纯静态一遍，先分批再执行 |
| `tap_extract.py` | 解码指令流，抽取每个解密调用点的硬编码参数 → `calls.tsv` |
| `Reflect.java` | 同 JVM 内按类分组重放：`getDeclaredMethod` + `invoke`，逐条落盘 |
| `StringsSpy.java`（`manifest.txt`） | javaagent：retransform `Cipher.doFinal`，append-on-record 记录明文（native 崩溃不丢已捕获数据） |
| `StringTap.java` | 追加 `new String(byte[])` 出口钩子 |
| `CipherTap.java` | 手写字节码重写版 Cipher 插桩（retransform 不可用时的降级路径） |
| `Step.java` | 逐类初始化驱动：按 `Class.forName` 时序把明文归属到产生它的类 |
| `quality_check.py` | 明文质量三档定性（自然词 / Java 词 / 乱码） |

## 使用顺序

1. `scan_targets.py` 分批 → 2. `tap_extract.py` 出调用点参数 →
3. `Reflect.java`（或 `Step.java` + `stringspy.jar`）跑重放/捕获 →
4. `quality_check.py` 定性。

更深层的手段（毒类桩化 agent、反射名映射表撞表、真环境倾倒 agent）与
目标强绑定，按个案适配，不入库；方法论见上，历史实现可从 git 历史找回。
