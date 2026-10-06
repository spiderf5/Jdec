# BytecodeVM 类虚拟化器：静态反虚拟化方法论

来源：2026-10-05/06 对 study/BytecodeVM 生成器的全量逆向（4 套 HIGH 结构
fixture 实测打通，395 静态 slot + 1713 运行时事件全部对拍）。生成器开源，
方法对闭源同构 VM（未知变体）按同路线缩减尝试面。

## 1. 识别特征

- `probe` 归因 `BytecodeVM`：类池出现 `BytecodeVM$N$CodePool`、
  `BytecodeVM$N$Frame`、`BytecodeVM$N$Program`、`Flavor$Shard$K` 家族；
- 水印：`BVMW` marker + AES-GCM capsule（key 内嵌，静态可解  
  owner/artifactId/protectedAt/inputSha256）；
- 桥接形态：原方法体替换为装箱参数 →
  `BytecodeVM$N$Integrity.$vm$integrityEntry$K(Object, Object[])`；
- 架构四味（同一生成器，派发循环模板相同，仅常量与 handler 家族不同）：
  DataFlow / Polymorphic / State(FSM) / RegisterOperation，外层各配一个
  Integrity VM（完整二级 VM，引导 + 校验）。

## 2. 数据模型（池结构）

每 CodePool 一行 = 一个被保护方法。流：OPCODE_STREAMS / OPERAND_STREAMS /
LAYOUT_STREAMS(每 slot 9 列) / BLOCK_STREAMS(4 列/块) / OPCODE_MAPS /
METHOD_KEYS / FEATURE_FLAGS / CONSTANTS / EXCEPTION_HANDLERS。

layout 9 列求解是第一道硬题：
- 4 个锚点列（state_key/block_index/pc/original_pc）用语义不变量硬绑定；
- 其余 5 列（next_pc/operand_start/operand_count/constant_mask/
  branch_selector）120 排列穷举，约束 = next⊆vpc域∪{-1}、operand 窗口、
  mask fit；**ostart/ocount 歧义取 max(ocount) 最小的解**（ostart 值域大、
  ocount 值域小）。
- **original_pc ≠ 源 pc**：降层后方法爆炸成微操作（set3 `<clinit>` 3 条
  指令 → 222 slot），orig 是降层程序内的归属指令号。验收口径改为路由
  对拍，不要试图和 javap 源指令逐条对齐。

## 3. 解码链（全部 jar 级证实）

- `v = opcodeStream[slot] ^ mix(key^sk, vpc, slot, salt_opcode)`
  ——**vpc 是 mix 的 a、slot 是 b**（slot=0 时 javap 标签歧义曾致误对调，
  用 OPCODE_MAPS 长度做 oracle 穷举排列证实）；
- `mapped = opcodeMap[v] ^ mix(methodKey, v, salt_opcode_map, 0)`（纯
  methodKey，无 stateKey）；
- `mapped` 是独立编译期 op-id 空间（非 Opcs 序号）；**语义单元 =
  (Shard 类序号, seed)**，同一 Shard 类可多实例（不同 seed 不同行为）。

## 4. 派发路由（clinit 桶注册 5 种构建变体）

`token = flags&8 ? dispatchKey(mapped) : mapped`；
`dispatchKey(x) = mix(K1, x, K2, 0)`（K1/K2 每 set 烘焙于 dispatchKey）；
`handler = BUCKETS[floorMod(token,8)].get(token)`。

clinit 注册变体（`_extract_bucket_registry` 全覆盖）：
- A：`map.put(TOKEN, new Shard$N(SEED))`
- B/FSM：`SYMBOLS.put(TOKEN, K)` + `TRANSITIONS[idx]=new Shard$N(SEED)`
  平行数组（运行时 `TRANSITIONS[floorMod(aux,4)*span+K]` 两级查表）；
- C：平行数组 `int[] tokens`/`Object[] handlers` 按 iastore/aastore 对齐；
- D：每 token 一个专属 Handler[k] 数组（`anewarray`+循环 aastore 填充后
  put 数组本身）——**运行时选槽，静态只给候选集**，校验按候选集命中。
- 校验口径：A/C 严格 (shard,seed) 1:1；D 按 token 候选集；FSM 按
  transitions 表全集 + token∈symbols。

## 5. 插桩对拍（BVMTrace）

ASM tree API 注入（COMPUTE_FRAMES 不需要：FrameNode 随指令流重定位，
纯栈中性插入帧内容不变）：
- 注入点 = `invokeinterface ...$Handler...$execute` 前；handler 局部 =
  回扫最近 `astore` 且该局部在 astore→call 间被 `aload` 重载；
- **生成器模板不变量：local 4=mapped、49=slot、62=aux62**，4 味通用；
- 运行时类零 ASM 依赖（logger 与 transformer 分类，logger 打包进产物
  jar）；TSV 无时间戳 → 逐字节确定；
- 对拍四层：程序输出（含 VM 解密 SECRET）→ mapped 100% → 路由 100%
  （1:1/候选集/FSM 表三口径）→ next_pc 执行链（pc 域值，需 pc→slot
  反查后比对；分支跳转计入 divergence）。

## 6. 工具与测试（2026-10-07 起移出产品树）

BytecodeVM 专属实现（静态反虚拟化器、水印解码器、插桩对拍工具）已从产品
代码删除——现实目标几乎不使用该混淆器，专属工具不具通用价值；方法论保留
于本 reference，可迁移至同构未知 VM（按 §1-§5 缩减尝试面）。原实现
（`jdec/bvmw.py` / `bvmw_ops.py` / `bvmw_devirt.py`、`tests/bvmw/` fixture
与对拍工具、`python jdec.py bvmw` CLI）可从 git 历史找回；验证数据与
开发日志存工作区 memory。`probe` 对 `BytecodeVM` 的归因指纹（数据驱动，
在 `fingerprints.json`）保留。

其中的通用原语已抽出并以通用形态回归产品（`run_tests.py` 有 javac
fixture 回归）：

- `jdec/jdec/jint.py` — Java 原语算术精确仿真（i32/i64 包装、>>> 无符号
  移位、rotl32、运算符优先级坑），移植任何 Java 解密器/mixer 的前置件；
- `jdec/jdec/clinit_sim.py` — clinit 建表的符号栈求值器（数组模型、
  wide 展开、valueOf 直通、hooks 机制承载保护器私有解包 API、
  unknown_ops 诚实上报不完整走查）——任何"clinit 静态建表"型保护的
  静态解包引擎。

## 7. 已知边界（2026-10-07 更新）

生成器（study/BytecodeVM）100% 逐行后关闭三项（NOTES 批次九/十/十八，
来源 = 生成器源码 InterpretContext / VMStructureGenerator / IntegrityGenerator）：

- **aux62 = STRUCTURE_STATE**——InterpretContext 官方槽位表：dispatch 循环
  内 local 4=OPCODE（对拍口径里的 "mapped"）、49=INSTRUCTION_INDEX（非
  槽号）、62=STRUCTURE_STATE（结构状态机变量，FSM 状态、DataFlow
  graphResult 均走它）；
- **FSM bucket 进静态模型**：state = floorMod(structureState, stateCount)，
  TRANSITIONS 两级查表 idx = bucket*symbolCount + K（fixture 里 9=
  symbolCount）；
- **Integrity 外壳 VM（1.1MB 二级 VM）信封代数全可逆**：`encoded =
  rotl(cap ^ xorMask, rotation) * oddM + addend`（multiplier 强制奇数，
  inverseOdd 牛顿迭代逆元），`envelope = encoded<<32 | (tag<<1|1)`；
  hashResource 自实现可复算，布局常量全部 emitted 进 VM 代码——"不是
  不能拆，是还没拆"，可复用同一套 17 结构工具链。

仍开放：

- handler 的 operand/constant 解密公式已定位（opnd ^ mix(..., vpc, opIdx,
  salt^pos)，arg4 经 lambda 适配层）但未逐 seed 语义化（每个 (Shard,seed)
  的算术行为需执行级 trace 才能命名）。
