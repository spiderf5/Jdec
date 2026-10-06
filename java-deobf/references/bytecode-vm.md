# BytecodeVM 类虚拟化器：静态反虚拟化方法论

来源：2026-10-05/06 对 study/BytecodeVM 生成器的全量逆向（4 套 HIGH 结构
fixture 实测打通，395 静态 slot + 1713 运行时事件全部对拍）。生成器开源，
方法对闭源同构 VM（未知变体）按同路线缩减尝试面。

## 1. 识别特征

- `probe` 归因 `BytecodeVM`：类池出现 `BytecodeVM$N$CodePool`、
  `BytecodeVM$N$Frame`、`BytecodeVM$N$Program`、`Flavor$Shard$K` 家族；
- 水印：`BVMW` marker + AES-GCM capsule（`jdec/bvmw.py` 静态解码
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

## 6. CLI 与测试

```
python jdec.py bvmw X.jar [-v] [--top N]   # 每 set salts/layout/routing/直方图
python tests/bvmw/verify_extract.py        # 阶段1/2 验收（含 unrouted==0）
python tests/bvmw/compare_dump.py          # golden 运行时 FieldDump 对拍
python tests/bvmw/bvmtrace/run_bvmtrace.py # 阶段3 插桩对拍（需 javac+ASM）
```

run_tests.py：`test_bvmw_devirt`（纯静态）+ `test_bvmw_trace`
（缺 javac/ASM 自动 skip）。

## 7. 已知边界

- aux62（scheduleReadyNode arg4，循环内常量）语义未定（疑 integrity/XXH
  nonce）；FSM 的运行时 bucket 选择函数已从 javap 人工确认但未进静态
  模型；
- Integrity 外壳 VM（1.1MB 完整二级 VM）未反虚拟化——引导/校验层，方法
  语义在内层 VM；需要时可复用同一路线；
- handler 的 operand/constant 解密公式已定位（opnd ^ mix(..., vpc, opIdx,
  salt^pos)，arg4 经 lambda 适配层）但未逐 seed 语义化（每个 (Shard,seed)
  的算术行为需执行级 trace 才能命名）。
