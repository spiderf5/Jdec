# BytecodeVM 静态反虚拟化 — 6 阶段收官报告

对象：`tests/bvmw/calc-bytecodevm.jar`（study/BytecodeVM 生成器产物，
98 类 / 4 被保护方法 / 4 套 HIGH 结构 VM）。水印 owner=jdec-study。

## 成绩单

| 阶段 | 内容 | 验收 | commit |
|------|------|------|--------|
| 0 资产入库 | fixture jar、mix Java 真值 1048 向量、原版 calc.jar | golden 对拍基线建立 | a317634 |
| 1 字节码级提取器 | bvmw_devirt：池提取 + profile（salts/layout 求解） | 运行时 FieldDump 全字段 44/44 | f3a5674 |
| 2 全静态解码+CLI | decode 全链 + 路由 5 变体 + `jdec.py bvmw` | 4 set 395 slot 全路由 unrouted=0 | eb4cca0 |
| 3 插桩对拍 | BVMTrace：ASM 注入 + 运行时 trace 对拍静态 | 1713/1713 事件命中；输出 3/3 | 13d23d4 |
| 4 定性+链路 | natives triage：0 库 / 0 native 方法 | 纯 Java 定性；Ghidra/nativedb 为 native 变体预备（nativedb 已在 JNIC 真库验收） | 本提交 |
| 5 测试/文档 | 基线 392→410；skill 方法论沉淀 | run_tests 全绿；skill 双写 + self_test | 本提交 |

## 架构结论

1. **4 set = 4 味 VM**（同一生成器模板，派发循环逐指令同构，仅常量与
   handler 家族不同）：set0 DataFlow、set1 Polymorphic、set2 State(FSM)、
   set3 RegisterOperation。跨味硬不变量：dispatch 循环内
   local 4=mapped、49=slot、62=aux62。
2. **双层结构**：内层 VM（被保护方法语义）+ 每 set 一个 Integrity VM
   （1.1MB 完整二级 VM：引导/校验层）。桥接 =
   `Integrity.$vm$integrityEntry$K(Object, Object[])`。
3. **解码链**（jar 级证实，端到端 token→clinit 桶键逐一命中）：
   `v = opcodeStream[slot] ^ mix(key^sk, vpc, slot, salt_opcode)`
   → `mapped = opcodeMap[v] ^ mix(methodKey, v, salt_opcode_map, 0)`
   → `token = flags&8 ? dispatchKey(mapped) : mapped`，
   dispatchKey(x)=mix(K1,x,K2,0)，K1/K2 每 set 烘焙。
4. **语义单元 = (Shard 类序号, semanticToken)**：mapped 是独立编译期
   op-id 空间；Shard$N 类可多实例（seed 决定行为变体）。
5. **clinit 注册 5 种构建变体**（解析器全覆盖）：
   A map.put(token, Shard) / B-FSM 两级查表（SYMBOLS token→K +
   TRANSITIONS[36] 平坦数组，运行时 idx=floorMod(aux,4)*9+K）/
   C 平行数组对齐 / D 每 token 专属 Handler[k] 数组（运行时选槽 →
   静态给候选集）/ E 遗留形态。
6. **original_pc ≠ 源指令号**：降层把方法爆炸成微操作（`<clinit>` 3 条
   指令 → 222 slot）；orig 是降层程序内归属 pc。对拍口径 = 路由 +
   mapped + 执行链，不与源 javap 逐条对齐。

## 对拍数字（阶段3）

- 事件 1713（set0 add=29 / set1 greet=602 / set2 mix=5 / set3 clinit=1077）
- mapped 命中 1713/1713；路由命中 1713/1713
  （严格 1:1 1106 + token 数组候选集 602 + FSM transitions 表 5）
- next_pc 执行链：1634 步吻合 + 75 分支/循环跳转（pc 域反查后比对）
- 程序输出：add(2,3)=16；greet="Hello, world! from alpha-beta-gamma"
  （SECRET 由 VM 行 3 运行时解密）；mix=LCG 位级复算一致。

## 已知边界（后续方向）

- aux62（循环常量 int）语义未定；FSM 运行时 bucket 选择函数已从 javap
  人工确认（floorMod(aux,4)）但未进静态模型。
- Integrity 外壳 VM 未反虚拟化（引导/校验层；需要时复用同路线）。
- per-(Shard,seed) 算术语义命名（ADD/XOR/…）需执行级操作数 trace，
  属阶段3 框架的自然扩展。
- Ghidra 引擎二进制未落地（GitHub 直连限速 16min≈140KB；镜像实测
  ~12KB/s 不可用）。本 fixture 无 native 对象，不影响结论；未来遇到
  native 化变体时 `python jdec.py engines --with-ghidra` 或手动放置。

## 复用入口

```
python jdec.py bvmw X.jar          # 静态反虚拟化报告
python tests/bvmw/verify_extract.py
python tests/bvmw/compare_dump.py
python tests/bvmw/bvmtrace/run_bvmtrace.py
```
方法论文档：java-deobf skill `references/bytecode-vm.md`。
