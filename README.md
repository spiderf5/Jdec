# jdec

多引擎 Java 反编译驱动：**用字节码当标准答案挑引擎**，把反混淆做在引擎之外。

CFR / Vineflower / Procyon 各自跑，按“成员名命中率”（对照 class 文件里的真实字段/
方法签名）逐类择优；控制流平坦化消除、Minecraft 符号重映射、indy 与字符串池解密
重放、native 分诊、可编译 Gradle 工程导出，都在引擎之外完成。

## 文档

本页是短概览，同时也是 PyPI 的项目说明。**完整手册与路线图在仓库的 `docs/`
目录**，以下链接均可直接打开（`HEAD` 跟随默认分支，改名也不会失效）：

| 文档 | 内容 |
| --- | --- |
| **[完整手册](https://github.com/spiderf5/Jdec/blob/HEAD/docs/README.md)** | 全部能力、实测数据与设计取舍（约 50 KB 长文） |
| **[路线图](https://github.com/spiderf5/Jdec/blob/HEAD/docs/ROADMAP.md)** | 01–04 阶段状态、未达成的边界与硬门槛 |
| [04 支持矩阵](https://github.com/spiderf5/Jdec/blob/HEAD/docs/SUPPORT_MATRIX.md) | 8 类机制、87 项交叉检查与保留边界 |
| [复现说明](https://github.com/spiderf5/Jdec/blob/HEAD/docs/REPRODUCE.md) | 头条数字的逐字口径、内置生成式基准与 83.0% 口径 |
| [02 可达性](https://github.com/spiderf5/Jdec/blob/HEAD/docs/REACHABILITY_02.md) | 剩余 195 个 inconclusive 的 API 级归因 |
| [离线交付](https://github.com/spiderf5/Jdec/blob/HEAD/docs/OFFLINE.md) | 离线引擎包与断网 CI 门禁 |

## 快速开始

需要 JDK 9+。`java` / `javac` 按 `JAVA_HOME` → `PATH` → 常见安装目录查找，
所以“JDK 装在 D:\java21、只配 JAVA_HOME”也能直接用：

```bash
python jdec.py engines                  # 下载三个反编译引擎（带 sha1 校验）
python jdec.py probe client.jar         # 先看对面是什么，不反编译
python jdec.py decompile client.jar -o out
python jdec.py auto client.jar -o out --web
python jdec.py ircheck client.jar       # 改写底座门禁：解析→重汇编→逐字节比对
python jdec.py verify client.jar        # JVM 门禁：每个类都要过 -Xverify:all
```

退出码：0 成功 / 1 部分成功 / 2 失败。`decompile` 按**还原结果**判定（全失败或没有可用引擎 / java → 2）；
`auto` 按**阶段状态**判定（任一阶段 failed → 2）。

## 发布内容

`pip install` 只装 `jdec` 包：运行时代码、模板、指纹表、web 资源，以及 04
验收链（`python -m jdec.stage04` / `jdec.support_matrix`）。装了包的人可以在
自己的语料上复跑验收，判据实现 `jdec.goldens` 随包提供但**不 import 任何
分析模块**。**wheel 里没有任何测试素材、样本 jar 或第三方引擎 jar**：回归套件
与夹具只属于源码仓库；引擎由 `jdec engines` 按 sha1 校验后下载到缓存，也可走
离线引擎包。CI 的 wheel-smoke 解包检查两侧边界，并在干净 venv 里验证验收模块
确实可导入。

验收链产出的是检查结论，**不是阶段判定**：04 的状态由 `docs/ROADMAP.md` 记录，
运行器不自称门槛达成。完整验收需自备外置授权语料；`--selfcheck` 是仓库内模式。

当前状态：alpha，核心回归 **1302 条断言 / 152 个用例**全绿
（`python src/tests/run_tests.py`）。测试素材与回归套件仅存在于源码仓库。

---

只用于分析你自己拥有或已授权的程序。
