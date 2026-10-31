# jdec

多引擎 Java 反编译驱动：**用字节码当标准答案挑引擎**，把反混淆做在引擎之外。

CFR / Vineflower / Procyon 各自跑，按“成员名命中率”（对照 class 文件里的真实字段/
方法签名）逐类择优；控制流平坦化消除、Minecraft 符号重映射、indy 与字符串池解密
重放、native 分诊、可编译 Gradle 工程导出，都在引擎之外完成。

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

## 文档

完整能力、实测数据与设计取舍见 **[jdec/README.md](jdec/README.md)**；
未达成的边界见 [jdec/ROADMAP.md](jdec/ROADMAP.md) 与 README 的“边界”一节。
当前状态：alpha，核心回归 1095 条断言（131 个用例）全绿（`python jdec/tests/run_tests.py`）；03 专项试用版（Java 级隔离重放、两类机制、独立样本）见 [jdec/README.md](jdec/README.md)。

---

只用于分析你自己拥有或已授权的程序。
