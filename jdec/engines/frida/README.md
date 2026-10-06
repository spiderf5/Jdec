# engines/frida — native 方法运行时捕获（tap 的 native 姊妹篇）

对 JNIC / MyJ2C / radioegor146 native-obfuscator / PhantomShield 系"字节码→C"  
保护产物做运行时捕获：RegisterNatives 全表 dump + JNI 调用面 trace +  
trace→伪 Java 回填。**不依赖 frida-java-bridge**（现代 JDK 上它因缺少  
Hotspot 内部符号拒绝初始化）。

## 文件

| 文件                     | 作用                                                                                                                                 |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `regnatives.js`        | hook JNIEnv 表槽位 215（RegisterNatives），dump 类名+方法名+签名+函数指针全表                                                                         |
| `jnitrace.js`          | trace 槽位 6/33/94/113/167/169（FindClass/GetMethodID/GetFieldID/GetStaticMethodID/NewStringUTF/GetStringUTFChars）= native 方法的"IO 骨架" |
| `dump_mappings.py`     | 启动目标 + 注入 + 采集 → TSV                                                                                                               |
| `trace2java.py`        | trace TSV → 伪 Java（FindClass→Class.forName、NewStringUTF→const-string…）                                                             |
| `HarnessTemplate.java` | ENTER/EXIT 打点模板（按方法切 trace 段）                                                                                                      |

## 用法

```bash
# 1) RegisterNatives 全表（方法 ↔ native 地址 的 Rosetta Stone）
python dump_mappings.py --java "<jdk>/bin/java.exe" --script regnatives.js \
    --out mappings.tsv --timeout 25 -- -jar target.jar

# 2) JNI 调用面 trace
python dump_mappings.py --java "<jdk>/bin/java.exe" --script jnitrace.js \
    --jni-out trace.tsv --timeout 25 -- -jar target.jar

# 3) 回填
python trace2java.py trace.tsv -o pseudo_java.txt
```

## 环境要求 / 已知坑（全部实测，2026-10-05）

- **frida 16.x / 17.x 均可**。脚本不用 frida-java-bridge（现代 JDK 上它  
  因缺少 Hotspot 内部符号拒绝初始化），直接 raw 访问 JNIEnv 表槽位，  
  内存读写用方法式 API（`ptr.readByteArray()`），16/17 双兼容；  
  17.x 移除的全局 `Memory.read*`、回调式枚举、内置 bridge 均未使用。  
  实测基线：`pip install "frida==16.7.19" "frida-tools==13.7.1"`（清华镜像）；  
  换 17.x（配 frida-tools 14+）后 attach 时序类经验值建议重测。
- **现代 JDK launcher 单进程跑 JVM**（实测 Zulu 21：全程只有一个 java.exe），  
  但 **JS 定时器（setInterval）在此类目标里从不触发**——脚本一律通过  
  `rpc.exports.tryinstall()` 由 python 侧泵驱动，禁止依赖 JS 定时器。
- **指针纪律（连环 AV 的根源）**：`AttachCurrentThread` 写出的 `env`  
  是"指向每线程 JNIEnv 变量"的指针，函数表要再解一层 `env.readPointer()`；  
  JNI 函数第一个参数用 `env`（不是表指针）。VM 启动中途 jvm.dll 已映射但  
  VM 对象半初始化——acquireEnv 全防御化，任何怀疑返回 null 下一轮重试。
- 目标存活窗口可能只有 ~2s（如 JNIC 引擎无 Zig 即退出），热循环只 pump  
  已知 pid（~20ms 节奏），重量级 enumerate_processes 降到 0.5s 一次。
- env 里看到的 `$(jar 名).dat` 内嵌 native payload 是加密压缩的（高熵无  
  magic），静态解需读 loader 算法；运行时侧 loader 会解压——需要 DLL 时  
  优先考虑 hook 文件写入/内存 dump（待办）。
