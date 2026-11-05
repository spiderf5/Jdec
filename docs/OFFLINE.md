# 离线交付

04 的两项交付之一。按 2026-11-04 拍板，采用**离线引擎包 + 断网 CI 门禁**：
第三方引擎 jar **不进 wheel**（再分发许可、体积，以及 wheel-smoke 里
「引擎缓存不得落在 site-packages」的断言都不允许），也不入库
（`.gitignore` 忽略 `src/engines/*.jar`，`git ls-files '*.jar'` 恒为空）。

## 为什么需要一层

`pip install jdec-*.whl` 装出来的包**不含**任何反编译引擎
（`pyproject.toml` 的 `package-data` 没有 `*.jar`）。首次运行 `decompile` /
`auto` 时，`engines.ensure_engines()` 会从 Maven Central 拉 4 个 jar：
CFR 0.152、Vineflower 1.11.1、Procyon compilertools/core 0.6.0。
运行期 Python 依赖为 0，但引擎仍是一次独立的网络获取。

代码里本来就有「已存在且 sha1 匹配即跳过下载」的缓存逻辑，本交付把它
包装成可生成、可校验、可断网验证的产品路径。

## 生成离线包（一次性，在有网机器上）

```bash
python scripts/verify_engine_bundle.py --build /path/to/jdec-engines
python scripts/verify_engine_bundle.py --build /path/to/jdec-engines \
    --zip /path/to/jdec-engines.zip

# 内网镜像
python scripts/verify_engine_bundle.py --build /path/to/jdec-engines \
    --mirror https://mirror.internal/maven2
# 或设置 JDEC_MAVEN_MIRROR 环境变量
```

`--build` 调用常规下载器，每个 jar 都按 `engines.py` 里硬编码的 sha1 校验，
写入 `ENGINES.json`（文件名、sha1、size、Maven 坐标、再分发提示）。
`--zip` 额外打一个压缩包。产物放在**仓库外**，不 commit。

## 在离线机器上安装

wheel 安装后，引擎目录由 `toolchain.default_engines_dir()` 决定：源码检出用
`src/engines/`，wheel 安装用每用户缓存
（Windows `%LOCALAPPDATA%/jdec/engines`，Linux `$XDG_CACHE_HOME/jdec/engines`，
macOS `~/Library/Caches/jdec/engines`）。**绝不写 site-packages**。

```bash
# 只校验，不安装（纯本地，不开 socket）
jdec engines --verify-only --from-dir /path/to/jdec-engines --json report.json

# 从离线包安装到默认引擎目录
jdec --engines-dir <每用户缓存> engines --offline --from-dir /path/to/jdec-engines

# 或者让 JDEC_OFFLINE 对所有调用点生效（decompile / pipeline / scorecard）
export JDEC_OFFLINE=1
export JDEC_ENGINES_DIR=/path/to/jdec-engines
jdec ircheck target.jar
```

注意 `--engines-dir` 是**顶层参数**，要放在子命令之前。

环境变量：

| 变量 | 作用 |
| --- | --- |
| `JDEC_OFFLINE=1` | `ensure_engines()` 完全不 import `urllib`、不发请求；缺失即记入 missing |
| `JDEC_ENGINES_DIR` | 覆盖默认引擎目录（wheel 安装时仍不得指向 site-packages） |
| `JDEC_MAVEN_MIRROR` | `--build`/在线下载时替换 Maven 基址 |

`--offline` 与 `--with-ghidra` 同时给会**显式报错退出 2**，不会静默跳过或下载。

## 完整性

`engines.available()` 只查文件大小和 zip 中央目录，**不查 sha1**。
`engines.verify_bundle()` 与 `--verify-only` 会逐个校验 sha1 + size + zip 目录，
返回 `ok / missing / mismatch / corrupt`；任何一个不是 `ok` 就退出 1。
离线安装时若目标目录里已有 sha1 不符的 jar，会先删掉再从包里复制，
避免 `available()` 把被篡改的 jar 误判为可用。

改一个字节的负控：

```bash
python scripts/verify_engine_bundle.py --verify /path/to/bundle   # 0
printf x >> /path/to/bundle/cfr-0.152.jar
python scripts/verify_engine_bundle.py --verify /path/to/bundle   # 1, mismatch
```

## Ghidra 不在离线包内

Ghidra Headless 是第四个、独立下载的引擎（`ghidra_engine.py` 有自己的
`GHIDRA_RELEASE_URL` 与 sha256 覆盖），体积与许可都不同，不纳入这 4 个 jar
的离线包。`jdec engines --with-ghidra` 在离线模式下直接拒绝。

## CI 门禁

`.github/workflows/ci.yml` 的 `offline-smoke` job 分两段：

1. **准备段（允许联网一次）**：装 wheel 到干净 venv，
   `verify_engine_bundle.py --build` 生成离线包，`--verify` 校验。
2. **断网段**：`HTTP_PROXY` / `HTTPS_PROXY` 指向 `http://127.0.0.1:9`、
   `NO_PROXY=""`、`JDEC_OFFLINE=1`，然后
   `jdec engines --offline --from-dir ...` → 三条 `grep available` →
   `test ! -d <venv>/.../site-packages/engines` →
   `jdec ircheck src/tests/flow.jar` + `jdec verify src/tests/flow.jar`。

用 `flow.jar` 而不是 `sample.jar`：后者故意塞了截断类，会让门禁报
PARTIAL / INVALID。断网段不跑整套 `run_tests.py`（它的 `_prepare_engines()`
会联网），也不带任何外置授权样本。

## 边界

- 这是「**无需公网即可获得并校验全部反编译引擎**」的交付，不是
  「整个工具链零网络」：`setup-python` / `setup-java` / pip 构建隔离仍联网，
  映射表下载、Ghidra 下载也各自独立。
- 离线包本身**不构成 04 门槛的验证**：证据等级由
  `docs/SUPPORT_MATRIX.md` 的 8 类支持项与双独立语料回归提供。
  04 状态列已撤回达标声明、退回「进行中」；离线交付是已交付的一项，
  不是门槛验收。
- 再分发离线包前请自行核对三个引擎各自的许可证；本仓库不代为授权。
