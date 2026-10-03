# 后端技术栈速查

供 `detect_project.py` 探测结果存疑、或需要人工确认命令时查阅。

## 识别标记与默认命令

| 栈 | 标记文件 | 包管理器判定 | 默认校验命令 |
|---|---|---|---|
| Node / TS | `package.json` | `pnpm-lock.yaml`→pnpm，`yarn.lock`→yarn，`bun.lockb`/`bun.lock`→bun，`package-lock.json`→npm，默认 npm | test/lint/build 取 `scripts` 中同名脚本；存在 `tsconfig.json` 且无 typecheck 脚本时，typecheck 用 `npx tsc --noEmit` |
| Python | `pyproject.toml` / `requirements.txt` / `setup.py` / `Pipfile` | — | 有 `tests/` 或 pytest 配置时 `pytest -q`；ruff 配置 → `ruff check .`；mypy → `mypy .`；pyright → `pyright` |
| Go | `go.mod` | — | `go test ./...`、`go build ./...`、`gofmt -l .`；有 `.golangci.yml` 时 lint 用 `golangci-lint run`，否则 `go vet ./...` |
| Java | `pom.xml` / `build.gradle(.kts)` | Maven / Gradle | 有 `gradlew(.bat)` → `./gradlew test`、`./gradlew build`；有 `mvnw(.cmd)` → `./mvnw -q test`；否则 `mvn -q test`、`mvn -q -DskipTests package` |
| Rust | `Cargo.toml` | — | `cargo test`、`cargo clippy --all-targets -- -D warnings`、`cargo build`、`cargo fmt --check` |
| Ruby | `Gemfile` | — | `bundle exec rspec`、`bundle exec rubocop` |

命令解析优先级：**项目显式配置（package.json scripts）> Makefile target > 语言工具链默认**。
`Makefile` 只覆盖 test / lint / build 三类，且仅填补仍缺失的项。

## 探测不到的情况

出现以下情形时，脚本给出的命令不可信，必须向用户确认：

- 输出 `notes` 含「未识别到已知的项目标记文件」——目录里没有上述标记，可能是空目录或非常规布局。
- 输出 `notes` 含 monorepo 提示——校验命令通常要在具体子包目录下执行，根目录命令可能只跑聚合任务。
- `commands` 中某项为 `null`——项目未配置该类别，直接跳过，不要临时发明命令。
- 同一个仓库检出多种栈标记（例如 `package.json` 与 `pom.xml` 共存）——以实际要改的模块为准。

## 各栈的实现约定要点

写新代码前先读同级文件确认项目自身的写法；下面只是常见默认值，服从于项目既有风格。

**Node / TypeScript**
- 先确认模块体系：ESM（`import`/`export`）还是 CJS（`require`），看 `package.json` 的 `type` 字段与现有文件。
- 常见分层：`controller`（HTTP 层）→ `service`（业务）→ `repository`（数据访问）。
- 错误处理不要混用：确认项目用的是抛出自定义异常、返回 Result 对象，还是 Express 式 `next(err)`。
- 异步一律走 async/await，禁止在业务代码里用回调风格。

**Python**
- 确认虚拟环境位置与依赖安装方式（uv / poetry / pip），命令要跑在正确环境里。
- 类型注解与 Pydantic 模型：新函数签名要与现有风格一致。
- 同步 vs 异步：FastAPI 项目里混入同步阻塞调用是常见性能问题，新增 IO 代码前确认是否应为 `async def`。
- 测试用 pytest，fixture 放在 `conftest.py`，不要在每个文件里重复搭环境。

**Go**
- 错误必须返回并逐层包装（`fmt.Errorf("...: %w", err)`），不要忽略 `_ =`。
- 带取消语义的函数第一个参数是 `context.Context`。
- 表驱动测试是惯例，新增测试沿用表格风格。

**Java**
- Spring 项目按 `controller` / `service` / `repository` 分层，依赖用构造器注入。
- 事务边界放在 service 层，确认 `@Transactional` 的既有用法与传播行为。
- 测试用 JUnit，确认是 JUnit 4 还是 5（注解不同）。

**Rust**
- 用 `Result` 传播错误，库代码里避免 `unwrap()`；确认项目已用的错误类型（thiserror / anyhow）。
- `cargo clippy` 会拦截大部分风格问题，提交前必须干净。
