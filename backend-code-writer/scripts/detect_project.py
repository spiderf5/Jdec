#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""探测后端项目的语言、框架、包管理器与校验命令。

输出 JSON（默认）或人类可读摘要（--text）。
仅依赖标准库，跨平台。不会执行项目里的任何命令，只做静态读取。

用法:
    python detect_project.py <项目根目录> [--text]
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------- 基础读取

def read_text(path, limit=None):
    """读取文本，失败返回空串。始终以 UTF-8 + replace 读取，避免 Windows 编码问题。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(limit) if limit else f.read()
    except OSError:
        return ""


def read_json(path):
    try:
        return json.loads(read_text(path) or "{}")
    except (ValueError, TypeError):
        return {}


def exists(root, name):
    return (root / name).is_file()


# ---------------------------------------------------------------- 栈识别

# (标记文件, 栈 id)
MARKERS = [
    ("package.json", "node"),
    ("go.mod", "go"),
    ("pyproject.toml", "python"),
    ("requirements.txt", "python"),
    ("setup.py", "python"),
    ("Pipfile", "python"),
    ("pom.xml", "java"),
    ("build.gradle", "java"),
    ("build.gradle.kts", "java"),
    ("Cargo.toml", "rust"),
    ("Gemfile", "ruby"),
]

# 栈 id -> {依赖关键词: 框架名}
FRAMEWORK_HINTS = {
    "node": {
        "express": "Express",
        "fastify": "Fastify",
        "koa": "Koa",
        "@nestjs/core": "NestJS",
        "hono": "Hono",
        "@hapi/hapi": "hapi",
        "prisma": "Prisma",
        "@prisma/client": "Prisma",
        "typeorm": "TypeORM",
        "sequelize": "Sequelize",
        "knex": "Knex",
        "drizzle-orm": "Drizzle",
        "mongoose": "Mongoose",
        "supertest": "supertest",
        "jest": "Jest",
        "vitest": "Vitest",
        "mocha": "Mocha",
    },
    "python": {
        "fastapi": "FastAPI",
        "django": "Django",
        "flask": "Flask",
        "tornado": "Tornado",
        "starlette": "Starlette",
        "sqlalchemy": "SQLAlchemy",
        "celery": "Celery",
        "pydantic": "Pydantic",
        "pytest": "pytest",
        "grpcio": "gRPC",
    },
    "go": {
        "gin-gonic/gin": "Gin",
        "labstack/echo": "Echo",
        "gofiber/fiber": "Fiber",
        "gorilla/mux": "Gorilla",
        "gorm.io/gorm": "GORM",
        "go-chi/chi": "Chi",
        "grpc": "gRPC",
    },
    "java": {
        "spring-boot": "Spring Boot",
        "springframework": "Spring",
        "quarkus": "Quarkus",
        "mybatis": "MyBatis",
        "hibernate": "Hibernate",
        "junit": "JUnit",
    },
    "rust": {
        "actix-web": "Actix Web",
        "axum": "Axum",
        "rocket": "Rocket",
        "tokio": "Tokio",
        "diesel": "Diesel",
        "sqlx": "SQLx",
    },
}


def detect_node_pm(root):
    if exists(root, "pnpm-lock.yaml") or exists(root, "pnpm-workspace.yaml"):
        return "pnpm"
    if exists(root, "bun.lockb") or exists(root, "bun.lock"):
        return "bun"
    if exists(root, "yarn.lock"):
        return "yarn"
    if exists(root, "package-lock.json"):
        return "npm"
    return "npm"


def collect_frameworks(root, stack):
    """从依赖声明里识别框架，返回去重后的名称列表。"""
    hints = FRAMEWORK_HINTS.get(stack, {})
    if not hints:
        return []
    blob = ""
    if stack == "node":
        pkg = read_json(root / "package.json")
        deps = {}
        deps.update(pkg.get("dependencies") or {})
        deps.update(pkg.get("devDependencies") or {})
        blob = " ".join(deps.keys())
    elif stack == "python":
        blob = "\n".join(
            [read_text(root / "pyproject.toml", 200000),
             read_text(root / "requirements.txt", 200000),
             read_text(root / "Pipfile", 200000)]
        ).lower()
    elif stack == "go":
        blob = read_text(root / "go.mod", 200000)
    elif stack == "java":
        for name in ("pom.xml", "build.gradle", "build.gradle.kts"):
            blob += read_text(root / name, 400000)
        blob = blob.lower()
    elif stack == "rust":
        blob = read_text(root / "Cargo.toml", 200000)

    low = blob.lower()
    found = [name for key, name in hints.items() if key.lower() in low]
    # 去重保序
    seen, out = set(), []
    for n in found:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def detect_stacks(root):
    stacks = []
    for marker, stack in MARKERS:
        if not exists(root, marker):
            continue
        entry = {
            "id": stack,
            "package_manager": detect_node_pm(root) if stack == "node" else None,
            "frameworks": collect_frameworks(root, stack),
            "evidence": [marker],
        }
        # 已存在同栈时合并 evidence
        for s in stacks:
            if s["id"] == stack:
                s["evidence"].append(marker)
                entry = None
                break
        if entry:
            stacks.append(entry)
    return stacks


# ---------------------------------------------------------------- 命令解析

# 每个校验类别的候选 script / target 名称，按优先级排列
SCRIPT_CANDIDATES = {
    "test": ["test", "test:unit", "unit", "test:ci", "spec"],
    "lint": ["lint", "lint:check", "eslint"],
    "typecheck": ["typecheck", "type-check", "check:types", "tsc", "types"],
    "build": ["build", "compile", "build:prod"],
    # 只认带 check 语义的脚本：裸 format / fmt 会直接改写文件，不能当校验命令执行
    "format": ["format:check", "fmt:check", "prettier:check", "check:format", "format:validate"],
}

ORDER = ["typecheck", "lint", "test", "build", "format"]


def parse_makefile_targets(root):
    """返回 Makefile 中定义过的目标名集合。"""
    text = read_text(root / "Makefile", 200000)
    if not text:
        return set()
    return set(re.findall(r"^([A-Za-z0-9_.-]+)\s*:", text, re.M))


def node_commands(root, pm):
    scripts = (read_json(root / "package.json").get("scripts") or {})
    out, src = {}, {}
    for category, candidates in SCRIPT_CANDIDATES.items():
        for name in candidates:
            if name in scripts:
                out[category] = "%s run %s" % (pm, name)
                src[category] = "package.json#scripts.%s" % name
                break
    # 未显式配置但有 TypeScript 时给出默认类型检查
    if "typecheck" not in out and exists(root, "tsconfig.json"):
        out["typecheck"] = "npx tsc --noEmit"
        src["typecheck"] = "默认（存在 tsconfig.json）"
    return out, src


def makefile_commands(root, targets):
    """Makefile 只覆盖 test / lint / build 三类。"""
    out, src = {}, {}
    mapping = {
        "test": ["test", "tests", "unit-test"],
        "lint": ["lint", "check"],
        "build": ["build", "compile"],
    }
    for category, candidates in mapping.items():
        for name in candidates:
            if name in targets:
                out[category] = "make %s" % name
                src[category] = "Makefile#%s" % name
                break
    return out, src


def python_commands(root, targets):
    pyproject = read_text(root / "pyproject.toml", 400000)
    out, src = {}, {}
    for category, candidates in mapping_python().items():
        for name in candidates:
            if name in targets:
                out[category] = "make %s" % name
                src[category] = "Makefile#%s" % name
                break

    has_tests = any((root / d).is_dir() for d in ("tests", "test"))
    if "test" not in out and (has_tests or "pytest" in pyproject.lower()):
        out["test"] = "pytest -q"
        src["test"] = "默认（检测到 pytest）"
    if "lint" not in out:
        if "ruff" in pyproject.lower():
            out["lint"] = "ruff check ."
            src["lint"] = "pyproject.toml#tool.ruff"
        elif exists(root, ".flake8") or "flake8" in pyproject.lower():
            out["lint"] = "flake8 ."
            src["lint"] = "默认（flake8）"
    if "typecheck" not in out:
        if "mypy" in pyproject.lower() or exists(root, "mypy.ini"):
            out["typecheck"] = "mypy ."
            src["typecheck"] = "默认（mypy）"
        elif "[tool.pyright]" in pyproject:
            out["typecheck"] = "pyright"
            src["typecheck"] = "pyproject.toml#tool.pyright"
    return out, src


def mapping_python():
    return {
        "test": ["test", "tests"],
        "lint": ["lint"],
        "typecheck": ["typecheck", "types"],
        "build": ["build"],
    }


def go_commands(root):
    out = {
        "test": "go test ./...",
        "build": "go build ./...",
        "format": "gofmt -l .",
    }
    src = {k: "默认（Go 工具链）" for k in out}
    if exists(root, ".golangci.yml") or exists(root, ".golangci.yaml"):
        out["lint"] = "golangci-lint run"
        src["lint"] = "默认（存在 .golangci.yml）"
    else:
        out["lint"] = "go vet ./..."
        src["lint"] = "默认（Go 工具链）"
    return out, src


def java_commands(root):
    if exists(root, "gradlew") or exists(root, "gradlew.bat"):
        runner = ".\\gradlew" if os.name == "nt" else "./gradlew"
        out = {"test": "%s test" % runner, "build": "%s build" % runner}
        src = {k: "gradlew" for k in out}
    else:
        if exists(root, "mvnw") or exists(root, "mvnw.cmd"):
            runner = "mvnw" if os.name == "nt" else "./mvnw"
            src_name = "mvnw"
        else:
            runner = "mvn"
            src_name = "默认（Maven）"
        out = {"test": "%s -q test" % runner, "build": "%s -q -DskipTests package" % runner}
        src = {k: src_name for k in out}
    return out, src


def rust_commands(root):
    out = {
        "test": "cargo test",
        "lint": "cargo clippy --all-targets -- -D warnings",
        "build": "cargo build",
        "format": "cargo fmt --check",
    }
    return out, {k: "默认（Cargo 工具链）" for k in out}


def ruby_commands(root):
    out = {"test": "bundle exec rspec", "lint": "bundle exec rubocop"}
    return out, {k: "默认（Ruby 工具链）" for k in out}


def resolve_commands(root, stacks, ci_cmds=None):
    """按栈解析命令：项目显式配置 > Makefile > CI 配置 > 语言默认。"""
    out, src = {}, {}
    targets = parse_makefile_targets(root)

    for stack in stacks:
        sid = stack["id"]
        if sid == "node":
            c, s = node_commands(root, stack.get("package_manager") or "npm")
        elif sid == "python":
            c, s = python_commands(root, targets)
        elif sid == "go":
            c, s = go_commands(root)
        elif sid == "java":
            c, s = java_commands(root)
        elif sid == "rust":
            c, s = rust_commands(root)
        elif sid == "ruby":
            c, s = ruby_commands(root)
        else:
            c, s = {}, {}

        for category in ORDER:
            if category in c and category not in out:
                out[category] = c[category]
                src[category] = s[category]

    # Makefile 作为跨语言兜底（仅填补仍缺失的项）
    mk, mk_src = makefile_commands(root, targets)
    for category, cmd in mk.items():
        if category not in out:
            out[category] = cmd
            src[category] = mk_src[category]

    # CI 配置兜底：这是项目在 CI 里真实执行的命令，但可能带 CI 专属上下文
    for category, (cmd, source) in (ci_cmds or {}).items():
        if category not in out:
            out[category] = cmd
            src[category] = source

    return out, src


# ---------------------------------------------------------------- 汇总

# ---------------------------------------------------------------- CI 解析

# 从 CI 命令文本判定类别，顺序即优先级（先匹配到的类别占坑）
CI_CATEGORY_RULES = [
    ("typecheck", ["tsc --noemit", "typecheck", "type-check", "check:types", "mypy", "pyright"]),
    ("format", ["prettier --check", "gofmt -l", "cargo fmt --check", "fmt --check",
                "black --check", "ruff format --check"]),
    ("lint", ["eslint", "ruff check", "golangci-lint", "rubocop", "clippy", "flake8", "pylint", "lint"]),
    ("test", ["pytest", "jest", "vitest", "mocha", "go test", "cargo test", "mvn test",
              "gradlew test", "rspec", "npm test", "pnpm test", "yarn test", "bun test",
              "npm run test", "pnpm run test"]),
    ("build", ["npm run build", "pnpm build", "yarn build", "go build", "cargo build",
               "mvn package", "gradlew build", "build"]),
]

# 含占位符的命令本地无法直接执行，直接丢弃
PLACEHOLDER_RE = re.compile(r"\$\{\{.*?\}\}|(?<![\w])\$[A-Z_]{2,}\b")


def extract_shell_commands(text, keys):
    """从 YAML 文本里提取 run / script / command 之后的命令行。

    逐行扫描，不用跨行正则：贪婪的块匹配会把后续所有缩进行（含下一个 `- name: xxx`）
    一并吞掉，导致后面的步骤根本解析不到。块语法按缩进界定结束 —— 缩进回到 key 同级或更浅即停止。
    缩进更深的 `- xxx` 是列表项（GitLab 的 `script:` 就是这种写法），要收进来而不是停下。
    """
    if isinstance(keys, str):
        keys = [keys]
    cmds = []
    lines = text.splitlines()
    key_re = re.compile(r"^(?:-\s*)?(?:" + "|".join(keys) + r"):[ \t]*(.*)$")
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        m = key_re.match(line.strip())
        if not m:
            i += 1
            continue
        rest = m.group(1).strip()
        if rest.startswith("#"):
            i += 1
            continue
        if rest and not rest.startswith(("|", ">")):
            cmds.append(rest)
            i += 1
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        i += 1
        while i < n:
            sub = lines[i]
            stripped = sub.strip()
            if not stripped:
                i += 1
                continue
            if len(sub) - len(sub.lstrip(" \t")) <= indent:
                break
            if stripped.startswith("- "):
                stripped = stripped[2:].strip()
            if stripped and not stripped.startswith("#"):
                cmds.append(stripped)
            i += 1
    return cmds


def parse_ci(root):
    """解析 CI 配置，返回 {category: (cmd, source)}。CI 命令只作为本地命令的补充来源。"""
    raw = []
    wf_dir = root / ".github" / "workflows"
    if wf_dir.is_dir():
        for f in sorted(wf_dir.glob("*.y*ml")):
            for c in extract_shell_commands(read_text(f, 400000), "run"):
                raw.append((c, "GitHub Actions#%s" % f.name))
    gl = root / ".gitlab-ci.yml"
    if gl.is_file():
        for c in extract_shell_commands(read_text(gl, 400000), ["script", "before_script"]):
            raw.append((c, "GitLab CI#.gitlab-ci.yml"))
    cc = root / ".circleci" / "config.yml"
    if cc.is_file():
        for c in extract_shell_commands(read_text(cc, 400000), "command"):
            raw.append((c, "CircleCI#config.yml"))
    jf = root / "Jenkinsfile"
    if jf.is_file():
        for m in re.finditer(r"""sh\s+["']([^"']+)["']""", read_text(jf, 400000)):
            raw.append((m.group(1), "Jenkinsfile#sh"))

    found = {}
    for cmd, source in raw:
        if PLACEHOLDER_RE.search(cmd):
            continue
        # 复合命令（&& 串联）只取第一段参与分类，避免误判
        first = re.split(r"\s*(?:&&|\|\|)\s*", cmd)[0]
        low = (first or cmd).lower()
        for category, keys in CI_CATEGORY_RULES:
            if category in found:
                continue
            if any(k in low for k in keys):
                found[category] = (cmd, source)
                break
    return found


# ---------------------------------------------------------------- monorepo

def detect_workspaces(root):
    """返回 monorepo 子包列表：[{path, name, stack}]，最多 30 个。"""
    patterns = []
    pw = read_text(root / "pnpm-workspace.yaml", 100000)
    if pw:
        for m in re.finditer(r"^\s*-\s*['\"]?([^'\"\n]+)['\"]?\s*$", pw, re.M):
            patterns.append(m.group(1).strip())
    lerna = read_json(root / "lerna.json")
    pkgs = lerna.get("packages")
    if isinstance(pkgs, list):
        patterns.extend([str(p) for p in pkgs])
    gow = read_text(root / "go.work", 100000)
    if gow:
        for m in re.finditer(r"^\s*(\./[^\s]+)\s*$", gow, re.M):
            patterns.append(m.group(1))
    sg = read_text(root / "settings.gradle", 100000)
    if sg:
        for m in re.finditer(r"""include\s*[:=]?\s*['"]([^'"]+)['"]""", sg):
            patterns.append(m.group(1).lstrip(":").replace(":", "/"))

    dirs = []
    seen = set()
    for pat in patterns:
        pat = pat.rstrip("/")
        try:
            matches = sorted(root.glob(pat))
        except (ValueError, OSError):
            continue
        for d in matches:
            if not d.is_dir():
                continue
            rel = str(d.relative_to(root)).replace("\\", "/")
            if rel in seen:
                continue
            seen.add(rel)
            sub_stacks = detect_stacks(d)
            dirs.append({
                "path": rel,
                "name": d.name,
                "stack": sub_stacks[0]["id"] if sub_stacks else None,
            })
            if len(dirs) >= 30:
                return dirs
    return dirs


# ---------------------------------------------------------------- 中间件

SERVICE_HINTS = {
    "MySQL": ["mysql", "pymysql", "mysql2", "jdbc:mysql"],
    "PostgreSQL": ["postgres", "psycopg", "pg-promise", "jdbc:postgresql"],
    "Redis": ["redis", "ioredis"],
    "Kafka": ["kafka", "kafkajs", "confluent"],
    "MongoDB": ["mongodb", "mongoose", "pymongo"],
    "RabbitMQ": ["rabbitmq", "amqplib"],
    "Elasticsearch": ["elasticsearch"],
    "ClickHouse": ["clickhouse"],
    "NATS": ["nats"],
    "gRPC": ["grpc"],
    "对象存储": ["minio", "aws-sdk", "boto3"],
}

CONFIG_FILE_NAMES = [
    "docker-compose.yml", "docker-compose.yaml", "application.yml",
    "application.properties", ".env.example", ".env.sample", "Dockerfile",
    "Makefile", "tsconfig.json", "alembic.ini", "flyway.conf",
]


def detect_services(root, stacks):
    """从依赖声明与配置文件识别数据库/中间件。返回 [{name, evidence}]。"""
    parts, scanned = [], []
    wanted = {s["id"] for s in stacks}
    markers = [m for m, st in MARKERS if st in wanted] or [m for m, _ in MARKERS]
    for marker in markers:
        p = root / marker
        if p.is_file():
            parts.append(read_text(p, 400000))
            scanned.append(marker)
    for name in ("docker-compose.yml", "docker-compose.yaml", "application.yml",
                 "application.properties", ".env.example", ".env.sample"):
        p = root / name
        if p.is_file():
            parts.append(read_text(p, 200000))
            scanned.append(name)

    blob = "\n".join(parts).lower()
    services = []
    for name, keys in SERVICE_HINTS.items():
        if any(k in blob for k in keys):
            services.append({"name": name, "evidence": ", ".join(scanned[:4]) or "依赖声明"})

    config_files = [n for n in CONFIG_FILE_NAMES if (root / n).is_file()]
    return services, config_files


TEST_DIR_NAMES = ["tests", "test", "spec", "__tests__", "src/test"]


def detect(root):
    stacks = detect_stacks(root)
    ci_cmds = parse_ci(root)
    commands, sources = resolve_commands(root, stacks, ci_cmds)
    workspaces = detect_workspaces(root)
    services, config_files = detect_services(root, stacks)

    test_dirs = [d for d in TEST_DIR_NAMES if (root / d).is_dir()]

    notes = []
    if workspaces:
        notes.append("monorepo：共 %d 个子包，改动与校验通常要在具体子包目录下进行" % len(workspaces))
    if services:
        db = [s["name"] for s in services if s["name"] in
              ("MySQL", "PostgreSQL", "MongoDB", "Redis", "ClickHouse", "Elasticsearch")]
        if db:
            notes.append("依赖外部服务 %s：跑测试前确认是否需要先启动，或使用测试替身"
                         % "/".join(db))
    if sources and any(v.startswith(("GitHub Actions", "GitLab CI", "CircleCI", "Jenkinsfile"))
                       for v in sources.values()):
        notes.append("部分命令来自 CI 配置，可能含 CI 专属上下文，本地跑不通时改用项目脚本或询问用户")
    if not stacks:
        notes.append("未识别到已知的项目标记文件，请改用用户指定的命令或人工确认技术栈")
    if not commands:
        notes.append("未解析出任何校验命令，需向用户确认测试与构建方式")

    return {
        "root": str(root),
        "git": (root / ".git").exists(),
        "stacks": stacks,
        "primary": stacks[0]["id"] if stacks else None,
        "commands": {k: commands.get(k) for k in ORDER},
        "command_sources": {k: sources.get(k) for k in ORDER if k in commands},
        "test_dirs": test_dirs,
        "workspaces": workspaces,
        "services": services,
        "config_files": config_files,
        "notes": notes,
    }


def to_text(info):
    lines = ["项目根目录: %s" % info["root"], "git 仓库: %s" % ("是" if info["git"] else "否")]
    if info["stacks"]:
        lines.append("识别栈:")
        for s in info["stacks"]:
            pm = " (%s)" % s["package_manager"] if s.get("package_manager") else ""
            fw = " 框架: %s" % ", ".join(s["frameworks"]) if s["frameworks"] else ""
            lines.append("  - %s%s  标记: %s%s" % (s["id"], pm, ", ".join(s["evidence"]), fw))
    else:
        lines.append("识别栈: 无")
    lines.append("校验命令:")
    any_cmd = False
    for k in ORDER:
        cmd = info["commands"].get(k)
        if cmd:
            any_cmd = True
            lines.append("  %-10s %-40s 来源: %s" % (k, cmd, info["command_sources"].get(k, "-")))
    if not any_cmd:
        lines.append("  （未解析到任何命令）")
    if info["test_dirs"]:
        lines.append("测试目录: %s" % ", ".join(info["test_dirs"]))
    if info.get("workspaces"):
        lines.append("子包（%d）:" % len(info["workspaces"]))
        for w in info["workspaces"][:10]:
            lines.append("  - %s%s" % (w["path"], " (%s)" % w["stack"] if w["stack"] else ""))
        if len(info["workspaces"]) > 10:
            lines.append("  ...（其余 %d 个已省略）" % (len(info["workspaces"]) - 10))
    if info.get("services"):
        lines.append("依赖服务: %s" % ", ".join(s["name"] for s in info["services"]))
    if info.get("config_files"):
        lines.append("配置文件: %s" % ", ".join(info["config_files"]))
    for n in info["notes"]:
        lines.append("提示: %s" % n)
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="探测后端项目的语言/框架/包管理器与校验命令")
    ap.add_argument("root", nargs="?", default=".", help="项目根目录，默认当前目录")
    ap.add_argument("--text", action="store_true", help="输出人类可读摘要，而非 JSON")
    args = ap.parse_args()

    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        sys.stderr.write("错误：目录不存在 -> %s\n" % root)
        return 2

    info = detect(root)
    if args.text:
        print(to_text(info))
    else:
        print(json.dumps(info, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
