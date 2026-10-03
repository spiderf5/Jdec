#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""按探测结果执行项目的校验命令（typecheck / lint / test / build / format）。

只执行 detect_project.py 从项目配置中解析出的命令，以及用户通过 --extra 显式传入的命令。
失败时提取关键错误上下文输出，避免整段日志刷屏。

用法:
    python run_checks.py <项目根目录> [--only test,lint] [--timeout 300] [--extra "go vet ./pkg/foo"]

退出码: 0 = 全部通过或跳过；1 = 存在失败；2 = 参数或环境错误。
"""

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import detect_project  # noqa: E402

ORDER = detect_project.ORDER

# 提取错误上下文时关注的关键字（小写匹配）
ERROR_PATTERNS = [
    "error", "failed", "failure", "fatal", "panic:", "traceback",
    "exception", "assert", "undefined is not", "cannot read",
    "compilation error", "✕", "✗", "×", "错误", "失败", "异常",
]

MAX_ERROR_LINES = 30
TAIL_LINES = 40
CONTEXT = 2

# 失败分类规则，顺序即优先级
CLASSIFY_RULES = [
    ("missing_tool", ["command not found", "不是内部或外部命令", "is not recognized",
                      "no such file or directory", "无法启动命令", "not found:"]),
    ("compile_error", ["error ts", "syntaxerror", "compilation error", "cannot find name",
                       "type error", "syntax error", "解析错误"]),
    ("test_failure", ["assertionerror", "expected", "✕", "✗", "failed test", "test failed",
                      "assert", "failing tests", "断言"]),
    ("environment", ["econnrefused", "connection refused", "could not connect",
                     "unable to connect", "timeout connecting", "no connection could be made"]),
    ("lint_violation", ["eslint", "ruff", "golangci", "clippy", "rubocop", "flake8", "lint"]),
    ("build_error", ["build failed", "failed to compile", "cannot find module",
                     "module not found", "unresolved reference"]),
]

SUGGESTIONS = {
    "compile_error": "类型或语法不匹配。检查调用处与定义签名，修调用方；禁止用 any / @ts-ignore / # type: ignore 绕过",
    "test_failure": "先判断是测试期望过时还是实现有 bug。禁止改断言或加 skip；确属测试写错时在报告中单独说明",
    "missing_tool": "工具未安装或不在 PATH。确认包管理器与依赖是否已装好，不要临时换成别的工具",
    "lint_violation": "按规则提示修正代码；若判定是规则配置过严，在报告中提出，不要用行内禁用注释绕过",
    "build_error": "从第一个错误看起，多为导入路径、缺失依赖或编译配置问题",
    "environment": "依赖的外部服务（数据库/缓存/队列）未启动。先起服务或改用测试替身，不要改代码去适配缺失环境",
    "timeout": "可能死循环、网络等待或测试集过大。先定位卡在哪一条，再决定优化或拆分",
    "unknown": "读第一条错误行，回溯到状态第一次变错的位置（见 references/debug-playbook.md）",
}


def classify(name, error_text, status):
    """把一次失败归类，便于给出针对性的下一步。"""
    if status == "timeout":
        return "timeout"
    text = (error_text or "").lower()
    if re.search(r"\bts\d{4}\b", text):
        return "compile_error"
    for category, keys in CLASSIFY_RULES:
        if any(k in text for k in keys):
            return category
    fallback = {
        "typecheck": "compile_error",
        "lint": "lint_violation",
        "format": "lint_violation",
        "test": "test_failure",
        "build": "build_error",
    }
    return fallback.get(name, "unknown")


def decode_output(data):
    """解码命令输出。

    Windows 中文环境里 cmd 的报错是 GBK 编码，按 UTF-8 解会得到一片替换字符，
    导致「不是内部或外部命令」这类关键中文提示匹配不到。两种编码都试，取替换字符少的。
    """
    if not data:
        return ""
    text = data.decode("utf-8", errors="replace")
    if "\ufffd" not in text:
        return text
    alt = data.decode("cp936", errors="replace")
    return alt if alt.count("\ufffd") < text.count("\ufffd") else text


def run_one(cmd, root, timeout):
    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            cwd=str(root),
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "exit_code": None,
            "duration": round(time.time() - started, 2),
            "errors": ["命令超过 %s 秒未完成，已终止" % timeout],
            "tail": [],
        }
    except OSError as exc:
        return {
            "status": "fail",
            "exit_code": None,
            "duration": round(time.time() - started, 2),
            "errors": ["无法启动命令: %s" % exc],
            "tail": [],
        }

    output = decode_output(proc.stdout)
    if proc.stderr:
        output += "\n" + decode_output(proc.stderr)
    lines = output.splitlines()
    return {
        "status": "pass" if proc.returncode == 0 else "fail",
        "exit_code": proc.returncode,
        "duration": round(time.time() - started, 2),
        "errors": extract_errors(lines) if proc.returncode != 0 else [],
        "tail": lines[-TAIL_LINES:],
    }


def is_error_line(line):
    low = line.lower()
    if not line.strip():
        return False
    # 排除常见误报
    if "0 error" in low or "no error" in low or "error: 0" in low:
        return False
    return any(p in low for p in ERROR_PATTERNS)


def extract_errors(lines):
    """抽取错误行及其上下若干行上下文，去重后截断。"""
    picked = set()
    for i, line in enumerate(lines):
        if is_error_line(line):
            for j in range(max(0, i - CONTEXT), min(len(lines), i + CONTEXT + 1)):
                picked.add(j)
    out = [lines[i] for i in sorted(picked)]
    if len(out) > MAX_ERROR_LINES:
        out = out[:MAX_ERROR_LINES] + ["...（共 %d 行错误上下文，已截断）" % len(picked)]
    return out


def to_text(results):
    lines = []
    for r in results:
        head = "[%s] %-10s %s" % (r["status"].upper(), r["name"], r["cmd"])
        lines.append(head)
        if r["status"] == "skipped":
            lines.append("    （未配置，已跳过）")
            continue
        lines.append("    退出码 %s，耗时 %.2fs" % (r["exit_code"], r["duration"]))
        if r["errors"]:
            lines.append("    关键错误:")
            for e in r["errors"]:
                lines.append("      | %s" % e)
        if r["status"] in ("fail", "timeout") and r.get("classification"):
            lines.append("    诊断: %s" % r["classification"])
            if r.get("suggestion"):
                lines.append("    建议: %s" % r["suggestion"])
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="执行项目校验命令并返回结构化结果")
    ap.add_argument("root", nargs="?", default=".", help="项目根目录，默认当前目录")
    ap.add_argument("--only", default="", help="只执行指定检查，逗号分隔，如 test,lint")
    ap.add_argument("--timeout", type=int, default=300, help="单条命令超时秒数，默认 300")
    ap.add_argument("--extra", action="append", default=[], help="额外执行的命令，可重复传入")
    ap.add_argument("--skip-missing", action="store_true", default=True, help="跳过项目未配置的检查（默认开启）")
    ap.add_argument("--fail-fast", action="store_true", help="遇到第一个失败就停止后续检查")
    ap.add_argument("--text", action="store_true", help="输出人类可读摘要，而非 JSON")
    args = ap.parse_args()

    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        sys.stderr.write("错误：目录不存在 -> %s\n" % root)
        return 2

    info = detect_project.detect(root)
    commands = info["commands"]
    sources = info["command_sources"]

    names = [n.strip() for n in args.only.split(",") if n.strip()] or list(ORDER)
    unknown = [n for n in names if n not in ORDER]
    if unknown:
        sys.stderr.write("错误：未知检查项 %s，可选值 %s\n" % (unknown, ORDER))
        return 2

    results = []
    stopped_early = False
    for name in names:
        cmd = commands.get(name)
        if not cmd:
            results.append({
                "name": name, "cmd": None, "status": "skipped", "source": None,
                "exit_code": None, "duration": 0, "errors": [], "tail": [],
            })
            continue
        r = run_one(cmd, root, args.timeout)
        r["name"] = name
        r["cmd"] = cmd
        r["source"] = sources.get(name, "-")
        results.append(r)
        if args.fail_fast and r["status"] in ("fail", "timeout"):
            stopped_early = True
            break

    if not stopped_early:
        for i, extra in enumerate(args.extra):
            r = run_one(extra, root, args.timeout)
            r["name"] = "extra-%d" % (i + 1)
            r["cmd"] = extra
            r["source"] = "用户指定"
            results.append(r)
            if args.fail_fast and r["status"] in ("fail", "timeout"):
                break

    for r in results:
        if r["status"] in ("fail", "timeout"):
            err_text = "\n".join(r.get("errors") or r.get("tail") or [])
            r["classification"] = classify(r["name"], err_text, r["status"])
            r["suggestion"] = SUGGESTIONS.get(r["classification"], "")

    summary = {
        "root": str(root),
        "primary": info["primary"],
        "passed": [r["name"] for r in results if r["status"] == "pass"],
        "failed": [r["name"] for r in results if r["status"] in ("fail", "timeout")],
        "skipped": [r["name"] for r in results if r["status"] == "skipped"],
        "failures": [{"name": r["name"], "classification": r["classification"],
                      "suggestion": r["suggestion"]}
                     for r in results if r["status"] in ("fail", "timeout")],
        "results": results,
    }

    if args.text:
        print(to_text(results))
        print("\n通过: %s | 失败: %s | 跳过: %s"
              % (summary["passed"] or "无", summary["failed"] or "无", summary["skipped"] or "无"))
    else:
        print(json.dumps(summary, ensure_ascii=False, indent=2))

    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
