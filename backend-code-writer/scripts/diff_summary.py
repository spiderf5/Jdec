#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""统计工作区的代码变更，供变更报告使用。

git 仓库：基于 git status + git diff --numstat 统计每个文件的状态与增删行数。
非 git 目录：按文件修改时间扫描最近变动的源码文件（--recent，单位分钟）。

用法:
    python diff_summary.py <项目根目录> [--text] [--recent 120] [--max-files 200]

退出码: 0 = 成功；2 = 参数或环境错误。
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

# git 的空树对象哈希，用于全新仓库（尚无 HEAD）时对比已暂存的改动
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", "out", "target", "coverage",
    "__pycache__", ".venv", "venv", "env", ".mypy_cache", ".pytest_cache",
    ".gradle", ".idea", ".next", ".turbo", "vendor", "bin", "obj",
}
SOURCE_EXT = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".kts",
    ".rs", ".rb", ".cs", ".php", ".scala", ".sql", ".sh", ".yml", ".yaml",
    ".toml", ".json", ".xml", ".proto", ".graphql", ".c", ".h", ".cpp",
}


def git_cmd(root, argv):
    try:
        proc = subprocess.run(
            ["git"] + argv,
            cwd=str(root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout if proc.returncode == 0 else None


def in_git_repo(root):
    out = git_cmd(root, ["rev-parse", "--is-inside-work-tree"])
    return bool(out and out.strip() == "true")


def count_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return sum(1 for _ in f)
    except OSError:
        return None


def parse_status(out):
    """解析 git status --porcelain，返回 {path: status}。"""
    mapping = {
        "M": "modified", "A": "added", "D": "deleted",
        "R": "renamed", "C": "copied", "?": "untracked", "U": "conflicted",
    }
    result = {}
    for line in (out or "").splitlines():
        if len(line) < 4:
            continue
        xy = line[:2]
        raw = line[3:]
        # 重命名/复制格式：old -> new
        path = raw.split(" -> ")[-1].strip().strip('"')
        code = "?" if xy.strip() == "??" else (xy[1] if xy[1] != " " else xy[0])
        result[path] = mapping.get(code, "modified")
    return result


def parse_numstat(out):
    """解析 git diff --numstat，返回 {path: (added, removed)}。"""
    result = {}
    for line in (out or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        add, rm, path = parts[0], parts[1], parts[2]
        if " => " in path or "\t" in path:
            path = path.split(" => ")[-1].strip().strip('"')
        else:
            path = path.strip().strip('"')
        if add == "-" or rm == "-":
            result[path] = (None, None)  # 二进制文件，行数不可比
        else:
            try:
                result[path] = (int(add), int(rm))
            except ValueError:
                result[path] = (None, None)
    return result


def git_summary(root, max_files):
    # -uall：展开未跟踪目录下的具体文件，否则只报目录名，无法统计行数
    # core.quotePath=false：避免非 ASCII 路径被转义成 \xxx
    status = parse_status(git_cmd(root, ["-c", "core.quotePath=false", "status", "--porcelain", "-uall"]))
    numstat = parse_numstat(git_cmd(root, ["-c", "core.quotePath=false", "diff", "--numstat", "HEAD"]))
    if not numstat:
        # 全新仓库还没有 HEAD，改为与空树对比，否则已暂存的文件统计不到行数
        numstat = parse_numstat(git_cmd(root, ["-c", "core.quotePath=false", "diff", "--numstat", EMPTY_TREE]))

    files = []
    for path, state in status.items():
        add, rm = numstat.get(path, (None, None))
        # 只有新增文件能用整文件行数代表新增；已存在的文件猜不出增删，保持 None，不要虚报
        if add is None and state in ("untracked", "added") and (root / path).is_file():
            add, rm = count_lines(root / path), 0
        files.append({
            "path": path,
            "status": state,
            "added_lines": add,
            "removed_lines": rm,
        })

    files.sort(key=lambda f: f["path"])
    truncated = len(files) > max_files
    if truncated:
        files = files[:max_files]

    total_add = sum(f["added_lines"] or 0 for f in files)
    total_rm = sum(f["removed_lines"] or 0 for f in files)
    return {
        "mode": "git",
        "root": str(root),
        "file_count": len(status),
        "files": files,
        "total_added_lines": total_add,
        "total_removed_lines": total_rm,
        "truncated": truncated,
        "notes": [
            "行数基于 git diff --numstat（优先 HEAD，全新仓库回退到空树）",
            "新增文件按整文件行数统计；统计不到的显示为 null，不要凭空填数字",
        ],
    }


def mtime_summary(root, minutes, max_files):
    cutoff = time.time() - minutes * 60
    hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            full = Path(dirpath) / name
            if full.suffix.lower() not in SOURCE_EXT:
                continue
            try:
                st = full.stat()
            except OSError:
                continue
            if st.st_mtime >= cutoff:
                hits.append({
                    "path": str(full.relative_to(root)).replace("\\", "/"),
                    "status": "modified",
                    "added_lines": None,
                    "removed_lines": None,
                    "size_bytes": st.st_size,
                    "modified_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                })
    hits.sort(key=lambda f: f["modified_at"], reverse=True)
    truncated = len(hits) > max_files
    if truncated:
        hits = hits[:max_files]
    return {
        "mode": "mtime",
        "root": str(root),
        "file_count": len(hits),
        "files": hits,
        "truncated": truncated,
        "notes": [
            "非 git 目录，按修改时间扫描最近 %d 分钟内变动的源码文件" % minutes,
            "增删行数无法统计，需人工核对",
        ],
    }


def to_text(info):
    lines = ["模式: %s" % info["mode"], "根目录: %s" % info["root"]]
    if info["file_count"] == 0:
        lines.append("未检测到变更文件。")
    else:
        lines.append("变更文件（%d 个%s）:" % (info["file_count"], "，已截断" if info["truncated"] else ""))
        for f in info["files"]:
            if f["added_lines"] is None:
                delta = ""
            elif f["added_lines"] == 0 and f["removed_lines"] == 0:
                delta = ""
            else:
                delta = "  +%s/-%s" % (f["added_lines"], f["removed_lines"])
            lines.append("  [%-10s] %s%s" % (f["status"], f["path"], delta))
        if info.get("total_added_lines") is not None:
            lines.append("合计: +%d / -%d 行" % (info["total_added_lines"], info["total_removed_lines"]))
    for n in info["notes"]:
        lines.append("说明: %s" % n)
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="统计工作区代码变更，供变更报告使用")
    ap.add_argument("root", nargs="?", default=".", help="项目根目录，默认当前目录")
    ap.add_argument("--recent", type=int, default=120, help="非 git 目录时扫描最近 N 分钟内修改的文件")
    ap.add_argument("--max-files", type=int, default=200, help="最多列出的文件数，默认 200")
    ap.add_argument("--text", action="store_true", help="输出人类可读摘要，而非 JSON")
    args = ap.parse_args()

    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        sys.stderr.write("错误：目录不存在 -> %s\n" % root)
        return 2

    if in_git_repo(root):
        info = git_summary(root, args.max_files)
    else:
        info = mtime_summary(root, args.recent, args.max_files)

    print(to_text(info) if args.text else json.dumps(info, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
