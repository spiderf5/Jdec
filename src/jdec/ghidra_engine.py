"""Ghidra headless engine management and native decompilation driver.

Provides automated JNI library decompilation via Ghidra Headless:
- Automatic detection of Ghidra installation (GHIDRA_HOME, engines/ghidra, PATH, standard dirs)
- Optional on-demand download & extraction into engines/ghidra/
- Subprocess invocation of analyzeHeadless with ghidra_worker.java
- Extraction of JNI entry points (Java_* and JNI_OnLoad) to C pseudo-code
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

GHIDRA_RELEASE_URL = (
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/"
    "Ghidra_11.0.3_build/ghidra_11.0.3_PUBLIC_20240410.zip"
)
# official release asset hash, cross-corroborated from two independent
# mirrors of the GitHub release artifact (chocolatey package + pinned build
# scripts, both 2024-04).  Override with JDEC_GHIDRA_SHA256 when bumping the
# URL to a newer release.
_GHIDRA_SHA256 = "2462a2d0ab11e30f9e907cd3b4aa6b48dd2642f325617e3d922c28e752be6761"
WORKER_JAVA = Path(__file__).resolve().parent / "ghidra_worker.java"


def find_ghidra(
    explicit_path: str | Path | None = None,
    engines_dir: Path | None = None,
) -> Path | None:
    """Find a valid Ghidra installation directory containing support/analyzeHeadless."""
    candidates: list[Path] = []

    if explicit_path:
        candidates.append(Path(explicit_path))

    for env_key in ("GHIDRA_HOME", "GHIDRA_INSTALL_DIR", "GHIDRA_DIR"):
        val = os.environ.get(env_key)
        if val:
            candidates.append(Path(val))

    if engines_dir:
        gdir = engines_dir / "ghidra"
        candidates.append(gdir)
        if gdir.exists():
            for sub in gdir.iterdir():
                if sub.is_dir() and sub.name.lower().startswith("ghidra"):
                    candidates.append(sub)

    # System PATH
    cmd = "analyzeHeadless.bat" if sys.platform == "win32" else "analyzeHeadless"
    which_path = shutil.which(cmd)
    if which_path:
        # which_path is usually <ghidra_root>/support/analyzeHeadless[.bat]
        p = Path(which_path).resolve()
        if p.parent.name == "support":
            candidates.append(p.parent.parent)

    # Standard Windows and Unix locations
    if sys.platform == "win32":
        for pattern in (
            r"C:\ghidra*",
            r"D:\ghidra*",
            r"C:\Program Files\ghidra*",
            r"C:\Tools\ghidra*",
        ):
            for match in glob.glob(pattern):
                candidates.append(Path(match))
    else:
        for pattern in (
            "/opt/ghidra*",
            "/usr/local/ghidra*",
            "~/ghidra*",
        ):
            for match in glob.glob(os.path.expanduser(pattern)):
                candidates.append(Path(match))

    for cand in candidates:
        if _is_valid_ghidra_dir(cand):
            return cand.resolve()

    return None


def _is_valid_ghidra_dir(path: Path) -> bool:
    if not path.is_dir():
        return False
    support = path / "support"
    if not support.is_dir():
        return False
    bin_name = "analyzeHeadless.bat" if sys.platform == "win32" else "analyzeHeadless"
    return (support / bin_name).is_file()


def get_headless_cmd(ghidra_home: Path) -> Path:
    bin_name = "analyzeHeadless.bat" if sys.platform == "win32" else "analyzeHeadless"
    cmd = ghidra_home / "support" / bin_name
    if not cmd.is_file():
        raise FileNotFoundError(f"analyzeHeadless not found at {cmd}")
    return cmd


def download_ghidra(
    dest_dir: Path,
    url: str = GHIDRA_RELEASE_URL,
    quiet: bool = False,
) -> Path:
    """Download and unpack Ghidra into dest_dir/ghidra."""
    target_base = dest_dir / "ghidra"
    target_base.mkdir(parents=True, exist_ok=True)

    zip_tmp = dest_dir / "ghidra_download.zip"
    if not quiet:
        print(f"Downloading Ghidra from {url} ...")
        print("Note: Ghidra release package is ~410MB, this may take a few minutes.")

    try:
        import hashlib
        want = os.environ.get("JDEC_GHIDRA_SHA256") or _GHIDRA_SHA256
        req = urllib.request.Request(url, headers={"User-Agent": "jdec/0.1"})
        digest = hashlib.sha256()
        with urllib.request.urlopen(req, timeout=600) as r, open(zip_tmp, "wb") as f:
            total = int(r.headers.get("Content-Length") or 0)
            done = 0
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                digest.update(chunk)
                f.write(chunk)
                done += len(chunk)
                if not quiet and total > 0:
                    mb, tot = done / (1024 * 1024), total / (1024 * 1024)
                    sys.stdout.write(f"\r  progress: {mb:.1f}MB / {tot:.1f}MB "
                                     f"({done * 100.0 / total:.1f}%)")
                    sys.stdout.flush()
        got = digest.hexdigest()
        if want and got != want:
            zip_tmp.unlink(missing_ok=True)
            raise RuntimeError(
                f"Ghidra download failed integrity verification: "
                f"sha256 {got} != expected {want}; nothing was extracted")
        if not quiet:
            sys.stdout.write("\n  extracting Ghidra package ...\n")
            sys.stdout.flush()
        with zipfile.ZipFile(zip_tmp, "r") as zf:
            zf.extractall(target_base)
    finally:
        if zip_tmp.exists():
            zip_tmp.unlink(missing_ok=True)

    found = find_ghidra(engines_dir=dest_dir)
    if not found:
        raise RuntimeError(f"Ghidra extracted to {target_base} but analyzeHeadless was not found")
    if not quiet:
        print(f"Ghidra ready at: {found}")
    return found


def decompile_library(
    ghidra_home: Path,
    lib_path: Path,
    out_dir: Path,
    filter_symbols: list[str] | None = None,
    timeout: int = 1800,
    quiet: bool = False,
    mappings_tsv: Path | None = None,
) -> dict:
    """Decompile JNI exports in lib_path into out_dir/src/*.c using Ghidra Headless.

    mappings_tsv: frida regnatives 转储(每行 ``name\\truntimePtr(hex)``)——
    动态注册(RegisterNatives)目标没有静态导出,worker 按模块基址偏移
    建函数反编译。"""
    headless_cmd = get_headless_cmd(ghidra_home)
    lib_path = Path(lib_path).resolve()
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    filter_file = None
    if filter_symbols:
        filter_file = out_dir / "_filter_symbols.txt"
        filter_file.write_text("\n".join(filter_symbols) + "\n", encoding="utf-8")

    mappings_file = None
    if mappings_tsv and Path(mappings_tsv).is_file():
        mappings_file = out_dir / "_addr_mappings.tsv"
        mappings_file.write_text(
            Path(mappings_tsv).read_text(encoding="utf-8"), encoding="utf-8")

    proj_dir = Path(tempfile.mkdtemp(prefix="jdec_ghidra_proj_"))
    proj_name = "JdecNative"

    # Ghidra headless 不认绝对路径的 -postScript —— 用 -scriptPath 指目录
    cmd = [
        str(headless_cmd),
        str(proj_dir),
        proj_name,
        "-import",
        str(lib_path),
        "-scriptPath",
        str(WORKER_JAVA.parent),
        "-postScript",
        WORKER_JAVA.name,
        str(out_dir),
    ]
    if filter_file:
        cmd.append(str(filter_file))
    if mappings_file:
        cmd.append(str(mappings_file))
    cmd.append("-deleteProject")

    if not quiet:
        print(f"  running Ghidra Headless on {lib_path.name} ...")

    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": f"Ghidra analysis timed out after {timeout}s",
            "decompiled": [],
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": f"Ghidra execution failed: {exc}",
            "decompiled": [],
        }
    finally:
        if proj_dir.exists():
            shutil.rmtree(proj_dir, ignore_errors=True)
        if filter_file and filter_file.exists():
            filter_file.unlink(missing_ok=True)

    # headless 日志强制落盘:worker 脚本失败曾被静默吞掉(0 产出无报错)
    (out_dir / "_ghidra_run.log").write_text(
        (r.stdout or "") + "\n===== STDERR =====\n" + (r.stderr or ""),
        encoding="utf-8", errors="replace")

    summary_json = out_dir / "decompiled_summary.json"
    if summary_json.exists():
        try:
            data = json.loads(summary_json.read_text(encoding="utf-8"))
            return {
                "ok": True,
                "total_matched": data.get("total_matched", 0),
                "decompiled_count": data.get("decompiled_count", 0),
                "functions": data.get("functions", []),
                "stdout": r.stdout[-1000:],
            }
        except Exception:
            pass

    src_files = list((out_dir / "src").glob("*.c")) if (out_dir / "src").exists() else []
    return {
        "ok": len(src_files) > 0,
        "total_matched": len(src_files),
        "decompiled_count": len(src_files),
        "functions": [{"name": f.stem, "file": f"src/{f.name}"} for f in src_files],
        "error": "" if src_files else ("Ghidra finished but no C files produced. " + r.stderr[-500:]),
    }
