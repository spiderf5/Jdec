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
import re
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


#: A header row only counts before the first data row.
_HEADER_TOKENS = frozenset({
    "cls", "class", "method", "name", "sig", "signature", "ptr", "pointer",
    "base", "module", "runtimeptr", "runtimebase",
})
#: Deliberately stricter than int(s, 16): Python accepts "+1", "-1" and
#: "1_000", all of which Java's Long.parseLong(s, 16) rejects.  Letting those
#: through made normalize_mappings() "succeed" while the worker silently
#: dropped the row -- the exact failure this normalization exists to prevent.
_HEX_RE = re.compile(r"(?:0[xX])?[0-9a-fA-F]+")


def _is_hex_token(value: str) -> bool:
    """Accept exactly the token shapes the Java worker can parse."""
    return bool(_HEX_RE.fullmatch(value.strip()))


def _canon_hex(value: str) -> str:
    """Normalize an optional ``0X``/``0x`` prefix to lowercase before emit.

    The Java worker strips the prefix with ``replace("0x", "")``, which is
    case-sensitive: ``0X1a`` passes the Python validator but makes
    ``Long.parseLong`` throw, silently dropping the row. Canonicalizing at the
    single normalization funnel keeps both sides on one contract.
    """
    v = value.strip()
    return "0x" + v[2:] if v[:2].lower() == "0x" else v


def _normalize_line(line: str, lineno: int,
                    first: bool) -> tuple[str | None, bool]:
    """Normalize one TSV row; returns (row_or_None, still_first).

    ``None`` means the line is blank, a comment or a header and contributes no
    address-table entry. ``first`` stays true across such lines, so a header
    is only recognised before the first data row.
    """
    if not line.strip() or line.lstrip().startswith("#"):
        return None, first
    cols = [c.strip() for c in line.split("\t")]
    # A single header-ish word is not enough: a legitimate first row may have
    # a method literally named "method"/"name"/"ptr". Require at least two.
    if first and sum(c.lower() in _HEADER_TOKENS for c in cols) >= 2:
        return None, False
    if len(cols) in (4, 6):
        # Frida regnatives: ptr is column 4, runtime base column 5.
        if not cols[0] or not cols[1]:
            raise ValueError(f"bad mapping line {lineno}: empty class or method")
        name = f"{cols[0]}.{cols[1]}"
        ptr = cols[3]
        base = cols[4] if len(cols) == 6 else "-"
    elif len(cols) in (2, 3):
        if not cols[0]:
            raise ValueError(f"bad mapping line {lineno}: empty name")
        name, ptr = cols[0], cols[1]
        base = cols[2] if len(cols) == 3 else "-"
    else:
        raise ValueError(
            f"bad mapping line {lineno}: expected 2/3/4/6 columns, got {len(cols)}")
    if not _is_hex_token(ptr) or (base not in ("", "-")
                                  and not _is_hex_token(base)):
        raise ValueError(
            f"bad mapping line {lineno}: non-hex ptr/base: {line!r}")
    base_out = "-" if base in ("", "-") else _canon_hex(base)
    return f"{name}\t{_canon_hex(ptr)}\t{base_out}", False


def normalize_mappings(text: str) -> str:
    """Convert a Frida regnatives dump into the worker's address-table form.

    ``dump_mappings.py`` writes 4 or 6 columns::

        cls <TAB> method <TAB> sig <TAB> ptr [<TAB> base <TAB> module]

    ``ghidra_worker.java`` consumes 3::

        name <TAB> runtimePtr(hex) <TAB> runtimeBase(hex | "-")

    Hand-written 2/3-column tables are already in that form and pass through.
    A row that cannot be interpreted raises ``ValueError`` with its line
    number instead of being silently dropped by the Java parser.
    """
    rows: list[str] = []
    first = True
    for lineno, line in enumerate(text.lstrip("\ufeff").splitlines(), 1):
        row, first = _normalize_line(line, lineno, first)
        if row is not None:
            rows.append(row)
    return "\n".join(rows) + ("\n" if rows else "")


def normalize_mappings_file(src: Path, dst: Path) -> int:
    """Stream a Frida dump into the worker's 3-column form; return row count.

    Production path: a RegisterNatives dump can hold hundreds of thousands of
    rows, so this never holds more than one line in memory. ``utf-8-sig``
    strips a leading BOM. The normalized table is kept in the output dir as
    an auditable artifact of what the worker actually received.
    """
    count = 0
    first = True
    with src.open("r", encoding="utf-8-sig") as fin, \
            dst.open("w", encoding="utf-8", newline="\n") as fout:
        for lineno, line in enumerate(fin, 1):
            row, first = _normalize_line(line.rstrip("\r\n"), lineno, first)
            if row is not None:
                fout.write(row + "\n")
                count += 1
    return count


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

    mappings_tsv: a Frida ``regnatives`` dump.  Frida writes 4 or 6 columns
    (``cls, method, sig, ptr, [base, module]``); an already-normalized 2/3
    column ``name, ptr(hex), base(hex|-)`` table is also accepted.  The dump is
    streamed through :func:`normalize_mappings_file` into
    ``out_dir/_addr_mappings.tsv`` before reaching the worker, which addresses
    dynamically registered natives (no static ``Java_*`` export) via
    ``imageBase + (ptr - runtimeBase)``.  The normalized table is left in the
    output dir as an auditable record; ``_filter_symbols.txt`` is transient.
    """
    lib_path = Path(lib_path).resolve()
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    filter_file = None
    if filter_symbols:
        filter_file = out_dir / "_filter_symbols.txt"
        filter_file.write_text("\n".join(filter_symbols) + "\n", encoding="utf-8")

    def _failed(error: str) -> dict:
        # A failed normalization must not leave half-written inputs behind.
        if filter_file and filter_file.exists():
            filter_file.unlink(missing_ok=True)
        return {"ok": False, "error": error, "decompiled": [],
                "bad_mapping_lines": 0}

    mappings_file = None
    if mappings_tsv and Path(mappings_tsv).is_file():
        mappings_file = out_dir / "_addr_mappings.tsv"
        try:
            mapping_rows = normalize_mappings_file(Path(mappings_tsv), mappings_file)
        except (OSError, ValueError, UnicodeError) as exc:
            mappings_file.unlink(missing_ok=True)
            return _failed(f"invalid --mappings TSV: {exc}")
        if not quiet:
            print(f"  normalized {mapping_rows} mapping row(s) -> {mappings_file.name}")

    try:
        headless_cmd = get_headless_cmd(ghidra_home)
    except OSError as exc:
        return _failed(f"Ghidra headless not found: {exc}")
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
            "bad_mapping_lines": 0,
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": f"Ghidra execution failed: {exc}",
            "decompiled": [],
            "bad_mapping_lines": 0,
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
                "bad_mapping_lines": data.get("bad_mapping_lines", 0),
                "stdout": r.stdout[-1000:],
            }
        except Exception as exc:  # noqa: BLE001 - fall back to the C file count
            print(f"[jdec-ghidra] ! cannot parse decompiled_summary.json: {exc}",
                  file=sys.stderr)

    src_files = list((out_dir / "src").glob("*.c")) if (out_dir / "src").exists() else []
    return {
        "ok": len(src_files) > 0,
        "total_matched": len(src_files),
        "decompiled_count": len(src_files),
        "functions": [{"name": f.stem, "file": f"src/{f.name}"} for f in src_files],
        "bad_mapping_lines": 0,
        "error": "" if src_files else ("Ghidra finished but no C files produced. " + r.stderr[-500:]),
    }
