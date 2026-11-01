"""One answer to "what kind of input is this?".

The commands grew their own container checks, and they disagreed: `probe`,
`decompile` and `deflat` go through `zipfile` and therefore open a
self-extracting installer (an `MZ` stub with a zip appended) without noticing,
while `callgraph` asked for a `.jar`/`.zip` suffix and answered a 10 MB
installer with an empty graph, and `ircheck` read the whole executable as if it
were one class file. Nothing crashed, which is the worst outcome: a silent empty
result reads like a finding.

So the classification lives here once, keyed on magic bytes rather than on the
file name, because a jar renamed to `.bin` is still a jar and a `.jar` that is
really a text file is not.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Iterator

MAGIC_CLASS = b"\xca\xfe\xba\xbe"
MAGIC_ZIP = b"PK\x03\x04"

KIND_DIR = "directory"
KIND_ZIP = "zip"
KIND_CLASS = "class"
KIND_UNKNOWN = "unknown"


class ContainerError(ValueError):
    """The input is not a container any command knows how to read."""


def _head(path: Path, n: int = 4) -> bytes:
    try:
        with path.open("rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def is_zip(path: Path) -> bool:
    """True for anything `zipfile.ZipFile` can open, stub or no stub.

    A self-extracting installer starts with a native stub, so its first four
    bytes are `MZ..`; `is_zipfile` finds the end-of-central-directory record
    instead of the local header, which is exactly the case that matters here.
    """
    path = Path(path)
    if not path.is_file():
        return False
    if _head(path) == MAGIC_ZIP:
        return True
    try:
        return zipfile.is_zipfile(path)
    except OSError:
        return False


def is_class_file(path: Path) -> bool:
    path = Path(path)
    return path.is_file() and _head(path) == MAGIC_CLASS


def kind_of(path: Path) -> str:
    path = Path(path)
    if path.is_dir():
        return KIND_DIR
    if is_class_file(path):
        return KIND_CLASS
    if is_zip(path):
        return KIND_ZIP
    return KIND_UNKNOWN


def describe(path: Path) -> str:
    """A short phrase for error messages: what the file actually is."""
    path = Path(path)
    if not path.exists():
        return "missing"
    if path.is_dir():
        return "a directory"
    head = _head(path)
    if head == MAGIC_CLASS:
        return "a class file"
    if is_zip(path):
        return "a zip container (possibly a self-extracting installer)"
    if head[:2] == b"MZ":
        return ("an executable with no zip payload - not a jar, so there is "
                "nothing to read")
    return f"unrecognized (first bytes {head!r})"


def class_entries(path: Path) -> Iterator[tuple[str, bytes]]:
    """Yield `(internal_name, bytes)` for every class in a container.

    `internal_name` drops the `.class` suffix and the root, so it matches
    `ClassFile.name` and the keys the call graph and IR layers expect.
    `META-INF/` entries are skipped: multi-release copies (`META-INF/versions/9/…`)
    are alternatives to the base class, not extra classes, and counting them
    produced `NoClassDefFoundError (wrong name)` in an earlier gate run.
    """
    path = Path(path)
    kind = kind_of(path)
    if kind == KIND_DIR:
        for p in sorted(path.rglob("*.class")):
            rel = p.relative_to(path).as_posix()
            if rel.startswith("META-INF/"):
                continue
            yield rel[:-6], p.read_bytes()
        return
    if kind == KIND_ZIP:
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if not n.endswith(".class") or n.startswith("META-INF/"):
                    continue
                try:
                    yield n[:-6], z.read(n)
                except (zipfile.BadZipFile, OSError):
                    # one unreadable entry must not hide the other 3000
                    continue
        return
    if kind == KIND_CLASS:
        yield path.stem, path.read_bytes()
        return
    raise ContainerError(f"{path}: {describe(path)}")


def read_classes(path: Path) -> dict[str, bytes]:
    """`class_entries` as a dict; raises `ContainerError` for unknown input."""
    return dict(class_entries(path))
