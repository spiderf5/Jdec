"""jdec - multi-engine Java decompiler driver.

Exposes core analysis, bytecode rewriting, control flow deobfuscation,
native symbol scanning, dynamic mock instrumentation, and project export pipelines.
"""

from . import (
    analyze,
    annotations,
    bsm,
    bvm_devirt,
    bytecode,
    cfg,
    classfile,
    cli,
    decompile,
    deflat,
    devirt,
    native_scan,
    pipeline,
    pool,
    probe,
    project,
    recover,
    stubs,
)
from .cli import main

from ._version import __version__

__all__ = [
    "__version__",
    "main",
    "analyze",
    "annotations",
    "bsm",
    "bvm_devirt",
    "bytecode",
    "cfg",
    "classfile",
    "cli",
    "decompile",
    "deflat",
    "devirt",
    "native_scan",
    "pipeline",
    "pool",
    "probe",
    "project",
    "recover",
    "stubs",
]
