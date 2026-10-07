"""jdec - multi-engine Java decompiler driver.

Exposes core analysis, bytecode rewriting, control flow deobfuscation,
native symbol scanning, dynamic mock instrumentation, and project export pipelines.
"""

from . import (
    analyze,
    annotations,
    bsm,
    bytecode,
    cfg,
    classfile,
    cli,
    decompile,
    deflat,
    native_scan,
    pipeline,
    pool,
    probe,
    project,
    recover,
    stubs,
)
from .cli import main

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "main",
    "analyze",
    "annotations",
    "bsm",
    "bytecode",
    "cfg",
    "classfile",
    "cli",
    "decompile",
    "deflat",
    "native_scan",
    "pipeline",
    "pool",
    "probe",
    "project",
    "recover",
    "stubs",
]
