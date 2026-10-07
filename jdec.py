#!/usr/bin/env python3
"""Root forwarder for jdec decompiler driver."""

import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

pkg_dir = Path(__file__).resolve().parent / "jdec"
if str(pkg_dir) not in sys.path:
    sys.path.insert(0, str(pkg_dir))

if __name__ == "__main__":
    from jdec.cli import main
    sys.exit(main())
else:
    # When imported as `import jdec` while in repo root,
    # cleanly load the package jdec/jdec/__init__.py
    import importlib.util
    pkg_init = Path(__file__).resolve().parent / "jdec" / "jdec" / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        "jdec", str(pkg_init), submodule_search_locations=[str(pkg_init.parent)]
    )
    _real_jdec = importlib.util.module_from_spec(spec)
    sys.modules["jdec"] = _real_jdec
    spec.loader.exec_module(_real_jdec)
    for _k, _v in _real_jdec.__dict__.items():
        globals()[_k] = _v
    __all__ = getattr(_real_jdec, "__all__", [])
