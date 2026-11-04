#!/usr/bin/env python3
"""Repo-root entry point for a source checkout.

The package lives in ``src/jdec`` (a standard src/ layout). This shim keeps
``python jdec.py ...`` working without an install by putting ``src/`` first
on sys.path. Installed users can use the ``jdec`` console script or
``python -m jdec`` instead.
"""

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

_ROOT = Path(__file__).resolve().parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

if __name__ == "__main__":
    from jdec.cli import main
    sys.exit(main())
else:
    # `import jdec` from the repo root would otherwise resolve to this file
    # (or to an empty namespace package) rather than the real package.
    import importlib.util

    _init = _SRC / "jdec" / "__init__.py"
    _spec = importlib.util.spec_from_file_location(
        "jdec", str(_init), submodule_search_locations=[str(_init.parent)]
    )
    _pkg = importlib.util.module_from_spec(_spec)
    sys.modules["jdec"] = _pkg
    _spec.loader.exec_module(_pkg)
    for _key, _value in _pkg.__dict__.items():
        globals()[_key] = _value
    __all__ = getattr(_pkg, "__all__", [])
