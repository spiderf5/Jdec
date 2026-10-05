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

sys.path.insert(0, str(Path(__file__).resolve().parent / "jdec"))

from jdec.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
