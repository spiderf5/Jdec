#!/usr/bin/env python3
"""jdec - run the decompiler driver without installing anything."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from jdec.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
