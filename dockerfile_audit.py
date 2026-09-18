#!/usr/bin/env python3
"""Single-file entry point: ``python3 dockerfile_audit.py <path>``.

The implementation lives in the :mod:`dockerfile_audit` package next to this
file; this shim only makes the tool runnable without installing anything.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dockerfile_audit.cli import main  # noqa: E402  (path set up above)

if __name__ == "__main__":
    sys.exit(main())
