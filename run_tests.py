#!/usr/bin/env python3
"""Run the whole test suite: ``python3 run_tests.py``.

Equivalent to ``python3 -m unittest discover -s tests -v``.  The runner is here
because the verbose discovery command is easy to mis-type, and because it sets
the exit code explicitly so CI can rely on it.
"""

from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    verbosity = 1
    if "-v" in argv or "--verbose" in argv:
        verbosity = 2
        argv = [a for a in argv if a not in ("-v", "--verbose")]

    sys.path.insert(0, HERE)
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(HERE, "tests"), top_level_dir=HERE)
    result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    print(
        f"\nran {result.testsRun} tests: "
        f"{result.testsRun - len(result.failures) - len(result.errors)} passed, "
        f"{len(result.failures)} failed, {len(result.errors)} errored, "
        f"{len(result.skipped)} skipped"
    )
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
