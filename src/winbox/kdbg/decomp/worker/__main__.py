"""Standalone entry point for the Ghidra worker process.

This file is invoked directly by a separate Python/PyGhidra interpreter::

    /path/to/python /path/to/worker/__main__.py --socket ... --lock ...

When executed by file path (not ``-m``), the package context is absent.
Bootstrap it by ensuring the grandparent directory (``decomp/``) is on
``sys.path`` so that ``from winbox.kdbg.decomp.worker._server import main``
resolves correctly.
"""

from __future__ import annotations

import os
import sys

_this = os.path.dirname(os.path.abspath(__file__))
_decomp = os.path.dirname(_this)
_src = os.path.dirname(os.path.dirname(os.path.dirname(_decomp)))
if _src not in sys.path:
    sys.path.insert(0, _src)

from winbox.kdbg.decomp.worker._server import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
