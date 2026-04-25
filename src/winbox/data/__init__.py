"""Bundled non-Python data: PowerShell templates, XML configs, etc.

Single entry point for reading bundled files instead of every caller
re-implementing the importlib.resources dance. Five copies of the
"load a bundled file" helper had appeared across the codebase
(setup/installer._data_file, cli/office._data_file, cli/applocker._read_data,
cli/_ps.load_ps, nwfilter._filter_path); the next contributor adding
a template would have made it six. Use these functions instead.

Layout under src/winbox/data/:

    *.ps1, *.xml          -- top-level templates (legacy)
    ps/<name>.ps1         -- PowerShell script templates
    applocker/*.xml       -- AppLocker policy XMLs

Examples::

    from winbox import data

    # Read a bundled file as text:
    body = data.read("ps", "set_dns.ps1")

    # Read + str.format() in one go (typical for templates with {placeholders}):
    body = data.render("ps", "set_dns.ps1", servers=ip)

    # Get a Path for callers that need to pass a real filesystem location
    # (e.g. virsh nwfilter-define that takes a path argument):
    p = data.path("winbox-isolate.xml")
"""

from __future__ import annotations

import importlib.resources
from pathlib import Path


def path(*parts: str) -> Path:
    """Return a real-filesystem ``Path`` to a bundled file.

    Use when the consumer takes a path string (e.g. external tools like
    ``virsh nwfilter-define``). For zip-installed packages this would
    materialize the resource; winbox is currently shipped as a regular
    package, so the materialization cost is zero.
    """
    res = importlib.resources.files(__name__).joinpath(*parts)
    return Path(str(res))


def read(*parts: str) -> str:
    """Read a bundled file as UTF-8 text."""
    return path(*parts).read_text(encoding="utf-8")


def read_bytes(*parts: str) -> bytes:
    """Read a bundled file as bytes."""
    return path(*parts).read_bytes()


def render(*parts: str, **params) -> str:
    """Read and ``str.format(**params)`` a template file.

    Templates use Python format-string syntax: ``{name}`` for placeholders,
    doubled ``{{`` / ``}}`` for literal braces (PowerShell uses braces in
    its own scope syntax, so PS templates need this routinely).
    """
    return read(*parts).format(**params)
