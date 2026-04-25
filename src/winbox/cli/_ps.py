"""Shared PowerShell helpers for cli/ commands.

Why this exists: every CLI module used to build PowerShell scripts as
inline f-strings or triple-quoted blobs, which made:
  * the scripts unlintable / undiffable as PS code
  * test assertions brittle (whitespace / escape changes)
  * the same script-shape duplicated across files (e.g. the DNS-set
    snippet had four near-identical copies in network.py alone)

The helpers below load script templates from src/winbox/data/ps/*.ps1
and render them with str.format(), so PowerShell-side changes happen
in actual .ps1 files that an editor can syntax-highlight.

Note on .format vs f-strings: PowerShell uses braces in its own scope
syntax (``${{var}}``), so authors must double-brace any literal brace
that should reach the guest. Each template has a header comment listing
the placeholders the renderer fills in.
"""

from __future__ import annotations

import importlib.resources
from pathlib import Path


def load_ps(name: str) -> str:
    """Read a bundled .ps1 template from ``winbox.data.ps``."""
    res = importlib.resources.files("winbox.data").joinpath("ps", f"{name}.ps1")
    return Path(str(res)).read_text(encoding="utf-8")


def render_ps(name: str, **params: str) -> str:
    """Load ``name``.ps1 and format it with ``params``."""
    return load_ps(name).format(**params)


def ps_quote(s: str) -> str:
    """Escape a string for inclusion inside a PowerShell single-quoted literal.

    PS single-quoted strings only escape themselves: doubling a `'` produces
    a literal `'`. No backslash interpretation, no variable expansion.
    Use whenever you need to interpolate a user-supplied string into a
    template via {placeholder}.
    """
    return s.replace("'", "''")


def ps_array(items: list[str]) -> str:
    """Render a list of strings as a PowerShell array literal.

    >>> ps_array(['10.0.0.1'])
    "@('10.0.0.1')"
    >>> ps_array(['10.0.0.1', '10.0.0.2'])
    "@('10.0.0.1', '10.0.0.2')"

    Each element is run through ps_quote so embedded apostrophes survive.
    """
    quoted = [f"'{ps_quote(s)}'" for s in items]
    return "@(" + ", ".join(quoted) + ")"
