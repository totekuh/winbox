"""Shared PowerShell helpers (templates + escaping).

This module holds the helpers that used to live in ``winbox.cli._ps``.
They are now top-level so non-CLI code (notably ``winbox.eventlogs``)
can use them without reaching across the ``cli/`` boundary, and so
``cli/_ps.py`` doesn't have to be imported transitively to get
``ps_quote``.

Templates live under ``src/winbox/data/ps/`` and are rendered via
``str.format``; PowerShell uses braces in its own scope syntax so
authors must double-brace any literal brace that should reach the
guest. Each template lists its placeholders in a header comment.

Quoting / escaping convention:
    All ``ps_quote``-aware helpers assume the user wraps the result in
    a PowerShell *single-quoted* literal (``'...'``). PS single quotes
    escape only themselves -- no backslash interpretation, no variable
    expansion. Double-quoted PS strings have their own rules and are
    not handled here; build them yourself.
"""

from __future__ import annotations

from winbox import data as _data


def load_ps(name: str) -> str:
    """Read a bundled .ps1 template from ``winbox/data/ps/``."""
    return _data.read("ps", f"{name}.ps1")


def render_ps(name: str, **params: str) -> str:
    """Load ``name``.ps1 and format it with ``params``."""
    return _data.render("ps", f"{name}.ps1", **params)


def ps_quote(s: str) -> str:
    """Escape a string for inclusion inside a PowerShell single-quoted literal.

    PS single-quoted strings only escape themselves: doubling a `'`
    produces a literal `'`. Use whenever interpolating a user-supplied
    string into a template via ``{placeholder}``.
    """
    return s.replace("'", "''")


def ps_array(items: list[str]) -> str:
    """Render a list of strings as a PowerShell array literal.

    >>> ps_array(['10.0.0.1'])
    "@('10.0.0.1')"
    >>> ps_array(['10.0.0.1', '10.0.0.2'])
    "@('10.0.0.1', '10.0.0.2')"

    Each element is run through ps_quote so embedded apostrophes survive.
    Single-element arrays still get the ``@(...)`` wrapping; PowerShell
    accepts a bare ``'foo'`` in array contexts but the explicit form is
    cheap insurance against operator-context surprises.
    """
    quoted = [f"'{ps_quote(s)}'" for s in items]
    return "@(" + ", ".join(quoted) + ")"


def ps_int_array(items: list[int]) -> str:
    """Render a list of integers as a PowerShell array literal.

    >>> ps_int_array([4624])
    '@(4624)'
    >>> ps_int_array([4624, 4625])
    '@(4624, 4625)'
    """
    return "@(" + ", ".join(str(int(i)) for i in items) + ")"
