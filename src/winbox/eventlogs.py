"""Windows event-log query primitives - shared between CLI and MCP.

Pure functions: time-range parsing, PowerShell FilterHashtable construction,
JSON parsing, and table formatting. No I/O, no VM access. The CLI and MCP
wrappers handle the GuestAgent call.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from rich.table import Table


_DURATION_RE = re.compile(r"^(\d+)([smhdw])$")
_DURATION_UNITS = {
    "s": "seconds",
    "m": "minutes",
    "h": "hours",
    "d": "days",
    "w": "weeks",
}

_LEVELS = {
    "Critical": 1,
    "Error": 2,
    "Warning": 3,
    "Information": 4,
    "Verbose": 5,
}
LEVEL_CHOICES = list(_LEVELS.keys())

_LEVEL_ABBREV = {
    1: "Cri",
    2: "Err",
    3: "Wrn",
    4: "Inf",
    5: "Vrb",
    0: "Inf",
}


@dataclass
class EventQuery:
    logs: list[str]
    since: datetime
    ids: list[int]
    provider: str | None
    level: str | None
    max_events: int


def parse_since(s: str, *, now: datetime | None = None) -> datetime:
    """Parse a duration ('1h', '30m', '2d', '1w') or ISO 8601 timestamp.

    Returns a naive local datetime - matches Get-WinEvent semantics on the
    Windows side, which also speaks local time without zone info.
    """
    if not isinstance(s, str) or not s:
        raise ValueError(f"invalid --since: {s!r}")
    s = s.strip()
    m = _DURATION_RE.match(s)
    if m:
        n = int(m.group(1))
        unit = _DURATION_UNITS[m.group(2)]
        base = now if now is not None else datetime.now()
        return base - timedelta(**{unit: n})
    try:
        return datetime.fromisoformat(s)
    except ValueError as e:
        raise ValueError(
            f"invalid --since: {s!r} (use Nh/Nm/Nd/Nw or ISO 8601)"
        ) from e


def _ps_quote(s: str) -> str:
    return s.replace("'", "''")


def _ps_string_array(items: list[str]) -> str:
    if len(items) == 1:
        return f"'{_ps_quote(items[0])}'"
    quoted = ",".join(f"'{_ps_quote(x)}'" for x in items)
    return f"@({quoted})"


def _ps_int_array(items: list[int]) -> str:
    if len(items) == 1:
        return str(items[0])
    return "@(" + ",".join(str(int(x)) for x in items) + ")"


def build_powershell(q: EventQuery) -> str:
    """Build the Get-WinEvent PowerShell script for a parsed query."""
    parts = [f"LogName={_ps_string_array(q.logs)}"]
    parts.append(
        "StartTime=[datetime]'" + q.since.strftime("%Y-%m-%dT%H:%M:%S") + "'"
    )
    if q.ids:
        parts.append(f"Id={_ps_int_array(q.ids)}")
    if q.provider:
        parts.append(f"ProviderName='{_ps_quote(q.provider)}'")
    if q.level:
        if q.level not in _LEVELS:
            raise ValueError(f"invalid level: {q.level!r}")
        parts.append(f"Level={_LEVELS[q.level]}")
    hashtable = ";".join(parts)
    max_events = int(q.max_events)
    return (
        "$ErrorActionPreference='Stop';"
        f"Get-WinEvent -FilterHashtable @{{{hashtable}}} -MaxEvents {max_events} "
        "| Select-Object TimeCreated,LogName,LevelDisplayName,Level,Id,"
        "ProviderName,Message "
        "| ConvertTo-Json -Depth 4 -Compress"
    )


def parse_events(stdout: str) -> list[dict[str, Any]]:
    """Parse Get-WinEvent JSON output, normalising the single-vs-array quirk."""
    s = (stdout or "").strip()
    if not s:
        return []
    data = json.loads(s)
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    raise ValueError(f"unexpected event JSON shape: {type(data).__name__}")


def _short_time(s: str | None) -> str:
    if not s:
        return ""
    s = str(s)
    if s.startswith("/Date("):
        m = re.match(r"^/Date\((\d+)", s)
        if m:
            ts = int(m.group(1)) / 1000.0
            return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    except ValueError:
        return s[:19]


def _level_abbrev(level: int | str | None, display: str | None) -> str:
    try:
        return _LEVEL_ABBREV.get(int(level) if level is not None else 0, "Inf")
    except (TypeError, ValueError):
        if isinstance(display, str) and display:
            return display[:3]
        return "Inf"


def _flatten_message(msg: str | None, max_chars: int = 240) -> str:
    if not msg:
        return ""
    flat = " | ".join(line.strip() for line in str(msg).splitlines() if line.strip())
    if max_chars and len(flat) > max_chars:
        return flat[: max_chars - 1] + "\u2026"
    return flat


def format_compact_table(
    events: list[dict[str, Any]],
    *,
    message_chars: int = 240,
) -> Table:
    table = Table(show_header=True, header_style="bold", expand=False)
    table.add_column("Time", min_width=19, no_wrap=True)
    table.add_column("Log", no_wrap=True)
    table.add_column("Lvl", min_width=3, no_wrap=True)
    table.add_column("Id", justify="right", min_width=4, no_wrap=True)
    table.add_column("Provider", no_wrap=True)
    if message_chars:
        table.add_column(
            "Message",
            no_wrap=True,
            max_width=message_chars,
            overflow="ellipsis",
        )
    else:
        table.add_column("Message", overflow="fold")

    for ev in events:
        table.add_row(
            _short_time(ev.get("TimeCreated")),
            str(ev.get("LogName", "")),
            _level_abbrev(ev.get("Level"), ev.get("LevelDisplayName")),
            str(ev.get("Id", "")),
            str(ev.get("ProviderName", "")),
            _flatten_message(ev.get("Message"), max_chars=message_chars),
        )
    return table
