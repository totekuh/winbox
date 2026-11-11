"""Bounded, streaming queries over kdbg action-breakpoint traces."""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Any, Iterator

from winbox.kdbg.debugger.trace_summary import (  # noqa: F401 — re-exported
    MAX_REPRESENTATIVE_HITS,
    MAX_SUMMARY_EXPRESSIONS,
    MAX_SUMMARY_TEXT_BYTES,
    MAX_TRACKED_VALUES,
    _Summary,
    _is_error,
    _numeric,
    _selected_values,
    _value_matches,
)

MAX_TRACE_RESULTS = 200
MAX_SUMMARY_TOP = 20
MAX_TRACE_LINE_BYTES = 1 << 20
MAX_TRACE_ENTRY_RESULT_BYTES = 384 << 10
_READ_BLOCK_BYTES = 64 << 10


def _decode_entry(line: bytes | None) -> dict[str, Any] | None:
    """Decode one generated trace record, rejecting malformed/foreign JSON."""
    if line is None or len(line) > MAX_TRACE_LINE_BYTES:
        return None
    try:
        entry = json.loads(line)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(entry, dict):
        return None
    hit = entry.get("hit")
    values = entry.get("values")
    if (isinstance(hit, bool) or not isinstance(hit, int)
            or not 0 <= hit <= 0x7FFF_FFFF_FFFF_FFFF):
        return None
    if not isinstance(values, dict):
        return None
    if not all(isinstance(k, str) and isinstance(v, str)
               for k, v in values.items()):
        return None
    return entry


def _iter_forward_lines(path: Path) -> Iterator[bytes | None]:
    """Yield bounded physical lines; ``None`` denotes an oversized line."""
    with path.open("rb") as stream:
        while True:
            line = stream.readline(MAX_TRACE_LINE_BYTES + 1)
            if not line:
                return
            if len(line) > MAX_TRACE_LINE_BYTES and not line.endswith(b"\n"):
                while line and not line.endswith(b"\n"):
                    line = stream.readline(MAX_TRACE_LINE_BYTES + 1)
                yield None
                continue
            yield line.rstrip(b"\r\n")


def _iter_reverse_lines(path: Path) -> Iterator[bytes | None]:
    """Yield lines newest-first without loading or scanning the whole file."""
    with path.open("rb") as stream:
        stream.seek(0, 2)
        position = stream.tell()
        pending = b""
        dropping_oversized = False

        while position:
            read_size = min(_READ_BLOCK_BYTES, position)
            position -= read_size
            stream.seek(position)
            chunk = stream.read(read_size)

            if dropping_oversized:
                boundary = chunk.rfind(b"\n")
                if boundary < 0:
                    continue
                yield None
                chunk = chunk[:boundary]
                dropping_oversized = False

            data = chunk + pending
            parts = data.split(b"\n")
            pending = parts[0]
            for line in reversed(parts[1:]):
                line = line.rstrip(b"\r")
                if not line:
                    continue
                yield line if len(line) <= MAX_TRACE_LINE_BYTES else None

            if len(pending) > MAX_TRACE_LINE_BYTES:
                pending = b""
                dropping_oversized = True

        if dropping_oversized:
            yield None
        elif pending:
            pending = pending.rstrip(b"\r")
            yield pending if len(pending) <= MAX_TRACE_LINE_BYTES else None


def _matches(
    entry: dict[str, Any],
    *,
    expression: str | None,
    value: str | None,
    errors_only: bool,
) -> bool:
    selected = _selected_values(entry, expression)
    if not selected:
        return False
    if value is not None and not any(
        _value_matches(actual, value) for actual in selected.values()
    ):
        return False
    if errors_only and not any(_is_error(actual) for actual in selected.values()):
        return False
    return True


def _project(entry: dict[str, Any], expression: str | None) -> dict[str, Any]:
    if expression is None:
        return entry
    projected = dict(entry)
    projected["values"] = _selected_values(entry, expression)
    return projected


def _entry_result_size(entry: dict[str, Any]) -> int:
    return len(json.dumps(entry, separators=(",", ":")).encode("utf-8"))


def query_trace(
    path: str | Path,
    *,
    total: int,
    tail: int = 20,
    from_hit: int | None = None,
    limit: int = 20,
    expression: str | None = None,
    value: str | None = None,
    errors_only: bool = False,
    summary: bool = False,
    top: int = 10,
) -> dict[str, Any]:
    """Query a trace with bounded output and memory.

    ``from_hit`` selects forward pagination and is inclusive. Without it,
    the newest ``tail`` matching records are returned. Summaries cover every
    matching record, not just the returned page.
    """
    trace_path = Path(path)
    filtered = expression is not None or value is not None or errors_only
    summary_builder = _Summary(expression=expression, top=top) if summary else None
    malformed = 0
    matched = 0
    scan_complete = False
    entries: list[dict[str, Any]] = []
    next_hit: int | None = None
    entry_bytes = 0
    result_bytes_truncated = False
    oversized_entries = 0

    if from_hit is None and not filtered and not summary:
        for line in _iter_reverse_lines(trace_path):
            entry = _decode_entry(line)
            if entry is None:
                malformed += 1
                continue
            size = _entry_result_size(entry)
            if size > MAX_TRACE_ENTRY_RESULT_BYTES:
                oversized_entries += 1
                result_bytes_truncated = True
                continue
            if entry_bytes + size > MAX_TRACE_ENTRY_RESULT_BYTES:
                result_bytes_truncated = True
                break
            entries.append(entry)
            entry_bytes += size
            if len(entries) == tail:
                break
        else:
            scan_complete = True
        entries.reverse()
        if total <= len(entries):
            scan_complete = True
        if scan_complete:
            matched = len(entries)
        truncated = total > len(entries)
    else:
        recent: deque[tuple[dict[str, Any], int]] | None = (
            deque() if from_hit is None else None
        )
        recent_bytes = 0
        page_closed = False
        for line in _iter_forward_lines(trace_path):
            entry = _decode_entry(line)
            if entry is None:
                malformed += 1
                continue
            if from_hit is not None and entry["hit"] < from_hit:
                continue
            if not _matches(
                entry, expression=expression, value=value,
                errors_only=errors_only,
            ):
                continue

            matched += 1
            if summary_builder is not None:
                summary_builder.add(entry)

            projected = _project(entry, expression)
            if recent is not None:
                size = _entry_result_size(projected)
                if size > MAX_TRACE_ENTRY_RESULT_BYTES:
                    oversized_entries += 1
                    result_bytes_truncated = True
                    continue
                recent.append((projected, size))
                recent_bytes += size
                while len(recent) > tail:
                    _, removed_size = recent.popleft()
                    recent_bytes -= removed_size
                while recent_bytes > MAX_TRACE_ENTRY_RESULT_BYTES:
                    _, removed_size = recent.popleft()
                    recent_bytes -= removed_size
                    result_bytes_truncated = True
            elif not page_closed and len(entries) < limit:
                size = _entry_result_size(projected)
                if size > MAX_TRACE_ENTRY_RESULT_BYTES:
                    oversized_entries += 1
                    result_bytes_truncated = True
                elif entry_bytes + size <= MAX_TRACE_ENTRY_RESULT_BYTES:
                    entries.append(projected)
                    entry_bytes += size
                else:
                    result_bytes_truncated = True
                    next_hit = entry["hit"]
                    page_closed = True
                    if summary_builder is None:
                        break
            elif not page_closed:
                next_hit = entry["hit"]
                page_closed = True
                if summary_builder is None:
                    break

        else:
            scan_complete = True

        if recent is not None:
            entries = [entry for entry, _ in recent]
            truncated = matched > len(entries)
        else:
            truncated = next_hit is not None or matched > len(entries)

    result: dict[str, Any] = {
        "entries": entries,
        "total": max(0, int(total)),
        "returned": len(entries),
        "truncated": truncated,
        "scan_complete": scan_complete,
        "malformed_lines": malformed,
        "result_bytes_truncated": result_bytes_truncated,
        "oversized_entries": oversized_entries,
    }
    if scan_complete:
        result["matched"] = matched
    if next_hit is not None:
        result["next_hit"] = next_hit
    if summary_builder is not None:
        result["summary"] = summary_builder.result()
    return result
