"""Bounded, streaming queries over kdbg action-breakpoint traces."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, deque
from pathlib import Path
from typing import Any, Iterator


MAX_TRACE_RESULTS = 200
MAX_SUMMARY_TOP = 20
MAX_SUMMARY_EXPRESSIONS = 32
MAX_TRACKED_VALUES = 4096
MAX_REPRESENTATIVE_HITS = 3
MAX_TRACE_LINE_BYTES = 1 << 20
MAX_TRACE_ENTRY_RESULT_BYTES = 384 << 10
MAX_SUMMARY_TEXT_BYTES = 128
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
                # The newline terminates the oversized line whose suffix was
                # already discarded. Report it once, then resume normally on
                # the complete earlier portion of this block.
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


def _is_error(value: str) -> bool:
    return value.lower().startswith("error:")


def _numeric(value: str) -> int | None:
    if _is_error(value):
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None


def _value_matches(actual: str, wanted: str) -> bool:
    if actual == wanted:
        return True
    actual_number = _numeric(actual)
    wanted_number = _numeric(wanted)
    return (actual_number is not None and wanted_number is not None
            and actual_number == wanted_number)


def _selected_values(
    entry: dict[str, Any], expression: str | None,
) -> dict[str, str]:
    values: dict[str, str] = entry["values"]
    if expression is None:
        return values
    if expression not in values:
        return {}
    return {expression: values[expression]}


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


class _Summary:
    """Streaming, explicitly bounded per-expression aggregation."""

    def __init__(self, *, expression: str | None, top: int) -> None:
        self.expression = expression
        self.top = top
        self.counts: dict[str, Counter[str]] = {}
        self.hits: dict[str, dict[str, list[int]]] = {}
        self.expression_labels: dict[str, str] = {}
        self.expression_labels_truncated: set[str] = set()
        self.value_labels: dict[str, dict[str, str]] = {}
        self.value_labels_truncated: dict[str, set[str]] = {}
        self.totals: Counter[str] = Counter()
        self.error_counts: Counter[str] = Counter()
        self.minimums: dict[str, int] = {}
        self.maximums: dict[str, int] = {}
        self.distinct_truncated: set[str] = set()
        self.expressions_truncated = False

    def add(self, entry: dict[str, Any]) -> None:
        hit = entry["hit"]
        for expr, value in _selected_values(entry, self.expression).items():
            expr_key = _compact_key(expr)
            if expr_key not in self.counts:
                if len(self.counts) >= MAX_SUMMARY_EXPRESSIONS:
                    self.expressions_truncated = True
                    continue
                self.counts[expr_key] = Counter()
                self.hits[expr_key] = {}
                self.expression_labels[expr_key] = _bounded_text(expr)
                if _text_is_truncated(expr):
                    self.expression_labels_truncated.add(expr_key)
                self.value_labels[expr_key] = {}
                self.value_labels_truncated[expr_key] = set()

            self.totals[expr_key] += 1
            counts = self.counts[expr_key]
            value_key = _compact_key(value)
            if value_key in counts or len(counts) < MAX_TRACKED_VALUES:
                counts[value_key] += 1
                self.value_labels[expr_key].setdefault(
                    value_key, _bounded_text(value),
                )
                if _text_is_truncated(value):
                    self.value_labels_truncated[expr_key].add(value_key)
                representatives = self.hits[expr_key].setdefault(value_key, [])
                if len(representatives) < MAX_REPRESENTATIVE_HITS:
                    representatives.append(hit)
            else:
                self.distinct_truncated.add(expr_key)

            if _is_error(value):
                self.error_counts[expr_key] += 1
                continue
            number = _numeric(value)
            if number is not None:
                self.minimums[expr_key] = min(
                    self.minimums.get(expr_key, number), number,
                )
                self.maximums[expr_key] = max(
                    self.maximums.get(expr_key, number), number,
                )

    def result(self) -> dict[str, Any]:
        expressions: list[dict[str, Any]] = []
        for expr_key, counts in self.counts.items():
            ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
            truncated = expr_key in self.distinct_truncated
            top_truncated = truncated or len(ranked) > self.top
            expression = self.expression_labels[expr_key]
            result: dict[str, Any] = {
                "expression": expression,
                "expression_truncated": (
                    expr_key in self.expression_labels_truncated
                ),
                "count": self.totals[expr_key],
                "error_count": self.error_counts[expr_key],
                "distinct_values": len(counts),
                "distinct_truncated": truncated,
                "top_values": [
                    {
                        "value": self.value_labels[expr_key][value_key],
                        "value_truncated": (
                            value_key in self.value_labels_truncated[expr_key]
                        ),
                        "count": count,
                        "hit_ids": self.hits[expr_key][value_key],
                    }
                    for value_key, count in ranked[:self.top]
                ],
                "top_values_complete": not top_truncated,
            }
            if expr_key in self.minimums:
                result["min"] = f"0x{self.minimums[expr_key]:x}"
                result["max"] = f"0x{self.maximums[expr_key]:x}"
            expressions.append(result)
        return {
            "expressions": expressions,
            "expressions_truncated": self.expressions_truncated,
            "limits": {
                "max_expressions": MAX_SUMMARY_EXPRESSIONS,
                "max_distinct_values_per_expression": MAX_TRACKED_VALUES,
                "representative_hit_ids_per_value": MAX_REPRESENTATIVE_HITS,
            },
        }


def _bounded_text(value: str) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= MAX_SUMMARY_TEXT_BYTES:
        return value
    return encoded[:MAX_SUMMARY_TEXT_BYTES].decode("utf-8", "ignore") + "…"


def _text_is_truncated(value: str) -> bool:
    return len(value.encode("utf-8")) > MAX_SUMMARY_TEXT_BYTES


def _compact_key(value: str) -> str:
    """Keep aggregation keys bounded without conflating large values."""
    encoded = value.encode("utf-8")
    if len(encoded) <= MAX_SUMMARY_TEXT_BYTES:
        return "v:" + value
    return "h:" + hashlib.sha256(encoded).hexdigest()


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

    # Common tail request: seek backward and stop as soon as the bounded page
    # is full. Exact total comes from the daemon's in-memory trace counter.
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
                # Summaries describe the filtered query range, so hits before
                # an explicit cursor are intentionally excluded.
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
