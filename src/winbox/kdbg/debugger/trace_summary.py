"""Streaming summary aggregation for breakpoint trace queries."""

from __future__ import annotations

import hashlib
from collections import Counter
from typing import Any

MAX_SUMMARY_EXPRESSIONS = 32
MAX_TRACKED_VALUES = 4096
MAX_REPRESENTATIVE_HITS = 3
MAX_SUMMARY_TEXT_BYTES = 128


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
