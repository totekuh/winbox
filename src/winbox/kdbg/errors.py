"""Versioned, bounded errors shared by the kdbg internal protocols."""

from __future__ import annotations

from typing import Any


ERROR_SCHEMA = "winbox.error/1"
MAX_ERROR_MESSAGE = 2048
MAX_DETAIL_KEYS = 16
MAX_DETAIL_STRING = 512
MAX_DETAIL_ITEMS = 16


def _bounded_value(value: Any, *, depth: int = 0) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:MAX_DETAIL_STRING]
    # Admission records naturally have ``details -> budget -> scalar``. Keep
    # that compact three-level shape machine-readable in doctor/busy reports;
    # key/item/string caps still bound any hostile or accidental payload.
    if depth >= 3:
        return str(value)[:MAX_DETAIL_STRING]
    if isinstance(value, (list, tuple)):
        return [
            _bounded_value(item, depth=depth + 1)
            for item in value[:MAX_DETAIL_ITEMS]
        ]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for raw_key, item in list(value.items())[:MAX_DETAIL_KEYS]:
            key = str(raw_key)[:64]
            result[key] = _bounded_value(item, depth=depth + 1)
        return result
    return str(value)[:MAX_DETAIL_STRING]


def bounded_details(details: Any) -> dict[str, Any]:
    """Return a small JSON-safe detail object; reject non-object wire input."""
    if not isinstance(details, dict):
        return {}
    value = _bounded_value(details)
    return value if isinstance(value, dict) else {}


def make_error_info(
    message: object,
    *,
    code: str = "operation_failed",
    retryable: bool = False,
    details: Any = None,
) -> dict[str, Any]:
    safe_code = str(code)
    if not safe_code or len(safe_code) > 64 or not all(
        char.islower() or char.isdigit() or char == "_" for char in safe_code
    ):
        safe_code = "operation_failed"
    return {
        "schema": ERROR_SCHEMA,
        "code": safe_code,
        "message": str(message)[:MAX_ERROR_MESSAGE],
        "retryable": bool(retryable),
        "details": bounded_details(details),
    }


def parse_error_info(value: Any) -> dict[str, Any] | None:
    """Validate a peer's typed error, returning ``None`` for legacy peers."""
    if not isinstance(value, dict) or value.get("schema") != ERROR_SCHEMA:
        return None
    code = value.get("code")
    message = value.get("message")
    retryable = value.get("retryable")
    if (
        not isinstance(code, str)
        or not code
        or len(code) > 64
        or not all(c.islower() or c.isdigit() or c == "_" for c in code)
        or not isinstance(message, str)
        or not isinstance(retryable, bool)
    ):
        return None
    return make_error_info(
        message, code=code, retryable=retryable, details=value.get("details")
    )
