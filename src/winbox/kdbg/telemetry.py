"""Bounded, metadata-only kdbg operation history.

The history deliberately never records target memory, module paths, command
arguments, or exception text.  It is an operator-control-plane aid: enough to
answer whether the debugger is busy, what held a stop budget, and which phase
is slow without quietly becoming another evidence store.
"""

from __future__ import annotations

import fcntl
import json
import math
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from winbox.config import Config


SCHEMA = "winbox.kdbg-operation-history/1"
MAX_RECORDS = 50
MAX_RECORD_BYTES = 4096


def _path(cfg: Config) -> Path:
    return cfg.winbox_dir / "kdbg" / "operation-history.json"


def _lock_path(cfg: Config) -> Path:
    return _path(cfg).with_suffix(".lock")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z",
    )


def _bounded_int(value: object, *, low: int = 0, high: int = 1 << 62) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        return None
    return value


def _bounded_float(value: object, *, low: float = 0.0, high: float = 86_400_000.0) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    parsed = float(value)
    if not math.isfinite(parsed) or not low <= parsed <= high:
        return None
    return round(parsed, 3)


def _safe_phase_map(value: object) -> dict[str, float]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, float] = {}
    for raw_name, raw_duration in value.items():
        if not isinstance(raw_name, str):
            continue
        name = "".join(ch if ch.isalnum() or ch in "_-" else "_" for ch in raw_name)[:64]
        duration = _bounded_float(raw_duration)
        if name and duration is not None:
            result[name] = duration
        if len(result) >= 32:
            break
    return result


def _sanitize_snapshot(metadata: object) -> dict[str, Any]:
    """Keep only explicit transport/control-plane facts from a snapshot."""
    raw = metadata if isinstance(metadata, dict) else {}
    budget = raw.get("budget") if isinstance(raw.get("budget"), dict) else {}
    clean_budget = {
        key: _bounded_int(budget.get(key), low=1, high=64 * 1024 * 1024)
        for key in ("max_duration_ms", "max_reads", "max_bytes")
    }
    return {
        "snapshot_id": str(raw.get("snapshot_id") or "")[:64] or None,
        "admission": str(raw.get("admission") or "unknown")[:32],
        "reader_owner": str(raw.get("reader_owner") or "unknown")[:64],
        "stop_duration_ms": _bounded_float(raw.get("stop_duration_ms")),
        "read_count": _bounded_int(raw.get("read_count")),
        "bytes_read": _bounded_int(raw.get("bytes_read")),
        "logical_read_count": _bounded_int(raw.get("logical_read_count")),
        "logical_bytes_read": _bounded_int(raw.get("logical_bytes_read")),
        "cache_hits": _bounded_int(raw.get("cache_hits")),
        "budget": {key: value for key, value in clean_budget.items() if value is not None},
        "budget_exhausted": bool(raw.get("budget_exhausted")),
        "phases_ms": _safe_phase_map(raw.get("phases_ms")),
    }


def _read(path: Path) -> list[dict[str, Any]]:
    try:
        if path.is_symlink() or path.stat().st_size > MAX_RECORDS * MAX_RECORD_BYTES * 2:
            return []
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return []
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        return []
    records = value.get("records")
    if not isinstance(records, list):
        return []
    return [record for record in records[-MAX_RECORDS:] if isinstance(record, dict)]


def _atomic_write(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump({"schema": SCHEMA, "records": records[-MAX_RECORDS:]}, output,
                      separators=(",", ":"), sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def record_snapshot_operation(
    cfg: Config,
    *,
    operation: str,
    outcome: str,
    snapshot_metadata: object,
    error_code: str | None = None,
    complete: bool | None = None,
) -> None:
    """Append one bounded metadata-only operation record, best effort.

    Observability must never turn a successful investigation into a failed
    one because an operator's runtime directory is momentarily unwritable.
    """
    safe_operation = "".join(
        char if char.isalnum() or char in "_.-" else "_" for char in str(operation)
    )[:64] or "snapshot"
    safe_outcome = outcome if outcome in {"ok", "error", "busy", "incomplete"} else "error"
    safe_error = None
    if error_code:
        safe_error = "".join(
            char if char.islower() or char.isdigit() or char == "_" else "_"
            for char in str(error_code)
        )[:64] or None
    record: dict[str, Any] = {
        "at": _utc_now(),
        "operation": safe_operation,
        "outcome": safe_outcome,
        "snapshot": _sanitize_snapshot(snapshot_metadata),
    }
    if safe_error is not None:
        record["error_code"] = safe_error
    if complete is not None:
        record["complete"] = bool(complete)
    try:
        encoded = json.dumps(record, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > MAX_RECORD_BYTES:
            return
        path = _path(cfg)
        lock = _lock_path(cfg)
        lock.parent.mkdir(parents=True, exist_ok=True)
        with lock.open("a+b") as handle:
            os.chmod(lock, 0o600)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            records = _read(path)
            records.append(record)
            _atomic_write(path, records)
    except OSError:
        return


def history(cfg: Config, *, limit: int = 10) -> list[dict[str, Any]]:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_RECORDS:
        raise ValueError(f"limit must be between 1 and {MAX_RECORDS}")
    return _read(_path(cfg))[-limit:]


def summary(cfg: Config) -> dict[str, Any]:
    records = _read(_path(cfg))
    durations = sorted(
        value for record in records
        if isinstance(record.get("snapshot"), dict)
        for value in [_bounded_float(record["snapshot"].get("stop_duration_ms"))]
        if value is not None
    )

    def percentile(fraction: float) -> float | None:
        if not durations:
            return None
        index = max(0, min(len(durations) - 1, math.ceil(len(durations) * fraction) - 1))
        return durations[index]

    outcomes: dict[str, int] = {}
    for record in records:
        outcome = str(record.get("outcome") or "unknown")[:32]
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
    return {
        "schema": SCHEMA,
        "retention": MAX_RECORDS,
        "record_count": len(records),
        "outcomes": outcomes,
        "stop_duration_ms": {"p50": percentile(0.50), "p95": percentile(0.95)},
        "recent": records[-10:],
    }
