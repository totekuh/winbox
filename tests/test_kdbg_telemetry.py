"""Metadata-only kdbg operation history coverage."""

from __future__ import annotations

from winbox.config import Config
from winbox.kdbg.telemetry import MAX_RECORDS, history, record_snapshot_operation, summary


def _metadata(duration=10.0):
    return {
        "snapshot_id": "abc", "admission": "accepted", "reader_owner": "persistent_reader",
        "stop_duration_ms": duration, "read_count": 4, "bytes_read": 128,
        "logical_read_count": 6, "logical_bytes_read": 160, "cache_hits": 2,
        "budget": {"max_duration_ms": 15000, "max_reads": 16384, "max_bytes": 16 * 1024 * 1024},
        "budget_exhausted": False, "phases_ms": {"thread walk": 4.5},
    }


def test_operation_history_is_bounded_and_redacts_unapproved_fields(tmp_path):
    cfg = Config(winbox_dir=tmp_path / ".winbox")
    metadata = _metadata()
    metadata["memory"] = "deadbeef"
    metadata["module_path"] = "C:\\sample.exe"
    for index in range(MAX_RECORDS + 5):
        record_snapshot_operation(
            cfg, operation=f"capture:{index}", outcome="ok", snapshot_metadata=metadata,
        )

    records = history(cfg, limit=MAX_RECORDS)

    assert len(records) == MAX_RECORDS
    assert records[-1]["operation"] == f"capture_{MAX_RECORDS + 4}"
    assert "memory" not in records[-1]["snapshot"]
    assert "module_path" not in records[-1]["snapshot"]
    assert records[-1]["snapshot"]["phases_ms"] == {"thread_walk": 4.5}


def test_operation_summary_reports_percentiles_and_recent_records(tmp_path):
    cfg = Config(winbox_dir=tmp_path / ".winbox")
    for duration in (10, 20, 30, 40):
        record_snapshot_operation(
            cfg, operation="vad", outcome="ok", snapshot_metadata=_metadata(duration),
        )

    result = summary(cfg)

    assert result["record_count"] == 4
    assert result["stop_duration_ms"] == {"p50": 20.0, "p95": 40.0}
    assert result["outcomes"] == {"ok": 4}
