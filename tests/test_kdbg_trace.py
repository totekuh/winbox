"""Unit coverage for bounded action-trace queries."""

from __future__ import annotations

import json

from winbox.kdbg.debugger import trace as trace_mod
from winbox.kdbg.debugger.trace import query_trace


def _entry(hit: int, **values: str) -> dict:
    return {"hit": hit, "rip": f"0x{0x1000 + hit:x}", "values": values}


def _write_trace(path, entries, *, trailing_newline=True) -> None:
    text = "\n".join(json.dumps(entry) for entry in entries)
    if trailing_newline:
        text += "\n"
    path.write_text(text)


def test_fast_tail_reads_newest_records_without_scanning_prefix(tmp_path):
    path = tmp_path / "trace.jsonl"
    prefix = b"not json\n" + (b"x" * (70 << 10)) + b"\n"
    records = b"".join(
        json.dumps(_entry(hit, rax=f"0x{hit:x}")).encode() + b"\n"
        for hit in range(5)
    )
    path.write_bytes(prefix + records)

    result = query_trace(path, total=5, tail=2)

    assert [entry["hit"] for entry in result["entries"]] == [3, 4]
    assert result["truncated"] is True
    assert result["scan_complete"] is False
    # The invalid prefix was never touched by the backwards fast path.
    assert result["malformed_lines"] == 0


def test_reverse_reader_handles_block_boundary_crlf_and_no_final_newline(tmp_path):
    path = tmp_path / "trace.jsonl"
    large = _entry(0, rax="0x" + "a" * (70 << 10))
    path.write_bytes(
        json.dumps(large).encode() + b"\r\n" + json.dumps(_entry(1, rax="0x1")).encode()
    )

    result = query_trace(path, total=2, tail=2)

    assert [entry["hit"] for entry in result["entries"]] == [0, 1]
    assert result["scan_complete"] is True
    assert result["matched"] == 2


def test_forward_pagination_is_inclusive_and_reports_next_hit(tmp_path):
    path = tmp_path / "trace.jsonl"
    _write_trace(path, [_entry(hit, rcx=f"0x{hit:x}") for hit in range(6)])

    first = query_trace(path, total=6, from_hit=2, limit=2)
    second = query_trace(path, total=6, from_hit=first["next_hit"], limit=2)

    assert [entry["hit"] for entry in first["entries"]] == [2, 3]
    assert first["next_hit"] == 4
    assert first["truncated"] is True
    assert first["scan_complete"] is False
    assert [entry["hit"] for entry in second["entries"]] == [4, 5]
    assert second["matched"] == 2
    assert second["truncated"] is False
    assert second["scan_complete"] is True


def test_expression_and_numeric_value_filter_projects_one_action(tmp_path):
    path = tmp_path / "trace.jsonl"
    _write_trace(path, [
        _entry(0, rcx="0x22", rdx="0xaa"),
        _entry(1, rcx="0x23", rdx="0x22"),
        _entry(2, rcx="0x22", rdx="0xbb"),
    ])

    result = query_trace(
        path, total=3, tail=20, expression="rcx", value="34",
    )

    assert [entry["hit"] for entry in result["entries"]] == [0, 2]
    assert all(entry["values"] == {"rcx": "0x22"} for entry in result["entries"])
    assert result["matched"] == 2


def test_value_without_expression_matches_any_action(tmp_path):
    path = tmp_path / "trace.jsonl"
    _write_trace(path, [
        _entry(0, rcx="0x1", rdx="0x2"),
        _entry(1, rcx="0x2", rdx="0x3"),
    ])

    result = query_trace(path, total=2, tail=20, value="0x2")

    assert [entry["hit"] for entry in result["entries"]] == [0, 1]


def test_errors_only_respects_expression_filter(tmp_path):
    path = tmp_path / "trace.jsonl"
    _write_trace(path, [
        _entry(0, rcx="error: unmapped", rdx="0x2"),
        _entry(1, rcx="0x1", rdx="error: short read"),
        _entry(2, rcx="0x2", rdx="0x3"),
    ])

    any_error = query_trace(path, total=3, tail=20, errors_only=True)
    rcx_error = query_trace(
        path, total=3, tail=20, expression="rcx", errors_only=True,
    )

    assert [entry["hit"] for entry in any_error["entries"]] == [0, 1]
    assert [entry["hit"] for entry in rcx_error["entries"]] == [0]


def test_summary_counts_top_values_range_errors_and_representative_hits(tmp_path):
    path = tmp_path / "trace.jsonl"
    _write_trace(path, [
        _entry(0, code="0x22"),
        _entry(1, code="0x22"),
        _entry(2, code="0x10"),
        _entry(3, code="error: unmapped"),
        _entry(4, code="0x22"),
    ])

    result = query_trace(path, total=5, tail=2, summary=True, top=2)
    summary = result["summary"]["expressions"][0]

    assert [entry["hit"] for entry in result["entries"]] == [3, 4]
    assert result["matched"] == 5
    assert summary["expression"] == "code"
    assert summary["count"] == 5
    assert summary["error_count"] == 1
    assert summary["distinct_values"] == 3
    assert summary["top_values_complete"] is False
    assert summary["min"] == "0x10"
    assert summary["max"] == "0x22"
    assert summary["top_values"][0] == {
        "value": "0x22", "value_truncated": False,
        "count": 3, "hit_ids": [0, 1, 4],
    }


def test_summary_distinct_tracking_is_bounded_but_total_is_exact(
    tmp_path, monkeypatch,
):
    monkeypatch.setattr(trace_mod, "MAX_TRACKED_VALUES", 2)
    path = tmp_path / "trace.jsonl"
    _write_trace(path, [_entry(hit, code=f"0x{hit:x}") for hit in range(5)])

    result = query_trace(path, total=5, tail=1, summary=True)
    summary = result["summary"]["expressions"][0]

    assert summary["count"] == 5
    assert summary["distinct_values"] == 2
    assert summary["distinct_truncated"] is True
    assert summary["top_values_complete"] is False


def test_malformed_and_oversized_physical_lines_are_skipped(tmp_path):
    path = tmp_path / "trace.jsonl"
    with path.open("wb") as stream:
        stream.write(b"not json\n")
        stream.write(b"x" * (trace_mod.MAX_TRACE_LINE_BYTES + 1) + b"\n")
        stream.write(json.dumps(_entry(7, rax="0x7")).encode() + b"\n")

    result = query_trace(path, total=1, tail=20, summary=True)

    assert [entry["hit"] for entry in result["entries"]] == [7]
    assert result["malformed_lines"] == 2
    assert result["scan_complete"] is True


def test_single_entry_larger_than_result_budget_is_omitted_explicitly(tmp_path):
    path = tmp_path / "trace.jsonl"
    huge_value = "x" * (trace_mod.MAX_TRACE_ENTRY_RESULT_BYTES + 1)
    _write_trace(path, [_entry(0, data=huge_value)])

    result = query_trace(path, total=1, tail=20)

    assert result["entries"] == []
    assert result["truncated"] is True
    assert result["result_bytes_truncated"] is True
    assert result["oversized_entries"] == 1


def test_summary_compacts_adversarially_large_values(tmp_path):
    path = tmp_path / "trace.jsonl"
    huge_value = "x" * (trace_mod.MAX_TRACE_ENTRY_RESULT_BYTES + 1)
    _write_trace(path, [_entry(0, data=huge_value)])

    result = query_trace(path, total=1, tail=20, summary=True)
    top = result["summary"]["expressions"][0]["top_values"][0]

    assert top["value_truncated"] is True
    assert len(top["value"].encode("utf-8")) <= trace_mod.MAX_SUMMARY_TEXT_BYTES + 3
    assert len(json.dumps(result).encode("utf-8")) < (1 << 20)


def test_missing_expression_matches_no_records(tmp_path):
    path = tmp_path / "trace.jsonl"
    _write_trace(path, [_entry(0, rax="0x1")])

    result = query_trace(path, total=1, tail=20, expression="rcx", summary=True)

    assert result["entries"] == []
    assert result["matched"] == 0
    assert result["summary"]["expressions"] == []
