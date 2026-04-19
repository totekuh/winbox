"""Tests for winbox eventlogs (core + CLI + MCP)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from winbox.eventlogs import (
    CSV_FIELDS,
    EventQuery,
    build_clear_powershell,
    build_powershell,
    format_csv,
    parse_clear_result,
    parse_events,
    parse_since,
)
from winbox.vm.guest import ExecResult


# ─── parse_since ────────────────────────────────────────────────────────────


class TestParseSince:
    def test_hours(self):
        anchor = datetime(2026, 4, 19, 12, 0, 0)
        assert parse_since("1h", now=anchor) == anchor - timedelta(hours=1)

    def test_minutes(self):
        anchor = datetime(2026, 4, 19, 12, 0, 0)
        assert parse_since("30m", now=anchor) == anchor - timedelta(minutes=30)

    def test_days(self):
        anchor = datetime(2026, 4, 19, 12, 0, 0)
        assert parse_since("2d", now=anchor) == anchor - timedelta(days=2)

    def test_weeks(self):
        anchor = datetime(2026, 4, 19, 12, 0, 0)
        assert parse_since("1w", now=anchor) == anchor - timedelta(weeks=1)

    def test_seconds(self):
        anchor = datetime(2026, 4, 19, 12, 0, 0)
        assert parse_since("90s", now=anchor) == anchor - timedelta(seconds=90)

    def test_iso8601(self):
        assert parse_since("2026-04-19T10:00:00") == datetime(2026, 4, 19, 10, 0, 0)

    def test_invalid_unit(self):
        with pytest.raises(ValueError, match="invalid --since"):
            parse_since("5x")

    def test_invalid_string(self):
        with pytest.raises(ValueError, match="invalid --since"):
            parse_since("yesterday")

    def test_empty_string(self):
        with pytest.raises(ValueError):
            parse_since("")


# ─── build_powershell ───────────────────────────────────────────────────────


def _mk(**overrides):
    base = dict(
        logs=["Security"],
        since=datetime(2026, 4, 19, 11, 30, 0),
        ids=[],
        provider=None,
        level=None,
        max_events=100,
    )
    base.update(overrides)
    return EventQuery(**base)


class TestBuildPowershell:
    def test_single_log(self):
        ps = build_powershell(_mk(logs=["Security"]))
        assert "LogName='Security'" in ps
        assert "@(" not in ps.split("LogName=")[1].split(";")[0]

    def test_multi_log(self):
        ps = build_powershell(_mk(logs=["Security", "System"]))
        assert "LogName=@('Security','System')" in ps

    def test_log_with_quote_escaped(self):
        ps = build_powershell(_mk(logs=["foo'bar"]))
        assert "LogName='foo''bar'" in ps

    def test_starttime_iso(self):
        ps = build_powershell(_mk(since=datetime(2026, 4, 19, 11, 30, 5)))
        assert "StartTime=[datetime]'2026-04-19T11:30:05'" in ps

    def test_single_id(self):
        ps = build_powershell(_mk(ids=[4624]))
        assert "Id=4624" in ps

    def test_multi_id(self):
        ps = build_powershell(_mk(ids=[4624, 4625, 4634]))
        assert "Id=@(4624,4625,4634)" in ps

    def test_provider(self):
        ps = build_powershell(_mk(provider="Microsoft-Windows-Sysmon"))
        assert "ProviderName='Microsoft-Windows-Sysmon'" in ps

    def test_level_information(self):
        ps = build_powershell(_mk(level="Information"))
        assert "Level=4" in ps

    def test_level_error(self):
        ps = build_powershell(_mk(level="Error"))
        assert "Level=2" in ps

    def test_level_invalid(self):
        with pytest.raises(ValueError):
            build_powershell(_mk(level="Bogus"))

    def test_max_events_in_command(self):
        ps = build_powershell(_mk(max_events=42))
        assert "-MaxEvents 42" in ps

    def test_max_events_coerced(self):
        ps = build_powershell(_mk(max_events="50"))  # type: ignore[arg-type]
        assert "-MaxEvents 50" in ps

    def test_includes_select_and_convert(self):
        ps = build_powershell(_mk())
        assert "Select-Object" in ps
        assert "ConvertTo-Json -Depth 4 -Compress" in ps
        assert "TimeCreated" in ps and "Message" in ps


# ─── parse_events ───────────────────────────────────────────────────────────


class TestParseEvents:
    def test_empty_string(self):
        assert parse_events("") == []

    def test_whitespace(self):
        assert parse_events("   \n  ") == []

    def test_array(self):
        data = [{"Id": 1}, {"Id": 2}]
        assert parse_events(json.dumps(data)) == data

    def test_single_object_quirk(self):
        """PS ConvertTo-Json returns a bare object when there's exactly one."""
        data = {"Id": 4624, "LogName": "Security"}
        assert parse_events(json.dumps(data)) == [data]

    def test_invalid_shape(self):
        with pytest.raises(ValueError, match="unexpected event JSON shape"):
            parse_events('"just-a-string"')

    def test_invalid_json(self):
        with pytest.raises(json.JSONDecodeError):
            parse_events("{not json")

    def test_normalises_ps_date_in_array(self):
        """PowerShell /Date(ms)/ serialisation gets rewritten to ISO 8601."""
        ev = {"TimeCreated": "/Date(1776612031632)/", "Id": 1}
        out = parse_events(json.dumps([ev]))
        # 1776612031632 ms == 2026-04-19T17:20:31 local time
        assert out[0]["TimeCreated"].startswith("2026-")
        assert "T" in out[0]["TimeCreated"]
        assert "/Date(" not in out[0]["TimeCreated"]

    def test_normalises_ps_date_in_single_object(self):
        ev = {"TimeCreated": "/Date(1776612031632)/", "Id": 1}
        out = parse_events(json.dumps(ev))
        assert "/Date(" not in out[0]["TimeCreated"]

    def test_normalises_ps_date_with_tz_offset(self):
        ev = {"TimeCreated": "/Date(1776612031632+0200)/", "Id": 1}
        out = parse_events(json.dumps([ev]))
        assert "/Date(" not in out[0]["TimeCreated"]

    def test_passes_through_iso_unchanged(self):
        ev = {"TimeCreated": "2026-04-19T17:20:31", "Id": 1}
        out = parse_events(json.dumps([ev]))
        assert out[0]["TimeCreated"] == "2026-04-19T17:20:31"

    def test_passes_through_missing_timecreated(self):
        ev = {"Id": 1}
        out = parse_events(json.dumps([ev]))
        assert out[0] == {"Id": 1}


# ─── format_csv ─────────────────────────────────────────────────────────────


class TestFormatCsv:
    def test_header_and_empty(self):
        out = format_csv([])
        assert out.strip() == "Time,Log,Level,Id,Provider,Message"

    def test_fields_constant(self):
        assert CSV_FIELDS == ("Time", "Log", "Level", "Id", "Provider", "Message")

    def test_basic_row(self):
        events = [{
            "TimeCreated": "2026-04-19T12:34:56", "LogName": "Security",
            "Level": 4, "LevelDisplayName": "Information", "Id": 4624,
            "ProviderName": "Microsoft-Windows-Security-Auditing",
            "Message": "An account was successfully logged on.",
        }]
        out = format_csv(events).splitlines()
        assert out[0] == "Time,Log,Level,Id,Provider,Message"
        assert out[1] == (
            "2026-04-19 12:34:56,Security,Information,4624,"
            "Microsoft-Windows-Security-Auditing,"
            "An account was successfully logged on."
        )

    def test_message_with_comma_quoted(self):
        events = [{
            "TimeCreated": "2026-04-19T12:34:56", "LogName": "Security",
            "Level": 4, "LevelDisplayName": "Information", "Id": 1,
            "ProviderName": "p", "Message": "a, b, c",
        }]
        out = format_csv(events).splitlines()
        assert '"a, b, c"' in out[1]

    def test_message_with_quote_escaped(self):
        events = [{
            "TimeCreated": "2026-04-19T12:34:56", "LogName": "Security",
            "Level": 4, "LevelDisplayName": "Information", "Id": 1,
            "ProviderName": "p", "Message": 'he said "hi"',
        }]
        out = format_csv(events).splitlines()
        assert '"he said ""hi"""' in out[1]

    def test_message_newlines_flatten(self):
        events = [{
            "TimeCreated": "2026-04-19T12:34:56", "LogName": "Security",
            "Level": 4, "LevelDisplayName": "Information", "Id": 1,
            "ProviderName": "p",
            "Message": "line one\r\nline two\n\nline three\ttab",
        }]
        out = format_csv(events).splitlines()
        # Tabs become single spaces, newlines become " | ", no embedded \n
        assert len(out) == 2
        assert "line one | line two | line three tab" in out[1]

    def test_no_truncation(self):
        big = "x" * 5000
        events = [{
            "TimeCreated": "2026-04-19T12:34:56", "LogName": "Security",
            "Level": 4, "LevelDisplayName": "Information", "Id": 1,
            "ProviderName": "p", "Message": big,
        }]
        out = format_csv(events)
        assert big in out

    def test_level_falls_back_to_numeric_abbrev(self):
        events = [{
            "TimeCreated": "2026-04-19T12:34:56", "LogName": "x",
            "Level": 2, "LevelDisplayName": None, "Id": 1,
            "ProviderName": "p", "Message": "m",
        }]
        out = format_csv(events).splitlines()
        # No LevelDisplayName -> abbreviation from numeric Level=2 (Err)
        assert ",Err," in out[1]


# ─── CLI integration ────────────────────────────────────────────────────────


class TestEventlogsCli:
    def test_default_invocation(self, runner, mock_env, cfg):
        from winbox.cli import cli
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="[]", stderr=""
        )

        result = runner.invoke(cli, ["eventlogs"])

        assert result.exit_code == 0, result.output
        # Default output is CSV with header row
        assert "Time,Log,Level,Id,Provider,Message" in result.output
        mock_env.exec_powershell.assert_called_once()
        script = mock_env.exec_powershell.call_args[0][0]
        assert "LogName='Security'" in script
        assert "-MaxEvents 100" in script

    def test_multi_log_and_ids(self, runner, mock_env, cfg):
        from winbox.cli import cli
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="[]", stderr=""
        )

        result = runner.invoke(
            cli,
            ["eventlogs", "--log", "Security", "--log", "System",
             "--id", "4624", "--id", "4625", "--max", "10"],
        )

        assert result.exit_code == 0, result.output
        script = mock_env.exec_powershell.call_args[0][0]
        assert "LogName=@('Security','System')" in script
        assert "Id=@(4624,4625)" in script
        assert "-MaxEvents 10" in script

    def test_since_relative(self, runner, mock_env, cfg):
        from winbox.cli import cli
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="[]", stderr=""
        )
        before = datetime.now() - timedelta(minutes=30)

        runner.invoke(cli, ["eventlogs", "--since", "30m"])

        script = mock_env.exec_powershell.call_args[0][0]
        # Extract the ISO timestamp from the script
        import re
        m = re.search(r"StartTime=\[datetime\]'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'", script)
        assert m is not None
        parsed = datetime.fromisoformat(m.group(1))
        # Should be within 5 seconds of "30m ago"
        delta = abs((parsed - before).total_seconds())
        assert delta < 5

    def test_since_iso(self, runner, mock_env, cfg):
        from winbox.cli import cli
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="[]", stderr=""
        )

        result = runner.invoke(
            cli, ["eventlogs", "--since", "2026-04-19T10:00:00"]
        )

        assert result.exit_code == 0, result.output
        script = mock_env.exec_powershell.call_args[0][0]
        assert "StartTime=[datetime]'2026-04-19T10:00:00'" in script

    def test_level_filter(self, runner, mock_env, cfg):
        from winbox.cli import cli
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="[]", stderr=""
        )

        runner.invoke(cli, ["eventlogs", "--level", "Error"])

        script = mock_env.exec_powershell.call_args[0][0]
        assert "Level=2" in script

    def test_provider_filter(self, runner, mock_env, cfg):
        from winbox.cli import cli
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="[]", stderr=""
        )

        runner.invoke(
            cli, ["eventlogs", "--provider", "Microsoft-Windows-Sysmon"]
        )

        script = mock_env.exec_powershell.call_args[0][0]
        assert "ProviderName='Microsoft-Windows-Sysmon'" in script

    def test_json_output(self, runner, mock_env, cfg):
        from winbox.cli import cli
        events = [{"Id": 4624, "LogName": "Security"}]
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout=json.dumps(events), stderr=""
        )

        result = runner.invoke(cli, ["eventlogs", "--json"])

        assert result.exit_code == 0
        # JSON, not CSV
        assert '"Id": 4624' in result.output
        assert "Time,Log,Level" not in result.output

    def test_empty_results(self, runner, mock_env, cfg):
        from winbox.cli import cli
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )

        result = runner.invoke(cli, ["eventlogs"])

        assert result.exit_code == 0
        # CSV header still emitted, no data rows
        assert "Time,Log,Level,Id,Provider,Message" in result.output
        # Just header + trailing newline; no data row
        data_rows = [
            line for line in result.output.splitlines()
            if line and not line.startswith("Time,") and not line.startswith("[")
        ]
        assert data_rows == []

    def test_powershell_failure_surfaces(self, runner, mock_env, cfg):
        from winbox.cli import cli
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=1, stdout="", stderr="No events were found"
        )

        result = runner.invoke(cli, ["eventlogs"])

        assert result.exit_code == 1
        assert "No events were found" in result.output

    def test_invalid_since_rejected_before_vm_call(self, runner, mock_env, cfg):
        from winbox.cli import cli

        result = runner.invoke(cli, ["eventlogs", "--since", "yesterday"])

        assert result.exit_code != 0
        mock_env.exec_powershell.assert_not_called()

    def test_invalid_level_rejected(self, runner, mock_env, cfg):
        from winbox.cli import cli

        result = runner.invoke(cli, ["eventlogs", "--level", "Bogus"])

        assert result.exit_code != 0
        mock_env.exec_powershell.assert_not_called()

    def test_single_event_quirk_renders(self, runner, mock_env, cfg):
        """Get-WinEvent returning a bare object (not array) still renders."""
        from winbox.cli import cli
        single = {
            "TimeCreated": "2026-04-19T12:34:56",
            "LogName": "Security", "Level": 4, "LevelDisplayName": "Information",
            "Id": 4624, "ProviderName": "Microsoft-Windows-Security-Auditing",
            "Message": "Logon",
        }
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout=json.dumps(single), stderr=""
        )

        result = runner.invoke(cli, ["eventlogs"])

        assert result.exit_code == 0
        assert "1 event(s)" in result.output
        assert "4624" in result.output

    def test_csv_message_is_single_row_even_with_newlines(self, runner, mock_env, cfg):
        """Long multi-line Message must collapse to one CSV row, no embedded newlines."""
        from winbox.cli import cli
        ev = {
            "TimeCreated": "2026-04-19T12:34:56",
            "LogName": "Security", "Level": 4, "LevelDisplayName": "Information",
            "Id": 4672, "ProviderName": "Microsoft-Windows-Security-Auditing",
            "Message": "first\r\nsecond\r\nthird",
        }
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout=json.dumps(ev), stderr=""
        )

        result = runner.invoke(cli, ["eventlogs"])

        assert result.exit_code == 0
        data_rows = [
            line for line in result.output.splitlines()
            if line.startswith("2026-04-19")
        ]
        assert len(data_rows) == 1
        assert "first | second | third" in data_rows[0]


# ─── build_clear_powershell ─────────────────────────────────────────────────


class TestBuildClearPowershell:
    def test_single_log(self):
        ps = build_clear_powershell(["Security"])
        assert "@('Security')" in ps
        assert "wevtutil cl" in ps
        assert "wevtutil el" not in ps  # not enumerating

    def test_multi_log(self):
        ps = build_clear_powershell(["Security", "System"])
        assert "@('Security','System')" in ps

    def test_log_quote_escaped(self):
        ps = build_clear_powershell(["foo'bar"])
        assert "'foo''bar'" in ps

    def test_all_logs(self):
        ps = build_clear_powershell(all_logs=True)
        assert "wevtutil el" in ps
        assert "wevtutil cl" in ps

    def test_mutex_logs_and_all(self):
        with pytest.raises(ValueError, match="mutually exclusive"):
            build_clear_powershell(["Security"], all_logs=True)

    def test_neither_required(self):
        with pytest.raises(ValueError, match="required"):
            build_clear_powershell()

    def test_emits_json(self):
        ps = build_clear_powershell(["Security"])
        assert "ConvertTo-Json" in ps
        assert "cleared" in ps and "failed" in ps and "total" in ps


# ─── parse_clear_result ─────────────────────────────────────────────────────


class TestParseClearResult:
    def test_full(self):
        s = json.dumps({"cleared": 3, "failed": 1, "total": 4, "errors": ["x"]})
        assert parse_clear_result(s) == {
            "cleared": 3, "failed": 1, "total": 4, "errors": ["x"]
        }

    def test_empty_stdout(self):
        out = parse_clear_result("")
        assert out["cleared"] == 0 and out["failed"] == 0 and out["total"] == 0
        assert out["errors"] == []

    def test_missing_keys_filled(self):
        out = parse_clear_result(json.dumps({"cleared": 2}))
        assert out["failed"] == 0
        assert out["total"] == 0
        assert out["errors"] == []

    def test_string_errors_normalised_to_list(self):
        out = parse_clear_result(json.dumps({"errors": "single"}))
        assert out["errors"] == ["single"]

    def test_invalid_shape(self):
        with pytest.raises(ValueError, match="unexpected clear result"):
            parse_clear_result(json.dumps([1, 2, 3]))


# ─── CLI clear subcommand ──────────────────────────────────────────────────


class TestEventlogsClearCli:
    def test_requires_log_or_all(self, runner, mock_env, cfg):
        from winbox.cli import cli

        result = runner.invoke(cli, ["eventlogs", "clear"])

        assert result.exit_code != 0
        assert "or --all" in result.output
        mock_env.exec_powershell.assert_not_called()

    def test_log_and_all_mutex(self, runner, mock_env, cfg):
        from winbox.cli import cli

        result = runner.invoke(
            cli, ["eventlogs", "clear", "--log", "Security", "--all", "-y"]
        )

        assert result.exit_code != 0
        assert "mutually exclusive" in result.output
        mock_env.exec_powershell.assert_not_called()

    def test_clear_single_log_yes(self, runner, mock_env, cfg):
        from winbox.cli import cli
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout=json.dumps({"cleared": 1, "failed": 0, "total": 1, "errors": []}),
            stderr="",
        )

        result = runner.invoke(
            cli, ["eventlogs", "clear", "--log", "Security", "-y"]
        )

        assert result.exit_code == 0, result.output
        mock_env.exec_powershell.assert_called_once()
        script = mock_env.exec_powershell.call_args[0][0]
        assert "@('Security')" in script
        assert "wevtutil cl" in script
        assert "Cleared 1" in result.output

    def test_clear_multi_log(self, runner, mock_env, cfg):
        from winbox.cli import cli
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout=json.dumps({"cleared": 2, "failed": 0, "total": 2, "errors": []}),
            stderr="",
        )

        result = runner.invoke(
            cli,
            ["eventlogs", "clear", "--log", "Security", "--log", "System", "-y"],
        )

        assert result.exit_code == 0, result.output
        script = mock_env.exec_powershell.call_args[0][0]
        assert "@('Security','System')" in script

    def test_clear_all_yes(self, runner, mock_env, cfg):
        from winbox.cli import cli
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout=json.dumps({"cleared": 200, "failed": 50, "total": 250, "errors": []}),
            stderr="",
        )

        result = runner.invoke(cli, ["eventlogs", "clear", "--all", "-y"])

        assert result.exit_code == 0, result.output
        script = mock_env.exec_powershell.call_args[0][0]
        assert "wevtutil el" in script
        # all_logs failures are expected; do not surface as error exit
        assert "Cleared 200/250" in result.output

    def test_clear_specific_log_failure_exits_nonzero(self, runner, mock_env, cfg):
        """Per-log clear failure (e.g. ACCESS DENIED) should exit non-zero."""
        from winbox.cli import cli
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout=json.dumps({
                "cleared": 0, "failed": 1, "total": 1,
                "errors": ["Security: Access is denied."],
            }),
            stderr="",
        )

        result = runner.invoke(
            cli, ["eventlogs", "clear", "--log", "Security", "-y"]
        )

        assert result.exit_code != 0
        assert "Access is denied" in result.output

    def test_confirmation_required_without_yes(self, runner, mock_env, cfg):
        from winbox.cli import cli

        result = runner.invoke(
            cli, ["eventlogs", "clear", "--log", "Security"], input="n\n"
        )

        assert result.exit_code != 0
        mock_env.exec_powershell.assert_not_called()

    def test_confirmation_y_proceeds(self, runner, mock_env, cfg):
        from winbox.cli import cli
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout=json.dumps({"cleared": 1, "failed": 0, "total": 1, "errors": []}),
            stderr="",
        )

        result = runner.invoke(
            cli, ["eventlogs", "clear", "--log", "Security"], input="y\n"
        )

        assert result.exit_code == 0, result.output
        mock_env.exec_powershell.assert_called_once()


# ─── CLI eventlogs is now a group; default-no-subcommand still queries ──────


class TestEventlogsGroupBackwardsCompat:
    def test_no_subcommand_queries(self, runner, mock_env, cfg):
        from winbox.cli import cli
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="[]", stderr=""
        )

        result = runner.invoke(cli, ["eventlogs", "--since", "1h"])

        assert result.exit_code == 0, result.output
        # CSV header row is from the query path
        assert "Time,Log,Level,Id,Provider,Message" in result.output
        mock_env.exec_powershell.assert_called_once()


# ─── MCP tool ───────────────────────────────────────────────────────────────


@pytest.fixture
def mock_mcp_eventlogs(cfg):
    """Minimal MCP fixture for eventlogs - mocks _ensure_vm_ready."""
    import winbox.mcp as mcp_mod

    ga = MagicMock()
    vm = MagicMock()
    mcp_mod._cfg = cfg
    mcp_mod._vm = vm
    mcp_mod._ga = ga

    with patch.object(mcp_mod, "_ensure_vm_ready", return_value=(cfg, vm, ga)):
        yield ga

    mcp_mod._cfg = None
    mcp_mod._vm = None
    mcp_mod._ga = None


class TestMcpEventlogs:
    def test_defaults_return_json(self, mock_mcp_eventlogs):
        from winbox.mcp import eventlogs
        events = [{"Id": 4624, "LogName": "Security"}]
        mock_mcp_eventlogs.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout=json.dumps(events), stderr=""
        )

        result = eventlogs()

        parsed = json.loads(result)
        assert parsed == events
        script = mock_mcp_eventlogs.exec_powershell.call_args[0][0]
        assert "LogName='Security'" in script

    def test_string_log_arg(self, mock_mcp_eventlogs):
        from winbox.mcp import eventlogs
        mock_mcp_eventlogs.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="[]", stderr=""
        )

        eventlogs(log="System")

        script = mock_mcp_eventlogs.exec_powershell.call_args[0][0]
        assert "LogName='System'" in script

    def test_list_args(self, mock_mcp_eventlogs):
        from winbox.mcp import eventlogs
        mock_mcp_eventlogs.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="[]", stderr=""
        )

        eventlogs(
            log=["Microsoft-Windows-Sysmon/Operational"],
            ids=[1, 3, 7],
            level="Information",
            max_events=50,
        )

        script = mock_mcp_eventlogs.exec_powershell.call_args[0][0]
        assert "LogName='Microsoft-Windows-Sysmon/Operational'" in script
        assert "Id=@(1,3,7)" in script
        assert "Level=4" in script
        assert "-MaxEvents 50" in script

    def test_empty_result(self, mock_mcp_eventlogs):
        from winbox.mcp import eventlogs
        mock_mcp_eventlogs.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )

        assert json.loads(eventlogs()) == []

    def test_invalid_since(self, mock_mcp_eventlogs):
        from winbox.mcp import eventlogs

        result = eventlogs(since="yesterday")

        assert result.startswith("error:")
        mock_mcp_eventlogs.exec_powershell.assert_not_called()

    def test_powershell_error(self, mock_mcp_eventlogs):
        from winbox.mcp import eventlogs
        mock_mcp_eventlogs.exec_powershell.return_value = ExecResult(
            exitcode=1, stdout="", stderr="No events were found"
        )

        result = eventlogs()

        assert result.startswith("error (exit 1):")
        assert "No events were found" in result


# ─── MCP eventlogs_clear ────────────────────────────────────────────────────


class TestMcpEventlogsClear:
    def test_refuses_without_confirm(self, mock_mcp_eventlogs):
        from winbox.mcp import eventlogs_clear

        result = eventlogs_clear(log="Security")

        assert "refusing" in result
        assert "confirm=True" in result
        mock_mcp_eventlogs.exec_powershell.assert_not_called()

    def test_neither_log_nor_all(self, mock_mcp_eventlogs):
        from winbox.mcp import eventlogs_clear

        result = eventlogs_clear(confirm=True)

        assert result.startswith("error:")
        mock_mcp_eventlogs.exec_powershell.assert_not_called()

    def test_log_and_all_mutex(self, mock_mcp_eventlogs):
        from winbox.mcp import eventlogs_clear

        result = eventlogs_clear(log="Security", all_logs=True, confirm=True)

        assert "mutually exclusive" in result
        mock_mcp_eventlogs.exec_powershell.assert_not_called()

    def test_clear_single(self, mock_mcp_eventlogs):
        from winbox.mcp import eventlogs_clear
        mock_mcp_eventlogs.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout=json.dumps({"cleared": 1, "failed": 0, "total": 1, "errors": []}),
            stderr="",
        )

        out = eventlogs_clear(log="Security", confirm=True)
        info = json.loads(out)
        assert info == {"cleared": 1, "failed": 0, "total": 1, "errors": []}

        script = mock_mcp_eventlogs.exec_powershell.call_args[0][0]
        assert "@('Security')" in script

    def test_clear_list_arg(self, mock_mcp_eventlogs):
        from winbox.mcp import eventlogs_clear
        mock_mcp_eventlogs.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout=json.dumps({"cleared": 2, "failed": 0, "total": 2, "errors": []}),
            stderr="",
        )

        eventlogs_clear(log=["Security", "System"], confirm=True)

        script = mock_mcp_eventlogs.exec_powershell.call_args[0][0]
        assert "@('Security','System')" in script

    def test_clear_all(self, mock_mcp_eventlogs):
        from winbox.mcp import eventlogs_clear
        mock_mcp_eventlogs.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout=json.dumps({"cleared": 200, "failed": 50, "total": 250, "errors": []}),
            stderr="",
        )

        out = eventlogs_clear(all_logs=True, confirm=True)
        info = json.loads(out)
        assert info["total"] == 250
        assert info["failed"] == 50

        script = mock_mcp_eventlogs.exec_powershell.call_args[0][0]
        assert "wevtutil el" in script

    def test_powershell_error(self, mock_mcp_eventlogs):
        from winbox.mcp import eventlogs_clear
        mock_mcp_eventlogs.exec_powershell.return_value = ExecResult(
            exitcode=1, stdout="", stderr="boom"
        )

        out = eventlogs_clear(log="Security", confirm=True)
        assert out.startswith("error (exit 1):")
        assert "boom" in out
