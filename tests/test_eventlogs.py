"""Tests for winbox eventlogs (core + CLI + MCP)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from winbox.eventlogs import (
    EventQuery,
    build_powershell,
    format_compact_table,
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


# ─── format_compact_table ───────────────────────────────────────────────────


class TestFormatCompactTable:
    def test_columns(self):
        table = format_compact_table([])
        headers = [c.header for c in table.columns]
        assert headers == ["Time", "Log", "Lvl", "Id", "Provider", "Message"]

    def test_row_count(self):
        events = [
            {"TimeCreated": "2026-04-19T12:34:56", "LogName": "Security",
             "Level": 4, "LevelDisplayName": "Information", "Id": 4624,
             "ProviderName": "Microsoft-Windows-Security-Auditing",
             "Message": "Logon"},
            {"TimeCreated": "2026-04-19T12:35:00", "LogName": "System",
             "Level": 3, "LevelDisplayName": "Warning", "Id": 1,
             "ProviderName": "Foo", "Message": "x"},
        ]
        table = format_compact_table(events)
        assert table.row_count == 2

    def test_message_newlines_collapse(self):
        events = [{
            "TimeCreated": "2026-04-19T12:34:56",
            "LogName": "Security", "Level": 4, "LevelDisplayName": "Information",
            "Id": 1, "ProviderName": "x",
            "Message": "line one\nline two\n\nline three",
        }]
        table = format_compact_table(events)
        # The message cell ends up in the underlying row tuple
        cells = list(table.columns[-1].cells)
        assert "line one | line two | line three" in cells[0]

    def test_level_abbrev(self):
        events = [{
            "TimeCreated": "2026-04-19T12:34:56", "LogName": "x",
            "Level": 2, "LevelDisplayName": "Error", "Id": 1,
            "ProviderName": "p", "Message": "m",
        }]
        table = format_compact_table(events)
        cells = list(table.columns[2].cells)
        assert cells[0] == "Err"


# ─── CLI integration ────────────────────────────────────────────────────────


class TestEventlogsCli:
    def test_default_invocation(self, runner, mock_env, cfg):
        from winbox.cli import cli
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="[]", stderr=""
        )

        result = runner.invoke(cli, ["eventlogs"])

        assert result.exit_code == 0, result.output
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
        # Output contains JSON, not a Rich table
        assert '"Id": 4624' in result.output
        assert "Time " not in result.output  # no header row

    def test_empty_results(self, runner, mock_env, cfg):
        from winbox.cli import cli
        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )

        result = runner.invoke(cli, ["eventlogs"])

        assert result.exit_code == 0
        assert "No matching events" in result.output

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
