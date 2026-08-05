"""Tests for winbox.executor — path resolution and the exec retry policy."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from winbox.exec.executor import resolve_exe, run_command
from winbox.vm.guest import (
    ExecResult,
    GuestAgentError,
    GuestAgentUnreachable,
    GuestExecAbandoned,
    GuestExecTimeout,
)


class TestResolveExe:
    def test_bare_exe_found_in_tools(self, tmp_path):
        (tmp_path / "SharpHound.exe").touch()
        assert resolve_exe("SharpHound.exe", tmp_path) == "Z:\\tools\\SharpHound.exe"

    def test_bare_exe_not_found(self, tmp_path):
        # Tool doesn't exist in tools dir — return as-is
        assert resolve_exe("Missing.exe", tmp_path) == "Missing.exe"

    def test_already_has_backslash_path(self, tmp_path):
        (tmp_path / "tool.exe").touch()
        assert resolve_exe("C:\\somewhere\\tool.exe", tmp_path) == "C:\\somewhere\\tool.exe"

    def test_already_has_forward_slash_path(self, tmp_path):
        (tmp_path / "tool.exe").touch()
        assert resolve_exe("/some/path/tool.exe", tmp_path) == "/some/path/tool.exe"

    def test_non_exe_passthrough(self, tmp_path):
        (tmp_path / "script.bat").touch()
        assert resolve_exe("script.bat", tmp_path) == "script.bat"

    def test_cmd_exe_not_resolved(self, tmp_path):
        # cmd.exe shouldn't be resolved to Z:\tools\ even if it hypothetically existed
        # but since it wouldn't be in tools_dir, it stays as-is
        assert resolve_exe("cmd.exe", tmp_path) == "cmd.exe"

    def test_exe_case_insensitive(self, tmp_path):
        (tmp_path / "Tool.EXE").touch()
        # .EXE should resolve just like .exe
        assert resolve_exe("Tool.EXE", tmp_path) == "Z:\\tools\\Tool.EXE"

    def test_exe_mixed_case(self, tmp_path):
        (tmp_path / "Rubeus.Exe").touch()
        assert resolve_exe("Rubeus.Exe", tmp_path) == "Z:\\tools\\Rubeus.Exe"

    def test_bare_exe_with_no_tools_dir(self):
        # Non-existent tools dir — can't resolve
        bogus = Path("/nonexistent/tools")
        assert resolve_exe("Rubeus.exe", bogus) == "Rubeus.exe"

    def test_local_path_copied_to_tools(self, tmp_path):
        # Simulate a local .exe outside tools dir
        local_dir = tmp_path / "downloads"
        local_dir.mkdir()
        local_exe = local_dir / "mimikatz.exe"
        local_exe.write_bytes(b"PE\x00\x00")

        tools_dir = tmp_path / "tools"
        tools_dir.mkdir()

        result = resolve_exe(str(local_exe), tools_dir)
        assert result == "Z:\\tools\\mimikatz.exe"
        assert (tools_dir / "mimikatz.exe").read_bytes() == b"PE\x00\x00"

    def test_local_path_already_in_tools(self, tmp_path):
        # File is already in tools dir — no redundant copy
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir()
        exe = tools_dir / "tool.exe"
        exe.write_bytes(b"orig")

        result = resolve_exe(str(exe), tools_dir)
        assert result == "Z:\\tools\\tool.exe"
        assert exe.read_bytes() == b"orig"

    def test_local_path_creates_tools_dir(self, tmp_path):
        local_exe = tmp_path / "thing.exe"
        local_exe.touch()

        tools_dir = tmp_path / "nonexistent" / "tools"
        result = resolve_exe(str(local_exe), tools_dir)
        assert result == "Z:\\tools\\thing.exe"
        assert (tools_dir / "thing.exe").exists()

    def test_local_path_nonexistent_file(self, tmp_path):
        # Linux-style path but file doesn't exist — pass through
        result = resolve_exe("/tmp/no_such_file.exe", tmp_path)
        assert result == "/tmp/no_such_file.exe"

    def test_local_relative_path(self, tmp_path, monkeypatch):
        # ./foo.exe style path
        local_exe = tmp_path / "foo.exe"
        local_exe.write_bytes(b"data")
        monkeypatch.chdir(tmp_path)

        tools_dir = tmp_path / "tools"
        tools_dir.mkdir()

        result = resolve_exe("./foo.exe", tools_dir)
        assert result == "Z:\\tools\\foo.exe"
        assert (tools_dir / "foo.exe").read_bytes() == b"data"


class TestRunCommandRetryPolicy:
    """The retry loop exists for one thing: the guest-agent pipe race, which
    fails before the guest process starts. Anything that means the command
    already ran must not be retried — `winbox exec installer.exe /S` running
    three partial installs off one command line is worse than one failure."""

    def _ga(self):
        ga = MagicMock()
        ga.exec.side_effect = None
        return ga

    def test_timeout_is_not_retried(self, cfg):
        """exec() taskkills the whole process tree on timeout, so a retry
        re-runs a half-finished, state-mutating command from scratch."""
        ga = self._ga()
        # The *type* is what marks this as already-run; matching the message
        # was the bug (libvirt says "operation timed out" for failures that
        # never launched anything).
        ga.exec.side_effect = GuestExecTimeout(
            "Command timed out after 60s (PID 4242)", pid=4242
        )

        with pytest.raises(GuestExecTimeout, match="timed out"):
            run_command(cfg, ga, "installer.exe", ("/S",), timeout=60)

        assert ga.exec.call_count == 1, (
            f"a timed-out command must run exactly once, ran {ga.exec.call_count} times"
        )

    def test_foreign_result_error_is_not_retried(self, cfg):
        """Same reasoning: the command executed, we just couldn't collect its
        output on a recycled PID."""
        ga = self._ga()
        ga.exec.side_effect = GuestExecAbandoned(
            "Could not obtain this command's own output on PID 4242 after 3 "
            "foreign results",
            pid=4242,
        )

        with pytest.raises(GuestExecAbandoned):
            run_command(cfg, ga, "installer.exe", (), timeout=60)

        assert ga.exec.call_count == 1

    def test_transient_ga_error_is_still_retried(self, cfg):
        """The pipe race this loop was built for must keep working."""
        ga = self._ga()
        ga.exec.side_effect = [
            # Pre-launch transport failure — nothing ran, so retry is free.
            GuestAgentUnreachable("Guest agent command failed: The handle is invalid."),
            ExecResult(exitcode=0, stdout="ok", stderr=""),
        ]

        rc = run_command(cfg, ga, "whoami.exe", (), timeout=60)

        assert rc == 0
        assert ga.exec.call_count == 2


class TestPreLaunchTimeoutTextIsStillRetried:
    """libvirt renders its own pre-launch failures as "operation timed out".

    The old classifier matched on that substring, so a transport failure that
    never started anything was treated as "already ran" and the retry loop —
    the entire reason this code exists — silently switched itself off.
    """

    def test_libvirt_operation_timeout_is_retried(self, cfg):
        ga = MagicMock()
        ga.exec.side_effect = [
            GuestAgentUnreachable(
                "Guest agent command failed: error: operation timed out"
            ),
            ExecResult(exitcode=0, stdout="ok", stderr=""),
        ]

        rc = run_command(cfg, ga, "whoami.exe", (), timeout=60)

        assert rc == 0
        assert ga.exec.call_count == 2, (
            "a pre-launch failure whose message says 'timed out' must still "
            "be retried — nothing ran"
        )
