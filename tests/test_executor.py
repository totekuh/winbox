"""Tests for winbox.executor — path resolution and the exec retry policy."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from winbox.exec.executor import resolve_exe, run_command, run_command_bg
from winbox.vm.guest import (
    ExecResult,
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


class TestRunCommandQuoting:
    """cmd.exe re-splits any unquoted whitespace into extra arguments, so a
    spacey exe path or argument must be wrapped in double quotes before it
    reaches ga.exec — otherwise `winbox exec tool.exe --path "C:\\Program
    Files\\Target"` arrives in the guest as four arguments instead of two."""

    def _ga(self):
        ga = MagicMock()
        ga.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")
        return ga

    def test_spacey_argument_is_quoted(self, cfg):
        ga = self._ga()
        run_command(cfg, ga, "whoami.exe", ("C:\\Program Files\\Target",), timeout=60)
        full_cmd = ga.exec.call_args[0][0]
        assert '"C:\\Program Files\\Target"' in full_cmd

    def test_spacey_resolved_exe_path_is_quoted(self, cfg):
        (cfg.tools_dir / "PsExec (v2).exe").touch()
        ga = self._ga()
        run_command(cfg, ga, "PsExec (v2).exe", (), timeout=60)
        full_cmd = ga.exec.call_args[0][0]
        assert '"Z:\\tools\\PsExec (v2).exe"' in full_cmd

    def test_argument_without_whitespace_is_not_quoted(self, cfg):
        ga = self._ga()
        run_command(cfg, ga, "whoami.exe", ("/priv",), timeout=60)
        full_cmd = ga.exec.call_args[0][0]
        assert full_cmd.endswith("whoami.exe /priv")

    def test_bg_spacey_argument_is_quoted(self, cfg):
        ga = MagicMock()
        ga.exec_background.return_value = 1234
        run_command_bg(cfg, ga, "whoami.exe", ("C:\\Program Files\\Target",))
        full_cmd = ga.exec_background.call_args[0][0]
        assert '"C:\\Program Files\\Target"' in full_cmd


class TestRunCommandRetryPolicy:
    """run_command retries exactly one thing: the *post-launch* pipe race, where
    the process started but its stdio handle broke and 'handle is invalid' comes
    back inside the command's own output. Launch-transport retries live one layer
    down in GuestAgent.exec; anything that means the command already ran
    (timeout/abandoned) must propagate untouched — `winbox exec installer.exe /S`
    running three partial installs off one command line is worse than one
    failure."""

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

    def test_post_launch_pipe_race_in_output_is_retried(self, cfg):
        """The one retry run_command still owns: a *post-launch* pipe race,
        where the process launched but its stdio handle broke and 'handle is
        invalid' rides back inside the command's own output. (Launch-transport
        retries moved down into GuestAgent.exec.)"""
        ga = self._ga()
        ga.exec.side_effect = [
            ExecResult(exitcode=1, stdout="The handle is invalid.\n", stderr=""),
            ExecResult(exitcode=0, stdout="ok", stderr=""),
        ]

        rc = run_command(cfg, ga, "whoami.exe", (), timeout=60)

        assert rc == 0
        assert ga.exec.call_count == 2

    def test_launch_exception_is_not_re_retried(self, cfg):
        """A launch-transport failure escaping ga.exec has already been retried
        inside exec (_start_guest_exec); run_command must not wrap it in a
        second retry loop — that stacked the two into up to 9 attempts."""
        ga = self._ga()
        ga.exec.side_effect = GuestAgentUnreachable(
            "Guest agent command failed: error: operation timed out"
        )

        with pytest.raises(GuestAgentUnreachable):
            run_command(cfg, ga, "whoami.exe", (), timeout=60)

        assert ga.exec.call_count == 1


class TestCredentialedExecCli:
    def test_forwards_user_and_password(self, runner, mock_env):
        from winbox.cli import cli

        with patch("winbox.cli.exec.run_command", return_value=0) as run:
            result = runner.invoke(
                cli,
                ["exec", "--user", "alice", "--password", "p&ss word", "whoami"],
            )

        assert result.exit_code == 0
        assert run.call_args.kwargs["user"] == "alice"
        assert run.call_args.kwargs["password"] == "p&ss word"

    @pytest.mark.parametrize(
        "options", [["--user", "alice"], ["--password", "secret"]],
    )
    def test_requires_both_options(self, runner, mock_env, options):
        from winbox.cli import cli

        result = runner.invoke(cli, ["exec", *options, "whoami"])

        assert result.exit_code != 0
        assert "must be supplied together" in result.output

    def test_background_forwards_credentials(self, runner, mock_env):
        from winbox.cli import cli
        from winbox.jobs import Job, JobMode

        job = Job(1, 123, "whoami", JobMode.BUFFERED)
        with patch("winbox.cli.exec.run_command_bg", return_value=job) as run:
            result = runner.invoke(
                cli,
                [
                    "exec", "--user", "alice", "--password", "secret",
                    "--bg", "whoami",
                ],
            )

        assert result.exit_code == 0
        assert run.call_args.kwargs["user"] == "alice"
        assert run.call_args.kwargs["password"] == "secret"
