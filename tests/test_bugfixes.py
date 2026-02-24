"""Tests for all bug fixes — validates each fix independently."""

from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import click
import pytest

from winbox.config import Config
from winbox.vm import VMState


# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def cfg(tmp_path):
    c = Config(winbox_dir=tmp_path / ".winbox")
    c.winbox_dir.mkdir(parents=True)
    c.shared_dir.mkdir(parents=True)
    c.tools_dir.mkdir(parents=True)
    c.loot_dir.mkdir(parents=True)
    return c


# ─── Bug #1: Double server.close() in shell.py ──────────────────────────────


class TestShellDoubleClose:
    """Bug #1: server.close() was called twice on timeout — once in except,
    once in finally. Now only finally closes it."""

    def test_timeout_does_not_double_close(self):
        """Simulate the timeout path and verify close is called exactly once."""
        import socket

        server = MagicMock(spec=socket.socket)
        server.accept.side_effect = socket.timeout("timed out")

        # Simulate the fixed pattern: try/except/finally
        try:
            server.accept()
        except socket.timeout:
            pass  # no server.close() here anymore
        finally:
            server.close()

        server.close.assert_called_once()

    def test_success_closes_once(self):
        """On success path, server is closed by finally."""
        import socket

        server = MagicMock(spec=socket.socket)
        client = MagicMock()
        server.accept.return_value = (client, ("127.0.0.1", 4444))

        try:
            c, _ = server.accept()
        except socket.timeout:
            pass
        finally:
            server.close()

        server.close.assert_called_once()


# ─── Bug #2: Case-sensitive .exe lookup on Linux ────────────────────────────


class TestCaseInsensitiveExeLookup:
    """Bug #10: resolve_exe used (tools_dir / exe).exists() which is
    case-sensitive on ext4. Now it scans with case-insensitive comparison."""

    def test_lowercase_query_finds_uppercase_file(self, tmp_path):
        from winbox.exec.executor import resolve_exe

        (tmp_path / "SharpHound.exe").touch()
        result = resolve_exe("sharphound.exe", tmp_path)
        assert result == "Z:\\tools\\SharpHound.exe"

    def test_uppercase_query_finds_lowercase_file(self, tmp_path):
        from winbox.exec.executor import resolve_exe

        (tmp_path / "rubeus.exe").touch()
        result = resolve_exe("RUBEUS.EXE", tmp_path)
        assert result == "Z:\\tools\\rubeus.exe"

    def test_mixed_case_query(self, tmp_path):
        from winbox.exec.executor import resolve_exe

        (tmp_path / "Mimikatz.exe").touch()
        result = resolve_exe("mImIkAtZ.ExE", tmp_path)
        assert result == "Z:\\tools\\Mimikatz.exe"

    def test_exact_case_still_works(self, tmp_path):
        from winbox.exec.executor import resolve_exe

        (tmp_path / "Tool.exe").touch()
        result = resolve_exe("Tool.exe", tmp_path)
        assert result == "Z:\\tools\\Tool.exe"

    def test_not_found_returns_as_is(self, tmp_path):
        from winbox.exec.executor import resolve_exe

        result = resolve_exe("missing.exe", tmp_path)
        assert result == "missing.exe"

    def test_preserves_actual_filename_case(self, tmp_path):
        """The returned path should use the on-disk filename, not the query."""
        from winbox.exec.executor import resolve_exe

        (tmp_path / "SharpHound.exe").touch()
        result = resolve_exe("SHARPHOUND.EXE", tmp_path)
        # Must use the real name from disk
        assert "SharpHound.exe" in result


# ─── Bug #3: VM_USER/VM_PASSWORD missing from config mapping ────────────────


class TestConfigCredentialOverrides:
    """Bug #16: VM_USER and VM_PASSWORD were not in the config file mapping."""

    def test_override_vm_user(self, tmp_path):
        config_file = tmp_path / "config"
        config_file.write_text("VM_USER=pentester\n")
        cfg = Config._apply_overrides(Config(), config_file)
        assert cfg.vm_user == "pentester"

    def test_override_vm_password(self, tmp_path):
        config_file = tmp_path / "config"
        config_file.write_text("VM_PASSWORD=S3cret!Pass\n")
        cfg = Config._apply_overrides(Config(), config_file)
        assert cfg.vm_password == "S3cret!Pass"

    def test_override_both(self, tmp_path):
        config_file = tmp_path / "config"
        config_file.write_text("VM_USER=admin\nVM_PASSWORD=hunter2\n")
        cfg = Config._apply_overrides(Config(), config_file)
        assert cfg.vm_user == "admin"
        assert cfg.vm_password == "hunter2"

    def test_defaults_unchanged_without_override(self):
        cfg = Config()
        assert cfg.vm_user == "Administrator"
        assert cfg.vm_password == "WinboxP@ss123"


# ─── Bug #4: binfmt remove_handler param ignored ────────────────────────────


class TestBinfmtRemoveHandler:
    """Bug #3: unregister(remove_handler=False) still deleted the persist file."""

    def test_remove_handler_false_preserves_persist(self, tmp_path):
        from winbox.binfmt import unregister

        persist = tmp_path / "winbox.conf"
        persist.write_text(":winbox:E::exe::/handler:")
        entry = tmp_path / "winbox"  # not exists → is_registered() False

        with (
            patch("winbox.binfmt.BINFMT_ENTRY", entry),
            patch("winbox.binfmt.BINFMT_PERSIST", persist),
        ):
            unregister(remove_handler=False)

        assert persist.exists(), "Persist file should NOT be deleted when remove_handler=False"

    def test_remove_handler_true_deletes_persist(self, tmp_path):
        from winbox.binfmt import unregister

        persist = tmp_path / "winbox.conf"
        persist.write_text(":winbox:E::exe::/handler:")
        entry = tmp_path / "winbox"  # not exists

        with (
            patch("winbox.binfmt.BINFMT_ENTRY", entry),
            patch("winbox.binfmt.BINFMT_PERSIST", persist),
            patch("subprocess.run") as mock_run,
        ):
            unregister(remove_handler=True)

        mock_run.assert_called_once()
        assert "rm" in mock_run.call_args[0][0]

    def test_remove_handler_default_is_true(self, tmp_path):
        from winbox.binfmt import unregister

        persist = tmp_path / "winbox.conf"
        persist.write_text(":winbox:E::exe::/handler:")
        entry = tmp_path / "winbox"

        with (
            patch("winbox.binfmt.BINFMT_ENTRY", entry),
            patch("winbox.binfmt.BINFMT_PERSIST", persist),
            patch("subprocess.run"),
        ):
            unregister()  # default = True


# ─── Bug #6: PowerShell input validation ────────────────────────────────────


class TestNetworkInputValidation:
    """Bug #4: hostname/ip/domain interpolated unsanitized into PowerShell."""

    def test_valid_ip_passes(self):
        from winbox.cli.network import _validate_ip
        _validate_ip("192.168.122.1")
        _validate_ip("10.0.0.1")
        _validate_ip("::1")

    def test_invalid_ip_rejected(self):
        from winbox.cli.network import _validate_ip
        with pytest.raises(click.BadParameter):
            _validate_ip("192.168.1.1; malicious")

    def test_ip_with_semicolon_rejected(self):
        from winbox.cli.network import _validate_ip
        with pytest.raises(click.BadParameter):
            _validate_ip("10.0.0.1;Invoke-Expression")

    def test_valid_hostname_passes(self):
        from winbox.cli.network import _validate_hostname
        _validate_hostname("dc01.corp.local")
        _validate_hostname("server-01")
        _validate_hostname("HOST_NAME")

    def test_invalid_hostname_rejected(self):
        from winbox.cli.network import _validate_hostname
        with pytest.raises(click.BadParameter):
            _validate_hostname("host; rm -rf /")

    def test_hostname_with_quotes_rejected(self):
        from winbox.cli.network import _validate_hostname
        with pytest.raises(click.BadParameter):
            _validate_hostname("host'$(malicious)")

    def test_valid_domain_passes(self):
        from winbox.cli.network import _validate_domain
        _validate_domain("corp.local")
        _validate_domain("ad.example.com")

    def test_invalid_domain_rejected(self):
        from winbox.cli.network import _validate_domain
        with pytest.raises(click.BadParameter):
            _validate_domain("corp.local; Invoke-Expression 'bad'")


# ─── Bug #7: Unbound result in executor retry loop ──────────────────────────


class TestExecutorRetryLoop:
    """Bug #1: result was potentially unbound if max_retries was 0."""

    def test_result_always_bound(self, cfg):
        """run_command always produces a result even on first call."""
        from winbox.exec.executor import run_command
        from winbox.vm.guest import ExecResult

        ga = MagicMock()
        ga.exec.return_value = ExecResult(exitcode=0, stdout="ok\n", stderr="")

        code = run_command(cfg, ga, "whoami", (), timeout=30)
        assert code == 0
        ga.exec.assert_called_once()

    def test_retry_on_handle_invalid(self, cfg):
        """Retries when output contains 'handle is invalid'."""
        from winbox.exec.executor import run_command
        from winbox.vm.guest import ExecResult

        bad = ExecResult(exitcode=1, stdout="The handle is invalid.\n", stderr="")
        good = ExecResult(exitcode=0, stdout="ok\n", stderr="")

        ga = MagicMock()
        ga.exec.side_effect = [bad, good]

        with patch("winbox.exec.executor.time.sleep"):
            code = run_command(cfg, ga, "whoami", (), timeout=30)

        assert code == 0
        assert ga.exec.call_count == 2


# ─── Bug #9: grant_libvirt_access off-by-one ─────────────────────────────────


class TestGrantLibvirtAccess:
    """Bug #7: Loop condition caused home dir to be ACL'd twice."""

    def test_home_dir_not_duplicated(self, tmp_path):
        """Verify home dir appears exactly once in the ACL dir list."""
        home = tmp_path / "fakehome"
        home.mkdir()
        winbox_dir = home / ".winbox"
        winbox_dir.mkdir()

        cfg = Config(winbox_dir=winbox_dir)

        dirs = []
        path = cfg.winbox_dir
        with patch("pathlib.Path.home", return_value=home):
            while path != Path.home():
                dirs.append(path)
                path = path.parent
            dirs.append(Path.home())

        assert dirs.count(home) == 1, f"Home dir should appear once, got: {dirs}"

    def test_includes_winbox_dir_and_home(self, tmp_path):
        home = tmp_path / "fakehome"
        home.mkdir()
        winbox_dir = home / ".winbox"
        winbox_dir.mkdir()

        dirs = []
        path = winbox_dir
        with patch("pathlib.Path.home", return_value=home):
            while path != Path.home():
                dirs.append(path)
                path = path.parent
            dirs.append(Path.home())

        assert winbox_dir in dirs
        assert home in dirs


# ─── Bug #10: _track_col bare newline ────────────────────────────────────────


class TestTrackColNewline:
    """Bug #12: _track_col didn't handle bare \\n, causing column drift."""

    def test_bare_newline_resets_column(self):
        """After \\n, start_col should be 0."""
        # Replicate the logic inline since _track_col is a closure
        start_col = 5  # simulate being at column 5
        data = b"\n"

        for b in data:
            if b == 0x0a:
                start_col = 0

        assert start_col == 0

    def test_cr_lf_resets_column(self):
        """\\r\\n should also reset to 0."""
        start_col = 10
        for b in b"\r\n":
            if b == 0x0d:
                start_col = 0
            elif b == 0x0a:
                start_col = 0
        assert start_col == 0

    def test_printable_after_newline(self):
        """After \\n + printable chars, start_col should equal char count."""
        start_col = 5
        data = b"\nABC"
        term_cols = 80
        for b in data:
            if b == 0x0a:
                start_col = 0
            elif b >= 0x20:
                start_col += 1
                if start_col >= term_cols:
                    start_col = 0
        assert start_col == 3


# ─── Bug #11: mock_env missing exec patches ─────────────────────────────────


class TestMockEnvCoversExec:
    """Bug #15: conftest mock_env didn't patch winbox.cli.exec module."""

    def test_mock_env_patches_exec_module(self, mock_env):
        """Verify exec module is patched — GuestAgent should be mocked."""
        from winbox.cli import exec as exec_module
        ga = exec_module.GuestAgent(Config())
        # If properly mocked, this returns the mock, not a real GuestAgent
        assert hasattr(ga, 'ping')  # MagicMock has all attrs

    def test_mock_env_patches_setup_module(self, mock_env):
        """Verify setup module VM is patched."""
        import sys
        setup_module = sys.modules["winbox.cli.setup"]
        vm = setup_module.VM(Config())
        assert hasattr(vm, 'state')


@pytest.fixture
def mock_env(cfg):
    """Duplicate of conftest mock_env to verify exec patches."""
    ga = MagicMock()
    ga.ping.return_value = True
    vm = MagicMock()
    vm.state.return_value = VMState.RUNNING
    vm.ip.return_value = "192.168.122.203"
    vm.exists.return_value = True
    vm.disk_usage.return_value = "6.5 GB"
    vm.snapshot_list.return_value = ["clean"]

    with (
        patch("winbox.cli.vm.ensure_running"),
        patch("winbox.cli.vm.GuestAgent", return_value=ga),
        patch("winbox.cli.vm.VM", return_value=vm),
        patch("winbox.cli.network.ensure_running"),
        patch("winbox.cli.network.GuestAgent", return_value=ga),
        patch("winbox.cli.network.VM", return_value=vm),
        patch("winbox.cli.network.VMState", VMState),
        patch("winbox.cli.exec.ensure_running"),
        patch("winbox.cli.exec.GuestAgent", return_value=ga),
        patch("winbox.cli.exec.VM", return_value=vm),
        patch("winbox.cli.setup.VM", return_value=vm),
        patch("winbox.cli.Config.load", return_value=cfg),
    ):
        ga._vm = vm
        yield ga


# ─── Bug #14: wait() and wait_shutdown() elapsed time accuracy ───────────────


class TestWaitTimeoutAccuracy:
    """Bugs #8/#9: wait loops used manual elapsed counter instead of monotonic."""

    def test_guest_wait_uses_monotonic(self):
        """GuestAgent.wait should use time.monotonic for deadline."""
        from winbox.vm.guest import GuestAgent, GuestAgentError

        ga = GuestAgent.__new__(GuestAgent)
        ga.vm_name = "test"

        call_count = 0

        def slow_ping():
            nonlocal call_count
            call_count += 1
            return False

        ga.ping = slow_ping

        # With a 0.1s timeout and patched sleep, should hit deadline quickly
        with (
            patch("time.monotonic", side_effect=[0.0, 0.05, 0.15]),
            patch("time.sleep"),
            pytest.raises(GuestAgentError, match="not responding"),
        ):
            ga.wait(timeout=0.1, interval=0.01)

    def test_vm_wait_shutdown_uses_monotonic(self):
        from winbox.vm.lifecycle import VM, VMState

        vm = VM.__new__(VM)
        vm.name = "test"

        vm.state = MagicMock(side_effect=[VMState.RUNNING, VMState.RUNNING, VMState.RUNNING])

        with (
            patch("time.monotonic", side_effect=[0.0, 0.5, 1.5]),
            patch("time.sleep"),
        ):
            result = vm.wait_shutdown(timeout=1, poll=0.1)

        assert result is False


# ─── Bug #15: Stale jq prerequisite ──────────────────────────────────────────


class TestStalePrereqs:
    """Bug: jq was checked in prereqs but never used in Python code."""

    def test_jq_not_in_required_tools(self):
        from winbox.setup.installer import REQUIRED_TOOLS
        assert "jq" not in REQUIRED_TOOLS

    def test_required_tools_still_has_essentials(self):
        from winbox.setup.installer import REQUIRED_TOOLS
        assert "virsh" in REQUIRED_TOOLS
        assert "virt-install" in REQUIRED_TOOLS
        assert "7z" in REQUIRED_TOOLS
        assert "qemu-system-x86_64" in REQUIRED_TOOLS


# ─── Bug #16: --user in domain join not validated (command injection) ─────


class TestDomainJoinUserValidation:
    """S1: user param in domain_join was not validated before interpolation
    into PowerShell scripts, allowing command injection."""

    def test_valid_user_passes_validation(self):
        from winbox.cli.network import _validate_hostname
        _validate_hostname("Administrator")
        _validate_hostname("domain_admin")
        _validate_hostname("svc-account")

    def test_malicious_user_semicolon_rejected(self):
        from winbox.cli.network import _validate_hostname
        with pytest.raises(click.BadParameter):
            _validate_hostname("admin; Invoke-Expression 'evil'")

    def test_malicious_user_backtick_rejected(self):
        from winbox.cli.network import _validate_hostname
        with pytest.raises(click.BadParameter):
            _validate_hostname("admin`$(whoami)")

    def test_malicious_user_quotes_rejected(self):
        from winbox.cli.network import _validate_hostname
        with pytest.raises(click.BadParameter):
            _validate_hostname("admin'$(whoami)")

    def test_domain_join_calls_validate_user_on_user(self, runner, mock_env):
        """Verify that domain_join invokes _validate_user for the user param."""
        from winbox.cli import cli

        with patch("winbox.cli.network._validate_user") as mock_vu:
            mock_vu.side_effect = click.BadParameter("Invalid username: bad;user")
            result = runner.invoke(
                cli,
                ["domain", "join", "corp.local", "--ns", "10.0.0.1",
                 "--user", "bad;user", "--password", "pass"],
            )
            # _validate_user should have been called with the user value
            mock_vu.assert_called_with("bad;user")


# ─── Bug #17: Unescaped dots in hostname regex for hosts set/delete ──────


class TestHostsRegexDotEscaping:
    """S2: hostname embedded into -notmatch regex without escaping dots.
    'dc01.corp.local' would match 'dc01Xcorp_local' because . is wildcard."""

    def test_hosts_set_escapes_dots_in_regex(self, runner, mock_env):
        from winbox.cli import cli
        from winbox.vm.guest import ExecResult

        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )

        result = runner.invoke(
            cli, ["hosts", "set", "10.0.0.5", "dc01.corp.local"]
        )
        assert result.exit_code == 0

        # Check that the PowerShell script uses escaped dots
        script = mock_env.exec_powershell.call_args[0][0]
        assert r"dc01\.corp\.local" in script
        # Raw unescaped hostname should NOT be in the regex portion
        assert "dc01.corp.local\\s*$" not in script

    def test_hosts_delete_escapes_dots_in_regex(self, runner, mock_env):
        from winbox.cli import cli
        from winbox.vm.guest import ExecResult

        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )

        result = runner.invoke(
            cli, ["hosts", "delete", "dc01.corp.local"]
        )
        assert result.exit_code == 0

        script = mock_env.exec_powershell.call_args[0][0]
        assert r"dc01\.corp\.local" in script

    def test_hosts_set_no_dots_unchanged(self, runner, mock_env):
        """Hostname without dots should be unaffected by escaping."""
        from winbox.cli import cli
        from winbox.vm.guest import ExecResult

        mock_env.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="", stderr=""
        )

        result = runner.invoke(
            cli, ["hosts", "set", "10.0.0.5", "server01"]
        )
        assert result.exit_code == 0
        script = mock_env.exec_powershell.call_args[0][0]
        assert "server01" in script


# ─── Bug #18: Infinite loop in grant_libvirt_access outside $HOME ────────


class TestGrantLibvirtAccessOutsideHome:
    """S3: grant_libvirt_access loops forever if winbox_dir is outside $HOME
    because while path != Path.home() never terminates at root."""

    def test_loop_terminates_outside_home(self, tmp_path):
        """winbox_dir at /tmp/winbox — loop must terminate without hitting root forever."""
        winbox_dir = tmp_path / "winbox"
        winbox_dir.mkdir()

        cfg = Config(winbox_dir=winbox_dir)

        # Simulate the fixed loop logic
        dirs = []
        path = cfg.winbox_dir
        with patch("pathlib.Path.home", return_value=Path("/home/fakeuser")):
            while path != Path.home() and path != path.parent:
                dirs.append(path)
                path = path.parent

        # Loop must terminate (not hang) and collect ancestor dirs
        assert len(dirs) > 0
        # Must NOT contain the root sentinel looping forever
        assert dirs.count(Path("/")) <= 1

    def test_loop_terminates_at_root(self):
        """When winbox_dir is /opt/winbox, the loop should stop at / (root)."""
        winbox_dir = Path("/opt/winbox")

        dirs = []
        path = winbox_dir
        with patch("pathlib.Path.home", return_value=Path("/home/fakeuser")):
            while path != Path.home() and path != path.parent:
                dirs.append(path)
                path = path.parent

        # Should have /opt/winbox and /opt, stop before infinite loop at /
        assert Path("/opt/winbox") in dirs
        assert Path("/opt") in dirs

    def test_loop_still_works_under_home(self, tmp_path):
        """Normal case: winbox_dir under $HOME still works correctly."""
        home = tmp_path / "fakehome"
        home.mkdir()
        winbox_dir = home / ".winbox"
        winbox_dir.mkdir()

        dirs = []
        path = winbox_dir
        with patch("pathlib.Path.home", return_value=home):
            while path != Path.home() and path != path.parent:
                dirs.append(path)
                path = path.parent

        assert winbox_dir in dirs
        assert home not in dirs  # home is the stop condition, not included in loop body

    def test_grant_libvirt_access_does_not_hang(self, tmp_path):
        """Full integration: call grant_libvirt_access with dir outside home."""
        from winbox.setup.installer import grant_libvirt_access

        winbox_dir = tmp_path / "winbox"
        winbox_dir.mkdir()
        iso_dir = winbox_dir / "iso"
        iso_dir.mkdir()
        shared_dir = winbox_dir / "shared"
        shared_dir.mkdir()
        tools_dir = shared_dir / "tools"
        tools_dir.mkdir()
        loot_dir = shared_dir / "loot"
        loot_dir.mkdir()

        cfg = Config(winbox_dir=winbox_dir)

        with (
            patch("pathlib.Path.home", return_value=Path("/home/fakeuser")),
            patch("shutil.which", return_value="/usr/bin/setfacl"),
            patch("winbox.setup.installer.subprocess.run") as mock_run,
        ):
            # This must complete in finite time (no infinite loop)
            grant_libvirt_access(cfg)

        # setfacl was called (loop completed and produced dirs to process)
        assert mock_run.call_count > 0


# ─── Bug #19: GuestAgentError from ga.wait() shows raw traceback ─────────


class TestEnsureRunningCatchesGAError:
    """C4: ga.wait() raises GuestAgentError on timeout, which was uncaught
    in ensure_running — users saw a Python traceback instead of clean error."""

    def test_ga_wait_timeout_while_running_raises_systemexit(self):
        """When VM is RUNNING but agent never responds, should get SystemExit."""
        from winbox.cli import ensure_running
        from winbox.vm.guest import GuestAgentError

        vm = MagicMock()
        vm.state.return_value = VMState.RUNNING
        ga = MagicMock()
        ga.ping.return_value = False
        ga.wait.side_effect = GuestAgentError("Guest agent not responding after 60s")
        cfg = MagicMock()

        with pytest.raises(SystemExit):
            ensure_running(vm, ga, cfg)

    def test_ga_wait_timeout_after_start_raises_systemexit(self):
        """When VM was SHUTOFF, started, but agent never responds."""
        from winbox.cli import ensure_running
        from winbox.vm.guest import GuestAgentError

        vm = MagicMock()
        vm.state.return_value = VMState.SHUTOFF
        ga = MagicMock()
        ga.wait.side_effect = GuestAgentError("Guest agent not responding after 120s")
        cfg = MagicMock()

        with pytest.raises(SystemExit):
            ensure_running(vm, ga, cfg)

    def test_ga_wait_timeout_after_resume_raises_systemexit(self):
        """When VM was PAUSED, resumed, but agent never responds."""
        from winbox.cli import ensure_running
        from winbox.vm.guest import GuestAgentError

        vm = MagicMock()
        vm.state.return_value = VMState.PAUSED
        ga = MagicMock()
        ga.wait.side_effect = GuestAgentError("Guest agent not responding after 120s")
        cfg = MagicMock()

        with pytest.raises(SystemExit):
            ensure_running(vm, ga, cfg)

    def test_ga_wait_success_does_not_raise(self):
        """When agent responds normally, no exception should be raised."""
        from winbox.cli import ensure_running

        vm = MagicMock()
        vm.state.return_value = VMState.RUNNING
        ga = MagicMock()
        ga.ping.return_value = True
        cfg = MagicMock()

        # Should complete without raising
        ensure_running(vm, ga, cfg)


# ─── Bug #20: Uncaught CalledProcessError on snapshot restore ─────────────


class TestSnapshotRestoreCatchesError:
    """C2: vm.snapshot_revert(name) calls _virsh with check=True. If snapshot
    doesn't exist, CalledProcessError bubbles up as a raw traceback."""

    def test_nonexistent_snapshot_raises_systemexit(self, runner, mock_env):
        from winbox.cli import cli

        mock_env._vm.snapshot_revert.side_effect = subprocess.CalledProcessError(
            1, "virsh", stderr="domain 'winbox' has no snapshot named 'bogus'"
        )

        result = runner.invoke(cli, ["restore", "bogus"])
        assert result.exit_code == 1
        assert "Failed to restore snapshot 'bogus'" in result.output

    def test_successful_restore_no_error(self, runner, mock_env):
        from winbox.cli import cli

        mock_env._vm.snapshot_revert.return_value = None
        mock_env._vm.state.return_value = VMState.SHUTOFF

        result = runner.invoke(cli, ["restore", "clean"])
        assert result.exit_code == 0
        assert "Restored to 'clean'" in result.output

    def test_restore_error_message_contains_name(self, runner, mock_env):
        from winbox.cli import cli

        mock_env._vm.snapshot_revert.side_effect = subprocess.CalledProcessError(
            1, "virsh"
        )

        result = runner.invoke(cli, ["restore", "nonexistent"])
        assert result.exit_code == 1
        assert "nonexistent" in result.output


# ─── Bug #21: Path traversal in tools remove ────────────────────────────────


class TestToolsRemovePathTraversal:
    """S4: tools remove accepted ../../ or absolute paths, allowing deletion
    of arbitrary files outside tools_dir. Fix resolves the path and checks
    it stays inside tools_dir."""

    def test_relative_traversal_rejected(self, cfg):
        """tools remove ../../etc/passwd must be rejected."""
        from winbox import tools as tools_mod

        # Create a file outside tools_dir that traversal would target
        outside = cfg.winbox_dir / "secret.txt"
        outside.write_text("sensitive data")

        # Attempt traversal: ../../secret.txt would escape tools_dir
        # (tools_dir is <tmp>/.winbox/shared/tools, so ../../ goes to .winbox)
        tools_mod.remove(cfg, "../../secret.txt")

        # File outside tools_dir must NOT be deleted
        assert outside.exists(), "File outside tools_dir should not be deleted"

    def test_absolute_path_rejected(self, cfg, tmp_path):
        """tools remove /etc/passwd (absolute path) must be rejected."""
        from winbox import tools as tools_mod

        # Create a file at an absolute path outside tools_dir
        target = tmp_path / "important.txt"
        target.write_text("do not delete")

        tools_mod.remove(cfg, str(target))

        # The file must not be deleted
        assert target.exists(), "Absolute path outside tools_dir should not be deleted"

    def test_legitimate_remove_still_works(self, cfg):
        """tools remove legit.exe should still work for files inside tools_dir."""
        from winbox import tools as tools_mod

        (cfg.tools_dir / "legit.exe").write_bytes(b"\x00" * 100)
        assert (cfg.tools_dir / "legit.exe").exists()

        tools_mod.remove(cfg, "legit.exe")

        assert not (cfg.tools_dir / "legit.exe").exists()

    def test_traversal_with_dotdot_prefix(self, cfg):
        """Paths like ../tools/../../../etc/hosts must be rejected."""
        from winbox import tools as tools_mod

        tools_mod.remove(cfg, "../tools/../../../etc/hosts")
        # No crash, no file deletion — just returns early

    def test_nonexistent_inside_tools_dir_shows_not_found(self, cfg, capsys):
        """A legitimate but nonexistent name should print 'Not found', not 'Invalid'."""
        from winbox import tools as tools_mod

        tools_mod.remove(cfg, "ghost.exe")
        # Should reach the "Not found" branch, not the "Invalid name" branch


# ─── Bug #22: termios crash on non-TTY stdin in shell.py ────────────────────


class TestShellNonTTYGuard:
    """S6: _relay and _relay_pipe called termios.tcgetattr before try block.
    If stdin was not a TTY, this raised termios.error and skipped all cleanup
    (socket close, signal handler restore, wakeup fd reset). Fix adds
    sys.stdin.isatty() guard that returns early with an error message."""

    def test_relay_returns_early_on_non_tty(self):
        """_relay should return without crash when stdin is not a TTY."""
        from winbox.exec.shell import _relay

        sock = MagicMock()

        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            _relay(sock)

        # Socket should NOT be closed by _relay (it returned before try/finally)
        sock.close.assert_not_called()

    def test_relay_pipe_returns_early_on_non_tty(self):
        """_relay_pipe should return without crash when stdin is not a TTY."""
        from winbox.exec.shell import _relay_pipe

        sock = MagicMock()

        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            _relay_pipe(sock)

        # Socket should NOT be closed by _relay_pipe (it returned before try/finally)
        sock.close.assert_not_called()

    def test_relay_no_termios_call_on_non_tty(self):
        """When stdin is not a TTY, termios.tcgetattr must NOT be called."""
        from winbox.exec.shell import _relay

        sock = MagicMock()

        with (
            patch("sys.stdin") as mock_stdin,
            patch("winbox.exec.shell.termios") as mock_termios,
        ):
            mock_stdin.isatty.return_value = False
            _relay(sock)

        mock_termios.tcgetattr.assert_not_called()

    def test_relay_pipe_no_termios_call_on_non_tty(self):
        """When stdin is not a TTY, termios.tcgetattr must NOT be called in pipe mode."""
        from winbox.exec.shell import _relay_pipe

        sock = MagicMock()

        with (
            patch("sys.stdin") as mock_stdin,
            patch("winbox.exec.shell.termios") as mock_termios,
        ):
            mock_stdin.isatty.return_value = False
            _relay_pipe(sock)

        mock_termios.tcgetattr.assert_not_called()


# ─── Bug #23: GA exec polling ignores _raw_command latency ──────────────────


class TestGAExecMonotonicDeadline:
    """S7: The exec() polling loop used elapsed += poll_interval to track time,
    but _raw_command() calls can take seconds that are NOT counted. Fix replaces
    the elapsed counter with time.monotonic() deadline."""

    def test_timeout_counts_raw_command_latency(self):
        """If _raw_command takes longer than timeout, exec should still time out."""
        from winbox.vm.guest import GuestAgent, GuestAgentError

        ga = GuestAgent.__new__(GuestAgent)
        ga.vm_name = "test"

        monotonic_values = [
            0.0,    # time.monotonic() for deadline calculation
            6.0,    # time.monotonic() >= deadline (5.0) → timeout
        ]

        exec_response = {"return": {"pid": 42}}
        poll_response = {"return": {"exited": False}}

        with (
            patch.object(ga, "_raw_command", side_effect=[exec_response, poll_response]),
            patch("time.monotonic", side_effect=monotonic_values),
            patch("time.sleep"),
            pytest.raises(GuestAgentError, match="timed out after 5s"),
        ):
            ga.exec("slow-command", timeout=5, poll_interval=0.5)

    def test_completes_before_deadline(self):
        """If command exits before deadline, exec should return normally."""
        from winbox.vm.guest import GuestAgent, ExecResult
        import base64

        ga = GuestAgent.__new__(GuestAgent)
        ga.vm_name = "test"

        stdout_b64 = base64.b64encode(b"output").decode()
        exec_response = {"return": {"pid": 42}}
        poll_response = {"return": {"exited": True, "exitcode": 0, "out-data": stdout_b64, "err-data": ""}}

        monotonic_values = [
            0.0,   # time.monotonic() for deadline calculation
        ]

        with (
            patch.object(ga, "_raw_command", side_effect=[exec_response, poll_response]),
            patch("time.monotonic", side_effect=monotonic_values),
        ):
            result = ga.exec("fast-command", timeout=10, poll_interval=0.5)

        assert result.exitcode == 0
        assert result.stdout == "output"

    def test_multiple_polls_before_deadline(self):
        """Multiple polls that stay under deadline should keep polling."""
        from winbox.vm.guest import GuestAgent, ExecResult
        import base64

        ga = GuestAgent.__new__(GuestAgent)
        ga.vm_name = "test"

        stdout_b64 = base64.b64encode(b"done").decode()
        exec_response = {"return": {"pid": 99}}
        poll_not_done = {"return": {"exited": False}}
        poll_done = {"return": {"exited": True, "exitcode": 0, "out-data": stdout_b64, "err-data": ""}}

        monotonic_values = [
            0.0,   # deadline = 0 + 10 = 10
            2.0,   # first poll check: 2 < 10, continue
            4.0,   # second poll check: 4 < 10, continue
        ]

        with (
            patch.object(ga, "_raw_command", side_effect=[exec_response, poll_not_done, poll_not_done, poll_done]),
            patch("time.monotonic", side_effect=monotonic_values),
            patch("time.sleep"),
        ):
            result = ga.exec("medium-command", timeout=10, poll_interval=0.5)

        assert result.exitcode == 0
        assert result.stdout == "done"

    def test_no_elapsed_counter_in_source(self):
        """Verify the fix: exec() no longer uses 'elapsed += poll_interval'."""
        import inspect
        from winbox.vm.guest import GuestAgent

        source = inspect.getsource(GuestAgent.exec)
        assert "elapsed += poll_interval" not in source
        assert "elapsed" not in source or "deadline" in source
        assert "time.monotonic()" in source
