"""Tests for the `winbox setup` pipeline's failure handling (cli/setup.py).

The pipeline's job on failure is to say what broke, tell the user the one
recovery command, and not leave a half-built VM running. GuestAgentError was
a plain Exception when this was written, so it escaped the handler as a raw
traceback with the guest still powered on. It subclasses RuntimeError now, but
these tests pin the behaviour rather than the class, so they keep their value
either way.
"""

from unittest.mock import MagicMock, patch

import pytest

from winbox.cli import cli
from winbox.vm import GuestAgentError


@pytest.fixture
def iso(tmp_path):
    path = tmp_path / "win.iso"
    path.write_bytes(b"\x00")
    return str(path)


def _run_setup_with_failure(runner, cfg, iso, exc):
    """Drive `winbox setup` to the point where a pipeline phase raises `exc`."""
    fake_installer = MagicMock()
    fake_installer.check_prereqs.return_value = []
    fake_installer.boot_for_provisioning.side_effect = exc

    with patch("winbox.cli.setup.installer", fake_installer):
        return runner.invoke(cli, ["setup", "-y", "--iso", iso])


class TestPipelineFailureHandling:
    def test_guest_agent_error_gets_the_clean_error_and_recovery_hint(
        self, runner, mock_env, cfg, iso
    ):
        """The provisioning boot's `ga.wait` raising must not produce a
        traceback — it's the single most likely way setup fails on win11."""
        result = _run_setup_with_failure(
            runner, cfg, iso, GuestAgentError("guest agent never answered")
        )

        assert result.exit_code == 1
        assert "Setup failed" in result.output
        assert "guest agent never answered" in result.output
        assert "winbox destroy" in result.output
        assert not isinstance(result.exception, GuestAgentError)

    def test_guest_agent_error_does_not_leave_the_vm_running(
        self, runner, mock_env, cfg, iso
    ):
        """A half-provisioned guest left running is what the next `winbox
        exec`/`av` would silently attach to."""
        mock_env._vm.is_running.return_value = True

        _run_setup_with_failure(
            runner, cfg, iso, GuestAgentError("guest agent never answered")
        )

        mock_env._vm.force_stop.assert_called_once()

    def test_permission_error_is_handled_too(self, runner, mock_env, cfg, iso):
        """Not a one-off: any infrastructure failure from a phase (e.g.
        build_unattend_image hitting a permission problem) takes the same
        path."""
        result = _run_setup_with_failure(
            runner, cfg, iso, PermissionError("cannot write unattend image")
        )

        assert result.exit_code == 1
        assert "Setup failed" in result.output
        assert "winbox destroy" in result.output

    def test_runtime_error_still_handled(self, runner, mock_env, cfg, iso):
        """Regression guard on the pre-existing contract."""
        result = _run_setup_with_failure(runner, cfg, iso, RuntimeError("phase 3 blew up"))

        assert result.exit_code == 1
        assert "phase 3 blew up" in result.output

    def test_a_powered_off_vm_is_not_force_stopped(self, runner, mock_env, cfg, iso):
        """Don't issue `virsh destroy` at a domain that is already down."""
        mock_env._vm.is_running.return_value = False

        _run_setup_with_failure(runner, cfg, iso, RuntimeError("boom"))

        mock_env._vm.force_stop.assert_not_called()


class TestPrereqCheckIsProfileScoped:
    """The prereq gate must be told which guest is being built.

    `check_prereqs` grew a `cfg` parameter so that tools only the Win11
    offline-hive path uses aren't demanded of a Server 2022 build. The
    parameter defaults to None, and with None every gated tool counts as
    required — so a call site that forgets to pass cfg silently reinstates
    the exact blockage the parameter exists to prevent, while the unit tests
    that call `check_prereqs(cfg)` directly keep passing.
    """

    def test_cli_passes_cfg_to_check_prereqs(self):
        """Pins the call site itself, not just the function's behaviour."""
        import inspect

        from winbox.cli import setup as setup_mod

        source = inspect.getsource(setup_mod)
        assert "installer.check_prereqs(cfg)" in source, (
            "cli/setup.py must pass cfg to check_prereqs; without it every "
            "profile-gated tool is treated as required for every profile"
        )

    def test_server2022_is_not_blocked_on_win11_only_tools(self):
        from winbox.config import Config
        from winbox.setup.installer import PROFILE_GATED_TOOLS, check_prereqs

        cfg = Config()
        cfg.vm_os = "server2022"
        assert not cfg.profile.disable_defender_offline

        with patch("winbox.setup.installer.shutil.which", side_effect=
                   lambda n: None if n in PROFILE_GATED_TOOLS else "/usr/bin/" + n), \
             patch("winbox.setup.installer.Path.exists", return_value=True):
            missing = check_prereqs(cfg)

        assert missing == [], (
            f"server2022 blocked on tools it never invokes: {missing}"
        )

    def test_win11_still_requires_them(self):
        from winbox.config import Config
        from winbox.setup.installer import PROFILE_GATED_TOOLS, check_prereqs

        cfg = Config()
        cfg.vm_os = "win11"
        assert cfg.profile.disable_defender_offline

        with patch("winbox.setup.installer.shutil.which", side_effect=
                   lambda n: None if n in PROFILE_GATED_TOOLS else "/usr/bin/" + n), \
             patch("winbox.setup.installer.Path.exists", return_value=True):
            missing = check_prereqs(cfg)

        # Entries carry an "(apt install ...)" hint, so match on the tool name.
        assert any(
            tool in entry for tool in PROFILE_GATED_TOOLS for entry in missing
        ), missing

    def test_remediation_line_names_every_required_package(self):
        """A user who runs the printed apt line must not fail the same check."""
        import inspect

        from winbox.cli import setup as setup_mod

        source = inspect.getsource(setup_mod)
        apt_line = source[source.index("Install with:"):source.index("Install with:") + 400]
        assert "libwin-hivex-perl" in apt_line, (
            "the apt line omits the package providing hivexregedit"
        )
