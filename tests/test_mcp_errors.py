"""Tests for MCP-layer guest-exec error translation.

`cli/exec.py` turns a lost guest agent into a clean, actionable message with a
VM-state hint. These tests pin the equivalent behaviour on the MCP side: a GA
transport/exec failure surfaces as a RuntimeError (which FastMCP renders as a
tool error) carrying that hint — instead of a bare exception string — while a
command that merely exited non-zero still flows back as a normal result.
"""

from unittest.mock import MagicMock, patch

import pytest

import winbox.mcp as mcp_mod
from winbox.vm import (
    VMState,
    GuestAgentUnreachable,
    GuestExecAbandoned,
    GuestExecTimeout,
)
from winbox.vm.guest import ExecResult, GuestAgentError


class TestGuestErrorMessage:
    def test_running_vm_abandoned_gets_unreachable_hint(self):
        vm = MagicMock()
        vm.state.return_value = VMState.RUNNING
        msg = mcp_mod._guest_error_message(
            GuestExecAbandoned("lost contact on PID 42", pid=42), vm
        )
        assert "lost contact" in msg
        assert "winbox up --reboot" in msg

    def test_running_vm_unreachable_gets_unreachable_hint(self):
        vm = MagicMock()
        vm.state.return_value = VMState.RUNNING
        msg = mcp_mod._guest_error_message(
            GuestAgentUnreachable("agent not responding"), vm
        )
        assert "unreachable" in msg.lower()

    def test_running_vm_timeout_is_plain_message(self):
        # A timeout ran for its full window; no reboot hint, just the message.
        vm = MagicMock()
        vm.state.return_value = VMState.RUNNING
        msg = mcp_mod._guest_error_message(
            GuestExecTimeout("Command timed out after 300s", pid=9), vm
        )
        assert "timed out" in msg
        assert "reboot" not in msg

    def test_non_running_vm_gets_state_hint(self):
        vm = MagicMock()
        vm.state.return_value = VMState.PAUSED
        msg = mcp_mod._guest_error_message(
            GuestExecAbandoned("lost contact", pid=1), vm
        )
        assert "paused" in msg
        assert "winbox up" in msg

    def test_state_probe_failure_does_not_mask_original(self):
        vm = MagicMock()
        vm.state.side_effect = RuntimeError("virsh blew up")
        msg = mcp_mod._guest_error_message(
            GuestAgentUnreachable("original problem"), vm
        )
        assert "original problem" in msg


class TestGuestErrorsContextManager:
    def test_translates_guest_error_to_runtime_error(self):
        vm = MagicMock()
        vm.state.return_value = VMState.RUNNING
        with pytest.raises(RuntimeError, match="unreachable"):
            with mcp_mod._guest_errors(vm):
                raise GuestExecAbandoned("lost contact", pid=3)

    def test_passes_through_non_guest_errors(self):
        vm = MagicMock()
        with pytest.raises(ValueError, match="not a GA error"):
            with mcp_mod._guest_errors(vm):
                raise ValueError("not a GA error")

    def test_no_error_is_transparent(self):
        vm = MagicMock()
        with mcp_mod._guest_errors(vm):
            pass  # must not raise


@pytest.fixture
def mcp_env(cfg):
    """Wire the module-level MCP state to a fake VM + GA, like the eventlogs
    fixture does, and restore it afterwards."""
    ga = MagicMock()
    vm = MagicMock()
    vm.state.return_value = VMState.RUNNING
    mcp_mod._cfg = cfg
    mcp_mod._vm = vm
    mcp_mod._ga = ga
    with patch.object(mcp_mod, "_ensure_vm_ready", return_value=(cfg, vm, ga)):
        yield cfg, vm, ga
    mcp_mod._cfg = None
    mcp_mod._vm = None
    mcp_mod._ga = None


class TestExecPythonErrorTranslation:
    def test_abandoned_becomes_runtime_error(self, mcp_env):
        cfg, vm, ga = mcp_env
        ga.exec.side_effect = GuestExecAbandoned("lost contact on PID 7", pid=7)
        with pytest.raises(RuntimeError, match="winbox up --reboot"):
            mcp_mod._exec_python("print('hi')")

    def test_timeout_becomes_runtime_error(self, mcp_env):
        cfg, vm, ga = mcp_env
        ga.exec.side_effect = GuestExecTimeout("timed out after 300s", pid=8)
        with pytest.raises(RuntimeError, match="timed out"):
            mcp_mod._exec_python("print('hi')")

    def test_call_dir_is_cleaned_up_on_failure(self, mcp_env):
        cfg, vm, ga = mcp_env
        ga.exec.side_effect = GuestAgentUnreachable("gone")
        mcp_dir = cfg.shared_dir / ".mcp"
        with pytest.raises(RuntimeError):
            mcp_mod._exec_python("print('hi')")
        # The per-call subdir must not be left behind.
        leftovers = list(mcp_dir.iterdir()) if mcp_dir.exists() else []
        assert leftovers == []

    def test_completed_nonzero_still_returns_normally(self, mcp_env):
        cfg, vm, ga = mcp_env
        ga.exec.return_value = ExecResult(exitcode=1, stdout="", stderr="boom")
        result = mcp_mod._exec_python("raise SystemExit(1)")
        assert result["exitcode"] == 1
        assert result["stderr"] == "boom"

    def test_python_tool_raises_on_ga_loss(self, mcp_env):
        cfg, vm, ga = mcp_env
        ga.exec.side_effect = GuestExecAbandoned("lost contact", pid=1)
        from winbox.mcp import python
        with pytest.raises(RuntimeError):
            python("print('hi')")


class TestEventlogsErrorTranslation:
    def test_powershell_ga_loss_becomes_runtime_error(self, mcp_env):
        cfg, vm, ga = mcp_env
        ga.exec_powershell.side_effect = GuestAgentUnreachable("agent gone")
        from winbox.mcp import eventlogs
        with pytest.raises(RuntimeError, match="unreachable"):
            eventlogs()
