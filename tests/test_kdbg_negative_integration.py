"""Negative / error-path integration tests for kdbg session lifecycle.

Every test hits a real QEMU/KVM Windows VM. Categories:
  A — session-requiring tools called without an attached daemon
  B — double-attach conflict
  C — operations in wrong run-state (running, not halted)
  D — detach / resume edge cases
"""

from __future__ import annotations

import json
import time
from contextlib import suppress

import pytest
from click.testing import CliRunner

from winbox.cli import cli
from winbox.config import Config
from winbox.kdbg.cet import CetSafetyError, require_safe
from winbox.vm import VM, GuestAgent, VMState


pytestmark = pytest.mark.integration

_runner = CliRunner()


def _run(*args: str, expect_ok: bool = True):
    result = _runner.invoke(cli, list(args))
    if expect_ok:
        assert result.exit_code == 0, (
            f"winbox {' '.join(args)} exited {result.exit_code}\n"
            f"{result.output}\n{result.exception!r}"
        )
    return result


def _tool(name: str):
    import winbox.mcp as mcp_mod
    obj = mcp_mod.__dict__[name]
    return obj.fn if hasattr(obj, "fn") else obj


def _force_reset(cfg: Config) -> None:
    from winbox.kdbg.debugger.daemon import force_stop_daemon
    from winbox.kdbg.debugger.reader import stop_reader
    from winbox.kdbg.hmp import ensure_not_paused, hmp
    with suppress(Exception):
        force_stop_daemon(cfg)
    with suppress(Exception):
        stop_reader(cfg)
    with suppress(Exception):
        hmp(cfg.vm_name, "gdbserver none", mode="tuple")
    with suppress(Exception):
        ensure_not_paused(cfg.vm_name)


def _reset_session(cfg: Config) -> None:
    """Kill daemon/reader and ensure VM running. Leave gdbstub intact."""
    from winbox.kdbg.debugger.daemon import force_stop_daemon
    from winbox.kdbg.debugger.reader import stop_reader
    from winbox.kdbg.hmp import ensure_not_paused
    with suppress(Exception):
        force_stop_daemon(cfg)
    with suppress(Exception):
        stop_reader(cfg)
    with suppress(Exception):
        ensure_not_paused(cfg.vm_name)


@pytest.fixture(scope="module")
def cfg(bootstrapped_vm):
    return Config.load()


@pytest.fixture(scope="module")
def vm(cfg):
    return VM(cfg)


@pytest.fixture(scope="module")
def ga(cfg):
    return GuestAgent(cfg)


@pytest.fixture(scope="module", autouse=True)
def _require_running(vm):
    if vm.state() != VMState.RUNNING:
        pytest.skip("VM not running")


@pytest.fixture(scope="module", autouse=True)
def _require_safe_vm(cfg, vm, ga):
    try:
        require_safe(cfg, ga)
    except CetSafetyError:
        pytest.skip("CET not safe for debugging")


def _assert_error(response, code: str | None = None):
    assert response["schema"] == "winbox.mcp/1", response
    assert response["ok"] is False, response
    assert response["error"] is not None, response
    if code:
        assert response["error"]["code"] == code, response["error"]


def _assert_ok(response):
    assert response["schema"] == "winbox.mcp/1", response
    assert response["ok"] is True, response
    return response["result"]


# ─── Category A: no session ──────────────────────────────────────────────────


class TestNoSessionErrors:
    @pytest.fixture(autouse=True)
    def _ensure_clean(self, cfg):
        _reset_session(cfg)
        yield
        _reset_session(cfg)

    def test_cont_without_session(self):
        _assert_error(_tool("kdbg_cont")(timeout=1.0), "no_session")

    def test_step_without_session(self):
        _assert_error(_tool("kdbg_step")(), "no_session")

    def test_interrupt_without_session(self):
        _assert_error(_tool("kdbg_interrupt")(), "no_session")

    def test_regs_without_session(self):
        _assert_error(_tool("kdbg_regs")(), "no_session")

    def test_bp_add_without_session(self):
        _assert_error(_tool("kdbg_bp")("nt!NtCreateFile"), "no_session")

    def test_bp_list_without_session(self):
        _assert_error(_tool("kdbg_bps")(), "no_session")

    def test_bp_trace_without_session(self):
        _assert_error(_tool("kdbg_bp_trace")(bp_id=0), "no_session")

    def test_disasm_without_session(self):
        _assert_error(_tool("kdbg_disasm")("", 4), "no_session")

    def test_mem_without_session(self):
        _assert_error(_tool("kdbg_mem")(va="0x7FFE0000", length=16), "no_session")

    def test_write_mem_without_session(self):
        _assert_error(_tool("kdbg_write_mem")(va="0x7FFE0000", data="00"), "no_session")

    def test_context_without_session(self):
        _assert_error(_tool("kdbg_context")(), "no_session")

    def test_stack_without_session(self):
        _assert_error(_tool("kdbg_stack")(), "no_session")

    def test_bt_without_session(self):
        _assert_error(_tool("kdbg_bt")(), "no_session")

    def test_cli_regs_without_session(self):
        result = _run("kdbg", "regs", expect_ok=False)
        assert result.exit_code != 0
        assert "session" in result.output.lower() or "no_session" in result.output


# ─── Category B: double attach ───────────────────────────────────────────────


class TestDoubleAttach:
    @pytest.fixture(autouse=True, scope="class")
    def _gdbstub(self, cfg):
        _force_reset(cfg)
        _run("kdbg", "start")
        yield
        _force_reset(cfg)

    @pytest.fixture(autouse=True)
    def _clean(self, cfg):
        _reset_session(cfg)
        yield
        _reset_session(cfg)

    def test_second_attach_refuses(self):
        """Second attach refused — either envelope error or RuntimeError from
        _ensure_vm_ready seeing a paused VM with an active session."""
        pid = json.loads(_tool("ps")("winlogon"))[0]["pid"]
        first = _tool("kdbg_attach")(pid)
        _assert_ok(first)
        try:
            try:
                second = _tool("kdbg_attach")(pid)
                assert second["ok"] is False, f"double attach should refuse: {second}"
            except RuntimeError as exc:
                assert "session" in str(exc).lower() or "halted" in str(exc).lower(), exc
        finally:
            _tool("kdbg_detach")()


# ─── Category C: wrong state ─────────────────────────────────────────────────


class TestWrongStateErrors:
    """Operations not in _RUNNING_OPS must refuse while daemon is running.

    The daemon allows only {status, interrupt, bp_list, bp_trace, detach}
    while running. Everything else gets a state error. We use the synchronous
    kdbg_cont (which blocks in the daemon, keeping it in running state) from
    a background thread while probing from the main thread.
    """

    @pytest.fixture(autouse=True, scope="class")
    def _gdbstub(self, cfg):
        _force_reset(cfg)
        _run("kdbg", "start")
        yield
        _force_reset(cfg)

    @pytest.fixture(autouse=True)
    def _clean(self, cfg):
        _reset_session(cfg)
        yield
        _reset_session(cfg)

    def test_step_refused_during_cont(self):
        """step is not lightweight — daemon returns BUSY during cont."""
        from winbox.kdbg.debugger.client import ClientError, DaemonClient
        import threading

        pid = json.loads(_tool("ps")("winlogon"))[0]["pid"]
        _assert_ok(_tool("kdbg_attach")(pid))
        try:
            client = DaemonClient(Config.load())

            def bg_cont():
                with suppress(Exception):
                    client.call("cont", sock_timeout=15.0, timeout=10.0)

            thread = threading.Thread(target=bg_cont)
            thread.start()
            time.sleep(1.0)
            try:
                with pytest.raises(ClientError) as exc_info:
                    client.call("step", sock_timeout=5.0)
                assert exc_info.value.code in ("busy", "state_conflict")
            finally:
                with suppress(Exception):
                    client.call("interrupt", sock_timeout=5.0)
                thread.join(timeout=15)
        finally:
            _tool("kdbg_detach")()

    def test_status_allowed_during_cont(self):
        """status is lightweight: daemon serves it even during cont."""
        from winbox.kdbg.debugger.client import DaemonClient
        import threading

        pid = json.loads(_tool("ps")("winlogon"))[0]["pid"]
        _assert_ok(_tool("kdbg_attach")(pid))
        try:
            client = DaemonClient(Config.load())

            def bg_cont():
                with suppress(Exception):
                    client.call("cont", sock_timeout=15.0, timeout=10.0)

            thread = threading.Thread(target=bg_cont)
            thread.start()
            time.sleep(1.0)
            try:
                status = client.call("status", sock_timeout=5.0)
                assert status["state"] == "running"
            finally:
                with suppress(Exception):
                    client.call("interrupt", sock_timeout=5.0)
                thread.join(timeout=15)
        finally:
            _tool("kdbg_detach")()


# ─── Category D: detach edge cases ───────────────────────────────────────────


class TestDetachEdgeCases:
    @pytest.fixture(autouse=True)
    def _clean(self, cfg):
        _reset_session(cfg)
        yield
        _reset_session(cfg)

    def test_detach_when_not_attached(self):
        result = _tool("kdbg_detach")()
        assert result["schema"] == "winbox.mcp/1"
        assert result["ok"] is True or "no_session" in str(result.get("error", ""))

    def test_session_reports_nothing_when_idle(self):
        result = _tool("kdbg_session")()
        assert result["schema"] == "winbox.mcp/1"
        if result["ok"]:
            assert result["result"].get("attached") is False or result["result"].get("state") == "idle"
        else:
            assert result["error"]["code"] == "no_session"

    def test_resume_on_running_vm_is_noop(self):
        result = _tool("kdbg_resume")()
        _assert_ok(result)
