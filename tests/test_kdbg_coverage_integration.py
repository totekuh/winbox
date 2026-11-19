"""Integration tests for remaining kdbg MCP tool coverage gaps.

Covers: kdbg_read_va happy path, kdbg_search, kdbg_session assertions,
kdbg_status, kdbg_cet_status, kdbg_target_status, kdbg_capture + diff,
kdbg_prepare/restore_cet edge cases, kdbg_base_refresh, ghidra stop,
and CLI round-trips for untested subcommands.
"""

from __future__ import annotations

import json
import shutil
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


def _assert_ok(response):
    assert response["schema"] == "winbox.mcp/1", response
    assert response["ok"] is True, response
    assert response["error"] is None, response
    return response["result"]


def _assert_error(response, code: str | None = None):
    assert response["schema"] == "winbox.mcp/1", response
    assert response["ok"] is False, response
    assert response["error"] is not None, response
    if code:
        assert response["error"]["code"] == code, response["error"]


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


# ─── reader tools (no session needed) ───────────────────────────────────────


class TestReaderTools:
    def _winlogon_pid(self):
        return json.loads(_tool("ps")("winlogon"))[0]["pid"]

    def test_read_va_happy_path(self):
        """Read 16 bytes from KUSER_SHARED_DATA in winlogon."""
        pid = self._winlogon_pid()
        result = _assert_ok(_tool("kdbg_read_va")(pid=pid, address="0x7FFE0000", length=16))
        assert result["pid"] == pid
        assert len(result["bytes"]) == 32
        bytes.fromhex(result["bytes"])

    def test_read_va_ntmajorversion(self):
        """NtMajorVersion at KUSER_SHARED_DATA+0x26C should be 10."""
        pid = self._winlogon_pid()
        result = _assert_ok(_tool("kdbg_read_va")(pid=pid, address="0x7FFE026C", length=4))
        version = int.from_bytes(bytes.fromhex(result["bytes"]), "little")
        assert version == 10, f"NtMajorVersion={version}, expected 10"

    def test_search_nt_module(self):
        result = _assert_ok(_tool("kdbg_search")(module="nt", query="NtCreateFile", limit=5))
        assert "module" in result
        assert result["query"] == "NtCreateFile"
        assert isinstance(result["results"], list)
        assert result["returned"] >= 1
        found = any("NtCreateFile" in str(r) for r in result["results"])
        assert found, f"NtCreateFile not in search results: {result['results'][:3]}"


# ─── session and status tools ────────────────────────────────────────────────


class TestSessionInfo:
    @pytest.fixture(autouse=True)
    def _clean(self, cfg):
        _force_reset(cfg)
        yield
        _force_reset(cfg)

    def test_session_when_idle(self):
        result = _assert_ok(_tool("kdbg_session")())
        assert result["attached"] is False

    def test_session_when_active(self):
        _run("kdbg", "start")
        try:
            pid = json.loads(_tool("ps")("winlogon"))[0]["pid"]
            _assert_ok(_tool("kdbg_attach")(pid))
            try:
                result = _assert_ok(_tool("kdbg_session")())
                assert result["attached"] is True
                assert "target" in result
                assert result["target"]["name"] == "winlogon.exe"
                assert "state" in result
                assert "session_id" in result
                assert "daemon_pid" in result
            finally:
                _tool("kdbg_detach")()
        finally:
            _run("kdbg", "stop", expect_ok=False)

    def test_status_gdbstub_stopped(self):
        result = _assert_ok(_tool("kdbg_status")())
        assert result["listening"] is False

    def test_status_gdbstub_running(self):
        _run("kdbg", "start")
        try:
            result = _assert_ok(_tool("kdbg_status")())
            assert result["listening"] is True
        finally:
            _run("kdbg", "stop", expect_ok=False)

    def test_cet_status(self):
        result = _assert_ok(_tool("kdbg_cet_status")())
        assert "safe_for_debug" in result
        assert "summary" in result
        assert result["safe_for_debug"] is True

    def test_target_status(self):
        _run("kdbg", "start")
        try:
            pid = json.loads(_tool("ps")("winlogon"))[0]["pid"]
            _assert_ok(_tool("kdbg_attach")(pid))
            try:
                result = _assert_ok(_tool("kdbg_target_status")())
                assert "state" in result
                assert "pid" in result
                assert result["state"] in ("alive", "exiting", "gone", "unknown")
            finally:
                _tool("kdbg_detach")()
        finally:
            _run("kdbg", "stop", expect_ok=False)


# ─── capture + diff ──────────────────────────────────────────────────────────


class TestCaptureDiff:
    def test_capture_and_diff(self):
        left = _assert_ok(
            _tool("kdbg_capture")(profile="system", name="test_cov_left")
        )
        assert left["saved"] is not None
        assert left["saved"]["name"] == "test_cov_left"
        assert "capture" in left

        right = _assert_ok(
            _tool("kdbg_capture")(profile="system", name="test_cov_right")
        )
        assert right["saved"]["name"] == "test_cov_right"

        diff = _assert_ok(
            _tool("kdbg_capture_diff")(left="test_cov_left", right="test_cov_right")
        )
        assert diff["profile"] == "system"
        assert diff["identity_match"] is True
        assert "processes" in diff
        for key in ("created", "removed", "changed"):
            assert key in diff["processes"]


# ─── infra tools ─────────────────────────────────────────────────────────────


class TestInfraTools:
    def test_prepare_already_done(self):
        result = _assert_ok(_tool("kdbg_prepare")(confirm=True))
        assert result["changed"] is False
        assert result["safe_for_debug"] is True

    def test_prepare_refuses_without_confirm(self):
        _assert_error(_tool("kdbg_prepare")(), "invalid_argument")

    def test_restore_cet_refuses_without_confirm(self):
        _assert_error(_tool("kdbg_restore_cet")(), "invalid_argument")

    def test_base_refresh(self):
        result = _assert_ok(_tool("kdbg_base_refresh")())
        assert result["module"] == "nt"
        assert result["base"].startswith("0x")


# ─── ghidra (Docker-dependent) ───────────────────────────────────────────────


class TestGhidraLifecycle:
    @pytest.fixture(autouse=True)
    def _require_docker(self):
        if shutil.which("docker") is None:
            pytest.skip("Docker not available")

    def test_ghidra_stop_when_not_running(self):
        result = _tool("kdbg_ghidra_stop")()
        if result["ok"]:
            r = result["result"]
            assert r.get("stopped") is False or r.get("already_stopped") is True


# ─── CLI round-trips ─────────────────────────────────────────────────────────


class TestCliRoundTrips:
    def test_cli_ps(self):
        result = _run("kdbg", "ps")
        assert "system" in result.output.lower() or "pid" in result.output.lower()

    def test_cli_lm(self):
        result = _run("kdbg", "lm")
        assert "ntoskrnl" in result.output.lower()

    def test_cli_struct(self):
        result = _run("kdbg", "struct", "_EPROCESS")
        assert "UniqueProcessId" in result.output

    def test_cli_status(self):
        _run("kdbg", "status")

    def test_cli_cet_status(self):
        _run("kdbg", "cet-status")

    def test_cli_session_idle(self, cfg):
        _force_reset(cfg)
        result = _run("kdbg", "session")
        lower = result.output.lower()
        assert "no" in lower and "session" in lower, result.output

    def test_cli_read_va(self):
        pid = json.loads(_tool("ps")("winlogon"))[0]["pid"]
        result = _run("kdbg", "read-va", str(pid), "0x7FFE0000", "16")
        assert result.exit_code == 0

    def test_cli_search(self):
        result = _run("kdbg", "search", "nt", "NtCreateFile")
        assert result.exit_code == 0
        assert "NtCreateFile" in result.output
