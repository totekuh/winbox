"""Integration tests for argument validation and bad-PID error paths.

Every test hits a real QEMU/KVM Windows VM through the RSP reader.
Validates that walker and inspection tools return typed errors for
invalid arguments and nonexistent targets instead of crashing.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from winbox.cli import cli
from winbox.config import Config
from winbox.kdbg.cet import CetSafetyError, require_safe
from winbox.vm import VM, GuestAgent, VMState


pytestmark = pytest.mark.integration

_runner = CliRunner()
BOGUS_PID = 999_999_999


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


def _assert_error(response, code: str | None = None):
    assert response["schema"] == "winbox.mcp/1", response
    assert response["ok"] is False, response
    assert response["error"] is not None, response
    if code:
        assert response["error"]["code"] == code, response["error"]


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


# ─── Bad PID ─────────────────────────────────────────────────────────────────


class TestWalkerBadPid:
    """Walker tools with a PID that cannot exist must fail with a typed error."""

    def test_threads_bad_pid(self):
        _assert_error(_tool("kdbg_threads")(pid=BOGUS_PID))

    def test_triage_bad_pid(self):
        _assert_error(_tool("kdbg_triage")(pid=BOGUS_PID))

    def test_token_bad_pid(self):
        _assert_error(_tool("kdbg_token")(pid=BOGUS_PID))

    def test_handles_bad_pid(self):
        _assert_error(_tool("kdbg_handles")(pid=BOGUS_PID))

    def test_vad_bad_pid(self):
        _assert_error(_tool("kdbg_vad")(pid=BOGUS_PID))

    def test_thread_diff_missing_baseline(self):
        result = _tool("kdbg_thread_diff")(pid=4, name="nonexistent_baseline_xyz")
        _assert_error(result)

    def test_cli_threads_bad_pid(self):
        result = _run("kdbg", "threads", str(BOGUS_PID), expect_ok=False)
        assert result.exit_code != 0


# ─── Bad arguments ───────────────────────────────────────────────────────────


class TestBadArguments:
    """Argument validation on walker and inspection tools against live VM."""

    def test_triage_zero_thread_limit(self):
        _assert_error(_tool("kdbg_triage")(pid=4, thread_limit=0))

    def test_triage_excessive_thread_limit(self):
        _assert_error(_tool("kdbg_triage")(pid=4, thread_limit=99999))

    def test_vad_invalid_limit(self):
        _assert_error(_tool("kdbg_vad")(pid=4, limit=0))

    def test_vad_excessive_limit(self):
        _assert_error(_tool("kdbg_vad")(pid=4, limit=999999))

    def test_read_va_bad_address(self):
        _assert_error(_tool("kdbg_read_va")(pid=4, address="not_hex", length=16))

    def test_read_va_zero_length(self):
        result = _tool("kdbg_read_va")(pid=4, address="0x7FFE0000", length=0)
        if result["ok"]:
            assert result["result"]["bytes"] == "" or result["result"]["length"] == 0
        else:
            _assert_error(result)

    def test_read_va_excessive_length(self):
        _assert_error(_tool("kdbg_read_va")(pid=4, address="0x7FFE0000", length=10_000_000))

    def test_object_bad_address(self):
        _assert_error(_tool("kdbg_object")(body="not_an_address"))

    def test_thread_diff_invalid_limit(self):
        _assert_error(_tool("kdbg_thread_diff")(pid=4, name="default", limit=0))

    def test_thread_diff_excessive_limit(self):
        _assert_error(_tool("kdbg_thread_diff")(pid=4, name="default", limit=999999))

    def test_threads_invalid_detail(self):
        _assert_error(_tool("kdbg_threads")(pid=4, detail="bogus_detail"))

    def test_thread_triage_zero_process_cap(self):
        result = _tool("kdbg_thread_triage")(process_cap=0, total_thread_cap=1)
        _assert_error(result)

    def test_cli_mem_read_bad_address(self):
        result = _run("kdbg", "mem", "not_an_address", "16", expect_ok=False)
        assert result.exit_code != 0
