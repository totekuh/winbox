"""Live integration tests for stepping, interrupt, disasm, and inspection tools.

Every test hits a real QEMU/KVM Windows VM through the gdbstub daemon.
Exercises step-over, step-out, interrupt-during-cont, disasm content
validation, and dedicated kdbg_ps/kdbg_lm/kdbg_struct coverage.
"""

from __future__ import annotations

import json
import threading
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


# ─── stepping tests ─────────────────────────────────────────────────────────


class TestStepOver:
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

    def test_step_over_on_call_instruction(self):
        """Single-step through kernel code until we hit a call, then step-over."""
        pid = json.loads(_tool("ps")("winlogon"))[0]["pid"]
        _assert_ok(_tool("kdbg_attach")(pid))
        try:
            for _ in range(50):
                disasm = _assert_ok(_tool("kdbg_disasm")(count=1))
                insn = disasm["instructions"][0]
                if insn["mnemonic"] == "call":
                    break
                _assert_ok(_tool("kdbg_step")())
            else:
                pytest.skip("no call found in 50 steps from initial halt")

            regs_before = _assert_ok(_tool("kdbg_regs")())
            rip_before = int(regs_before["rip"], 0)

            result = _assert_ok(_tool("kdbg_step")(over=True))
            assert result["reason"] == "step_over"
            assert result["state"] == "halted"
            assert result["stepped_over"] == "call"
            rip_after = int(result["rip"], 0)
            assert rip_after != rip_before

            regs_after = _assert_ok(_tool("kdbg_regs")())
            assert regs_after["rip"] is not None
        finally:
            _tool("kdbg_detach")()

    def test_step_over_non_call_falls_back_to_step(self):
        """Step-over on a non-call instruction behaves like single-step."""
        pid = json.loads(_tool("ps")("winlogon"))[0]["pid"]
        _assert_ok(_tool("kdbg_attach")(pid))
        try:
            disasm = _assert_ok(_tool("kdbg_disasm")(count=1))
            insn = disasm["instructions"][0]
            if insn["mnemonic"] in ("call", "syscall", "sysenter"):
                _assert_ok(_tool("kdbg_step")())

            regs_before = _assert_ok(_tool("kdbg_regs")())
            rip_before = int(regs_before["rip"], 0)
            result = _assert_ok(_tool("kdbg_step")(over=True))
            assert result["state"] == "halted"
            rip_after = int(result["rip"], 0)
            assert rip_after != rip_before
        finally:
            _tool("kdbg_detach")()


class TestStepOut:
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

    def test_step_out_returns_to_caller(self):
        """Step into a function via single-step past a call, then step-out."""
        pid = json.loads(_tool("ps")("winlogon"))[0]["pid"]
        _assert_ok(_tool("kdbg_attach")(pid))
        try:
            for _ in range(50):
                disasm = _assert_ok(_tool("kdbg_disasm")(count=1))
                insn = disasm["instructions"][0]
                if insn["mnemonic"] == "call":
                    _assert_ok(_tool("kdbg_step")())
                    break
                _assert_ok(_tool("kdbg_step")())
            else:
                pytest.skip("no call found in 50 steps from initial halt")

            regs = _assert_ok(_tool("kdbg_regs")())
            rsp = int(regs["rsp"], 0)
            mem = _assert_ok(_tool("kdbg_mem")(va=hex(rsp), length=8))
            ret_bytes = bytes.fromhex(mem["bytes"])
            ret_addr = int.from_bytes(ret_bytes, "little")

            result = _assert_ok(_tool("kdbg_step")(out=True))
            assert result["reason"] == "step_out"
            assert result["state"] == "halted"
            rip_after = int(result["rip"], 0)

            if ret_addr != 0:
                assert abs(rip_after - ret_addr) < 0x100, (
                    f"RIP {rip_after:#x} too far from return addr {ret_addr:#x}"
                )

            regs_after = _assert_ok(_tool("kdbg_regs")())
            assert regs_after["rip"] is not None
        finally:
            _tool("kdbg_detach")()


# ─── interrupt during cont ───────────────────────────────────────────────────


class TestInterruptDuringCont:
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

    def test_interrupt_halts_running_target_and_inspect(self):
        """Interrupt a running target, then verify full halt context."""
        from winbox.kdbg.debugger.client import DaemonClient

        pid = json.loads(_tool("ps")("winlogon"))[0]["pid"]
        _assert_ok(_tool("kdbg_attach")(pid))
        try:
            client = DaemonClient(Config.load())
            cont_done = threading.Event()

            def bg_cont():
                try:
                    client.call("cont", sock_timeout=12.0, timeout=8.0)
                except Exception:
                    pass
                finally:
                    cont_done.set()

            thread = threading.Thread(target=bg_cont, daemon=True)
            thread.start()
            time.sleep(1.5)
            try:
                status = client.call("status", sock_timeout=5.0)
                assert status["state"] == "running"

                interrupt_result = client.call("interrupt", sock_timeout=5.0)
                assert interrupt_result.get("queued") is True or "reason" in interrupt_result
            finally:
                cont_done.wait(timeout=10)
                thread.join(timeout=5)

            regs = _assert_ok(_tool("kdbg_regs")())
            assert "rip" in regs
            assert "rsp" in regs

            disasm = _assert_ok(_tool("kdbg_disasm")(count=1))
            assert len(disasm["instructions"]) >= 1

            context = _assert_ok(_tool("kdbg_context")())
            assert "state" in context or "stop_id" in context
        finally:
            _tool("kdbg_detach")()


# ─── disasm content validation ───────────────────────────────────────────────


class TestDisasmContent:
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

    def test_disasm_returns_valid_instructions(self):
        """Decoded instructions should have valid mnemonics and sequential addresses."""
        pid = json.loads(_tool("ps")("winlogon"))[0]["pid"]
        _assert_ok(_tool("kdbg_attach")(pid))
        try:
            result = _assert_ok(_tool("kdbg_disasm")(count=8))
            instructions = result["instructions"]
            assert len(instructions) >= 1

            prev_addr = None
            for insn in instructions:
                assert "addr" in insn
                assert "mnemonic" in insn
                assert "op_str" in insn
                assert len(insn["mnemonic"]) > 0
                addr = int(insn["addr"], 0)
                if prev_addr is not None:
                    assert addr > prev_addr
                prev_addr = addr
        finally:
            _tool("kdbg_detach")()

    def test_disasm_with_instruction_bytes(self):
        """instruction_bytes=True includes raw bytes for each instruction."""
        pid = json.loads(_tool("ps")("winlogon"))[0]["pid"]
        _assert_ok(_tool("kdbg_attach")(pid))
        try:
            result = _assert_ok(
                _tool("kdbg_disasm")(count=4, instruction_bytes=True)
            )
            for insn in result["instructions"]:
                assert "bytes" in insn, f"missing bytes field: {insn}"
                assert len(insn["bytes"]) > 0
        finally:
            _tool("kdbg_detach")()


# ─── ps / lm / struct ───────────────────────────────────────────────────────


class TestPsLmStruct:
    """Dedicated tests for MCP tools that had no e2e coverage."""

    def test_kdbg_ps_lists_system(self):
        result = _assert_ok(_tool("kdbg_ps")())
        assert isinstance(result["processes"], list)
        assert isinstance(result["count"], int)
        assert result["count"] > 0
        pids = {p["pid"] for p in result["processes"]}
        assert 4 in pids, "System (pid=4) not found"
        for proc in result["processes"]:
            assert "pid" in proc
            assert "name" in proc
            assert "dtb" in proc
            assert "eprocess" in proc

    def test_kdbg_lm_lists_ntoskrnl(self):
        result = _assert_ok(_tool("kdbg_lm")())
        assert isinstance(result["modules"], list)
        assert isinstance(result["count"], int)
        assert result["count"] > 0
        names = [m["name"].lower() for m in result["modules"]]
        assert any("ntoskrnl" in n for n in names), f"ntoskrnl not in {names[:10]}"
        for mod in result["modules"]:
            assert "base" in mod
            assert "size" in mod
            assert "name" in mod

    def test_kdbg_struct_eprocess(self):
        result = _assert_ok(_tool("kdbg_struct")(type_name="_EPROCESS"))
        assert isinstance(result["lines"], list)
        assert len(result["lines"]) > 0
        text = "\n".join(result["lines"])
        assert "UniqueProcessId" in text, f"UniqueProcessId not in struct output"
