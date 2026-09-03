"""Tests for winbox MCP server tools."""

from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import ANY, MagicMock, patch, PropertyMock

import pytest
from click.testing import CliRunner

from winbox.config import Config
from winbox.vm import VMState
from winbox.vm.guest import ExecResult


def _mcp_result(reply):
    assert reply["schema"] == "winbox.mcp/1"
    assert reply["ok"] is True
    assert reply["error"] is None
    return reply["result"]


def _mcp_error(reply):
    assert reply["schema"] == "winbox.mcp/1"
    assert reply["ok"] is False
    assert reply["result"] is None
    return reply["error"]


def test_kdbg_search_mcp_uses_offline_static_service(mock_mcp):
    from winbox.mcp import kdbg_search

    payload = {"schema": "winbox.kdbg-static-search/1", "results": []}
    digest = "b" * 64
    with patch(
        "winbox.kdbg.static_search.search_cached_module", return_value=payload,
    ) as search:
        result = kdbg_search("MpEngine.dll", "Unpacker", limit=5, sha256=digest)
    assert _mcp_result(result) == payload
    search.assert_called_once_with(
        ANY, module="MpEngine.dll", query="Unpacker", limit=5, sha256=digest,
    )


def test_kdbg_search_mcp_preserves_typed_static_error(mock_mcp):
    from winbox.kdbg.static_search import StaticSearchError
    from winbox.mcp import kdbg_search

    with patch(
        "winbox.kdbg.static_search.search_cached_module",
        side_effect=StaticSearchError("no exact cached PE matches module 'x'"),
    ):
        result = kdbg_search("x", "needle")
    error = _mcp_error(result)
    assert error["code"] == "static_search_error"
    assert error["operation"] == "kdbg_search"


def test_breakpoint_intent_mcp_round_trip_is_detached_and_explicit(mock_mcp):
    from winbox.mcp import (
        kdbg_bp_intent_add,
        kdbg_bp_intent_remove,
        kdbg_bp_intents,
    )

    saved = _mcp_result(kdbg_bp_intent_add(
        "MPENGINE+0x20", condition="rcx != 0", actions=["rip"],
    ))
    assert saved["target"] == "mpengine+0x20"
    assert _mcp_result(kdbg_bp_intents())["intents"] == [saved]
    removed = _mcp_result(kdbg_bp_intent_remove(saved["id"]))
    assert removed["remaining"] == 0


def test_breakpoint_intent_mcp_rejects_resolved_va(mock_mcp):
    from winbox.mcp import kdbg_bp_intent_add

    error = _mcp_error(kdbg_bp_intent_add("0x7ff700001000"))
    assert error["code"] == "breakpoint_intent_error"
    assert error["operation"] == "kdbg_bp_intent_add"


# ─── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def cfg(tmp_path):
    c = Config(winbox_dir=tmp_path / ".winbox")
    c.winbox_dir.mkdir(parents=True)
    c.shared_dir.mkdir(parents=True)
    c.tools_dir.mkdir(parents=True)
    c.loot_dir.mkdir(parents=True)
    return c


@pytest.fixture
def mock_mcp(cfg):
    """Patch MCP server internals so tools run without a real VM.

    Wraps _exec_python so tests can inspect the code/args that were
    sent to the VM via `ga.captured_code` / `ga.captured_args_dict`.
    This replaces the older pattern of reading .mcp/script.py off the
    shared dir, which became unreliable after _exec_python started
    cleaning up its temp files in a finally block.
    """
    import winbox.mcp as mcp_mod
    import winbox.kdbg.staging as staging_mod

    ga = MagicMock()
    ga.ping.return_value = True
    ga.captured_code = None
    ga.captured_args_dict = None

    vm = MagicMock()
    vm.state.return_value = VMState.RUNNING

    mcp_mod._cfg = cfg
    mcp_mod._vm = vm
    mcp_mod._ga = ga
    # State is injected directly, so mark init complete: _get_state now keys
    # its fast path on _initialized rather than on _cfg being non-None.
    mcp_mod._initialized = True

    original_exec_python = mcp_mod._exec_python
    original_debug_snapshot = mcp_mod._kdbg_debug_snapshot
    original_prepare_manifest = staging_mod.prepare_user_module_manifest

    def capturing_exec_python(code, timeout=300, args=None):
        ga.captured_code = code
        ga.captured_args_dict = args
        return original_exec_python(code, timeout=timeout, args=args)

    mcp_mod._exec_python = capturing_exec_python
    # Unit tests must never touch a real VM monitor. Transaction behavior has
    # dedicated tests in test_kdbg_snapshot.py; individual MCP tests can
    # override this stub when asserting the operation boundary.
    mcp_mod._kdbg_debug_snapshot = lambda *_args, **_kwargs: nullcontext()
    staging_mod.prepare_user_module_manifest = lambda _cfg, _ga, _store, pid, **_kw: SimpleNamespace(
        pid=pid,
        summary=lambda: {
            "schema": "winbox.kdbg-user-manifest/1", "pid": pid,
            "discovered": 2, "staged": 2, "symbol_enriched": 2,
            "symbol_failed": 0, "symbol_warning_count": 0, "failed": 0,
            "total_file_bytes": 4096, "symbol_failures": [],
            "symbol_warnings": [], "failures": [],
        },
    )

    yield ga, vm, cfg

    mcp_mod._exec_python = original_exec_python
    mcp_mod._kdbg_debug_snapshot = original_debug_snapshot
    staging_mod.prepare_user_module_manifest = original_prepare_manifest
    mcp_mod._cfg = None
    mcp_mod._vm = None
    mcp_mod._ga = None
    mcp_mod._initialized = False


@pytest.fixture
def runner():
    return CliRunner()


# ─── _ensure_vm_ready ───────────────────────────────────────────────────────


class TestEnsureVmReady:
    def test_running_and_responding(self, mock_mcp):
        from winbox.mcp import _ensure_vm_ready
        ga, vm, cfg = mock_mcp

        result_cfg, result_vm, result_ga = _ensure_vm_ready()
        assert result_cfg is cfg
        ga.ping.assert_called()

    def test_running_not_responding_waits(self, mock_mcp):
        from winbox.mcp import _ensure_vm_ready
        ga, vm, cfg = mock_mcp
        ga.ping.return_value = False

        _ensure_vm_ready()
        ga.wait.assert_called_once_with(timeout=60)

    def test_running_not_responding_timeout(self, mock_mcp):
        from winbox.mcp import _ensure_vm_ready
        from winbox.vm import GuestAgentError
        ga, vm, cfg = mock_mcp
        ga.ping.return_value = False
        ga.wait.side_effect = GuestAgentError("timeout")

        with pytest.raises(RuntimeError, match="not responding"):
            _ensure_vm_ready()

    def test_shutoff_starts_vm(self, mock_mcp):
        from winbox.mcp import _ensure_vm_ready
        ga, vm, cfg = mock_mcp
        vm.state.return_value = VMState.SHUTOFF

        _ensure_vm_ready()
        vm.start.assert_called_once()
        ga.wait.assert_called_once_with(timeout=120)

    def test_paused_resumes_vm(self, mock_mcp):
        from winbox.mcp import _ensure_vm_ready
        ga, vm, cfg = mock_mcp
        vm.state.return_value = VMState.PAUSED

        with patch(
            "winbox.kdbg.debugger.client.DaemonClient"
        ) as dc_cls:
            dc_cls.return_value.session_alive.return_value = False
            _ensure_vm_ready()
        vm.resume.assert_called_once()

    def test_kdbg_walker_tools_work_when_paused(self, mock_mcp):
        """kdbg_ps/kdbg_lm/kdbg_read_va/kdbg_base_refresh use HMP, not GA.
        They must not be blocked when the VM is paused by a kdbg session."""
        ga, vm, cfg = mock_mcp
        vm.state.return_value = VMState.PAUSED

        from winbox.mcp import kdbg_ps
        with patch("winbox.mcp._kdbg_get_store") as mock_store, \
             patch("winbox.mcp._kdbg_list_processes", return_value=[]):
            mock_store.return_value = MagicMock()
            result = kdbg_ps()
        payload = _mcp_result(result)
        assert payload["processes"] == []
        assert payload["count"] == 0
        assert payload["snapshot_metadata"]["admission"] == "unknown"
        vm.resume.assert_not_called()

    def test_paused_with_kdbg_session_refuses(self, mock_mcp):
        from winbox.mcp import _ensure_vm_ready
        ga, vm, cfg = mock_mcp
        vm.state.return_value = VMState.PAUSED

        with patch(
            "winbox.kdbg.debugger.client.DaemonClient"
        ) as dc_cls:
            dc_cls.return_value.session_alive.return_value = True
            with pytest.raises(RuntimeError, match="halted by a kdbg debug session"):
                _ensure_vm_ready()
        vm.resume.assert_not_called()

    def test_paused_without_kdbg_session_resumes(self, mock_mcp):
        from winbox.mcp import _ensure_vm_ready
        ga, vm, cfg = mock_mcp
        vm.state.return_value = VMState.PAUSED

        with patch(
            "winbox.kdbg.debugger.client.DaemonClient"
        ) as dc_cls:
            dc_cls.return_value.session_alive.return_value = False
            _ensure_vm_ready()
        vm.resume.assert_called_once()

    def test_saved_starts_vm(self, mock_mcp):
        from winbox.mcp import _ensure_vm_ready
        ga, vm, cfg = mock_mcp
        vm.state.return_value = VMState.SAVED

        _ensure_vm_ready()
        vm.start.assert_called_once()

    def test_not_found_raises(self, mock_mcp):
        from winbox.mcp import _ensure_vm_ready
        ga, vm, cfg = mock_mcp
        vm.state.return_value = VMState.NOT_FOUND

        with pytest.raises(RuntimeError, match="not found"):
            _ensure_vm_ready()

    def test_unknown_state_raises(self, mock_mcp):
        from winbox.mcp import _ensure_vm_ready
        ga, vm, cfg = mock_mcp
        vm.state.return_value = VMState.UNKNOWN

        with pytest.raises(RuntimeError, match="unexpected state"):
            _ensure_vm_ready()


# ─── _exec_python ───────────────────────────────────────────────────────────


class TestExecPython:
    def test_writes_script_and_executes(self, mock_mcp):
        """_exec_python writes script under per-call uuid subdir, then cleans up."""
        from winbox.mcp import _exec_python
        ga, vm, cfg = mock_mcp

        seen_script = {}
        def capture_fs(*args, **kwargs):
            mcp_root = cfg.shared_dir / ".mcp"
            scripts = list(mcp_root.rglob("script.py"))
            seen_script["count"] = len(scripts)
            if scripts:
                seen_script["path"] = scripts[0]
                seen_script["content"] = scripts[0].read_text()
                seen_script["parent"] = scripts[0].parent.name
            return ExecResult(exitcode=0, stdout="hello\n", stderr="")
        ga.exec.side_effect = capture_fs

        result = _exec_python("print('hello')")

        assert result["exitcode"] == 0
        assert result["stdout"] == "hello\n"

        assert seen_script["count"] == 1
        assert seen_script["content"] == "print('hello')"
        # Parent dir is a uuid hex (32 lowercase hex chars).
        assert len(seen_script["parent"]) == 32
        assert all(c in "0123456789abcdef" for c in seen_script["parent"])

        # Subdir is removed in finally.
        assert not seen_script["path"].exists()
        assert not seen_script["path"].parent.exists()

        ga.exec.assert_called_once()
        cmd = ga.exec.call_args[0][0]
        assert cmd.startswith("python.exe Z:\\.mcp\\")
        assert cmd.endswith("\\script.py")

    def test_concurrent_calls_get_unique_paths(self, mock_mcp):
        """Two _exec_python calls must not share script.py or args.json paths."""
        from winbox.mcp import _exec_python
        ga, vm, cfg = mock_mcp

        seen_cmds = []
        def capture(*args, **kwargs):
            seen_cmds.append(args[0])
            return ExecResult(exitcode=0, stdout="", stderr="")
        ga.exec.side_effect = capture

        _exec_python("pass")
        _exec_python("pass")

        assert len(seen_cmds) == 2
        assert seen_cmds[0] != seen_cmds[1]

    def test_custom_timeout(self, mock_mcp):
        from winbox.mcp import _exec_python
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        _exec_python("pass", timeout=60)
        ga.exec.assert_called_once()
        cmd, = ga.exec.call_args[0]
        assert cmd.startswith("python.exe Z:\\.mcp\\")
        assert cmd.endswith("\\script.py")
        assert ga.exec.call_args[1] == {"timeout": 60}

    def test_returns_stderr(self, mock_mcp):
        from winbox.mcp import _exec_python
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=1, stdout="", stderr="error\n")

        result = _exec_python("bad code")
        assert result["stderr"] == "error\n"
        assert result["exitcode"] == 1

    def test_args_path_rewritten_in_script(self, mock_mcp):
        """Hardcoded Z:\\.mcp\\args.json in script bodies points at per-call file."""
        from winbox.mcp import _exec_python
        ga, vm, cfg = mock_mcp

        seen = {}
        def capture(*args, **kwargs):
            scripts = list((cfg.shared_dir / ".mcp").rglob("script.py"))
            seen["content"] = scripts[0].read_text() if scripts else None
            return ExecResult(exitcode=0, stdout="", stderr="")
        ga.exec.side_effect = capture

        _exec_python("args = open(r'Z:\\.mcp\\args.json').read()", args={"k": "v"})

        assert "Z:\\.mcp\\args.json" not in seen["content"]
        assert "args.json" in seen["content"]


# ─── python tool ────────────────────────────────────────────────────────────


class TestPythonTool:
    def test_returns_structured_json(self, mock_mcp):
        import json
        from winbox.mcp import python
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=0, stdout="42\n", stderr="")

        result = python("print(42)")
        parsed = json.loads(result)
        assert parsed == {"stdout": "42\n", "stderr": "", "exitcode": 0}

    def test_stderr_kept_separate_from_stdout(self, mock_mcp):
        """Regression: prose-blob format used to concatenate stdout+stderr,
        which corrupted callers that expected json.loads(stdout)."""
        import json
        from winbox.mcp import python
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0,
            stdout='{"answer": 42}',
            stderr="DeprecationWarning: foo\n",
        )

        result = python("...")
        parsed = json.loads(result)
        # Caller can json.loads(parsed["stdout"]) cleanly — stderr does not bleed in.
        assert parsed["stdout"] == '{"answer": 42}'
        assert parsed["stderr"] == "DeprecationWarning: foo\n"
        assert json.loads(parsed["stdout"]) == {"answer": 42}

    def test_failure_carries_exitcode(self, mock_mcp):
        import json
        from winbox.mcp import python
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=1, stdout="", stderr="NameError\n")

        result = python("bad")
        parsed = json.loads(result)
        assert parsed["exitcode"] == 1
        assert parsed["stderr"] == "NameError\n"

    def test_no_output(self, mock_mcp):
        import json
        from winbox.mcp import python
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        result = python("pass")
        parsed = json.loads(result)
        assert parsed == {"stdout": "", "stderr": "", "exitcode": 0}

    def test_credentials_are_forwarded(self, mock_mcp):
        from winbox.mcp import python

        with patch("winbox.mcp._exec_python") as execute:
            execute.return_value = {
                "stdout": "ok", "stderr": "", "exitcode": 0,
            }
            python("print('ok')", user="alice", password="secret")

        execute.assert_called_once_with(
            "print('ok')", timeout=300, user="alice", password="secret",
        )


class TestMcpExecSurfaces:
    def test_exec_forwards_credentials(self, mock_mcp):
        import json
        from winbox.mcp import exec as exec_tool

        ga, _, _ = mock_mcp
        ga.exec.return_value = ExecResult(9, "out", "err")
        result = json.loads(
            exec_tool("exit /b 9", user="alice", password="secret")
        )

        ga.exec.assert_called_with(
            "exit /b 9", timeout=300, user="alice", password="secret",
        )
        assert result == {"stdout": "out", "stderr": "err", "exitcode": 9}

    def test_powershell_forwards_credentials(self, mock_mcp):
        import json
        from winbox.mcp import powershell

        ga, _, _ = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "alice", "")
        result = json.loads(
            powershell("whoami", user="alice", password="secret")
        )

        ga.exec_powershell.assert_called_with(
            "whoami", timeout=600, user="alice", password="secret",
        )
        assert result["stdout"] == "alice"


# ─── powershell tool ─────────────────────────────────────────────────────────


class TestPowershellTool:
    def test_returns_structured_json(self, mock_mcp):
        import json
        from winbox.mcp import powershell
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="42\r\n", stderr=""
        )

        result = powershell("Write-Output (6*7)")
        parsed = json.loads(result)
        assert parsed == {"stdout": "42\r\n", "stderr": "", "exitcode": 0}

    def test_stderr_kept_separate_from_stdout(self, mock_mcp):
        """stdout must stay cleanly json.loads-able — stderr does not bleed in."""
        import json
        from winbox.mcp import powershell
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout='{"answer": 42}',
            stderr="WARNING: something\r\n",
        )

        result = powershell("...")
        parsed = json.loads(result)
        assert parsed["stdout"] == '{"answer": 42}'
        assert parsed["stderr"] == "WARNING: something\r\n"
        assert json.loads(parsed["stdout"]) == {"answer": 42}

    def test_failure_carries_exitcode(self, mock_mcp):
        import json
        from winbox.mcp import powershell
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(
            exitcode=3, stdout="", stderr="oops\r\n"
        )

        result = powershell("exit 3")
        parsed = json.loads(result)
        assert parsed["exitcode"] == 3
        assert parsed["stderr"] == "oops\r\n"

    def test_no_output(self, mock_mcp):
        import json
        from winbox.mcp import powershell
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        result = powershell("$null = 1")
        parsed = json.loads(result)
        assert parsed == {"stdout": "", "stderr": "", "exitcode": 0}

    def test_passes_timeout(self, mock_mcp):
        from winbox.mcp import powershell
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        powershell("Get-Date", timeout=60)
        ga.exec_powershell.assert_called_once_with("Get-Date", timeout=60)

    def test_uses_exec_powershell_not_python(self, mock_mcp):
        """Route through the CLIXML/progress-stripping ga.exec_powershell path,
        never the nested python-subprocess approach it exists to replace."""
        from winbox.mcp import powershell
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        powershell("Get-Process")

        ga.exec_powershell.assert_called_once()
        ga.exec.assert_not_called()
        mcp_root = cfg.shared_dir / ".mcp"
        if mcp_root.exists():
            assert list(mcp_root.rglob("script.py")) == []


# ─── background exec / python / powershell + job_result ──────────────────────


class TestBackgroundExec:
    def test_python_background_returns_job_handle(self, mock_mcp):
        import json
        from winbox.mcp import python
        ga, vm, cfg = mock_mcp
        ga.exec_background.return_value = 4321

        out = json.loads(python("while True: pass", background=True))
        assert out == {"background": True, "job_id": 1, "pid": 4321}
        # Fired detached — never waited on via the synchronous path.
        ga.exec.assert_not_called()
        cmd = ga.exec_background.call_args[0][0]
        # Command is nonce-prefixed: echo __wbx<hex>__&&python.exe ...
        assert cmd.startswith("echo __wbx")
        assert "&&python.exe Z:\\.mcp\\jobs\\1\\script.py" in cmd
        # Script materialized in a persistent per-job dir (not the auto-cleaned
        # synchronous one).
        script = cfg.shared_dir / ".mcp" / "jobs" / "1" / "script.py"
        assert script.read_text() == "while True: pass"

    def test_powershell_background_returns_job_handle(self, mock_mcp):
        import json
        from winbox.mcp import powershell
        ga, vm, cfg = mock_mcp
        ga.exec_background.return_value = 999

        out = json.loads(powershell("Start-Sleep 999", background=True))
        assert out == {"background": True, "job_id": 1, "pid": 999}
        # Powershell bg now calls exec_background directly (not
        # exec_powershell_background) so the nonce echo can be prepended.
        ga.exec_background.assert_called_once()
        cmd = ga.exec_background.call_args[0][0]
        assert cmd.startswith("echo __wbx")
        assert "&&powershell -ExecutionPolicy Bypass -EncodedCommand " in cmd
        ga.exec_powershell.assert_not_called()
        ga.exec.assert_not_called()

    def test_exec_background_returns_job_handle(self, mock_mcp):
        import json
        from winbox.mcp import exec as exec_tool
        ga, vm, cfg = mock_mcp
        ga.exec_background.return_value = 555

        out = json.loads(exec_tool("trigger.exe", background=True))
        assert out == {"background": True, "job_id": 1, "pid": 555}
        cmd = ga.exec_background.call_args[0][0]
        assert cmd.startswith("echo __wbx")
        assert "&&trigger.exe" in cmd
        ga.exec.assert_not_called()

    def test_exec_background_forwards_alternate_credentials(self, mock_mcp):
        import json
        from winbox.mcp import exec as exec_tool
        ga, vm, cfg = mock_mcp
        ga.exec_background.return_value = 556

        out = json.loads(exec_tool(
            "whoami", background=True,
            user=r"WINBOX\rpcprobe", password="Cobalt!Raven_2026-47",
        ))

        assert out == {"background": True, "job_id": 1, "pid": 556}
        call_kwargs = ga.exec_background.call_args[1]
        assert call_kwargs["user"] == r"WINBOX\rpcprobe"
        assert call_kwargs["password"] == "Cobalt!Raven_2026-47"
        cmd = ga.exec_background.call_args[0][0]
        assert "&&whoami" in cmd

    def test_python_background_forwards_alternate_credentials(self, mock_mcp):
        import json
        from winbox.mcp import python
        ga, vm, cfg = mock_mcp
        ga.exec_background.return_value = 4332

        out = json.loads(python(
            "import getpass; print(getpass.getuser())", background=True,
            user="rpcprobe", password="Cobalt!Raven_2026-47",
        ))

        assert out == {"background": True, "job_id": 1, "pid": 4332}
        call_kwargs = ga.exec_background.call_args[1]
        assert call_kwargs["user"] == "rpcprobe"
        assert call_kwargs["password"] == "Cobalt!Raven_2026-47"
        cmd = ga.exec_background.call_args[0][0]
        assert r"python.exe Z:\.mcp\jobs\1\script.py" in cmd

    def test_powershell_background_forwards_alternate_credentials(self, mock_mcp):
        import json
        from winbox.mcp import powershell
        ga, vm, cfg = mock_mcp
        ga.exec_background.return_value = 1000

        out = json.loads(powershell(
            "whoami", background=True,
            user="rpcprobe", password="Cobalt!Raven_2026-47",
        ))

        assert out == {"background": True, "job_id": 1, "pid": 1000}
        call_kwargs = ga.exec_background.call_args[1]
        assert call_kwargs["user"] == "rpcprobe"
        assert call_kwargs["password"] == "Cobalt!Raven_2026-47"
        cmd = ga.exec_background.call_args[0][0]
        assert cmd.startswith("echo __wbx")
        assert "&&powershell -ExecutionPolicy Bypass -EncodedCommand " in cmd

    def test_exec_sync_runs_and_returns_structured_json(self, mock_mcp):
        import json
        from winbox.mcp import exec as exec_tool
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=0, stdout="hi\r\n", stderr="")

        out = json.loads(exec_tool("whoami"))
        assert out == {"stdout": "hi\r\n", "stderr": "", "exitcode": 0}
        ga.exec.assert_called_once_with("whoami", timeout=300)
        ga.exec_background.assert_not_called()

    def test_background_job_is_registered_in_jobstore(self, mock_mcp):
        from winbox.mcp import python
        from winbox.jobs import JobStore, JobStatus, JobMode
        ga, vm, cfg = mock_mcp
        ga.exec_background.return_value = 111

        python("print(1)", background=True)
        job = JobStore(cfg).get(1)
        assert job is not None
        assert job.pid == 111
        assert job.status is JobStatus.RUNNING
        assert job.mode is JobMode.BUFFERED
        assert job.nonce.startswith("__wbx") and job.nonce.endswith("__")


class TestJobResult:
    def _launch(self, mock_mcp, pid=7):
        """Launch a background python job and return the stored nonce."""
        from winbox.mcp import python
        from winbox.jobs import JobStore
        ga, vm, cfg = mock_mcp
        ga.exec_background.return_value = pid
        python("print(1)", background=True)
        return JobStore(cfg).get(1).nonce

    def test_unknown_job(self, mock_mcp):
        import json
        from winbox.mcp import job_result
        out = json.loads(job_result(999))
        assert "not found" in out["error"]

    def test_running_job(self, mock_mcp):
        import json
        from winbox.mcp import job_result
        ga, vm, cfg = mock_mcp
        self._launch(mock_mcp, pid=7)
        ga.exec_status.return_value = {
            "exited": False, "exitcode": -1, "stdout": "", "stderr": "",
        }

        out = json.loads(job_result(1))
        assert out == {"job_id": 1, "pid": 7, "running": True}

    def test_finished_job_returns_output_and_cleans_up(self, mock_mcp):
        import json
        from winbox.mcp import job_result
        ga, vm, cfg = mock_mcp
        nonce = self._launch(mock_mcp, pid=8)
        ga.exec_status.return_value = {
            "exited": True, "exitcode": 0,
            "stdout": f"{nonce}\r\n42\r\n", "stderr": "",
        }

        out = json.loads(job_result(1))
        assert out["running"] is False
        assert out["exitcode"] == 0
        # Nonce prefix is stripped — caller sees clean output only.
        assert out["stdout"] == "42\r\n"
        # The per-job script dir is removed once the process is done with it.
        assert not (cfg.shared_dir / ".mcp" / "jobs" / "1").exists()

    def test_powershell_error_is_clixml_decoded(self, mock_mcp):
        """A background job's CLIXML error stderr is decoded on retrieval, the
        same as the synchronous powershell path."""
        import json
        from winbox.mcp import powershell, job_result
        from winbox.jobs import JobStore
        ga, vm, cfg = mock_mcp
        ga.exec_background.return_value = 9
        powershell("asdf", background=True)
        nonce = JobStore(cfg).get(1).nonce
        ga.exec_status.return_value = {
            "exited": True, "exitcode": 1, "stdout": f"{nonce}\r\n",
            "stderr": (
                '#< CLIXML\r\n<Objs xmlns="http://schemas.microsoft.com/'
                'powershell/2004/04"><S S="Error">'
                "asdf : not recognized_x000D__x000A_</S></Objs>"
            ),
        }

        out = json.loads(job_result(1))
        assert out["exitcode"] == 1
        assert "not recognized" in out["stderr"]
        assert "CLIXML" not in out["stderr"]
        assert "_x000D_" not in out["stderr"]

    def test_cached_after_first_poll(self, mock_mcp):
        """The guest agent frees its slot on the read that first saw the exit,
        so a second job_result must serve the cached copy, not re-poll into a
        potentially recycled PID."""
        import json
        from winbox.mcp import job_result
        ga, vm, cfg = mock_mcp
        nonce = self._launch(mock_mcp, pid=10)
        ga.exec_status.return_value = {
            "exited": True, "exitcode": 0,
            "stdout": f"{nonce}\r\ndone\r\n", "stderr": "",
        }
        job_result(1)
        ga.exec_status.reset_mock()

        out = json.loads(job_result(1))
        assert out["stdout"] == "done\r\n"
        ga.exec_status.assert_not_called()

    def test_job_result_rejects_stale_output(self, mock_mcp):
        """When exec_status returns output that doesn't carry the job's nonce,
        the job is marked LOST — the PID was recycled and the output belongs
        to an unrelated process."""
        import json
        from winbox.mcp import job_result
        from winbox.jobs import JobStore, JobStatus
        ga, vm, cfg = mock_mcp
        self._launch(mock_mcp, pid=42)
        ga.exec_status.return_value = {
            "exited": True, "exitcode": 0,
            "stdout": "someone-elses-output\r\n", "stderr": "",
        }

        out = json.loads(job_result(1))
        assert "PID recycled" in out["error"]
        assert JobStore(cfg).get(1).status is JobStatus.LOST

    def test_job_result_strips_nonce_from_stdout(self, mock_mcp):
        """The nonce echo line is stripped from the returned stdout."""
        import json
        from winbox.mcp import job_result
        ga, vm, cfg = mock_mcp
        nonce = self._launch(mock_mcp, pid=50)
        ga.exec_status.return_value = {
            "exited": True, "exitcode": 0,
            "stdout": f"{nonce}\r\nreal output\r\n", "stderr": "",
        }

        out = json.loads(job_result(1))
        assert nonce not in out["stdout"]
        assert out["stdout"] == "real output\r\n"

    def test_job_result_no_nonce_job_passes_through(self, mock_mcp):
        """LOG mode jobs (nonce='') pass through without nonce verification."""
        import json
        from winbox.mcp import job_result
        from winbox.jobs import Job, JobMode, JobStatus, JobStore
        ga, vm, cfg = mock_mcp

        # Manually create a LOG-mode job (no nonce) to simulate the
        # CLI's exec --bg --log path which doesn't go through MCP.
        store = JobStore(cfg)
        store.add(Job(
            id=1, pid=77, command="detached.exe",
            mode=JobMode.LOG, nonce="",
        ))
        ga.exec_status.return_value = {
            "exited": True, "exitcode": 0,
            "stdout": "raw output\r\n", "stderr": "",
        }

        out = json.loads(job_result(1))
        assert out["stdout"] == "raw output\r\n"
        assert out["exitcode"] == 0
        assert JobStore(cfg).get(1).status is JobStatus.DONE

    def test_bg_job_has_nonce(self, mock_mcp):
        """Background python/exec/powershell launches generate a nonce and
        store it in the job."""
        from winbox.mcp import python, exec as exec_tool, powershell
        from winbox.jobs import JobStore
        ga, vm, cfg = mock_mcp
        ga.exec_background.return_value = 100

        python("print(1)", background=True)
        job = JobStore(cfg).get(1)
        assert job.nonce.startswith("__wbx") and job.nonce.endswith("__")
        assert len(job.nonce) == 23  # __wbx(5) + 16 hex + __(2)

        ga.exec_background.return_value = 200
        exec_tool("dir", background=True)
        job = JobStore(cfg).get(2)
        assert job.nonce.startswith("__wbx") and job.nonce.endswith("__")
        assert job.nonce != JobStore(cfg).get(1).nonce  # unique per job

        ga.exec_background.return_value = 300
        powershell("Get-Process", background=True)
        job = JobStore(cfg).get(3)
        assert job.nonce.startswith("__wbx") and job.nonce.endswith("__")

    def test_poll_failure_reports_running_not_lost(self, mock_mcp):
        """A transient GA hiccup must not be reported as a finished/empty job —
        the caller should retry."""
        import json
        from winbox.mcp import job_result
        from winbox.vm import GuestAgentError
        ga, vm, cfg = mock_mcp
        self._launch(mock_mcp, pid=11)
        ga.exec_status.side_effect = GuestAgentError("virtio hiccup")

        out = json.loads(job_result(1))
        assert out["running"] is True
        assert "hiccup" in out["note"]


# ─── ioctl tool ─────────────────────────────────────────────────────────────


class TestIoctlTool:
    def test_generates_ctypes_script(self, mock_mcp):
        import json
        from winbox.mcp import ioctl
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0, stdout="deadbeef\n", stderr=""
        )

        result = ioctl(
            device=r"\\.\PhysicalDrive0",
            code=0x70000,
            input_hex="01020304",
            output_size=256,
        )
        assert "deadbeef" in result

        # Verify the generated script has the right elements
        script = ga.captured_code
        assert "CreateFileW" in script
        assert "DeviceIoControl" in script
        assert "CloseHandle" in script

        # Verify args.json has the right values
        args = ga.captured_args_dict
        assert args["device"] == r"\\.\PhysicalDrive0"
        assert args["code"] == 0x70000
        assert args["input_hex"] == "01020304"
        assert args["output_size"] == 256

    def test_no_input_no_output(self, mock_mcp):
        from winbox.mcp import ioctl
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0, stdout="ok (0 bytes returned)\n", stderr=""
        )

        result = ioctl(device=r"\\.\Null", code=0x1)
        assert "ok" in result

    def test_device_open_failure(self, mock_mcp):
        from winbox.mcp import ioctl
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=1, stdout="", stderr="CreateFileW failed: error 5\n"
        )

        result = ioctl(device=r"\\.\NoDev", code=0x1)
        assert "error 5" in result
        assert "[exit code: 1]" in result


# ─── reg_query tool ─────────────────────────────────────────────────────────


class TestRegQueryTool:
    def test_query_specific_value(self, mock_mcp):
        from winbox.mcp import reg_query
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0,
            stdout="ProductName (REG_SZ): Windows Server 2022 Datacenter\n",
            stderr="",
        )

        result = reg_query(
            key=r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            value="ProductName",
        )
        assert "Windows Server 2022" in result

        script = ga.captured_code
        assert "QueryValueEx" in script

    def test_query_all_values(self, mock_mcp):
        from winbox.mcp import reg_query
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0,
            stdout="val1 (REG_SZ): data1\nval2 (REG_DWORD): 42\n",
            stderr="",
        )

        result = reg_query(key=r"HKLM\SOFTWARE\Test")
        assert "val1" in result
        assert "val2" in result

        script = ga.captured_code
        assert "EnumValue" in script

    def test_key_not_found(self, mock_mcp):
        from winbox.mcp import reg_query
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=1,
            stdout="",
            stderr="Key not found: HKLM\\SOFTWARE\\NoSuch\n",
        )

        result = reg_query(key=r"HKLM\SOFTWARE\NoSuch")
        assert "not found" in result.lower()


# ─── reg_set tool ───────────────────────────────────────────────────────────


class TestRegSetTool:
    def test_set_string_value(self, mock_mcp):
        from winbox.mcp import reg_set
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0,
            stdout=r"Set HKLM\SOFTWARE\Test\MyVal = hello (REG_SZ)" + "\n",
            stderr="",
        )

        result = reg_set(
            key=r"HKLM\SOFTWARE\Test",
            value="MyVal",
            data="hello",
        )
        assert "Set" in result

        script = ga.captured_code
        assert "SetValueEx" in script
        assert "CreateKey" in script

    def test_set_dword(self, mock_mcp):
        from winbox.mcp import reg_set
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0,
            stdout="Set HKLM\\SOFTWARE\\Test\\Num = 1 (REG_DWORD)\n",
            stderr="",
        )

        result = reg_set(
            key=r"HKLM\SOFTWARE\Test",
            value="Num",
            data="1",
            value_type="REG_DWORD",
        )
        assert "REG_DWORD" in result

    def test_set_binary(self, mock_mcp):
        from winbox.mcp import reg_set
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=0, stdout="Set ok\n", stderr="")

        result = reg_set(
            key=r"HKLM\SOFTWARE\Test",
            value="Bin",
            data="deadbeef",
            value_type="REG_BINARY",
        )
        script = ga.captured_code
        assert "REG_BINARY" in script


# ─── ps tool ────────────────────────────────────────────────────────────────


class TestPsTool:
    def test_list_all(self, mock_mcp):
        import json
        from winbox.mcp import ps
        ga, vm, cfg = mock_mcp
        procs = [
            {"pid": 4, "name": "System", "path": None, "working_set_mb": 0.1, "virtual_mb": 0.1},
            {"pid": 672, "name": "lsass.exe", "path": "C:\\Windows\\system32\\lsass.exe", "working_set_mb": 15.2, "virtual_mb": 42.0},
            {"pid": 800, "name": "svchost.exe", "path": "C:\\Windows\\system32\\svchost.exe", "working_set_mb": 22.1, "virtual_mb": 55.3},
        ]
        ga.exec.return_value = ExecResult(
            exitcode=0, stdout=json.dumps(procs, indent=2) + "\n", stderr=""
        )

        result = ps()
        assert "lsass" in result
        assert "svchost" in result
        assert "pid" in result

    def test_filter(self, mock_mcp):
        import json
        from winbox.mcp import ps
        ga, vm, cfg = mock_mcp
        procs = [
            {"pid": 672, "name": "lsass.exe", "path": "C:\\Windows\\system32\\lsass.exe", "working_set_mb": 15.2, "virtual_mb": 42.0},
        ]
        ga.exec.return_value = ExecResult(
            exitcode=0, stdout=json.dumps(procs, indent=2) + "\n", stderr=""
        )

        result = ps(filter="lsass")
        assert "lsass" in result

        script = ga.captured_code
        assert "'lsass'" in script

    def test_no_filter(self, mock_mcp):
        from winbox.mcp import ps
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=0, stdout="[]\n", stderr="")

        ps(filter=None)
        script = ga.captured_code
        assert "None" in script


# ─── reg_delete tool ────────────────────────────────────────────────────────


class TestRegDeleteTool:
    def test_delete_value(self, mock_mcp):
        from winbox.mcp import reg_delete
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0,
            stdout="Deleted value HKLM\\SOFTWARE\\Test\\MyVal\n",
            stderr="",
        )

        result = reg_delete(key=r"HKLM\SOFTWARE\Test", value="MyVal")
        assert "Deleted value" in result

        script = ga.captured_code
        assert "DeleteValue" in script

    def test_delete_key(self, mock_mcp):
        from winbox.mcp import reg_delete
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0,
            stdout="Deleted key HKLM\\SOFTWARE\\Test\n",
            stderr="",
        )

        result = reg_delete(key=r"HKLM\SOFTWARE\Test")
        assert "Deleted key" in result

        script = ga.captured_code
        assert "DeleteKey" in script
        assert "delete_key_tree" in script

    def test_value_not_found(self, mock_mcp):
        from winbox.mcp import reg_delete
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=1,
            stdout="",
            stderr="Not found: HKLM\\SOFTWARE\\Nope\\Val\n",
        )

        result = reg_delete(key=r"HKLM\SOFTWARE\Nope", value="Val")
        assert "not found" in result.lower()

    def test_access_denied(self, mock_mcp):
        from winbox.mcp import reg_delete
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=1,
            stdout="",
            stderr="Access denied: HKLM\\SOFTWARE\\Protected\n",
        )

        result = reg_delete(key=r"HKLM\SOFTWARE\Protected")
        assert "denied" in result.lower()


# ─── upload tool ────────────────────────────────────────────────────────────


class TestUploadTool:
    def test_upload_to_share(self, mock_mcp, tmp_path):
        from winbox.mcp import upload
        ga, vm, cfg = mock_mcp

        # Create a source file on "Kali"
        src = tmp_path / "payload.dll"
        src.write_bytes(b"\x00" * 100)

        result = upload(src=str(src))
        assert "Uploaded" in result
        assert "payload.dll" in result
        assert "100 bytes" in result

        # Verify file was copied to shared dir
        assert (cfg.shared_dir / "payload.dll").exists()

    def test_upload_with_dst(self, mock_mcp, tmp_path):
        import json
        from winbox.mcp import upload
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=0, stdout="ok\n", stderr="")

        src = tmp_path / "evil.exe"
        src.write_bytes(b"MZ" + b"\x00" * 50)

        result = upload(src=str(src), dst="C:\\Users\\Public\\evil.exe")
        assert "Uploaded" in result
        assert "C:\\Users\\Public\\evil.exe" in result

        # Verify args.json was written with correct paths
        args = ga.captured_args_dict
        assert args["dst"] == "C:\\Users\\Public\\evil.exe"
        assert "Z:\\" in args["src"]

    def test_upload_dst_copy_fails(self, mock_mcp, tmp_path):
        from winbox.mcp import upload
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=1, stdout="", stderr="Permission denied\n")

        src = tmp_path / "test.dll"
        src.write_bytes(b"\x00" * 10)

        result = upload(src=str(src), dst="C:\\Windows\\System32\\test.dll")
        assert "failed" in result.lower()

    def test_upload_source_not_found(self, mock_mcp):
        from winbox.mcp import upload
        ga, vm, cfg = mock_mcp

        result = upload(src="/tmp/nonexistent_file.exe")
        assert "not found" in result.lower()


# ─── file_copy tool ─────────────────────────────────────────────────────────


class TestFileCopyTool:
    def test_copy_success(self, mock_mcp):
        import json
        from winbox.mcp import file_copy
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0,
            stdout="Copied Z:\\tools\\cytool.exe -> C:\\temp\\cytool.exe (12345 bytes)\n",
            stderr="",
        )

        result = file_copy(
            src="Z:\\tools\\cytool.exe",
            dst="C:\\temp\\cytool.exe",
        )
        assert "Copied" in result
        assert "12345" in result

        # Verify args.json
        args = ga.captured_args_dict
        assert args["src"] == "Z:\\tools\\cytool.exe"
        assert args["dst"] == "C:\\temp\\cytool.exe"

    def test_source_not_found(self, mock_mcp):
        from winbox.mcp import file_copy
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=1,
            stdout="",
            stderr="Source not found: C:\\nope.exe\n",
        )

        result = file_copy(src="C:\\nope.exe", dst="C:\\temp\\nope.exe")
        assert "not found" in result.lower()

    def test_script_uses_shutil(self, mock_mcp):
        from winbox.mcp import file_copy
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=0, stdout="ok\n", stderr="")

        file_copy(src="a", dst="b")
        script = ga.captured_code
        assert "shutil.copy2" in script


# ─── mem_read tool ──────────────────────────────────────────────────────────


class TestMemReadTool:
    def test_read_success(self, mock_mcp):
        from winbox.mcp import mem_read
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0, stdout="4d5a9000\n", stderr=""
        )

        result = mem_read(pid=672, address="0x7FF600000000", length=4)
        assert "4d5a9000" in result

        script = ga.captured_code
        assert "ReadProcessMemory" in script
        assert "SeDebugPrivilege" in script
        assert "AdjustTokenPrivileges" in script
        assert "672" in script
        assert str(0x7FF600000000) in script

    def test_kernel_address_precision(self, mock_mcp):
        """Address above 2^53 must survive without losing low bits."""
        from winbox.mcp import mem_read
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        big = 0xfffff80012345678
        mem_read(pid=4, address=hex(big), length=8)

        assert str(big) in ga.captured_code

    def test_decimal_address_accepted(self, mock_mcp):
        from winbox.mcp import mem_read
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        mem_read(pid=4, address="65536", length=4)

        assert "address = 65536" in ga.captured_code

    def test_invalid_address_string(self, mock_mcp):
        from winbox.mcp import mem_read
        ga, vm, cfg = mock_mcp

        result = mem_read(pid=4, address="not-a-number", length=4)
        assert "invalid address" in result
        ga.exec.assert_not_called()

    def test_length_too_large(self, mock_mcp):
        from winbox.mcp import mem_read
        ga, vm, cfg = mock_mcp

        result = mem_read(pid=4, address="0x1000", length=2 * 1024 * 1024)
        assert "max 1MB" in result
        ga.exec.assert_not_called()

    def test_open_process_failure(self, mock_mcp):
        from winbox.mcp import mem_read
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=1, stdout="", stderr="OpenProcess failed: error 5\n"
        )

        result = mem_read(pid=4, address="0x0", length=16)
        assert "error 5" in result

    def test_read_failure(self, mock_mcp):
        from winbox.mcp import mem_read
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=1, stdout="", stderr="ReadProcessMemory failed: error 299\n"
        )

        result = mem_read(pid=672, address="0xDEAD", length=4096)
        assert "error 299" in result


# ─── service_stop / service_start tools ─────────────────────────────────────


class TestServiceTools:
    def test_stop_success(self, mock_mcp):
        from winbox.mcp import service_stop
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0,
            stdout="SERVICE_NAME: CyProtectDrv\n        STATE: 1  STOPPED\n",
            stderr="",
        )

        result = service_stop(name="CyProtectDrv")
        assert "STOPPED" in result

        ga.exec.assert_called_with("sc.exe stop CyProtectDrv", timeout=30)

    def test_start_success(self, mock_mcp):
        from winbox.mcp import service_start
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0,
            stdout="SERVICE_NAME: CyProtectDrv\n        STATE: 4  RUNNING\n",
            stderr="",
        )

        result = service_start(name="CyProtectDrv")
        assert "RUNNING" in result

        ga.exec.assert_called_with("sc.exe start CyProtectDrv", timeout=30)

    def test_stop_already_stopped(self, mock_mcp):
        from winbox.mcp import service_stop
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=1062,
            stdout="",
            stderr="The service has not been started.\n",
        )

        result = service_stop(name="WinDefend")
        assert "not been started" in result

    def test_start_already_running(self, mock_mcp):
        from winbox.mcp import service_start
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=1056,
            stdout="",
            stderr="An instance of the service is already running.\n",
        )

        result = service_start(name="sshd")
        assert "already running" in result

    def test_stop_uses_ga_directly(self, mock_mcp):
        """service_stop/start use GA exec directly, not _exec_python."""
        from winbox.mcp import service_stop
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=0, stdout="ok", stderr="")

        service_stop(name="test")

        mcp_root = cfg.shared_dir / ".mcp"
        if mcp_root.exists():
            assert list(mcp_root.rglob("script.py")) == []


# ─── av_enable / av_disable / av_status tools ────────────────────────────────


class TestAvTools:
    def test_status_returns_summary(self, mock_mcp):
        from winbox.mcp import av_status
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout="Defender: ON\n  RealTimeProtection: True\n",
            stderr="",
        )

        result = av_status()
        assert "Defender: ON" in result
        assert "RealTimeProtection: True" in result

    def test_enable_drives_all_steps(self, mock_mcp):
        from winbox.mcp import av_enable
        ga, vm, cfg = mock_mcp
        # Serves the three enable scripts *and* the closing status query.
        ga.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="Defender: ON\n  RealTimeProtection: True\n", stderr=""
        )
        ga.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        result = av_enable()
        assert "Defender enabled" in result

        # 3 PowerShell steps (registry cleanup, exclusions, prefs) + sc.exe
        # start + the status query that backs the claim we just made.
        assert ga.exec_powershell.call_count == 4
        assert "sc.exe start WinDefend" in ga.exec.call_args[0][0]

    def test_enable_does_not_claim_protections_it_has_not_verified(self, mock_mcp):
        """WdFilter is a boot-start driver: when it was disabled at boot,
        real-time protection cannot arm this boot no matter what we ran. An
        agent told "enabled" runs its sample believing it is being scanned."""
        from winbox.mcp import av_enable
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout="Defender: partial\n  RealTimeProtection: False\n",
            stderr="",
        )
        ga.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        result = av_enable()

        assert "Defender enabled (real-time, AMSI, behavior monitoring)" not in result
        assert "not every protection is active" in result
        assert "RealTimeProtection: False" in result
        assert "reboot" in result.lower()

    def test_enable_survives_a_guest_that_wont_answer_the_status_query(self, mock_mcp):
        """A status probe that fails must downgrade the claim, not crash."""
        from winbox.mcp import av_enable
        from winbox.vm import GuestAgentError
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")
        ga.exec_powershell.side_effect = [
            ExecResult(exitcode=0, stdout="", stderr=""),
            ExecResult(exitcode=0, stdout="", stderr=""),
            ExecResult(exitcode=0, stdout="", stderr=""),
            GuestAgentError("guest agent gone"),
        ]

        result = av_enable()
        assert "not every protection is active" in result

    def test_enable_docstring_does_not_promise_no_reboot(self, mock_mcp):
        import winbox.mcp as m
        fn = m.av_enable.fn if hasattr(m.av_enable, "fn") else m.av_enable
        assert "No reboot needed" not in (fn.__doc__ or "")

    def test_enable_start_failure_surfaces_error(self, mock_mcp):
        from winbox.mcp import av_enable
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(exitcode=0, stdout="", stderr="")
        ga.exec.return_value = ExecResult(
            exitcode=5, stdout="Access is denied", stderr=""
        )

        result = av_enable()
        assert result.startswith("error:")
        assert "Failed to start WinDefend" in result
        assert "Access is denied" in result

    def test_disable_requires_confirm(self, mock_mcp):
        from winbox.mcp import av_disable
        ga, vm, cfg = mock_mcp

        result = av_disable()
        assert "confirm=True" in result
        # No reboot, no registry writes without confirmation.
        ga.exec_argv.assert_not_called()
        ga.exec.assert_not_called()

    def test_disable_sets_regkeys_then_reboots(self, mock_mcp):
        from winbox.mcp import av_disable
        from winbox.defender import DISABLE_REG_ARGS
        ga, vm, cfg = mock_mcp
        ga.exec_argv.return_value = ExecResult(exitcode=0, stdout="", stderr="")
        ga.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")
        # exec_powershell serves both the pre-flight Tamper-Protection probe
        # (needs no TAMPER_ON) and the post-reboot verification (needs an OFF
        # status), so one benign payload satisfies both.
        ga.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout="TAMPER_OFF\nDefender: OFF (all protections disabled)\n",
            stderr="",
        )

        with patch("time.sleep"):
            result = av_disable(confirm=True)

        assert "Defender disabled" in result
        assert ga.exec_argv.call_count == len(DISABLE_REG_ARGS)
        reboot_calls = [c for c in ga.exec.call_args_list if "shutdown" in c[0][0]]
        assert len(reboot_calls) == 1
        ga.wait.assert_called_once()

    def test_disable_refuses_when_tamper_protection_on(self, mock_mcp):
        from winbox.mcp import av_disable
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(
            exitcode=0, stdout="TAMPER_ON\n", stderr=""
        )

        result = av_disable(confirm=True)

        assert result.startswith("error:")
        assert "Tamper Protection" in result
        # Gate must trip before any registry write or reboot.
        ga.exec_argv.assert_not_called()
        ga.exec.assert_not_called()

    def test_disable_reports_when_defender_survives_reboot(self, mock_mcp):
        from winbox.mcp import av_disable
        ga, vm, cfg = mock_mcp
        ga.exec_argv.return_value = ExecResult(exitcode=0, stdout="", stderr="")
        ga.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")
        # TP probe passes, but the post-reboot status still shows Defender up.
        ga.exec_powershell.return_value = ExecResult(
            exitcode=0,
            stdout="TAMPER_OFF\nDefender: ON (real-time protection enabled)\n",
            stderr="",
        )

        with patch("time.sleep"):
            result = av_disable(confirm=True)

        assert "still reports active" in result
        assert "Defender disabled" not in result

    def test_disable_reg_failure_aborts_before_reboot(self, mock_mcp):
        from winbox.mcp import av_disable
        ga, vm, cfg = mock_mcp
        ga.exec_argv.return_value = ExecResult(
            exitcode=1, stdout="", stderr="Access denied"
        )

        result = av_disable(confirm=True)
        assert result.startswith("error:")
        # Should not have rebooted.
        ga.exec.assert_not_called()

    def test_disable_reboot_wait_failure(self, mock_mcp):
        from winbox.mcp import av_disable
        from winbox.vm import GuestAgentError
        ga, vm, cfg = mock_mcp
        ga.exec_argv.return_value = ExecResult(exitcode=0, stdout="", stderr="")
        ga.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")
        ga.wait.side_effect = GuestAgentError("timeout")

        with patch("time.sleep"):
            result = av_disable(confirm=True)
        assert "did not" in result and "come back" in result


# ─── net_isolate / net_unplug / net_connect tools ───────────────────────────


class TestNetTools:
    def test_isolate_attaches_nwfilter(self, mock_mcp):
        """net_isolate now uses libvirt nwfilter (guest-proof) instead of
        the old Remove-NetRoute approach that DHCP renewal could undo."""
        from winbox.mcp import net_isolate
        ga, vm, cfg = mock_mcp
        vm.name = "winbox"
        vm.net_link_state = MagicMock(return_value="up")
        vm.net_set_link = MagicMock()

        with patch("winbox.nwfilter.ensure_filter_defined") as mock_define, \
             patch("winbox.nwfilter.attach_filter", return_value=True) as mock_attach:
            result = net_isolate()

        assert "isolated" in result.lower()
        mock_define.assert_called_once()
        mock_attach.assert_called_once_with("winbox")
        # The legacy Remove-NetRoute path must NOT be invoked anymore.
        ga.exec_powershell.assert_not_called()

    def test_isolate_idempotent_when_already_attached(self, mock_mcp):
        from winbox.mcp import net_isolate
        ga, vm, cfg = mock_mcp
        vm.name = "winbox"
        vm.net_link_state = MagicMock(return_value="up")

        with patch("winbox.nwfilter.ensure_filter_defined"), \
             patch("winbox.nwfilter.attach_filter", return_value=False):
            result = net_isolate()

        assert "already" in result.lower()

    def test_isolate_surfaces_nwfilter_error(self, mock_mcp):
        from winbox.mcp import net_isolate
        ga, vm, cfg = mock_mcp
        vm.name = "winbox"

        with patch("winbox.nwfilter.ensure_filter_defined"), \
             patch("winbox.nwfilter.attach_filter",
                   side_effect=RuntimeError("libvirt refused")):
            result = net_isolate()

        assert "failed" in result.lower()
        assert "libvirt refused" in result

    def test_isolate_vm_not_running(self, mock_mcp):
        from winbox.mcp import net_isolate
        ga, vm, cfg = mock_mcp
        vm.state.return_value = VMState.SHUTOFF

        result = net_isolate()
        assert "not running" in result.lower()
        ga.exec_powershell.assert_not_called()

    def test_unplug_sets_link_down(self, mock_mcp):
        from winbox.mcp import net_unplug
        ga, vm, cfg = mock_mcp
        vm.net_set_link = MagicMock(return_value=True)

        result = net_unplug()
        assert "unplugged" in result.lower() or "air-gapped" in result.lower()
        vm.net_set_link.assert_called_once_with("down")

    def test_unplug_vm_not_running(self, mock_mcp):
        from winbox.mcp import net_unplug
        ga, vm, cfg = mock_mcp
        vm.state.return_value = VMState.SHUTOFF

        result = net_unplug()
        assert "not running" in result.lower()

    def test_unplug_no_interface(self, mock_mcp):
        from winbox.mcp import net_unplug
        ga, vm, cfg = mock_mcp
        vm.net_set_link = MagicMock(return_value=False)

        result = net_unplug()
        assert "failed" in result.lower()

    def test_connect_from_isolated_link_up(self, mock_mcp):
        """Undo `net isolate`: link is already up, detach filter, re-DHCP."""
        from winbox.mcp import net_connect
        ga, vm, cfg = mock_mcp
        vm.name = "winbox"
        vm.net_link_state = MagicMock(return_value="up")
        vm.net_set_link = MagicMock()
        vm.ip.return_value = "192.168.122.42"

        with patch("winbox.nwfilter.detach_filter", return_value=True) as mock_detach:
            result = net_connect()

        assert "192.168.122.42" in result
        mock_detach.assert_called_once_with("winbox")
        # link is up → no need to flip it
        vm.net_set_link.assert_not_called()
        # Full release + renew cycle
        cmds = [c[0][0] for c in ga.exec.call_args_list]
        assert any("ipconfig /release" in c for c in cmds)
        assert any("ipconfig /renew" in c for c in cmds)

    def test_connect_from_unplugged_link_down(self, mock_mcp):
        """Undo `net unplug`: link is down, must flip it first."""
        from winbox.mcp import net_connect
        ga, vm, cfg = mock_mcp
        vm.name = "winbox"
        vm.net_link_state = MagicMock(return_value="down")
        vm.net_set_link = MagicMock(return_value=True)
        vm.ip.return_value = "192.168.122.42"

        with patch("winbox.nwfilter.detach_filter", return_value=False):
            result = net_connect()

        assert "192.168.122.42" in result
        vm.net_set_link.assert_called_once_with("up")
        # Restart-NetAdapter after link-up so DHCP re-queries
        assert ga.exec_powershell.called
        cmds = [c[0][0] for c in ga.exec.call_args_list]
        assert any("ipconfig /release" in c for c in cmds)
        assert any("ipconfig /renew" in c for c in cmds)

    def test_connect_unplug_link_up_fails(self, mock_mcp):
        from winbox.mcp import net_connect
        ga, vm, cfg = mock_mcp
        vm.name = "winbox"
        vm.net_link_state = MagicMock(return_value="down")
        vm.net_set_link = MagicMock(return_value=False)

        with patch("winbox.nwfilter.detach_filter", return_value=False):
            result = net_connect()
        assert "failed" in result.lower()
        ga.exec.assert_not_called()

    def test_connect_vm_not_running(self, mock_mcp):
        from winbox.mcp import net_connect
        ga, vm, cfg = mock_mcp
        vm.state.return_value = VMState.SHUTOFF

        result = net_connect()
        assert "not running" in result.lower()


# ─── CLI command ────────────────────────────────────────────────────────────


class TestMcpCli:
    def test_help(self, runner):
        from winbox.cli import cli
        result = runner.invoke(cli, ["mcp", "--help"])
        assert result.exit_code == 0
        assert "MCP server" in result.output

    def test_import_error(self, runner):
        """When mcp package is missing, show install instructions."""
        from winbox.cli import cli

        with patch.dict("sys.modules", {"winbox.mcp": None}):
            result = runner.invoke(cli, ["mcp"])
            assert result.exit_code != 0
            assert "pip install winbox[mcp]" in result.output


# ─── _get_state ─────────────────────────────────────────────────────────────


class TestGetState:
    def test_creates_instances_once(self):
        import winbox.mcp as mcp_mod

        # Reset
        mcp_mod._cfg = None
        mcp_mod._vm = None
        mcp_mod._ga = None
        mcp_mod._initialized = False

        with patch("winbox.mcp.Config.load") as mock_load, \
             patch("winbox.mcp.VM") as mock_vm_cls, \
             patch("winbox.mcp.GuestAgent") as mock_ga_cls:
            mock_cfg = MagicMock()
            mock_load.return_value = mock_cfg

            cfg1, vm1, ga1 = mcp_mod._get_state()
            cfg2, vm2, ga2 = mcp_mod._get_state()

            # Should only create once
            mock_load.assert_called_once()
            assert cfg1 is cfg2
            assert vm1 is vm2
            assert ga1 is ga2

        # Cleanup
        mcp_mod._cfg = None
        mcp_mod._vm = None
        mcp_mod._ga = None
        mcp_mod._initialized = False


# ─── pipe_list / pipe_info / pipe_connect tools ─────────────────────────────


class TestPipeTools:
    def test_pipe_list_no_filter(self, mock_mcp):
        import json
        from winbox.mcp import pipe_list
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0,
            stdout=json.dumps(["lsass", "svcctl", "winreg"]) + "\n",
            stderr="",
        )

        result = pipe_list()
        assert "lsass" in result
        assert "svcctl" in result

    def test_pipe_list_with_filter(self, mock_mcp):
        import json
        from winbox.mcp import pipe_list
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0,
            stdout=json.dumps(["lsass"]) + "\n",
            stderr="",
        )

        result = pipe_list(filter="lsass")
        assert "lsass" in result
        assert ga.captured_args_dict["filter"] == "lsass"

    def test_pipe_list_empty(self, mock_mcp):
        import json
        from winbox.mcp import pipe_list
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0, stdout=json.dumps([]) + "\n", stderr=""
        )

        result = pipe_list(filter="nomatch")
        assert "[]" in result

    def test_pipe_info_success(self, mock_mcp):
        import json
        from winbox.mcp import pipe_info
        ga, vm, cfg = mock_mcp
        info = {
            "pipe": "\\\\.\\pipe\\svcctl",
            "mode": "message",
            "end": "server",
            "out_buf": 4096,
            "in_buf": 4096,
            "max_instances": "unlimited",
            "sddl": "O:SYG:SYD:(A;;0x12019b;;;WD)",
        }
        ga.exec.return_value = ExecResult(
            exitcode=0, stdout=json.dumps(info) + "\n", stderr=""
        )

        result = pipe_info(name="svcctl")
        assert '"mode": "message"' in result
        assert "O:SYG:SYD:" in result

        assert ga.captured_args_dict["name"] == "svcctl"

    def test_pipe_info_access_denied(self, mock_mcp):
        import json
        from winbox.mcp import pipe_info
        ga, vm, cfg = mock_mcp
        info = {"pipe": "\\\\.\\pipe\\lsass", "error": "Cannot open (error 5)", "sddl": None}
        ga.exec.return_value = ExecResult(
            exitcode=1, stdout=json.dumps(info) + "\n", stderr=""
        )

        result = pipe_info(name="lsass")
        assert "error 5" in result
        assert '"sddl": null' in result
        assert "[exit code: 1]" in result

    def test_pipe_info_get_info_failure(self, mock_mcp):
        """GetNamedPipeInfo failure is reported, not silently dropped."""
        import json
        from winbox.mcp import pipe_info
        ga, vm, cfg = mock_mcp
        info = {
            "pipe": "\\\\.\\pipe\\svcctl",
            "error": "GetNamedPipeInfo failed (error 6)",
            "sddl": None,
        }
        ga.exec.return_value = ExecResult(
            exitcode=1, stdout=json.dumps(info) + "\n", stderr=""
        )

        result = pipe_info(name="svcctl")
        assert "GetNamedPipeInfo failed" in result
        assert "[exit code: 1]" in result

    def test_pipe_connect_success(self, mock_mcp):
        from winbox.mcp import pipe_connect
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0,
            stdout="OK: opened \\\\.\\pipe\\svcctl [read] successfully\n",
            stderr="",
        )

        result = pipe_connect(name="svcctl")
        assert "OK" in result

        assert ga.captured_args_dict["name"] == "svcctl"
        assert ga.captured_args_dict["access"] == "read"

    def test_pipe_connect_access_denied(self, mock_mcp):
        from winbox.mcp import pipe_connect
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=1,
            stdout="",
            stderr="FAILED: \\\\.\\pipe\\lsass [write] -> ACCESS_DENIED\n",
        )

        result = pipe_connect(name="lsass", access="write")
        assert "ACCESS_DENIED" in result

    def test_pipe_connect_readwrite(self, mock_mcp):
        from winbox.mcp import pipe_connect
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0, stdout="OK: opened \\\\.\\pipe\\test [readwrite] successfully\n", stderr=""
        )

        pipe_connect(name="test", access="readwrite")
        assert ga.captured_args_dict["access"] == "readwrite"


# ─── pipe_open / pipe_send / pipe_recv / pipe_close (session-based) ──────────


def _make_session(cfg, session_id: str) -> object:
    """Create a session dir with a fake ready status.json."""
    from pathlib import Path
    session_dir = cfg.shared_dir / ".mcp" / "pipes" / session_id
    session_dir.mkdir(parents=True, exist_ok=True)
    (session_dir / "status.json").write_text('{"status": "ready"}')
    return session_dir


def _pending_cmds(session_dir):
    """(seq, path) for every command file the broker hasn't consumed, in order."""
    out = []
    for p in session_dir.glob("cmd.*.json"):
        try:
            out.append((int(p.name[4:-5]), p))
        except ValueError:
            continue
    return sorted(out)


def _broker_thread(session_dir, response: dict, *, delay: float = 0.05, count: int = 1):
    """Simulate the broker: consume the next cmd.<seq>.json, answer into
    result.<seq>.json. `response` may be a dict or a list of dicts (one per
    command served)."""
    import json
    import threading
    import time as _t

    responses = response if isinstance(response, list) else [response] * count

    def _run():
        deadline = _t.time() + 3
        served = 0
        while _t.time() < deadline and served < len(responses):
            pending = _pending_cmds(session_dir)
            if pending:
                seq, path = pending[0]
                path.unlink()
                _t.sleep(delay)
                (session_dir / f"result.{seq}.json").write_text(
                    json.dumps({**responses[served], "seq": seq})
                )
                served += 1
                continue
            _t.sleep(0.01)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


class TestPipeSession:
    # ── pipe_open ──────────────────────────────────────────────────────────────

    def test_open_success(self, mock_mcp):
        import json
        from unittest.mock import patch
        from winbox.mcp import pipe_open
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=0, stdout="pid:1234\n", stderr="")

        # Intercept _exec_python to write status.json immediately
        import winbox.mcp as mcp_mod
        real_exec = mcp_mod._exec_python

        def _fake_exec(code, timeout=300, args=None):
            result = real_exec(code, timeout=timeout, args=args)
            # Find the session dir that was just created and write status.json
            pipes_dir = cfg.shared_dir / ".mcp" / "pipes"
            for d in pipes_dir.iterdir():
                sfile = d / "status.json"
                if not sfile.exists():
                    sfile.write_text('{"status": "ready"}')
            return result

        with patch.object(mcp_mod, '_exec_python', side_effect=_fake_exec):
            session_id = pipe_open(name="srvsvc")

        assert len(session_id) == 12
        assert session_id.isalnum()

        # Broker script and config were written
        session_dir = cfg.shared_dir / ".mcp" / "pipes" / session_id
        assert (session_dir / "broker.py").exists()
        config = json.loads((session_dir / "config.json").read_text())
        assert config["name"] == "srvsvc"
        assert config["access"] == "readwrite"

    def test_open_spawner_failure(self, mock_mcp):
        from winbox.mcp import pipe_open
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=1, stdout="", stderr="python not found\n"
        )

        result = pipe_open(name="srvsvc")
        assert "spawner failed" in result

    def test_open_broker_error(self, mock_mcp):
        import winbox.mcp as mcp_mod
        from unittest.mock import patch
        from winbox.mcp import pipe_open
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=0, stdout="pid:1234\n", stderr="")

        def _fake_exec(code, timeout=300, args=None):
            pipes_dir = cfg.shared_dir / ".mcp" / "pipes"
            if pipes_dir.exists():
                for d in pipes_dir.iterdir():
                    sfile = d / "status.json"
                    if not sfile.exists():
                        sfile.write_text('{"status": "error", "error": "ACCESS_DENIED"}')
            return {"exitcode": 0, "stdout": "pid:1234\n", "stderr": ""}

        with patch.object(mcp_mod, '_exec_python', side_effect=_fake_exec):
            result = pipe_open(name="lsass")

        assert "ACCESS_DENIED" in result

    def test_open_broker_error_kills_orphan_broker(self, mock_mcp):
        """On broker-error path the orphaned python.exe must be taskkilled —
        otherwise repeated pipe_open failures accumulate zombie brokers."""
        import winbox.mcp as mcp_mod
        from unittest.mock import patch
        from winbox.mcp import pipe_open
        ga, vm, cfg = mock_mcp

        def _fake_exec(code, timeout=300, args=None):
            pipes_dir = cfg.shared_dir / ".mcp" / "pipes"
            if pipes_dir.exists():
                for d in pipes_dir.iterdir():
                    sfile = d / "status.json"
                    if not sfile.exists():
                        sfile.write_text('{"status": "error", "error": "boom"}')
            return {"exitcode": 0, "stdout": "pid:4242\n", "stderr": ""}

        # _is_broker_alive confirms the PID is still python.exe.
        ga.exec.return_value = ExecResult(
            exitcode=0, stdout="4242 python.exe", stderr=""
        )
        ga.exec_argv.return_value = ExecResult(exitcode=0, stdout="", stderr="")
        with patch.object(mcp_mod, "_exec_python", side_effect=_fake_exec):
            pipe_open(name="lsass")

        taskkill_calls = [
            c for c in ga.exec_argv.call_args_list
            if c[0][0] == "taskkill.exe" and "/PID" in c[0][1] and "4242" in c[0][1]
        ]
        assert len(taskkill_calls) == 1, (
            f"expected one taskkill /F /PID 4242 call on broker error, "
            f"got {len(taskkill_calls)}: {ga.exec_argv.call_args_list}"
        )

    def test_open_timeout_kills_orphan_broker(self, mock_mcp):
        """On the timeout path the orphaned broker must also be taskkilled."""
        import winbox.mcp as mcp_mod
        from unittest.mock import patch
        from winbox.mcp import pipe_open
        ga, vm, cfg = mock_mcp

        def _fake_exec(code, timeout=300, args=None):
            # Never writes status.json → pipe_open polls until timeout.
            return {"exitcode": 0, "stdout": "pid:7777\n", "stderr": ""}

        # _is_broker_alive confirms the PID is still python.exe.
        ga.exec.return_value = ExecResult(
            exitcode=0, stdout="7777 python.exe", stderr=""
        )
        ga.exec_argv.return_value = ExecResult(exitcode=0, stdout="", stderr="")
        with patch.object(mcp_mod, "_exec_python", side_effect=_fake_exec):
            result = pipe_open(name="srvsvc", timeout=0)  # instant timeout

        assert "timeout" in result
        taskkill_calls = [
            c for c in ga.exec_argv.call_args_list
            if c[0][0] == "taskkill.exe" and "/PID" in c[0][1] and "7777" in c[0][1]
        ]
        assert len(taskkill_calls) == 1, (
            f"expected one taskkill /F /PID 7777 call on timeout, "
            f"got {len(taskkill_calls)}: {ga.exec_argv.call_args_list}"
        )

    def test_open_timeout_kills_broker_via_pid_file_when_stdout_pid_missing(self, mock_mcp):
        """If the spawner's 'pid:' stdout line is lost, _abort must still kill
        the broker using the broker.pid file the broker writes itself —
        otherwise a wedged broker leaks a python.exe + pipe instance."""
        import winbox.mcp as mcp_mod
        from unittest.mock import patch
        from winbox.mcp import pipe_open
        ga, vm, cfg = mock_mcp

        def _fake_exec(code, timeout=300, args=None):
            # Broker self-writes its pid but never writes status.json → timeout.
            # stdout carries NO 'pid:' line, so the host parse yields nothing.
            pipes_dir = cfg.shared_dir / ".mcp" / "pipes"
            if pipes_dir.exists():
                for d in pipes_dir.iterdir():
                    (d / "broker.pid").write_text("9191")
            return {"exitcode": 0, "stdout": "", "stderr": ""}

        # _is_broker_alive confirms the PID is still python.exe.
        ga.exec.return_value = ExecResult(
            exitcode=0, stdout="9191 python.exe", stderr=""
        )
        ga.exec_argv.return_value = ExecResult(exitcode=0, stdout="", stderr="")
        with patch.object(mcp_mod, "_exec_python", side_effect=_fake_exec):
            result = pipe_open(name="srvsvc", timeout=0)

        assert "timeout" in result
        taskkill_calls = [
            c for c in ga.exec_argv.call_args_list
            if c[0][0] == "taskkill.exe" and "/PID" in c[0][1] and "9191" in c[0][1]
        ]
        assert len(taskkill_calls) == 1, (
            f"expected taskkill of the broker-written PID 9191, got "
            f"{ga.exec_argv.call_args_list}"
        )

    def test_open_success_does_not_kill_broker(self, mock_mcp):
        """Happy path must not taskkill the broker we just launched."""
        import winbox.mcp as mcp_mod
        from unittest.mock import patch
        from winbox.mcp import pipe_open
        ga, vm, cfg = mock_mcp

        def _fake_exec(code, timeout=300, args=None):
            pipes_dir = cfg.shared_dir / ".mcp" / "pipes"
            if pipes_dir.exists():
                for d in pipes_dir.iterdir():
                    sfile = d / "status.json"
                    if not sfile.exists():
                        sfile.write_text('{"status": "ready"}')
            return {"exitcode": 0, "stdout": "pid:5555\n", "stderr": ""}

        with patch.object(mcp_mod, "_exec_python", side_effect=_fake_exec):
            session_id = pipe_open(name="srvsvc")

        assert len(session_id) == 12
        taskkill_calls = [
            c for c in ga.exec_argv.call_args_list
            if c[0][0] == "taskkill.exe"
        ]
        assert taskkill_calls == [], (
            f"taskkill must not run on success path, got: {taskkill_calls}"
        )

    # ── pipe_send ──────────────────────────────────────────────────────────────

    def test_send_success(self, mock_mcp):
        import json
        from winbox.mcp import pipe_send
        _, _, cfg = mock_mcp

        sid = "aabbcc001122"
        session_dir = _make_session(cfg, sid)
        _broker_thread(session_dir, {"ok": True, "written": 4})

        result = pipe_send(sid, "deadbeef")
        assert "wrote 4 bytes" in result

    def test_send_write_error(self, mock_mcp):
        from winbox.mcp import pipe_send
        _, _, cfg = mock_mcp

        sid = "aabbcc001123"
        session_dir = _make_session(cfg, sid)
        _broker_thread(session_dir, {"ok": False, "error": "WriteFile failed: error 109"})

        result = pipe_send(sid, "ff")
        assert "error 109" in result

    def test_send_session_not_found(self, mock_mcp):
        from winbox.mcp import pipe_send
        result = pipe_send("nonexistent123", "deadbeef")
        assert "session not found" in result

    def test_send_timeout(self, mock_mcp):
        from winbox.mcp import pipe_send
        _, _, cfg = mock_mcp

        sid = "aabbcc001124"
        _make_session(cfg, sid)
        # No broker thread — result.json never appears

        result = pipe_send(sid, "ff", timeout=0)
        assert "timeout" in result

    def test_send_invalid_hex_rejected_before_broker(self, mock_mcp):
        """A malformed payload must fail fast host-side and never reach the
        broker — an unguarded bytes.fromhex there would crash it and wedge the
        whole session."""
        from winbox.mcp import pipe_send
        _, _, cfg = mock_mcp

        sid = "aabbcc001125"
        session_dir = _make_session(cfg, sid)

        # Note: bytes.fromhex tolerates inter-byte spaces, so "de ad" is valid;
        # these are genuinely malformed (odd length / non-hex characters).
        for bad in ("abc", "xy", "zz"):
            result = pipe_send(sid, bad)
            assert "not valid hex" in result
        # No command file was ever written for the broker to choke on.
        assert _pending_cmds(session_dir) == []

    # ── pipe_recv ──────────────────────────────────────────────────────────────

    def test_recv_success(self, mock_mcp):
        from winbox.mcp import pipe_recv
        _, _, cfg = mock_mcp

        sid = "aabbcc001125"
        session_dir = _make_session(cfg, sid)
        _broker_thread(session_dir, {"ok": True, "data_hex": "deadbeef"})

        result = pipe_recv(sid, 4)
        assert result == "deadbeef"

    def test_recv_read_error(self, mock_mcp):
        from winbox.mcp import pipe_recv
        _, _, cfg = mock_mcp

        sid = "aabbcc001126"
        session_dir = _make_session(cfg, sid)
        _broker_thread(session_dir, {"ok": False, "error": "ReadFile failed: error 109"})

        result = pipe_recv(sid, 256)
        assert "error 109" in result

    def test_recv_session_not_found(self, mock_mcp):
        from winbox.mcp import pipe_recv
        result = pipe_recv("nonexistent456", 64)
        assert "session not found" in result

    def test_recv_cmd_written(self, mock_mcp):
        import json
        from winbox.mcp import pipe_recv
        _, _, cfg = mock_mcp

        sid = "aabbcc001127"
        session_dir = _make_session(cfg, sid)
        _broker_thread(session_dir, {"ok": True, "data_hex": "ff"})

        pipe_recv(sid, 128)
        # cmd.json was consumed by the broker thread — just check result
        # (cmd.json is deleted by broker before writing result)

    # ── pipe_close ─────────────────────────────────────────────────────────────

    def test_close_success(self, mock_mcp):
        from winbox.mcp import pipe_close
        _, _, cfg = mock_mcp

        sid = "aabbcc001128"
        session_dir = _make_session(cfg, sid)
        _broker_thread(session_dir, {"ok": True})

        result = pipe_close(sid)
        assert "closed session" in result
        assert not session_dir.exists()

    def test_close_session_not_found(self, mock_mcp):
        from winbox.mcp import pipe_close
        result = pipe_close("nonexistent789")
        assert "session not found" in result

    def test_close_cleans_up_even_without_broker_ack(self, mock_mcp):
        from winbox.mcp import pipe_close
        _, _, cfg = mock_mcp

        sid = "aabbcc001129"
        session_dir = _make_session(cfg, sid)
        # No broker thread — no result ever appears; close should still clean up

        result = pipe_close(sid)
        assert "closed session" in result
        assert not session_dir.exists()

    # ── broker script content ──────────────────────────────────────────────────

    def test_broker_script_content(self, mock_mcp):
        from winbox.mcp import _BROKER_SCRIPT
        assert "chr(92)" in _BROKER_SCRIPT
        assert "WriteFile" in _BROKER_SCRIPT
        assert "ReadFile" in _BROKER_SCRIPT
        assert "status.json" in _BROKER_SCRIPT
        # Assert the sequence-numbered protocol specifically. Matching on a
        # bare "cmd." prefix passes against almost any text, which would let a
        # regression back to the fixed cmd.json/result.json pair — the desync
        # this protocol exists to prevent — sail straight through.
        assert "result.%d.json" in _BROKER_SCRIPT, "results must be seq-numbered"
        assert "startswith('cmd.')" in _BROKER_SCRIPT
        assert "endswith('.json')" in _BROKER_SCRIPT
        # The fixed single-slot filenames must not come back.
        assert "cmd.json" not in _BROKER_SCRIPT
        assert "result.json" not in _BROKER_SCRIPT

    def test_broker_script_is_valid_python(self, mock_mcp):
        import ast
        from winbox.mcp import _BROKER_SCRIPT
        ast.parse(_BROKER_SCRIPT)  # raises SyntaxError if invalid


class TestPipeSessionDoesNotDesync:
    """One timed-out pipe call used to poison the session forever: commands
    and results were unkeyed, so a late answer was consumed by whatever call
    polled next."""

    def test_a_late_result_is_never_handed_to_the_next_call(self, mock_mcp):
        """The exact reported sequence: a recv times out, then the broker
        answers a *write*. The next recv must not receive that write's result
        (which has no data_hex and used to raise KeyError out of the tool)."""
        import json
        from winbox.mcp import pipe_recv, pipe_send
        _, _, cfg = mock_mcp

        sid = "de5ync000001"
        session_dir = _make_session(cfg, sid)

        # 1. recv times out with nothing answering.
        assert "timeout" in pipe_recv(sid, 1024, timeout=0)
        # 2. send times out too.
        assert "timeout" in pipe_send(sid, "deadbeef", timeout=0)
        # 3. the broker now wakes up and answers both abandoned commands.
        for seq, path in _pending_cmds(session_dir):
            cmd = json.loads(path.read_text())
            path.unlink()
            answer = (
                {"ok": True, "data_hex": "cafe"} if cmd["cmd"] == "read"
                else {"ok": True, "written": 4}
            )
            (session_dir / f"result.{seq}.json").write_text(
                json.dumps({**answer, "seq": seq})
            )

        # 4. a fresh recv recovers the orphaned read data first.
        assert pipe_recv(sid, 16) == "cafe"
        # 5. the next recv gets a fresh answer from the broker.
        _broker_thread(session_dir, {"ok": True, "data_hex": "beef"})
        assert pipe_recv(sid, 16) == "beef"

    def test_a_stale_answer_alone_does_not_satisfy_a_new_call(self, mock_mcp):
        """Belt and braces: an orphan result from an earlier seq must not be
        mistaken for the current call's."""
        import json
        from winbox.mcp import pipe_recv
        _, _, cfg = mock_mcp

        sid = "de5ync000002"
        session_dir = _make_session(cfg, sid)
        (session_dir / "result.1.json").write_text(
            json.dumps({"ok": True, "written": 4, "seq": 1})
        )

        result = pipe_recv(sid, 16, timeout=0)
        assert "timeout" in result

    def test_a_command_is_not_overwritten_while_another_is_in_flight(self, mock_mcp):
        """Both commands went to the same fixed cmd.json, so a call issued
        while the broker was busy silently destroyed the previous one."""
        import json
        from winbox.mcp import pipe_recv, pipe_send
        _, _, cfg = mock_mcp

        sid = "de5ync000003"
        session_dir = _make_session(cfg, sid)

        pipe_recv(sid, 1024, timeout=0)
        pipe_send(sid, "deadbeef", timeout=0)

        pending = [json.loads(p.read_text()) for _, p in _pending_cmds(session_dir)]
        assert [c["cmd"] for c in pending] == ["read", "write"]
        assert [c["seq"] for c in pending] == sorted(c["seq"] for c in pending)

    def test_recv_reports_an_unexpected_result_shape_as_an_error(self, mock_mcp):
        """Never a KeyError out of an MCP tool call."""
        from winbox.mcp import pipe_recv
        _, _, cfg = mock_mcp

        sid = "de5ync000004"
        session_dir = _make_session(cfg, sid)
        _broker_thread(session_dir, {"ok": True, "written": 4})

        result = pipe_recv(sid, 16)
        assert "error" in result

    def test_recv_asks_the_broker_to_time_out_first(self, mock_mcp):
        """ReadFile on the synchronous handle blocks forever with no data and
        nothing host-side can cancel it, so the broker needs its own deadline —
        shorter than ours, or the answer arrives after we've given up."""
        import json
        from winbox.mcp import pipe_recv
        _, _, cfg = mock_mcp

        sid = "de5ync000005"
        session_dir = _make_session(cfg, sid)
        pipe_recv(sid, 16, timeout=0)

        cmd = json.loads(_pending_cmds(session_dir)[0][1].read_text())
        assert "wait_ms" in cmd

    def test_broker_side_timeout_is_reported_as_no_data(self, mock_mcp):
        from winbox.mcp import pipe_recv
        _, _, cfg = mock_mcp

        sid = "de5ync000006"
        session_dir = _make_session(cfg, sid)
        _broker_thread(
            session_dir,
            {"ok": False, "timed_out": True, "error": "no data available within 9.0s"},
        )

        result = pipe_recv(sid, 16)
        assert "no data" in result

    def test_broker_peeks_before_reading_and_exits_when_its_dir_is_gone(self, mock_mcp):
        """Both halves of "a wedged broker is unreachable": it must be able to
        time out a read, and it must give up when pipe_close removes the
        session dir it takes orders from."""
        from winbox.mcp import _BROKER_SCRIPT
        assert "PeekNamedPipe" in _BROKER_SCRIPT
        assert "config_file" in _BROKER_SCRIPT

    def test_broker_cmd_does_not_delete_another_in_flight_calls_result(self, mock_mcp):
        """A readwrite session has pipe_send/pipe_recv racing concurrently by
        design (pipe_open's own docstring). A stray result belonging to some
        other call that hasn't been polled for yet must survive issuing a
        new command -- deleting it would be real data already dequeued off
        the guest's pipe, gone for good, not just a status string."""
        import json
        from winbox.mcp import pipe_send
        _, _, cfg = mock_mcp

        sid = "nosweep00001"
        session_dir = _make_session(cfg, sid)
        (session_dir / "result.999.json").write_text(
            json.dumps({"ok": True, "data_hex": "cafe", "seq": 999})
        )

        pipe_send(sid, "deadbeef", timeout=0)

        assert (session_dir / "result.999.json").exists()

    def test_next_seq_is_race_free_under_concurrent_callers(self, mock_mcp):
        """Without a lock around the read-modify-write of the seq file, two
        callers racing _broker_cmd (exactly what readwrite pipe_send/recv
        does) can read the same current value and allocate the same seq --
        one command's cmd.<seq>.json silently overwriting the other's
        before the broker ever reads it."""
        import threading
        from winbox.mcp import _next_seq
        _, _, cfg = mock_mcp

        sid = "raceseq00001"
        session_dir = _make_session(cfg, sid)

        results = []
        results_lock = threading.Lock()

        def worker():
            seq = _next_seq(session_dir)
            with results_lock:
                results.append(seq)

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == len(set(results)), f"seq collision: {sorted(results)}"
        assert sorted(results) == list(range(1, 51))


class TestPipeRecvOrphanRecovery:
    """Item 24: a timed-out pipe_recv leaves orphaned bytes — the broker
    already dequeued them from the pipe but the host never read the result
    file. The next pipe_recv must reclaim them before issuing a new read."""

    def test_recovers_orphaned_read_data(self, mock_mcp):
        import json
        from winbox.mcp import pipe_recv
        _, _, cfg = mock_mcp

        sid = "orphan000001"
        session_dir = _make_session(cfg, sid)
        (session_dir / "result.1.json").write_text(
            json.dumps({"ok": True, "data_hex": "deadbeef", "seq": 1})
        )
        assert pipe_recv(sid, 16) == "deadbeef"
        assert not (session_dir / "result.1.json").exists()

    def test_skips_write_results(self, mock_mcp):
        import json
        from winbox.mcp import pipe_recv
        _, _, cfg = mock_mcp

        sid = "orphan000002"
        session_dir = _make_session(cfg, sid)
        (session_dir / "result.1.json").write_text(
            json.dumps({"ok": True, "written": 4, "seq": 1})
        )
        result = pipe_recv(sid, 16, timeout=0)
        assert "timeout" in result
        assert (session_dir / "result.1.json").exists()

    def test_recovers_oldest_first(self, mock_mcp):
        import json
        from winbox.mcp import pipe_recv
        _, _, cfg = mock_mcp

        sid = "orphan000003"
        session_dir = _make_session(cfg, sid)
        (session_dir / "result.5.json").write_text(
            json.dumps({"ok": True, "data_hex": "second", "seq": 5})
        )
        (session_dir / "result.2.json").write_text(
            json.dumps({"ok": True, "data_hex": "first", "seq": 2})
        )
        assert pipe_recv(sid, 16) == "first"
        assert pipe_recv(sid, 16) == "second"

    def test_no_orphans_issues_fresh_read(self, mock_mcp):
        from winbox.mcp import pipe_recv
        _, _, cfg = mock_mcp

        sid = "orphan000004"
        _make_session(cfg, sid)
        result = pipe_recv(sid, 16, timeout=0)
        assert "timeout" in result


class TestPipeCloseDoesNotLeakTheBroker:
    """pipe_close deleted broker.pid along with the session dir, so a broker
    still blocked in ReadFile kept the pipe handle (and one of the pipe's
    instances) forever with nothing left able to kill it."""

    def test_unacknowledged_close_taskkills_the_broker(self, mock_mcp):
        from winbox.mcp import pipe_close
        ga, _, cfg = mock_mcp

        sid = "1eak00000001"
        session_dir = _make_session(cfg, sid)
        (session_dir / "broker.pid").write_text("4242")
        # _is_broker_alive checks via ga.exec — confirm the PID is still python.exe.
        ga.exec.return_value = ExecResult(
            exitcode=0, stdout="4242 python.exe", stderr=""
        )
        ga.exec_argv.return_value = ExecResult(exitcode=0, stdout="", stderr="")
        # No broker thread — the close is never acknowledged.

        result = pipe_close(sid)

        kills = [
            c for c in ga.exec_argv.call_args_list
            if c[0][0] == "taskkill.exe" and "4242" in c[0][1]
        ]
        assert len(kills) == 1, f"expected the orphan broker to be killed, got {kills}"
        assert "force-killed" in result
        assert not session_dir.exists()

    def test_acknowledged_close_does_not_kill_anything(self, mock_mcp):
        from winbox.mcp import pipe_close
        ga, _, cfg = mock_mcp

        sid = "1eak00000002"
        session_dir = _make_session(cfg, sid)
        (session_dir / "broker.pid").write_text("4242")
        _broker_thread(session_dir, {"ok": True})

        result = pipe_close(sid)

        assert result == f"closed session {sid}"
        assert [c for c in ga.exec_argv.call_args_list if c[0][0] == "taskkill.exe"] == []

    def test_unkillable_broker_is_reported_not_papered_over(self, mock_mcp):
        from winbox.mcp import pipe_close
        ga, _, cfg = mock_mcp

        sid = "1eak00000003"
        session_dir = _make_session(cfg, sid)
        (session_dir / "broker.pid").write_text("4242")
        # _is_broker_alive says yes (PID is still python.exe), but taskkill fails.
        ga.exec.return_value = ExecResult(
            exitcode=0, stdout="4242 python.exe", stderr=""
        )
        ga.exec_argv.return_value = ExecResult(exitcode=128, stdout="", stderr="no such PID")

        result = pipe_close(sid)

        assert "4242" in result
        assert "may still hold the pipe handle" in result


class TestPipeBrokerOwnershipCheck:
    """Bug 23: taskkill must verify the PID still belongs to the broker
    (python.exe) before killing it — otherwise a recycled PID causes an
    unrelated process to be killed."""

    def test_close_does_not_kill_recycled_pid(self, mock_mcp):
        """If _is_broker_alive returns False, pipe_close must NOT taskkill."""
        from unittest.mock import patch
        from winbox.mcp import pipe_close
        ga, _, cfg = mock_mcp

        sid = "own_check_001"
        session_dir = _make_session(cfg, sid)
        (session_dir / "broker.pid").write_text("5555")
        # No broker thread — close is never acknowledged.
        # _is_broker_alive returns False (PID recycled to a non-python.exe process).
        ga.exec.return_value = ExecResult(exitcode=0, stdout="INFO: No tasks", stderr="")

        result = pipe_close(sid)

        taskkill_calls = [
            c for c in ga.exec_argv.call_args_list
            if c[0][0] == "taskkill.exe"
        ]
        assert taskkill_calls == [], (
            f"taskkill should NOT be called when the PID is recycled, "
            f"got {taskkill_calls}"
        )
        assert "already gone" in result or "taskkill skipped" in result

    def test_close_kills_live_broker(self, mock_mcp):
        """If _is_broker_alive returns True and broker doesn't ACK the close,
        pipe_close must taskkill."""
        from winbox.mcp import pipe_close
        ga, _, cfg = mock_mcp

        sid = "own_check_002"
        session_dir = _make_session(cfg, sid)
        (session_dir / "broker.pid").write_text("6666")
        # No broker thread — close is never acknowledged.
        # _is_broker_alive returns True (PID is still python.exe).
        ga.exec.return_value = ExecResult(
            exitcode=0, stdout="6666 python.exe", stderr=""
        )
        ga.exec_argv.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        result = pipe_close(sid)

        taskkill_calls = [
            c for c in ga.exec_argv.call_args_list
            if c[0][0] == "taskkill.exe" and "6666" in c[0][1]
        ]
        assert len(taskkill_calls) == 1, (
            f"expected taskkill for live broker PID 6666, got {taskkill_calls}"
        )
        assert "force-killed" in result

    def test_abort_does_not_kill_recycled_pid(self, mock_mcp):
        """The _abort closure inside pipe_open must also skip taskkill when the
        PID no longer belongs to python.exe."""
        import winbox.mcp as mcp_mod
        from unittest.mock import patch
        from winbox.mcp import pipe_open
        ga, vm, cfg = mock_mcp

        def _fake_exec(code, timeout=300, args=None):
            # Never writes status.json → pipe_open polls until timeout.
            return {"exitcode": 0, "stdout": "pid:8888\n", "stderr": ""}

        # _is_broker_alive will use ga.exec — return no python.exe match.
        ga.exec.return_value = ExecResult(
            exitcode=0, stdout="INFO: No tasks", stderr=""
        )
        ga.exec_argv.return_value = ExecResult(exitcode=0, stdout="", stderr="")
        with patch.object(mcp_mod, "_exec_python", side_effect=_fake_exec):
            result = pipe_open(name="srvsvc", timeout=0)  # instant timeout

        assert "timeout" in result
        taskkill_calls = [
            c for c in ga.exec_argv.call_args_list
            if c[0][0] == "taskkill.exe"
        ]
        assert taskkill_calls == [], (
            f"_abort should NOT taskkill a recycled PID, got {taskkill_calls}"
        )


# ─── kdbg_start / kdbg_stop / kdbg_status tools ─────────────────────────────


class TestKdbgTools:
    """MCP tool wrappers around QEMU HMP gdbserver.

    Patches winbox.mcp._kdbg_hmp and winbox.mcp._kdbg_probe directly so
    we don't shell out to virsh or open real sockets during tests.
    """

    def _stub_hmp_start(self, bind="127.0.0.1", port=1234):
        return (0, f"Waiting for gdb connection on device 'tcp:{bind}:{port}'", "")

    def test_start_defaults_to_localhost(self, mock_mcp):
        from winbox.mcp import kdbg_start
        ga, vm, cfg = mock_mcp
        cfg.vm_name = "winbox"

        with patch("winbox.mcp._kdbg_hmp", return_value=self._stub_hmp_start()) as hmp, \
             patch("winbox.mcp._kdbg_probe", return_value=False):
            result = kdbg_start()

        out = _mcp_result(result)
        assert out["bind"] == "127.0.0.1"
        assert out["port"] == 1234
        hmp.assert_called_once_with("winbox", "gdbserver tcp:127.0.0.1:1234")
        # Attach hint is included so the agent knows how to proceed
        assert "target remote :1234" in out["gdb_command"]

    def test_start_custom_port(self, mock_mcp):
        from winbox.mcp import kdbg_start
        cfg = mock_mcp[2]
        cfg.vm_name = "winbox"

        with patch("winbox.mcp._kdbg_hmp",
                   return_value=self._stub_hmp_start(port=9999)) as hmp, \
             patch("winbox.mcp._kdbg_probe", return_value=False):
            result = kdbg_start(port=9999)

        assert _mcp_result(result)["port"] == 9999
        hmp.assert_called_once_with("winbox", "gdbserver tcp:127.0.0.1:9999")

    def test_start_any_interface_opt_in(self, mock_mcp):
        from winbox.mcp import kdbg_start
        cfg = mock_mcp[2]
        cfg.vm_name = "winbox"

        with patch("winbox.mcp._kdbg_hmp",
                   return_value=self._stub_hmp_start(bind="0.0.0.0")) as hmp, \
             patch("winbox.mcp._kdbg_probe", return_value=False):
            result = kdbg_start(any_interface=True)

        out = _mcp_result(result)
        assert out["bind"] == "0.0.0.0"
        assert out["lan_accessible"] is True
        hmp.assert_called_once_with("winbox", "gdbserver tcp:0.0.0.0:1234")

    def test_start_refuses_when_port_already_in_use(self, mock_mcp):
        from winbox.mcp import kdbg_start
        cfg = mock_mcp[2]
        cfg.vm_name = "winbox"

        with patch("winbox.mcp._kdbg_hmp") as hmp, \
             patch("winbox.mcp._kdbg_probe", return_value=True):
            result = kdbg_start()

        assert "already listening" in _mcp_error(result)["message"]
        hmp.assert_not_called()

    def test_start_refuses_when_persistent_reader_owns_stub(self, mock_mcp):
        from winbox.mcp import kdbg_start
        with patch("winbox.mcp._kdbg_reader_info", return_value={"port": 4321}), \
             patch("winbox.mcp._kdbg_hmp") as hmp:
            result = kdbg_start()
        error = _mcp_error(result)
        assert "reader already owns" in error["message"]
        assert "4321" in error["message"]
        hmp.assert_not_called()

    def test_start_vm_not_running(self, mock_mcp):
        from winbox.mcp import kdbg_start
        ga, vm, cfg = mock_mcp
        vm.state.return_value = VMState.SHUTOFF

        with patch("winbox.mcp._kdbg_hmp") as hmp:
            result = kdbg_start()

        assert "not running" in _mcp_error(result)["message"].lower()
        hmp.assert_not_called()

    def test_start_virsh_failure(self, mock_mcp):
        from winbox.mcp import kdbg_start
        cfg = mock_mcp[2]
        cfg.vm_name = "winbox"

        with patch("winbox.mcp._kdbg_hmp",
                   return_value=(1, "", "qemu agent not connected")), \
             patch("winbox.mcp._kdbg_probe", return_value=False):
            result = kdbg_start()

        error = _mcp_error(result)
        assert "Failed to start" in error["message"]
        assert "qemu agent not connected" in error["message"]

    def test_start_unexpected_hmp_response(self, mock_mcp):
        """Unknown responses bail — silent success would mask real errors."""
        from winbox.mcp import kdbg_start
        cfg = mock_mcp[2]
        cfg.vm_name = "winbox"

        with patch("winbox.mcp._kdbg_hmp", return_value=(0, "Unknown command", "")), \
             patch("winbox.mcp._kdbg_probe", return_value=False):
            result = kdbg_start()

        assert "Unexpected HMP response" in _mcp_error(result)["message"]

    def test_stop_sends_gdbserver_none(self, mock_mcp):
        from winbox.mcp import kdbg_stop
        cfg = mock_mcp[2]
        cfg.vm_name = "winbox"

        with patch("winbox.mcp._kdbg_hmp",
                   return_value=(0, "Disabled gdbserver", "")) as hmp:
            result = kdbg_stop()

        assert _mcp_result(result) == {"stopped": True}
        hmp.assert_called_once_with("winbox", "gdbserver none")

    def test_stop_vm_not_running(self, mock_mcp):
        from winbox.mcp import kdbg_stop
        ga, vm, cfg = mock_mcp
        vm.state.return_value = VMState.SHUTOFF

        with patch("winbox.mcp._kdbg_hmp") as hmp:
            result = kdbg_stop()

        assert "not running" in _mcp_error(result)["message"].lower()
        hmp.assert_not_called()

    def test_stop_virsh_failure(self, mock_mcp):
        from winbox.mcp import kdbg_stop
        cfg = mock_mcp[2]
        cfg.vm_name = "winbox"

        with patch("winbox.mcp._kdbg_hmp", return_value=(1, "", "monitor error")):
            result = kdbg_stop()

        assert "Failed to stop" in _mcp_error(result)["message"]

    def test_status_listening(self, mock_mcp):
        from winbox.mcp import kdbg_status

        with patch("winbox.mcp._kdbg_probe", return_value=True):
            result = kdbg_status()

        out = _mcp_result(result)
        assert out["state"] == "listening"
        assert out["host"] == "127.0.0.1" and out["port"] == 1234

    def test_status_not_running(self, mock_mcp):
        from winbox.mcp import kdbg_status

        with patch("winbox.mcp._kdbg_probe", return_value=False):
            result = kdbg_status()

        assert _mcp_result(result)["state"] == "stopped"

    def test_status_custom_port(self, mock_mcp):
        from winbox.mcp import kdbg_status

        with patch("winbox.mcp._kdbg_probe", return_value=True) as probe:
            result = kdbg_status(port=4321)

        out = _mcp_result(result)
        assert out["host"] == "127.0.0.1" and out["port"] == 4321
        probe.assert_called_once_with("127.0.0.1", 4321)

    def test_status_vm_not_running(self, mock_mcp):
        from winbox.mcp import kdbg_status
        ga, vm, cfg = mock_mcp
        vm.state.return_value = VMState.SHUTOFF

        with patch("winbox.mcp._kdbg_probe") as probe:
            result = kdbg_status()

        assert _mcp_result(result)["state"] == "vm_not_running"
        probe.assert_not_called()

    def test_status_reports_connected_reader_without_probe(self, mock_mcp):
        from winbox.mcp import kdbg_status
        with patch("winbox.mcp._kdbg_reader_info", return_value={"port": 1234}), \
             patch("winbox.mcp._kdbg_probe") as probe:
            result = kdbg_status()
        out = _mcp_result(result)
        assert out["state"] == "connected"
        assert out["owner"] == "persistent_reader"
        probe.assert_not_called()

    def test_kdbg_probe_helper_real_socket(self):
        """Direct unit test for _kdbg_probe with a real ephemeral listener."""
        import socket as _sk
        from winbox.mcp import _kdbg_probe

        srv = _sk.socket(_sk.AF_INET, _sk.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            assert _kdbg_probe("127.0.0.1", port) is True
        finally:
            srv.close()

    def test_kdbg_probe_helper_closed_port(self):
        from winbox.mcp import _kdbg_probe
        assert _kdbg_probe("127.0.0.1", 1, timeout=0.1) is False


class TestKdbgCetTools:
    def test_status_reports_safe_boot(self, mock_mcp):
        from winbox.mcp import kdbg_cet_status

        status = SimpleNamespace(
            safe_for_debug=True, user_shadow_stack="OFF", strict_mode="OFF",
            enabled_processes=(), unqueryable_processes=(),
        )
        with patch("winbox.mcp._kdbg_query_cet_status", return_value=status):
            result = kdbg_cet_status()
        out = _mcp_result(result)
        assert out["safe_for_debug"] is True
        assert out["summary"] == (
            "SAFE: UserShadowStack=OFF, StrictMode=OFF, active_processes=0, "
            "unqueryable_processes=0"
        )

    def test_status_reports_active_processes_as_unsafe(self, mock_mcp):
        from winbox.mcp import kdbg_cet_status

        status = SimpleNamespace(
            safe_for_debug=False,
            user_shadow_stack="OFF",
            strict_mode="OFF",
            enabled_processes=("svchost[404]",),
            unqueryable_processes=(),
        )
        with patch("winbox.mcp._kdbg_query_cet_status", return_value=status):
            result = kdbg_cet_status()
        out = _mcp_result(result)
        assert out["safe_for_debug"] is False
        assert out["summary"].startswith(
            "UNSAFE: UserShadowStack=OFF, StrictMode=OFF, active_processes=1"
        )
        assert "active_sample=svchost[404]" in out["summary"]

    def test_prepare_refuses_without_confirmation(self, mock_mcp):
        from winbox.mcp import kdbg_prepare

        with patch("winbox.mcp._kdbg_prepare_cet") as prepare:
            result = kdbg_prepare()
        assert _mcp_error(result)["message"].startswith("refused:")
        prepare.assert_not_called()

    def test_prepare_stops_reader_before_policy_change(self, mock_mcp, tmp_path):
        from winbox.mcp import kdbg_prepare

        backup = tmp_path / "kdbg-cet-backup.json"
        with patch("winbox.mcp._kdbg_stop_reader") as stop, patch(
            "winbox.mcp._kdbg_prepare_cet", return_value=backup,
        ):
            result = kdbg_prepare(confirm=True)
        out = _mcp_result(result)
        assert out["backup"] == str(backup)
        assert out["reboot_required"] is True
        stop.assert_called_once()

    def test_restore_refuses_without_confirmation(self, mock_mcp):
        from winbox.mcp import kdbg_restore_cet

        with patch("winbox.mcp._kdbg_restore_cet_policy") as restore:
            result = kdbg_restore_cet()
        assert _mcp_error(result)["message"].startswith("refused:")
        restore.assert_not_called()


class TestKdbgListTools:
    """JSON output contract for kdbg_ps / kdbg_lm and auto-resume on paused VMs."""

    def test_kdbg_ps_returns_json_array(self, mock_mcp):
        import json as _json
        from winbox.kdbg.walk import ProcessRecord
        from winbox.mcp import kdbg_ps

        ga, vm, cfg = mock_mcp
        cfg.vm_name = "winbox"

        procs = [
            ProcessRecord(pid=4, name="System",
                          eprocess=0xffffae0012345000,
                          directory_table_base=0x1ad000),
            ProcessRecord(pid=1234, name="explorer.exe",
                          eprocess=0xffffae00abcdef00,
                          directory_table_base=0x7fa000),
        ]

        with patch("winbox.mcp._kdbg_get_store"), \
             patch("winbox.mcp._kdbg_list_processes", return_value=procs):
            result = kdbg_ps()

        parsed = _mcp_result(result)["processes"]
        assert isinstance(parsed, list)
        assert len(parsed) == 2
        assert parsed[0] == {
            "pid": 4,
            "dtb": "0x0000001ad000",
            "eprocess": "0xffffae0012345000",
            "name": "System",
        }
        assert parsed[1]["pid"] == 1234
        assert parsed[1]["name"] == "explorer.exe"
        for entry in parsed:
            assert entry["dtb"].startswith("0x")
            assert entry["eprocess"].startswith("0x")

    def test_kdbg_threads_returns_identity_and_truthful_partial_status(self, mock_mcp):
        from winbox.kdbg.walk import ProcessRecord, ThreadRecord, ThreadWalkResult
        from winbox.mcp import kdbg_threads

        _, _, cfg = mock_mcp
        cfg.vm_name = "winbox"
        target = ProcessRecord(
            pid=1234, name="target.exe", eprocess=0xffffae00abcdef00,
            directory_table_base=0x7fa000, create_time=0x11223344,
        )
        walked = ThreadWalkResult(
            threads=[ThreadRecord(
                tid=4321, ethread=0xffffae0012345000, state=5,
                state_name="Waiting", wait_reason=6, wait_reason_name="UserRequest",
                priority=13, base_priority=8, context_switches=927,
                teb=0x7ffde000, kernel_stack=0xfffff80001234000,
                stack_limit=0xfffff80001230000, stack_base=0xfffff80001238000,
                start_address=0xfffff80010001000,
                win32_start_address=0x7ff740001000, create_time=0x1234,
                exit_status=259,
            )],
            complete=False,
            truncated_reason="cycle detected at ETHREAD list entry 0xffffae0012345578",
        )

        with patch("winbox.mcp._kdbg_get_store"), \
             patch("winbox.mcp._kdbg_find_process", return_value=target), \
             patch("winbox.mcp._kdbg_list_threads", return_value=walked):
            result = _mcp_result(kdbg_threads(1234))

        assert result["pid"] == 1234
        assert result["name"] == "target.exe"
        assert result["eprocess"] == "0xffffae00abcdef00"
        assert result["process_create_time"] == 0x11223344
        assert result["count"] == 1
        assert result["complete"] is False
        assert result["truncated_reason"] == walked.truncated_reason
        assert result["truncation"] == {
            "stage": "unknown", "link": None, "ethread": None,
            "returned": 1,
            "reason": walked.truncated_reason,
        }
        expected_legacy = {
            "tid": 4321,
            "ethread": "0xffffae0012345000",
            "state": {"raw": 5, "name": "Waiting"},
            "wait_reason": {"raw": 6, "name": "UserRequest"},
            "priority": 13,
            "base_priority": 8,
            "context_switches": 927,
            "teb": "0x000000007ffde000",
            "kernel_stack": "0xfffff80001234000",
            "stack_limit": "0xfffff80001230000",
            "stack_base": "0xfffff80001238000",
            "start_address": "0xfffff80010001000",
            "win32_start_address": "0x00007ff740001000",
            "create_time": 0x1234,
            "exit_status": 259,
        }
        thread = result["threads"][0]
        assert {key: thread[key] for key in expected_legacy} == expected_legacy
        assert thread["create_time_filetime"] == 0x1234
        assert thread["create_time_utc"] == "1601-01-01T00:00:00.000466Z"
        assert (thread["exit_status_ntstatus"], thread["exit_status_name"]) == (
            "0x00000103", "STATUS_PENDING",
        )
        assert thread["kernel_stack_semantics"] == "KTHREAD.KernelStack field; not a saved RSP"
        assert thread["pointer_values"]["teb"] == "0x000000007ffde000"

    def test_kdbg_threads_require_complete_returns_typed_partial_error(self, mock_mcp):
        from winbox.kdbg.walk import ProcessRecord, ThreadWalkResult
        from winbox.mcp import kdbg_threads

        _, _, cfg = mock_mcp
        cfg.vm_name = "winbox"
        target = ProcessRecord(
            pid=1234, name="target.exe", eprocess=0xffffae00abcdef00,
            directory_table_base=0x7fa000, create_time=0x11223344,
        )
        walked = ThreadWalkResult(
            threads=[], complete=False, truncated_reason="ThreadListHead contained a null link",
        )
        with patch("winbox.mcp._kdbg_get_store"), \
             patch("winbox.mcp._kdbg_find_process", return_value=target), \
             patch("winbox.mcp._kdbg_list_threads", return_value=walked):
            result = kdbg_threads(1234, require_complete=True)

        assert result["ok"] is False
        assert result["error"]["code"] == "incomplete_result"
        assert result["error"]["retryable"] is True
        assert result["error"]["details"]["truncation"]["reason"] == walked.truncated_reason

    def test_kdbg_global_thread_triage_forwards_bounds_and_snapshot_metadata(self, mock_mcp):
        from winbox.mcp import kdbg_thread_triage

        expected = {
            "schema": "winbox.kdbg-global-thread-triage/1",
            "scope": {"complete": True, "reasons": []},
            "rankings": {},
        }
        with patch("winbox.mcp._kdbg_get_store"), \
             patch("winbox.mcp._kdbg_triage_all_process_threads", return_value=expected) as triage:
            result = _mcp_result(kdbg_thread_triage(
                process_cap=7, total_thread_cap=99, sample_per_process=3,
                result_limit=5, resolve=False,
            ))

        assert result["snapshot_metadata"]["admission"] == "unknown"
        assert triage.call_args.kwargs == {
            "cache": ANY, "process_cap": 7, "total_thread_cap": 99,
            "sample_per_process": 3, "result_limit": 5, "resolve": False,
        }

    def test_kdbg_global_thread_triage_require_complete_is_typed(self, mock_mcp):
        from winbox.mcp import kdbg_thread_triage

        expected = {
            "schema": "winbox.kdbg-global-thread-triage/1",
            "scope": {"complete": False, "reasons": ["process cap"]},
            "rankings": {},
        }
        with patch("winbox.mcp._kdbg_get_store"), \
             patch("winbox.mcp._kdbg_triage_all_process_threads", return_value=expected):
            result = kdbg_thread_triage(require_complete=True)

        assert result["ok"] is False
        assert result["error"]["code"] == "incomplete_result"
        assert result["error"]["details"]["scope_complete"] is False
        assert result["error"]["details"]["scope_reasons"] == expected["scope"]["reasons"]

    def test_kdbg_threads_rejects_missing_pid_without_walking(self, mock_mcp):
        from winbox.mcp import kdbg_threads

        _, _, cfg = mock_mcp
        cfg.vm_name = "winbox"
        with patch("winbox.mcp._kdbg_get_store"), \
             patch("winbox.mcp._kdbg_find_process", return_value=None), \
             patch("winbox.mcp._kdbg_list_threads") as listed:
            error = _mcp_error(kdbg_threads(9999))

        assert error["message"] == "pid 9999 not found"
        listed.assert_not_called()

    def test_kdbg_threads_bounds_rows_and_serializes_attribution_and_vcpu(self, mock_mcp):
        from winbox.kdbg.walk import (
            CurrentVcpuRecord,
            ProcessRecord,
            ThreadAddressAttribution,
            ThreadRecord,
            ThreadStartAttribution,
            ThreadWalkResult,
        )
        from winbox.mcp import kdbg_threads

        _, _, cfg = mock_mcp
        cfg.vm_name = "winbox"
        target = ProcessRecord(
            pid=1234, name="target.exe", eprocess=0xffffae00abcdef00,
            directory_table_base=0x7fa000,
        )
        thread = ThreadRecord(
            tid=4321, ethread=0xffffae0012345000, state=5,
            state_name="Waiting", wait_reason=6, wait_reason_name="UserRequest",
            priority=13, base_priority=8, context_switches=927,
            teb=0x7ffde000, kernel_stack=0xfffff80001234000,
            stack_limit=0xfffff80001230000, stack_base=0xfffff80001238000,
            start_address=0xfffff80010001000,
            win32_start_address=0x7ff740001000, create_time=0x1234,
            exit_status=259,
        )
        attribution = ThreadStartAttribution(
            start_address=ThreadAddressAttribution(
                address=thread.start_address, mapping="kernel_module",
                module="ntoskrnl.exe", module_base=0xfffff80010000000,
                module_size=0x4000, rva=0x1000,
                symbol="PspSystemThreadStartup", symbol_offset=0,
            ),
            win32_start_address=ThreadAddressAttribution(
                address=thread.win32_start_address, mapping="user_not_in_loader_module",
            ),
        )
        current = CurrentVcpuRecord(
            vcpu=3, status="current", ethread=thread.ethread,
            eprocess=target.eprocess, pid=target.pid, process_name=target.name,
            tid=thread.tid, in_target_process=True,
        )
        with patch("winbox.mcp._kdbg_get_store"), \
             patch("winbox.mcp._kdbg_find_process", return_value=target), \
             patch("winbox.mcp._kdbg_list_threads", return_value=ThreadWalkResult([thread], True)), \
             patch("winbox.mcp._kdbg_resolve_thread_start_addresses", return_value=({thread.ethread: attribution}, ())), \
             patch("winbox.mcp._kdbg_list_current_vcpu_threads", return_value=[current]):
            result = _mcp_result(kdbg_threads(1234, resolve=True))

        assert (result["count"], result["total_count"], result["matched_count"], result["returned"]) == (1, 1, 1, 1)
        assert result["walk_complete"] is True
        assert result["threads"][0]["running_on_vcpus"] == [3]
        start = result["threads"][0]["start_attribution"]["start_address"]
        assert (start["mapping"], start["module"], start["symbol"], start["symbol_offset"]) == (
            "kernel_module", "ntoskrnl.exe", "PspSystemThreadStartup", "0x0",
        )
        assert result["current_vcpus"] == [{
            "vcpu": 3, "status": "current", "ethread": "0xffffae0012345000",
            "eprocess": "0xffffae00abcdef00", "pid": 1234,
            "process_name": "target.exe", "tid": 4321,
            "in_target_process": True, "reason": None,
        }]

    def test_kdbg_threads_wait_objects_preloads_layouts_and_preserves_evidence(self, mock_mcp):
        from winbox.kdbg.walk import ProcessRecord, ThreadRecord, ThreadWalkResult
        from winbox.mcp import kdbg_threads

        _, _, cfg = mock_mcp
        cfg.vm_name = "winbox"
        target = ProcessRecord(1234, "target.exe", 0xffffae00abcdef00, 0x7fa000)
        thread = ThreadRecord(
            tid=4321, ethread=0xffffae0012345000, state=5, state_name="Waiting",
            wait_reason=6, wait_reason_name="UserRequest", priority=13, base_priority=8,
            context_switches=1, teb=0, kernel_stack=0, stack_limit=0, stack_base=0,
            start_address=0, win32_start_address=0, create_time=0, exit_status=0,
        )
        evidence = {
            "scope": {
                "waiting_threads": 1, "examined": 1, "output_truncated": False,
                "wait_object_limit": 1, "wait_owner_depth": 2,
                "external_wait_blocks": "not_chased", "owner_relation": "mutant_only",
            },
            "records": {thread.ethread: {"complete": True, "owner_chain": []}},
        }
        with patch("winbox.mcp._kdbg_get_store") as store, \
             patch("winbox.mcp._kdbg_ensure_types_loaded") as ensure, \
             patch("winbox.mcp._kdbg_find_process", return_value=target), \
             patch("winbox.mcp._kdbg_list_threads", return_value=ThreadWalkResult([thread], True)), \
             patch("winbox.mcp._kdbg_resolve_thread_wait_objects", return_value=evidence) as resolved, \
             patch("winbox.mcp._kdbg_list_current_vcpu_threads", return_value=[]):
            result = _mcp_result(kdbg_threads(
                1234, wait_objects=True, wait_object_limit=1, wait_owner_depth=2,
            ))

        ensure.assert_called_once_with(
            cfg, store.return_value,
            ["_KWAIT_BLOCK", "_DISPATCHER_HEADER", "_KMUTANT"], module="nt",
        )
        assert resolved.call_args.kwargs["limit"] == 1
        assert resolved.call_args.kwargs["owner_depth"] == 2
        assert result["wait_objects"]["enabled"] is True
        assert result["threads"][0]["wait_object"] == evidence["records"][thread.ethread]

    def test_kdbg_threads_wait_objects_refuse_summary_before_snapshot(self, mock_mcp):
        from winbox.mcp import kdbg_threads

        with patch("winbox.mcp._kdbg_debug_snapshot") as snapshot, \
             patch("winbox.mcp._kdbg_ensure_types_loaded") as ensure:
            error = _mcp_error(kdbg_threads(1234, detail="summary", wait_objects=True))

        assert error["code"] == "invalid_argument"
        assert "requires detail='full'" in error["message"]
        ensure.assert_not_called()
        snapshot.assert_not_called()

    def test_kdbg_threads_wait_object_bounds_refuse_before_snapshot(self, mock_mcp):
        from winbox.mcp import kdbg_threads

        with patch("winbox.mcp._kdbg_debug_snapshot") as snapshot:
            error = _mcp_error(kdbg_threads(1234, wait_object_limit=0))

        assert error["code"] == "invalid_argument"
        assert "between 1 and 128" in error["message"]
        snapshot.assert_not_called()

    def test_kdbg_threads_rejects_invalid_bounded_view(self, mock_mcp):
        from winbox.kdbg.walk import ProcessRecord, ThreadWalkResult
        from winbox.mcp import kdbg_threads

        _, _, cfg = mock_mcp
        cfg.vm_name = "winbox"
        target = ProcessRecord(
            pid=1234, name="target.exe", eprocess=0xffffae00abcdef00,
            directory_table_base=0x7fa000,
        )
        with patch("winbox.mcp._kdbg_get_store"), \
             patch("winbox.mcp._kdbg_find_process", return_value=target), \
             patch("winbox.mcp._kdbg_list_threads", return_value=ThreadWalkResult([], True)):
            error = _mcp_error(kdbg_threads(1234, state="invented"))

        assert error["code"] == "invalid_argument"
        assert "invalid state" in error["message"]

    def test_kdbg_doctor_reports_catalog_without_opening_rsp(self, mock_mcp):
        from winbox.mcp import kdbg_doctor

        _, _, cfg = mock_mcp
        report = {
            "ready": True,
            "vm": {"name": "winbox", "state": "running", "running": True},
            "guest_agent": {"responding": True, "error": None},
            "cet": {"safe_for_debug": True, "summary": "safe", "error": None},
            "symbols": {"nt": {"identity": "cached_unverified", "live_base": "not_checked"}},
            "debugger": {"state": "stopped", "owner": None},
            "mcp": {"catalog_revision": "test", "tool_count": 85},
            "notes": [],
        }
        with patch("winbox.mcp._kdbg_collect_doctor", return_value=report) as doctor:
            result = _mcp_result(kdbg_doctor())

        assert result is report
        assert doctor.call_args.kwargs["tool_count"] == 97

    def test_kdbg_triage_is_single_snapshot_and_bounds_unmapped_leads(self, mock_mcp):
        from contextlib import nullcontext
        from winbox.kdbg.walk import (
            CurrentVcpuRecord, ModuleRecord, ProcessRecord, ThreadAddressAttribution,
            ThreadRecord, ThreadStartAttribution, ThreadWalkResult, UserModuleRecord,
        )
        from winbox.mcp import kdbg_triage

        _, _, cfg = mock_mcp
        cfg.vm_name = "winbox"
        target = ProcessRecord(
            pid=1234, name="target.exe", eprocess=0xffffae00abcdef00,
            directory_table_base=0x7fa000,
        )
        thread = ThreadRecord(
            tid=4321, ethread=0xffffae0012345000, state=5, state_name="Waiting",
            wait_reason=6, wait_reason_name="UserRequest", priority=13, base_priority=8,
            context_switches=927, teb=0x7ffde000, kernel_stack=0xfffff80001234000,
            stack_limit=0xfffff80001230000, stack_base=0xfffff80001238000,
            start_address=0xfffff80010001000, win32_start_address=0x7ff740001000,
            create_time=0x1234, exit_status=259,
        )
        attribution = ThreadStartAttribution(
            start_address=ThreadAddressAttribution(
                address=thread.start_address, mapping="kernel_module", module="ntoskrnl.exe",
                module_base=0xfffff80010000000, module_size=0x4000, rva=0x1000,
            ),
            win32_start_address=ThreadAddressAttribution(
                address=thread.win32_start_address, mapping="user_not_in_loader_module",
            ),
        )
        current = CurrentVcpuRecord(
            vcpu=1, status="current", ethread=thread.ethread, eprocess=target.eprocess,
            pid=target.pid, process_name=target.name, tid=thread.tid, in_target_process=True,
        )
        snapshot = MagicMock(return_value=nullcontext())
        with patch("winbox.mcp._kdbg_debug_snapshot", snapshot), \
             patch("winbox.mcp._kdbg_get_store"), \
             patch("winbox.mcp._kdbg_find_process", return_value=target), \
             patch("winbox.mcp._kdbg_list_threads", return_value=ThreadWalkResult([thread], True)), \
             patch("winbox.mcp._kdbg_list_modules", return_value=[ModuleRecord("ntoskrnl.exe", 0xfffff80010000000, 0x4000, 0)]), \
             patch("winbox.mcp._kdbg_ensure_types_loaded"), \
             patch("winbox.mcp._kdbg_list_user_modules", return_value=[UserModuleRecord("target.exe", 0x7ff740000000, 0x4000, "C:\\target.exe", 0)]), \
             patch("winbox.mcp._kdbg_resolve_thread_start_addresses", return_value=({thread.ethread: attribution}, ())), \
             patch("winbox.mcp._kdbg_list_current_vcpu_threads", return_value=[current]):
            result = _mcp_result(kdbg_triage(1234, thread_limit=1))

        assert snapshot.call_count == 1
        assert result["snapshot"] == "single_rsp_stop"
        assert result["thread_summary"]["top_rows_returned"] == 1
        assert result["threads"][0]["running_on_vcpus"] == [1]
        assert result["user_modules"]["count"] == 1
        assert result["unmapped_starts"] == [{
            "tid": 4321, "ethread": "0xffffae0012345000",
            "field": "win32_start_address", "address": "0x00007ff740001000",
            "mapping": "user_not_in_loader_module",
        }]

    def test_kdbg_triage_rejects_unbounded_limit_before_a_snapshot(self, mock_mcp):
        from winbox.mcp import kdbg_triage

        error = _mcp_error(kdbg_triage(1234, thread_limit=65))
        assert error["code"] == "invalid_argument"
        assert "between 1 and 64" in error["message"]

    def test_kdbg_thread_baseline_captures_once_then_saves_host_state(self, mock_mcp):
        from winbox.mcp import kdbg_thread_baseline

        _, _, cfg = mock_mcp
        cfg.vm_name = "winbox"
        baseline = MagicMock()
        capture = object()
        baseline.save.return_value = {"name": "case", "thread_count": 3}
        with patch("winbox.mcp._KdbgThreadBaselineStore", return_value=baseline), \
             patch("winbox.mcp._kdbg_get_store"), \
             patch("winbox.mcp._kdbg_capture_thread_baseline", return_value=capture) as collected:
            result = _mcp_result(kdbg_thread_baseline(1234, name="case"))

        assert result["name"] == "case"
        assert result["thread_count"] == 3
        assert result["snapshot_metadata"]["admission"] == "unknown"
        collected.assert_called_once()
        baseline.validate_name.assert_called_once_with("case")
        baseline.save.assert_called_once_with("case", capture)

    def test_kdbg_thread_diff_checks_missing_baseline_before_stopping_vm(self, mock_mcp):
        from winbox.kdbg.thread_baseline import BaselineNotFoundError
        from winbox.mcp import kdbg_thread_diff

        baseline = MagicMock()
        baseline.load.side_effect = BaselineNotFoundError("baseline 'case' was not found")
        with patch("winbox.mcp._KdbgThreadBaselineStore", return_value=baseline), \
             patch("winbox.mcp._kdbg_debug_snapshot") as snapshot, \
             patch("winbox.mcp._kdbg_capture_thread_baseline") as collected:
            error = _mcp_error(kdbg_thread_diff(1234, name="case"))

        assert error["code"] == "baseline_not_found"
        snapshot.assert_not_called()
        collected.assert_not_called()

    def test_kdbg_thread_diff_returns_bounded_delta_contract(self, mock_mcp):
        from winbox.mcp import kdbg_thread_diff

        _, _, cfg = mock_mcp
        cfg.vm_name = "winbox"
        baseline = MagicMock()
        capture = object()
        baseline.diff.return_value = {"created_count": 0, "exited_count": 0, "changed_count": 1}
        with patch("winbox.mcp._KdbgThreadBaselineStore", return_value=baseline), \
             patch("winbox.mcp._kdbg_get_store"), \
             patch("winbox.mcp._kdbg_capture_thread_baseline", return_value=capture):
            result = _mcp_result(kdbg_thread_diff(1234, name="case", limit=8))

        assert result["changed_count"] == 1
        baseline.load.assert_called_once_with("case")
        baseline.diff.assert_called_once_with("case", capture, limit=8)

    def test_kdbg_lm_returns_json_array(self, mock_mcp):
        import json as _json
        from winbox.kdbg.walk import ModuleRecord
        from winbox.mcp import kdbg_lm

        ga, vm, cfg = mock_mcp
        cfg.vm_name = "winbox"

        mods = [
            ModuleRecord(name="ntoskrnl.exe", base=0xfffff80012000000,
                         size=0x00a00000, entry=0xffffae0011110000),
            ModuleRecord(name="hal.dll", base=0xfffff80012a00000,
                         size=0x00080000, entry=0xffffae0011120000),
        ]

        with patch("winbox.mcp._kdbg_get_store"), \
             patch("winbox.mcp._kdbg_list_modules", return_value=mods):
            result = kdbg_lm()

        parsed = _mcp_result(result)["modules"]
        assert isinstance(parsed, list)
        assert len(parsed) == 2
        assert parsed[0] == {
            "base": "0xfffff80012000000",
            "size": "0x00a00000",
            "name": "ntoskrnl.exe",
        }
        assert parsed[1]["name"] == "hal.dll"
        for entry in parsed:
            assert entry["base"].startswith("0x")
            assert entry["size"].startswith("0x")

    def test_kdbg_ps_works_when_paused(self, mock_mcp):
        """kdbg_ps uses the debugger transport and never VM.resume()."""
        import json as _json
        from winbox.kdbg.walk import ProcessRecord
        from winbox.mcp import kdbg_ps

        ga, vm, cfg = mock_mcp
        cfg.vm_name = "winbox"
        vm.state.return_value = VMState.PAUSED

        procs = [ProcessRecord(pid=4, name="System",
                               eprocess=0xffffae0012345000,
                               directory_table_base=0x1ad000)]

        with patch("winbox.mcp._kdbg_get_store"), \
             patch("winbox.mcp._kdbg_list_processes", return_value=procs):
            result = kdbg_ps()

        vm.resume.assert_not_called()
        parsed = _mcp_result(result)["processes"]
        assert parsed[0]["pid"] == 4

    def test_kdbg_read_va_works_when_paused(self, mock_mcp):
        """kdbg_read_va uses one debugger snapshot and never VM.resume()."""
        from winbox.kdbg.walk import ProcessRecord
        from winbox.mcp import kdbg_read_va

        ga, vm, cfg = mock_mcp
        cfg.vm_name = "winbox"
        vm.state.return_value = VMState.PAUSED

        target = ProcessRecord(pid=1234, name="target.exe",
                               eprocess=0xffffae00abcdef00,
                               directory_table_base=0x7fa000)
        payload = b"\xde\xad\xbe\xef"

        with patch("winbox.mcp._kdbg_get_store"), \
             patch("winbox.mcp._kdbg_find_process", return_value=target), \
             patch("winbox.mcp._kdbg_read_virt_cr3", return_value=payload):
            result = kdbg_read_va(pid=1234, address="0x7ff600001000", length=4)

        vm.resume.assert_not_called()
        assert _mcp_result(result) == {
            "pid": 1234, "va": "0x7ff600001000", "bytes": "deadbeef",
        }

    def test_kdbg_ps_walk_is_inside_snapshot(self, mock_mcp):
        from contextlib import contextmanager
        from winbox.kdbg.walk import ProcessRecord
        from winbox.mcp import kdbg_ps

        _, _, cfg = mock_mcp
        active = False
        events = []

        @contextmanager
        def snapshot(snapshot_cfg):
            nonlocal active
            assert snapshot_cfg is cfg
            active = True
            events.append("enter")
            try:
                yield
            finally:
                active = False
                events.append("exit")

        def walk(*args, **kwargs):
            assert active
            events.append("walk")
            return [ProcessRecord(4, "System", 0x1000, 0x2000)]

        with patch("winbox.mcp._kdbg_debug_snapshot", snapshot), \
             patch("winbox.mcp._kdbg_get_store"), \
             patch("winbox.mcp._kdbg_list_processes", side_effect=walk):
            kdbg_ps()

        assert events == ["enter", "walk", "exit"]

    def test_composite_read_va_stays_in_one_snapshot(self, mock_mcp):
        from contextlib import contextmanager
        from winbox.kdbg.walk import ProcessRecord
        from winbox.mcp import kdbg_read_va

        _, _, cfg = mock_mcp
        active = False
        events = []

        @contextmanager
        def snapshot(snapshot_cfg):
            nonlocal active
            active = True
            events.append("enter")
            try:
                yield
            finally:
                active = False
                events.append("exit")

        def find(*args, **kwargs):
            assert active
            events.append("find")
            return ProcessRecord(1234, "target.exe", 0x1000, 0x2000)

        def read(*args, **kwargs):
            assert active
            events.append("read")
            return b"OK"

        with patch("winbox.mcp._kdbg_debug_snapshot", snapshot), \
             patch("winbox.mcp._kdbg_get_store"), \
             patch("winbox.mcp._kdbg_find_process", side_effect=find), \
             patch("winbox.mcp._kdbg_read_virt_cr3", side_effect=read):
            result = kdbg_read_va(1234, "0x1000", 2)

        assert _mcp_result(result)["bytes"] == "4f4b"
        assert events == ["enter", "find", "read", "exit"]


class TestKdbgEvidenceTools:
    """MCP adapter contracts for the bounded evidence/capture surface."""

    @staticmethod
    def _target():
        from winbox.kdbg.walk import ProcessRecord

        return ProcessRecord(
            pid=1234, name="target.exe", eprocess=0xffffae00abcdef00,
            directory_table_base=0x7fa000, create_time=1,
        )

    def test_vad_token_handles_and_object_preserve_provenance(self, mock_mcp):
        from winbox.mcp import kdbg_handles, kdbg_object, kdbg_token, kdbg_vad

        target = self._target()
        walked = SimpleNamespace(public=lambda: {
            "records": [{"start": "0x0000000010000000", "protection": {"executable": True}}],
            "returned": 1, "complete": True, "truncation": None,
        })
        token = {"token": {"body": "0xffff800000123450"}, "object_header": {"body": "0xffff800000123450"}}
        handles = {"handle_table": {"address": "0xffff800000223000"}, "enumeration": {"available": False}}
        header = SimpleNamespace(public=lambda: {"body": "0xffff800000123450", "type_index": 5})

        with patch("winbox.mcp._kdbg_get_store"), \
             patch("winbox.mcp._kdbg_ensure_vad_layouts"), \
             patch("winbox.mcp._kdbg_ensure_object_layouts"), \
             patch("winbox.mcp._kdbg_find_process", return_value=target), \
             patch("winbox.mcp._kdbg_list_vads", return_value=walked) as listed, \
             patch("winbox.mcp._kdbg_token_evidence", return_value=token), \
             patch("winbox.mcp._kdbg_handle_table_status", return_value=handles), \
             patch("winbox.mcp._kdbg_object_header", return_value=header):
            vad = _mcp_result(kdbg_vad(1234, executable=True, limit=1))
            primary = _mcp_result(kdbg_token(1234))
            table = _mcp_result(kdbg_handles(1234))
            object_result = _mcp_result(kdbg_object("0xffff800000123450"))

        assert vad["returned"] == 1 and vad["snapshot_metadata"]["admission"] == "unknown"
        assert listed.call_args.kwargs["executable_only"] is True
        assert primary["token"]["body"] == object_result["body"]
        assert table["enumeration"]["available"] is False

    def test_capture_and_offline_diff_are_separate_boundaries(self, mock_mcp):
        from winbox.mcp import kdbg_capture, kdbg_capture_diff

        capture = {
            "schema": "winbox.kdbg-capture/1", "capture": {"profile": "process"},
            "snapshot_metadata": {"phases_ms": {"capture": 1.0}},
        }
        expected_diff = {"schema": "winbox.kdbg-capture-diff/1", "profile": "process", "identity_match": True}
        with patch("winbox.mcp._kdbg_get_store"), \
             patch("winbox.mcp._kdbg_capture_live", return_value=capture) as live:
            result = _mcp_result(kdbg_capture(profile="process", pid=1234))
        assert result == {"capture": capture, "saved": None}
        assert live.call_args.kwargs == {
            "profile": "process", "pid": 1234, "require_complete": False,
        }

        capture_store = MagicMock()
        capture_store.load.side_effect = [{"schema": "left"}, {"schema": "right"}]
        with patch("winbox.mcp._KdbgCaptureStore", return_value=capture_store), \
             patch("winbox.mcp._kdbg_diff_captures", return_value=expected_diff) as diff:
            result = _mcp_result(kdbg_capture_diff("left", "right", limit=8))
        assert result == expected_diff
        diff.assert_called_once_with(
            {"schema": "left"}, {"schema": "right"}, limit=8,
            allow_identity_mismatch=False,
        )

    def test_vad_extract_returns_manifest_not_bytes_and_persists_once(self, mock_mcp):
        from winbox.mcp import kdbg_vad_extract

        _, _, cfg = mock_mcp
        extraction = SimpleNamespace(manifest={
            "schema": "winbox.kdbg-vad-extract/1", "complete": True,
            "blob": {"size": 4096, "sha256": "a" * 64}, "holes": [],
        })
        artifacts = MagicMock()
        artifacts.save.return_value = {
            "name": "private-rwx", "blob_path": "/evidence/private-rwx.bin",
            "manifest_path": "/evidence/private-rwx.json",
        }
        with patch("winbox.mcp._kdbg_get_store") as symbols, \
             patch("winbox.mcp._kdbg_extract_vad_live", return_value=extraction) as extract, \
             patch("winbox.mcp._KdbgVadExtractStore", return_value=artifacts):
            result = _mcp_result(kdbg_vad_extract(
                1234, "0x40000000", "private-rwx", length=4096,
            ))

        assert result["extraction"] == extraction.manifest
        assert "bytes" not in result["extraction"]
        assert extract.call_args.args[:2] == (cfg, symbols.return_value)
        assert extract.call_args.kwargs == {
            "pid": 1234, "address": 0x40000000,
            "length": 4096, "require_complete": False,
        }
        artifacts.save.assert_called_once_with("private-rwx", extraction)

    def test_vad_extract_rejects_invalid_length_before_touching_vm(self, mock_mcp):
        from winbox.mcp import kdbg_vad_extract

        with patch("winbox.mcp._kdbg_extract_vad_live") as extract:
            error = _mcp_error(kdbg_vad_extract(1234, "0x40000000", "case", length=True))
        assert error["code"] == "invalid_argument"
        extract.assert_not_called()

    def test_vad_extract_rejects_an_unsafe_name_before_stopping_the_vm(self, mock_mcp):
        from winbox.mcp import kdbg_vad_extract
        from winbox.kdbg.vad_extract import VadExtractError

        artifacts = MagicMock()
        artifacts.validate_name.side_effect = VadExtractError("artifact name must match safe pattern")
        with patch("winbox.mcp._KdbgVadExtractStore", return_value=artifacts), \
             patch("winbox.mcp._kdbg_extract_vad_live") as extract:
            error = _mcp_error(kdbg_vad_extract(1234, "0x40000000", "../../escape"))
        assert error["code"] == "vad_extract_error"
        extract.assert_not_called()

    def test_vad_extract_rejects_duplicate_name_before_stopping_the_vm(self, mock_mcp):
        from winbox.mcp import kdbg_vad_extract
        from winbox.kdbg.vad_extract import VadExtractError

        artifacts = MagicMock()
        artifacts.ensure_available.side_effect = VadExtractError("artifact already exists and is immutable")
        with patch("winbox.mcp._KdbgVadExtractStore", return_value=artifacts), \
             patch("winbox.mcp._kdbg_extract_vad_live") as extract:
            error = _mcp_error(kdbg_vad_extract(1234, "0x40000000", "case"))
        assert error["code"] == "vad_extract_error"
        extract.assert_not_called()


# ─── kdbg session daemon tools (Tool 14) ───────────────────────────────────


import json as _json_mod


class TestKdbgDaemonTools:
    """MCP wrappers around the long-running session daemon.

    Patches winbox.mcp._kdbg_client (and _fork_daemon for attach) so we
    don't fork or open Unix sockets during tests.
    """

    def _client_with(self, *, alive=True, info=None, call_result=None,
                     call_raises=None):
        client = MagicMock()
        client.session_alive.return_value = alive
        client.session_info.return_value = info or {
            "target_pid": 4584, "target_dtb": "0x4d6bb000",
            "target_name": "notepad.exe", "daemon_pid": 9999,
            "gdbstub_port": 1234,
        }
        if call_raises is not None:
            client.call.side_effect = call_raises
        else:
            client.call.return_value = call_result if call_result is not None else {}
        return client

    # ── kdbg_attach ─────────────────────────────────────────────────────

    def _fake_proc(self, pid=4584, name="notepad.exe", dtb=0x4d6bb000,
                   user_dtb=0):
        """Build a minimal ProcessRecord for mocking _kdbg_list_processes."""
        from winbox.kdbg.walk import ProcessRecord
        return ProcessRecord(
            pid=pid, name=name, eprocess=0xffff,
            directory_table_base=dtb,
            user_directory_table_base=user_dtb,
        )

    def test_attach_passes_pid_to_fork_daemon(self, mock_mcp):
        """fork_daemon receives the raw PID — the daemon child walks
        processes after halting the VM for a stable CR3."""
        from winbox.mcp import kdbg_attach
        client = self._client_with(alive=False, info={
            "target_pid": 4584, "target_dtb": "0x4d6bb000",
            "target_name": "notepad.exe", "daemon_pid": 1234,
            "gdbstub_port": 1234,
        })
        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch("winbox.kdbg.hmp.gdbstub_has_client", return_value=False), \
             patch("winbox.mcp._fork_daemon", return_value=1234) as ff:
            result = kdbg_attach(4584)

        ff.assert_called_once()
        assert ff.call_args[0][1] == 4584
        out = _mcp_result(result)
        assert out["daemon_pid"] == 1234
        assert out["auto_stage"]["staged"] == 2
        assert ff.call_args.kwargs["module_manifest"].pid == 4584

    def test_attach_forwards_reduced_staging_policy(self, mock_mcp):
        from winbox.mcp import kdbg_attach
        import winbox.kdbg.staging as staging_module

        client = self._client_with(alive=False)
        captured = {}

        def prepare(_cfg, _ga, _store, pid, **kwargs):
            captured.update(pid=pid, **kwargs)
            return SimpleNamespace(pid=pid, summary=lambda: {
                "staging_policy": kwargs["policy"], "staged": 1,
            })

        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch("winbox.kdbg.hmp.gdbstub_has_client", return_value=False), \
             patch.object(staging_module, "prepare_user_module_manifest", prepare), \
             patch("winbox.mcp._fork_daemon", return_value=1234):
            result = kdbg_attach(4584, staging_policy="binaries")
        assert result["ok"] is True
        assert captured["policy"] == "binaries"
        assert captured["enrich_symbols"] is False

    def test_attach_preflight_does_not_take_gdbstub_or_fork(self, mock_mcp):
        from winbox.mcp import kdbg_attach
        import winbox.kdbg.staging as staging_module

        client = self._client_with(alive=False)
        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch.object(
                 staging_module, "preflight_user_module_staging",
                 return_value={"schema": "winbox.kdbg-staging-preflight/1", "dry_run": True},
             ) as preflight, \
             patch("winbox.kdbg.hmp.gdbstub_has_client") as probe, \
             patch("winbox.mcp._fork_daemon") as fork:
            result = kdbg_attach(4584, staging_policy="cached-only", preflight=True)
        assert _mcp_result(result)["dry_run"] is True
        preflight.assert_called_once()
        assert preflight.call_args.kwargs["policy"] == "cached-only"
        probe.assert_not_called()
        fork.assert_not_called()

    def test_attach_forwards_intents_only_after_explicit_opt_in(self, mock_mcp):
        from winbox.kdbg.breakpoint_intent import BreakpointIntentStore
        from winbox.mcp import kdbg_attach
        import winbox.kdbg.staging as staging_module

        _ga, _vm, cfg = mock_mcp
        BreakpointIntentStore(cfg).add("mpengine+0x40")
        client = self._client_with(alive=False)
        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch("winbox.kdbg.hmp.gdbstub_has_client", return_value=False), \
             patch.object(
                 staging_module, "prepare_user_module_manifest",
                 wraps=staging_module.prepare_user_module_manifest,
             ), \
             patch("winbox.mcp._fork_daemon", return_value=1234) as fork:
            kdbg_attach(4584)
            assert fork.call_args.kwargs["breakpoint_intents"] is None
            kdbg_attach(4584, apply_intents=True)
            selected = fork.call_args.kwargs["breakpoint_intents"]
        assert len(selected) == 1
        assert selected[0]["target"] == "mpengine+0x40"

    def test_attach_prewarm_starts_only_exact_symbol_modules(self, mock_mcp):
        from winbox.mcp import kdbg_attach
        from winbox.kdbg.staging import StagedUserModule, UserModuleManifest
        import winbox.kdbg.staging as staging_module

        client = self._client_with(alive=False)
        modules = (
            StagedUserModule(
                "a.dll", "C:\\a.dll", "x64", 0x1000, 0x1000,
                "/cache/a.dll", "a" * 64, "a", store_build="BUILD-A",
            ),
            StagedUserModule(
                "b.dll", "C:\\b.dll", "x64", 0x2000, 0x1000,
                "/cache/b.dll", "b" * 64, "b", store_build=None,
            ),
        )
        manifest = UserModuleManifest(pid=4584, modules=modules)
        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch("winbox.kdbg.hmp.gdbstub_has_client", return_value=False), \
             patch.object(
                 staging_module, "prepare_user_module_manifest",
                 return_value=manifest,
             ), \
             patch("winbox.mcp._fork_daemon", return_value=1234), \
             patch(
                 "winbox.kdbg.decomp.start_prepare_background",
                 return_value={"token": "c" * 32, "state": "starting"},
             ) as start:
            result = kdbg_attach(4584, prewarm=True)
        assert _mcp_result(result)["prewarm"]["token"] == "c" * 32
        assert start.call_args.kwargs["modules"] == ["a"]

    def test_attach_surfaces_manifest_failure_before_taking_gdbstub(self, mock_mcp):
        from winbox.mcp import kdbg_attach
        from winbox.kdbg.staging import StagingError

        client = self._client_with(alive=False)
        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch(
                 "winbox.kdbg.staging.prepare_user_module_manifest",
                 side_effect=StagingError("loader inventory corrupt"),
             ), \
             patch("winbox.mcp._fork_daemon") as ff:
            result = kdbg_attach(4584)
        ff.assert_not_called()
        assert "loader inventory corrupt" in _mcp_error(result)["message"]

    def test_attach_refuses_when_session_already_alive(self, mock_mcp):
        from winbox.mcp import kdbg_attach
        client = self._client_with(alive=True)
        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch("winbox.mcp._fork_daemon") as ff:
            result = kdbg_attach(4584)

        ff.assert_not_called()
        error = _mcp_error(result)
        assert "another session" in error["message"]
        assert "kdbg_detach" in error["message"]

    def test_attach_refuses_when_gdb_client_connected(self, mock_mcp):
        from winbox.mcp import kdbg_attach
        client = self._client_with(alive=False)
        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch("winbox.kdbg.hmp.gdbstub_has_client", return_value=True), \
             patch("winbox.mcp._fork_daemon") as ff:
            result = kdbg_attach(4584)
        ff.assert_not_called()
        assert "another gdb client" in _mcp_error(result)["message"]

    def test_attach_proceeds_when_no_gdb_client(self, mock_mcp):
        from winbox.mcp import kdbg_attach
        client = self._client_with(alive=False)
        client.session_info.return_value = {"target_pid": 4584, "target_name": "test.exe",
                                            "target_dtb": "0x1ae000", "gdbstub_port": 1234}
        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch("winbox.kdbg.hmp.gdbstub_has_client", return_value=False), \
             patch("winbox.mcp._fork_daemon", return_value=12345):
            result = kdbg_attach(4584)
        assert "daemon_pid" in _mcp_result(result)

    def test_attach_surfaces_daemon_error(self, mock_mcp):
        from winbox.mcp import kdbg_attach
        from winbox.kdbg.debugger.daemon import DaemonError
        proc = self._fake_proc(pid=99999)
        client = self._client_with(alive=False)
        fake_store = MagicMock()
        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch("winbox.mcp._kdbg_get_store", return_value=fake_store), \
             patch("winbox.mcp._kdbg_list_processes", return_value=[proc]), \
             patch("winbox.kdbg.hmp.gdbstub_has_client", return_value=False), \
             patch("winbox.mcp._fork_daemon", side_effect=DaemonError("gdbstub refused")):
            result = kdbg_attach(99999)
        assert _mcp_error(result)["message"] == "gdbstub refused"

    def test_attach_warns_when_hvci_on(self, mock_mcp):
        from winbox.mcp import kdbg_attach
        from winbox.hvci import HvciStatus
        proc = self._fake_proc()
        client = self._client_with(alive=False, info={
            "target_pid": 4584, "target_dtb": "0x4d6bb000",
            "target_name": "notepad.exe", "daemon_pid": 1234,
            "gdbstub_port": 1234,
        })
        fake_store = MagicMock()
        hvci_on = HvciStatus(vbs_enabled=True, hvci_enabled=True, hypervisor_off=False)
        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch("winbox.mcp._kdbg_get_store", return_value=fake_store), \
             patch("winbox.mcp._kdbg_list_processes", return_value=[proc]), \
             patch("winbox.kdbg.hmp.gdbstub_has_client", return_value=False), \
             patch("winbox.mcp._fork_daemon", return_value=1234), \
             patch("winbox.hvci.status", return_value=hvci_on):
            result = kdbg_attach(4584)
        out = _mcp_result(result)
        assert "warning" in out
        assert "HVCI" in out["warning"]

    def test_attach_no_warning_when_hvci_off(self, mock_mcp):
        from winbox.mcp import kdbg_attach
        from winbox.hvci import HvciStatus
        proc = self._fake_proc()
        client = self._client_with(alive=False, info={
            "target_pid": 4584, "target_dtb": "0x4d6bb000",
            "target_name": "notepad.exe", "daemon_pid": 1234,
            "gdbstub_port": 1234,
        })
        fake_store = MagicMock()
        hvci_off = HvciStatus(vbs_enabled=False, hvci_enabled=False, hypervisor_off=True)
        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch("winbox.mcp._kdbg_get_store", return_value=fake_store), \
             patch("winbox.mcp._kdbg_list_processes", return_value=[proc]), \
             patch("winbox.kdbg.hmp.gdbstub_has_client", return_value=False), \
             patch("winbox.mcp._fork_daemon", return_value=1234), \
             patch("winbox.hvci.status", return_value=hvci_off):
            result = kdbg_attach(4584)
        out = _mcp_result(result)
        assert "warning" not in out

    # ── kdbg_session ────────────────────────────────────────────────────

    def test_session_when_not_attached(self, mock_mcp):
        from winbox.mcp import kdbg_session
        client = self._client_with(alive=False)
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_session()
        assert _mcp_result(result) == {"attached": False}

    def test_session_when_attached(self, mock_mcp):
        from winbox.mcp import kdbg_session
        client = self._client_with(alive=True, call_result={
            "target": {"pid": 4584, "dtb": "0x4d6bb000", "name": "notepad.exe"},
            "bps": 1, "halted": True, "uptime_s": 12.3, "daemon_pid": 1234,
        })
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_session()
        out = _mcp_result(result)
        assert out["attached"] is True
        assert out["target"]["pid"] == 4584
        assert out["bps"] == 1

    def test_target_status_forwards_bounded_daemon_probe(self, mock_mcp):
        from winbox.mcp import kdbg_target_status
        client = self._client_with(call_result={
            "state": "gone", "reason": "pid_reused", "advisory": True,
        })
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_target_status()
        assert _mcp_result(result)["state"] == "gone"
        client.call.assert_called_once_with("target_status")

    # ── kdbg_bp ─────────────────────────────────────────────────────────

    def test_bp_passes_target_and_mode_to_daemon(self, mock_mcp):
        from winbox.mcp import kdbg_bp
        client = self._client_with(call_result={
            "id": 0, "va": "0x7ff7b04eeabc",
            "user_mode": True, "hw": True, "elapsed_ms": 3.7,
        })
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_bp("notepad!Save")
        # Default mode is "hw" — verify it's forwarded
        client.call.assert_called_once_with(
            "bp_add", target="notepad!Save", mode="hw", condition=None,
        )
        out = _mcp_result(result)
        assert out["id"] == 0
        assert out["hw"] is True

    def test_bp_explicit_soft_mode_forwarded(self, mock_mcp):
        from winbox.mcp import kdbg_bp
        client = self._client_with(call_result={
            "id": 0, "va": "0x7ff7b04eeabc",
            "user_mode": True, "hw": False, "elapsed_ms": 4.2,
        })
        with patch("winbox.mcp._kdbg_client", return_value=client):
            kdbg_bp("notepad!Save", mode="soft")
        client.call.assert_called_once_with(
            "bp_add", target="notepad!Save", mode="soft", condition=None,
        )

    def test_bp_returns_error_on_install_failure(self, mock_mcp):
        from winbox.mcp import kdbg_bp
        from winbox.kdbg.debugger.client import ClientError
        client = self._client_with(call_raises=ClientError("Z0 failed: E22"))
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_bp("notepad!Cold")
        assert _mcp_error(result)["message"] == "Z0 failed: E22"

    def test_bp_condition_passed_through(self, mock_mcp):
        from winbox.mcp import kdbg_bp
        client = self._client_with(call_result={
            "id": 1, "va": "0xfffff806123456", "user_mode": False,
            "hw": True, "condition": "rcx == 0xdeadbeef", "elapsed_ms": 2.1,
        })
        with patch("winbox.mcp._kdbg_client", return_value=client):
            kdbg_bp("nt!NtClose", condition="rcx == 0xdeadbeef")
        client.call.assert_called_once_with(
            "bp_add", target="nt!NtClose", mode="hw",
            condition="rcx == 0xdeadbeef",
        )

    def test_bp_empty_condition_treated_as_none(self, mock_mcp):
        from winbox.mcp import kdbg_bp
        client = self._client_with(call_result={
            "id": 0, "va": "0x1", "user_mode": False, "hw": True,
            "condition": None, "elapsed_ms": 1.0,
        })
        with patch("winbox.mcp._kdbg_client", return_value=client):
            kdbg_bp("nt!Foo", condition="   ")
        client.call.assert_called_once_with(
            "bp_add", target="nt!Foo", mode="hw", condition=None,
        )

    def test_bp_actions_are_forwarded_without_lossy_coercion(self, mock_mcp):
        from winbox.mcp import kdbg_bp
        client = self._client_with(call_result={"id": 0})
        actions = ["byte(rcx)", "bytes(rdx,16)"]
        with patch("winbox.mcp._kdbg_client", return_value=client):
            kdbg_bp("nt!Foo", actions=actions)
        client.call.assert_called_once_with(
            "bp_add", target="nt!Foo", mode="hw", condition=None,
            actions=actions,
        )

    # ── kdbg_bps / kdbg_rm ─────────────────────────────────────────────

    def test_bps_returns_list(self, mock_mcp):
        from winbox.mcp import kdbg_bps
        client = self._client_with(call_result={
            "bps": [{"id": 0, "va": "0x...", "target": "x", "user_mode": True,
                     "hits": 5, "age_s": 1.2}]
        })
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_bps()
        out = _mcp_result(result)
        assert len(out["bps"]) == 1
        assert out["bps"][0]["hits"] == 5

    def test_bp_trace_forwards_bounded_query_options(self, mock_mcp):
        from winbox.mcp import kdbg_bp_trace
        client = self._client_with(call_result={
            "id": 3, "entries": [], "total": 100, "returned": 0,
            "truncated": False,
        })
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_bp_trace(
                3,
                from_hit=40,
                limit=50,
                expression="[rsp+0x18]",
                value="0x22c004",
                errors_only=True,
                summary=True,
                top=7,
            )

        client.call.assert_called_once_with(
            "bp_trace",
            id=3,
            tail=20,
            from_hit=40,
            limit=50,
            expression="[rsp+0x18]",
            value="0x22c004",
            errors_only=True,
            summary=True,
            top=7,
        )
        assert _mcp_result(result)["total"] == 100

    def test_bp_trace_default_query_remains_tail_compatible(self, mock_mcp):
        from winbox.mcp import kdbg_bp_trace
        client = self._client_with(call_result={
            "id": 1, "entries": [], "total": 0, "returned": 0,
            "truncated": False,
        })
        with patch("winbox.mcp._kdbg_client", return_value=client):
            kdbg_bp_trace(1)

        client.call.assert_called_once_with(
            "bp_trace", id=1, tail=20, limit=20,
            errors_only=False, summary=False, top=10,
        )

    def test_rm_passes_id(self, mock_mcp):
        from winbox.mcp import kdbg_rm
        client = self._client_with(call_result={"removed": 0, "va": "0x123"})
        with patch("winbox.mcp._kdbg_client", return_value=client):
            kdbg_rm(0)
        client.call.assert_called_once_with("bp_remove", id=0)

    # ── kdbg_cont ─────────────────────────────────────────────────────

    def test_cont_passes_timeout_in_args_not_sock_kwarg(self, mock_mcp):
        """Critical: timeout is op-level (in args), sock_timeout is the
        client-side socket timeout. They MUST NOT collide."""
        from winbox.mcp import kdbg_cont
        client = self._client_with(call_result={"reason": "bp"})
        with patch("winbox.mcp._kdbg_client", return_value=client):
            kdbg_cont(timeout=15.0)
        # Call must be call("cont", sock_timeout=25.0, timeout=15.0)
        args, kwargs = client.call.call_args
        assert args == ("cont",)
        assert kwargs["sock_timeout"] == 25.0
        assert kwargs["timeout"] == 15.0

    def test_cont_returns_stop_info(self, mock_mcp):
        from winbox.mcp import kdbg_cont
        client = self._client_with(call_result={
            "reason": "bp", "vcpu": "01", "rip": "0x7ff7...",
            "cr3": "0x4d6bb000", "in_target": True,
            "bp_id": 0, "bp_target": "notepad!SaveFile",
        })
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_cont()
        out = _mcp_result(result)
        assert out["reason"] == "bp"
        assert out["bp_id"] == 0

    def test_async_cont_tools_use_durable_worker_contract(self, mock_mcp):
        from winbox.mcp import kdbg_cont_cancel, kdbg_cont_poll, kdbg_cont_start

        with patch(
            "winbox.kdbg.debugger.continue_job.start_continue",
            return_value={"state": "starting", "token": "tok", "active": True},
        ) as start, patch(
            "winbox.kdbg.debugger.continue_job.poll_continue",
            return_value={"state": "running", "token": "tok", "active": True},
        ) as poll, patch(
            "winbox.kdbg.debugger.continue_job.cancel_continue",
            return_value={"state": "cancel_requested", "token": "tok", "active": True},
        ) as cancel:
            assert _mcp_result(kdbg_cont_start(600))["token"] == "tok"
            assert _mcp_result(kdbg_cont_poll("tok"))["state"] == "running"
            assert _mcp_result(kdbg_cont_cancel("tok"))["state"] == "cancel_requested"

        start.assert_called_once_with(mock_mcp[2], timeout=600)
        poll.assert_called_once_with(mock_mcp[2], token="tok")
        cancel.assert_called_once_with(mock_mcp[2], token="tok")

    def test_structured_errors_are_classified_and_bounded(self):
        from winbox.mcp import _research_error

        stale = _research_error(
            "continuation no longer matches this debugger stop",
            operation="kdbg_decomp",
        )
        assert stale["error"]["code"] == "stale_stop"
        assert stale["error"]["retryable"] is True
        invalid = _research_error("count must be between 0 and 32", operation="x")
        assert invalid["error"]["code"] == "invalid_argument"
        no_session = _research_error("no kdbg daemon running", operation="x")
        assert no_session["error"]["code"] == "no_session"
        busy = _research_error("continue job already active", operation="x")
        assert busy["error"]["code"] == "busy" and busy["error"]["retryable"]
        mismatch = _research_error(
            "worker API 3 owns api4; reload/version-align", operation="x",
        )
        assert mismatch["error"]["code"] == "worker_version_mismatch"
        cap = _research_error("actions may contain at most 16", operation="x")
        assert cap["error"]["code"] == "invalid_argument"
        timeout_bound = _research_error(
            "timeout must be between 0.5 and 86400 seconds", operation="x",
        )
        assert timeout_bound["error"]["code"] == "invalid_argument"
        assert timeout_bound["error"]["retryable"] is False
        huge = _research_error("x" * 5000, operation="x")
        assert len(huge["error"]["message"]) == 2048

    # ── kdbg_step / kdbg_interrupt ────────────────────────────────────

    def test_step_calls_daemon(self, mock_mcp):
        from winbox.mcp import kdbg_step
        client = self._client_with(call_result={"reason": "step", "rip": "0x..."})
        with patch("winbox.mcp._kdbg_client", return_value=client):
            kdbg_step()
        client.call.assert_called_once_with("step")

    def test_interrupt_calls_daemon(self, mock_mcp):
        from winbox.mcp import kdbg_interrupt
        client = self._client_with(call_result={"queued": True})
        with patch("winbox.mcp._kdbg_client", return_value=client):
            kdbg_interrupt()
        client.call.assert_called_once_with("interrupt")

    # ── kdbg_regs / kdbg_mem / kdbg_stack / kdbg_bt ───────────────────

    def test_regs_returns_dict(self, mock_mcp):
        from winbox.mcp import kdbg_regs
        client = self._client_with(call_result={
            "rip": "0x123", "rsp": "0x456", "cr3": "0x789",
        })
        with patch("winbox.mcp._kdbg_client", return_value=client):
            out = _mcp_result(kdbg_regs())
        assert out["rip"] == "0x123"
        assert out["cr3"] == "0x789"

    def test_mem_passes_va_and_length(self, mock_mcp):
        from winbox.mcp import kdbg_mem
        client = self._client_with(call_result={"va": "0x1000", "bytes": "deadbeef"})
        with patch("winbox.mcp._kdbg_client", return_value=client):
            kdbg_mem("0x1000", length=4)
        client.call.assert_called_once_with("mem", va="0x1000", length=4)

    def test_write_mem_passes_va_and_data(self, mock_mcp):
        from winbox.mcp import kdbg_write_mem
        client = self._client_with(call_result={"va": "0x1000", "length": 4})
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_write_mem("0x1000", "deadbeef")
        client.call.assert_called_once_with("write_mem", va="0x1000", data="deadbeef")
        out = _mcp_result(result)
        assert out["length"] == 4

    def test_write_mem_surfaces_error(self, mock_mcp):
        from winbox.mcp import kdbg_write_mem
        from winbox.kdbg.debugger.client import ClientError
        client = self._client_with(call_raises=ClientError("M failed: E22"))
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_write_mem("0x1000", "ff")
        assert _mcp_error(result)["message"] == "M failed: E22"

    def test_mem_decode_utf16le(self, mock_mcp):
        from winbox.mcp import kdbg_mem
        # "abc" in UTF-16LE = 61 00 62 00 63 00
        client = self._client_with(call_result={"va": "0x1000", "bytes": "610062006300"})
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_mem("0x1000", length=6, decode="utf-16le")
        out = _mcp_result(result)
        assert out["decoded"] == "abc"

    def test_mem_decode_utf8(self, mock_mcp):
        from winbox.mcp import kdbg_mem
        # "hello" in UTF-8 = 68 65 6c 6c 6f
        client = self._client_with(call_result={"va": "0x1000", "bytes": "68656c6c6f"})
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_mem("0x1000", length=5, decode="utf-8")
        out = _mcp_result(result)
        assert out["decoded"] == "hello"

    def test_mem_decode_ascii_replaces_control(self, mock_mcp):
        from winbox.mcp import kdbg_mem
        # bytes: 41 42 01 7f 43 (A B ctrl-A DEL C)
        client = self._client_with(call_result={"va": "0x1", "bytes": "41420143"})
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_mem("0x1", length=4, decode="ascii")
        out = _mcp_result(result)
        assert out["decoded"] == "AB.C"

    def test_mem_decode_cstr_truncates_at_null(self, mock_mcp):
        from winbox.mcp import kdbg_mem
        # "hello" then null then "tail"
        client = self._client_with(call_result={
            "va": "0x1", "bytes": "68656c6c6f00" + "7461696c"
        })
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_mem("0x1", length=10, decode="cstr")
        out = _mcp_result(result)
        assert out["decoded"] == "hello"

    def test_mem_decode_hex_default_no_decode_field(self, mock_mcp):
        from winbox.mcp import kdbg_mem
        client = self._client_with(call_result={"va": "0x1", "bytes": "deadbeef"})
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_mem("0x1", length=4)
        out = _mcp_result(result)
        assert "decoded" not in out  # default hex mode keeps raw

    def test_mem_decode_unknown_mode_surfaces_in_decoded(self, mock_mcp):
        from winbox.mcp import kdbg_mem
        client = self._client_with(call_result={"va": "0x1", "bytes": "00"})
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_mem("0x1", length=1, decode="bogus")
        out = _mcp_result(result)
        assert "unknown decode" in out["decoded"]

    # ── kdbg_disasm ───────────────────────────────────────────────────

    def test_disasm_uses_rip_when_addr_empty(self, mock_mcp):
        from winbox.mcp import kdbg_disasm
        # mock client: regs returns rip; mem returns a few bytes;
        # capstone disasms them.
        client = MagicMock()
        client.call.side_effect = [
            {"rip": "0x401000", "rsp": "0x0", "cr3": "0x0"},  # regs reply
            {"va": "0x401000", "bytes": "9090c3"},            # mem reply
        ]
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_disasm(addr="", count=4)
        out = _mcp_result(result)
        assert out["base"] == "0x401000"
        # 90 90 c3 = nop; nop; ret
        mnemonics = [i["mnemonic"] for i in out["instructions"]]
        assert mnemonics[:3] == ["nop", "nop", "ret"]
        assert out["instruction_bytes"] is False
        assert all("bytes" not in item for item in out["instructions"])

    def test_disasm_raw_bytes_are_opt_in(self, mock_mcp):
        from winbox.mcp import kdbg_disasm

        client = MagicMock()
        client.call.return_value = {"va": "0x500000", "bytes": "90"}
        with patch("winbox.mcp._kdbg_client", return_value=client):
            out = _mcp_result(kdbg_disasm(
                addr="0x500000", count=1, instruction_bytes=True,
            ))
        assert out["instructions"][0]["bytes"] == "90"

    def test_disasm_explicit_addr_skips_regs_call(self, mock_mcp):
        from winbox.mcp import kdbg_disasm
        client = MagicMock()
        # Only mem call expected (no regs since addr was given)
        client.call.return_value = {"va": "0x500000", "bytes": "488d0500000000"}
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_disasm(addr="0x500000", count=1)
        # Only mem should be called once.
        assert client.call.call_count == 1
        op_name, kwargs = client.call.call_args[0][0], client.call.call_args[1]
        assert op_name == "mem"
        out = _mcp_result(result)
        assert out["instructions"][0]["mnemonic"] == "lea"

    def test_disasm_invalid_addr_returns_error(self, mock_mcp):
        from winbox.mcp import kdbg_disasm
        with patch("winbox.mcp._kdbg_client", return_value=MagicMock()):
            result = kdbg_disasm(addr="not_a_number", count=1)
        error = _mcp_error(result)
        assert error["code"] == "invalid_argument"
        assert "not a valid VA" in error["message"]

    def test_stack_passes_n(self, mock_mcp):
        from winbox.mcp import kdbg_stack
        client = self._client_with(call_result={
            "rsp": "0x100",
            "qwords": [{"offset": "rsp+0x00", "va": "0x100", "value": "0x0000000000000001"}],
        })
        with patch("winbox.mcp._kdbg_client", return_value=client):
            kdbg_stack(n=8)
        client.call.assert_called_once_with("stack", n=8)

    def test_stack_returns_offset_labeled_qwords(self, mock_mcp):
        from winbox.mcp import kdbg_stack
        import json as _json
        qwords = [
            {"offset": "rsp+0x00", "va": "0x1000", "value": "0x00000000deadbeef"},
            {"offset": "rsp+0x08", "va": "0x1008", "value": "0x00000000cafebabe"},
        ]
        client = self._client_with(call_result={"rsp": "0x1000", "qwords": qwords})
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_stack(n=2)
        parsed = _mcp_result(result)
        assert parsed["rsp"] == "0x1000"
        assert len(parsed["qwords"]) == 2
        assert parsed["qwords"][0]["offset"] == "rsp+0x00"
        assert parsed["qwords"][0]["value"] == "0x00000000deadbeef"
        assert parsed["qwords"][1]["offset"] == "rsp+0x08"

    def test_mem_decode_qwords(self, mock_mcp):
        from winbox.mcp import kdbg_mem
        import json as _json
        raw_hex = "efbeadde00000000" + "bebafeca00000000"
        client = self._client_with(call_result={"va": "0x1000", "bytes": raw_hex})
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_mem(va="0x1000", length=16, decode="qwords")
        parsed = _mcp_result(result)
        assert parsed["decoded"] == [
            "0x00000000deadbeef",
            "0x00000000cafebabe",
        ]

    def test_bt_passes_depth(self, mock_mcp):
        from winbox.mcp import kdbg_bt
        client = self._client_with(call_result={"rsp": "0x100", "frames": []})
        with patch("winbox.mcp._kdbg_client", return_value=client):
            kdbg_bt(depth=12)
        client.call.assert_called_once_with("bt", depth=12)

    # ── kdbg_detach ───────────────────────────────────────────────────

    def test_detach_no_session_is_noop(self, mock_mcp):
        from winbox.mcp import kdbg_detach
        client = self._client_with(alive=False)
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_detach()
        assert _mcp_result(result) == {
            "detached": False, "already_detached": True,
        }
        client.call.assert_not_called()

    def test_detach_calls_daemon_and_waits_for_release(self, mock_mcp):
        from winbox.mcp import kdbg_detach
        # Alive on first probe, dead on second (simulates fast daemon shutdown).
        client = MagicMock()
        client.session_alive.side_effect = [True, False]
        client.call.return_value = {
            "shutting_down": True,
            "resume_safe": True,
            "cr3_poisoned": False,
        }
        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch("winbox.kdbg.hmp.ensure_not_paused", return_value=None) as guard:
            result = kdbg_detach()
        client.call.assert_called_once_with("detach")
        parsed = _mcp_result(result)
        assert parsed["detached"] is True
        assert parsed["resume_safe"] is True
        guard.assert_called_once()

    def test_poisoned_detach_never_uses_out_of_band_resume(self, mock_mcp):
        from winbox.mcp import kdbg_detach

        client = MagicMock()
        client.session_alive.side_effect = [True, False]
        client.call.return_value = {
            "shutting_down": True,
            "resume_safe": False,
            "cr3_poisoned": True,
            "recovery": "restore snapshot before resuming",
        }
        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch("winbox.kdbg.hmp.ensure_not_paused") as guard:
            result = kdbg_detach()

        parsed = _mcp_result(result)
        assert parsed["detached"] is True
        assert parsed["cr3_poisoned"] is True
        assert "restore snapshot" in parsed["recovery"]
        guard.assert_not_called()

    def test_detach_transport_error_without_certificate_never_resumes(self, mock_mcp):
        from winbox.kdbg.debugger.client import ClientError
        from winbox.mcp import kdbg_detach

        client = MagicMock()
        client.session_alive.side_effect = [True, False]
        client.call.side_effect = ClientError("connection closed")
        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch("winbox.kdbg.hmp.ensure_not_paused") as guard:
            result = kdbg_detach()

        parsed = _mcp_result(result)
        assert parsed["detached"] is True
        assert parsed["resume_safe"] is False
        assert "automatic resume skipped" in parsed["warning"]
        guard.assert_not_called()

    # ── kdbg_resume ───────────────────────────────────────────────────

    def test_resume_refuses_when_session_active(self, mock_mcp):
        from winbox.mcp import kdbg_resume
        import winbox.mcp as mcp_mod
        mcp_mod._vm.state.return_value = VMState.PAUSED
        client = self._client_with(alive=True)
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_resume()
        assert "kdbg_detach instead" in _mcp_error(result)["message"]

    def test_resume_errors_when_no_gdbstub(self, mock_mcp):
        from winbox.mcp import kdbg_resume
        import winbox.mcp as mcp_mod
        mcp_mod._vm.state.return_value = VMState.PAUSED
        client = self._client_with(alive=False)
        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch("winbox.kdbg.hmp.probe_port", return_value=False):
            result = kdbg_resume()
        assert "gdbstub not listening" in _mcp_error(result)["message"]

    def test_resume_is_a_clean_no_op_on_a_running_vm(self, mock_mcp):
        """Docstring promises 'No-op if VM is already running' — it must
        not connect to the gdbstub, which would halt a healthy VM."""
        from winbox.mcp import kdbg_resume
        import winbox.mcp as mcp_mod
        mcp_mod._vm.state.return_value = VMState.RUNNING
        client = self._client_with(alive=False)
        with patch("winbox.mcp._kdbg_client", return_value=client) as kc, \
             patch("winbox.mcp._RspClient") as rsp:
            result = kdbg_resume()
        assert _mcp_result(result) == {"resumed": False, "already_running": True}
        kc.assert_not_called()
        rsp.connect.assert_not_called()

    def test_resume_reports_success_only_when_vm_actually_ends_up_running(self, mock_mcp):
        """close() does interrupt+detach, which its own docstring says can
        race QEMU and leave the VM paused instead of running. kdbg_resume
        must not claim success it did not verify."""
        from winbox.mcp import kdbg_resume
        import winbox.mcp as mcp_mod
        # Not running yet (proceeds past the no-op check); running by the
        # time the post-release check happens.
        mcp_mod._vm.state.side_effect = [VMState.PAUSED, VMState.RUNNING]
        daemon_client = self._client_with(alive=False)
        rsp_client = MagicMock()
        with patch("winbox.mcp._kdbg_client", return_value=daemon_client), \
             patch("winbox.kdbg.hmp.probe_port", return_value=True), \
             patch("winbox.mcp._RspClient") as rsp_cls, \
             patch("time.sleep"):
            rsp_cls.connect.return_value = rsp_client
            result = kdbg_resume()
        rsp_client.cont.assert_called_once()
        rsp_client.close.assert_called_once()
        assert _mcp_result(result) == {"resumed": True, "state": "running"}

    def test_resume_reports_the_real_state_when_release_leaves_it_paused(self, mock_mcp):
        from winbox.mcp import kdbg_resume
        import winbox.mcp as mcp_mod
        mcp_mod._vm.state.side_effect = [VMState.PAUSED, VMState.PAUSED]
        daemon_client = self._client_with(alive=False)
        rsp_client = MagicMock()
        with patch("winbox.mcp._kdbg_client", return_value=daemon_client), \
             patch("winbox.kdbg.hmp.probe_port", return_value=True), \
             patch("winbox.mcp._RspClient") as rsp_cls, \
             patch("time.sleep"):
            rsp_cls.connect.return_value = rsp_client
            result = kdbg_resume()
        assert "paused" in _mcp_error(result)["message"]


class TestReadmeToolCount:
    """The README advertises how many MCP tools ship; it has drifted before.

    Comparing against the README's own number (rather than a literal here)
    means adding a tool fails this test until the docs are updated, without
    needing two magic numbers kept in sync.
    """

    def _readme(self):
        import pathlib

        path = pathlib.Path(__file__).resolve().parents[1] / "README.md"
        if not path.exists():
            import pytest

            pytest.skip("README.md not present (installed package)")
        return path.read_text(encoding="utf-8")

    def test_readme_count_matches_registered_tools(self):
        import asyncio
        import re

        from winbox.mcp import mcp

        tools = asyncio.run(mcp.list_tools())
        m = re.search(r"\*\*MCP server\*\* — (\d+) tools", self._readme())
        assert m, "README no longer states an MCP tool count in the expected form"
        assert int(m.group(1)) == len(tools), (
            f"README says {m.group(1)} MCP tools but {len(tools)} are registered"
        )

    def test_tool_names_are_unique(self):
        import asyncio

        from winbox.mcp import mcp

        names = [t.name for t in asyncio.run(mcp.list_tools())]
        assert len(names) == len(set(names))

    def test_every_tool_has_a_description(self):
        """Tool docstrings are the only thing an agent sees when choosing."""
        import asyncio

        from winbox.mcp import mcp

        undocumented = [
            t.name for t in asyncio.run(mcp.list_tools()) if not (t.description or "").strip()
        ]
        assert undocumented == []

    def test_detailed_tool_table_matches_registered_tools(self):
        """The Features-bullet count above only checks one number; the
        detailed "Available tools (N):" table has its own count and its own
        row list, and neither is derived from the other. This table drifted
        silently to 51/54 with the whole av_status/av_enable/av_disable
        group missing before this test existed."""
        import asyncio
        import re

        from winbox.mcp import mcp

        tools = {t.name for t in asyncio.run(mcp.list_tools())}
        readme = self._readme()

        m = re.search(r"\*\*Available tools \((\d+)\):\*\*", readme)
        assert m, "README no longer states the detailed-table tool count in the expected form"
        assert int(m.group(1)) == len(tools), (
            f"README's detailed table header says {m.group(1)} tools but {len(tools)} are registered"
        )

        section = readme.split(f"**Available tools ({m.group(1)}):**", 1)[1]
        section = section.split("## Architecture", 1)[0]
        listed = set(re.findall(r"`([a-z_]+)\(", section))
        missing = tools - listed
        assert not missing, f"registered tools missing from the detailed table: {sorted(missing)}"


class TestFormatExecResultDiagnostics:
    """A non-zero exit with nothing on either stream used to render as the
    bare string "\\n[exit code: 1]" — indistinguishable from a tool that
    simply had nothing to say, and the exact shape an externally killed
    in-guest process leaves behind (Python block-buffers stdout to a pipe,
    so a kill before interpreter shutdown discards it)."""

    def test_silent_failure_explains_itself(self):
        from winbox.mcp import _format_exec_result

        out = _format_exec_result({"stdout": "", "stderr": "", "exitcode": 1})

        assert "[exit code: 1]" in out
        assert "no output on either stream" in out
        assert "flush" in out

    def test_failure_with_stderr_is_left_alone(self):
        from winbox.mcp import _format_exec_result

        out = _format_exec_result(
            {"stdout": "", "stderr": "Traceback...", "exitcode": 1}
        )

        assert "Traceback..." in out
        assert "no output on either stream" not in out

    def test_failure_with_stdout_is_left_alone(self):
        from winbox.mcp import _format_exec_result

        out = _format_exec_result({"stdout": "partial", "stderr": "", "exitcode": 1})

        assert "partial" in out
        assert "no output on either stream" not in out

    def test_success_with_no_output_is_unchanged(self):
        from winbox.mcp import _format_exec_result

        assert _format_exec_result(
            {"stdout": "", "stderr": "", "exitcode": 0}
        ) == "(no output)"


class TestRegSetTypeLeniency:
    """A registry write should not fail over the spelling of its type."""

    def _script_for(self, value_type):
        import winbox.mcp as m

        captured = {}

        def fake_exec_python(script, timeout=30):
            captured["script"] = script
            return {"stdout": "", "stderr": "", "exitcode": 0}

        fn = m.reg_set.fn if hasattr(m.reg_set, "fn") else m.reg_set
        with patch.object(m, "_exec_python", fake_exec_python):
            fn(r"HKLM\SOFTWARE\X", "V", "1", value_type)
        return captured["script"]

    def test_shorthand_is_normalized(self):
        script = self._script_for("dword")
        assert 'reg_type_name.strip().upper()' in script
        assert 'reg_type_name = "REG_" + reg_type_name' in script

    def test_unknown_type_lists_the_valid_ones(self):
        script = self._script_for("frobnicate")
        assert "Expected one of" in script


class TestBrokerScriptExecutes:
    """The in-guest broker was checked with ast.parse and substring greps.

    That proves it is syntactically Python and mentions the right words — not
    that it does the right thing. Its sequencing logic is the whole basis of
    the desync fix (a recv that timed out must never be answered by the next
    command's result), and it is pure Python over os.listdir, so it can be
    run here rather than only on a Windows guest.
    """

    def _next_command(self, script_dir):
        """Extract and bind the broker's `next_command` against a real dir."""
        import os

        from winbox.mcp import _BROKER_SCRIPT

        lines = _BROKER_SCRIPT.splitlines()
        start = next(i for i, l in enumerate(lines) if l.startswith("def next_command()"))
        end = next(
            (i for i in range(start + 1, len(lines))
             if lines[i].startswith("def ") or lines[i].startswith("while ")),
            len(lines),
        )
        ns = {"os": os, "script_dir": str(script_dir)}
        exec("\n".join(lines[start:end]), ns)
        return ns["next_command"]

    def test_takes_the_lowest_pending_sequence(self, tmp_path):
        """Out-of-order execution is the desync this protocol prevents."""
        for seq in (7, 2, 5):
            (tmp_path / f"cmd.{seq}.json").write_text("{}")

        assert self._next_command(tmp_path)() == (2, "cmd.2.json")

    def test_returns_none_when_nothing_is_pending(self, tmp_path):
        assert self._next_command(tmp_path)() is None

    def test_ignores_files_that_are_not_commands(self, tmp_path):
        (tmp_path / "result.3.json").write_text("{}")
        (tmp_path / "config.json").write_text("{}")
        (tmp_path / "broker.pid").write_text("123")
        (tmp_path / "cmd.9.json").write_text("{}")

        assert self._next_command(tmp_path)() == (9, "cmd.9.json")

    def test_skips_a_malformed_sequence_rather_than_crashing(self, tmp_path):
        """A half-written or stray name must not take the broker down — it
        would strand the session with no way to close it."""
        (tmp_path / "cmd.notanumber.json").write_text("{}")
        (tmp_path / "cmd..json").write_text("{}")
        (tmp_path / "cmd.4.json").write_text("{}")

        assert self._next_command(tmp_path)() == (4, "cmd.4.json")

    def test_sequences_are_ordered_numerically_not_lexically(self, tmp_path):
        """String ordering would run 10 before 9 and desync the session."""
        for seq in (9, 10, 11):
            (tmp_path / f"cmd.{seq}.json").write_text("{}")

        assert self._next_command(tmp_path)() == (9, "cmd.9.json")

    def test_a_vanished_directory_is_not_fatal(self, tmp_path):
        """pipe_close rmtree's the session dir; the broker may still be in
        its loop and must exit rather than raise."""
        gone = tmp_path / "never-existed"
        assert self._next_command(gone)() is None
