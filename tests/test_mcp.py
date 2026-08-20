"""Tests for winbox MCP server tools."""

from __future__ import annotations

from unittest.mock import MagicMock, patch, PropertyMock

import pytest
from click.testing import CliRunner

from winbox.config import Config
from winbox.vm import VMState
from winbox.vm.guest import ExecResult


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

    def capturing_exec_python(code, timeout=300, args=None):
        ga.captured_code = code
        ga.captured_args_dict = args
        return original_exec_python(code, timeout=timeout, args=args)

    mcp_mod._exec_python = capturing_exec_python

    yield ga, vm, cfg

    mcp_mod._exec_python = original_exec_python
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
        assert "[]" in result
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

        # 4. a fresh recv, answered properly, must get its own answer.
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

        assert "listening on 127.0.0.1:1234" in result
        hmp.assert_called_once_with("winbox", "gdbserver tcp:127.0.0.1:1234")
        # Attach hint is included so the agent knows how to proceed
        assert "target remote :1234" in result

    def test_start_custom_port(self, mock_mcp):
        from winbox.mcp import kdbg_start
        cfg = mock_mcp[2]
        cfg.vm_name = "winbox"

        with patch("winbox.mcp._kdbg_hmp",
                   return_value=self._stub_hmp_start(port=9999)) as hmp, \
             patch("winbox.mcp._kdbg_probe", return_value=False):
            result = kdbg_start(port=9999)

        assert "127.0.0.1:9999" in result
        hmp.assert_called_once_with("winbox", "gdbserver tcp:127.0.0.1:9999")

    def test_start_any_interface_opt_in(self, mock_mcp):
        from winbox.mcp import kdbg_start
        cfg = mock_mcp[2]
        cfg.vm_name = "winbox"

        with patch("winbox.mcp._kdbg_hmp",
                   return_value=self._stub_hmp_start(bind="0.0.0.0")) as hmp, \
             patch("winbox.mcp._kdbg_probe", return_value=False):
            result = kdbg_start(any_interface=True)

        assert "0.0.0.0:1234" in result
        assert "WARNING" in result and "LAN-accessible" in result
        hmp.assert_called_once_with("winbox", "gdbserver tcp:0.0.0.0:1234")

    def test_start_refuses_when_port_already_in_use(self, mock_mcp):
        from winbox.mcp import kdbg_start
        cfg = mock_mcp[2]
        cfg.vm_name = "winbox"

        with patch("winbox.mcp._kdbg_hmp") as hmp, \
             patch("winbox.mcp._kdbg_probe", return_value=True):
            result = kdbg_start()

        assert "already listening" in result
        hmp.assert_not_called()

    def test_start_vm_not_running(self, mock_mcp):
        from winbox.mcp import kdbg_start
        ga, vm, cfg = mock_mcp
        vm.state.return_value = VMState.SHUTOFF

        with patch("winbox.mcp._kdbg_hmp") as hmp:
            result = kdbg_start()

        assert "not running" in result.lower()
        hmp.assert_not_called()

    def test_start_virsh_failure(self, mock_mcp):
        from winbox.mcp import kdbg_start
        cfg = mock_mcp[2]
        cfg.vm_name = "winbox"

        with patch("winbox.mcp._kdbg_hmp",
                   return_value=(1, "", "qemu agent not connected")), \
             patch("winbox.mcp._kdbg_probe", return_value=False):
            result = kdbg_start()

        assert "Failed to start" in result
        assert "qemu agent not connected" in result

    def test_start_unexpected_hmp_response(self, mock_mcp):
        """Unknown responses bail — silent success would mask real errors."""
        from winbox.mcp import kdbg_start
        cfg = mock_mcp[2]
        cfg.vm_name = "winbox"

        with patch("winbox.mcp._kdbg_hmp", return_value=(0, "Unknown command", "")), \
             patch("winbox.mcp._kdbg_probe", return_value=False):
            result = kdbg_start()

        assert "Unexpected HMP response" in result

    def test_stop_sends_gdbserver_none(self, mock_mcp):
        from winbox.mcp import kdbg_stop
        cfg = mock_mcp[2]
        cfg.vm_name = "winbox"

        with patch("winbox.mcp._kdbg_hmp",
                   return_value=(0, "Disabled gdbserver", "")) as hmp:
            result = kdbg_stop()

        assert "gdb stub stopped" in result
        hmp.assert_called_once_with("winbox", "gdbserver none")

    def test_stop_vm_not_running(self, mock_mcp):
        from winbox.mcp import kdbg_stop
        ga, vm, cfg = mock_mcp
        vm.state.return_value = VMState.SHUTOFF

        with patch("winbox.mcp._kdbg_hmp") as hmp:
            result = kdbg_stop()

        assert "not running" in result.lower()
        hmp.assert_not_called()

    def test_stop_virsh_failure(self, mock_mcp):
        from winbox.mcp import kdbg_stop
        cfg = mock_mcp[2]
        cfg.vm_name = "winbox"

        with patch("winbox.mcp._kdbg_hmp", return_value=(1, "", "monitor error")):
            result = kdbg_stop()

        assert "Failed to stop" in result

    def test_status_listening(self, mock_mcp):
        from winbox.mcp import kdbg_status

        with patch("winbox.mcp._kdbg_probe", return_value=True):
            result = kdbg_status()

        assert "listening" in result
        assert "127.0.0.1:1234" in result

    def test_status_not_running(self, mock_mcp):
        from winbox.mcp import kdbg_status

        with patch("winbox.mcp._kdbg_probe", return_value=False):
            result = kdbg_status()

        assert "not running" in result

    def test_status_custom_port(self, mock_mcp):
        from winbox.mcp import kdbg_status

        with patch("winbox.mcp._kdbg_probe", return_value=True) as probe:
            result = kdbg_status(port=4321)

        assert "127.0.0.1:4321" in result
        probe.assert_called_once_with("127.0.0.1", 4321)

    def test_status_vm_not_running(self, mock_mcp):
        from winbox.mcp import kdbg_status
        ga, vm, cfg = mock_mcp
        vm.state.return_value = VMState.SHUTOFF

        with patch("winbox.mcp._kdbg_probe") as probe:
            result = kdbg_status()

        assert "not running" in result.lower()
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

        parsed = _json.loads(result)
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

        parsed = _json.loads(result)
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
        """kdbg_ps uses HMP, not GA — must work while paused (no resume)."""
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
        parsed = _json.loads(result)
        assert parsed[0]["pid"] == 4

    def test_kdbg_read_va_works_when_paused(self, mock_mcp):
        """kdbg_read_va uses HMP page-walks — must work while paused."""
        from winbox.kdbg.walk import ProcessRecord
        from winbox.mcp import kdbg_read_va

        ga, vm, cfg = mock_mcp
        cfg.vm_name = "winbox"
        vm.state.return_value = VMState.PAUSED

        procs = [ProcessRecord(pid=1234, name="target.exe",
                               eprocess=0xffffae00abcdef00,
                               directory_table_base=0x7fa000)]
        payload = b"\xde\xad\xbe\xef"

        with patch("winbox.mcp._kdbg_get_store"), \
             patch("winbox.mcp._kdbg_list_processes", return_value=procs), \
             patch("winbox.mcp._kdbg_read_virt_cr3", return_value=payload):
            result = kdbg_read_va(pid=1234, address="0x7ff600001000", length=4)

        vm.resume.assert_not_called()
        assert result == "deadbeef"


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

    def test_attach_walks_processes_before_fork(self, mock_mcp):
        """_kdbg_list_processes must be called AND _fork_daemon must
        receive a TargetInfo (not a raw int pid)."""
        from winbox.mcp import kdbg_attach
        from winbox.kdbg.debugger.daemon import TargetInfo
        proc = self._fake_proc()
        client = self._client_with(alive=False, info={
            "target_pid": 4584, "target_dtb": "0x4d6bb000",
            "target_name": "notepad.exe", "daemon_pid": 1234,
            "gdbstub_port": 1234,
        })
        fake_store = MagicMock()
        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch("winbox.mcp._kdbg_get_store", return_value=fake_store), \
             patch("winbox.mcp._kdbg_list_processes", return_value=[proc]) as lp, \
             patch("winbox.mcp._fork_daemon", return_value=1234) as ff:
            result = kdbg_attach(4584)

        lp.assert_called_once()
        ff.assert_called_once()
        # fork_daemon must receive a TargetInfo, not an int
        call_args = ff.call_args
        target_arg = call_args[0][1]  # positional: cfg, target
        assert isinstance(target_arg, TargetInfo)
        assert target_arg.pid == 4584
        assert target_arg.dtb == 0x4d6bb000
        assert target_arg.name == "notepad.exe"
        out = _json_mod.loads(result)
        assert out["daemon_pid"] == 1234
        assert out["target"]["pid"] == 4584
        assert out["target"]["name"] == "notepad.exe"

    def test_attach_pid_not_found_without_forking(self, mock_mcp):
        """When the target pid is not in the process list, _fork_daemon
        must NOT be called and the error should be returned."""
        from winbox.mcp import kdbg_attach
        client = self._client_with(alive=False)
        fake_store = MagicMock()
        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch("winbox.mcp._kdbg_get_store", return_value=fake_store), \
             patch("winbox.mcp._kdbg_list_processes", return_value=[]) as lp, \
             patch("winbox.mcp._fork_daemon") as ff:
            result = kdbg_attach(99999)

        lp.assert_called_once()
        ff.assert_not_called()
        assert "error:" in result
        assert "99999" in result
        assert "not found" in result

    def test_attach_refuses_when_session_already_alive(self, mock_mcp):
        from winbox.mcp import kdbg_attach
        client = self._client_with(alive=True)
        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch("winbox.mcp._fork_daemon") as ff:
            result = kdbg_attach(4584)

        ff.assert_not_called()
        assert "another session" in result
        assert "kdbg_detach" in result

    def test_attach_surfaces_daemon_error(self, mock_mcp):
        from winbox.mcp import kdbg_attach
        from winbox.kdbg.debugger.daemon import DaemonError
        proc = self._fake_proc(pid=99999)
        client = self._client_with(alive=False)
        fake_store = MagicMock()
        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch("winbox.mcp._kdbg_get_store", return_value=fake_store), \
             patch("winbox.mcp._kdbg_list_processes", return_value=[proc]), \
             patch("winbox.mcp._fork_daemon", side_effect=DaemonError("gdbstub refused")):
            result = kdbg_attach(99999)
        assert "error: gdbstub refused" in result

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
             patch("winbox.mcp._fork_daemon", return_value=1234), \
             patch("winbox.hvci.status", return_value=hvci_on):
            result = kdbg_attach(4584)
        out = _json_mod.loads(result)
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
             patch("winbox.mcp._fork_daemon", return_value=1234), \
             patch("winbox.hvci.status", return_value=hvci_off):
            result = kdbg_attach(4584)
        out = _json_mod.loads(result)
        assert "warning" not in out

    # ── kdbg_session ────────────────────────────────────────────────────

    def test_session_when_not_attached(self, mock_mcp):
        from winbox.mcp import kdbg_session
        client = self._client_with(alive=False)
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_session()
        assert _json_mod.loads(result) == {"attached": False}

    def test_session_when_attached(self, mock_mcp):
        from winbox.mcp import kdbg_session
        client = self._client_with(alive=True, call_result={
            "target": {"pid": 4584, "dtb": "0x4d6bb000", "name": "notepad.exe"},
            "bps": 1, "halted": True, "uptime_s": 12.3, "daemon_pid": 1234,
        })
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_session()
        out = _json_mod.loads(result)
        assert out["attached"] is True
        assert out["target"]["pid"] == 4584
        assert out["bps"] == 1

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
        out = _json_mod.loads(result)
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
        assert "error: Z0 failed: E22" in result

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

    # ── kdbg_bps / kdbg_rm ─────────────────────────────────────────────

    def test_bps_returns_list(self, mock_mcp):
        from winbox.mcp import kdbg_bps
        client = self._client_with(call_result={
            "bps": [{"id": 0, "va": "0x...", "target": "x", "user_mode": True,
                     "hits": 5, "age_s": 1.2}]
        })
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_bps()
        out = _json_mod.loads(result)
        assert len(out["bps"]) == 1
        assert out["bps"][0]["hits"] == 5

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
        out = _json_mod.loads(result)
        assert out["reason"] == "bp"
        assert out["bp_id"] == 0

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
            out = _json_mod.loads(kdbg_regs())
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
        out = _json_mod.loads(result)
        assert out["length"] == 4

    def test_write_mem_surfaces_error(self, mock_mcp):
        from winbox.mcp import kdbg_write_mem
        from winbox.kdbg.debugger.client import ClientError
        client = self._client_with(call_raises=ClientError("M failed: E22"))
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_write_mem("0x1000", "ff")
        assert "error: M failed: E22" in result

    def test_mem_decode_utf16le(self, mock_mcp):
        from winbox.mcp import kdbg_mem
        # "abc" in UTF-16LE = 61 00 62 00 63 00
        client = self._client_with(call_result={"va": "0x1000", "bytes": "610062006300"})
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_mem("0x1000", length=6, decode="utf-16le")
        out = _json_mod.loads(result)
        assert out["decoded"] == "abc"

    def test_mem_decode_utf8(self, mock_mcp):
        from winbox.mcp import kdbg_mem
        # "hello" in UTF-8 = 68 65 6c 6c 6f
        client = self._client_with(call_result={"va": "0x1000", "bytes": "68656c6c6f"})
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_mem("0x1000", length=5, decode="utf-8")
        out = _json_mod.loads(result)
        assert out["decoded"] == "hello"

    def test_mem_decode_ascii_replaces_control(self, mock_mcp):
        from winbox.mcp import kdbg_mem
        # bytes: 41 42 01 7f 43 (A B ctrl-A DEL C)
        client = self._client_with(call_result={"va": "0x1", "bytes": "41420143"})
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_mem("0x1", length=4, decode="ascii")
        out = _json_mod.loads(result)
        assert out["decoded"] == "AB.C"

    def test_mem_decode_cstr_truncates_at_null(self, mock_mcp):
        from winbox.mcp import kdbg_mem
        # "hello" then null then "tail"
        client = self._client_with(call_result={
            "va": "0x1", "bytes": "68656c6c6f00" + "7461696c"
        })
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_mem("0x1", length=10, decode="cstr")
        out = _json_mod.loads(result)
        assert out["decoded"] == "hello"

    def test_mem_decode_hex_default_no_decode_field(self, mock_mcp):
        from winbox.mcp import kdbg_mem
        client = self._client_with(call_result={"va": "0x1", "bytes": "deadbeef"})
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_mem("0x1", length=4)
        out = _json_mod.loads(result)
        assert "decoded" not in out  # default hex mode keeps raw

    def test_mem_decode_unknown_mode_surfaces_in_decoded(self, mock_mcp):
        from winbox.mcp import kdbg_mem
        client = self._client_with(call_result={"va": "0x1", "bytes": "00"})
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_mem("0x1", length=1, decode="bogus")
        out = _json_mod.loads(result)
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
        out = _json_mod.loads(result)
        assert out["base"] == "0x401000"
        # 90 90 c3 = nop; nop; ret
        mnemonics = [i["mnemonic"] for i in out["instructions"]]
        assert mnemonics[:3] == ["nop", "nop", "ret"]

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
        out = _json_mod.loads(result)
        assert out["instructions"][0]["mnemonic"] == "lea"

    def test_disasm_invalid_addr_returns_error(self, mock_mcp):
        from winbox.mcp import kdbg_disasm
        with patch("winbox.mcp._kdbg_client", return_value=MagicMock()):
            result = kdbg_disasm(addr="not_a_number", count=1)
        assert result.startswith("error:")

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
        parsed = _json.loads(result)
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
        parsed = _json.loads(result)
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
        assert "no kdbg session" in result
        client.call.assert_not_called()

    def test_detach_calls_daemon_and_waits_for_release(self, mock_mcp):
        from winbox.mcp import kdbg_detach
        # Alive on first probe, dead on second (simulates fast daemon shutdown).
        client = MagicMock()
        client.session_alive.side_effect = [True, False]
        client.call.return_value = {"shutting_down": True}
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_detach()
        client.call.assert_called_once_with("detach")
        assert result == "detached"

    # ── kdbg_resume ───────────────────────────────────────────────────

    def test_resume_refuses_when_session_active(self, mock_mcp):
        from winbox.mcp import kdbg_resume
        import winbox.mcp as mcp_mod
        mcp_mod._vm.state.return_value = VMState.PAUSED
        client = self._client_with(alive=True)
        with patch("winbox.mcp._kdbg_client", return_value=client):
            result = kdbg_resume()
        assert "kdbg_detach instead" in result

    def test_resume_errors_when_no_gdbstub(self, mock_mcp):
        from winbox.mcp import kdbg_resume
        import winbox.mcp as mcp_mod
        mcp_mod._vm.state.return_value = VMState.PAUSED
        client = self._client_with(alive=False)
        with patch("winbox.mcp._kdbg_client", return_value=client), \
             patch("winbox.kdbg.hmp.probe_port", return_value=False):
            result = kdbg_resume()
        assert "gdbstub not listening" in result

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
        assert "already running" in result
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
        assert result == "VM resumed"

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
        assert result != "VM resumed"
        assert "paused" in result.lower()


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
