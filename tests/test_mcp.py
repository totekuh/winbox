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


# ─── net_isolate / net_unplug / net_connect tools ───────────────────────────


class TestNetTools:
    def test_isolate_removes_default_route(self, mock_mcp):
        from winbox.mcp import net_isolate
        ga, vm, cfg = mock_mcp
        vm.net_set_link = MagicMock()

        result = net_isolate()
        assert "isolated" in result.lower()
        # isolate must NOT touch the link — the whole point is to keep
        # Kali <-> VM same-subnet traffic alive
        vm.net_set_link.assert_not_called()
        ga.exec_powershell.assert_called_once()
        script = ga.exec_powershell.call_args[0][0]
        assert "Remove-NetRoute" in script
        assert "0.0.0.0/0" in script

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
        """Undo `net isolate`: link is already up, just re-DHCP."""
        from winbox.mcp import net_connect
        ga, vm, cfg = mock_mcp
        vm.net_link_state = MagicMock(return_value="up")
        vm.net_set_link = MagicMock()
        vm.ip.return_value = "192.168.122.42"

        result = net_connect()
        assert "192.168.122.42" in result
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
        vm.net_link_state = MagicMock(return_value="down")
        vm.net_set_link = MagicMock(return_value=True)
        vm.ip.return_value = "192.168.122.42"

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
        vm.net_link_state = MagicMock(return_value="down")
        vm.net_set_link = MagicMock(return_value=False)

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


def _broker_thread(session_dir, response: dict, *, delay: float = 0.05):
    """Simulate the broker: wait for cmd.json, write result.json."""
    import json
    import threading
    import time as _t

    def _run():
        cmd_file    = session_dir / "cmd.json"
        result_file = session_dir / "result.json"
        deadline = _t.time() + 3
        while _t.time() < deadline:
            if cmd_file.exists():
                cmd_file.unlink()
                _t.sleep(delay)
                result_file.write_text(json.dumps(response))
                return
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
        # No broker thread — result.json never appears; close should still clean up

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
        assert "cmd.json" in _BROKER_SCRIPT
        assert "result.json" in _BROKER_SCRIPT

    def test_broker_script_is_valid_python(self, mock_mcp):
        import ast
        from winbox.mcp import _BROKER_SCRIPT
        ast.parse(_BROKER_SCRIPT)  # raises SyntaxError if invalid


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

    def test_kdbg_ps_auto_resumes_paused_vm(self, mock_mcp):
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

        vm.resume.assert_called_once()
        assert "VM not running" not in result
        parsed = _json.loads(result)
        assert parsed[0]["pid"] == 4

    def test_kdbg_read_va_auto_resumes_paused_vm(self, mock_mcp):
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

        vm.resume.assert_called_once()
        assert "VM not running" not in result
        assert result == "deadbeef"
