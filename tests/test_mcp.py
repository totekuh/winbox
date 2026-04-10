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
    """Patch MCP server internals so tools run without a real VM."""
    import winbox.mcp as mcp_mod

    ga = MagicMock()
    ga.ping.return_value = True

    vm = MagicMock()
    vm.state.return_value = VMState.RUNNING

    mcp_mod._cfg = cfg
    mcp_mod._vm = vm
    mcp_mod._ga = ga

    yield ga, vm, cfg

    # Reset global state
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
        from winbox.mcp import _exec_python
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=0, stdout="hello\n", stderr="")

        result = _exec_python("print('hello')")

        assert result["exitcode"] == 0
        assert result["stdout"] == "hello\n"

        # Verify script was written to .mcp dir
        script = cfg.shared_dir / ".mcp" / "script.py"
        assert script.exists()
        assert script.read_text() == "print('hello')"

        # Verify GA exec was called with correct path
        ga.exec.assert_called_once()
        call_args = ga.exec.call_args
        assert r"Z:\.mcp\script.py" in call_args[0][0]

    def test_custom_timeout(self, mock_mcp):
        from winbox.mcp import _exec_python
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        _exec_python("pass", timeout=60)
        ga.exec.assert_called_once_with(
            r'python.exe Z:\.mcp\script.py', timeout=60
        )

    def test_returns_stderr(self, mock_mcp):
        from winbox.mcp import _exec_python
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=1, stdout="", stderr="error\n")

        result = _exec_python("bad code")
        assert result["stderr"] == "error\n"
        assert result["exitcode"] == 1


# ─── python tool ────────────────────────────────────────────────────────────


class TestPythonTool:
    def test_success(self, mock_mcp):
        from winbox.mcp import python
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=0, stdout="42\n", stderr="")

        result = python("print(42)")
        assert "42" in result

    def test_stderr_included(self, mock_mcp):
        from winbox.mcp import python
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=1, stdout="", stderr="NameError\n")

        result = python("bad")
        assert "[stderr]" in result
        assert "NameError" in result
        assert "[exit code: 1]" in result

    def test_no_output(self, mock_mcp):
        from winbox.mcp import python
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=0, stdout="", stderr="")

        result = python("pass")
        assert result == "(no output)"


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
        script = (cfg.shared_dir / ".mcp" / "script.py").read_text()
        assert "CreateFileW" in script
        assert "DeviceIoControl" in script
        assert "CloseHandle" in script

        # Verify args.json has the right values
        args = json.loads((cfg.shared_dir / ".mcp" / "args.json").read_text())
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

        script = (cfg.shared_dir / ".mcp" / "script.py").read_text()
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

        script = (cfg.shared_dir / ".mcp" / "script.py").read_text()
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

        script = (cfg.shared_dir / ".mcp" / "script.py").read_text()
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
            type="REG_DWORD",
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
            type="REG_BINARY",
        )
        script = (cfg.shared_dir / ".mcp" / "script.py").read_text()
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

        script = (cfg.shared_dir / ".mcp" / "script.py").read_text()
        assert "'lsass'" in script

    def test_no_filter(self, mock_mcp):
        from winbox.mcp import ps
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(exitcode=0, stdout="[]\n", stderr="")

        ps(filter=None)
        script = (cfg.shared_dir / ".mcp" / "script.py").read_text()
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

        script = (cfg.shared_dir / ".mcp" / "script.py").read_text()
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

        script = (cfg.shared_dir / ".mcp" / "script.py").read_text()
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
        args = json.loads((cfg.shared_dir / ".mcp" / "args.json").read_text())
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
        args = json.loads((cfg.shared_dir / ".mcp" / "args.json").read_text())
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
        script = (cfg.shared_dir / ".mcp" / "script.py").read_text()
        assert "shutil.copy2" in script


# ─── mem_read tool ──────────────────────────────────────────────────────────


class TestMemReadTool:
    def test_read_success(self, mock_mcp):
        from winbox.mcp import mem_read
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0, stdout="4d5a9000\n", stderr=""
        )

        result = mem_read(pid=672, address=0x7FF600000000, size=4)
        assert "4d5a9000" in result

        script = (cfg.shared_dir / ".mcp" / "script.py").read_text()
        assert "ReadProcessMemory" in script
        assert "672" in script

    def test_open_process_failure(self, mock_mcp):
        from winbox.mcp import mem_read
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=1, stdout="", stderr="OpenProcess failed: error 5\n"
        )

        result = mem_read(pid=4, address=0, size=16)
        assert "error 5" in result

    def test_read_failure(self, mock_mcp):
        from winbox.mcp import mem_read
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=1, stdout="", stderr="ReadProcessMemory failed: error 299\n"
        )

        result = mem_read(pid=672, address=0xDEAD, size=4096)
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

        # Should NOT write a script file
        script_path = cfg.shared_dir / ".mcp" / "script.py"
        assert not script_path.exists()


# ─── net_isolate / net_connect tools ─────────────────────────────────────────


class TestNetTools:
    def test_isolate(self, mock_mcp):
        from winbox.mcp import net_isolate
        ga, vm, cfg = mock_mcp
        vm.net_set_link = MagicMock(return_value=True)

        result = net_isolate()
        assert "isolated" in result.lower()
        vm.net_set_link.assert_called_once_with("down")

    def test_connect(self, mock_mcp):
        from winbox.mcp import net_connect
        ga, vm, cfg = mock_mcp
        vm.net_set_link = MagicMock(return_value=True)

        result = net_connect()
        assert "connected" in result.lower()
        vm.net_set_link.assert_called_once_with("up")

    def test_isolate_vm_not_running(self, mock_mcp):
        from winbox.mcp import net_isolate
        ga, vm, cfg = mock_mcp
        vm.state.return_value = VMState.SHUTOFF

        result = net_isolate()
        assert "not running" in result.lower()

    def test_isolate_no_interface(self, mock_mcp):
        from winbox.mcp import net_isolate
        ga, vm, cfg = mock_mcp
        vm.net_set_link = MagicMock(return_value=False)

        result = net_isolate()
        assert "failed" in result.lower()


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
        from winbox.mcp import pipe_list
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0,
            stdout="3 pipe(s):\n  lsass\n  svcctl\n  winreg\n",
            stderr="",
        )

        result = pipe_list()
        assert "lsass" in result
        assert "3 pipe(s)" in result

    def test_pipe_list_with_filter(self, mock_mcp):
        from winbox.mcp import pipe_list
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0,
            stdout="1 pipe(s):\n  lsass\n",
            stderr="",
        )

        result = pipe_list(filter="lsass")
        assert "lsass" in result
        args = (cfg.shared_dir / ".mcp" / "args.json").read_text()
        import json
        assert json.loads(args)["filter"] == "lsass"

    def test_pipe_list_empty(self, mock_mcp):
        from winbox.mcp import pipe_list
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0, stdout="0 pipe(s):\n", stderr=""
        )

        result = pipe_list(filter="nomatch")
        assert "0 pipe(s)" in result

    def test_pipe_info_success(self, mock_mcp):
        from winbox.mcp import pipe_info
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0,
            stdout=(
                "Pipe:       \\\\.\\pipe\\svcctl\n"
                "Mode:       message\n"
                "End:        server\n"
                "OutBuf:     4096 bytes\n"
                "InBuf:      4096 bytes\n"
                "MaxInst:    unlimited\n"
                "SDDL:       O:SYG:SYD:(A;;0x12019b;;;WD)\n"
            ),
            stderr="",
        )

        result = pipe_info(name="svcctl")
        assert "Mode:       message" in result
        assert "SDDL:" in result

        args = (cfg.shared_dir / ".mcp" / "args.json").read_text()
        import json
        assert json.loads(args)["name"] == "svcctl"

    def test_pipe_info_access_denied(self, mock_mcp):
        from winbox.mcp import pipe_info
        ga, vm, cfg = mock_mcp
        ga.exec.return_value = ExecResult(
            exitcode=0,
            stdout="Cannot open pipe (error 5) — trying SDDL via PowerShell only\n(no SDDL)\n",
            stderr="",
        )

        result = pipe_info(name="lsass")
        assert "error 5" in result

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

        args = (cfg.shared_dir / ".mcp" / "args.json").read_text()
        import json
        data = json.loads(args)
        assert data["name"] == "svcctl"
        assert data["access"] == "read"

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
        args = (cfg.shared_dir / ".mcp" / "args.json").read_text()
        import json
        assert json.loads(args)["access"] == "readwrite"
