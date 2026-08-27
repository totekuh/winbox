"""Live end-to-end suite — drives a real VM through every covered command.

Run explicitly (a bare ``pytest`` deselects these):

    pytest -m integration tests/test_e2e_live.py -v

Runs against whichever image ``~/.winbox/config`` points at, and is written to
pass on any target profile (``server2022``, ``server2025``, ``win11``). Where
they genuinely differ — Tamper Protection, Server Core's missing services, the
Python payload — the test asserts the profile-appropriate behavior (keyed off
``profile.client_sku`` / ``supports_core``, not a hardcoded OS list) rather than
skipping.

``tests/e2e_manifest.py`` lists what must be covered here and
``tests/test_e2e_coverage.py`` enforces it, so a new command cannot quietly
arrive without a decision about how it gets exercised.

State: tests restore what they change. The lifecycle tests that stop the VM
are deliberately last in the file, since pytest runs in definition order.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import timedelta

import pytest
from click.testing import CliRunner

from winbox.cli import cli
from winbox.cli import capture as capture_mod
from winbox.config import Config
from winbox.vm import VM, GuestAgent, VMState

pytestmark = pytest.mark.integration


# ─── fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def cfg() -> Config:
    return Config.load()


@pytest.fixture(scope="session")
def ga(cfg) -> GuestAgent:
    return GuestAgent(cfg)


@pytest.fixture(scope="session")
def vm(cfg) -> VM:
    return VM(cfg)


@pytest.fixture(scope="session", autouse=True)
def running_vm(vm, ga):
    """Guarantee a booted, agent-responsive VM for the whole session."""
    if vm.state() != VMState.RUNNING:
        vm.start()
    ga.wait(timeout=420)
    yield
    # Leave the VM as we found it: up and reachable.
    if vm.state() != VMState.RUNNING:
        vm.start()
        ga.wait(timeout=420)


@pytest.fixture(scope="session")
def profile(cfg):
    """The OS profile the config claims. Asserted against the guest below."""
    return cfg.profile


@pytest.fixture(scope="session")
def guest_product_type(ga) -> int:
    """1 = client (Win11), 2/3 = server. Read from the guest, not the config."""
    result = ga.exec_powershell(
        "(Get-CimInstance Win32_OperatingSystem).ProductType", timeout=60
    )
    return int(result.stdout.strip())


@pytest.fixture(autouse=True)
def guest_is_healthy(vm, ga, request):
    """Fail fast, and clearly, once the guest stops answering.

    A wedged guest turns into twenty near-identical downstream failures whose
    tracebacks all point at whatever command happened to run next, which
    buries the test that actually broke it. Check before each test and say
    plainly that the guest — not this test — is the problem.
    """
    # A deliberately stopped VM is not a wedged one: the lifecycle tests shut
    # it down on purpose and bring it back themselves.
    if vm.state() is VMState.RUNNING and not ga.ping():
        # A busy guest can miss a ping without being dead — give it a grace
        # period before condemning the run, but do not silently recover, or a
        # test that genuinely wedges the guest would go unnoticed.
        try:
            ga.wait(timeout=60)
        except Exception:
            pytest.fail(
                f"guest agent is not responding before {request.node.name} "
                f"(libvirt domstate: {_domstate(vm.name)}). An earlier test "
                f"left the guest unusable; fix that rather than this test. "
                f"Recover with: "
                f"virsh -c qemu:///system destroy {vm.name} && winbox up",
                pytrace=False,
            )
    yield


@pytest.fixture
def run():
    """Invoke a winbox CLI command in-process against the real config."""
    runner = CliRunner()

    def _run(*args, expect_ok: bool = True):
        result = runner.invoke(cli, list(args))
        if expect_ok:
            assert result.exit_code == 0, (
                f"winbox {' '.join(args)} exited {result.exit_code}\n"
                f"{result.output}\n{result.exception!r}"
            )
        return result

    return _run


@pytest.fixture(scope="session")
def tool():
    """Fetch an MCP tool's underlying function by name."""
    import winbox.mcp as mcp_mod

    def _tool(name):
        obj = mcp_mod.__dict__[name]
        return obj.fn if hasattr(obj, "fn") else obj

    return _tool


def _accept_not_halted(result) -> None:
    """Allow a kdbg command to refuse because the target is not halted.

    `stack` and `bt` read the halted CPU context. An attached-but-running
    target has none, so the refusal is correct — but any *other* failure is
    a real one and must not be swallowed.
    """
    if result.exit_code != 0:
        assert "not halted" in result.output, result.output


def _domstate(vm_name: str) -> str:
    return subprocess.run(
        ["virsh", "-c", "qemu:///system", "domstate", vm_name],
        capture_output=True, text=True, check=False,
    ).stdout.strip()


# ─── identity: the config and the guest must agree ──────────────────────────


class TestGuestIdentity:
    def test_config_profile_matches_the_running_guest(
        self, profile, guest_product_type
    ):
        """The whole dual-image split rests on this.

        ``winbox setup --os X`` records VM_OS so every later command resolves
        the same profile as the disk. If those drift, every profile-driven
        decision — virtio subdir, install partition, Python payload, Defender
        handling — is being made for the wrong operating system.
        """
        guest_is_client = guest_product_type == 1
        assert profile.client_sku is guest_is_client, (
            f"config says {profile.key} (client_sku={profile.client_sku}) but "
            f"the guest reports ProductType={guest_product_type}"
        )

    def test_guest_reports_the_expected_windows_family(self, ga, profile):
        result = ga.exec_powershell(
            "(Get-CimInstance Win32_OperatingSystem).Caption", timeout=60
        )
        caption = result.stdout.strip()
        assert caption, "guest did not report an OS caption"
        if profile.key == "win11":
            assert "Windows 11" in caption or "Windows 10" in caption, caption
        else:
            assert "Server" in caption, caption

    def test_guest_agent_runs_as_system(self, ga):
        assert "system" in ga.exec("whoami", timeout=60).stdout.lower()


# ─── exec ───────────────────────────────────────────────────────────────────


class TestExec:
    def test_exec_runs_a_command(self, run):
        assert "e2e-exec-ok" in run("exec", "cmd.exe", "/c", "echo e2e-exec-ok").output

    def test_exec_propagates_a_nonzero_exit(self, ga):
        assert ga.exec("exit /b 7", timeout=60).exitcode == 7

    def test_exec_captures_stderr(self, ga):
        result = ga.exec("nonexistent_command_xyz", timeout=60)
        assert result.exitcode != 0
        assert "not recognized" in result.stderr

    @pytest.mark.parametrize(
        "command,expected",
        [
            ("echo plain", "plain"),
            ("echo a & echo b", "b"),
            ("hostname && ver", "Windows"),
            ('echo "quoted"', "quoted"),
        ],
    )
    def test_shell_metacharacters_survive_the_nonce_wrapper(
        self, ga, command, expected
    ):
        """`exec` prefixes an echo of an identity nonce joined with `&&`.
        That must not disturb the caller's own shell syntax."""
        result = ga.exec(command, timeout=60)
        assert expected in result.stdout

    def test_nonce_never_leaks_into_stdout(self, ga):
        assert "__wbx" not in ga.exec("echo clean", timeout=60).stdout

    def test_powershell_stderr_is_free_of_clixml_progress_noise(self, ga):
        """Defender cmdlets emit progress records that PowerShell serializes
        onto stderr as CLIXML when stderr is redirected."""
        result = ga.exec_powershell("Get-Service WinDefend | Out-Null", timeout=90)
        assert "#< CLIXML" not in result.stderr

    def test_powershell_file_runs_a_script_with_a_quoted_path(self, ga, cfg):
        """Script paths must not traverse cmd.exe — it forwards the guest
        agent's \\" escaping verbatim and PowerShell then sees literal
        quotes in the path."""
        script = cfg.tools_dir / "e2e_probe.ps1"
        script.write_text("Write-Host e2e-psfile-ok\n")
        try:
            result = ga.exec_powershell_file(r"Z:\tools\e2e_probe.ps1", timeout=120)
            assert result.exitcode == 0, result.stderr
            assert "e2e-psfile-ok" in result.stdout
        finally:
            script.unlink(missing_ok=True)

    def test_a_timed_out_command_raises_the_timeout_type(self, ga):
        """The type is what tells callers the command already ran — matching
        on "timed out" also matched libvirt's own pre-launch failures."""
        from winbox.vm import GuestAgentUnreachable, GuestExecTimeout

        with pytest.raises(GuestExecTimeout) as excinfo:
            ga.exec("ping -n 30 127.0.0.1", timeout=3, poll_interval=0.5)

        assert excinfo.value.pid is not None
        assert not isinstance(excinfo.value, GuestAgentUnreachable)

    def test_the_guest_is_still_usable_after_a_timeout(self, ga):
        """The timed-out tree is killed and reaped, so the next command must
        get its own output rather than the dead one's."""
        from winbox.vm import GuestExecTimeout

        with pytest.raises(GuestExecTimeout):
            ga.exec("ping -n 30 127.0.0.1", timeout=3, poll_interval=0.5)

        assert ga.exec("echo after-timeout", timeout=60).stdout.strip() == "after-timeout"

    def test_status_reports_a_running_vm(self, run):
        out = run("status").output
        assert "running" in out
        assert "responding" in out

    def test_channel_reads_connected_on_a_live_vm(self, vm, ga):
        """The authoritative readiness signal agrees with a real round-trip."""
        assert vm.agent_connected() is True
        assert ga.ping() is True


class TestCredentialedExec:
    USER = "_winbox_e2e_user"
    PASSWORD = "WbxE2E!&26"

    @pytest.fixture(autouse=True)
    def disposable_user(self, ga):
        # Direct argv keeps the metacharacter-bearing password out of cmd.exe.
        ga.exec_argv("net.exe", ["user", self.USER, "/delete"], timeout=30)
        created = ga.exec_argv(
            "net.exe", ["user", self.USER, self.PASSWORD, "/add"], timeout=30,
        )
        assert created.exitcode == 0, created.stderr
        try:
            yield
        finally:
            ga.exec_argv("net.exe", ["user", self.USER, "/delete"], timeout=30)

    def test_runex_is_installed(self, ga):
        result = ga.exec(r"if exist C:\Tools\RunEx.exe (exit /b 0) else (exit /b 1)")
        assert result.exitcode == 0

    def test_cli_exec_runs_as_local_user(self, run):
        result = run(
            "exec", "--user", self.USER, "--password", self.PASSWORD,
            "whoami.exe",
        )
        assert f"winbox\\{self.USER}" in result.output.lower()

    def test_mcp_exec_python_and_powershell_run_as_local_user(self, tool):
        expected = f"winbox\\{self.USER}".lower()

        cmd_result = json.loads(tool("exec")(
            "whoami", user=self.USER, password=self.PASSWORD,
        ))
        py_result = json.loads(tool("python")(
            "import subprocess; print(subprocess.check_output(['whoami'], text=True).strip())",
            user=self.USER, password=self.PASSWORD,
        ))
        ps_result = json.loads(tool("powershell")(
            "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name",
            user=self.USER, password=self.PASSWORD,
        ))

        for result in (cmd_result, py_result, ps_result):
            assert result["exitcode"] == 0, result
            assert expected in result["stdout"].lower()

    def test_mcp_background_handlers_run_as_qualified_local_user(self, tool):
        expected = f"winbox\\{self.USER}".lower()
        qualified = f"WINBOX\\{self.USER}"
        launches = (
            tool("exec")(
                "whoami", background=True,
                user=qualified, password=self.PASSWORD,
            ),
            tool("python")(
                "import subprocess; print(subprocess.check_output(['whoami'], text=True).strip())",
                background=True, user=qualified, password=self.PASSWORD,
            ),
            tool("powershell")(
                "[Security.Principal.WindowsIdentity]::GetCurrent().Name",
                background=True, user=qualified, password=self.PASSWORD,
            ),
        )

        for raw_launch in launches:
            launch = json.loads(raw_launch)
            assert launch["background"] is True, launch
            result = None
            for _ in range(30):
                result = json.loads(tool("job_result")(launch["job_id"]))
                if not result.get("running"):
                    break
                time.sleep(0.25)
            assert result and result.get("running") is False, result
            assert result["exitcode"] == 0, result
            assert expected in result["stdout"].lower(), result

    def test_real_mcp_stdio_server_runs_as_local_user(self):
        """Cross the real stdio transport, not the direct tool-function shim."""
        import anyio
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        expected = f"winbox\\{self.USER}".lower()

        async def exercise_server():
            server = StdioServerParameters(
                command=sys.executable,
                args=["-m", "winbox", "mcp"],
                cwd=os.getcwd(),
                env=os.environ.copy(),
            )
            async with stdio_client(server) as (read_stream, write_stream):
                async with ClientSession(
                    read_stream,
                    write_stream,
                    read_timeout_seconds=timedelta(seconds=120),
                ) as session:
                    await session.initialize()
                    calls = (
                        (
                            "exec",
                            {
                                "command": "whoami",
                                "timeout": 60,
                                "user": self.USER,
                                "password": self.PASSWORD,
                            },
                        ),
                        (
                            "python",
                            {
                                "code": (
                                    "import subprocess; "
                                    "print(subprocess.check_output(["
                                    "'whoami'], text=True).strip())"
                                ),
                                "timeout": 60,
                                "user": self.USER,
                                "password": self.PASSWORD,
                            },
                        ),
                        (
                            "powershell",
                            {
                                "script": (
                                    "[System.Security.Principal.WindowsIdentity]"
                                    "::GetCurrent().Name"
                                ),
                                "timeout": 60,
                                "user": self.USER,
                                "password": self.PASSWORD,
                            },
                        ),
                    )
                    results = []
                    for name, arguments in calls:
                        response = await session.call_tool(name, arguments)
                        assert not response.isError, response
                        assert len(response.content) == 1, response
                        results.append(json.loads(response.content[0].text))
                    return results

        for result in anyio.run(exercise_server):
            assert result["exitcode"] == 0, result
            assert expected in result["stdout"].lower()

    def test_real_mcp_stdio_background_runs_as_qualified_local_user(self):
        """Exercise credentialed background jobs through real MCP framing."""
        import anyio
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        expected = f"winbox\\{self.USER}".lower()
        qualified = f"WINBOX\\{self.USER}"

        async def exercise_server():
            server = StdioServerParameters(
                command=sys.executable,
                args=["-m", "winbox", "mcp"],
                cwd=os.getcwd(),
                env=os.environ.copy(),
            )
            async with stdio_client(server) as (read_stream, write_stream):
                async with ClientSession(
                    read_stream,
                    write_stream,
                    read_timeout_seconds=timedelta(seconds=120),
                ) as session:
                    await session.initialize()
                    calls = (
                        ("exec", {"command": "whoami"}),
                        ("python", {"code": (
                            "import subprocess; print(subprocess.check_output("
                            "['whoami'], text=True).strip())"
                        )}),
                        ("powershell", {"script": (
                            "[Security.Principal.WindowsIdentity]"
                            "::GetCurrent().Name"
                        )}),
                    )
                    results = []
                    for name, arguments in calls:
                        response = await session.call_tool(name, {
                            **arguments,
                            "background": True,
                            "user": qualified,
                            "password": self.PASSWORD,
                        })
                        assert not response.isError, response
                        launch = json.loads(response.content[0].text)
                        assert launch["background"] is True, launch

                        result = None
                        for _ in range(30):
                            polled = await session.call_tool(
                                "job_result", {"job_id": launch["job_id"]},
                            )
                            assert not polled.isError, polled
                            result = json.loads(polled.content[0].text)
                            if not result.get("running"):
                                break
                            await anyio.sleep(0.25)
                        results.append(result)
                    return results

        for result in anyio.run(exercise_server):
            assert result and result.get("running") is False, result
            assert result["exitcode"] == 0, result
            assert expected in result["stdout"].lower(), result


# ─── files ──────────────────────────────────────────────────────────────────


class TestFiles:
    def test_tools_add_list_remove_round_trip(self, run, tmp_path):
        payload = tmp_path / "e2e_tool.txt"
        payload.write_text("marker")

        run("tools", "add", str(payload))
        assert "e2e_tool.txt" in run("tools", "list").output
        run("tools", "remove", "e2e_tool.txt")
        assert "e2e_tool.txt" not in run("tools", "list").output

    def test_upload_places_a_file_in_the_guest(self, run, ga, tmp_path):
        src = tmp_path / "e2e_upload.txt"
        src.write_text("uploaded-marker")

        run("upload", str(src), r"C:\Windows\Temp\e2e_upload.txt")

        got = ga.exec(r"type C:\Windows\Temp\e2e_upload.txt", timeout=60)
        assert "uploaded-marker" in got.stdout

    def test_iso_status_finds_the_profile_iso(self, run, cfg):
        out = run("iso", "status").output
        assert cfg.profile.iso_filename in out

    def test_msi_rejects_a_missing_package(self, run):
        result = run("msi", "/nonexistent/definitely-not-here.msi", expect_ok=False)
        assert result.exit_code != 0

    def test_mcp_upload_and_file_copy(self, tool, ga):
        assert "Uploaded" in tool("upload")("/etc/hostname", r"C:\Windows\Temp\e2e_h.txt")

        out = tool("file_copy")(
            r"C:\Windows\System32\cmd.exe", r"C:\Windows\Temp\e2e_cmd.exe"
        )
        assert "Copied" in out, out
        assert "EXISTS" in ga.exec(
            r'if exist C:\Windows\Temp\e2e_cmd.exe (echo EXISTS)', timeout=60
        ).stdout

    def test_file_copy_reports_a_missing_source(self, tool):
        out = tool("file_copy")(r"C:\nope\missing.bin", r"C:\Windows\Temp\x.bin")
        assert "exit code" in out
        # A bare "[exit code: 1]" with empty streams is indistinguishable from
        # a tool that had nothing to say.
        assert out.strip() != "[exit code: 1]"


# ─── registry, processes, memory, services ──────────────────────────────────


class TestMcpCore:
    def test_python_runs_in_the_guest(self, tool):
        out = json.loads(tool("python")("print(6*7)"))
        assert out["exitcode"] == 0
        assert "42" in out["stdout"]

    def test_python_reports_a_traceback(self, tool):
        out = json.loads(tool("python")("raise ValueError('boom')"))
        assert out["exitcode"] != 0
        assert "ValueError" in out["stderr"]

    def test_guest_python_is_installed(self, tool):
        """provision.ps1 treats a failed Python install as non-fatal, so the
        only thing standing between a broken build and a green one is a check
        like this."""
        out = json.loads(tool("python")("import sys; print(sys.version)"))
        assert out["exitcode"] == 0, out
        assert "3." in out["stdout"]

    def test_powershell_runs_in_the_guest(self, tool):
        out = json.loads(tool("powershell")("Write-Output (6*7)"))
        assert out["exitcode"] == 0, out
        assert "42" in out["stdout"]

    def test_powershell_propagates_a_nonzero_exit(self, tool):
        out = json.loads(tool("powershell")("exit 3"))
        assert out["exitcode"] == 3, out

    def test_powershell_stderr_is_free_of_clixml_progress(self, tool):
        """The encoded path silences $ProgressPreference and strips any CLIXML
        progress document — a cmdlet that reports progress must not leave XML
        masquerading as an error on stderr."""
        out = json.loads(tool("powershell")("Get-Service WinDefend | Out-Null"))
        assert out["exitcode"] == 0, out
        assert "CLIXML" not in out["stderr"]

    def test_powershell_handles_backslash_paths_without_escaping(self, tool):
        """The whole point of the tool: Windows paths survive verbatim, with
        none of the nested backslash-doubling the python-subprocess route needs."""
        out = json.loads(tool("powershell")(r"Test-Path C:\Windows\System32\cmd.exe"))
        assert out["exitcode"] == 0, out
        assert "True" in out["stdout"]

    def test_exec_runs_a_command_line(self, tool):
        out = json.loads(tool("exec")("echo hello-exec"))
        assert out["exitcode"] == 0, out
        assert "hello-exec" in out["stdout"]

    def _await_job(self, tool, job_id, tries=20):
        out = None
        for _ in range(tries):
            out = json.loads(tool("job_result")(job_id))
            if not out.get("running"):
                return out
            time.sleep(0.5)
        return out

    def test_exec_background_launch_and_result(self, tool):
        launch = json.loads(tool("exec")("echo bg-exec", background=True))
        assert launch["background"] is True
        out = self._await_job(tool, launch["job_id"])
        assert out and out["running"] is False, out
        assert out["exitcode"] == 0
        assert "bg-exec" in out["stdout"]

    def test_powershell_background_launch_and_result(self, tool):
        launch = json.loads(tool("powershell")(
            "Start-Sleep -Milliseconds 300; Write-Output ps-bg-done", background=True
        ))
        assert launch["background"] is True
        out = self._await_job(tool, launch["job_id"])
        assert out and out["running"] is False, out
        assert out["exitcode"] == 0
        assert "ps-bg-done" in out["stdout"]

    def test_python_background_launch_and_result(self, tool):
        launch = json.loads(tool("python")(
            "import time; time.sleep(0.3); print('py-bg-done')", background=True
        ))
        out = self._await_job(tool, launch["job_id"])
        assert out and out["running"] is False, out
        assert "py-bg-done" in out["stdout"]

    def test_job_result_reports_unknown_job(self, tool):
        out = json.loads(tool("job_result")(999999))
        assert "not found" in out["error"]

    def test_ps_lists_processes(self, tool):
        procs = json.loads(tool("ps")("lsass"))
        assert any(p["name"].lower() == "lsass.exe" for p in procs)

    def test_reg_round_trip(self, tool):
        key = r"HKLM\SOFTWARE\WinboxE2E"
        try:
            assert "Set" in tool("reg_set")(key, "Probe", "4919", "REG_DWORD")
            assert "4919" in tool("reg_query")(key, "Probe")
            tool("reg_delete")(key, "Probe")
            assert "Not found" in tool("reg_query")(key, "Probe")
        finally:
            tool("reg_delete")(key)

    def test_reg_set_accepts_a_type_shorthand(self, tool):
        key = r"HKLM\SOFTWARE\WinboxE2E"
        try:
            assert "REG_DWORD" in tool("reg_set")(key, "P2", "1", "dword")
        finally:
            tool("reg_delete")(key)

    def test_reg_set_rejects_an_unknown_type_with_the_valid_list(self, tool):
        out = tool("reg_set")(r"HKLM\SOFTWARE\WinboxE2E", "P", "1", "frobnicate")
        assert "Expected one of" in out

    def test_reg_delete_reports_a_missing_key(self, tool):
        assert "not found" in tool("reg_query")(r"HKLM\SOFTWARE\NoSuchWinboxKey").lower()

    def test_mem_read_returns_hex_for_a_live_process(self, tool):
        pid = json.loads(tool("ps")("winlogon"))[0]["pid"]
        out = tool("mem_read")(pid, "0x7FFE0000", 32)
        assert len(out.strip()) == 64, out
        int(out.strip(), 16)  # must be valid hex

    def test_mem_read_reports_a_bad_address(self, tool):
        pid = json.loads(tool("ps")("winlogon"))[0]["pid"]
        assert "exit code" in tool("mem_read")(pid, "0x1", 16)

    def test_ioctl_reports_a_missing_device(self, tool):
        out = tool("ioctl")(r"\\.\NoSuchWinboxDevice", "0x222000", "")
        assert "CreateFileW failed" in out

    def test_service_stop_and_start_round_trip(self, tool, ga):
        """Server Core has a smaller service set than a client image, so pick
        a service that is actually present rather than assuming one."""
        candidates = ["Winmgmt", "EventLog", "Schedule", "Dnscache"]
        name = next(
            (c for c in candidates
             if "RUNNING" in ga.exec(f"sc.exe query {c}", timeout=60).stdout),
            None,
        )
        assert name, "no expected service was running in the guest"

        # `... or True` made this unfailable. Stopping a service the suite
        # depends on (Winmgmt backs the WMI calls) is not an option, so
        # exercise service_stop against a name that cannot exist and assert
        # it reports the service is unknown rather than claiming success.
        stopped = tool("service_stop")("NoSuchWinboxSvc")
        assert "1060" in stopped, stopped
        out = tool("service_start")(name)
        assert "1056" in out or "SUCCESS" in out.upper() or "START_PENDING" in out, out

    def test_service_start_reports_an_unknown_service(self, tool):
        assert "1060" in tool("service_start")("NoSuchWinboxSvc")

    def test_eventlogs_returns_records(self, tool):
        out = tool("eventlogs")("System")
        assert "TimeCreated" in out or out.strip() in ("[]", "(no output)")

    def test_eventlogs_clear_refuses_without_confirmation(self, tool):
        """Clearing is unrecoverable, so the default must be a no-op — an
        agent should not be able to wipe logs by guessing at arguments."""
        out = tool("eventlogs_clear")(["Application"])
        assert "confirm=True" in out
        assert "refusing" in out.lower()

    def test_eventlogs_clear_runs_with_confirmation(self, tool):
        out = tool("eventlogs_clear")(["Application"], confirm=True)
        result = json.loads(out)
        assert result["total"] == 1
        assert result["cleared"] == 1, result


# ─── named-pipe broker ──────────────────────────────────────────────────────


class TestMcpPipes:
    def test_pipe_list_includes_a_well_known_pipe(self, tool):
        pipes = json.loads(tool("pipe_list")())
        assert "lsass" in pipes or "eventlog" in pipes

    def test_pipe_info_describes_a_pipe(self, tool):
        info = json.loads(tool("pipe_info")("lsass"))
        assert info["pipe"].endswith("lsass")
        assert "sddl" in info

    def test_pipe_connect_opens_and_closes(self, tool):
        assert "OK" in tool("pipe_connect")("lsass")

    def test_pipe_session_lifecycle(self, tool):
        sid = tool("pipe_open")("lsass").strip()
        assert sid and "error" not in sid.lower()

        assert "wrote" in tool("pipe_send")(sid, "0500")
        tool("pipe_recv")(sid, 16)  # may legitimately time out
        # "closed" alone was satisfied by the broker-leak case too — the very
        # bug this covers. Require the session id, and that nothing reports
        # the broker had to be killed.
        closed = tool("pipe_close")(sid)
        assert f"closed session {sid}" in closed, closed
        assert "could not" not in closed.lower(), closed

        # Everything after a close must fail cleanly, not raise.
        assert "not found" in tool("pipe_close")(sid)
        assert "not found" in tool("pipe_recv")(sid, 16)

    def test_pipe_info_reports_a_missing_pipe(self, tool):
        out = tool("pipe_info")("no_such_winbox_pipe")
        assert "error" in out.lower() or "failed" in out.lower()


# ─── network ────────────────────────────────────────────────────────────────


class TestNetwork:
    def test_isolate_blocks_the_internet_but_keeps_the_agent(self, run, ga):
        run("net", "isolate")
        try:
            assert "isolated" in run("net", "status").output
            ping = ga.exec("ping -n 2 8.8.8.8", timeout=90)
            assert "Received = 0" in ping.stdout or ping.exitcode != 0
            # The host channel must survive isolation.
            assert "alive" in ga.exec("echo alive", timeout=60).stdout
        finally:
            run("net", "connect")

    def test_isolate_is_idempotent(self, run):
        """setup leaves the VM isolated, so re-isolating is the common case.
        It used to fail: libvirt refuses to undefine a filter that is in use,
        and the redefine path treated that as fatal."""
        run("net", "isolate")
        try:
            second = run("net", "isolate")
            assert "Already isolated" in second.output
            run("net", "isolate")  # and a third time
        finally:
            run("net", "connect")

    def test_connect_is_idempotent(self, run):
        run("net", "connect")
        run("net", "connect")
        assert "reachable" in run("net", "status").output

    def test_unplug_then_replug(self, run, ga):
        run("net", "unplug")
        try:
            assert "down" in run("net", "status").output.lower()
        finally:
            run("net", "connect")
        # Leave the NIC genuinely back, not merely re-attached: the next test
        # runs `gpupdate /force`, which blocks for minutes on a settling NIC.
        assert "up" in run("net", "status").output.lower()
        assert "replugged" in ga.exec("echo replugged", timeout=90).stdout

    def test_mcp_net_isolate_and_connect(self, tool):
        try:
            assert "isolat" in tool("net_isolate")().lower()
        finally:
            assert "connect" in tool("net_connect")().lower()

    def test_mcp_net_unplug(self, tool, run, ga):
        try:
            tool("net_unplug")()
        finally:
            tool("net_connect")()
        assert "up" in run("net", "status").output.lower()
        assert "replugged" in ga.exec("echo replugged", timeout=90).stdout

    def test_dns_set_and_sync(self, run):
        run("dns", "set", "1.1.1.1")
        assert "1.1.1.1" in run("dns", "view").output
        run("dns", "sync")
        assert "1.1.1.1" not in run("dns", "view").output.split("VM:")[-1]

    def test_hosts_add_view_delete(self, run):
        run("hosts", "add", "10.9.9.9", "e2e.local")
        try:
            assert "e2e.local" in run("hosts", "view").output
        finally:
            out = run("hosts", "delete", "e2e.local").output
            assert "Removed" in out
        assert "e2e.local" not in run("hosts", "view").output

    def test_hosts_set_replaces_an_entry(self, run):
        run("hosts", "set", "10.9.9.9", "e2e2.local")
        try:
            run("hosts", "set", "10.9.9.10", "e2e2.local")
            view = run("hosts", "view").output
            assert "10.9.9.10" in view
            assert "10.9.9.9" not in view
        finally:
            run("hosts", "delete", "e2e2.local")

    def test_hosts_delete_says_so_when_nothing_matched(self, run):
        out = run("hosts", "delete", "never-added.local").output
        assert "nothing to remove" in out


# ─── target hardening toggles ───────────────────────────────────────────────


class TestTargetToggles:
    def test_applocker_enable_status_disable(self, run):
        try:
            run("applocker", "enable")
            assert "AppLocker" in run("applocker", "status").output
        finally:
            run("applocker", "disable")
            assert "off" in run("applocker", "status").output

    def test_autologin_enable_reports_fully_configured(self, run):
        run("autologin", "enable")
        try:
            out = run("autologin", "status").output
            assert "AutoAdminLogon" in out
            assert "DefaultPassword set:            True" in out
        finally:
            run("autologin", "disable")

    def test_autologin_disable_clears_it(self, run):
        run("autologin", "enable")
        run("autologin", "disable")
        assert "off" in run("autologin", "status").output.lower()

    def test_binfmt_status_runs(self, run):
        run("binfmt", "status")


class TestDefender:
    """Defender is the sharpest profile difference: Win11 client ships with
    Tamper Protection on, Server 2022 has none."""

    def test_status_reports_tamper_protection_state(self, run):
        out = run("av", "status").output
        assert "Defender:" in out

    def test_tamper_protection_is_off_on_server(self, tool, profile):
        if profile.client_sku:
            pytest.skip("Win11 client: TP state depends on the offline hive edit")
        out = tool("av_status")()
        assert "TamperProtection: False" in out or "service stopped" in out

    def test_enable_then_exec_still_works(self, run, ga, tool, profile):
        """Defender flags the guest agent's encoded PowerShell unless the
        QEMU-GA and Z:\\ exclusions land before protections come up.

        On Win11 the services were disabled offline in the SYSTEM hive, and
        WdFilter is a boot-start driver — so `av enable` restores the start
        types and brings up what it can, but real-time protection only fully
        re-arms after a reboot. Either way it must not still read as off, and
        exec must keep working.
        """
        original = tool("av_status")()
        run("av", "enable")
        try:
            assert "exec-under-defender" in ga.exec(
                "echo exec-under-defender", timeout=90
            ).stdout

            status = tool("av_status")()
            assert "service stopped" not in status, status
            if not profile.client_sku:
                assert "Defender: ON" in status, status
        finally:
            if "Defender: ON" not in original:
                undo = run("av", "disable", expect_ok=False)
                if undo.exit_code != 0:
                    # Enabling Defender on Win11 re-arms Tamper Protection,
                    # which then blocks disabling it from the running OS. The
                    # refusal is the correct behavior, so only accept it when
                    # that is genuinely the reason.
                    assert profile.client_sku, undo.output
                    assert "Tamper Protection is ON" in undo.output, undo.output

    def test_disable_never_falsely_reports_success(self, run, tool, profile):
        """On Win11 client, Tamper Protection silently ignores the GP keys.

        The honest outcome is a refusal, not a cheerful message about a
        Defender that is still running.
        """
        result = run("av", "disable", expect_ok=False)
        status = tool("av_status")()
        claimed_success = "Defender disabled" in result.output

        if claimed_success:
            assert "Defender: ON" not in status, (
                "av disable reported success but Defender is still on:\n" + status
            )
        else:
            assert "Tamper" in result.output or "tamper" in result.output.lower(), (
                "av disable failed for a reason it did not explain:\n"
                + result.output
            )

    def test_enable_never_claims_start_types_it_did_not_write(self, ga, profile):
        """`Services\\*\\Start` is ACL-protected. enable() used to write those
        four values, discard every exit code, and report a restore that never
        happened — sending the caller into a reboot loop that could not help."""
        from winbox import defender

        unwritten = defender.start_types_unwritten(ga)

        # Whatever it reports must match what the guest actually holds.
        for svc in defender._DEFENDER_DEFAULT_START:
            want = defender._DEFENDER_DEFAULT_START[svc]
            result = ga.exec_argv(
                "reg.exe",
                ["query", rf"HKLM\SYSTEM\CurrentControlSet\Services\{svc}",
                 "/v", "Start"],
                timeout=30,
            )
            import re as _re
            match = _re.search(r"Start\s+REG_DWORD\s+0x([0-9a-fA-F]+)", result.stdout or "")
            actually_right = (
                result.exitcode == 0 and match is not None
                and int(match.group(1), 16) == want
            )
            assert (svc in unwritten) is not actually_right, (
                f"{svc}: reported unwritten={svc in unwritten} but the guest "
                f"says correct={actually_right}"
            )

    def test_av_status_stderr_is_clean(self, tool):
        assert "#< CLIXML" not in tool("av_status")()

    def test_mcp_av_enable(self, tool, ga, profile):
        """The MCP mirror of `av enable` — a separate wrapper over the same
        shared defender module."""
        original = tool("av_status")()
        out = tool("av_enable")()
        try:
            if "error" in out.lower():
                # On a client SKU this tool legitimately cannot finish:
                # Defender's Services\*\Start values are ACL-protected, so an
                # offline disable can only be undone by the host CLI, which
                # powers the VM down. Refusing and naming that remedy is the
                # correct outcome — what must never happen is a false success.
                assert profile.client_sku, out
                assert "winbox av enable" in out, out
            assert "alive" in ga.exec("echo alive", timeout=90).stdout
        finally:
            if "Defender: ON" not in original:
                from click.testing import CliRunner

                CliRunner().invoke(cli, ["av", "disable"])


class TestHvci:
    """HVCI / VBS detection and toggle."""

    def test_hvci_status(self, run, tool):
        """CLI and MCP status both succeed and report a consistent view."""
        out = run("hvci", "status").output
        assert "VBS:" in out
        assert "HVCI:" in out

        mcp_out = tool("hvci_status")()
        assert '"hvci":' in mcp_out

    def test_hvci_disable_then_enable(self, run, tool):
        """Full cycle: disable then restore."""
        run("hvci", "disable")
        status = run("hvci", "status").output
        # After disable, HVCI should be off (or at least the attempt was made)
        assert "off" in status.lower() or "disabled" in status.lower()

        run("hvci", "enable")
        status = run("hvci", "status").output
        # Re-enable may or may not activate without Secure Boot
        assert "VBS:" in status


class TestMalwareAnalysis:
    """capture/sinkhole/detonate. `capture start` needs root for tcpdump, so
    it is not exercised here — see tests/test_capture.py."""

    def test_capture_status_and_stop_without_a_running_capture(self, run):
        status = run("capture", "status").output
        assert "Capture:" in status
        stopped = run("capture", "stop", expect_ok=False)
        assert stopped.exit_code != 0
        assert "No capture running" in stopped.output

    def test_capture_start_captures_real_traffic(self, run, ga, cfg):
        """dumpcap needs no root when Kali's Wireshark package granted it
        cap_net_raw for the wireshark group (see capture.py's docstring).
        Skip rather than fail on a host where that isn't true and there's
        no root either -- that gap is exactly what the command itself
        reports, not something this test should paper over."""
        result = run("capture", "start", expect_ok=False)
        if result.exit_code != 0:
            pytest.skip(f"capture start unavailable on this host:\n{result.output}")
        try:
            ga.exec("ping -n 2 192.168.122.1", timeout=30)
        finally:
            # Read the pidfile before `stop` deletes it, so the pcap path
            # comes from the module's own bookkeeping, not a text-parsed
            # (and possibly line-wrapped) CLI message.
            state = capture_mod.read_pidfile(cfg)
            run("capture", "stop")
        assert state is not None
        _, pcap = state
        assert pcap.exists() and pcap.stat().st_size > 0

    def test_sinkhole_start_status_log_stop_on_an_unprivileged_port(self, run):
        """The default :53 bind needs root (like capture start), so this
        exercises the same documented low-privilege path instead."""
        run("sinkhole", "start", "--port", "5353")
        try:
            assert "running" in run("sinkhole", "status").output.lower()
            run("sinkhole", "log")
        finally:
            run("sinkhole", "stop")
        assert "stopped" in run("sinkhole", "status").output.lower()

    def test_sinkhole_inetsim(self, run):
        """Accept either outcome — INETSim may or may not be installed on
        whatever host runs this suite; only a wrong claim is a bug."""
        out = run("sinkhole", "inetsim", expect_ok=False).output
        assert "Config written" in out or "not installed" in out

    def test_detonate_check_reports_safe_when_isolated(self, run):
        run("net", "isolate")
        try:
            result = run("detonate", "check")
            assert "Safe to detonate" in result.output
        finally:
            run("net", "connect")


class TestEventLogsCli:
    """The CLI query/clear paths, distinct from the MCP tools above."""

    def test_query_returns_records(self, run):
        result = run("eventlogs", "--log", "System", "--since", "7d", "--max", "5")
        assert result.exit_code == 0

    def test_json_output_parses(self, run):
        result = run(
            "eventlogs", "--log", "System", "--since", "7d", "--max", "3", "--json"
        )
        # The progress line ("[*] Querying ...") shares the runner's captured
        # output, so find the array by its own line rather than the first "[".
        lines = result.output.splitlines()
        start = next(i for i, line in enumerate(lines) if line.strip() == "[")
        end = max(i for i, line in enumerate(lines) if line.strip() == "]")
        payload = json.loads("\n".join(lines[start:end + 1]))
        assert isinstance(payload, list)

    def test_clear_requires_confirmation_or_yes(self, run):
        result = run("eventlogs", "clear", "--log", "Application", "-y")
        assert result.exit_code == 0


# ─── jobs ───────────────────────────────────────────────────────────────────


class TestJobs:
    def test_background_job_lifecycle(self, run, ga):
        """Covers jobs list / output / kill, and the reap discipline: a killed
        job's buffered result must not be left in the agent to collide with a
        later command that lands on the recycled PID."""
        result = run("exec", "--bg", "cmd.exe", "/c", "ping -n 20 127.0.0.1")
        assert "job" in result.output.lower()

        listing = run("jobs", "list").output
        assert "running" in listing.lower() or "done" in listing.lower()

        job_id = None
        for line in listing.splitlines():
            parts = [p.strip() for p in line.split("│") if p.strip()]
            if parts and parts[0].isdigit():
                job_id = parts[0]
        assert job_id, listing

        run("jobs", "kill", job_id)
        run("jobs", "output", job_id, expect_ok=False)

        # The guest must still answer correctly right after the kill.
        assert "post-kill-ok" in ga.exec("echo post-kill-ok", timeout=60).stdout

    def test_exec_is_not_contaminated_by_prior_output(self, ga):
        """Rapid-fire distinct commands; each must get its own result.

        A recycled PID carrying an abandoned result used to hand one command
        another's stdout and exit code.
        """
        for i in range(12):
            marker = f"marker-{i}"
            result = ga.exec(f"echo {marker}", timeout=60)
            assert result.stdout.strip() == marker, (
                f"expected {marker!r}, got {result.stdout!r}"
            )
            assert result.exitcode == 0


# ─── kdbg ───────────────────────────────────────────────────────────────────


class TestKdbg:
    @staticmethod
    def _result(tool, name, *args, **kwargs):
        """Unwrap and validate the common structured KDBG MCP envelope."""
        response = tool(name)(*args, **kwargs)
        assert response["schema"] == "winbox.mcp/1", response
        assert response["ok"] is True, response
        assert response["error"] is None, response
        return response["result"]

    @staticmethod
    def _target_pid(tool, module="winlogon.exe"):
        """A PID to attach to. Nothing more.

        This used to also force `kdbg_base_refresh` and a full
        `kdbg_user_symbols_load` first, because ASLR moves every base on each
        boot while the symbol store survives — so a post-reboot attach failed
        until the caches were manually re-pointed. The daemon repairs them
        itself now, and the absence of that dance here is what proves it.
        """
        return json.loads(tool("ps")(module.split(".")[0]))[0]["pid"]

    def test_stub_start_status_stop(self, run):
        run("kdbg", "stop", expect_ok=False)  # ensure a clean slate
        run("kdbg", "start")
        try:
            assert "listening" in run("kdbg", "status").output
        finally:
            run("kdbg", "stop")
        assert "not running" in run("kdbg", "status").output

    def test_symbols_and_lookups(self, run, tool):
        run("kdbg", "start")
        try:
            symbols = self._result(tool, "kdbg_symbols_load")
            assert symbols["module"] == "nt" and symbols["symbol_count"] > 0
            match = self._result(
                tool, "kdbg_sym", "nt!PsInitialSystemProcess"
            )["matches"]
            assert "PsInitialSystemProcess" in match[0]
            layout = self._result(
                tool, "kdbg_struct", "_EPROCESS", "UniqueProcessId"
            )
            assert layout["field"] == "UniqueProcessId" and layout["lines"]
            modules = self._result(tool, "kdbg_lm")["modules"]
            assert any(m["name"].lower() == "ntoskrnl.exe" for m in modules)
            procs = self._result(tool, "kdbg_ps")["processes"]
            assert any(p["name"] == "System" for p in procs)
            self._result(tool, "kdbg_base_refresh")
        finally:
            run("kdbg", "stop")

    def test_attach_read_and_detach_leaves_the_vm_running(self, tool, cfg, run):
        """A daemon that does not shut down cleanly never resumes the CPU,
        which left the guest paused behind a warning."""
        run("kdbg", "start")
        try:
            pid = self._target_pid(tool)
            loaded = self._result(tool, "kdbg_user_symbols_load", pid, "ntdll")
            assert loaded["module"] == "ntdll" and loaded["symbol_count"] > 0
            prepared = self._result(tool, "kdbg_decomp_prepare", "ntdll", 900)
            assert prepared["prepared"] == 1
            assert self._result(tool, "kdbg_decomp_prepare_status")["state"] in {
                "none", "starting", "running", "completed", "partial", "failed",
            }
            nt_close = self._result(
                tool, "kdbg_sym", "ntdll!NtClose"
            )["matches"][0].split()[-1]
            user_modules = self._result(tool, "kdbg_user_lm", pid)["modules"]
            assert any(m["name"].lower() == "winlogon.exe" for m in user_modules)
            read = self._result(tool, "kdbg_read_va", pid, "0x7FFE0000", 16)
            assert len(read["bytes"]) == 32
            session = self._result(tool, "kdbg_attach", pid)
            assert session["target"]["pid"] == pid

            assert self._result(tool, "kdbg_session")["attached"] is True
            liveness = self._result(tool, "kdbg_target_status")
            assert liveness["state"] == "alive"
            self._result(tool, "kdbg_regs")
            self._result(tool, "kdbg_stack")
            self._result(tool, "kdbg_bt")
            context = self._result(tool, "kdbg_context")
            assert context["schema"] == "winbox.kdbg-context/1"
            assert context["state"] == "halted"
            started = self._result(tool, "kdbg_cont_start", 30)
            polled = self._result(tool, "kdbg_cont_poll", started["token"])
            assert polled["state"] in {"starting", "running"}
            self._result(tool, "kdbg_cont_cancel", started["token"])
            deadline = time.monotonic() + 5
            while True:
                polled = self._result(tool, "kdbg_cont_poll", started["token"])
                if not polled["active"]:
                    break
                assert time.monotonic() < deadline, polled
                time.sleep(0.05)
            assert polled["state"] == "cancelled"
            assert polled["result"]["reason"] == "interrupt"
            self._result(tool, "kdbg_mem", "0x7FFE0000", 16)
            self._result(tool, "kdbg_disasm", "", 4)
            lifecycle = self._result(tool, "kdbg_ghidra_run")
            assert lifecycle["api"]["worker_pid"] == 1
            assert self._result(tool, "kdbg_decomp_status")["image_installed"]
            cache = self._result(tool, "kdbg_decomp_cache")
            assert cache["schema"] == "winbox.decomp-cache/1"
            decomp = self._result(
                tool, "kdbg_decomp", nt_close, before=1, after=2
            )
            assert decomp["schema"] == "winbox.kdbg-decomp/5"
            assert decomp["detail"] == "compact"
            assert decomp["target"]["name"]
            assert decomp["verified"]["identity_method"] == "pdb-guid-age"
            assert decomp["rip_mapping"]["kind"] in {
                "exact", "range", "nearest-forward", "nearest-backward",
                "ambiguous", "unmapped",
            }
            assert decomp["function"]["name"]
            assert self._result(tool, "kdbg_bps")["bps"] == []

            self._result(tool, "kdbg_detach")
            assert self._result(tool, "kdbg_session")["attached"] is False
            assert self._result(tool, "kdbg_ghidra_stop")["stopped"]
        finally:
            run("kdbg", "stop", expect_ok=False)

        assert _domstate(cfg.vm_name) == "running", (
            "the debug session left the guest paused"
        )

    def test_breakpoint_add_and_remove(self, tool, run, cfg):
        run("kdbg", "start")
        try:
            pid = self._target_pid(tool)
            self._result(tool, "kdbg_attach", pid)
            self._result(tool, "kdbg_symbols_load")
            try:
                # Which mechanism works depends on the image. Win11 runs
                # HVCI by default, which protects kernel code pages, so a
                # software breakpoint (a 0xCC patch) cannot be installed —
                # hardware ones do. On Server 2022 the hardware path has been
                # seen to time out on its 4-slot DR0..3 budget while soft
                # works. Either mechanism proves the add/remove path; needing
                # a specific one does not.
                attempts = {
                    mode: tool("kdbg_bp")("nt!NtCreateFile", mode)
                    for mode in ("hw", "soft")
                }
                assert any(out["ok"] for out in attempts.values()), (
                    "no breakpoint mechanism worked: " + repr(attempts)
                )
                bps = self._result(tool, "kdbg_bps")["bps"]
                assert bps, "breakpoint did not register"
                self._result(tool, "kdbg_rm", bps[0]["id"])
                assert self._result(tool, "kdbg_bps")["bps"] == []
            finally:
                self._result(tool, "kdbg_detach")
        finally:
            run("kdbg", "stop", expect_ok=False)
        assert _domstate(cfg.vm_name) == "running"

    def test_private_user_soft_breakpoint_remove_restores_original_byte(
        self, tool, run, cfg
    ):
        """Regression for roadmap #21: z0 removal must reuse install CR3."""
        run("kdbg", "stop", expect_ok=False)
        run("kdbg", "start")
        try:
            pid = self._target_pid(tool)
            loaded = self._result(tool, "kdbg_user_symbols_load", pid, "ntdll")
            assert loaded["module"] == "ntdll" and loaded["symbol_count"] > 0
            nt_close = self._result(
                tool, "kdbg_sym", "ntdll!NtClose"
            )["matches"][0].split()[-1]
            original = self._result(
                tool, "kdbg_read_va", pid, nt_close, 1
            )["bytes"]
            assert len(original) == 2 and original != "cc", original

            self._result(tool, "kdbg_attach", pid)
            try:
                for _ in range(3):
                    added = self._result(
                        tool, "kdbg_bp", "ntdll!NtClose", "soft"
                    )
                    assert added["user_mode"] is True
                    assert added["hw"] is False
                    self._result(tool, "kdbg_rm", added["id"])
                    assert self._result(tool, "kdbg_bps")["bps"] == []
                    restored = self._result(
                        tool, "kdbg_mem", nt_close, 1
                    )["bytes"]
                    assert restored == original
            finally:
                self._result(tool, "kdbg_detach")
        finally:
            run("kdbg", "stop", expect_ok=False)
        assert _domstate(cfg.vm_name) == "running"

    def test_attach_works_after_a_reboot_without_a_manual_refresh(
        self, tool, run, cfg, ga, vm
    ):
        """ASLR re-randomizes every base each boot, but the symbol store
        survives — so an attach after a restart used to fail with
        `PageWalkError` or "stale module bases … ASLR moved them" until the
        user knew to run `kdbg base` and `kdbg user-symbols`. The daemon
        repairs its own caches now.

        This is the fix's real test: the reboot happens *between* loading
        symbols and using them, and nothing refreshes them in between.
        """
        run("kdbg", "start")
        try:
            # Load symbols against this boot, then move every base underneath
            # them.
            self._result(tool, "kdbg_symbols_load")
            pid = self._target_pid(tool)
            self._result(tool, "kdbg_user_symbols_load", pid, "winlogon.exe")
        finally:
            run("kdbg", "stop", expect_ok=False)

        # Reboot the way the rest of this suite does, not via the CLI's
        # reboot_and_wait: that helper waits 120s and raises SystemExit when
        # the agent is late, which is right for a command and wrong for a
        # test — Win11 routinely needs longer, and aborting mid-suite leaves
        # every later test staring at a guest that was merely still booting.
        try:
            ga.exec("shutdown /r /t 0", timeout=10)
        except Exception:
            pass  # the VM dies before it can ACK
        time.sleep(10)
        ga.wait(timeout=420)

        run("kdbg", "start")
        try:
            # No kdbg_base_refresh, no kdbg_user_symbols_load. Just attach.
            fresh_pid = self._target_pid(tool)
            session = self._result(tool, "kdbg_attach", fresh_pid)
            assert session["target"]["pid"] == fresh_pid
            try:
                procs = self._result(tool, "kdbg_ps")["processes"]
                assert any(p["name"] == "System" for p in procs), (
                    "walkers still using a stale nt base"
                )
                modules = self._result(tool, "kdbg_user_lm", fresh_pid)["modules"]
                assert any(m["name"].lower() == "winlogon.exe" for m in modules)
            finally:
                self._result(tool, "kdbg_detach")
        finally:
            run("kdbg", "stop", expect_ok=False)

        assert _domstate(cfg.vm_name) == "running"

    def test_session_reports_nothing_attached_when_idle(self, tool):
        assert self._result(tool, "kdbg_session")["attached"] is False

    def test_resume_is_a_noop_on_a_running_vm(self, tool, cfg):
        self._result(tool, "kdbg_resume")
        assert _domstate(cfg.vm_name) == "running"

    def test_user_symbols_load(self, tool, run):
        run("kdbg", "start")
        try:
            pid = self._target_pid(tool)
            self._result(tool, "kdbg_attach", pid)
            try:
                out = self._result(
                    tool, "kdbg_user_symbols_load", pid, "winlogon.exe"
                )
                assert out["module"] == "winlogon" and out["symbol_count"] > 0
            finally:
                self._result(tool, "kdbg_detach")
        finally:
            run("kdbg", "stop", expect_ok=False)

    def test_mcp_stub_lifecycle_tools(self, tool, cfg):
        """The MCP mirrors of `kdbg start/status/stop`."""
        assert "UserShadowStack=" in self._result(
            tool, "kdbg_cet_status"
        )["summary"]
        refused = tool("kdbg_prepare")()
        assert refused["ok"] is False and refused["error"]["code"] == "invalid_argument"
        refused = tool("kdbg_restore_cet")()
        assert refused["ok"] is False and refused["error"]["code"] == "invalid_argument"
        self._result(tool, "kdbg_stop")
        assert "listening" in self._result(tool, "kdbg_start")
        try:
            assert "listening" in self._result(tool, "kdbg_status")
        finally:
            assert "stopped" in self._result(tool, "kdbg_stop")
        assert _domstate(cfg.vm_name) == "running"

    def test_kdbg_cli_surface(self, run, tool, cfg):
        """The CLI mirrors of the tools exercised above. These are separate
        code paths from the MCP tools, not thin wrappers over them."""
        assert "UserShadowStack=" in run("kdbg", "cet-status").output
        assert "--confirm" in run("kdbg", "prepare", expect_ok=False).output
        assert "--confirm" in run("kdbg", "restore-cet", expect_ok=False).output
        run("kdbg", "ghidra", "run")
        assert "image_installed" in run("kdbg", "ghidra", "status").output
        assert "total_bytes" in run("kdbg", "ghidra", "cache").output
        run("kdbg", "ghidra", "stop")
        run("kdbg", "start")
        try:
            run("kdbg", "symbols")
            assert "0x" in run("kdbg", "sym", "nt!PsInitialSystemProcess").output
            run("kdbg", "struct", "_EPROCESS")
            run("kdbg", "ps")
            run("kdbg", "lm")
            run("kdbg", "base")
            run("kdbg", "session")

            pid = str(self._target_pid(tool))
            loaded = self._result(tool, "kdbg_user_symbols_load", int(pid), "ntdll")
            assert loaded["module"] == "ntdll" and loaded["symbol_count"] > 0
            assert '"prepared": 1' in run("kdbg", "ghidra", "prepare", "ntdll").output
            assert '"state"' in run("kdbg", "ghidra", "prepare-status").output
            nt_close = self._result(
                tool, "kdbg_sym", "ntdll!NtClose"
            )["matches"][0].split()[-1]
            run("kdbg", "attach", pid)
            try:
                run("kdbg", "regs")
                assert '"state": "alive"' in run("kdbg", "target-status").output
                decomp_status = run("kdbg", "decomp-status")
                assert "image_installed" in decomp_status.output
                decomp = run("kdbg", "decomp", nt_close,
                    "--before", "1", "--after", "2",
                )
                assert "pdb-guid-age" in decomp.output
                run("kdbg", "mem", "0x7FFE0000", "16")
                # stack/bt read the halted context; an attached-but-running
                # target has none, and refusing is the correct answer.
                _accept_not_halted(run("kdbg", "stack", "4", expect_ok=False))
                _accept_not_halted(run("kdbg", "bt", expect_ok=False))
                run("kdbg", "bps")
                run("kdbg", "user-lm", pid)
                run("kdbg", "user-symbols", pid, "winlogon.exe")
                run("kdbg", "read-va", pid, "0x7FFE0000", "16")

                # Same image-dependent mechanism split as the MCP bp test:
                # HVCI blocks the soft path on Win11, and the hw path has
                # been seen to exhaust its DR slots on Server.
                run("kdbg", "bp", "nt!NtCreateFile", "--mode", "hw",
                    expect_ok=False)
                if not self._result(tool, "kdbg_bps")["bps"]:
                    run("kdbg", "bp", "nt!NtCreateFile", "--mode", "soft",
                        expect_ok=False)
                bps = self._result(tool, "kdbg_bps")["bps"]
                assert bps, "no breakpoint mechanism worked from the CLI"
                run("kdbg", "rm", str(bps[0]["id"]))
            finally:
                run("kdbg", "detach")
            run("kdbg", "resume")
        finally:
            run("kdbg", "stop", expect_ok=False)
        assert _domstate(cfg.vm_name) == "running"

    def test_user_bp_rejects_a_bad_target(self, run):
        run("kdbg", "user-bp", "999999", "nosuch!symbol", expect_ok=False)


# ─── provisioning ───────────────────────────────────────────────────────────


class TestProvision:
    def test_reprovision_is_idempotent(self, run, tool):
        """`winbox provision` must be safe to re-run on a built VM."""
        run("provision")
        out = json.loads(tool("python")("print('still-alive')"))
        assert "still-alive" in out["stdout"]


# ─── lifecycle (last: these stop the VM) ────────────────────────────────────


class TestLifecycleTeardown:
    def test_snapshot_create_and_list(self, run, vm, ga):
        # A snapshot left behind by an interrupted earlier run would make
        # creation fail with "domain moment already exists".
        if "e2e-snap" in vm.snapshot_list():
            subprocess.run(
                ["virsh", "-c", "qemu:///system", "snapshot-delete",
                 vm.name, "e2e-snap"],
                capture_output=True, check=False,
            )

        run("snapshot", "e2e-snap")
        assert "e2e-snap" in run("snapshot").output
        if vm.state() != VMState.RUNNING:
            vm.start()
            ga.wait(timeout=420)

    def test_restore_snapshot(self, run, vm, ga):
        run("restore", "e2e-snap")
        vm.start()
        ga.wait(timeout=420)
        assert "restored-ok" in ga.exec("echo restored-ok", timeout=60).stdout

    def test_suspend_and_resume(self, run, vm, ga):
        run("suspend")
        run("up")
        assert "resumed-ok" in ga.exec("echo resumed-ok", timeout=60).stdout

    def test_down_then_up(self, run, vm, ga):
        run("down")
        assert vm.state() != VMState.RUNNING
        # A stopped domain's channel is genuinely disconnected — this is the
        # signal the readiness gate reads, observed at its source.
        assert vm.agent_connected() is False
        run("up")
        assert "back-up" in ga.exec("echo back-up", timeout=60).stdout
