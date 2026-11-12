"""Execution commands — exec, shell, ssh."""

from __future__ import annotations

import os
import shutil

import click

from winbox.cli import console, needs_vm
from winbox.config import Config
from winbox.exec import run_command, run_command_bg
from winbox.vm import GuestAgent, GuestAgentError, VM, VMState
from winbox.exec import open_shell


@click.command("exec", context_settings=dict(
    ignore_unknown_options=True,
    allow_interspersed_args=False,
))
@click.argument("command", nargs=-1, type=click.UNPROCESSED, required=True)
@click.option("--timeout", default=300, help="Execution timeout in seconds.")
@click.option("--bg", is_flag=True, help="Run in background, return immediately.")
@click.option("--log", is_flag=True, help="Redirect output to log files (with --bg).")
@click.option("--user", help="Run as this local Windows user.")
@click.option("--password", help="Password for --user.")
@needs_vm()
def exec_cmd(
    cfg: Config, vm: VM, ga: GuestAgent,
    command: tuple[str, ...], timeout: int, bg: bool, log: bool,
    user: str | None, password: str | None,
) -> None:
    """Execute a command in the Windows VM.

    Bare .exe names are resolved from Z:\\tools\\. Output files land in
    ~/.winbox/shared/loot/ via VirtIO-FS.
    """
    exe = command[0]
    args = command[1:]

    if log and not bg:
        # Previously a yellow-warning-and-ignore. The user explicitly asked
        # for log mode; silently dropping it violated least-surprise and
        # masked typos. Hard-fail with the standard Click "Error:" prefix.
        raise click.UsageError("--log requires --bg")
    if (user is None) != (password is None):
        raise click.UsageError("--user and --password must be supplied together")

    if bg:
        from winbox.jobs import JobMode
        job = run_command_bg(cfg, ga, exe, args, log=log, user=user, password=password)
        console.print(f"[green][+][/] Job {job.id} started (PID {job.pid})")
        if job.mode == JobMode.LOG:
            from winbox.jobs import JobStore
            store = JobStore(cfg)
            console.print(f"    stdout: {store.log_path(job.id, 'stdout')}")
            console.print(f"    tail -f {store.log_path(job.id, 'stdout')}")
        else:
            console.print(f"    Retrieve output: winbox jobs output {job.id}")
        return

    try:
        exitcode = run_command(cfg, ga, exe, args, timeout=timeout, user=user, password=password)
    except GuestAgentError as e:
        # Mid-execution GA disconnect (VM rebooted, crashed, or paused).
        # The command may or may not have completed on the guest side —
        # there's no way to recover state from here. Surface it cleanly
        # instead of letting the traceback escape.
        console.print("[red][-][/] Guest agent disconnected mid-execution:")
        console.print(f"    {e}", markup=False, highlight=False)
        state = vm.state()
        if state != VMState.RUNNING:
            console.print(f"    VM state: [yellow]{state.value}[/] — try [bold]winbox up[/] and re-run")
        else:
            console.print("    VM is still running but GA is unreachable — try [bold]winbox up --reboot[/]")
        raise SystemExit(1)
    raise SystemExit(exitcode)


@click.command()
@click.option("--port", default=4444, help="Listener port for reverse shell.")
@click.option("--pipe", is_flag=True, help="Pipe mode (no PTY). Use when tools need real pipe handles (e.g. RunasCs -P).")
@click.option("--user", help="Run as this local Windows user.")
@click.option("--password", help="Password for --user.")
@needs_vm()
def shell(
    cfg: Config, vm: VM, ga: GuestAgent,
    port: int, pipe: bool,
    user: str | None, password: str | None,
) -> None:
    """Open an interactive shell in the VM (ConPTY reverse shell).

    Runs as SYSTEM by default. Use --user/--password to spawn the shell
    as a different local Windows user (via RunEx).
    """
    if (user is None) != (password is None):
        raise click.UsageError("--user and --password must be supplied together")
    open_shell(cfg, ga, port=port, pipe_mode=pipe, user=user, password=password)


@click.command()
@needs_vm()
def ssh(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Open an interactive SSH session to the VM (fallback)."""
    ip = vm.ip()
    if not ip:
        console.print("[red][-][/] Cannot determine VM IP address")
        raise SystemExit(1)

    console.print(f"[blue][*][/] Connecting to {ip}...")

    ssh_args = [
        "ssh", "-t",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
    ]
    if cfg.ssh_key.exists():
        ssh_args += ["-i", str(cfg.ssh_key)]

    ssh_args += [
        f"{cfg.vm_user}@{ip}",
        "powershell.exe", "-NoLogo", "-NoExit",
    ]

    # Use sshpass for automatic password auth if available
    if shutil.which("sshpass"):
        ssh_args = ["sshpass", "-e"] + ssh_args
        env = {**os.environ, "SSHPASS": cfg.vm_password}
        os.execvpe("sshpass", ssh_args, env)
    else:
        os.execvp("ssh", ssh_args)


@click.command("powershell")
@click.argument("script", required=False)
@click.option("-f", "--file", "script_file", type=click.Path(exists=True, dir_okay=False),
              help="Read script from a .ps1 file instead of an inline argument.")
@click.option("--timeout", default=600, show_default=True, help="Execution timeout in seconds.")
@click.option("--bg", is_flag=True, help="Run in background, return immediately.")
@click.option("--user", help="Run as this local Windows user.")
@click.option("--password", help="Password for --user.")
@needs_vm()
def powershell_cmd(
    cfg: Config, vm: VM, ga: GuestAgent,
    script: str | None, script_file: str | None, timeout: int, bg: bool,
    user: str | None, password: str | None,
) -> None:
    """Execute a PowerShell script in the Windows VM.

    Provide SCRIPT as an inline argument, or use -f to read from a .ps1
    file on the host. Both are sent via -EncodedCommand, so backslash
    paths and quotes pass through verbatim — no nested escaping needed.

    Examples::

        winbox powershell 'Get-Process | Select -First 5'
        winbox powershell -f ./recon.ps1
        winbox powershell --bg 'Start-Sleep 60'
    """
    if script is not None and script_file is not None:
        raise click.UsageError("provide SCRIPT or --file, not both")
    if script is None and script_file is None:
        raise click.UsageError("provide a SCRIPT argument or --file")
    if script_file is not None:
        from pathlib import Path
        script = Path(script_file).read_text(encoding="utf-8-sig")
    if (user is None) != (password is None):
        raise click.UsageError("--user and --password must be supplied together")

    kwargs = {}
    if user is not None:
        kwargs.update(user=user, password=password)

    if bg:
        import uuid
        from winbox.jobs import Job, JobMode, JobStore

        store = JobStore(cfg)
        nonce = f"__wbx{uuid.uuid4().hex[:16]}__"

        def _spawn(job_id: int) -> Job:
            pid = ga.exec_powershell_background(script, **kwargs)
            return Job(
                id=job_id, pid=pid,
                command=f"powershell: {script[:80]}",
                mode=JobMode.BUFFERED, nonce=nonce,
            )

        job = store.claim(_spawn)
        console.print(f"[green][+][/] Job {job.id} started (PID {job.pid})")
        console.print(f"    Retrieve output: winbox jobs output {job.id}")
        return

    try:
        result = ga.exec_powershell(script, timeout=timeout, **kwargs)
    except GuestAgentError as e:
        console.print("[red][-][/] Guest agent disconnected mid-execution:")
        console.print(f"    {e}", markup=False, highlight=False)
        state = vm.state()
        if state != VMState.RUNNING:
            console.print(f"    VM state: [yellow]{state.value}[/] — try [bold]winbox up[/] and re-run")
        else:
            console.print("    VM is still running but GA is unreachable — try [bold]winbox up --reboot[/]")
        raise SystemExit(1)

    if result.stdout:
        console.print(result.stdout, end="", markup=False, highlight=False)
    if result.stderr:
        console.print(result.stderr, end="", markup=False, style="red", highlight=False)
    raise SystemExit(result.exitcode)


REGISTER = ("Execute", [exec_cmd, powershell_cmd, shell, ssh])
