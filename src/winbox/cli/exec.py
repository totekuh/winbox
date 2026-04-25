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
@needs_vm()
def exec_cmd(
    cfg: Config, vm: VM, ga: GuestAgent,
    command: tuple[str, ...], timeout: int, bg: bool, log: bool,
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

    if bg:
        from winbox.jobs import JobMode
        job = run_command_bg(cfg, ga, exe, args, log=log)
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
        exitcode = run_command(cfg, ga, exe, args, timeout=timeout)
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
@needs_vm()
def shell(cfg: Config, vm: VM, ga: GuestAgent, port: int, pipe: bool) -> None:
    """Open an interactive SYSTEM shell in the VM (ConPTY reverse shell)."""
    open_shell(cfg, ga, port=port, pipe_mode=pipe)


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


REGISTER = ("Execute", [exec_cmd, shell, ssh])
