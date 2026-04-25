"""Execution commands — exec, shell, ssh."""

from __future__ import annotations

import os
import shutil

import click

from winbox.cli import console, ensure_running
from winbox.config import Config
from winbox.exec import run_command, run_command_bg
from winbox.vm import GuestAgent, GuestAgentError
from winbox.exec import open_shell
from winbox.vm import VM


@click.command("exec", context_settings=dict(
    ignore_unknown_options=True,
    allow_interspersed_args=False,
))
@click.argument("command", nargs=-1, type=click.UNPROCESSED, required=True)
@click.option("--timeout", default=300, help="Execution timeout in seconds.")
@click.option("--bg", is_flag=True, help="Run in background, return immediately.")
@click.option("--log", is_flag=True, help="Redirect output to log files (with --bg).")
@click.pass_context
def exec_cmd(ctx: click.Context, command: tuple[str, ...], timeout: int, bg: bool, log: bool) -> None:
    """Execute a command in the Windows VM.

    Bare .exe names are resolved from Z:\\tools\\. Output files land in
    ~/.winbox/shared/loot/ via VirtIO-FS.
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)

    exe = command[0]
    args = command[1:]

    if log and not bg:
        console.print("[yellow][!][/] --log has no effect without --bg, ignoring")

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
        from winbox.vm import VMState
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
@click.pass_context
def shell(ctx: click.Context, port: int, pipe: bool) -> None:
    """Open an interactive SYSTEM shell in the VM (ConPTY reverse shell)."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)
    open_shell(cfg, ga, port=port, pipe_mode=pipe)


@click.command()
@click.pass_context
def ssh(ctx: click.Context) -> None:
    """Open an interactive SSH session to the VM (fallback)."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)

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
