"""Execution commands — exec, shell, ssh."""

from __future__ import annotations

import os
import shutil

import click

from winbox.cli import console, ensure_running
from winbox.config import Config
from winbox.exec import run_command
from winbox.vm import GuestAgent
from winbox.exec import open_shell
from winbox.vm import VM


@click.command("exec", context_settings=dict(
    ignore_unknown_options=True,
    allow_interspersed_args=False,
))
@click.argument("command", nargs=-1, type=click.UNPROCESSED, required=True)
@click.option("--timeout", default=300, help="Execution timeout in seconds.")
@click.pass_context
def exec_cmd(ctx: click.Context, command: tuple[str, ...], timeout: int) -> None:
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
    exitcode = run_command(cfg, ga, exe, args, timeout=timeout)
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
        ssh_args = ["sshpass", "-p", cfg.vm_password] + ssh_args
        os.execvp("sshpass", ssh_args)
    else:
        os.execvp("ssh", ssh_args)
