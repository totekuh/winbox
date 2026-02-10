"""winbox CLI — click entry point."""

from __future__ import annotations

import time

import click
from rich.console import Console

from winbox import smb
from winbox.config import Config
from winbox.guest import GuestAgent
from winbox.vm import VM, VMState

console = Console()


def ensure_running(vm: VM, ga: GuestAgent, cfg: Config) -> None:
    """Make sure the VM and SMB server are running, guest agent responding."""
    state = vm.state()

    if state == VMState.NOT_FOUND:
        console.print("[red][-][/] VM not found. Run [bold]winbox setup[/] first.")
        raise SystemExit(1)

    # Ensure SMB server is up
    smb.start(cfg)

    if state == VMState.RUNNING:
        if not ga.ping():
            console.print("[blue][*][/] Waiting for guest agent...")
            ga.wait(timeout=60)
        _ensure_smb_mapped(ga, cfg)
        _ensure_sshd_running(ga)
        return

    if state == VMState.SHUTOFF:
        console.print("[blue][*][/] VM is off, starting...")
        vm.start()
    elif state == VMState.PAUSED:
        console.print("[blue][*][/] VM is paused, resuming...")
        vm.resume()
    elif state == VMState.SAVED:
        console.print("[blue][*][/] Restoring saved VM state...")
        vm.start()
    else:
        console.print(f"[red][-][/] VM is in unexpected state: {state.value}")
        raise SystemExit(1)

    console.print("[blue][*][/] Waiting for guest agent...")
    ga.wait(timeout=120)
    _ensure_smb_mapped(ga, cfg)
    _ensure_sshd_running(ga)
    console.print("[green][+][/] VM ready")


def _ensure_smb_mapped(ga: GuestAgent, cfg: Config) -> None:
    """Ensure Z: drive is mapped to the host SMB share."""
    try:
        result = ga.exec(f"net use Z: \\\\{cfg.smb_host_ip}\\winbox", timeout=10)
        if result.exitcode != 0 and "already" not in result.stderr.lower():
            # Already mapped or different error — try remapping
            ga.exec("net use Z: /delete /y", timeout=10)
            ga.exec(f"net use Z: \\\\{cfg.smb_host_ip}\\winbox", timeout=10)
    except Exception:
        pass  # Best effort — exec will fail with a clear error if Z: is missing


def _ensure_sshd_running(ga: GuestAgent) -> None:
    """Start sshd if it's not running."""
    try:
        ga.exec("net start sshd", timeout=10)
    except Exception:
        pass  # Best effort — ssh will fail with a clear error if sshd is down


# ─── CLI Group ───────────────────────────────────────────────────────────────


@click.group()
@click.version_option(package_name="winbox")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """winbox — Transparent Windows execution proxy for Kali."""
    ctx.ensure_object(dict)
    ctx.obj["cfg"] = Config.load()


# ─── Register subcommands ────────────────────────────────────────────────────

from winbox.cli.vm import up, down, suspend, destroy, status, snapshot, restore  # noqa: E402
from winbox.cli.setup import setup, provision  # noqa: E402
from winbox.cli.exec import exec_cmd, shell, ssh  # noqa: E402
from winbox.cli.network import dns, domain  # noqa: E402
from winbox.cli.files import tools, iso  # noqa: E402

cli.add_command(up)
cli.add_command(down)
cli.add_command(suspend)
cli.add_command(destroy)
cli.add_command(status)
cli.add_command(snapshot)
cli.add_command(restore)
cli.add_command(setup)
cli.add_command(provision)
cli.add_command(exec_cmd)
cli.add_command(shell)
cli.add_command(ssh)
cli.add_command(dns)
cli.add_command(domain)
cli.add_command(tools)
cli.add_command(iso)
