"""winbox CLI — click entry point."""

from __future__ import annotations

import time

import click
from rich.console import Console

from winbox.config import Config
from winbox.vm import GuestAgent, GuestAgentError
from winbox.vm import VM, VMState

console = Console()


def ensure_running(vm: VM, ga: GuestAgent, cfg: Config) -> None:
    """Make sure the VM is running and guest agent responding."""
    state = vm.state()

    if state == VMState.NOT_FOUND:
        console.print("[red][-][/] VM not found. Run [bold]winbox setup[/] first.")
        raise SystemExit(1)

    if state == VMState.RUNNING:
        if not ga.ping():
            console.print("[blue][*][/] Waiting for guest agent...")
            try:
                ga.wait(timeout=60)
            except GuestAgentError:
                console.print("[red][-][/] Guest agent not responding. Is the VM healthy?")
                raise SystemExit(1)
        _ensure_z_drive(ga)
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
    try:
        ga.wait(timeout=120)
    except GuestAgentError:
        console.print("[red][-][/] Guest agent not responding. Is the VM healthy?")
        raise SystemExit(1)
    _ensure_z_drive(ga)
    _ensure_sshd_running(ga)
    console.print("[green][+][/] VM ready")


def _ensure_z_drive(ga: GuestAgent) -> None:
    """Verify the VirtIO-FS Z: drive is accessible (VirtioFsSvc auto-mounts it)."""
    # Kick the service in case it hasn't started yet
    try:
        ga.exec("net start VirtioFsSvc", timeout=10)
    except Exception:
        pass

    for _ in range(15):
        try:
            result = ga.exec("dir Z:", timeout=5)
            if result.exitcode == 0:
                return
        except Exception:
            pass
        time.sleep(1)
    console.print("[yellow][!][/] Z: drive may not be ready")


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
from winbox.cli.network import dns, domain, hosts  # noqa: E402
from winbox.cli.files import tools, iso  # noqa: E402
from winbox.cli.binfmt import binfmt  # noqa: E402

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
cli.add_command(hosts)
cli.add_command(tools)
cli.add_command(iso)
cli.add_command(binfmt)
