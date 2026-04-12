"""VM lifecycle commands — up, down, suspend, destroy, status, snapshot, restore, vnc."""

from __future__ import annotations

import shutil
import subprocess
import time

import click

from winbox.cli import console, ensure_running
from winbox.config import Config
from winbox.vm import GuestAgent, GuestAgentError
from winbox.vm import VM, VMState


def _graceful_shutdown(vm: VM, ga: GuestAgent, *, timeout: int = 60) -> None:
    """Shut the VM down cleanly, force-stop on timeout. No-op if already off."""
    if vm.state() != VMState.RUNNING:
        return

    if ga.ping():
        ga.shutdown()
    else:
        vm.shutdown()

    elapsed = 0
    while vm.state() == VMState.RUNNING:
        time.sleep(2)
        elapsed += 2
        if elapsed >= timeout:
            console.print("[yellow][!][/] Graceful shutdown timeout, forcing...")
            vm.force_stop()
            break


@click.command()
@click.option("--reboot", "-r", is_flag=True, help="If the VM is already running, shut it down first and start it again.")
@click.pass_context
def up(ctx: click.Context, reboot: bool) -> None:
    """Start or resume the VM."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    if reboot and vm.state() == VMState.RUNNING:
        console.print("[blue][*][/] Rebooting VM — shutting down first...")
        _graceful_shutdown(vm, ga)
        console.print("[green][+][/] VM stopped, restarting...")

    ensure_running(vm, ga, cfg)

    ip = vm.ip()
    if ip:
        console.print(f"[blue][*][/] IP: {ip}")
    console.print("[green][+][/] VM is up")


@click.command()
@click.pass_context
def down(ctx: click.Context) -> None:
    """Shut down the VM."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    state = vm.state()
    if state != VMState.RUNNING:
        console.print(f"[yellow][!][/] VM is not running (state: {state.value})")
        return

    console.print("[blue][*][/] Shutting down VM...")
    _graceful_shutdown(vm, ga)
    console.print("[green][+][/] VM stopped")


@click.command()
@click.pass_context
def suspend(ctx: click.Context) -> None:
    """Save VM state to disk for instant resume."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)

    state = vm.state()
    if state != VMState.RUNNING:
        console.print(f"[yellow][!][/] VM is not running (state: {state.value})")
        return

    console.print("[blue][*][/] Saving VM state...")
    vm.suspend()
    console.print("[green][+][/] VM state saved — resume with [bold]winbox up[/]")


@click.command()
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation.")
@click.pass_context
def destroy(ctx: click.Context, yes: bool) -> None:
    """Delete the VM and all its storage."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)

    if not vm.exists():
        console.print(f"[yellow][!][/] VM '{cfg.vm_name}' does not exist")
        return

    if not yes and not click.confirm("Destroy VM and all storage?", default=False):
        console.print("Aborted.")
        return

    console.print("[blue][*][/] Destroying VM and all storage...")
    vm.destroy()
    console.print("[green][+][/] VM destroyed")


@click.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show VM state, IP, and resource usage."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    state = vm.state()
    state_color = {
        VMState.RUNNING: "green",
        VMState.SHUTOFF: "red",
        VMState.PAUSED: "yellow",
        VMState.SAVED: "yellow",
    }.get(state, "white")

    console.print(f"[bold]winbox status[/]")
    console.print("\u2500" * 32)
    console.print(f"  VM:      [bold]{cfg.vm_name}[/]")
    console.print(f"  State:   [{state_color}]{state.value}[/]")

    if state == VMState.RUNNING:
        ip = vm.ip()
        if ip:
            console.print(f"  IP:      {ip}")
        agent_status = "[green]responding[/]" if ga.ping() else "[red]not responding[/]"
        console.print(f"  Agent:   {agent_status}")

    disk = vm.disk_usage()
    if disk:
        console.print(f"  Disk:    {disk}")

    if cfg.tools_dir.exists():
        tool_count = sum(1 for f in cfg.tools_dir.iterdir() if f.is_file() and not f.name.startswith("."))
        console.print(f"  Tools:   {tool_count} files")

    if cfg.loot_dir.exists():
        loot_count = sum(
            1 for f in cfg.loot_dir.rglob("*")
            if f.is_file() and not f.is_relative_to(cfg.jobs_log_dir)
        )
        console.print(f"  Loot:    {loot_count} files")

    snaps = vm.snapshot_list()
    console.print(f"  Snaps:   {len(snaps)}")
    console.print("\u2500" * 32)


@click.command()
@click.argument("name", required=False)
@click.pass_context
def snapshot(ctx: click.Context, name: str | None) -> None:
    """Create a named VM snapshot, or list existing ones if no name is given.

    Shuts the VM down first if it's running — internal qcow2 snapshots
    of a live VM with UEFI/pflash are unreliable, and virsh refuses them.
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    if not vm.exists():
        console.print("[red][-][/] VM not found")
        raise SystemExit(1)

    if name is None:
        snaps = vm.snapshot_list()
        if not snaps:
            console.print("[yellow][!][/] No snapshots")
            return
        console.print(f"[bold]Snapshots ({len(snaps)}):[/]")
        for s in snaps:
            console.print(f"  {s}")
        return

    if vm.state() == VMState.RUNNING:
        console.print("[blue][*][/] VM is running — shutting down before snapshot...")
        _graceful_shutdown(vm, ga)
        console.print("[green][+][/] VM stopped")

    console.print(f"[blue][*][/] Creating snapshot '{name}'...")
    try:
        vm.snapshot_create(name)
    except Exception as e:
        console.print(f"[red][-][/] Failed to create snapshot '{name}':")
        console.print(f"    {e}", markup=False, highlight=False)
        raise SystemExit(1)
    console.print(f"[green][+][/] Snapshot '{name}' created")


@click.command()
@click.argument("name")
@click.pass_context
def restore(ctx: click.Context, name: str) -> None:
    """Restore the VM to a named snapshot."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    console.print(f"[blue][*][/] Restoring snapshot '{name}'...")
    try:
        vm.snapshot_revert(name)
    except Exception:
        console.print(f"[red][-][/] Failed to restore snapshot '{name}'")
        raise SystemExit(1)
    console.print(f"[green][+][/] Restored to '{name}'")

    if vm.state() == VMState.RUNNING:
        console.print("[blue][*][/] Waiting for guest agent...")
        try:
            ga.wait(timeout=60)
        except GuestAgentError:
            console.print("[yellow][!][/] Guest agent not responding after restore")


@click.command()
@click.pass_context
def vnc(ctx: click.Context) -> None:
    """Open the VM display in virt-manager."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    if not shutil.which("virt-manager"):
        console.print("[red][-][/] virt-manager not found. Install with: [bold]apt install virt-manager[/]")
        raise SystemExit(1)

    ensure_running(vm, ga, cfg)

    console.print(f"[blue][*][/] Opening virt-manager console for {cfg.vm_name}")
    subprocess.Popen(
        ["virt-manager", "--connect", "qemu:///system", "--show-domain-console", cfg.vm_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    console.print("[green][+][/] virt-manager launched")
