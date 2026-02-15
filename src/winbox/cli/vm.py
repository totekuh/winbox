"""VM lifecycle commands — up, down, suspend, destroy, status, snapshot, restore."""

from __future__ import annotations

import time

import click

from winbox.cli import console, ensure_running
from winbox.config import Config
from winbox.vm import GuestAgent
from winbox.vm import VM, VMState


@click.command()
@click.pass_context
def up(ctx: click.Context) -> None:
    """Start or resume the VM."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

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

    # Graceful shutdown via guest agent
    if ga.ping():
        ga.shutdown()
        timeout = 60
        elapsed = 0
        while vm.state() == VMState.RUNNING:
            time.sleep(2)
            elapsed += 2
            if elapsed >= timeout:
                console.print("[yellow][!][/] Graceful shutdown timeout, forcing...")
                vm.force_stop()
                break
    else:
        vm.shutdown()

    console.print("[green][+][/] VM stopped")


@click.command()
@click.pass_context
def suspend(ctx: click.Context) -> None:
    """Save VM state to disk for instant resume."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)

    if vm.state() != VMState.RUNNING:
        console.print(f"[yellow][!][/] VM is not running (state: {vm.state().value})")
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
        exe_count = sum(1 for f in cfg.tools_dir.iterdir() if f.suffix == ".exe")
        console.print(f"  Tools:   {exe_count} executables")

    if cfg.loot_dir.exists():
        loot_count = sum(1 for f in cfg.loot_dir.rglob("*") if f.is_file())
        console.print(f"  Loot:    {loot_count} files")

    snaps = vm.snapshot_list()
    console.print(f"  Snaps:   {len(snaps)}")
    console.print("\u2500" * 32)


@click.command()
@click.argument("name")
@click.pass_context
def snapshot(ctx: click.Context, name: str) -> None:
    """Create a named VM snapshot."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)

    if not vm.exists():
        console.print("[red][-][/] VM not found")
        raise SystemExit(1)

    console.print(f"[blue][*][/] Creating snapshot '{name}'...")
    vm.snapshot_create(name)
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
    vm.snapshot_revert(name)
    console.print(f"[green][+][/] Restored to '{name}'")

    if vm.state() == VMState.RUNNING:
        console.print("[blue][*][/] Waiting for guest agent...")
        ga.wait(timeout=60)
