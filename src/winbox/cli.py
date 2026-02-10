"""winbox CLI — click entry point."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import click
from rich.console import Console

from winbox import installer
from winbox import smb
from winbox import tools as tools_mod
from winbox.config import Config
from winbox.executor import run_command
from winbox.guest import GuestAgent
from winbox.iso import ISO_FILENAME, download_iso
from winbox.utils import human_size
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


# ─── CLI Group ───────────────────────────────────────────────────────────────


@click.group()
@click.version_option(package_name="winbox")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """winbox — Transparent Windows execution proxy for Kali."""
    ctx.ensure_object(dict)
    ctx.obj["cfg"] = Config.load()


# ─── setup ───────────────────────────────────────────────────────────────────


@cli.command()
@click.option(
    "--iso", "windows_iso",
    type=click.Path(exists=True),
    help="Path to Windows Server 2022 ISO.",
)
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts.")
@click.pass_context
def setup(ctx: click.Context, windows_iso: str | None, yes: bool) -> None:
    """Build the Windows VM (one-time setup)."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)

    console.print("[bold]winbox setup[/] — building Windows VM\n")

    # Check prereqs
    missing = installer.check_prereqs()
    if missing:
        console.print(f"[red][-][/] Missing: {', '.join(missing)}")
        console.print(
            "    Install with: [bold]apt install "
            "qemu-system-x86 libvirt-daemon-system virtinst guestfs-tools jq "
            "genisoimage python3-impacket impacket-scripts[/]"
        )
        raise SystemExit(1)

    # Clean up previous resources
    smb.stop(cfg)

    if vm.exists():
        console.print(f"[yellow][!][/] VM '{cfg.vm_name}' already exists.")
        if not yes and not click.confirm("Destroy and recreate?", default=False):
            console.print("Aborted.")
            return
        vm.destroy()
        console.print("[green][+][/] Previous VM destroyed")

    # Remove orphaned files from failed/partial previous setup
    for stale in [cfg.disk_path, cfg.unattend_img]:
        if stale.exists():
            console.print(f"[yellow][!][/] Removing stale {stale.name}")
            try:
                stale.unlink()
            except PermissionError:
                subprocess.run(["rm", "-f", str(stale)], check=False)

    # Windows ISO
    if windows_iso is None:
        # Check if already downloaded
        cached = cfg.iso_dir / ISO_FILENAME
        if cached.exists() and cached.stat().st_size > 1_000_000_000:
            console.print(f"[green][+][/] Using cached ISO: {cached}")
            windows_iso = str(cached)
        else:
            console.print("[bold]Windows Server 2022 Evaluation ISO required.[/]")
            console.print(
                "    Run [bold]winbox iso download[/] to fetch it automatically,\n"
                "    or provide a path.\n"
            )
            windows_iso = click.prompt(
                "Path to Windows ISO (or 'download' to fetch now)",
            )
            if windows_iso.strip().lower() == "download":
                iso_path = download_iso(cfg)
                windows_iso = str(iso_path)

    if not Path(windows_iso).exists():
        console.print(f"[red][-][/] ISO not found: {windows_iso}")
        raise SystemExit(1)

    # Phase 1: ISO install
    installer.create_directories(cfg)
    installer.grant_libvirt_access(cfg)
    installer.download_virtio_iso(cfg)
    installer.generate_ssh_keypair(cfg)
    installer.build_unattend_image(cfg)
    installer.create_disk(cfg)
    installer.run_virt_install(cfg, windows_iso)

    console.print("[blue][*][/] Waiting for Windows installation to complete...")
    console.print("    The VM will shut down automatically when done.")
    if not vm.wait_shutdown(timeout=1200):
        console.print("[yellow][!][/] Installation timed out (VM did not shut down).")
        console.print(f"    Check with: virsh console {cfg.vm_name}")
        raise SystemExit(1)
    console.print("[green][+][/] Phase 1 complete — Windows installed")

    # Phase 2: Offline provisioning via virt-customize
    installer.provision_vm_disk(cfg)
    console.print("[green][+][/] Phase 2 complete — provision files injected")

    # Phase 3: Provisioning via guest agent
    installer.boot_for_provisioning(cfg)
    console.print("[green][+][/] Phase 3 complete — VM provisioned")

    # Phase 4: Snapshot
    installer.create_clean_snapshot(cfg)

    console.print("\n[green][+][/] [bold]winbox setup complete![/]\n")
    console.print("  [bold]Quick start:[/]")
    console.print('    winbox exec cmd.exe /c "echo hello"')
    console.print("    winbox exec SharpHound.exe --help")
    console.print("    winbox suspend")


# ─── up ──────────────────────────────────────────────────────────────────────


@cli.command()
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


# ─── down ────────────────────────────────────────────────────────────────────


@cli.command()
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

    smb.stop(cfg)
    console.print("[green][+][/] VM stopped")


# ─── suspend ─────────────────────────────────────────────────────────────────


@cli.command()
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
    smb.stop(cfg)
    console.print("[green][+][/] VM state saved — resume with [bold]winbox up[/]")


# ─── destroy ─────────────────────────────────────────────────────────────────


@cli.command()
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
    smb.stop(cfg)
    vm.destroy()
    console.print("[green][+][/] VM destroyed")


# ─── status ──────────────────────────────────────────────────────────────────


@cli.command()
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
    console.print("─" * 32)
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
    console.print("─" * 32)


# ─── exec ────────────────────────────────────────────────────────────────────


@cli.command("exec", context_settings=dict(
    ignore_unknown_options=True,
    allow_interspersed_args=False,
))
@click.argument("command", nargs=-1, type=click.UNPROCESSED, required=True)
@click.option("--timeout", default=300, help="Execution timeout in seconds.")
@click.pass_context
def exec_cmd(ctx: click.Context, command: tuple[str, ...], timeout: int) -> None:
    """Execute a command in the Windows VM.

    Bare .exe names are resolved from Z:\\tools\\. Output files land in
    ~/.winbox/shared/loot/ via SMB share.
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)

    exe = command[0]
    args = command[1:]
    exitcode = run_command(cfg, ga, exe, args, timeout=timeout)
    raise SystemExit(exitcode)


# ─── tools ───────────────────────────────────────────────────────────────────


@cli.group()
def tools() -> None:
    """Manage tools in the shared directory."""
    pass


@tools.command("add")
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
@click.pass_context
def tools_add(ctx: click.Context, files: tuple[str, ...]) -> None:
    """Copy files into the shared tools directory."""
    cfg: Config = ctx.obj["cfg"]
    tools_mod.add(cfg, files)


@tools.command("list")
@click.pass_context
def tools_list(ctx: click.Context) -> None:
    """List tools in the shared directory."""
    cfg: Config = ctx.obj["cfg"]
    tools_mod.list_tools(cfg)


@tools.command("remove")
@click.argument("name")
@click.pass_context
def tools_remove(ctx: click.Context, name: str) -> None:
    """Remove a tool from the shared directory."""
    cfg: Config = ctx.obj["cfg"]
    tools_mod.remove(cfg, name)


# ─── iso ─────────────────────────────────────────────────────────────────────


@cli.group()
def iso() -> None:
    """Manage the Windows ISO."""
    pass


@iso.command("download")
@click.option("--force", "-f", is_flag=True, help="Re-download even if ISO exists.")
@click.pass_context
def iso_download(ctx: click.Context, force: bool) -> None:
    """Download the Windows Server 2022 Evaluation ISO (~5GB)."""
    cfg: Config = ctx.obj["cfg"]
    download_iso(cfg, force=force)


@iso.command("status")
@click.pass_context
def iso_status(ctx: click.Context) -> None:
    """Check if the Windows ISO is downloaded."""
    cfg: Config = ctx.obj["cfg"]
    path = cfg.iso_dir / ISO_FILENAME
    if path.exists():
        size = path.stat().st_size
        console.print(f"[green][+][/] ISO found: {path} ({human_size(size)})")
    else:
        console.print("[yellow][!][/] ISO not downloaded")
        console.print("    Run: [bold]winbox iso download[/]")


# ─── snapshot ────────────────────────────────────────────────────────────────


@cli.command()
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


# ─── restore ─────────────────────────────────────────────────────────────────


@cli.command()
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


# ─── provision ───────────────────────────────────────────────────────────────


@cli.command()
@click.pass_context
def provision(ctx: click.Context) -> None:
    """Re-run the provisioning script inside the VM."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)

    # Copy latest provision files to shared dir for guest access
    installer.copy_setup_files(cfg)

    console.print("[blue][*][/] Running provisioning script...")
    result = ga.exec_powershell_file("Z:\\tools\\provision.ps1", timeout=600)

    if result.stdout:
        console.print(result.stdout, end="", highlight=False)
    if result.stderr:
        console.print(result.stderr, end="", style="red", highlight=False)

    # Clean up provisioning files from shared tools dir
    for name in ("provision.ps1", "tools.txt", ".ssh_pubkey"):
        (cfg.tools_dir / name).unlink(missing_ok=True)

    if result.exitcode == 0:
        console.print("[green][+][/] Provisioning complete")
    else:
        console.print(f"[yellow][!][/] Provisioning exited with code {result.exitcode}")

    raise SystemExit(result.exitcode)


# ─── ssh ─────────────────────────────────────────────────────────────────────


@cli.command()
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
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
    ]
    if cfg.ssh_key.exists():
        ssh_args += ["-i", str(cfg.ssh_key)]

    ssh_args += [f"{cfg.vm_user}@{ip}", "powershell.exe"]

    # Use sshpass for automatic password auth if available
    if shutil.which("sshpass"):
        ssh_args = ["sshpass", "-p", cfg.vm_password] + ssh_args
        os.execvp("sshpass", ssh_args)
    else:
        os.execvp("ssh", ssh_args)
