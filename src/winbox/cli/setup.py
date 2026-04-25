"""Setup and provisioning commands."""

from __future__ import annotations

import fcntl
import subprocess
import time
from pathlib import Path

import click

from winbox.setup import installer
from winbox.cli import console, ensure_running
from winbox.config import Config
from winbox.vm import GuestAgent
from winbox.setup.iso import ISO_FILENAME, download_iso
from winbox.vm import VM


@click.command()
@click.option(
    "--iso", "windows_iso",
    type=click.Path(exists=True),
    help="Path to Windows Server 2022 ISO.",
)
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts.")
@click.option(
    "--desktop", is_flag=True,
    help="Install Desktop Experience instead of Server Core (needed for Office/GUI apps).",
)
@click.pass_context
def setup(ctx: click.Context, windows_iso: str | None, yes: bool, desktop: bool) -> None:
    """Build the Windows VM (one-time setup)."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)

    # Serialize concurrent `winbox setup` runs. We hit a race earlier where a
    # backgrounded setup fought a manual one over disk.qcow2 — this lock makes
    # that impossible. The lock is held for the entire setup lifetime by keeping
    # lock_fh alive as a local; Python releases it when setup() returns (normal
    # exit) or when the stack unwinds (exception propagation).
    cfg.winbox_dir.mkdir(parents=True, exist_ok=True)
    lock_path = cfg.winbox_dir / ".setup.lock"
    lock_fh = open(lock_path, "w")
    try:
        fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_fh.close()
        console.print(
            "[red][-][/] Another [bold]winbox setup[/] is already running.\n"
            f"    Lock file: {lock_path}\n"
            "    If you're sure no other setup is running, delete the lock file and retry."
        )
        raise SystemExit(1)

    console.print("[bold]winbox setup[/] — building Windows VM\n")
    t0 = time.monotonic()

    # Check prereqs
    missing = installer.check_prereqs()
    if missing:
        console.print(f"[red][-][/] Missing: {', '.join(missing)}")
        console.print(
            "    Install with: [bold]apt install "
            "qemu-system-x86 qemu-utils libvirt-daemon-system virtinst "
            "libguestfs-tools virtiofsd p7zip-full genisoimage wget[/]"
        )
        raise SystemExit(1)

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

    # The four-phase pipeline. If any phase fails (or the user hits Ctrl-C),
    # the VM, disk, and unattend image may be in a half-built state that
    # would confuse the next run. Wrap the whole pipeline so we surface a
    # clean error and a single recovery command instead of a CalledProcessError
    # traceback or worse, a partially-defined libvirt domain.
    try:
        # Phase 1: ISO install
        installer.create_directories(cfg)
        installer.grant_libvirt_access(cfg)
        installer.download_virtio_iso(cfg)
        installer.download_openssh(cfg)
        installer.download_winfsp(cfg)
        installer.download_python(cfg)
        installer.download_x64dbg(cfg)
        installer.extract_virtiofs(cfg)
        installer.generate_ssh_keypair(cfg)
        installer.build_unattend_image(cfg, desktop=desktop)
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

        # Pre-register the libvirt nwfilter used by `winbox net isolate`, then
        # attach it to the persistent domain config so the VM boots isolated by
        # default. Runs while the VM is shut down (end of Phase 3).
        installer.register_nwfilter(cfg)
        installer.attach_default_filter(cfg)

        # Phase 4: Snapshot
        installer.create_clean_snapshot(cfg)
    except KeyboardInterrupt:
        console.print()
        console.print("[yellow][!][/] Setup interrupted by user.")
        console.print(
            f"    Partial state may remain. Clean up with "
            f"[bold]winbox destroy -y[/], then re-run [bold]winbox setup[/]."
        )
        raise SystemExit(130)
    except (subprocess.CalledProcessError, RuntimeError) as e:
        console.print()
        console.print(f"[red][-][/] Setup failed: {e}")
        console.print(
            f"    The VM may be partially built. Clean up with "
            f"[bold]winbox destroy -y[/] before re-running [bold]winbox setup[/]."
        )
        raise SystemExit(1)

    elapsed = time.monotonic() - t0
    minutes, seconds = divmod(int(elapsed), 60)
    console.print(f"\n[green][+][/] [bold]winbox setup complete![/] ({minutes}m {seconds}s)\n")
    console.print("  [bold]Quick start:[/]")
    console.print('    winbox exec cmd.exe /c "echo hello"')
    console.print("    winbox exec SharpHound.exe --help")
    console.print("    winbox suspend")


@click.command()
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
        console.print(result.stdout, end="", markup=False, highlight=False)
    if result.stderr:
        console.print(result.stderr, end="", markup=False, style="red", highlight=False)

    # Clean up provisioning files from shared tools dir
    for name in ("provision.ps1", ".ssh_pubkey"):
        (cfg.tools_dir / name).unlink(missing_ok=True)

    if result.exitcode == 0:
        console.print("[green][+][/] Provisioning complete")
    else:
        console.print(f"[yellow][!][/] Provisioning exited with code {result.exitcode}")
        raise SystemExit(result.exitcode)
