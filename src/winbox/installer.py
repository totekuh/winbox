"""VM setup, installation, and provisioning."""

from __future__ import annotations

import importlib.resources
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console

from winbox.guest import GuestAgent
from winbox.vm import VM

if TYPE_CHECKING:
    from winbox.config import Config

console = Console()


def _data_file(name: str) -> Path:
    """Get path to a bundled data file."""
    return importlib.resources.files("winbox.data").joinpath(name)  # type: ignore[return-value]


REQUIRED_TOOLS = [
    "qemu-system-x86_64",
    "virsh",
    "virt-install",
    "jq",
]


def check_prereqs() -> list[str]:
    """Check for required system tools. Returns list of missing ones."""
    missing = []
    for tool in REQUIRED_TOOLS:
        if shutil.which(tool) is None:
            missing.append(tool)
    if not Path("/dev/kvm").exists():
        missing.append("/dev/kvm")
    return missing


def _find_mkisofs() -> str | None:
    """Find mkisofs or genisoimage."""
    for cmd in ("mkisofs", "genisoimage"):
        if shutil.which(cmd):
            return cmd
    return None


def create_directories(cfg: Config) -> None:
    """Create the winbox directory structure."""
    for d in [cfg.winbox_dir, cfg.iso_dir, cfg.tools_dir, cfg.loot_dir]:
        d.mkdir(parents=True, exist_ok=True)


def download_virtio_iso(cfg: Config) -> None:
    """Download VirtIO drivers ISO if not cached."""
    if cfg.virtio_iso.exists():
        console.print("[green][+][/] VirtIO ISO cached")
        return

    console.print("[blue][*][/] Downloading VirtIO drivers ISO...")
    subprocess.run(
        ["wget", "-q", "--show-progress", "-O", str(cfg.virtio_iso), cfg.virtio_iso_url],
        check=True,
    )
    console.print("[green][+][/] VirtIO ISO downloaded")


def generate_ssh_keypair(cfg: Config) -> None:
    """Generate an ED25519 SSH keypair for fallback access."""
    if cfg.ssh_key.exists():
        console.print("[green][+][/] SSH keypair exists")
        return

    console.print("[blue][*][/] Generating SSH keypair...")
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(cfg.ssh_key), "-N", "", "-q"],
        check=True,
    )
    console.print("[green][+][/] SSH keypair created")

    # Copy pubkey to shared tools for provisioning
    shutil.copy2(cfg.ssh_pubkey, cfg.tools_dir / ".ssh_pubkey")


def copy_setup_files(cfg: Config) -> None:
    """Copy provisioning files to shared tools directory."""
    for name in ("provision.ps1", "tools.txt"):
        src = _data_file(name)
        dst = cfg.tools_dir / name
        dst.write_bytes(Path(src).read_bytes())


def build_unattend_image(cfg: Config) -> None:
    """Build an ISO image containing autounattend.xml."""
    mkisofs = _find_mkisofs()
    if mkisofs is None:
        raise RuntimeError(
            "Neither mkisofs nor genisoimage found. "
            "Install with: apt install genisoimage"
        )

    console.print("[blue][*][/] Building unattend image...")
    with tempfile.TemporaryDirectory() as tmpdir:
        src = _data_file("unattend.xml")
        dst = Path(tmpdir) / "autounattend.xml"
        dst.write_bytes(Path(src).read_bytes())

        subprocess.run(
            [mkisofs, "-o", str(cfg.unattend_img), "-J", "-r", tmpdir],
            capture_output=True,
            check=True,
        )
    console.print("[green][+][/] Unattend image created")


def create_disk(cfg: Config) -> None:
    """Create the QCOW2 disk image."""
    console.print(f"[blue][*][/] Creating VM disk ({cfg.vm_disk}GB)...")
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", str(cfg.disk_path), f"{cfg.vm_disk}G"],
        capture_output=True,
        check=True,
    )
    console.print("[green][+][/] Disk created")


def run_virt_install(cfg: Config, windows_iso: str) -> None:
    """Run virt-install to create and boot the VM."""
    console.print("[blue][*][/] Installing Windows VM (this takes ~10-15 minutes)...")
    console.print(f"    Monitor with: virsh console {cfg.vm_name}")
    console.print()

    cmd = [
        "virt-install",
        "--name", cfg.vm_name,
        "--ram", str(cfg.vm_ram),
        "--vcpus", str(cfg.vm_cpus),
        "--disk", f"path={cfg.disk_path},bus=virtio",
        "--cdrom", windows_iso,
        "--disk", f"{cfg.virtio_iso},device=cdrom",
        "--disk", f"{cfg.unattend_img},device=cdrom",
        "--network", f"bridge={cfg.vm_bridge},model=virtio",
        "--channel", "unix,target.type=virtio,target.name=org.qemu.guest_agent.0",
        "--memorybacking", "source.type=memfd,access.mode=shared",
        "--filesystem", (
            f"type=mount,driver.type=virtiofs,"
            f"source.dir={cfg.shared_dir},target.dir=winbox_share"
        ),
        "--os-variant", "win2k22",
        "--graphics", "none",
        "--noautoconsole",
        "--boot", "uefi",
    ]

    subprocess.run(cmd, check=True)
    console.print("[green][+][/] VM installation started")


def wait_for_install(cfg: Config, timeout: int = 1200) -> bool:
    """Wait for Windows installation to complete (guest agent becomes available).

    Returns True if the guest agent responded within timeout.
    """
    console.print("[blue][*][/] Waiting for Windows installation to complete...")
    console.print("    This will take 10-15 minutes.")
    console.print()

    ga = GuestAgent(cfg)
    import time

    elapsed = 0
    while not ga.ping():
        time.sleep(10)
        elapsed += 10
        if elapsed >= timeout:
            return False
        print(f"\r    {elapsed}/{timeout}s elapsed...", end="", flush=True)

    print()
    console.print("[green][+][/] Windows installed — guest agent responding")
    return True


def provision(cfg: Config) -> int:
    """Run the provisioning script inside the VM. Returns exit code."""
    ga = GuestAgent(cfg)

    console.print("[blue][*][/] Running provisioning script...")
    result = ga.exec_powershell_file("Z:\\tools\\provision.ps1", timeout=600)

    if result.stdout:
        console.print(result.stdout, end="", highlight=False)
    if result.stderr:
        console.print(result.stderr, end="", style="red", highlight=False)

    if result.exitcode == 0:
        console.print("[green][+][/] Provisioning complete")
    else:
        console.print(f"[yellow][!][/] Provisioning exited with code {result.exitcode}")

    return result.exitcode


def create_clean_snapshot(cfg: Config) -> None:
    """Create a 'clean' snapshot after setup."""
    vm = VM(cfg)
    console.print("[blue][*][/] Creating 'clean' snapshot...")
    try:
        vm.snapshot_create("clean")
        console.print("[green][+][/] Snapshot 'clean' created")
    except subprocess.CalledProcessError:
        console.print("[yellow][!][/] Could not create snapshot")
