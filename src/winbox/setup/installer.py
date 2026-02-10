"""VM setup, installation, and provisioning."""

from __future__ import annotations

import importlib.resources
import os
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console

from winbox.vm import VM

if TYPE_CHECKING:
    from winbox.config import Config

console = Console()


def _data_file(name: str) -> Path:
    """Get path to a bundled data file."""
    return importlib.resources.files("winbox.data").joinpath(name)  # type: ignore[return-value]


def run(cmd: list[str], *, check: bool = True, **kwargs) -> subprocess.CompletedProcess[str]:
    """Run a shell command with text output."""
    return subprocess.run(cmd, text=True, check=check, **kwargs)


REQUIRED_TOOLS = [
    "qemu-system-x86_64",
    "virsh",
    "virt-install",
    "virt-customize",
    "jq",
    "impacket-smbserver",
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


def ensure_default_network() -> None:
    """Ensure the libvirt 'default' network exists and is active."""
    # Check if network is active
    result = subprocess.run(
        ["virsh", "-c", "qemu:///system", "net-info", "default"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode == 0 and "Active:         yes" in result.stdout:
        return

    # Try to start it (might be defined but inactive)
    start = subprocess.run(
        ["virsh", "-c", "qemu:///system", "net-start", "default"],
        capture_output=True, text=True, check=False,
    )
    if start.returncode == 0:
        subprocess.run(
            ["virsh", "-c", "qemu:///system", "net-autostart", "default"],
            capture_output=True, text=True, check=False,
        )
        console.print("[green][+][/] Started libvirt default network")
        return

    # Not defined — try to define from system default XML
    default_xml = Path("/usr/share/libvirt/networks/default.xml")
    if not default_xml.exists():
        raise RuntimeError(
            "Libvirt 'default' network not found and no default.xml to create it.\n"
            "    Fix with: sudo virsh net-define /usr/share/libvirt/networks/default.xml "
            "&& sudo virsh net-start default && sudo virsh net-autostart default"
        )

    define = subprocess.run(
        ["virsh", "-c", "qemu:///system", "net-define", str(default_xml)],
        capture_output=True, text=True, check=False,
    )
    if define.returncode != 0:
        raise RuntimeError(
            f"Failed to define default network: {define.stderr.strip()}\n"
            "    Fix with: sudo virsh net-define /usr/share/libvirt/networks/default.xml "
            "&& sudo virsh net-start default && sudo virsh net-autostart default"
        )

    subprocess.run(
        ["virsh", "-c", "qemu:///system", "net-start", "default"],
        capture_output=True, text=True, check=True,
    )
    subprocess.run(
        ["virsh", "-c", "qemu:///system", "net-autostart", "default"],
        capture_output=True, text=True, check=False,
    )
    console.print("[green][+][/] Created and started libvirt default network")


def _find_mkisofs() -> str | None:
    """Find mkisofs or genisoimage."""
    for cmd in ("mkisofs", "genisoimage"):
        if shutil.which(cmd):
            return cmd
    return None


def grant_libvirt_access(cfg: Config) -> None:
    """Grant libvirt-qemu traverse/read access to winbox directories via ACL."""
    if not shutil.which("setfacl"):
        raise RuntimeError(
            "setfacl not found. Install with: apt install acl\n"
            "    Or manually: setfacl -m u:libvirt-qemu:x ~/.winbox"
        )

    # Grant traverse (x) on each parent dir up to and including ~/.winbox
    # so libvirt-qemu can reach the files inside
    dirs = []
    path = cfg.winbox_dir
    while path != Path.home().parent:
        dirs.append(path)
        path = path.parent
    # Include home dir itself
    dirs.append(Path.home())

    for d in dirs:
        subprocess.run(
            ["setfacl", "-m", "u:libvirt-qemu:x", str(d)],
            capture_output=True, check=False,
        )

    # Grant read+traverse on subdirs that contain VM files
    for d in [cfg.winbox_dir, cfg.iso_dir, cfg.shared_dir, cfg.tools_dir, cfg.loot_dir]:
        if d.exists():
            subprocess.run(
                ["setfacl", "-m", "u:libvirt-qemu:rx", str(d)],
                capture_output=True, check=False,
            )

    console.print("[green][+][/] Granted libvirt-qemu access to ~/.winbox")


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


def copy_setup_files(cfg: Config) -> None:
    """Copy provisioning files to shared tools directory (for re-provisioning)."""
    for name in ("provision.ps1", "tools.txt"):
        src = _data_file(name)
        dst = cfg.tools_dir / name
        dst.write_bytes(Path(src).read_bytes())
    # Copy SSH pubkey so provision.ps1 can find it at Z:\tools\.ssh_pubkey
    if cfg.ssh_pubkey.exists():
        shutil.copy2(cfg.ssh_pubkey, cfg.tools_dir / ".ssh_pubkey")


def build_unattend_image(cfg: Config) -> None:
    """Build an ISO image containing autounattend.xml."""
    mkisofs = _find_mkisofs()
    if mkisofs is None:
        raise RuntimeError(
            "Neither mkisofs nor genisoimage found. "
            "Install with: apt install genisoimage"
        )

    # Remove stale image (may be owned by libvirt-qemu from previous run)
    if cfg.unattend_img.exists():
        try:
            cfg.unattend_img.unlink()
        except PermissionError:
            subprocess.run(["rm", "-f", str(cfg.unattend_img)], check=False)

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
    """Run virt-install to create and boot the VM for Phase 1 (ISO install)."""
    ensure_default_network()
    console.print("[blue][*][/] Installing Windows VM (this takes ~10-15 minutes)...")
    console.print(f"    Monitor with: virsh console {cfg.vm_name}")
    console.print()

    cmd = [
        "virt-install",
        "--connect", "qemu:///system",
        "--name", cfg.vm_name,
        "--ram", str(cfg.vm_ram),
        "--vcpus", str(cfg.vm_cpus),
        "--disk", f"path={cfg.disk_path},bus=sata",
        "--cdrom", windows_iso,
        "--disk", f"{cfg.unattend_img},device=cdrom",
        "--disk", f"{cfg.virtio_iso},device=cdrom",
        "--network", "network=default,model=e1000",
        "--channel", "unix,target.type=virtio,target.name=org.qemu.guest_agent.0",
        "--os-variant", "win2k22",
        "--graphics", "vnc,listen=127.0.0.1",
        "--noautoconsole",
        "--boot", "uefi",
    ]

    subprocess.run(cmd, check=True)
    console.print("[green][+][/] VM installation started")

    # UEFI shows "Press any key to boot from CD or DVD..." — send keypresses
    console.print("[blue][*][/] Sending boot keystroke...")
    for _ in range(5):
        time.sleep(3)
        result = subprocess.run(
            ["virsh", "-c", "qemu:///system", "send-key", cfg.vm_name, "KEY_ENTER"],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            break


def provision_vm_disk(cfg: Config) -> None:
    """Phase 2: Inject provision files into disk image via virt-customize."""
    console.print("[blue][*][/] Preparing provision payload...")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        # Build provision.zip containing provision.ps1, tools.txt, .ssh_pubkey
        zip_path = tmpdir_path / "provision.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for name in ("provision.ps1", "tools.txt"):
                src = _data_file(name)
                zf.write(src, name)
            if cfg.ssh_pubkey.exists():
                zf.write(cfg.ssh_pubkey, ".ssh_pubkey")

        # Copy bootstrap.ps1 to temp dir
        bootstrap_src = _data_file("bootstrap.ps1")
        bootstrap_tmp = tmpdir_path / "bootstrap.ps1"
        bootstrap_tmp.write_bytes(Path(bootstrap_src).read_bytes())

        console.print("[blue][*][/] Injecting provision files into disk image...")
        env = {**os.environ, "LIBGUESTFS_BACKEND": "direct"}
        run([
            "virt-customize",
            "-a", str(cfg.disk_path),
            "--upload", f"{zip_path}:/provision.zip",
            "--upload", f"{bootstrap_tmp}:/bootstrap.ps1",
        ], env=env)

    console.print("[green][+][/] Provision files injected")


def boot_for_provisioning(cfg: Config) -> None:
    """Phase 3: Boot VM, run bootstrap.ps1 via guest agent, wait for shutdown.

    Starts SMB server (so guest can map Z:), boots VM, waits for guest agent,
    then triggers bootstrap.ps1 which runs provisioning and shuts down.
    """
    from winbox.vm import smb
    from winbox.vm import GuestAgent

    smb.start(cfg)

    console.print("[blue][*][/] Booting VM for provisioning...")
    vm = VM(cfg)
    vm.start()

    console.print("[blue][*][/] Waiting for guest agent...")
    ga = GuestAgent(cfg)
    ga.wait(timeout=180)
    console.print("[green][+][/] Guest agent responding")

    console.print("[blue][*][/] Running bootstrap.ps1 via guest agent...")
    console.print("    This may take 5-10 minutes.")
    ga.exec_detached(
        'powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\\bootstrap.ps1',
    )

    console.print("[blue][*][/] Waiting for VM to shut down...")
    if not vm.wait_shutdown(timeout=600):
        console.print("[yellow][!][/] Provisioning timed out (VM did not shut down in 600s)")
        console.print(f"    Check with: virsh console {cfg.vm_name}")
        raise RuntimeError("Provisioning timed out")

    smb.stop(cfg)
    console.print("[green][+][/] Provisioning complete")


def create_clean_snapshot(cfg: Config) -> None:
    """Create a 'clean' snapshot after setup."""
    vm = VM(cfg)
    console.print("[blue][*][/] Creating 'clean' snapshot...")
    try:
        vm.snapshot_create("clean")
        console.print("[green][+][/] Snapshot 'clean' created")
    except subprocess.CalledProcessError:
        console.print("[yellow][!][/] Could not create snapshot")
