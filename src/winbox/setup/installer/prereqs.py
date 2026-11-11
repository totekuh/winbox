"""System prerequisites, network, access control, directory and key setup."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console

from winbox import data as _data
from winbox.vm import virsh_run

if TYPE_CHECKING:
    from winbox.config import Config

console = Console()


REQUIRED_TOOLS = [
    "qemu-system-x86_64",
    "qemu-img",
    "virsh",
    "virt-install",
    # Offline provisioning uses guestfish directly, not virt-customize:
    # virt-customize auto-inspects the guest OS, and inspection fails on the
    # Win11 install image. Without this entry a missing guestfish surfaced as
    # a raw FileNotFoundError from deep inside phase 2 instead of the
    # prereq list.
    "guestfish",
    # The other half of the offline-registry machinery. It ships in a
    # *different* package from guestfish (libwin-hivex-perl vs
    # libguestfs-tools, and the latter does not depend on it), so
    # "guestfish present, hivexregedit absent" is the normal state of a host
    # that installed exactly what the setup command tells it to. Missing it
    # used to surface ~40 minutes into a win11 build, as a best-effort
    # warning during phase 2 that left Defender fully armed and failed the
    # build two phases later for an apparently unrelated reason.
    "hivexregedit",
    "7z",
    "wget",
]

# Tools whose apt package name isn't guessable from the binary name. Reported
# alongside the tool so the "Missing: ..." line is actually actionable.
TOOL_PACKAGES = {"hivexregedit": "libwin-hivex-perl"}

# Tools only some guest profiles need, and the profile flag that decides.
# Offline hive edits are how a client SKU's Defender gets disabled; Server
# 2022 never takes that path, so it shouldn't be blocked on the package.
PROFILE_GATED_TOOLS = {"hivexregedit": "disable_defender_offline"}

# virtiofsd is installed to /usr/libexec on Debian/Kali, not on PATH
VIRTIOFSD_PATHS = ["/usr/libexec/virtiofsd", "/usr/lib/qemu/virtiofsd"]


def _tool_required(tool: str, cfg: Config | None) -> bool:
    """Is ``tool`` needed for the build ``cfg`` describes?

    Without a cfg we cannot know which guest is about to be built, so every
    gated tool counts as required: over-reporting costs one apt install,
    under-reporting costs a 40-minute build that quietly comes out wrong.
    """
    flag = PROFILE_GATED_TOOLS.get(tool)
    if flag is None or cfg is None:
        return True
    return bool(getattr(cfg.profile, flag))


def check_prereqs(cfg: Config | None = None) -> list[str]:
    """Check for required system tools. Returns list of missing ones.

    Pass ``cfg`` to scope the check to the guest actually being built;
    profile-gated tools are otherwise all assumed necessary.
    """
    missing = []
    for tool in REQUIRED_TOOLS:
        if not _tool_required(tool, cfg):
            continue
        if shutil.which(tool) is None:
            package = TOOL_PACKAGES.get(tool)
            missing.append(f"{tool} (apt install {package})" if package else tool)
    if not shutil.which("virtiofsd") and not any(Path(p).exists() for p in VIRTIOFSD_PATHS):
        missing.append("virtiofsd")
    if not Path("/dev/kvm").exists():
        missing.append("/dev/kvm")
    return missing


def ensure_default_network() -> None:
    """Ensure the libvirt 'default' network exists and is active."""
    # Check if network is active
    result = virsh_run("net-list", "--name", check=False)
    if result.returncode == 0 and "default" in result.stdout.split():
        return

    # Try to start it (might be defined but inactive)
    start = virsh_run("net-start", "default", check=False)
    if start.returncode == 0:
        virsh_run("net-autostart", "default", check=False)
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

    define = virsh_run("net-define", str(default_xml), check=False)
    if define.returncode != 0:
        raise RuntimeError(
            f"Failed to define default network: {define.stderr.strip()}\n"
            "    Fix with: sudo virsh net-define /usr/share/libvirt/networks/default.xml "
            "&& sudo virsh net-start default && sudo virsh net-autostart default"
        )

    virsh_run("net-start", "default")
    virsh_run("net-autostart", "default", check=False)
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
    while path != Path.home() and path != path.parent:
        dirs.append(path)
        path = path.parent
    # Include home dir itself
    dirs.append(Path.home())

    acl_ok = True
    for d in dirs:
        r = subprocess.run(
            ["setfacl", "-m", "u:libvirt-qemu:x", str(d)],
            capture_output=True, check=False,
        )
        if r.returncode != 0:
            acl_ok = False

    # Grant read+traverse on subdirs that contain VM files
    for d in [cfg.winbox_dir, cfg.iso_dir]:
        if d.exists():
            subprocess.run(
                ["setfacl", "-m", "u:libvirt-qemu:rx", str(d)],
                capture_output=True, check=False,
            )

    # virtiofsd needs full rwx on the shared directory tree
    for d in [cfg.shared_dir, cfg.tools_dir, cfg.loot_dir]:
        if d.exists():
            subprocess.run(
                ["setfacl", "-R", "-m", "u:libvirt-qemu:rwx", str(d)],
                capture_output=True, check=False,
            )
            subprocess.run(
                ["setfacl", "-R", "-d", "-m", "u:libvirt-qemu:rwx", str(d)],
                capture_output=True, check=False,
            )

    if acl_ok:
        console.print("[green][+][/] Granted libvirt-qemu access to ~/.winbox")
    else:
        console.print("[yellow][!][/] Some ACL operations failed — VirtIO-FS may not work")
        console.print("    Check QEMU user with: ps aux | grep qemu")


def create_directories(cfg: Config) -> None:
    """Create the winbox directory structure."""
    for d in [cfg.winbox_dir, cfg.iso_dir, cfg.tools_dir, cfg.loot_dir]:
        d.mkdir(parents=True, exist_ok=True)


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
    from winbox.setup.installer.downloads import RUNEX_EXE, download_runex

    src = _data.path("provision.ps1")
    dst = cfg.tools_dir / "provision.ps1"
    dst.write_bytes(Path(src).read_bytes())
    runex = download_runex(cfg)
    shutil.copy2(runex, cfg.tools_dir / RUNEX_EXE)
    # Copy SSH pubkey so provision.ps1 can find it at Z:\tools\.ssh_pubkey
    if cfg.ssh_pubkey.exists():
        shutil.copy2(cfg.ssh_pubkey, cfg.tools_dir / ".ssh_pubkey")
