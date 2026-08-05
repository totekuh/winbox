"""VM setup, installation, and provisioning."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console

from winbox import data as _data
from winbox.vm import VM, VMState, GuestAgent, GuestAgentError, virsh_run

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
    "7z",
    "wget",
]

# virtiofsd is installed to /usr/libexec on Debian/Kali, not on PATH
VIRTIOFSD_PATHS = ["/usr/libexec/virtiofsd", "/usr/lib/qemu/virtiofsd"]


def check_prereqs() -> list[str]:
    """Check for required system tools. Returns list of missing ones."""
    missing = []
    for tool in REQUIRED_TOOLS:
        if shutil.which(tool) is None:
            missing.append(tool)
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


def download_virtio_iso(cfg: Config) -> None:
    """Download VirtIO drivers ISO if not cached."""
    if cfg.virtio_iso.exists() and cfg.virtio_iso.stat().st_size > 500_000_000:
        console.print("[green][+][/] VirtIO ISO cached")
        return

    console.print("[blue][*][/] Downloading VirtIO drivers ISO...")
    subprocess.run(
        ["wget", "-q", "--show-progress", "-O", str(cfg.virtio_iso), cfg.virtio_iso_url],
        check=True,
    )
    if not cfg.virtio_iso.exists() or cfg.virtio_iso.stat().st_size < 500_000_000:
        raise RuntimeError(f"VirtIO ISO download appears truncated: {cfg.virtio_iso}")
    console.print("[green][+][/] VirtIO ISO downloaded")


OPENSSH_URL = (
    "https://github.com/PowerShell/Win32-OpenSSH/releases/latest/download/OpenSSH-Win64.zip"
)
OPENSSH_ZIP = "OpenSSH-Win64.zip"

WINFSP_URL = (
    "https://github.com/winfsp/winfsp/releases/download/v2.1/winfsp-2.1.25156.msi"
)
WINFSP_MSI = "winfsp.msi"

PYTHON_URL = "https://www.python.org/ftp/python/3.13.13/python-3.13.13-amd64.exe"
PYTHON_EXE = "python-3.13.13-amd64.exe"

# Windows 11 can't run the Python WiX *bundle* installer under the SYSTEM /
# session-0 context the guest agent provides (it deadlocks / returns 1601 —
# single MSIs like WinFsp are fine, only the Burn bootstrapper breaks). The
# embeddable distribution is a plain zip with no installer, so provision.ps1
# extracts it on client SKUs instead. Same version as PYTHON_EXE.
PYTHON_EMBED_URL = "https://www.python.org/ftp/python/3.13.13/python-3.13.13-embed-amd64.zip"
PYTHON_EMBED_ZIP = "python-3.13.13-embed-amd64.zip"

X64DBG_URL = (
    "https://github.com/x64dbg/x64dbg/releases/download/2025.08.19/"
    "snapshot_2025-08-19_19-40.zip"
)
X64DBG_ZIP = "x64dbg.zip"

PROVISION_SENTINEL = "C:\\winbox-provisioned.ok"
BOOTSTRAP_LOG = "C:\\winbox-bootstrap.log"


def download_openssh(cfg: Config) -> Path:
    """Download Win32-OpenSSH zip if not cached. Returns path to zip."""
    dest = cfg.iso_dir / OPENSSH_ZIP
    if dest.exists() and dest.stat().st_size > 5_000_000:
        console.print("[green][+][/] OpenSSH zip cached")
        return dest

    console.print("[blue][*][/] Downloading OpenSSH for Windows...")
    subprocess.run(
        ["wget", "-q", "--show-progress", "-O", str(dest), OPENSSH_URL],
        check=True,
    )
    if not dest.exists() or dest.stat().st_size < 5_000_000:
        raise RuntimeError(f"OpenSSH download appears truncated: {dest}")
    console.print("[green][+][/] OpenSSH zip downloaded")
    return dest


def download_winfsp(cfg: Config) -> Path:
    """Download WinFsp MSI if not cached. Returns path to MSI."""
    dest = cfg.iso_dir / WINFSP_MSI
    if dest.exists() and dest.stat().st_size > 1_000_000:
        console.print("[green][+][/] WinFsp MSI cached")
        return dest

    console.print("[blue][*][/] Downloading WinFsp...")
    subprocess.run(
        ["wget", "-q", "--show-progress", "-O", str(dest), WINFSP_URL],
        check=True,
    )
    if not dest.exists() or dest.stat().st_size < 1_000_000:
        raise RuntimeError(f"WinFsp download appears truncated: {dest}")
    console.print("[green][+][/] WinFsp MSI downloaded")
    return dest


def download_python(cfg: Config) -> Path:
    """Download the regular Python Windows installer if not cached."""
    dest = cfg.iso_dir / PYTHON_EXE
    if dest.exists() and dest.stat().st_size > 20_000_000:
        console.print("[green][+][/] Python installer cached")
        return dest

    console.print("[blue][*][/] Downloading Python installer...")
    subprocess.run(
        ["wget", "-q", "--show-progress", "-O", str(dest), PYTHON_URL],
        check=True,
    )
    if not dest.exists() or dest.stat().st_size < 20_000_000:
        raise RuntimeError(f"Python installer download appears truncated: {dest}")
    console.print("[green][+][/] Python installer downloaded")
    return dest


def download_python_embed(cfg: Config) -> Path:
    """Download the Python embeddable zip (used on Win11) if not cached."""
    dest = cfg.iso_dir / PYTHON_EMBED_ZIP
    if dest.exists() and dest.stat().st_size > 5_000_000:
        console.print("[green][+][/] Python embeddable cached")
        return dest

    console.print("[blue][*][/] Downloading Python embeddable...")
    subprocess.run(
        ["wget", "-q", "--show-progress", "-O", str(dest), PYTHON_EMBED_URL],
        check=True,
    )
    if not dest.exists() or dest.stat().st_size < 5_000_000:
        raise RuntimeError(f"Python embeddable download appears truncated: {dest}")
    console.print("[green][+][/] Python embeddable downloaded")
    return dest


def download_x64dbg(cfg: Config) -> Path:
    """Download the x64dbg snapshot zip if not cached."""
    dest = cfg.iso_dir / X64DBG_ZIP
    if dest.exists() and dest.stat().st_size > 20_000_000:
        console.print("[green][+][/] x64dbg zip cached")
        return dest

    console.print("[blue][*][/] Downloading x64dbg...")
    subprocess.run(
        ["wget", "-q", "--show-progress", "-O", str(dest), X64DBG_URL],
        check=True,
    )
    if not dest.exists() or dest.stat().st_size < 20_000_000:
        raise RuntimeError(f"x64dbg download appears truncated: {dest}")
    console.print("[green][+][/] x64dbg downloaded")
    return dest


# Arcname of virtiofs.exe inside provision.zip (what provision.ps1 expects).
VIRTIOFS_EXE = "virtiofs.exe"


def _virtiofs_iso_member(cfg: Config) -> str:
    """Path of virtiofs.exe inside the virtio-win ISO, per active OS profile."""
    return f"viofs/{cfg.profile.virtio_subdir}/amd64/virtiofs.exe"


def _virtiofs_cache_path(cfg: Config) -> Path:
    """Host cache path for the extracted virtiofs.exe.

    Namespaced by VirtIO subdir so a Server (``2k22``) cache is never reused
    for a Win11 (``w11``) build when the ISO dir survives a destroy/rebuild.
    """
    return cfg.iso_dir / f"virtiofs-{cfg.profile.virtio_subdir}.exe"


def extract_virtiofs(cfg: Config) -> Path:
    """Extract virtiofs.exe from the VirtIO ISO. Returns path to extracted exe."""
    dest = _virtiofs_cache_path(cfg)
    if dest.exists():
        console.print("[green][+][/] virtiofs.exe cached")
        return dest

    console.print("[blue][*][/] Extracting virtiofs.exe from VirtIO ISO...")
    # `7z e` flattens to the basename; extract into a temp dir then move to
    # the subdir-namespaced cache path so 2k22 and w11 don't collide.
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            ["7z", "e", str(cfg.virtio_iso), f"-o{tmp}", _virtiofs_iso_member(cfg), "-y"],
            capture_output=True, check=True,
        )
        extracted = Path(tmp) / "virtiofs.exe"
        if not extracted.exists():
            raise RuntimeError(
                f"virtiofs.exe not found in VirtIO ISO at {_virtiofs_iso_member(cfg)}"
            )
        shutil.move(str(extracted), str(dest))
    console.print("[green][+][/] virtiofs.exe extracted")
    return dest


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
    src = _data.path("provision.ps1")
    dst = cfg.tools_dir / "provision.ps1"
    dst.write_bytes(Path(src).read_bytes())
    # Copy SSH pubkey so provision.ps1 can find it at Z:\tools\.ssh_pubkey
    if cfg.ssh_pubkey.exists():
        shutil.copy2(cfg.ssh_pubkey, cfg.tools_dir / ".ssh_pubkey")


# LabConfig bypass keys injected in the WinPE pass for Win11 so setup
# proceeds without TPM 2.0 / Secure Boot / the RAM/storage/CPU gates.
# Emitted into the {LABCONFIG_BLOCK} placeholder of unattend.xml; empty
# for Server 2022 (whose rendered XML is then byte-identical to before).
_LABCONFIG_KEYS = (
    "BypassTPMCheck",
    "BypassSecureBootCheck",
    "BypassRAMCheck",
    "BypassStorageCheck",
    "BypassCPUCheck",
)


def _specialize_deploy_block() -> str:
    """Microsoft-Windows-Deployment RunSynchronous for the specialize pass.

    Runs on first boot before OOBE, so the registry keys are in place before
    Win11 would auto-enable Device Encryption or stop OOBE on the network
    screen:
      * BitLocker\\PreventDeviceEncryption = 1 — never auto-encrypt the OS
        drive (we have no TPM, and encryption breaks offline provisioning /
        memory + kernel analysis).
      * OOBE\\BypassNRO = 1 — let OOBE proceed without a network / Microsoft
        account (Win11 24H2+ otherwise blocks on "Let's connect you to a
        network").
    (Defender is handled separately, in the offline SYSTEM hive — Tamper
    Protection ignores these specialize-pass reg writes.)
    Emitted into {SPECIALIZE_DEPLOY_BLOCK}; empty for Server 2022.
    """
    cmds = [
        r"reg add HKLM\SYSTEM\CurrentControlSet\Control\BitLocker "
        r"/v PreventDeviceEncryption /t REG_DWORD /d 1 /f",
        r"reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE "
        r"/v BypassNRO /t REG_DWORD /d 1 /f",
    ]
    lines = [
        "",
        "",
        '    <component name="Microsoft-Windows-Deployment"',
        '               processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"',
        '               language="neutral" versionScope="nonSxS"',
        '               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">',
        "      <RunSynchronous>",
    ]
    for order, cmd in enumerate(cmds, start=1):
        lines.append('        <RunSynchronousCommand wcm:action="add">')
        lines.append(f"          <Order>{order}</Order>")
        lines.append(f"          <Path>{cmd}</Path>")
        lines.append("        </RunSynchronousCommand>")
    lines.append("      </RunSynchronous>")
    lines.append("    </component>")
    return "\n".join(lines)


def _labconfig_block() -> str:
    """Render the <RunSynchronous> LabConfig-bypass block for the WinPE pass.

    Returned string leads with a blank line so it substitutes inline right
    after ``</DiskConfiguration>`` (the ``{LABCONFIG_BLOCK}`` placeholder);
    an empty value leaves the Server 2022 XML byte-identical.
    """
    lines = [
        "",
        "",
        "      <RunSynchronous>",
    ]
    for order, key in enumerate(_LABCONFIG_KEYS, start=1):
        lines.append('        <RunSynchronousCommand wcm:action="add">')
        lines.append(f"          <Order>{order}</Order>")
        lines.append(
            "          <Path>reg add HKLM\\System\\Setup\\LabConfig /v "
            f"{key} /t REG_DWORD /d 1 /f</Path>"
        )
        lines.append("        </RunSynchronousCommand>")
    lines.append("      </RunSynchronous>")
    return "\n".join(lines)


def _disk_partitions_block(cfg: Config) -> str:
    """Render the <CreatePartitions>/<ModifyPartitions> XML for the profile's
    UEFI/GPT disk layout.

    Server 2022 uses a minimal ESP + Windows layout (2 partitions). Windows 11
    Setup rejects that with "error selecting this partition for install" and
    needs the standard ESP + MSR + Windows layout, so ``include_msr`` inserts
    the Microsoft Reserved partition (unformatted) and pushes Windows to
    partition 3. ``esp_size_mb`` sizes the EFI System Partition (Win11 wants a
    larger ESP than the 100 MB that satisfies Server).
    """
    p = cfg.profile
    create: list[str] = []
    modify: list[str] = []
    order = 1

    # 1) EFI System Partition
    create.append(
        f'            <CreatePartition wcm:action="add">\n'
        f"              <Order>{order}</Order>\n"
        f"              <Size>{p.esp_size_mb}</Size>\n"
        f"              <Type>EFI</Type>\n"
        f"            </CreatePartition>"
    )
    modify.append(
        f'            <ModifyPartition wcm:action="add">\n'
        f"              <Order>{len(modify) + 1}</Order>\n"
        f"              <PartitionID>{order}</PartitionID>\n"
        f"              <Format>FAT32</Format>\n"
        f"              <Label>System</Label>\n"
        f"            </ModifyPartition>"
    )
    esp_id = order
    order += 1

    # 2) Microsoft Reserved partition (Win11) — created but never formatted.
    if p.include_msr:
        create.append(
            f'            <CreatePartition wcm:action="add">\n'
            f"              <Order>{order}</Order>\n"
            f"              <Size>128</Size>\n"
            f"              <Type>MSR</Type>\n"
            f"            </CreatePartition>"
        )
        order += 1

    # 3) Windows partition — rest of the disk.
    create.append(
        f'            <CreatePartition wcm:action="add">\n'
        f"              <Order>{order}</Order>\n"
        f"              <Extend>true</Extend>\n"
        f"              <Type>Primary</Type>\n"
        f"            </CreatePartition>"
    )
    modify.append(
        f'            <ModifyPartition wcm:action="add">\n'
        f"              <Order>{len(modify) + 1}</Order>\n"
        f"              <PartitionID>{order}</PartitionID>\n"
        f"              <Format>NTFS</Format>\n"
        f"              <Label>Windows</Label>\n"
        f"            </ModifyPartition>"
    )
    # Not an assert: under `python -O` this check would vanish, and a mismatch
    # here means the unattend installs Windows to the wrong partition — a
    # failure that only shows up 20 minutes into a build, inside WinPE.
    if order != p.install_partition_id:
        raise RuntimeError(
            f"disk layout bug: Windows landed on partition {order} but "
            f"{p.key}'s install_partition_id is {p.install_partition_id}"
        )

    return (
        "          <CreatePartitions>\n"
        + "\n".join(create)
        + "\n          </CreatePartitions>\n"
        + "          <ModifyPartitions>\n"
        + "\n".join(modify)
        + "\n          </ModifyPartitions>"
    )


def build_unattend_image(cfg: Config, *, desktop: bool = False) -> None:
    """Build an ISO image containing autounattend.xml for the active OS profile."""
    mkisofs = _find_mkisofs()
    if mkisofs is None:
        raise RuntimeError(
            "Neither mkisofs nor genisoimage found. "
            "Install with: apt install genisoimage"
        )

    profile = cfg.profile
    if desktop and not profile.supports_core:
        raise RuntimeError(
            f"--desktop is a Windows Server option (Core vs Desktop Experience); "
            f"{profile.key} is always a full desktop. Drop --desktop."
        )

    # Remove stale image (may be owned by libvirt-qemu from previous run)
    if cfg.unattend_img.exists():
        try:
            cfg.unattend_img.unlink()
        except PermissionError:
            # Fallback: previously called `rm -f` here on the assumption
            # that user-mode rm could remove a file owned by libvirt-qemu.
            # That's wrong -- rm needs the same FS-level perms as
            # Path.unlink, so it would fail too. Try `sudo rm -f` instead;
            # if sudo isn't available, surface the original PermissionError
            # so the user can clean up manually with explicit guidance.
            if shutil.which("sudo"):
                subprocess.run(
                    ["sudo", "rm", "-f", str(cfg.unattend_img)],
                    check=False,
                )
            if cfg.unattend_img.exists():
                raise PermissionError(
                    f"{cfg.unattend_img} is owned by another user "
                    "(probably libvirt-qemu from a previous setup) and "
                    "couldn't be removed.\n"
                    f"    Manual cleanup: sudo rm -f {cfg.unattend_img}"
                )

    image_name = profile.image_name
    if profile.supports_core and desktop:
        # Server: swap the Core image for the Desktop Experience one.
        image_name = image_name.replace("SERVERSTANDARDCORE", "SERVERSTANDARD")

    if profile.supports_core:
        edition = "Desktop Experience" if desktop else "Server Core"
    else:
        edition = profile.key
    console.print(f"[blue][*][/] Building unattend image ({edition})...")
    with tempfile.TemporaryDirectory() as tmpdir:
        dst = Path(tmpdir) / "autounattend.xml"
        xml = _data.render(
            "unattend.xml",
            IMAGE_NAME=image_name,
            VIRTIO_SUBDIR=profile.virtio_subdir,
            INSTALL_PARTITION_ID=str(profile.install_partition_id),
            DISK_PARTITIONS=_disk_partitions_block(cfg),
            LABCONFIG_BLOCK=_labconfig_block() if profile.labconfig_bypass else "",
            SPECIALIZE_DEPLOY_BLOCK=(
                _specialize_deploy_block() if profile.prevent_device_encryption else ""
            ),
        )
        dst.write_text(xml)

        subprocess.run(
            [mkisofs, "-o", str(cfg.unattend_img), "-J", "-r", tmpdir],
            capture_output=True,
            check=True,
        )
    console.print("[green][+][/] Unattend image created")


def create_disk(cfg: Config) -> None:
    """Create the QCOW2 disk image.

    Honors the OS profile's minimum disk size: Win11 Setup rejects a system
    drive under 64 GB, so we never create one smaller than ``min_disk_gb``
    regardless of the (Server-oriented) ``vm_disk`` default.
    """
    disk_gb = max(cfg.vm_disk, cfg.profile.min_disk_gb)
    if disk_gb != cfg.vm_disk:
        console.print(
            f"[yellow][!][/] {cfg.profile.key} needs ≥{cfg.profile.min_disk_gb}GB; "
            f"using {disk_gb}GB instead of the configured {cfg.vm_disk}GB."
        )
    console.print(f"[blue][*][/] Creating VM disk ({disk_gb}GB)...")
    result = subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", str(cfg.disk_path), f"{disk_gb}G"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"qemu-img create failed (exit {result.returncode}):\n"
            f"  stdout: {result.stdout.strip()}\n"
            f"  stderr: {result.stderr.strip()}"
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
        "--memorybacking", "source.type=memfd,access.mode=shared",
        "--disk", f"path={cfg.disk_path},bus=sata",
        "--cdrom", windows_iso,
        "--disk", f"{cfg.unattend_img},device=cdrom",
        "--disk", f"{cfg.virtio_iso},device=cdrom",
        "--network", "network=default,model=e1000",
        "--channel", "unix,target.type=virtio,target.name=org.qemu.guest_agent.0",
        "--filesystem", (
            f"type=mount,accessmode=passthrough,driver.type=virtiofs,"
            f"driver.queue=1024,source.dir={cfg.shared_dir},"
            f"target.dir=winbox_share"
        ),
        "--os-variant", cfg.profile.os_variant,
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
        result = virsh_run("send-key", cfg.vm_name, "KEY_ENTER", check=False)
        if result.returncode != 0:
            break


def provision_vm_disk(cfg: Config) -> None:
    """Phase 2: Inject provision files into disk image via virt-customize."""
    console.print("[blue][*][/] Preparing provision payload...")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        # Build provision.zip: provision.ps1, .ssh_pubkey, OpenSSH, WinFsp, virtiofs.exe
        openssh_zip = cfg.iso_dir / OPENSSH_ZIP
        winfsp_msi = cfg.iso_dir / WINFSP_MSI
        virtiofs_exe = _virtiofs_cache_path(cfg)
        python_exe = cfg.iso_dir / PYTHON_EXE
        python_embed = cfg.iso_dir / PYTHON_EMBED_ZIP
        x64dbg_zip = cfg.iso_dir / X64DBG_ZIP
        # provision.ps1 picks its Python payload by probing the guest's
        # ProductType, so the build has to ship the one that probe will ask
        # for. Shipping the wrong one isn't an error there — it just quietly
        # leaves the VM with no Python, which only surfaces later as a broken
        # MCP `python` tool.
        if cfg.profile.client_sku:
            required_python = (python_embed, "Python embeddable zip")
        else:
            required_python = (python_exe, "Python installer")

        missing_files = []
        for path, label in [
            (openssh_zip, "OpenSSH"), (winfsp_msi, "WinFsp"), (virtiofs_exe, "virtiofs"),
            required_python,
        ]:
            if not path.exists():
                missing_files.append(f"{label}: {path}")
        if missing_files:
            raise RuntimeError(
                "Missing critical provisioning files (re-run setup):\n  "
                + "\n  ".join(missing_files)
            )

        # Sanity-check the zip-shaped downloads beyond size > N (the previous
        # check would happily reuse a partial download stuck above the
        # threshold — captive portal interstitial, MITM error page, etc.).
        for zpath, label in [(openssh_zip, "OpenSSH"), (x64dbg_zip, "x64dbg")]:
            if zpath.exists() and not zipfile.is_zipfile(zpath):
                raise RuntimeError(
                    f"{label} download at {zpath} is not a valid zip "
                    "(probably truncated or an HTML error page). "
                    f"Delete it and re-run winbox setup."
                )
        zip_path = tmpdir_path / "provision.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(_data.path("provision.ps1"), "provision.ps1")
            if cfg.ssh_pubkey.exists():
                zf.write(cfg.ssh_pubkey, ".ssh_pubkey")
            if openssh_zip.exists():
                zf.write(openssh_zip, OPENSSH_ZIP)
            if winfsp_msi.exists():
                zf.write(winfsp_msi, WINFSP_MSI)
            if virtiofs_exe.exists():
                zf.write(virtiofs_exe, VIRTIOFS_EXE)
            if python_exe.exists():
                zf.write(python_exe, PYTHON_EXE)
            if python_embed.exists():
                zf.write(python_embed, PYTHON_EMBED_ZIP)
            if x64dbg_zip.exists():
                zf.write(x64dbg_zip, X64DBG_ZIP)

        # Copy bootstrap.ps1 to temp dir
        bootstrap_src = _data.path("bootstrap.ps1")
        bootstrap_tmp = tmpdir_path / "bootstrap.ps1"
        bootstrap_tmp.write_bytes(Path(bootstrap_src).read_bytes())

        console.print("[blue][*][/] Injecting provision files into disk image...")
        env = {**os.environ, "LIBGUESTFS_BACKEND": "direct"}
        # virt-customize's automatic OS inspection (inspect_os) fails on the
        # Win11 image — the installer leaves Windows.old / $Windows.~BT behind,
        # which confuses libguestfs OS detection ("file exited with status 1").
        # Mount the Windows partition explicitly (its index comes from the
        # profile's disk layout) and upload; no inspection required.
        win_part = f"/dev/sda{cfg.profile.install_partition_id}"
        _guestfish(cfg.disk_path, env, [
            f"mount {win_part} /",
            f"upload {zip_path} /provision.zip",
            f"upload {bootstrap_tmp} /bootstrap.ps1",
        ])

        if cfg.profile.disable_defender_offline:
            _disable_defender_offline(cfg, tmpdir_path, env, win_part)

    console.print("[green][+][/] Provision files injected")


# The Defender-disable payload and the offline-hive mechanics both live
# outside the installer now — `winbox av disable` needs the identical
# operation at runtime. Re-exported so this module reads standalone.
from winbox.defender import DEFENDER_OFF_SYSTEM_REG as _DEFENDER_OFF_SYSTEM_REG


def _guestfish(disk_path: Path, env: dict[str, str], commands: list[str]) -> None:
    """Run a read-write guestfish script against ``disk_path``.

    ``run`` is prepended automatically; ``commands`` are the guestfish
    statements that follow (e.g. ``mount``/``upload``/``download``). Raises
    :class:`RuntimeError` on a non-zero exit. Used instead of virt-customize /
    virt-win-reg because those auto-inspect the OS, and inspection fails on the
    Win11 install image.
    """
    script = "run\n" + "\n".join(commands) + "\n"
    result = subprocess.run(
        ["guestfish", "--rw", "-a", str(disk_path)],
        input=script, text=True, capture_output=True, env=env, check=False,
    )
    if result.returncode != 0:
        msg = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise RuntimeError(f"guestfish failed: {msg}")


# Path to the SYSTEM registry hive inside the mounted Windows partition.
_SYSTEM_HIVE = "/Windows/System32/config/SYSTEM"


def _disable_defender_offline(
    cfg: Config, tmpdir_path: Path, env: dict[str, str], win_part: str
) -> None:
    """Disable the Defender services in the offline SYSTEM hive (Start=4).

    Delegates to :mod:`winbox.offlinereg`, which is the same machinery
    ``winbox av disable`` uses at runtime — a client SKU can only have its
    Defender state changed while the VM is off, so build time and run time
    genuinely want the same operation.

    Best-effort here, unlike the runtime path: a build should not abort over
    this, and the caller is not a user who explicitly asked for it.
    """
    from winbox import defender, offlinereg

    console.print("[blue][*][/] Disabling Defender in the offline SYSTEM hive...")
    try:
        offlinereg.merge_hive(
            cfg.disk_path,
            hive=offlinereg.SYSTEM_HIVE,
            prefix="HKEY_LOCAL_MACHINE\\SYSTEM",
            reg_body=defender.DEFENDER_OFF_SYSTEM_REG,
            win_part=win_part,
        )
    except offlinereg.OfflineRegistryError as e:
        console.print(
            f"[yellow][!][/] Offline Defender disable failed: {e}\n"
            "    Best-effort step — continuing; Defender may stay active on Win11."
        )
        return
    console.print("[green][+][/] Defender services disabled in offline SYSTEM hive")


def _settle_firstlogon_boot(cfg: "Config", vm: VM, ga: GuestAgent) -> None:
    """Boot once to let Win11's re-triggered OOBE FirstLogonCommands settle.

    After the offline SYSTEM-hive Defender edit, Win11 re-runs its
    FirstLogonCommands on the next boot (reinstalling the guest agent, ending in
    ``shutdown /s``). We boot and wait for that shutdown; if instead the guest
    agent comes up and stays (the edit didn't re-trigger OOBE that time), we
    shut down cleanly. Either way the VM is left shut off, ready for a clean
    provisioning boot.
    """
    console.print("[blue][*][/] Settling Win11 OOBE FirstLogon boot...")
    vm.start()
    deadline = time.monotonic() + 600
    ga_stable = 0
    while time.monotonic() < deadline:
        if vm.state() == VMState.SHUTOFF:
            console.print("[green][+][/] FirstLogon settled (VM shut down)")
            return
        try:
            ga.wait(timeout=5)
            ga_stable += 1
        except GuestAgentError:
            ga_stable = 0
        # GA up and steady for ~30s => this boot didn't re-run OOBE; stop it.
        if ga_stable >= 3:
            console.print("[green][+][/] Boot came up clean; shutting down to provision")
            try:
                ga.shutdown()
            except GuestAgentError:
                pass
            vm.wait_shutdown(timeout=120) or vm.force_stop()
            return
        time.sleep(10)
    # Timed out waiting for a stable state — force it off and proceed.
    console.print("[yellow][!][/] Settle boot didn't reach a stable state; forcing off")
    vm.force_stop()
    vm.wait_shutdown(timeout=60)


def boot_for_provisioning(cfg: Config) -> None:
    """Phase 3: Boot VM, run bootstrap.ps1 via guest agent, wait for shutdown.

    VirtIO-FS is configured in the VM definition but WinFsp isn't installed yet,
    so provisioning reads from C:\\Provision\\ (injected by virt-customize).
    The provision script installs WinFsp + VirtioFsSvc so Z: works after setup.

    After the bootstrap shutdown we boot the VM one more time and verify the
    provision sentinel exists — bootstrap.ps1's finally-block shutdown runs
    regardless of whether provision.ps1 parse-errored or crashed, so "VM shut
    down cleanly" is not by itself proof that anything actually got installed.
    """
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    # Win11: the offline Defender edit (SYSTEM hive) makes OOBE re-run its
    # FirstLogonCommands on the very next boot — they reinstall the guest agent
    # and end in `shutdown /s`. If we booted straight into provisioning we'd
    # race that shutdown. Do one throwaway "settle" boot first and let it
    # finish, so the real provisioning boot comes up clean.
    if cfg.profile.disable_defender_offline:
        _settle_firstlogon_boot(cfg, vm, ga)

    console.print("[blue][*][/] Booting VM for provisioning...")
    vm.start()

    # Win11's OOBE finalization ("Installing…", "Just a moment…") can spill
    # into this boot and pushes the guest agent past the old 180s window;
    # give it longer (returns as soon as the agent answers, so Server 2022
    # isn't slowed).
    console.print("[blue][*][/] Waiting for guest agent...")
    ga.wait(timeout=420)
    console.print("[green][+][/] Guest agent responding")

    console.print("[blue][*][/] Running bootstrap.ps1 via guest agent...")
    console.print("    This may take 5-10 minutes.")
    bootstrap_pid = ga.exec_detached(
        'powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\\bootstrap.ps1',
    )

    # Sanity probe: bootstrap.ps1's first action is `Start-Transcript -Path
    # C:\winbox-bootstrap.log -Force`, so the file appears within seconds of
    # PowerShell loading the script. If it doesn't show up in 30s, something
    # blocked the launch (corrupt file, ExecutionPolicy, no PowerShell on
    # PATH) and waiting the full 600s for shutdown is wasted time.
    console.print("[blue][*][/] Probing bootstrap launch...")
    launched = False
    for _ in range(15):
        time.sleep(2)
        if vm.state() == VMState.SHUTOFF:
            launched = True
            break
        try:
            probe = ga.exec(
                "if exist C:\\winbox-bootstrap.log (echo OK) else (echo MISSING)",
                timeout=10,
            )
        except GuestAgentError:
            # VM may be rebooting or GA may be momentarily unreachable
            # mid-provision; keep polling.
            continue
        if "OK" in probe.stdout:
            launched = True
            break

    if not launched:
        raise RuntimeError(
            "bootstrap.ps1 did not start within 30s — no transcript log appeared.\n"
            f"    Check with: virsh console {cfg.vm_name}\n"
            "    Common causes: ExecutionPolicy block, corrupt provision.zip,\n"
            "    or PowerShell missing/broken in the install image."
        )

    console.print("[blue][*][/] Waiting for VM to shut down...")
    # Win11 provisioning (Python 3.13 + x64dbg + OpenSSH + WinFsp installs) runs
    # slower than Server 2022, so allow more headroom before declaring a hang.
    if not vm.wait_shutdown(timeout=900):
        console.print(
            f"[yellow][!][/] Provisioning timed out (VM did not shut down in 600s)"
        )
        console.print(
            f"    bootstrap.ps1 PID inside VM: {bootstrap_pid} "
            f"(check with: virsh console {cfg.vm_name})"
        )
        # Try a clean kill before force-stopping the whole VM, so the user
        # can grep the bootstrap log on the share without worrying about
        # the VM having been hard-yanked mid-write.
        try:
            ga.exec(f"taskkill /pid {bootstrap_pid} /f", timeout=10)
        except Exception:
            pass
        console.print("[blue][*][/] Force-stopping hung VM...")
        try:
            vm.force_stop()
        except Exception:
            pass
        raise RuntimeError("Provisioning timed out")

    _verify_provisioning(cfg, vm, ga)
    console.print("[green][+][/] Provisioning complete")


def _verify_python(ga: GuestAgent) -> None:
    """Warn loudly if the guest has no working Python.

    provision.ps1 treats a failed Python install as non-fatal and continues,
    and the provisioning sentinel only proves the script *finished* — so a
    build with no Python previously reported complete success. Python in the
    guest is what the MCP ``python`` tool and parts of kdbg run on, so that
    silence turned a broken VM into a puzzle discovered much later.
    """
    # On client SKUs Python comes from the embeddable zip extracted to
    # C:\Python313 and put on the machine PATH — which a process started
    # before the PATH write would not see. Check the explicit path too so a
    # working install is never reported as missing.
    candidates = ["python.exe", r"C:\Python313\python.exe"]
    for candidate in candidates:
        try:
            # No quotes: the guest agent escapes them as \" and cmd.exe has no
            # backslash-escape rule, so they arrive as literal characters.
            # Neither candidate path contains a space.
            result = ga.exec(f"{candidate} --version", timeout=30)
        except GuestAgentError:
            continue
        if result.exitcode == 0 and "Python" in (result.stdout + result.stderr):
            version = (result.stdout or result.stderr).strip()
            console.print(f"[green][+][/] Guest Python verified ({version})")
            return

    console.print(
        "[yellow][!][/] No working Python in the guest — the MCP [bold]python[/] "
        "tool and parts of kdbg will not work.\n"
        "    Provisioning otherwise completed, so the VM is usable for "
        "everything else.\n"
        "    Check the install log in the VM: "
        "[bold]winbox exec 'type C:\\winbox-python-install.log'[/]\n"
        "    Then re-run provisioning with: [bold]winbox provision[/]"
    )


def _verify_provisioning(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Boot the VM once more and assert provision.ps1 actually finished.

    On failure, dumps the bootstrap log from inside the VM so the user sees
    the actual PowerShell error. Shuts the VM back down before returning so
    the caller can create the clean snapshot.
    """
    console.print("[blue][*][/] Booting VM to verify provisioning...")
    vm.start()
    try:
        ga.wait(timeout=420)
    except GuestAgentError as e:
        raise RuntimeError(
            f"VM came back up but guest agent is unreachable: {e}"
        ) from e

    sentinel_check = ga.exec(
        f"if exist {PROVISION_SENTINEL} (echo OK) else (echo MISSING)",
        timeout=30,
    )

    if "OK" in sentinel_check.stdout:
        console.print("[green][+][/] Provisioning sentinel verified")
        _verify_python(ga)
        _shutdown_and_wait(vm, ga)
        return

    console.print("[red][-][/] Provisioning sentinel missing — provision.ps1 did not finish")
    console.print("[blue][*][/] Dumping bootstrap log from VM:")
    console.print("─" * 60)
    try:
        log = ga.exec(f"type {BOOTSTRAP_LOG}", timeout=30)
        if log.stdout:
            console.print(log.stdout, markup=False, highlight=False, end="")
        else:
            console.print("[yellow](bootstrap log is empty)[/]")
    except GuestAgentError:
        console.print("[yellow](could not read bootstrap log)[/]")
    console.print("─" * 60)

    # Best-effort shutdown before bailing so we don't leave a running VM behind
    try:
        _shutdown_and_wait(vm, ga)
    except Exception:
        try:
            vm.force_stop()
        except Exception:
            pass

    raise RuntimeError(
        "Provisioning did not complete — see bootstrap log above. "
        "Fix the underlying issue and re-run `winbox setup -y`."
    )


def _shutdown_and_wait(vm: VM, ga: GuestAgent, timeout: int = 300) -> None:
    """Ask the guest to shut down and wait for the VM to reach SHUTOFF."""
    console.print("[blue][*][/] Shutting VM down...")
    try:
        ga.shutdown()
    except GuestAgentError:
        pass  # expected — VM dies before GA can reply
    if not vm.wait_shutdown(timeout=timeout):
        console.print("[yellow][!][/] VM did not shut down in time, force-stopping")
        vm.force_stop()


def create_clean_snapshot(cfg: Config) -> None:
    """Create a 'clean' snapshot after setup."""
    vm = VM(cfg)
    console.print("[blue][*][/] Creating 'clean' snapshot...")
    try:
        vm.snapshot_create("clean")
        console.print("[green][+][/] Snapshot 'clean' created")
    except RuntimeError as e:
        console.print(f"[yellow][!][/] Could not create snapshot: {e}")


def register_nwfilter(cfg: Config) -> None:
    """Register the 'winbox-isolate' libvirt nwfilter (idempotent).

    Ensures `winbox net isolate` can attach the filter without needing
    a separate registration step. Safe to re-run.
    """
    from winbox.nwfilter import ensure_filter_defined, FILTER_NAME

    console.print(f"[blue][*][/] Registering libvirt nwfilter '{FILTER_NAME}'...")
    try:
        ensure_filter_defined(cfg)
        console.print(f"[green][+][/] nwfilter '{FILTER_NAME}' registered")
    except RuntimeError as e:
        console.print(f"[yellow][!][/] Could not register nwfilter: {e}")
        console.print("    `winbox net isolate` will retry on first use.")


def attach_default_filter(cfg: Config) -> None:
    """Attach 'winbox-isolate' to the persistent domain config at setup time.

    The VM is shut down at this point (end of Phase 3), so we pass
    ``live=False, config=True`` — libvirt rejects ``--live`` on a stopped
    domain. On the VM's next boot the filter is active; the Phase 4 snapshot
    captures the already-filtered config so ``winbox restore clean`` stays
    isolated too.

    Idempotent. Failures are a warning, not a hard abort — the user can
    always `winbox net isolate` manually later.
    """
    from winbox.nwfilter import attach_filter, FILTER_NAME

    vm = VM(cfg)
    console.print(f"[blue][*][/] Isolating VM by default (attaching '{FILTER_NAME}')...")
    try:
        changed = attach_filter(vm.name, live=False, config=True)
        if changed:
            console.print("[green][+][/] VM boots isolated by default")
        else:
            console.print("[green][+][/] VM already isolated by default")
        console.print("    Run [bold]winbox net connect[/] when you need internet.")
    except RuntimeError as e:
        console.print(f"[yellow][!][/] Could not attach default filter: {e}")
        console.print("    Use `winbox net isolate` manually after first boot.")
