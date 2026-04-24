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

from winbox.vm import VM, GuestAgent, GuestAgentError

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
    "qemu-img",
    "virsh",
    "virt-install",
    "virt-customize",
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
    result = subprocess.run(
        ["virsh", "-c", "qemu:///system", "net-list", "--name"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode == 0 and "default" in result.stdout.split():
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


VIRTIOFS_ISO_PATH = "viofs/2k22/amd64/virtiofs.exe"
VIRTIOFS_EXE = "virtiofs.exe"


def extract_virtiofs(cfg: Config) -> Path:
    """Extract virtiofs.exe from the VirtIO ISO. Returns path to extracted exe."""
    dest = cfg.iso_dir / VIRTIOFS_EXE
    if dest.exists():
        console.print("[green][+][/] virtiofs.exe cached")
        return dest

    console.print("[blue][*][/] Extracting virtiofs.exe from VirtIO ISO...")
    subprocess.run(
        ["7z", "e", str(cfg.virtio_iso), f"-o{cfg.iso_dir}", VIRTIOFS_ISO_PATH, "-y"],
        capture_output=True, check=True,
    )
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
    src = _data_file("provision.ps1")
    dst = cfg.tools_dir / "provision.ps1"
    dst.write_bytes(Path(src).read_bytes())
    # Copy SSH pubkey so provision.ps1 can find it at Z:\tools\.ssh_pubkey
    if cfg.ssh_pubkey.exists():
        shutil.copy2(cfg.ssh_pubkey, cfg.tools_dir / ".ssh_pubkey")


def build_unattend_image(cfg: Config, *, desktop: bool = False) -> None:
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

    edition = "Desktop Experience" if desktop else "Server Core"
    console.print(f"[blue][*][/] Building unattend image ({edition})...")
    with tempfile.TemporaryDirectory() as tmpdir:
        src = _data_file("unattend.xml")
        dst = Path(tmpdir) / "autounattend.xml"
        xml = Path(src).read_text()
        if desktop:
            xml = xml.replace("SERVERSTANDARDCORE", "SERVERSTANDARD")
        dst.write_text(xml)

        subprocess.run(
            [mkisofs, "-o", str(cfg.unattend_img), "-J", "-r", tmpdir],
            capture_output=True,
            check=True,
        )
    console.print("[green][+][/] Unattend image created")


def create_disk(cfg: Config) -> None:
    """Create the QCOW2 disk image."""
    console.print(f"[blue][*][/] Creating VM disk ({cfg.vm_disk}GB)...")
    result = subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", str(cfg.disk_path), f"{cfg.vm_disk}G"],
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

        # Build provision.zip: provision.ps1, .ssh_pubkey, OpenSSH, WinFsp, virtiofs.exe
        openssh_zip = cfg.iso_dir / OPENSSH_ZIP
        winfsp_msi = cfg.iso_dir / WINFSP_MSI
        virtiofs_exe = cfg.iso_dir / VIRTIOFS_EXE
        python_exe = cfg.iso_dir / PYTHON_EXE
        x64dbg_zip = cfg.iso_dir / X64DBG_ZIP
        missing_files = []
        for path, label in [
            (openssh_zip, "OpenSSH"), (winfsp_msi, "WinFsp"), (virtiofs_exe, "virtiofs"),
        ]:
            if not path.exists():
                missing_files.append(f"{label}: {path}")
        if missing_files:
            raise RuntimeError(
                "Missing critical provisioning files (re-run setup):\n  "
                + "\n  ".join(missing_files)
            )
        zip_path = tmpdir_path / "provision.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(_data_file("provision.ps1"), "provision.ps1")
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
            if x64dbg_zip.exists():
                zf.write(x64dbg_zip, X64DBG_ZIP)

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

    VirtIO-FS is configured in the VM definition but WinFsp isn't installed yet,
    so provisioning reads from C:\\Provision\\ (injected by virt-customize).
    The provision script installs WinFsp + VirtioFsSvc so Z: works after setup.

    After the bootstrap shutdown we boot the VM one more time and verify the
    provision sentinel exists — bootstrap.ps1's finally-block shutdown runs
    regardless of whether provision.ps1 parse-errored or crashed, so "VM shut
    down cleanly" is not by itself proof that anything actually got installed.
    """
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
        console.print("[blue][*][/] Force-stopping hung VM...")
        try:
            vm.force_stop()
        except Exception:
            pass
        raise RuntimeError("Provisioning timed out")

    _verify_provisioning(cfg, vm, ga)
    console.print("[green][+][/] Provisioning complete")


def _verify_provisioning(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Boot the VM once more and assert provision.ps1 actually finished.

    On failure, dumps the bootstrap log from inside the VM so the user sees
    the actual PowerShell error. Shuts the VM back down before returning so
    the caller can create the clean snapshot.
    """
    console.print("[blue][*][/] Booting VM to verify provisioning...")
    vm.start()
    try:
        ga.wait(timeout=180)
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
    except (RuntimeError, subprocess.CalledProcessError) as e:
        console.print(f"[yellow][!][/] Could not create snapshot: {e}")


def register_nwfilter(cfg: Config) -> None:
    """Register the 'winbox-isolate' libvirt nwfilter (idempotent).

    Ensures `winbox net isolate` can attach the filter without needing
    a separate registration step. Safe to re-run.
    """
    from winbox.nwfilter import ensure_filter_defined, FILTER_NAME

    console.print(f"[blue][*][/] Registering libvirt nwfilter '{FILTER_NAME}'...")
    try:
        ensure_filter_defined()
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
