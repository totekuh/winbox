"""Asset download functions and VirtIO-FS extraction."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console

if TYPE_CHECKING:
    from winbox.config import Config

console = Console()


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

RUNEX_URL = "https://github.com/totekuh/RunEx/releases/download/v2.1.2/RunEx.exe"
RUNEX_EXE = "RunEx.exe"
RUNEX_SHA256 = "7fcef8419f3829e3dcab167d071203097db9ef7a2aff97360d15a2933956fa6b"

X64DBG_URL = (
    "https://github.com/x64dbg/x64dbg/releases/download/2025.08.19/"
    "snapshot_2025-08-19_19-40.zip"
)
X64DBG_ZIP = "x64dbg.zip"

# spice-guest-tools: QXL WDDM display driver + spice-vdagent (dynamic
# resolution + host<->guest clipboard). Only fetched/installed in the
# --display spice path. spice-space serves no stable versioned path, so the
# URL stays "-latest" and the SHA-256 is the real pin: an upstream rebuild
# fails verification loudly and we re-pin deliberately (same as RunEx).
SPICE_TOOLS_URL = (
    "https://www.spice-space.org/download/windows/spice-guest-tools/"
    "spice-guest-tools-latest.exe"
)
SPICE_TOOLS_EXE = "spice-guest-tools.exe"
SPICE_TOOLS_SHA256 = "b5be0754802bcd7f7fe0ccdb877f8a6224ba13a2af7d84eb087a89b3b0237da2"

LIGOLO_AGENT_URL = (
    "https://github.com/nicocha30/ligolo-ng/releases/download/v0.9.2/"
    "ligolo-ng_agent_0.9.2_windows_amd64.zip"
)
LIGOLO_AGENT_ZIP = "ligolo-agent.zip"
LIGOLO_AGENT_EXE = "ligolo-agent.exe"
LIGOLO_AGENT_SHA256 = "1c7581cb54dab15b61cc8b5fee944d12f8cf96510f993637b91ce57aecbacaa0"

# Arcname of virtiofs.exe inside provision.zip (what provision.ps1 expects).
VIRTIOFS_EXE = "virtiofs.exe"


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
    # Download to a temp path and only os.replace into place once the size
    # check passes, so an interrupted/truncated wget never lands a partial at
    # dest that a later run would return as 'cached' (MSI has no zip check).
    part = dest.with_name(dest.name + ".part")
    subprocess.run(
        ["wget", "-q", "--show-progress", "-O", str(part), WINFSP_URL],
        check=True,
    )
    if not part.exists() or part.stat().st_size < 1_000_000:
        part.unlink(missing_ok=True)
        raise RuntimeError(f"WinFsp download appears truncated: {dest}")
    os.replace(part, dest)
    console.print("[green][+][/] WinFsp MSI downloaded")
    return dest


def download_python(cfg: Config) -> Path:
    """Download the regular Python Windows installer if not cached."""
    dest = cfg.iso_dir / PYTHON_EXE
    if dest.exists() and dest.stat().st_size > 20_000_000:
        console.print("[green][+][/] Python installer cached")
        return dest

    console.print("[blue][*][/] Downloading Python installer...")
    # Download to a temp path and only os.replace into place once the size
    # check passes, so an interrupted/truncated wget never lands a partial at
    # dest that a later run would return as 'cached' (the EXE has no zip check).
    part = dest.with_name(dest.name + ".part")
    subprocess.run(
        ["wget", "-q", "--show-progress", "-O", str(part), PYTHON_URL],
        check=True,
    )
    if not part.exists() or part.stat().st_size < 20_000_000:
        part.unlink(missing_ok=True)
        raise RuntimeError(f"Python installer download appears truncated: {dest}")
    os.replace(part, dest)
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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_runex(cfg: Config) -> Path:
    """Ensure the pinned, hash-verified RunEx binary is cached."""
    dest = cfg.iso_dir / RUNEX_EXE
    if dest.exists() and _sha256(dest) == RUNEX_SHA256:
        console.print("[green][+][/] RunEx cached")
        return dest
    dest.unlink(missing_ok=True)
    part = dest.with_name(dest.name + ".part")
    part.unlink(missing_ok=True)
    console.print("[blue][*][/] Downloading RunEx...")
    try:
        subprocess.run(
            ["wget", "-q", "--show-progress", "-O", str(part), RUNEX_URL],
            check=True,
        )
        if not part.exists() or _sha256(part) != RUNEX_SHA256:
            raise RuntimeError("RunEx download failed SHA-256 verification")
        os.replace(part, dest)
    except Exception:
        part.unlink(missing_ok=True)
        raise
    console.print("[green][+][/] RunEx downloaded and verified")
    return dest


def download_spice_tools(cfg: Config) -> Path:
    """Ensure the pinned, hash-verified spice-guest-tools installer is cached."""
    dest = cfg.iso_dir / SPICE_TOOLS_EXE
    if dest.exists() and _sha256(dest) == SPICE_TOOLS_SHA256:
        console.print("[green][+][/] spice-guest-tools cached")
        return dest
    dest.unlink(missing_ok=True)
    part = dest.with_name(dest.name + ".part")
    part.unlink(missing_ok=True)
    console.print("[blue][*][/] Downloading spice-guest-tools...")
    try:
        subprocess.run(
            ["wget", "-q", "--show-progress", "-O", str(part), SPICE_TOOLS_URL],
            check=True,
        )
        if not part.exists() or _sha256(part) != SPICE_TOOLS_SHA256:
            raise RuntimeError(
                "spice-guest-tools download failed SHA-256 verification"
            )
        os.replace(part, dest)
    except Exception:
        part.unlink(missing_ok=True)
        raise
    console.print("[green][+][/] spice-guest-tools downloaded and verified")
    return dest


def download_ligolo_agent(cfg: Config) -> Path:
    """Ensure the pinned, hash-verified ligolo-ng agent EXE is cached."""
    dest = cfg.iso_dir / LIGOLO_AGENT_EXE
    if dest.exists() and _sha256(dest) == LIGOLO_AGENT_SHA256:
        console.print("[green][+][/] ligolo-agent cached")
        return dest
    dest.unlink(missing_ok=True)
    zip_part = cfg.iso_dir / (LIGOLO_AGENT_ZIP + ".part")
    zip_part.unlink(missing_ok=True)
    console.print("[blue][*][/] Downloading ligolo-ng agent...")
    try:
        subprocess.run(
            ["wget", "-q", "--show-progress", "-O", str(zip_part), LIGOLO_AGENT_URL],
            check=True,
        )
        if not zip_part.exists():
            raise RuntimeError("ligolo-agent download failed")
        if not zipfile.is_zipfile(zip_part):
            raise RuntimeError(
                "ligolo-agent download is not a valid zip "
                "(probably truncated or an HTML error page)"
            )
        with zipfile.ZipFile(zip_part) as zf:
            for name in zf.namelist():
                if name.endswith("agent.exe"):
                    with zf.open(name) as src, open(str(dest), "wb") as dst:
                        dst.write(src.read())
                    break
            else:
                raise RuntimeError("agent.exe not found inside ligolo-agent zip")
        if _sha256(dest) != LIGOLO_AGENT_SHA256:
            dest.unlink(missing_ok=True)
            raise RuntimeError("ligolo-agent.exe failed SHA-256 verification")
        zip_part.unlink(missing_ok=True)
    except Exception:
        zip_part.unlink(missing_ok=True)
        dest.unlink(missing_ok=True)
        raise
    console.print("[green][+][/] ligolo-agent downloaded and verified")
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
