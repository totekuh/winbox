"""SMB server for host-guest file sharing via impacket-smbserver."""

from __future__ import annotations

import os
import signal
import subprocess
from typing import TYPE_CHECKING

from rich.console import Console

if TYPE_CHECKING:
    from winbox.config import Config

console = Console()

SMB_PORT = 445


def _pid_file(cfg: Config):
    return cfg.winbox_dir / "smb.pid"


def start(cfg: Config) -> None:
    """Start impacket-smbserver as a background process."""
    pid_path = _pid_file(cfg)

    # Already running?
    if pid_path.exists():
        try:
            pid = int(pid_path.read_text().strip())
            os.kill(pid, 0)
            return  # still alive
        except (OSError, ValueError):
            pid_path.unlink(missing_ok=True)

    cfg.shared_dir.mkdir(parents=True, exist_ok=True)

    console.print("[blue][*][/] Starting SMB server...")
    proc = subprocess.Popen(
        [
            "impacket-smbserver",
            "-smb2support",
            "-ip", cfg.smb_host_ip,
            "-port", str(SMB_PORT),
            "winbox",
            str(cfg.shared_dir),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    pid_path.write_text(str(proc.pid))
    console.print("[green][+][/] SMB server started")


def stop(cfg: Config) -> None:
    """Stop the SMB server."""
    pid_path = _pid_file(cfg)
    if not pid_path.exists():
        return

    try:
        pid = int(pid_path.read_text().strip())
        os.kill(pid, signal.SIGTERM)
    except (OSError, ValueError):
        pass
    pid_path.unlink(missing_ok=True)


def is_running(cfg: Config) -> bool:
    """Check if the SMB server is running."""
    pid_path = _pid_file(cfg)
    if not pid_path.exists():
        return False
    try:
        pid = int(pid_path.read_text().strip())
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        pid_path.unlink(missing_ok=True)
        return False
