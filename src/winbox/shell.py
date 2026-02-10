"""Interactive SYSTEM shell via ConPTY reverse connection."""

from __future__ import annotations

import base64
import os
import select
import shutil
import socket
import sys
import termios
import tty
from importlib import resources
from typing import TYPE_CHECKING

from rich.console import Console

from winbox.guest import GuestAgent

if TYPE_CHECKING:
    from winbox.config import Config

console = Console()

CONPTY_SCRIPT = "Invoke-ConPtyShell.ps1"
CONPTY_VM_PATH = f"C:\\{CONPTY_SCRIPT}"
DEFAULT_PORT = 4444


def _ensure_conpty_on_vm(cfg: Config, ga: GuestAgent) -> None:
    """Push Invoke-ConPtyShell.ps1 from package data to C:\\ on the VM."""
    # Check if already on the VM
    result = ga.exec(f'if exist "{CONPTY_VM_PATH}" echo YES', timeout=10)
    if "YES" in result.stdout:
        return

    console.print(f"[blue][*][/] Pushing {CONPTY_SCRIPT} to VM...")

    # Copy from package data to share (temp), then into the VM
    src = resources.files("winbox.data").joinpath(CONPTY_SCRIPT)
    tmp = cfg.shared_dir / CONPTY_SCRIPT
    with resources.as_file(src) as src_path:
        shutil.copy2(src_path, tmp)

    ga.exec(f'copy "Z:\\{CONPTY_SCRIPT}" "{CONPTY_VM_PATH}"', timeout=10)
    tmp.unlink(missing_ok=True)
    console.print(f"[green][+][/] {CONPTY_SCRIPT} installed on VM")


def open_shell(
    cfg: Config,
    ga: GuestAgent,
    *,
    port: int = DEFAULT_PORT,
) -> None:
    """Open an interactive SYSTEM shell via ConPTY reverse connection."""
    _ensure_conpty_on_vm(cfg, ga)

    # Get terminal size
    try:
        size = os.get_terminal_size()
        rows, cols = size.lines, size.columns
    except OSError:
        rows, cols = 24, 80

    # Start TCP listener on virbr0
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((cfg.smb_host_ip, port))
    except OSError as e:
        console.print(f"[red][-][/] Cannot bind {cfg.smb_host_ip}:{port}: {e}")
        return
    server.listen(1)
    console.print(f"[blue][*][/] Listening on {cfg.smb_host_ip}:{port}")

    # Build PowerShell command — use EncodedCommand to avoid quoting hell
    ps_cmd = (
        f"IEX(Get-Content '{CONPTY_VM_PATH}' -Raw); "
        f"Invoke-ConPtyShell -RemoteIp {cfg.smb_host_ip} -RemotePort {port} "
        f"-Rows {rows} -Cols {cols}"
    )
    encoded = base64.b64encode(ps_cmd.encode("utf-16-le")).decode("ascii")
    cmd = f"powershell -ExecutionPolicy Bypass -EncodedCommand {encoded}"

    # Fire via guest agent — detached, the shell runs until we disconnect
    console.print("[blue][*][/] Launching reverse shell as SYSTEM...")
    ga.exec_detached(cmd)

    # Wait for incoming connection
    server.settimeout(30)
    try:
        client, _ = server.accept()
    except socket.timeout:
        console.print("[red][-][/] Timed out waiting for connection")
        server.close()
        return
    finally:
        server.close()

    console.print("[green][+][/] SYSTEM shell ready — type 'exit' to close\n")

    # Enter raw terminal mode and relay I/O
    _relay(client)


def _relay(sock: socket.socket) -> None:
    """Raw terminal I/O relay between stdin/stdout and the socket."""
    old_settings = termios.tcgetattr(sys.stdin)
    tty.setraw(sys.stdin)

    try:
        while True:
            readable, _, _ = select.select([sys.stdin, sock], [], [])
            if sys.stdin in readable:
                data = os.read(sys.stdin.fileno(), 1024)
                if not data:
                    break
                sock.sendall(data)
            if sock in readable:
                data = sock.recv(4096)
                if not data:
                    break
                os.write(sys.stdout.fileno(), data)
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        sock.close()
        console.print("\n[blue][*][/] Shell closed")
