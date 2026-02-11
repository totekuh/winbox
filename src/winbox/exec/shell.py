"""Interactive SYSTEM shell via ConPTY reverse connection."""

from __future__ import annotations

import base64
import os
import select
import shutil
import signal
import socket
import struct
import sys
import termios
import tty
from importlib import resources
from typing import TYPE_CHECKING

from rich.console import Console

from winbox.vm.guest import GuestAgent

if TYPE_CHECKING:
    from winbox.config import Config

console = Console()

CONPTY_SCRIPT = "Invoke-ConPtyShell.ps1"
DEFAULT_PORT = 4444
RESIZE_MAGIC = b"\x00RSIZ"


def _ensure_conpty_on_share(cfg: Config) -> None:
    """Copy Invoke-ConPtyShell.ps1 from package data to share root (always refreshed)."""
    dest = cfg.shared_dir / CONPTY_SCRIPT
    src = resources.files("winbox.data").joinpath(CONPTY_SCRIPT)
    with resources.as_file(src) as src_path:
        shutil.copy2(src_path, dest)


def open_shell(
    cfg: Config,
    ga: GuestAgent,
    *,
    port: int = DEFAULT_PORT,
    pipe_mode: bool = False,
) -> None:
    """Open an interactive SYSTEM shell via ConPTY reverse connection."""
    _ensure_conpty_on_share(cfg)

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

    # Build PowerShell command — read script from Z:\ (SMB share root)
    nopty_flag = " -NoPty" if pipe_mode else ""
    ps_cmd = (
        f"IEX(Get-Content 'Z:\\{CONPTY_SCRIPT}' -Raw); "
        f"Invoke-ConPtyShell -RemoteIp {cfg.smb_host_ip} -RemotePort {port} "
        f"-Rows {rows} -Cols {cols}{nopty_flag}"
    )
    encoded = base64.b64encode(ps_cmd.encode("utf-16-le")).decode("ascii")
    cmd = f"powershell -ExecutionPolicy Bypass -EncodedCommand {encoded}"

    # Fire via guest agent — detached, the shell runs until we disconnect
    mode = "pipe" if pipe_mode else "ConPTY"
    console.print(f"[blue][*][/] Launching reverse shell as SYSTEM ({mode})...")
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
    _relay(client, resize=not pipe_mode)


def _relay(sock: socket.socket, *, resize: bool = True) -> None:
    """Raw terminal I/O relay between stdin/stdout and the socket."""
    old_settings = termios.tcgetattr(sys.stdin)
    tty.setraw(sys.stdin)

    # Self-pipe so SIGWINCH wakes up select() (only needed for resize)
    sig_r = sig_w = -1
    old_wakeup = -1
    old_handler = None
    if resize:
        sig_r, sig_w = os.pipe()
        os.set_blocking(sig_r, False)
        os.set_blocking(sig_w, False)
        old_wakeup = signal.set_wakeup_fd(sig_w)
        old_handler = signal.signal(signal.SIGWINCH, lambda *_: None)

    try:
        while True:
            select_fds = [sys.stdin, sock]
            if resize:
                select_fds.append(sig_r)
            readable, _, _ = select.select(select_fds, [], [])
            if resize and sig_r in readable:
                try:
                    os.read(sig_r, 4096)  # drain wakeup bytes
                except OSError:
                    pass
                try:
                    size = os.get_terminal_size()
                    msg = RESIZE_MAGIC + struct.pack(">HH", size.lines, size.columns)
                    sock.sendall(msg)
                except OSError:
                    pass
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
        if resize:
            signal.signal(signal.SIGWINCH, old_handler)
            signal.set_wakeup_fd(old_wakeup)
            os.close(sig_r)
            os.close(sig_w)
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        sock.close()
        console.print("\n[blue][*][/] Shell closed")
