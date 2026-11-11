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
from winbox import data as _data
from typing import TYPE_CHECKING

from rich.console import Console

import click

from winbox.exec.shell_editor import LineEditor, _relay_pipe  # noqa: F401
from winbox.vm.guest import GuestAgent
from winbox.vm.lifecycle import VM

if TYPE_CHECKING:
    from winbox.config import Config

console = Console()

CONPTY_SCRIPT = "Invoke-ConPtyShell.ps1"
DEFAULT_PORT = 4444
RESIZE_MAGIC = b"\x00RSIZ"


def _ensure_conpty_on_share(cfg: Config) -> None:
    """Copy Invoke-ConPtyShell.ps1 from package data to share root (always refreshed)."""
    dest = cfg.shared_dir / CONPTY_SCRIPT
    shutil.copy2(_data.path(CONPTY_SCRIPT), dest)


def open_shell(
    cfg: Config,
    ga: GuestAgent,
    *,
    port: int = DEFAULT_PORT,
    pipe_mode: bool = False,
    user: str | None = None,
    password: str | None = None,
) -> None:
    """Open an interactive shell via ConPTY reverse connection.

    Runs as SYSTEM by default.  Pass *user* and *password* to spawn the
    shell as a different local Windows user (delegated to RunEx by the
    guest agent layer).
    """
    if cfg.host_ip == "0.0.0.0":
        # Hard-fail: a typo'd HOST_IP=0.0.0.0 in ~/.winbox/config would
        # otherwise expose a SYSTEM-shell listener to the entire LAN
        # every single `winbox shell` invocation. The previous yellow
        # warning was easily missed in noisy output.
        raise click.ClickException(
            "host_ip is 0.0.0.0 — refusing to bind a SYSTEM-shell listener "
            "on all interfaces. Fix HOST_IP in ~/.winbox/config (e.g. "
            "192.168.122.1) or comment it out to use the default."
        )

    _ensure_conpty_on_share(cfg)

    # Get terminal size
    try:
        size = os.get_terminal_size()
        rows, cols = size.lines, size.columns
    except OSError:
        rows, cols = 24, 80

    # Start TCP listener on virbr0. The whole bind+listen sequence goes
    # through one try/except so a socket leak isn't possible if `listen()`
    # or anything else raises -- the previous code only caught OSError on
    # bind, leaving the socket open if listen() raised something exotic.
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((cfg.host_ip, port))
        server.listen(1)
    except Exception as e:
        server.close()
        console.print(f"[red][-][/] Cannot bind {cfg.host_ip}:{port}: {e}")
        return
    console.print(f"[blue][*][/] Listening on {cfg.host_ip}:{port}")

    # Build PowerShell command — read script from Z:\ (VirtIO-FS share root)
    nopty_flag = " -NoPty" if pipe_mode else ""
    ps_cmd = (
        f"IEX(Get-Content 'Z:\\{CONPTY_SCRIPT}' -Raw); "
        f"Invoke-ConPtyShell -RemoteIp {cfg.host_ip} -RemotePort {port} "
        f"-Rows {rows} -Cols {cols}{nopty_flag}"
    )
    encoded = base64.b64encode(ps_cmd.encode("utf-16-le")).decode("ascii")
    cmd = f"powershell -ExecutionPolicy Bypass -EncodedCommand {encoded}"

    # Fire via guest agent — detached, the shell runs until we disconnect
    mode = "pipe" if pipe_mode else "ConPTY"
    identity = user or "SYSTEM"
    console.print(f"[blue][*][/] Launching reverse shell as {identity} ({mode})...")
    shell_pid: int | None = None
    try:
        shell_pid = ga.exec_detached(cmd, user=user, password=password)
    except Exception:
        server.close()
        console.print("[red][-][/] Failed to launch reverse shell via guest agent")
        return

    # Wait for incoming connection
    server.settimeout(30)
    try:
        client, addr = server.accept()
    except socket.timeout:
        # Probe the launched PowerShell to surface its stderr/exitcode
        # instead of the opaque "timed out" the user used to see. If the
        # in-guest script crashed (Z: not mounted, ConPTY module missing,
        # firewall block, etc.) the diagnostic is right here.
        diag = None
        if shell_pid:
            try:
                status = ga.exec_status(shell_pid)
                if status.get("exited"):
                    diag = (
                        f"shell process (PID {shell_pid}) exited "
                        f"rc={status.get('exitcode')!r}"
                    )
                    stderr = (status.get("stderr") or "").strip()
                    if stderr:
                        diag += f"; stderr: {stderr.splitlines()[-1][:200]}"
                else:
                    diag = (
                        f"shell process (PID {shell_pid}) is still running "
                        "but never connected back — likely a firewall block "
                        f"on {cfg.host_ip}:{port}"
                    )
            except Exception:
                diag = None
            # Best-effort kill the orphan regardless of probe outcome.
            try:
                ga.exec(f"taskkill /PID {shell_pid} /F", timeout=10)
            except Exception:
                pass
        console.print("[red][-][/] Timed out waiting for connection")
        if diag:
            console.print(f"    {diag}")
        return
    finally:
        server.close()

    # TCP keepalive on the relay socket so a half-open connection (VM
    # suspended, network hiccup) eventually surfaces as a recv error
    # instead of leaving the user wedged forever waiting on stdin.
    try:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, "TCP_KEEPIDLE"):
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
        if hasattr(socket, "TCP_KEEPINTVL"):
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 30)
        if hasattr(socket, "TCP_KEEPCNT"):
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except OSError:
        pass  # keepalive is a nice-to-have, not a hard requirement

    # Validate connecting IP matches expected VM
    vm = VM(cfg)
    expected_ip = vm.ip()
    if not expected_ip or addr[0] != expected_ip:
        client.close()
        # Kill orphaned shell process in VM
        if shell_pid:
            try:
                ga.exec(f"taskkill /PID {shell_pid} /F", timeout=10)
            except Exception:
                pass
        if not expected_ip:
            raise click.ClickException(
                f"Cannot verify connecting IP {addr[0]} — VM IP unknown"
            )
        raise click.ClickException(
            f"Rejected connection from {addr[0]} (expected VM at {expected_ip})"
        )

    console.print(f"[green][+][/] {identity} shell ready — type 'exit' to close\n")

    # Enter raw terminal mode and relay I/O
    if pipe_mode:
        _relay_pipe(client)
    else:
        _relay(client)


def _relay(sock: socket.socket) -> None:
    """Raw terminal I/O relay between stdin/stdout and the socket."""
    if not sys.stdin.isatty():
        console.print("[red][-][/] shell requires an interactive terminal")
        return
    old_settings = termios.tcgetattr(sys.stdin)
    tty.setraw(sys.stdin)

    # Self-pipe so SIGWINCH wakes up select()
    sig_r, sig_w = os.pipe()
    os.set_blocking(sig_r, False)
    os.set_blocking(sig_w, False)
    old_wakeup = signal.set_wakeup_fd(sig_w)
    old_handler = signal.signal(signal.SIGWINCH, lambda *_: None)

    try:
        while True:
            readable, _, _ = select.select([sys.stdin, sock, sig_r], [], [])
            if sig_r in readable:
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
        signal.signal(signal.SIGWINCH, old_handler)
        signal.set_wakeup_fd(old_wakeup)
        os.close(sig_r)
        os.close(sig_w)
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        sock.close()
        console.print("\n[blue][*][/] Shell closed")
