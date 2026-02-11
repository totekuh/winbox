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
    if pipe_mode:
        _relay_pipe(client)
    else:
        _relay(client)


def _relay(sock: socket.socket) -> None:
    """Raw terminal I/O relay between stdin/stdout and the socket."""
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


def _relay_pipe(sock: socket.socket) -> None:
    """Line-buffered relay with client-side readline for pipe mode.

    Provides local line editing (backspace, arrows, history) since the
    remote shell has no terminal in pipe mode — std handles are kernel
    pipe objects, not console pseudo-handles.
    """
    old_settings = termios.tcgetattr(sys.stdin)
    tty.setraw(sys.stdin)

    stdout_fd = sys.stdout.fileno()
    stdin_fd = sys.stdin.fileno()

    buf = bytearray()       # current line being edited
    pos = 0                 # cursor position within buf
    history: list[bytes] = []
    hist_idx = -1           # -1 = not browsing history
    saved = bytearray()     # line saved when entering history browse

    def out(data: bytes) -> None:
        os.write(stdout_fd, data)

    def _replace_buf(new: bytes) -> None:
        """Replace visible input line with new content, cursor at end."""
        nonlocal pos
        # Move cursor to start of our buffer
        if pos > 0:
            out(b'\x1b[%dD' % pos)
        # Write new content + spaces to clear any leftover old chars
        pad = max(0, len(buf) - len(new))
        out(new + b' ' * pad)
        if pad > 0:
            out(b'\x1b[%dD' % pad)
        buf[:] = bytearray(new)
        pos = len(buf)

    try:
        while True:
            readable, _, _ = select.select([sys.stdin, sock], [], [])

            if sock in readable:
                data = sock.recv(4096)
                if not data:
                    break
                # Erase user's partial input, print output, then redraw
                if buf:
                    if pos > 0:
                        out(b'\x1b[%dD' % pos)
                    out(b'\x1b[K')
                out(data)
                if buf:
                    out(bytes(buf))
                    if pos < len(buf):
                        out(b'\x1b[%dD' % (len(buf) - pos))

            if sys.stdin in readable:
                ch = os.read(stdin_fd, 1)
                if not ch:
                    break
                b = ch[0]

                if b == 0x0d:  # Enter
                    out(b'\r\n')
                    line = bytes(buf)
                    sock.sendall(line + b'\n')
                    if line.strip():
                        history.append(line)
                    buf.clear()
                    pos = 0
                    hist_idx = -1

                elif b in (0x7f, 0x08):  # Backspace
                    if pos > 0:
                        del buf[pos - 1]
                        pos -= 1
                        # Rewrite from cursor: remaining chars + space to clear old last char
                        tail = bytes(buf[pos:]) + b' '
                        out(b'\b' + tail + b'\x1b[%dD' % len(tail))

                elif b == 0x1b:  # Escape sequence start
                    # Wait briefly for rest of sequence (bare Esc = ignore)
                    r, _, _ = select.select([sys.stdin], [], [], 0.02)
                    if not r:
                        continue
                    s1 = os.read(stdin_fd, 1)
                    if not s1 or s1[0] != 0x5b:  # expect [
                        continue
                    s2 = os.read(stdin_fd, 1)
                    if not s2:
                        break
                    c = s2[0]

                    if c == 0x41:  # Up — previous history
                        if history and hist_idx < len(history) - 1:
                            if hist_idx == -1:
                                saved[:] = buf[:]
                            hist_idx += 1
                            _replace_buf(history[-(hist_idx + 1)])

                    elif c == 0x42:  # Down — next history
                        if hist_idx > 0:
                            hist_idx -= 1
                            _replace_buf(history[-(hist_idx + 1)])
                        elif hist_idx == 0:
                            hist_idx = -1
                            _replace_buf(bytes(saved))

                    elif c == 0x43 and pos < len(buf):  # Right
                        out(b'\x1b[C')
                        pos += 1

                    elif c == 0x44 and pos > 0:  # Left
                        out(b'\x1b[D')
                        pos -= 1

                    elif c == 0x31:  # ESC[1;5C / ESC[1;5D — Ctrl+Right/Left
                        rest = os.read(stdin_fd, 3)  # ";5C" or ";5D"
                        if len(rest) == 3 and rest[0:2] == b';5':
                            old_pos = pos
                            if rest[2:3] == b'C':  # Ctrl+Right
                                while pos < len(buf) and buf[pos:pos+1] == b' ':
                                    pos += 1
                                while pos < len(buf) and buf[pos:pos+1] != b' ':
                                    pos += 1
                                if pos > old_pos:
                                    out(b'\x1b[%dC' % (pos - old_pos))
                            elif rest[2:3] == b'D':  # Ctrl+Left
                                while pos > 0 and buf[pos-1:pos] == b' ':
                                    pos -= 1
                                while pos > 0 and buf[pos-1:pos] != b' ':
                                    pos -= 1
                                if old_pos > pos:
                                    out(b'\x1b[%dD' % (old_pos - pos))

                    elif c == 0x48 and pos > 0:  # Home
                        out(b'\x1b[%dD' % pos)
                        pos = 0

                    elif c == 0x46 and pos < len(buf):  # End
                        out(b'\x1b[%dC' % (len(buf) - pos))
                        pos = len(buf)

                    elif c == 0x33:  # Delete key (ESC[3~)
                        os.read(stdin_fd, 1)  # consume ~
                        if pos < len(buf):
                            del buf[pos]
                            tail = bytes(buf[pos:]) + b' '
                            out(tail + b'\x1b[%dD' % len(tail))

                elif b == 0x03:  # Ctrl+C
                    out(b'^C\r\n')
                    buf.clear()
                    pos = 0
                    hist_idx = -1
                    sock.sendall(b'\n')  # trigger fresh prompt

                elif b == 0x04:  # Ctrl+D
                    break

                elif b == 0x01 and pos > 0:  # Ctrl+A — Home
                    out(b'\x1b[%dD' % pos)
                    pos = 0

                elif b == 0x05 and pos < len(buf):  # Ctrl+E — End
                    out(b'\x1b[%dC' % (len(buf) - pos))
                    pos = len(buf)

                elif b == 0x0b:  # Ctrl+K — kill to end of line
                    if pos < len(buf):
                        out(b'\x1b[K')
                        del buf[pos:]

                elif b == 0x15:  # Ctrl+U — kill to start of line
                    if pos > 0:
                        deleted = pos
                        del buf[:pos]
                        pos = 0
                        out(b'\x1b[%dD' % deleted)
                        out(bytes(buf) + b' ' * deleted)
                        out(b'\x1b[%dD' % (len(buf) + deleted))

                elif b == 0x17:  # Ctrl+W — delete word backward
                    if pos > 0:
                        old_pos = pos
                        while pos > 0 and buf[pos-1:pos] == b' ':
                            pos -= 1
                        while pos > 0 and buf[pos-1:pos] != b' ':
                            pos -= 1
                        deleted = old_pos - pos
                        del buf[pos:old_pos]
                        out(b'\x1b[%dD' % deleted)
                        out(bytes(buf[pos:]) + b' ' * deleted)
                        out(b'\x1b[%dD' % (len(buf) - pos + deleted))

                elif b == 0x0c:  # Ctrl+L — clear screen
                    out(b'\x1b[2J\x1b[H')  # clear + cursor home
                    # Redraw whatever was in the buffer
                    out(bytes(buf))
                    if pos < len(buf):
                        out(b'\x1b[%dD' % (len(buf) - pos))

                elif b >= 0x20:  # Printable character
                    buf.insert(pos, b)
                    pos += 1
                    if pos == len(buf):
                        out(bytes([b]))
                    else:
                        # Write from inserted char onward, then reposition cursor
                        tail = bytes(buf[pos - 1:])
                        out(tail + b'\x1b[%dD' % (len(buf) - pos))

    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        sock.close()
        console.print("\n[blue][*][/] Shell closed")
