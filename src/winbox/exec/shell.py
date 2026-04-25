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
) -> None:
    """Open an interactive SYSTEM shell via ConPTY reverse connection."""
    if cfg.host_ip == "0.0.0.0":
        console.print(
            "[yellow][!][/] Warning: host_ip is 0.0.0.0 — shell listener exposed on all interfaces"
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
    console.print(f"[blue][*][/] Launching reverse shell as SYSTEM ({mode})...")
    shell_pid: int | None = None
    try:
        shell_pid = ga.exec_detached(cmd)
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

    console.print("[green][+][/] SYSTEM shell ready — type 'exit' to close\n")

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


def _relay_pipe(sock: socket.socket) -> None:
    """Line-buffered relay with client-side readline for pipe mode.

    Provides local line editing (backspace, arrows, history) since the
    remote shell has no terminal in pipe mode — std handles are kernel
    pipe objects, not console pseudo-handles.

    Handles multi-line wrapping by tracking terminal width and prompt
    column, using cursor up/down + absolute column for line crossings.
    """
    if not sys.stdin.isatty():
        console.print("[red][-][/] shell requires an interactive terminal")
        return
    old_settings = termios.tcgetattr(sys.stdin)
    tty.setraw(sys.stdin)

    stdout_fd = sys.stdout.fileno()
    stdin_fd = sys.stdin.fileno()

    buf = bytearray()       # current line being edited
    pos = 0                 # cursor position within buf
    history: list[bytes] = []
    hist_idx = -1           # -1 = not browsing history
    saved = bytearray()     # line saved when entering history browse
    _inbuf = bytearray()    # input buffer for batching reads

    try:
        term_cols = os.get_terminal_size().columns
    except OSError:
        term_cols = 80
    start_col = 0           # cursor column where user input starts (after prompt)

    # SIGWINCH handling — keep term_cols accurate after terminal resize
    sig_r, sig_w = os.pipe()
    os.set_blocking(sig_r, False)
    os.set_blocking(sig_w, False)
    old_wakeup = signal.set_wakeup_fd(sig_w)
    old_sighandler = signal.signal(signal.SIGWINCH, lambda *_: None)

    def out(data: bytes) -> None:
        os.write(stdout_fd, data)

    def _screen(bpos: int) -> tuple[int, int]:
        """Screen (line_offset, column) for a buffer position."""
        return divmod(start_col + bpos, term_cols)

    def _move(from_bpos: int, to_bpos: int) -> None:
        """Move terminal cursor between two buffer positions (handles line wrapping)."""
        if from_bpos == to_bpos:
            return
        fl, fc = _screen(from_bpos)
        tl, tc = _screen(to_bpos)
        seq = b''
        if tl < fl:
            seq += b'\x1b[%dA' % (fl - tl)
        elif tl > fl:
            seq += b'\x1b[%dB' % (tl - fl)
        if tc != fc:
            seq += b'\r'
            if tc > 0:
                seq += b'\x1b[%dC' % tc
        out(seq)

    def _redraw(cursor_at: int) -> None:
        """Erase all user input and rewrite. cursor_at = where cursor physically is."""
        nonlocal term_cols
        try:
            term_cols = os.get_terminal_size().columns
        except OSError:
            pass
        _move(cursor_at, 0)
        out(b'\x1b[J')  # clear from cursor to end of screen
        if buf:
            out(bytes(buf))
            if pos < len(buf):
                _move(len(buf), pos)

    def _track_col(data: bytes) -> None:
        """Update start_col by tracking cursor column through output data."""
        nonlocal start_col
        i = 0
        while i < len(data):
            b = data[i]
            if b == 0x1b and i + 1 < len(data) and data[i + 1] == 0x5b:
                # Skip CSI sequence: ESC[ ... final_byte
                i += 2
                while i < len(data) and not (0x40 <= data[i] <= 0x7e):
                    i += 1
                if i < len(data):
                    i += 1
            elif b == 0x0d:  # \r
                start_col = 0
                i += 1
            elif b == 0x0a:  # \n
                start_col = 0
                i += 1
            elif b == 0x08:  # \b
                if start_col > 0:
                    start_col -= 1
                i += 1
            elif b >= 0x20:  # printable
                start_col += 1
                if start_col >= term_cols:
                    start_col = 0
                i += 1
            else:
                i += 1

    def _fill(n=1, timeout=0.02):
        """Ensure at least n bytes in _inbuf, reading from stdin if needed."""
        while len(_inbuf) < n:
            r, _, _ = select.select([sys.stdin], [], [], timeout)
            if r:
                data = os.read(stdin_fd, 1024)
                if data:
                    _inbuf.extend(data)
                else:
                    return False
            else:
                return False
        return True

    try:
        while True:
            # Only block in select when input buffer is empty
            if not _inbuf:
                readable, _, _ = select.select([sys.stdin, sock, sig_r], [], [])

                if sig_r in readable:
                    try:
                        os.read(sig_r, 4096)  # drain wakeup bytes
                    except OSError:
                        pass
                    try:
                        term_cols = os.get_terminal_size().columns
                    except OSError:
                        pass
                    if buf:
                        _redraw(pos)

                if sock in readable:
                    data = sock.recv(4096)
                    if not data:
                        break
                    # Erase user's partial input, print output, then redraw
                    if buf:
                        _move(pos, 0)
                        out(b'\x1b[J')
                    out(data)
                    _track_col(data)
                    if buf:
                        out(bytes(buf))
                        if pos < len(buf):
                            _move(len(buf), pos)

                if sys.stdin in readable:
                    raw = os.read(stdin_fd, 1024)
                    if not raw:
                        break
                    _inbuf.extend(raw)

            if not _inbuf:
                continue

            b = _inbuf[0]

            # Batch-insert printable characters (fast paste support)
            if b >= 0x20 and b != 0x7f:
                end = 1
                while end < len(_inbuf) and _inbuf[end] >= 0x20 and _inbuf[end] != 0x7f:
                    end += 1
                run = bytes(_inbuf[:end])
                del _inbuf[:end]
                old = pos
                buf[pos:pos] = run
                pos += len(run)
                if pos == len(buf):
                    out(run)
                else:
                    _redraw(old)
                continue

            del _inbuf[0]

            if b == 0x0d:  # Enter
                if pos < len(buf):
                    _move(pos, len(buf))
                out(b'\r\n')
                line = bytes(buf)
                sock.sendall(line + b'\n')
                if line.strip():
                    history.append(line)
                buf.clear()
                pos = 0
                hist_idx = -1
                start_col = 0

            elif b in (0x7f, 0x08):  # Backspace
                if pos > 0:
                    old = pos
                    del buf[pos - 1]
                    pos -= 1
                    _redraw(old)

            elif b == 0x1b:  # Escape sequence start
                if not _fill(1):
                    continue
                if _inbuf[0] != 0x5b:  # expect [
                    continue
                del _inbuf[0]
                if not _fill(1):
                    continue
                c = _inbuf[0]
                del _inbuf[0]

                if c == 0x41:  # Up — previous history
                    if history and hist_idx < len(history) - 1:
                        old = pos
                        if hist_idx == -1:
                            saved[:] = buf[:]
                        hist_idx += 1
                        buf[:] = bytearray(history[-(hist_idx + 1)])
                        pos = len(buf)
                        _redraw(old)

                elif c == 0x42:  # Down — next history
                    if hist_idx > 0:
                        old = pos
                        hist_idx -= 1
                        buf[:] = bytearray(history[-(hist_idx + 1)])
                        pos = len(buf)
                        _redraw(old)
                    elif hist_idx == 0:
                        old = pos
                        hist_idx = -1
                        buf[:] = saved[:]
                        pos = len(buf)
                        _redraw(old)

                elif c == 0x43 and pos < len(buf):  # Right
                    old = pos
                    pos += 1
                    _move(old, pos)

                elif c == 0x44 and pos > 0:  # Left
                    old = pos
                    pos -= 1
                    _move(old, pos)

                elif c == 0x31:  # ESC[1;5C / ESC[1;5D — Ctrl+Right/Left
                    if _fill(3):
                        rest = bytes(_inbuf[:3])
                        del _inbuf[:3]
                        if rest[0:2] == b';5':
                            old = pos
                            if rest[2:3] == b'C':  # Ctrl+Right
                                while pos < len(buf) and buf[pos:pos+1] == b' ':
                                    pos += 1
                                while pos < len(buf) and buf[pos:pos+1] != b' ':
                                    pos += 1
                            elif rest[2:3] == b'D':  # Ctrl+Left
                                while pos > 0 and buf[pos-1:pos] == b' ':
                                    pos -= 1
                                while pos > 0 and buf[pos-1:pos] != b' ':
                                    pos -= 1
                            if pos != old:
                                _move(old, pos)

                elif c == 0x48:  # Home
                    if pos > 0:
                        old = pos
                        pos = 0
                        _move(old, pos)

                elif c == 0x46:  # End
                    if pos < len(buf):
                        old = pos
                        pos = len(buf)
                        _move(old, pos)

                elif c == 0x33:  # Delete key (ESC[3~)
                    if _fill(1):
                        del _inbuf[0]  # consume ~
                    if pos < len(buf):
                        del buf[pos]
                        _redraw(pos)

            elif b == 0x03:  # Ctrl+C
                if pos < len(buf):
                    _move(pos, len(buf))
                out(b'^C\r\n')
                buf.clear()
                pos = 0
                hist_idx = -1
                start_col = 0
                sock.sendall(b'\n')  # trigger fresh prompt

            elif b == 0x04:  # Ctrl+D
                break

            elif b == 0x09:  # Tab — no completion in pipe mode
                out(b'\x07')  # bell

            elif b == 0x1a:  # Ctrl+Z — pass through to remote
                sock.sendall(b'\x1a')

            elif b == 0x01:  # Ctrl+A — Home
                if pos > 0:
                    old = pos
                    pos = 0
                    _move(old, pos)

            elif b == 0x05:  # Ctrl+E — End
                if pos < len(buf):
                    old = pos
                    pos = len(buf)
                    _move(old, pos)

            elif b == 0x0b:  # Ctrl+K — kill to end of line
                if pos < len(buf):
                    del buf[pos:]
                    _redraw(pos)

            elif b == 0x15:  # Ctrl+U — kill to start of line
                if pos > 0:
                    old = pos
                    del buf[:pos]
                    pos = 0
                    _redraw(old)

            elif b == 0x17:  # Ctrl+W — delete word backward
                if pos > 0:
                    old = pos
                    while pos > 0 and buf[pos-1:pos] == b' ':
                        pos -= 1
                    while pos > 0 and buf[pos-1:pos] != b' ':
                        pos -= 1
                    del buf[pos:old]
                    _redraw(old)

            elif b == 0x0c:  # Ctrl+L — clear screen
                out(b'\x1b[2J\x1b[H')  # clear + cursor home
                start_col = 0
                if buf:
                    out(bytes(buf))
                    if pos < len(buf):
                        _move(len(buf), pos)

    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        signal.signal(signal.SIGWINCH, old_sighandler)
        signal.set_wakeup_fd(old_wakeup)
        os.close(sig_r)
        os.close(sig_w)
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        sock.close()
        console.print("\n[blue][*][/] Shell closed")
