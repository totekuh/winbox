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


class LineEditor:
    """Pure state-machine line editor for pipe-mode shell. No I/O."""

    def __init__(self, term_cols: int = 80):
        self.buf = bytearray()
        self.pos = 0
        self.history: list[bytes] = []
        self.hist_idx = -1
        self.saved = bytearray()
        self.term_cols = max(1, term_cols)
        self.start_col = 0

    def screen(self, bpos: int) -> tuple[int, int]:
        return divmod(self.start_col + bpos, self.term_cols)

    def move(self, from_bpos: int, to_bpos: int) -> bytes:
        if from_bpos == to_bpos:
            return b""
        fl, fc = self.screen(from_bpos)
        tl, tc = self.screen(to_bpos)
        seq = b""
        if tl < fl:
            seq += b"\x1b[%dA" % (fl - tl)
        elif tl > fl:
            seq += b"\x1b[%dB" % (tl - fl)
        if tc != fc:
            seq += b"\r"
            if tc > 0:
                seq += b"\x1b[%dC" % tc
        return seq

    def redraw(self, cursor_at: int) -> bytes:
        out = self.move(cursor_at, 0)
        out += b"\x1b[J"
        if self.buf:
            out += bytes(self.buf)
            if self.pos < len(self.buf):
                out += self.move(len(self.buf), self.pos)
        return out

    def track_col(self, data: bytes) -> None:
        i = 0
        while i < len(data):
            b = data[i]
            if b == 0x1B and i + 1 < len(data) and data[i + 1] == 0x5B:
                i += 2
                while i < len(data) and not (0x40 <= data[i] <= 0x7E):
                    i += 1
                if i < len(data):
                    i += 1
            elif b == 0x0D:
                self.start_col = 0
                i += 1
            elif b == 0x0A:
                self.start_col = 0
                i += 1
            elif b == 0x08:
                if self.start_col > 0:
                    self.start_col -= 1
                i += 1
            elif b >= 0x20:
                self.start_col += 1
                if self.start_col >= self.term_cols:
                    self.start_col = 0
                i += 1
            else:
                i += 1

    def resize(self, cols: int) -> bytes:
        self.term_cols = max(1, cols)
        if self.buf:
            return self.redraw(self.pos)
        return b""

    def insert(self, data: bytes) -> bytes:
        old = self.pos
        self.buf[self.pos:self.pos] = data
        self.pos += len(data)
        if self.pos == len(self.buf):
            return data
        return self.redraw(old)

    def enter(self) -> tuple[bytes, bytes]:
        out = b""
        if self.pos < len(self.buf):
            out += self.move(self.pos, len(self.buf))
        out += b"\r\n"
        line = bytes(self.buf)
        if line.strip():
            self.history.append(line)
        self.buf.clear()
        self.pos = 0
        self.hist_idx = -1
        self.start_col = 0
        return out, line + b"\n"

    def backspace(self) -> bytes:
        if self.pos <= 0:
            return b""
        old = self.pos
        del self.buf[self.pos - 1]
        self.pos -= 1
        return self.redraw(old)

    def delete(self) -> bytes:
        if self.pos >= len(self.buf):
            return b""
        del self.buf[self.pos]
        return self.redraw(self.pos)

    def cursor_left(self) -> bytes:
        if self.pos <= 0:
            return b""
        old = self.pos
        self.pos -= 1
        return self.move(old, self.pos)

    def cursor_right(self) -> bytes:
        if self.pos >= len(self.buf):
            return b""
        old = self.pos
        self.pos += 1
        return self.move(old, self.pos)

    def word_left(self) -> bytes:
        if self.pos <= 0:
            return b""
        old = self.pos
        while self.pos > 0 and self.buf[self.pos - 1 : self.pos] == b" ":
            self.pos -= 1
        while self.pos > 0 and self.buf[self.pos - 1 : self.pos] != b" ":
            self.pos -= 1
        if self.pos == old:
            return b""
        return self.move(old, self.pos)

    def word_right(self) -> bytes:
        if self.pos >= len(self.buf):
            return b""
        old = self.pos
        while self.pos < len(self.buf) and self.buf[self.pos : self.pos + 1] == b" ":
            self.pos += 1
        while self.pos < len(self.buf) and self.buf[self.pos : self.pos + 1] != b" ":
            self.pos += 1
        if self.pos == old:
            return b""
        return self.move(old, self.pos)

    def home(self) -> bytes:
        if self.pos <= 0:
            return b""
        old = self.pos
        self.pos = 0
        return self.move(old, self.pos)

    def end(self) -> bytes:
        if self.pos >= len(self.buf):
            return b""
        old = self.pos
        self.pos = len(self.buf)
        return self.move(old, self.pos)

    def history_up(self) -> bytes:
        if not self.history or self.hist_idx >= len(self.history) - 1:
            return b""
        old = self.pos
        if self.hist_idx == -1:
            self.saved[:] = self.buf[:]
        self.hist_idx += 1
        self.buf[:] = bytearray(self.history[-(self.hist_idx + 1)])
        self.pos = len(self.buf)
        return self.redraw(old)

    def history_down(self) -> bytes:
        if self.hist_idx <= -1:
            return b""
        old = self.pos
        if self.hist_idx > 0:
            self.hist_idx -= 1
            self.buf[:] = bytearray(self.history[-(self.hist_idx + 1)])
        else:
            self.hist_idx = -1
            self.buf[:] = self.saved[:]
        self.pos = len(self.buf)
        return self.redraw(old)

    def ctrl_c(self) -> tuple[bytes, bytes]:
        out = b""
        if self.pos < len(self.buf):
            out += self.move(self.pos, len(self.buf))
        out += b"^C\r\n"
        self.buf.clear()
        self.pos = 0
        self.hist_idx = -1
        self.start_col = 0
        return out, b"\n"

    def ctrl_k(self) -> bytes:
        if self.pos >= len(self.buf):
            return b""
        del self.buf[self.pos :]
        return self.redraw(self.pos)

    def ctrl_u(self) -> bytes:
        if self.pos <= 0:
            return b""
        old = self.pos
        del self.buf[: self.pos]
        self.pos = 0
        return self.redraw(old)

    def ctrl_w(self) -> bytes:
        if self.pos <= 0:
            return b""
        old = self.pos
        while self.pos > 0 and self.buf[self.pos - 1 : self.pos] == b" ":
            self.pos -= 1
        while self.pos > 0 and self.buf[self.pos - 1 : self.pos] != b" ":
            self.pos -= 1
        del self.buf[self.pos : old]
        return self.redraw(old)

    def clear_screen(self) -> bytes:
        out = b"\x1b[2J\x1b[H"
        self.start_col = 0
        if self.buf:
            out += bytes(self.buf)
            if self.pos < len(self.buf):
                out += self.move(len(self.buf), self.pos)
        return out

    def tab(self) -> bytes:
        return b"\x07"


def _relay_pipe(sock: socket.socket) -> None:
    """Line-buffered relay with client-side readline for pipe mode."""
    if not sys.stdin.isatty():
        console.print("[red][-][/] shell requires an interactive terminal")
        return
    old_settings = termios.tcgetattr(sys.stdin)
    tty.setraw(sys.stdin)

    stdout_fd = sys.stdout.fileno()
    stdin_fd = sys.stdin.fileno()

    try:
        cols = os.get_terminal_size().columns
    except OSError:
        cols = 80
    ed = LineEditor(term_cols=cols)
    _inbuf = bytearray()

    sig_r, sig_w = os.pipe()
    os.set_blocking(sig_r, False)
    os.set_blocking(sig_w, False)
    old_wakeup = signal.set_wakeup_fd(sig_w)
    old_sighandler = signal.signal(signal.SIGWINCH, lambda *_: None)

    def out(data: bytes) -> None:
        if data:
            os.write(stdout_fd, data)

    def _fill(n=1, timeout=0.02):
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
            if not _inbuf:
                readable, _, _ = select.select([sys.stdin, sock, sig_r], [], [])

                if sig_r in readable:
                    try:
                        os.read(sig_r, 4096)
                    except OSError:
                        pass
                    try:
                        out(ed.resize(os.get_terminal_size().columns))
                    except OSError:
                        pass

                if sock in readable:
                    data = sock.recv(4096)
                    if not data:
                        break
                    if ed.buf:
                        out(ed.move(ed.pos, 0))
                        out(b"\x1b[J")
                    out(data)
                    ed.track_col(data)
                    if ed.buf:
                        out(bytes(ed.buf))
                        if ed.pos < len(ed.buf):
                            out(ed.move(len(ed.buf), ed.pos))

                if sys.stdin in readable:
                    raw = os.read(stdin_fd, 1024)
                    if not raw:
                        break
                    _inbuf.extend(raw)

            if not _inbuf:
                continue

            b = _inbuf[0]

            if b >= 0x20 and b != 0x7F:
                end = 1
                while end < len(_inbuf) and _inbuf[end] >= 0x20 and _inbuf[end] != 0x7F:
                    end += 1
                run = bytes(_inbuf[:end])
                del _inbuf[:end]
                out(ed.insert(run))
                continue

            del _inbuf[0]

            if b == 0x0D:
                stdout_bytes, sock_bytes = ed.enter()
                out(stdout_bytes)
                sock.sendall(sock_bytes)
            elif b in (0x7F, 0x08):
                out(ed.backspace())
            elif b == 0x1B:
                if not _fill(1):
                    continue
                if _inbuf[0] != 0x5B:
                    continue
                del _inbuf[0]
                if not _fill(1):
                    continue
                c = _inbuf[0]
                del _inbuf[0]
                if c == 0x41:
                    out(ed.history_up())
                elif c == 0x42:
                    out(ed.history_down())
                elif c == 0x43:
                    out(ed.cursor_right())
                elif c == 0x44:
                    out(ed.cursor_left())
                elif c == 0x31:
                    if _fill(3):
                        rest = bytes(_inbuf[:3])
                        del _inbuf[:3]
                        if rest[0:2] == b";5":
                            if rest[2:3] == b"C":
                                out(ed.word_right())
                            elif rest[2:3] == b"D":
                                out(ed.word_left())
                elif c == 0x48:
                    out(ed.home())
                elif c == 0x46:
                    out(ed.end())
                elif c == 0x33:
                    if _fill(1):
                        del _inbuf[0]
                    out(ed.delete())
            elif b == 0x03:
                stdout_bytes, sock_bytes = ed.ctrl_c()
                out(stdout_bytes)
                sock.sendall(sock_bytes)
            elif b == 0x04:
                break
            elif b == 0x09:
                out(ed.tab())
            elif b == 0x1A:
                sock.sendall(b"\x1a")
            elif b == 0x01:
                out(ed.home())
            elif b == 0x05:
                out(ed.end())
            elif b == 0x0B:
                out(ed.ctrl_k())
            elif b == 0x15:
                out(ed.ctrl_u())
            elif b == 0x17:
                out(ed.ctrl_w())
            elif b == 0x0C:
                out(ed.clear_screen())

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
