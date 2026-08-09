"""Packet capture for malware detonation — capture VM traffic to a pcap.

`winbox capture start/stop/status`. Runs a host-side capture process on the
libvirt bridge (virbr0) so the VM's traffic is seen pre-SNAT: DNS queries
and TCP SYNs carry the real/sinkhole destination, which is exactly what
you want for C2 extraction afterwards.

This is a host-local process (not a guest job): the capture runs on Kali,
detached, with its pid recorded in a pidfile under the Config dir so
`stop`/`status` can find it again.

Backend: prefers ``dumpcap`` over ``tcpdump``. Debian/Kali's Wireshark
package installs ``dumpcap`` as root:wireshark, mode 750, with
``cap_net_raw``/``cap_net_admin`` set on the file — so any member of the
``wireshark`` group can capture without root, without ever needing sudo.
Plain ``tcpdump`` carries no such capability by default and almost always
needs root. Falls back to it only when ``dumpcap`` isn't installed.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from datetime import datetime
from pathlib import Path

import click

from winbox.cli import console
from winbox.config import Config
from winbox.vm import virsh_run

# Fallback bridge for libvirt's "default" network.
DEFAULT_BRIDGE = "virbr0"

# Backends in preference order — dumpcap first, since it's the one that
# commonly works without root on a Kali box.
_BACKENDS = ("dumpcap", "tcpdump")


def captures_dir(cfg: Config) -> Path:
    """Directory where pcaps and the capture state live."""
    return cfg.winbox_dir / "captures"


def pidfile_path(cfg: Config) -> Path:
    """Pidfile recording the running tcpdump pid and its pcap path."""
    return captures_dir(cfg) / "capture.pid"


def discover_bridge(net: str = "default") -> str:
    """Return the host bridge for a libvirt network.

    Parses the ``Bridge:`` line of ``virsh net-info <net>``. Falls back to
    :data:`DEFAULT_BRIDGE` if virsh fails or the line is absent.
    """
    try:
        result = virsh_run("net-info", net, check=False)
    except Exception:
        return DEFAULT_BRIDGE
    if result.returncode != 0:
        return DEFAULT_BRIDGE
    for line in result.stdout.splitlines():
        if line.strip().lower().startswith("bridge:"):
            _, _, value = line.partition(":")
            value = value.strip()
            if value:
                return value
    return DEFAULT_BRIDGE


def read_pidfile(cfg: Config) -> tuple[int, Path] | None:
    """Read (pid, pcap_path) from the pidfile, or None if absent/malformed."""
    pf = pidfile_path(cfg)
    if not pf.exists():
        return None
    try:
        lines = pf.read_text().splitlines()
        pid = int(lines[0].strip())
        pcap = Path(lines[1].strip())
    except (ValueError, IndexError):
        return None
    return pid, pcap


def pid_alive(pid: int) -> bool:
    """True if a process with this pid exists."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Exists but owned by another user (likely root tcpdump).
        return True
    return True


def pick_backend() -> str | None:
    """First available capture binary, dumpcap preferred. None if neither."""
    for name in _BACKENDS:
        if shutil.which(name):
            return name
    return None


def can_capture_unprivileged(path: str) -> bool:
    """True if ``path`` can open a capture socket without root.

    Root can always capture. Otherwise the binary needs to be executable by
    us *and* carry ``cap_net_raw`` — both must hold, since a file can have
    the capability set yet still be group-restricted to a group we are not
    in (exactly dumpcap's default packaging: root:wireshark, mode 750).
    """
    if os.geteuid() == 0:
        return True
    if not os.access(path, os.X_OK):
        return False
    try:
        result = subprocess.run(
            ["getcap", path], capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return "cap_net_raw" in result.stdout


def build_capture_cmd(backend: str, bridge: str, pcap: Path, bpf: str | None) -> list[str]:
    if backend == "tcpdump":
        # -U: packet-buffered so the pcap is readable mid-capture.
        cmd = ["tcpdump", "-i", bridge, "-U", "-w", str(pcap)]
        if bpf:
            cmd.append(bpf)
    else:  # dumpcap
        cmd = ["dumpcap", "-i", bridge, "-w", str(pcap)]
        if bpf:
            cmd += ["-f", bpf]
    return cmd


def _human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


@click.group()
def capture() -> None:
    """Capture VM network traffic to a pcap (for C2 extraction)."""
    pass


@capture.command("start")
@click.option(
    "--filter", "bpf", default=None,
    help="Optional BPF capture filter (e.g. 'not port 22').",
)
@click.option(
    "--output", "-o", "output", type=click.Path(dir_okay=False), default=None,
    help="Override pcap output path (default: <winbox_dir>/captures/<ts>.pcap).",
)
@click.pass_context
def capture_start(ctx: click.Context, bpf: str | None, output: str | None) -> None:
    """Start capturing VM traffic on the host bridge.

    Uses dumpcap when it can capture without root (the common case on Kali —
    see the module docstring), otherwise tcpdump, which needs root unless
    you've set capabilities on it yourself. Stop with `winbox capture stop`.
    """
    cfg: Config = ctx.obj["cfg"]

    backend = pick_backend()
    if backend is None:
        console.print("[red][-][/] Neither dumpcap nor tcpdump found.")
        console.print("    Install with: [bold]apt install tshark[/] (recommended, no-root capture) "
                       "or [bold]apt install tcpdump[/]")
        raise SystemExit(1)

    binary_path = shutil.which(backend)
    if not can_capture_unprivileged(binary_path):
        console.print(f"[red][-][/] {backend} needs elevated privileges to capture on the bridge.")
        if backend == "dumpcap":
            console.print("    Join the wireshark group and re-login: "
                           "[bold]sudo usermod -aG wireshark $USER[/]")
            console.print("    Or re-run with sudo: [bold]sudo -E winbox capture start[/]")
        else:
            console.print("    Re-run with sudo: [bold]sudo -E winbox capture start[/]")
        raise SystemExit(1)

    existing = read_pidfile(cfg)
    if existing and pid_alive(existing[0]):
        console.print(f"[yellow][!][/] Capture already running (pid {existing[0]})")
        console.print(f"    pcap: {existing[1]}")
        console.print("    Stop it first: [bold]winbox capture stop[/]")
        raise SystemExit(1)

    bridge = discover_bridge()

    cap_dir = captures_dir(cfg)
    cap_dir.mkdir(parents=True, exist_ok=True)

    if output:
        pcap = Path(output)
        pcap.parent.mkdir(parents=True, exist_ok=True)
    else:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        pcap = cap_dir / f"capture-{ts}.pcap"

    cmd = build_capture_cmd(backend, bridge, pcap, bpf)

    # stderr goes to a small logfile, not a PIPE: an unread PIPE fills its
    # kernel buffer on a long capture and blocks the child writing to it.
    log_path = pcap.with_suffix(pcap.suffix + ".log")
    with open(log_path, "wb") as errlog:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=errlog)

    # Give it a beat to fail fast (bad interface, a permission surprise the
    # capability check above didn't catch) instead of reporting success over
    # a process that already exited.
    time.sleep(0.3)
    if proc.poll() is not None:
        detail = log_path.read_text(errors="replace").strip() if log_path.exists() else ""
        console.print(f"[red][-][/] {backend} exited immediately (code {proc.returncode})")
        if detail:
            console.print(f"    {detail}")
        log_path.unlink(missing_ok=True)
        raise SystemExit(1)

    pidfile_path(cfg).write_text(f"{proc.pid}\n{pcap}\n")

    console.print(f"[green][+][/] Capturing on [bold]{bridge}[/] via {backend} (pid {proc.pid})")
    console.print(f"    pcap: {pcap}")
    if bpf:
        console.print(f"    filter: {bpf}")
    console.print("    Stop with: [bold]winbox capture stop[/]")


@capture.command("stop")
@click.pass_context
def capture_stop(ctx: click.Context) -> None:
    """Stop the running capture and report where the pcap was saved."""
    cfg: Config = ctx.obj["cfg"]

    state = read_pidfile(cfg)
    if state is None:
        console.print("[yellow][!][/] No capture running (no pidfile)")
        raise SystemExit(1)

    pid, pcap = state
    if pid_alive(pid):
        try:
            os.kill(pid, signal.SIGTERM)
            console.print(f"[green][+][/] Stopped capture (pid {pid})")
        except ProcessLookupError:
            console.print(f"[yellow][!][/] Process {pid} already gone")
    else:
        console.print(f"[yellow][!][/] Capture not running (stale pid {pid})")

    pidfile_path(cfg).unlink(missing_ok=True)

    if pcap.exists():
        size = _human_size(pcap.stat().st_size)
        console.print(f"    pcap saved: {pcap} ({size})")
    else:
        console.print(f"    pcap path: {pcap} [yellow](not found)[/]")


@capture.command("status")
@click.pass_context
def capture_status(ctx: click.Context) -> None:
    """Show whether a capture is running, the bridge, and the pcap."""
    cfg: Config = ctx.obj["cfg"]

    bridge = discover_bridge()
    console.print(f"Bridge:  {bridge}")

    state = read_pidfile(cfg)
    if state is None:
        console.print("Capture: [red]stopped[/]")
        return

    pid, pcap = state
    if pid_alive(pid):
        console.print(f"Capture: [green]running[/] (pid {pid})")
    else:
        console.print(f"Capture: [red]stopped[/] (stale pid {pid})")

    if pcap.exists():
        size = _human_size(pcap.stat().st_size)
        console.print(f"pcap:    {pcap} ({size})")
    else:
        console.print(f"pcap:    {pcap} [yellow](not found)[/]")


REGISTER = ("Malware Analysis", [capture])
