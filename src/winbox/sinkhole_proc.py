"""Process lifecycle, pidfile management, and INETSim config for the sinkhole."""

from __future__ import annotations

import os
import signal
import socket
import time
from pathlib import Path
from typing import TYPE_CHECKING

from winbox.sinkhole import (
    DNS_PORT,
    READY_MARKER,
    inetsim_conf_path,
    inetsim_data_dir,
    pidfile_path,
    query_log_path,
    server_log_path,
    sinkhole_dir,
)

if TYPE_CHECKING:
    from winbox.config import Config


# ─── process / pidfile management ───────────────────────────────────────────────


def read_pidfile(cfg: Config) -> int | None:
    """Return the PID recorded in the pidfile, or None if absent/garbage.

    The pidfile is ``"<pid>"`` or ``"<pid> <port>"`` (the bound port, when
    not the default). Only the leading PID token is parsed here; the port is
    read separately by :func:`read_port`.
    """
    pf = pidfile_path(cfg)
    if not pf.exists():
        return None
    try:
        text = pf.read_text().strip()
    except OSError:
        return None
    if not text:
        return None
    first = text.split()[0]
    if not first.isdigit():
        return None
    return int(first)


def read_port(cfg: Config) -> int:
    """Return the port recorded in the pidfile, or ``DNS_PORT`` if absent.

    Lets ``status`` report the port the running server actually bound rather
    than assuming the default.
    """
    pf = pidfile_path(cfg)
    if not pf.exists():
        return DNS_PORT
    try:
        tokens = pf.read_text().split()
    except OSError:
        return DNS_PORT
    if len(tokens) >= 2 and tokens[1].isdigit():
        return int(tokens[1])
    return DNS_PORT


def pid_alive(pid: int) -> bool:
    """True if a process with ``pid`` exists and is signalable by us."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but owned by another user
    return True


def _is_sinkhole_proc(pid: int) -> bool:
    """True if ``pid`` looks like our detached ``winbox sinkhole _serve``.

    The pidfile records a bare PID, which Linux recycles freely — a crashed
    sinkhole's PID can be reassigned to an unrelated process, and signalling it
    on ``stop`` would kill a bystander. Confirm identity via the process's own
    command line before we ever signal it. If ``/proc`` can't be read we return
    False (fail safe: refuse to signal an unverifiable PID rather than risk
    hitting the wrong process)."""
    if pid <= 0:
        return False
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmd = f.read().replace(b"\x00", b" ").decode("utf-8", "replace")
    except OSError:
        return False
    return "sinkhole" in cmd and "_serve" in cmd


def is_running(cfg: Config) -> int | None:
    """Return the live sinkhole PID, or None. Cleans up a stale pidfile."""
    pid = read_pidfile(cfg)
    if pid is None:
        return None
    # Alive AND actually our sinkhole — a recycled PID owned by an unrelated
    # process must read as "not running" (and clean up the stale pidfile), not
    # as a live sinkhole.
    if pid_alive(pid) and _is_sinkhole_proc(pid):
        return pid
    # Stale pidfile from a crashed process (or a recycled PID) — clean it up.
    try:
        pidfile_path(cfg).unlink()
    except OSError:
        pass
    return None


def wait_ready(server_log: Path, proc, *, timeout: float = 4.0) -> bool:
    """Block until the detached server is serving, dead, or ``timeout``.

    Returns True once :data:`READY_MARKER` appears in ``server_log`` (the
    server logged a successful bind). Returns False if the process exits
    first (bind failed — the traceback is in ``server_log``) or the timeout
    elapses. ``proc`` is the ``subprocess.Popen`` handle.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if READY_MARKER in server_log.read_text(errors="replace"):
                return True
        except OSError:
            pass
        if proc.poll() is not None:
            return False
        time.sleep(0.1)
    return False


def write_pidfile(cfg: Config, pid: int, port: int | None = None) -> None:
    pf = pidfile_path(cfg)
    pf.parent.mkdir(parents=True, exist_ok=True)
    pf.write_text(f"{pid}\n" if port is None else f"{pid} {port}\n")


def stop(cfg: Config, *, timeout: float = 5.0) -> bool:
    """Stop the detached sinkhole via its pidfile. Returns True if a live
    process was signalled. Always removes the pidfile afterwards."""
    pid = read_pidfile(cfg)
    pf = pidfile_path(cfg)
    if pid is None:
        return False
    # Only signal a PID we can confirm is actually our sinkhole — a recycled PID
    # (crashed sinkhole, OS reassigned the number) must not get SIGTERM/SIGKILL.
    if not pid_alive(pid) or not _is_sinkhole_proc(pid):
        try:
            pf.unlink()
        except OSError:
            pass
        return False

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pid = None
    except PermissionError:
        # Can't signal it (root-owned, we're not root). Leave the pidfile so
        # status still reflects reality; caller surfaces the error.
        raise

    deadline = time.time() + timeout
    while pid is not None and time.time() < deadline:
        if not pid_alive(pid):
            break
        time.sleep(0.1)
    else:
        if pid is not None and pid_alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

    try:
        pf.unlink()
    except OSError:
        pass
    return True


def try_bind(bind_ip: str, port: int = DNS_PORT) -> str:
    """Probe whether we can bind udp/``port`` on ``bind_ip``.

    Returns one of:
      * ``"ok"``      -- the bind succeeded (we can serve here)
      * ``"in_use"``  -- something already holds the address (EADDRINUSE)
      * ``"denied"``  -- we lack privilege for it (EACCES/EPERM, e.g. a
                         port < 1024 as a non-root user with no
                         CAP_NET_BIND_SERVICE / lowered port floor)
      * ``"error:<detail>"`` -- any other bind failure, verbatim

    The probe socket is closed immediately; the momentary gap is harmless.
    This lets ``start`` give an accurate, actionable error instead of
    pre-judging on euid — if the OS permits an unprivileged :53 bind, the
    sinkhole just works.

    The probe deliberately does **not** set ``SO_REUSEADDR``: libvirt's own
    dnsmasq holds the bridge :53 with it, and a probe that also sets it would
    co-bind and return "ok" — so ``start`` would launch the sinkhole over
    dnsmasq, the kernel would keep delivering guest DNS to dnsmasq, and the
    capture would silently record nothing. Without it the probe hits
    EADDRINUSE and correctly reports "in_use".
    """
    import errno

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((bind_ip, port))
    except PermissionError:
        return "denied"
    except OSError as e:
        if e.errno == errno.EADDRINUSE:
            return "in_use"
        if e.errno in (errno.EACCES, errno.EPERM):
            return "denied"
        return f"error:{e}"
    finally:
        s.close()
    return "ok"


def port_in_use(bind_ip: str, port: int = DNS_PORT) -> bool:
    """True if something already holds udp/``port`` on ``bind_ip``.

    Thin wrapper over :func:`try_bind` kept for callers that only care about
    the EADDRINUSE case.
    """
    return try_bind(bind_ip, port) == "in_use"


def line_count(path: Path) -> int:
    """Count lines in the query log (0 if it doesn't exist)."""
    if not path.exists():
        return 0
    try:
        with open(path, "rb") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


# ─── INETSim config generation ──────────────────────────────────────────────────


def inetsim_installed() -> str | None:
    """Path to the INETSim binary if installed, else None."""
    import shutil

    found = shutil.which("inetsim")
    if found:
        return found
    for candidate in ("/usr/bin/inetsim", "/usr/sbin/inetsim"):
        if Path(candidate).exists():
            return candidate
    return None


def build_inetsim_conf(cfg: Config, *, bind_ip: str | None = None,
                       sink_ip: str | None = None) -> str:
    """Render an INETSim config bound to the bridge IP.

    DNS is left OFF on purpose — our own sinkhole owns udp/53. The fake
    service ports (http/https/ftp/smtp/...) are enabled and pointed at the
    bridge so a sample that connects after resolving its C2 to the sink IP
    gets a canned response captured by INETSim.
    """
    bind = bind_ip or cfg.host_ip
    sink = sink_ip or cfg.host_ip
    data_dir = inetsim_data_dir(cfg)
    lines = [
        "# winbox sinkhole — generated INETSim config",
        "# DNS is intentionally disabled: winbox's built-in sinkhole owns udp/53.",
        "# Point the guest's DNS at the bridge with: winbox dns set " + bind,
        "",
        f"service_bind_address   {bind}",
        f"dns_default_ip         {sink}",
        f"data_dir               {data_dir}",
        "",
        "# --- enabled fake services (start_service) ---",
        "start_service http",
        "start_service https",
        "start_service ftp",
        "start_service smtp",
        "start_service pop3",
        "start_service irc",
        "",
        "# DNS handled by winbox sinkhole — do NOT start INETSim's dns:",
        "# start_service dns",
        "",
        f"http_bind_port   80",
        f"https_bind_port  443",
    ]
    return "\n".join(lines) + "\n"


def write_inetsim_conf(cfg: Config, *, bind_ip: str | None = None,
                       sink_ip: str | None = None) -> Path:
    """Write the generated INETSim config + data dir, return the conf path."""
    conf = build_inetsim_conf(cfg, bind_ip=bind_ip, sink_ip=sink_ip)
    path = inetsim_conf_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    inetsim_data_dir(cfg).mkdir(parents=True, exist_ok=True)
    path.write_text(conf)
    return path
