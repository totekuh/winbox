"""Host-side ligolo-proxy daemon lifecycle management."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING

from winbox.tunnel import (
    API_PASS,
    API_USER,
    config_path,
    pidfile_path,
    tunnel_dir,
)

if TYPE_CHECKING:
    from winbox.config import Config


class ProxyNotFound(RuntimeError):
    """ligolo-proxy binary is not on PATH."""


class ProxyError(RuntimeError):
    """Generic proxy lifecycle error."""


def find_proxy() -> str:
    """Return path to ligolo-proxy binary, or raise ProxyNotFound."""
    path = shutil.which("ligolo-proxy")
    if path:
        return path
    raise ProxyNotFound(
        "ligolo-proxy not found on PATH. "
        "Install it (go install, release binary, or package manager) "
        "and ensure it is on PATH."
    )


def read_pidfile(cfg: Config) -> int | None:
    pf = pidfile_path(cfg)
    if not pf.exists():
        return None
    try:
        text = pf.read_text().strip()
    except OSError:
        return None
    if not text or not text.split()[0].isdigit():
        return None
    return int(text.split()[0])


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _is_proxy_proc(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmd = f.read().replace(b"\x00", b" ").decode("utf-8", "replace")
    except OSError:
        return False
    return "ligolo" in cmd and "proxy" in cmd


def is_running(cfg: Config) -> int | None:
    """Return live proxy PID, or None. Cleans stale pidfile."""
    pid = read_pidfile(cfg)
    if pid is None:
        return None
    if _pid_alive(pid) and _is_proxy_proc(pid):
        return pid
    try:
        pidfile_path(cfg).unlink()
    except OSError:
        pass
    return None


def _write_config(cfg: Config) -> Path:
    """Generate a ligolo-ng.yaml for daemon mode."""
    api_port = cfg.tunnel_api_port
    conf = config_path(cfg)
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text(
        f"web:\n"
        f"  enabled: true\n"
        f"  enableui: false\n"
        f"  listen: 127.0.0.1:{api_port}\n"
        f"  debug: false\n"
        f"  logfile: \"\"\n"
        f"  behindreverseproxy: false\n"
        f"  trustedproxies:\n"
        f"    - 127.0.0.1\n"
        f"  corsAllowedOrigin:\n"
        f"    - http://127.0.0.1:{api_port}\n"
        f"  users:\n"
        f"    {API_USER}: {API_PASS}\n"
        f"  tls:\n"
        f"    enabled: false\n"
        f"proxy:\n"
        f"  maxinflight: 4096\n"
        f"  selfcertcache: {tunnel_dir(cfg) / 'selfcerts'}\n"
        f"  historyfile: \"\"\n"
    )
    return conf


def _write_pidfile(cfg: Config, pid: int) -> None:
    pf = pidfile_path(cfg)
    pf.parent.mkdir(parents=True, exist_ok=True)
    pf.write_text(f"{pid}\n")


def start(cfg: Config) -> int:
    """Start ligolo-proxy in daemon mode. Returns PID."""
    existing = is_running(cfg)
    if existing:
        return existing

    proxy_bin = find_proxy()
    conf = _write_config(cfg)
    tdir = tunnel_dir(cfg)
    tdir.mkdir(parents=True, exist_ok=True)

    proc = subprocess.Popen(
        [
            proxy_bin,
            "-daemon",
            "-selfcert",
            "-laddr", f"0.0.0.0:{cfg.tunnel_proxy_port}",
            "-config", str(conf),
        ],
        stdout=open(tdir / "proxy.log", "w"),
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    _write_pidfile(cfg, proc.pid)

    deadline = time.time() + 8.0
    while time.time() < deadline:
        if proc.poll() is not None:
            raise ProxyError(
                f"ligolo-proxy exited immediately (code {proc.returncode}). "
                f"Check {tdir / 'proxy.log'}"
            )
        try:
            from winbox.tunnel.api import ping
            if ping(cfg):
                return proc.pid
        except Exception:
            pass
        time.sleep(0.3)

    raise ProxyError(
        f"ligolo-proxy did not become ready within 8s. "
        f"Check {tdir / 'proxy.log'}"
    )


def stop(cfg: Config, *, timeout: float = 5.0) -> bool:
    """Stop the proxy daemon. Returns True if a process was signalled."""
    pid = read_pidfile(cfg)
    pf = pidfile_path(cfg)
    if pid is None:
        return False
    if not _pid_alive(pid) or not _is_proxy_proc(pid):
        try:
            pf.unlink()
        except OSError:
            pass
        return False

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pid = None

    deadline = time.time() + timeout
    while pid is not None and time.time() < deadline:
        if not _pid_alive(pid):
            break
        time.sleep(0.1)
    else:
        if pid is not None and _pid_alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

    try:
        pf.unlink()
    except OSError:
        pass
    return True
