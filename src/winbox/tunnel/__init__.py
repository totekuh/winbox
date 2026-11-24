"""Ligolo-ng tunnel integration — route Linux traffic through the Windows VM."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from winbox.config import Config

PROXY_PORT = 11601
API_PORT = 8080
API_USER = "ligolo"
API_PASS = "ligolo"
TUN_INTERFACE = "ligolo"
AGENT_VM_PATH = r"C:\Tools\ligolo-agent.exe"


def tunnel_dir(cfg: Config) -> Path:
    return cfg.winbox_dir / "tunnel"


def pidfile_path(cfg: Config) -> Path:
    return tunnel_dir(cfg) / "ligolo-proxy.pid"


def config_path(cfg: Config) -> Path:
    return tunnel_dir(cfg) / "ligolo-ng.yaml"
