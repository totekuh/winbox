"""Configuration management for winbox."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class Config:
    """winbox configuration with defaults and user overrides."""

    vm_name: str = "winbox"
    vm_user: str = "Administrator"
    vm_password: str = "WinboxP@ss123"
    vm_ram: int = 4096
    vm_cpus: int = 4
    vm_disk: int = 30
    host_ip: str = "192.168.122.1"
    # libvirt's default network. If you ever change this, the nwfilter
    # XMLs are rendered from these so isolation continues to allow only
    # intra-subnet traffic.
    vm_subnet: str = "192.168.122.0"
    vm_subnet_mask: int = 24
    winbox_dir: Path = field(default_factory=lambda: Path.home() / ".winbox")
    virtio_iso_url: str = (
        "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/"
        "stable-virtio/virtio-win.iso"
    )

    @property
    def shared_dir(self) -> Path:
        return self.winbox_dir / "shared"

    @property
    def tools_dir(self) -> Path:
        return self.shared_dir / "tools"

    @property
    def loot_dir(self) -> Path:
        return self.shared_dir / "loot"

    @property
    def jobs_file(self) -> Path:
        return self.winbox_dir / "jobs.json"

    @property
    def jobs_log_dir(self) -> Path:
        return self.shared_dir / "loot" / ".jobs"

    @property
    def iso_dir(self) -> Path:
        return self.winbox_dir / "iso"

    @property
    def symbols_dir(self) -> Path:
        return self.winbox_dir / "symbols"

    @property
    def disk_path(self) -> Path:
        return self.winbox_dir / "disk.qcow2"

    @property
    def ssh_key(self) -> Path:
        return self.winbox_dir / "id_ed25519"

    @property
    def ssh_pubkey(self) -> Path:
        return self.winbox_dir / "id_ed25519.pub"

    @property
    def virtio_iso(self) -> Path:
        return self.iso_dir / "virtio-win.iso"

    @property
    def unattend_img(self) -> Path:
        return self.iso_dir / "unattend.img"

    @classmethod
    def load(cls) -> Config:
        """Load config from defaults + ~/.winbox/config overrides."""
        cfg = cls()
        config_file = cfg.winbox_dir / "config"
        if config_file.exists():
            cfg = cls._apply_overrides(cfg, config_file)
        return cfg

    @staticmethod
    def _apply_overrides(cfg: Config, path: Path) -> Config:
        """Parse shell-style KEY=VALUE config file and apply to config.

        Malformed lines and unknown keys are reported via ``logger.warning``
        rather than silently dropped — a typo in ``VM_RAM`` would otherwise
        leave the user wondering why their override never took effect.
        """
        mapping = {
            "VM_NAME": "vm_name",
            "VM_USER": "vm_user",
            "VM_PASSWORD": "vm_password",
            "VM_RAM": "vm_ram",
            "VM_CPUS": "vm_cpus",
            "VM_DISK": "vm_disk",
            "HOST_IP": "host_ip",
            "WINBOX_DIR": "winbox_dir",
            "VIRTIO_ISO_URL": "virtio_iso_url",
        }
        int_fields = {"vm_ram", "vm_cpus", "vm_disk"}
        path_fields = {"winbox_dir"}

        for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                logger.warning(
                    "%s:%d: ignoring malformed line (no '='): %r",
                    path, lineno, line,
                )
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and (
                (value[0] == '"' and value[-1] == '"')
                or (value[0] == "'" and value[-1] == "'")
            ):
                value = value[1:-1]
            # Expand ~ and env vars
            value = os.path.expandvars(os.path.expanduser(value))

            attr = mapping.get(key)
            if attr is None:
                logger.warning(
                    "%s:%d: unknown config key %r (known: %s)",
                    path, lineno, key, ", ".join(sorted(mapping)),
                )
                continue
            if attr in int_fields:
                try:
                    setattr(cfg, attr, int(value))
                except ValueError:
                    logger.warning(
                        "%s:%d: %s expects an integer, got %r — keeping default",
                        path, lineno, key, value,
                    )
                    continue
            elif attr in path_fields:
                setattr(cfg, attr, Path(value))
            else:
                setattr(cfg, attr, value)

        return cfg
