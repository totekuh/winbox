"""Configuration management for winbox."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    """winbox configuration with defaults and user overrides."""

    vm_name: str = "winbox"
    vm_ram: int = 4096
    vm_cpus: int = 4
    vm_disk: int = 30
    vm_bridge: str = "virbr0"
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
    def iso_dir(self) -> Path:
        return self.winbox_dir / "iso"

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
        """Parse shell-style KEY=VALUE config file and apply to config."""
        mapping = {
            "VM_NAME": "vm_name",
            "VM_RAM": "vm_ram",
            "VM_CPUS": "vm_cpus",
            "VM_DISK": "vm_disk",
            "VM_BRIDGE": "vm_bridge",
            "WINBOX_DIR": "winbox_dir",
            "VIRTIO_ISO_URL": "virtio_iso_url",
        }
        int_fields = {"vm_ram", "vm_cpus", "vm_disk"}
        path_fields = {"winbox_dir"}

        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            # Expand ~ and env vars
            value = os.path.expandvars(os.path.expanduser(value))

            attr = mapping.get(key)
            if attr is None:
                continue
            if attr in int_fields:
                try:
                    setattr(cfg, attr, int(value))
                except ValueError:
                    continue
            elif attr in path_fields:
                setattr(cfg, attr, Path(value))
            else:
                setattr(cfg, attr, value)

        return cfg
