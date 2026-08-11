"""Configuration management for winbox."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from winbox.osprofile import DEFAULT_OS, OS_PROFILES, OSProfile

logger = logging.getLogger(__name__)


@dataclass
class Config:
    """winbox configuration with defaults and user overrides."""

    vm_name: str = "winbox"
    vm_os: str = DEFAULT_OS
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
    # The config file load() actually read, so persist() can write back to the
    # same file even when it set WINBOX_DIR (which would otherwise repoint
    # config_file). None for a directly-constructed Config; set by load().
    config_source: Path | None = None

    @property
    def profile(self) -> OSProfile:
        """The :class:`~winbox.osprofile.OSProfile` for ``vm_os``.

        Falls back to the default profile (with a warning) if ``vm_os`` was
        set to something unknown — ``_apply_overrides`` already rejects
        unknown values from the config file, so this only trips if the field
        is mutated in code.
        """
        try:
            return OS_PROFILES[self.vm_os]
        except KeyError:
            logger.warning(
                "unknown vm_os %r — falling back to %r", self.vm_os, DEFAULT_OS
            )
            return OS_PROFILES[DEFAULT_OS]

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

    @property
    def config_file(self) -> Path:
        return self.winbox_dir / "config"

    @classmethod
    def load(cls) -> Config:
        """Load config from defaults + ~/.winbox/config overrides."""
        cfg = cls()
        config_file = cfg.config_file
        if config_file.exists():
            cfg = cls._apply_overrides(cfg, config_file)
        # Remember the file we actually read so persist() writes back to it, not
        # to an overridden WINBOX_DIR that load() would never read from.
        cfg.config_source = config_file
        return cfg

    def persist(self, key: str, value: str) -> None:
        """Write ``KEY=value`` into ``~/.winbox/config``, in place.

        The build-time OS choice has to outlive the ``winbox setup`` process:
        every later command (``status``, ``av``, ``exec``, the MCP server)
        constructs its own :class:`Config` from the file, and a ``--os`` that
        only lived in setup's memory would leave them all reading the default
        profile against a VM built from the other one.

        Rewrites an existing assignment in place (preserving comments, blank
        lines, and unrelated keys) and appends otherwise, so a hand-edited
        config survives.

        Writes back to the file ``load()`` actually read (``config_source``),
        not ``self.config_file``. ``load()`` finds the config from a defaults-
        only Config *before* any ``WINBOX_DIR`` override is known, so it always
        reads the default ``~/.winbox/config``; a config that set
        ``WINBOX_DIR=/mnt/vms`` then made ``self.config_file`` point at
        ``/mnt/vms/config``, so a persisted ``VM_OS`` was written somewhere
        ``load()`` never looks and silently vanished. A directly-constructed
        Config (no ``load()``) has no ``config_source`` and falls back to
        ``self.config_file``.
        """
        path = self.config_source or self.config_file
        path.parent.mkdir(parents=True, exist_ok=True)
        line = f"{key}={value}"
        lines = path.read_text().splitlines() if path.exists() else []
        for i, existing in enumerate(lines):
            stripped = existing.strip()
            if stripped.startswith("#") or "=" not in stripped:
                continue
            if stripped.split("=", 1)[0].strip() == key:
                lines[i] = line
                break
        else:
            lines.append(line)
        path.write_text("\n".join(lines) + "\n")

    @staticmethod
    def _apply_overrides(cfg: Config, path: Path) -> Config:
        """Parse shell-style KEY=VALUE config file and apply to config.

        Malformed lines and unknown keys are reported via ``logger.warning``
        rather than silently dropped — a typo in ``VM_RAM`` would otherwise
        leave the user wondering why their override never took effect.
        """
        mapping = {
            "VM_NAME": "vm_name",
            "VM_OS": "vm_os",
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

            attr = mapping.get(key)
            if attr is None:
                logger.warning(
                    "%s:%d: unknown config key %r (known: %s)",
                    path, lineno, key, ", ".join(sorted(mapping)),
                )
                continue
            # Expand ~ and env vars, but never for credential fields: a
            # literal '$', '${...}' or leading '~' in a password/username
            # must be preserved verbatim, otherwise autologin/ssh would
            # authenticate with silently mangled credentials.
            if attr not in {"vm_password", "vm_user"}:
                value = os.path.expandvars(os.path.expanduser(value))
            if attr in int_fields:
                try:
                    parsed = int(value)
                except ValueError:
                    logger.warning(
                        "%s:%d: %s expects an integer, got %r — keeping default",
                        path, lineno, key, value,
                    )
                    continue
                if parsed <= 0:
                    # virt-install would otherwise fail much later with a
                    # confusing error like "Memory amount must be greater
                    # than 0". Reject upfront.
                    logger.warning(
                        "%s:%d: %s must be > 0 (got %d) — keeping default",
                        path, lineno, key, parsed,
                    )
                    continue
                setattr(cfg, attr, parsed)
            elif attr in path_fields:
                setattr(cfg, attr, Path(value))
            elif attr == "vm_os":
                if value not in OS_PROFILES:
                    logger.warning(
                        "%s:%d: %s must be one of %s (got %r) — keeping default",
                        path, lineno, key, ", ".join(sorted(OS_PROFILES)), value,
                    )
                    continue
                setattr(cfg, attr, value)
            else:
                setattr(cfg, attr, value)

        return cfg
