"""Tests for winbox.config — Config defaults, properties, and file parsing."""

from pathlib import Path

import pytest

from winbox.config import Config


class TestConfigDefaults:
    def test_default_values(self):
        cfg = Config()
        assert cfg.vm_name == "winbox"
        assert cfg.vm_ram == 4096
        assert cfg.vm_cpus == 4
        assert cfg.vm_disk == 30
        assert cfg.smb_host_ip == "192.168.122.1"

    def test_winbox_dir_default(self):
        cfg = Config()
        assert cfg.winbox_dir == Path.home() / ".winbox"

    def test_virtio_iso_url_default(self):
        cfg = Config()
        assert "virtio-win" in cfg.virtio_iso_url
        assert cfg.virtio_iso_url.startswith("https://")


class TestConfigProperties:
    def test_shared_dir(self):
        cfg = Config(winbox_dir=Path("/tmp/wb"))
        assert cfg.shared_dir == Path("/tmp/wb/shared")

    def test_tools_dir(self):
        cfg = Config(winbox_dir=Path("/tmp/wb"))
        assert cfg.tools_dir == Path("/tmp/wb/shared/tools")

    def test_loot_dir(self):
        cfg = Config(winbox_dir=Path("/tmp/wb"))
        assert cfg.loot_dir == Path("/tmp/wb/shared/loot")

    def test_iso_dir(self):
        cfg = Config(winbox_dir=Path("/tmp/wb"))
        assert cfg.iso_dir == Path("/tmp/wb/iso")

    def test_disk_path(self):
        cfg = Config(winbox_dir=Path("/tmp/wb"))
        assert cfg.disk_path == Path("/tmp/wb/disk.qcow2")

    def test_ssh_key(self):
        cfg = Config(winbox_dir=Path("/tmp/wb"))
        assert cfg.ssh_key == Path("/tmp/wb/id_ed25519")

    def test_ssh_pubkey(self):
        cfg = Config(winbox_dir=Path("/tmp/wb"))
        assert cfg.ssh_pubkey == Path("/tmp/wb/id_ed25519.pub")

    def test_virtio_iso(self):
        cfg = Config(winbox_dir=Path("/tmp/wb"))
        assert cfg.virtio_iso == Path("/tmp/wb/iso/virtio-win.iso")

    def test_unattend_img(self):
        cfg = Config(winbox_dir=Path("/tmp/wb"))
        assert cfg.unattend_img == Path("/tmp/wb/iso/unattend.img")

    def test_properties_chain_from_winbox_dir(self):
        """All paths derive from winbox_dir — changing it changes everything."""
        cfg = Config(winbox_dir=Path("/opt/custom"))
        assert str(cfg.shared_dir).startswith("/opt/custom")
        assert str(cfg.tools_dir).startswith("/opt/custom")
        assert str(cfg.loot_dir).startswith("/opt/custom")
        assert str(cfg.disk_path).startswith("/opt/custom")
        assert str(cfg.ssh_key).startswith("/opt/custom")


class TestConfigOverrides:
    def test_override_string_fields(self, tmp_path):
        config_file = tmp_path / "config"
        config_file.write_text("VM_NAME=myvm\n")
        cfg = Config._apply_overrides(Config(), config_file)
        assert cfg.vm_name == "myvm"

    def test_override_int_fields(self, tmp_path):
        config_file = tmp_path / "config"
        config_file.write_text("VM_RAM=8192\nVM_CPUS=8\nVM_DISK=60\n")
        cfg = Config._apply_overrides(Config(), config_file)
        assert cfg.vm_ram == 8192
        assert cfg.vm_cpus == 8
        assert cfg.vm_disk == 60

    def test_override_path_field(self, tmp_path):
        config_file = tmp_path / "config"
        config_file.write_text("WINBOX_DIR=/opt/winbox\n")
        cfg = Config._apply_overrides(Config(), config_file)
        assert cfg.winbox_dir == Path("/opt/winbox")

    def test_override_smb_host_ip(self, tmp_path):
        config_file = tmp_path / "config"
        config_file.write_text("SMB_HOST_IP=10.0.0.1\n")
        cfg = Config._apply_overrides(Config(), config_file)
        assert cfg.smb_host_ip == "10.0.0.1"

    def test_override_url_field(self, tmp_path):
        config_file = tmp_path / "config"
        config_file.write_text("VIRTIO_ISO_URL=https://example.com/virtio.iso\n")
        cfg = Config._apply_overrides(Config(), config_file)
        assert cfg.virtio_iso_url == "https://example.com/virtio.iso"

    def test_comments_and_blank_lines_ignored(self, tmp_path):
        config_file = tmp_path / "config"
        config_file.write_text("# this is a comment\n\n  \nVM_NAME=test\n# another\n")
        cfg = Config._apply_overrides(Config(), config_file)
        assert cfg.vm_name == "test"
        # Other fields untouched
        assert cfg.vm_ram == 4096

    def test_unknown_keys_ignored(self, tmp_path):
        config_file = tmp_path / "config"
        config_file.write_text("BOGUS_KEY=whatever\nVM_NAME=ok\n")
        cfg = Config._apply_overrides(Config(), config_file)
        assert cfg.vm_name == "ok"
        assert not hasattr(cfg, "bogus_key")

    def test_quoted_values_stripped(self, tmp_path):
        config_file = tmp_path / "config"
        config_file.write_text('VM_NAME="quoted_name"\n')
        cfg = Config._apply_overrides(Config(), config_file)
        assert cfg.vm_name == "quoted_name"

    def test_single_quoted_values_stripped(self, tmp_path):
        config_file = tmp_path / "config"
        config_file.write_text("VM_NAME='single_quoted'\n")
        cfg = Config._apply_overrides(Config(), config_file)
        assert cfg.vm_name == "single_quoted"

    def test_tilde_expansion(self, tmp_path):
        config_file = tmp_path / "config"
        config_file.write_text("WINBOX_DIR=~/my_winbox\n")
        cfg = Config._apply_overrides(Config(), config_file)
        assert "~" not in str(cfg.winbox_dir)
        assert str(cfg.winbox_dir).endswith("my_winbox")

    def test_env_var_expansion(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MYVAR", "expanded")
        config_file = tmp_path / "config"
        config_file.write_text("VM_NAME=$MYVAR\n")
        cfg = Config._apply_overrides(Config(), config_file)
        assert cfg.vm_name == "expanded"

    def test_lines_without_equals_ignored(self, tmp_path):
        config_file = tmp_path / "config"
        config_file.write_text("no_equals_here\nVM_NAME=valid\n")
        cfg = Config._apply_overrides(Config(), config_file)
        assert cfg.vm_name == "valid"

    def test_value_with_equals_sign(self, tmp_path):
        config_file = tmp_path / "config"
        config_file.write_text("VIRTIO_ISO_URL=https://example.com/path?a=1&b=2\n")
        cfg = Config._apply_overrides(Config(), config_file)
        assert cfg.virtio_iso_url == "https://example.com/path?a=1&b=2"

    def test_empty_config_file(self, tmp_path):
        config_file = tmp_path / "config"
        config_file.write_text("")
        cfg = Config._apply_overrides(Config(), config_file)
        # All defaults preserved
        assert cfg.vm_name == "winbox"
        assert cfg.vm_ram == 4096

    def test_invalid_int_value_skipped(self, tmp_path):
        config_file = tmp_path / "config"
        config_file.write_text("VM_RAM=not_a_number\nVM_CPUS=8\n")
        cfg = Config._apply_overrides(Config(), config_file)
        # Invalid VM_RAM skipped, keeps default
        assert cfg.vm_ram == 4096
        # Valid VM_CPUS applied
        assert cfg.vm_cpus == 8

    def test_load_without_config_file(self, tmp_path, monkeypatch):
        """Config.load() works even if ~/.winbox/config doesn't exist."""
        monkeypatch.setattr(Config, "__init__", lambda self: (
            setattr(self, "vm_name", "winbox"),
            setattr(self, "vm_ram", 4096),
            setattr(self, "vm_cpus", 4),
            setattr(self, "vm_disk", 30),
            setattr(self, "smb_host_ip", "192.168.122.1"),
            setattr(self, "winbox_dir", tmp_path / ".winbox"),
            setattr(self, "virtio_iso_url", "https://example.com"),
        )[-1])
        cfg = Config.load()
        assert cfg.vm_name == "winbox"
