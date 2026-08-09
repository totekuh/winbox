"""Tests for winbox.config — Config defaults, properties, and file parsing."""

from pathlib import Path

import pytest

from winbox.config import Config


class TestConfigDefaults:
    def test_default_values(self):
        cfg = Config()
        assert cfg.vm_name == "winbox"
        assert cfg.vm_os == "server2022"
        assert cfg.vm_ram == 4096
        assert cfg.vm_cpus == 4
        assert cfg.vm_disk == 30
        assert cfg.host_ip == "192.168.122.1"

    def test_winbox_dir_default(self):
        cfg = Config()
        assert cfg.winbox_dir == Path.home() / ".winbox"

    def test_virtio_iso_url_default(self):
        cfg = Config()
        assert "virtio-win" in cfg.virtio_iso_url
        assert cfg.virtio_iso_url.startswith("https://")


class TestConfigProfile:
    def test_default_profile_is_server(self):
        assert Config().profile.key == "server2022"

    def test_profile_follows_vm_os(self):
        cfg = Config()
        cfg.vm_os = "win11"
        assert cfg.profile.key == "win11"

    def test_profile_unknown_falls_back(self):
        cfg = Config()
        cfg.vm_os = "nonsense"
        assert cfg.profile.key == "server2022"


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

    def test_override_vm_os(self, tmp_path):
        config_file = tmp_path / "config"
        config_file.write_text("VM_OS=win11\n")
        cfg = Config._apply_overrides(Config(), config_file)
        assert cfg.vm_os == "win11"
        assert cfg.profile.os_variant == "win11"

    def test_override_vm_os_invalid_keeps_default(self, tmp_path):
        config_file = tmp_path / "config"
        config_file.write_text("VM_OS=windows95\n")
        cfg = Config._apply_overrides(Config(), config_file)
        assert cfg.vm_os == "server2022"

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

    def test_override_host_ip(self, tmp_path):
        config_file = tmp_path / "config"
        config_file.write_text("HOST_IP=10.0.0.1\n")
        cfg = Config._apply_overrides(Config(), config_file)
        assert cfg.host_ip == "10.0.0.1"

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

    def test_invalid_int_value_skipped(self, tmp_path, caplog):
        config_file = tmp_path / "config"
        config_file.write_text("VM_RAM=not_a_number\nVM_CPUS=8\n")
        with caplog.at_level("WARNING", logger="winbox.config"):
            cfg = Config._apply_overrides(Config(), config_file)
        # Invalid VM_RAM skipped, keeps default
        assert cfg.vm_ram == 4096
        # Valid VM_CPUS applied
        assert cfg.vm_cpus == 8
        # And the user is warned, not left guessing why their override didn't take.
        assert any(
            "VM_RAM" in r.message and "not_a_number" in r.message
            for r in caplog.records
        )

    def test_unknown_key_warns(self, tmp_path, caplog):
        config_file = tmp_path / "config"
        config_file.write_text("VM_TYPO=foo\n")
        with caplog.at_level("WARNING", logger="winbox.config"):
            Config._apply_overrides(Config(), config_file)
        assert any("unknown config key" in r.message for r in caplog.records)

    def test_malformed_line_warns(self, tmp_path, caplog):
        config_file = tmp_path / "config"
        config_file.write_text("VM_RAM 8192\n")  # missing '='
        with caplog.at_level("WARNING", logger="winbox.config"):
            Config._apply_overrides(Config(), config_file)
        assert any("malformed" in r.message for r in caplog.records)

    def test_load_without_config_file(self, tmp_path, monkeypatch):
        """Config.load() works even if ~/.winbox/config doesn't exist."""
        monkeypatch.setattr(Config, "__init__", lambda self: (
            setattr(self, "vm_name", "winbox"),
            setattr(self, "vm_ram", 4096),
            setattr(self, "vm_cpus", 4),
            setattr(self, "vm_disk", 30),
            setattr(self, "host_ip", "192.168.122.1"),
            setattr(self, "winbox_dir", tmp_path / ".winbox"),
            setattr(self, "virtio_iso_url", "https://example.com"),
        )[-1])
        cfg = Config.load()
        assert cfg.vm_name == "winbox"


class TestConfigPersist:
    """`winbox setup --os X` has to outlive its own process.

    Without a write-back, setup built (say) a Win11 disk while every later
    command re-loaded Config from a file with no VM_OS and resolved the
    default server2022 profile — wrong virtio subdir, wrong install
    partition, wrong Defender handling, against a VM that was never
    Server 2022.
    """

    def test_persist_creates_file_and_round_trips(self, tmp_path):
        cfg = Config(winbox_dir=tmp_path / ".winbox")
        cfg.vm_os = "win11"
        cfg.persist("VM_OS", cfg.vm_os)

        reloaded = Config._apply_overrides(
            Config(winbox_dir=cfg.winbox_dir), cfg.config_file
        )
        assert reloaded.vm_os == "win11"
        assert reloaded.profile.virtio_subdir == "w11"
        assert reloaded.profile.install_partition_id == 3

    def test_persist_rewrites_existing_key_in_place(self, tmp_path):
        cfg = Config(winbox_dir=tmp_path / ".winbox")
        cfg.winbox_dir.mkdir(parents=True)
        cfg.config_file.write_text("VM_OS=win11\nVM_RAM=8192\n")

        cfg.persist("VM_OS", "server2022")

        assert cfg.config_file.read_text() == "VM_OS=server2022\nVM_RAM=8192\n"

    def test_persist_preserves_comments_and_unrelated_keys(self, tmp_path):
        cfg = Config(winbox_dir=tmp_path / ".winbox")
        cfg.winbox_dir.mkdir(parents=True)
        cfg.config_file.write_text("# hand-edited\nVM_RAM=8192\n\nVM_NAME=lab\n")

        cfg.persist("VM_OS", "win11")

        body = cfg.config_file.read_text()
        assert "# hand-edited" in body
        assert "VM_RAM=8192" in body
        assert "VM_NAME=lab" in body
        assert "VM_OS=win11" in body

    def test_persist_ignores_commented_out_assignment(self, tmp_path):
        cfg = Config(winbox_dir=tmp_path / ".winbox")
        cfg.winbox_dir.mkdir(parents=True)
        cfg.config_file.write_text("#VM_OS=server2022\n")

        cfg.persist("VM_OS", "win11")

        lines = cfg.config_file.read_text().splitlines()
        assert lines == ["#VM_OS=server2022", "VM_OS=win11"]

    def test_persisted_value_survives_full_load(self, tmp_path, monkeypatch):
        winbox_dir = tmp_path / ".winbox"
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
        cfg = Config(winbox_dir=winbox_dir)
        cfg.persist("VM_OS", "win11")

        assert Config.load().vm_os == "win11"
