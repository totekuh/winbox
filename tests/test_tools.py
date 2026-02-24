"""Tests for winbox.tools — add, remove, list using real filesystem."""

from pathlib import Path

import pytest

from winbox.config import Config
from winbox import tools as tools_mod


@pytest.fixture
def cfg(tmp_path):
    """Config pointing at a temp directory."""
    return Config(winbox_dir=tmp_path / ".winbox")


@pytest.fixture
def setup_dirs(cfg):
    """Create the tools and loot directories."""
    cfg.tools_dir.mkdir(parents=True, exist_ok=True)
    cfg.loot_dir.mkdir(parents=True, exist_ok=True)
    return cfg


class TestToolsAdd:
    def test_add_single_file(self, setup_dirs, tmp_path):
        cfg = setup_dirs
        src = tmp_path / "Rubeus.exe"
        src.write_bytes(b"\x00" * 100)

        tools_mod.add(cfg, (str(src),))
        assert (cfg.tools_dir / "Rubeus.exe").exists()

    def test_add_multiple_files(self, setup_dirs, tmp_path):
        cfg = setup_dirs
        files = []
        for name in ("a.exe", "b.exe", "c.exe"):
            f = tmp_path / name
            f.write_bytes(b"\x00")
            files.append(str(f))

        tools_mod.add(cfg, tuple(files))
        for name in ("a.exe", "b.exe", "c.exe"):
            assert (cfg.tools_dir / name).exists()

    def test_add_nonexistent_file_skipped(self, setup_dirs, capsys):
        cfg = setup_dirs
        tools_mod.add(cfg, ("/nonexistent/ghost.exe",))
        assert not (cfg.tools_dir / "ghost.exe").exists()

    def test_add_preserves_content(self, setup_dirs, tmp_path):
        cfg = setup_dirs
        content = b"MZ\x90\x00" * 50
        src = tmp_path / "tool.exe"
        src.write_bytes(content)

        tools_mod.add(cfg, (str(src),))
        assert (cfg.tools_dir / "tool.exe").read_bytes() == content

    def test_add_creates_tools_dir_if_missing(self, cfg, tmp_path):
        # tools_dir doesn't exist yet
        assert not cfg.tools_dir.exists()
        src = tmp_path / "tool.exe"
        src.write_bytes(b"\x00")

        tools_mod.add(cfg, (str(src),))
        assert cfg.tools_dir.exists()
        assert (cfg.tools_dir / "tool.exe").exists()


class TestToolsRemove:
    def test_remove_existing(self, setup_dirs):
        cfg = setup_dirs
        (cfg.tools_dir / "old.exe").write_bytes(b"\x00")
        tools_mod.remove(cfg, "old.exe")
        assert not (cfg.tools_dir / "old.exe").exists()

    def test_remove_nonexistent(self, setup_dirs, capsys):
        cfg = setup_dirs
        # Should not raise
        tools_mod.remove(cfg, "ghost.exe")


class TestToolsList:
    def test_list_with_tools(self, setup_dirs):
        cfg = setup_dirs
        (cfg.tools_dir / "Rubeus.exe").write_bytes(b"\x00" * 1024)
        (cfg.tools_dir / "SharpHound.exe").write_bytes(b"\x00" * 2048)

        # Just check it doesn't crash — output goes to rich console
        tools_mod.list_tools(cfg)

    def test_list_empty(self, setup_dirs):
        tools_mod.list_tools(setup_dirs)

    def test_list_hides_internal_files(self, setup_dirs):
        cfg = setup_dirs
        # These should be hidden
        for name in (".ssh_pubkey", "provision.ps1"):
            (cfg.tools_dir / name).write_text("internal")
        # This should show
        (cfg.tools_dir / "Rubeus.exe").write_bytes(b"\x00")

        # The _HIDDEN set should filter internal files
        visible = [
            f for f in cfg.tools_dir.iterdir()
            if f.is_file() and f.name not in tools_mod._HIDDEN
        ]
        assert len(visible) == 1
        assert visible[0].name == "Rubeus.exe"

    def test_list_nonexistent_dir(self, cfg):
        # tools_dir doesn't exist — should not crash
        tools_mod.list_tools(cfg)
