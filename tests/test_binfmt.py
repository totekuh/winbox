"""Tests for binfmt_misc registration and CLI."""

from __future__ import annotations

import re
import stat
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from winbox.binfmt import (
    BINFMT_NAME,
    generate_handler,
    install_handler,
    registration_string,
    is_registered,
    mark_tools_executable,
    handler_path,
)
from winbox.cli import cli
from winbox.config import Config


# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def cfg(tmp_path):
    c = Config(winbox_dir=tmp_path / ".winbox")
    c.winbox_dir.mkdir(parents=True)
    c.shared_dir.mkdir(parents=True)
    c.tools_dir.mkdir(parents=True)
    c.loot_dir.mkdir(parents=True)
    return c


# ─── generate_handler ────────────────────────────────────────────────────────


class TestGenerateHandler:
    def test_shebang(self, cfg):
        with patch("shutil.which", return_value="/usr/local/bin/winbox"):
            script = generate_handler(cfg)
        assert script.startswith("#!/bin/bash\n")

    def test_winbox_path_embedded(self, cfg):
        with patch("shutil.which", return_value="/usr/local/bin/winbox"):
            script = generate_handler(cfg)
        assert 'WINBOX="/usr/local/bin/winbox"' in script

    def test_tools_dir_embedded(self, cfg):
        with patch("shutil.which", return_value="/usr/local/bin/winbox"):
            script = generate_handler(cfg)
        assert f'TOOLS_DIR="{cfg.tools_dir}"' in script

    def test_uses_exec(self, cfg):
        with patch("shutil.which", return_value="/usr/local/bin/winbox"):
            script = generate_handler(cfg)
        assert 'exec "$WINBOX" exec "$EXE_NAME" "$@"' in script

    def test_passes_args(self, cfg):
        with patch("shutil.which", return_value="/usr/local/bin/winbox"):
            script = generate_handler(cfg)
        assert '"$@"' in script

    def test_winbox_not_found_raises(self, cfg):
        with patch("shutil.which", return_value=None):
            with pytest.raises(FileNotFoundError, match="winbox not found"):
                generate_handler(cfg)


# ─── install_handler ─────────────────────────────────────────────────────────


class TestInstallHandler:
    def test_creates_file(self, cfg):
        with patch("shutil.which", return_value="/usr/local/bin/winbox"):
            path = install_handler(cfg)
        assert path.exists()
        assert path.name == "binfmt-handler.sh"

    def test_is_executable(self, cfg):
        with patch("shutil.which", return_value="/usr/local/bin/winbox"):
            path = install_handler(cfg)
        mode = path.stat().st_mode
        assert mode & stat.S_IXUSR
        assert mode & stat.S_IXGRP
        assert mode & stat.S_IXOTH

    def test_in_winbox_dir(self, cfg):
        with patch("shutil.which", return_value="/usr/local/bin/winbox"):
            path = install_handler(cfg)
        assert path.parent == cfg.winbox_dir


# ─── registration_string ─────────────────────────────────────────────────────


class TestRegistrationString:
    def test_contains_name(self):
        reg = registration_string(Path("/tmp/handler.sh"))
        assert f":{BINFMT_NAME}:" in reg

    def test_extension_match(self):
        reg = registration_string(Path("/tmp/handler.sh"))
        assert ":E:" in reg

    def test_exe_extension(self):
        reg = registration_string(Path("/tmp/handler.sh"))
        assert ":exe:" in reg

    def test_handler_path(self):
        reg = registration_string(Path("/tmp/handler.sh"))
        assert "::/tmp/handler.sh:" in reg

    def test_format(self):
        reg = registration_string(Path("/home/user/.winbox/binfmt-handler.sh"))
        assert reg == ":winbox:E::exe::/home/user/.winbox/binfmt-handler.sh:"


# ─── is_registered ───────────────────────────────────────────────────────────


class TestIsRegistered:
    def test_registered(self, tmp_path):
        entry = tmp_path / BINFMT_NAME
        entry.write_text("enabled\n")
        with patch("winbox.binfmt.BINFMT_ENTRY", entry):
            assert is_registered() is True

    def test_not_registered(self, tmp_path):
        entry = tmp_path / BINFMT_NAME
        with patch("winbox.binfmt.BINFMT_ENTRY", entry):
            assert is_registered() is False


# ─── mark_tools_executable ──────────────────────────────────────────────────


class TestMarkToolsExecutable:
    def test_marks_exe_files(self, cfg):
        exe = cfg.tools_dir / "Tool.exe"
        exe.write_text("MZ")
        exe.chmod(0o644)
        count = mark_tools_executable(cfg)
        assert count == 1
        assert exe.stat().st_mode & stat.S_IXUSR

    def test_skips_non_exe(self, cfg):
        txt = cfg.tools_dir / "readme.txt"
        txt.write_text("hello")
        txt.chmod(0o644)
        count = mark_tools_executable(cfg)
        assert count == 0
        assert not (txt.stat().st_mode & stat.S_IXUSR)

    def test_skips_already_executable(self, cfg):
        exe = cfg.tools_dir / "Tool.exe"
        exe.write_text("MZ")
        exe.chmod(0o755)
        count = mark_tools_executable(cfg)
        assert count == 0

    def test_empty_dir(self, cfg):
        count = mark_tools_executable(cfg)
        assert count == 0

    def test_no_tools_dir(self, tmp_path):
        c = Config(winbox_dir=tmp_path / "missing")
        count = mark_tools_executable(c)
        assert count == 0

    def test_case_insensitive(self, cfg):
        exe = cfg.tools_dir / "Tool.EXE"
        exe.write_text("MZ")
        exe.chmod(0o644)
        count = mark_tools_executable(cfg)
        assert count == 1


# ─── handler_path ────────────────────────────────────────────────────────────


class TestHandlerPath:
    def test_returns_expected_path(self, cfg):
        assert handler_path(cfg) == cfg.winbox_dir / "binfmt-handler.sh"


# ─── CLI: binfmt enable ─────────────────────────────────────────────────────


class TestBinfmtEnable:
    def test_enable_output(self, runner, cfg):
        with (
            patch("winbox.cli.Config.load", return_value=cfg),
            patch("winbox.binfmt.register", return_value=cfg.winbox_dir / "binfmt-handler.sh"),
            patch("winbox.binfmt.mark_tools_executable", return_value=3),
        ):
            result = runner.invoke(cli, ["binfmt", "enable"])
        assert result.exit_code == 0
        out = re.sub(r"\s+", " ", result.output)
        assert "Installing handler script" in out
        assert "Handler:" in out
        assert ".exe files will now execute via winbox" in out
        assert "Marked 3 tools executable" in out

    def test_enable_calls_register(self, runner, cfg):
        mock_register = MagicMock(return_value=cfg.winbox_dir / "binfmt-handler.sh")
        with (
            patch("winbox.cli.Config.load", return_value=cfg),
            patch("winbox.binfmt.register", mock_register),
            patch("winbox.binfmt.mark_tools_executable", return_value=0),
        ):
            runner.invoke(cli, ["binfmt", "enable"])
        mock_register.assert_called_once_with(cfg, persist=True)

    def test_enable_no_persist(self, runner, cfg):
        mock_register = MagicMock(return_value=cfg.winbox_dir / "binfmt-handler.sh")
        with (
            patch("winbox.cli.Config.load", return_value=cfg),
            patch("winbox.binfmt.register", mock_register),
            patch("winbox.binfmt.mark_tools_executable", return_value=0),
        ):
            result = runner.invoke(cli, ["binfmt", "enable", "--no-persist"])
        mock_register.assert_called_once_with(cfg, persist=False)
        assert "Persistent" not in result.output

    def test_enable_persist_message(self, runner, cfg):
        with (
            patch("winbox.cli.Config.load", return_value=cfg),
            patch("winbox.binfmt.register", return_value=cfg.winbox_dir / "binfmt-handler.sh"),
            patch("winbox.binfmt.mark_tools_executable", return_value=0),
        ):
            result = runner.invoke(cli, ["binfmt", "enable"])
        assert "Persistent across reboots" in result.output

    def test_enable_shows_path_hint(self, runner, cfg):
        with (
            patch("winbox.cli.Config.load", return_value=cfg),
            patch("winbox.binfmt.register", return_value=cfg.winbox_dir / "binfmt-handler.sh"),
            patch("winbox.binfmt.mark_tools_executable", return_value=0),
        ):
            result = runner.invoke(cli, ["binfmt", "enable"])
        out = re.sub(r"\s+", " ", result.output)
        assert "Add tools dir to PATH:" in out
        assert "export" in out

    def test_enable_winbox_not_found(self, runner, cfg):
        with (
            patch("winbox.cli.Config.load", return_value=cfg),
            patch("winbox.binfmt.register", side_effect=FileNotFoundError("winbox not found on PATH")),
        ):
            result = runner.invoke(cli, ["binfmt", "enable"])
        assert result.exit_code == 1
        assert "winbox not found" in result.output

    def test_enable_permission_error(self, runner, cfg):
        with (
            patch("winbox.cli.Config.load", return_value=cfg),
            patch("winbox.binfmt.register", side_effect=PermissionError("sudo denied")),
        ):
            result = runner.invoke(cli, ["binfmt", "enable"])
        assert result.exit_code == 1
        assert "sudo denied" in result.output

    def test_enable_binfmt_not_mounted(self, runner, cfg):
        with (
            patch("winbox.cli.Config.load", return_value=cfg),
            patch("winbox.binfmt.register", side_effect=RuntimeError("binfmt_misc not mounted")),
        ):
            result = runner.invoke(cli, ["binfmt", "enable"])
        assert result.exit_code == 1
        assert "binfmt_misc not mounted" in result.output

    def test_enable_no_mark_message_when_zero(self, runner, cfg):
        with (
            patch("winbox.cli.Config.load", return_value=cfg),
            patch("winbox.binfmt.register", return_value=cfg.winbox_dir / "binfmt-handler.sh"),
            patch("winbox.binfmt.mark_tools_executable", return_value=0),
        ):
            result = runner.invoke(cli, ["binfmt", "enable"])
        assert "Marked" not in result.output


# ─── CLI: binfmt disable ────────────────────────────────────────────────────


class TestBinfmtDisable:
    def test_disable_registered(self, runner, cfg):
        with (
            patch("winbox.cli.Config.load", return_value=cfg),
            patch("winbox.binfmt.is_registered", return_value=True),
            patch("winbox.binfmt.BINFMT_PERSIST", cfg.winbox_dir / "nonexistent"),
            patch("winbox.binfmt.unregister"),
        ):
            result = runner.invoke(cli, ["binfmt", "disable"])
        assert result.exit_code == 0
        assert "unregistered" in result.output

    def test_disable_not_registered(self, runner, cfg):
        with (
            patch("winbox.cli.Config.load", return_value=cfg),
            patch("winbox.binfmt.is_registered", return_value=False),
            patch("winbox.binfmt.BINFMT_PERSIST", cfg.winbox_dir / "nonexistent"),
        ):
            result = runner.invoke(cli, ["binfmt", "disable"])
        assert result.exit_code == 0
        assert "Not registered" in result.output

    def test_disable_permission_error(self, runner, cfg):
        with (
            patch("winbox.cli.Config.load", return_value=cfg),
            patch("winbox.binfmt.is_registered", return_value=True),
            patch("winbox.binfmt.BINFMT_PERSIST", cfg.winbox_dir / "nonexistent"),
            patch("winbox.binfmt.unregister", side_effect=PermissionError("sudo denied")),
        ):
            result = runner.invoke(cli, ["binfmt", "disable"])
        assert result.exit_code == 1


# ─── CLI: binfmt status ─────────────────────────────────────────────────────


class TestBinfmtStatus:
    def test_status_registered(self, runner, cfg):
        handler = cfg.winbox_dir / "binfmt-handler.sh"
        handler.write_text("#!/bin/bash\n")
        persist_path = cfg.winbox_dir / "winbox.conf"
        persist_path.write_text(":winbox:E::exe::/handler:")
        with (
            patch("winbox.cli.Config.load", return_value=cfg),
            patch("winbox.binfmt.is_registered", return_value=True),
            patch("winbox.binfmt.BINFMT_PERSIST", persist_path),
        ):
            result = runner.invoke(cli, ["binfmt", "status"])
        assert result.exit_code == 0
        out = re.sub(r"\s+", " ", result.output)
        assert "Registered: enabled" in out
        assert "Handler:" in out
        assert "Persistent:" in out

    def test_status_not_registered(self, runner, cfg):
        with (
            patch("winbox.cli.Config.load", return_value=cfg),
            patch("winbox.binfmt.is_registered", return_value=False),
            patch("winbox.binfmt.BINFMT_PERSIST", cfg.winbox_dir / "nonexistent"),
        ):
            result = runner.invoke(cli, ["binfmt", "status"])
        assert result.exit_code == 0
        assert "Registered: no" in result.output

    def test_status_handler_missing_warns(self, runner, cfg):
        with (
            patch("winbox.cli.Config.load", return_value=cfg),
            patch("winbox.binfmt.is_registered", return_value=True),
            patch("winbox.binfmt.BINFMT_PERSIST", cfg.winbox_dir / "nonexistent"),
        ):
            result = runner.invoke(cli, ["binfmt", "status"])
        assert "Handler: not found" in result.output
        assert "re-run" in result.output

    def test_status_shows_path_hint(self, runner, cfg):
        with (
            patch("winbox.cli.Config.load", return_value=cfg),
            patch("winbox.binfmt.is_registered", return_value=False),
            patch("winbox.binfmt.BINFMT_PERSIST", cfg.winbox_dir / "nonexistent"),
        ):
            result = runner.invoke(cli, ["binfmt", "status"])
        out = re.sub(r"\s+", " ", result.output)
        assert "export PATH=" in out

    def test_status_path_included(self, runner, cfg):
        with (
            patch("winbox.cli.Config.load", return_value=cfg),
            patch("winbox.binfmt.is_registered", return_value=False),
            patch("winbox.binfmt.BINFMT_PERSIST", cfg.winbox_dir / "nonexistent"),
            patch.dict("os.environ", {"PATH": str(cfg.tools_dir) + ":/usr/bin"}),
        ):
            result = runner.invoke(cli, ["binfmt", "status"])
        assert "tools dir included" in result.output
        assert "export PATH=" not in result.output

    def test_status_persistent(self, runner, cfg):
        persist_path = cfg.winbox_dir / "winbox.conf"
        persist_path.write_text(":winbox:E::exe::/handler:")
        with (
            patch("winbox.cli.Config.load", return_value=cfg),
            patch("winbox.binfmt.is_registered", return_value=True),
            patch("winbox.binfmt.BINFMT_PERSIST", persist_path),
        ):
            result = runner.invoke(cli, ["binfmt", "status"])
        # Persistent line should show the path (not "no")
        assert "Persistent: no" not in result.output
        assert "Persistent:" in result.output
