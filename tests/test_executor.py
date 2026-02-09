"""Tests for winbox.executor — path resolution and human_size."""

from pathlib import Path

import pytest

from winbox.executor import _human_size, resolve_exe


class TestResolveExe:
    def test_bare_exe_found_in_tools(self, tmp_path):
        (tmp_path / "SharpHound.exe").touch()
        assert resolve_exe("SharpHound.exe", tmp_path) == "Z:\\tools\\SharpHound.exe"

    def test_bare_exe_not_found(self, tmp_path):
        # Tool doesn't exist in tools dir — return as-is
        assert resolve_exe("Missing.exe", tmp_path) == "Missing.exe"

    def test_already_has_backslash_path(self, tmp_path):
        (tmp_path / "tool.exe").touch()
        assert resolve_exe("C:\\somewhere\\tool.exe", tmp_path) == "C:\\somewhere\\tool.exe"

    def test_already_has_forward_slash_path(self, tmp_path):
        (tmp_path / "tool.exe").touch()
        assert resolve_exe("/some/path/tool.exe", tmp_path) == "/some/path/tool.exe"

    def test_non_exe_passthrough(self, tmp_path):
        (tmp_path / "script.bat").touch()
        assert resolve_exe("script.bat", tmp_path) == "script.bat"

    def test_cmd_exe_not_resolved(self, tmp_path):
        # cmd.exe shouldn't be resolved to Z:\tools\ even if it hypothetically existed
        # but since it wouldn't be in tools_dir, it stays as-is
        assert resolve_exe("cmd.exe", tmp_path) == "cmd.exe"

    def test_exe_case_sensitive(self, tmp_path):
        (tmp_path / "Tool.EXE").touch()
        # .exe check is lowercase, so .EXE won't match
        assert resolve_exe("Tool.EXE", tmp_path) == "Tool.EXE"

    def test_bare_exe_with_no_tools_dir(self):
        # Non-existent tools dir — can't resolve
        bogus = Path("/nonexistent/tools")
        assert resolve_exe("Rubeus.exe", bogus) == "Rubeus.exe"


class TestHumanSize:
    def test_bytes(self):
        assert _human_size(0) == "0.0 B"
        assert _human_size(1) == "1.0 B"
        assert _human_size(512) == "512.0 B"
        assert _human_size(1023) == "1023.0 B"

    def test_kilobytes(self):
        assert _human_size(1024) == "1.0 KB"
        assert _human_size(1536) == "1.5 KB"

    def test_megabytes(self):
        assert _human_size(1024 * 1024) == "1.0 MB"
        assert _human_size(int(1.5 * 1024 * 1024)) == "1.5 MB"

    def test_gigabytes(self):
        assert _human_size(1024 ** 3) == "1.0 GB"

    def test_terabytes(self):
        assert _human_size(1024 ** 4) == "1.0 TB"
        assert _human_size(2 * 1024 ** 4) == "2.0 TB"
