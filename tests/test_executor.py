"""Tests for winbox.executor — path resolution."""

from pathlib import Path

import pytest

from winbox.exec.executor import resolve_exe


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

    def test_exe_case_insensitive(self, tmp_path):
        (tmp_path / "Tool.EXE").touch()
        # .EXE should resolve just like .exe
        assert resolve_exe("Tool.EXE", tmp_path) == "Z:\\tools\\Tool.EXE"

    def test_exe_mixed_case(self, tmp_path):
        (tmp_path / "Rubeus.Exe").touch()
        assert resolve_exe("Rubeus.Exe", tmp_path) == "Z:\\tools\\Rubeus.Exe"

    def test_bare_exe_with_no_tools_dir(self):
        # Non-existent tools dir — can't resolve
        bogus = Path("/nonexistent/tools")
        assert resolve_exe("Rubeus.exe", bogus) == "Rubeus.exe"
