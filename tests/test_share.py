"""Tests for winbox.cli.share — share and user commands."""

from unittest.mock import patch

import pytest

from winbox.cli import cli
from winbox.vm.guest import ExecResult


# ─── share create ────────────────────────────────────────────────────────────


class TestShareCreate:
    def test_create_default_path(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            0, "NAME=Data\nPATH=C:\\Shares\\Data", ""
        )
        result = runner.invoke(cli, ["share", "create", "Data"])
        assert result.exit_code == 0, result.output
        assert "Data" in result.output
        script = mock_env.exec_powershell.call_args[0][0]
        assert "New-SmbShare" in script
        assert "C:\\Shares\\Data" in script

    def test_create_custom_path(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(
            cli, ["share", "create", "Data", "D:\\MyData"]
        )
        assert result.exit_code == 0, result.output
        script = mock_env.exec_powershell.call_args[0][0]
        assert "D:\\MyData" in script

    def test_create_with_access_flags(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(
            cli,
            ["share", "create", "Data", "--full-access", "alice",
             "--read-access", "bob"],
        )
        assert result.exit_code == 0, result.output
        script = mock_env.exec_powershell.call_args[0][0]
        assert "-FullAccess" in script
        assert "alice" in script
        assert "-ReadAccess" in script
        assert "bob" in script

    def test_create_invalid_name(self, runner, mock_env):
        result = runner.invoke(cli, ["share", "create", "bad share!"])
        assert result.exit_code != 0

    def test_create_failure(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            1, "", "Share already exists"
        )
        result = runner.invoke(cli, ["share", "create", "Data"])
        assert result.exit_code != 0
        assert "Failed" in result.output


# ─── share delete ────────────────────────────────────────────────────────────


class TestShareDelete:
    def test_delete_simple(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(cli, ["share", "delete", "Data"])
        assert result.exit_code == 0, result.output
        assert "removed" in result.output.lower()

    def test_delete_purge(self, runner, mock_env):
        mock_env.exec_powershell.side_effect = [
            ExecResult(0, "C:\\Shares\\Data", ""),  # resolve path
            ExecResult(0, "", ""),                   # remove share
            ExecResult(0, "", ""),                   # remove folder
        ]
        result = runner.invoke(cli, ["share", "delete", "Data", "--purge"])
        assert result.exit_code == 0, result.output
        assert "deleted" in result.output.lower()

    def test_delete_failure(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            1, "", "Share not found"
        )
        result = runner.invoke(cli, ["share", "delete", "Data"])
        assert result.exit_code != 0


# ─── share list ──────────────────────────────────────────────────────────────


class TestShareList:
    def test_list(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            0, "Name   Path            Description\n"
               "----   ----            -----------\n"
               "Data   C:\\Shares\\Data\n", ""
        )
        result = runner.invoke(cli, ["share", "list"])
        assert result.exit_code == 0, result.output
        assert "Data" in result.output

    def test_list_empty(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(cli, ["share", "list"])
        assert result.exit_code == 0
        assert "No shares" in result.output


# ─── share grant ─────────────────────────────────────────────────────────────


class TestShareGrant:
    def test_grant_full(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(
            cli, ["share", "grant", "Data", "bob"]
        )
        assert result.exit_code == 0, result.output
        assert "Full" in result.output
        script = mock_env.exec_powershell.call_args[0][0]
        assert "Grant-SmbShareAccess" in script
        assert "Full" in script

    def test_grant_read(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(
            cli, ["share", "grant", "Data", "bob", "--permission", "read"]
        )
        assert result.exit_code == 0, result.output
        assert "Read" in result.output


# ─── share revoke ────────────────────────────────────────────────────────────


class TestShareRevoke:
    def test_revoke(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(cli, ["share", "revoke", "Data", "bob"])
        assert result.exit_code == 0, result.output
        assert "revoked" in result.output.lower()


# ─── share ls ────────────────────────────────────────────────────────────────


class TestShareLs:
    def test_ls_root(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            0, "Name      Length LastWriteTime\nfile.txt  1024   2024-01-01", ""
        )
        result = runner.invoke(cli, ["share", "ls", "Data"])
        assert result.exit_code == 0, result.output
        assert "file.txt" in result.output

    def test_ls_subdir(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(cli, ["share", "ls", "Data", "subdir"])
        assert result.exit_code == 0, result.output
        script = mock_env.exec_powershell.call_args[0][0]
        assert "GetFullPath" in script
        assert "StartsWith" in script

    def test_ls_traversal_rejected(self, runner, mock_env):
        result = runner.invoke(cli, ["share", "ls", "Data", "../etc"])
        assert result.exit_code != 0

    def test_ls_absolute_rejected(self, runner, mock_env):
        result = runner.invoke(cli, ["share", "ls", "Data", "C:\\Windows"])
        assert result.exit_code != 0


# ─── share mkdir ─────────────────────────────────────────────────────────────


class TestShareMkdir:
    def test_mkdir(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            0, "C:\\Shares\\Data\\reports", ""
        )
        result = runner.invoke(cli, ["share", "mkdir", "Data", "reports"])
        assert result.exit_code == 0, result.output
        assert "Created" in result.output

    def test_mkdir_traversal_rejected(self, runner, mock_env):
        result = runner.invoke(
            cli, ["share", "mkdir", "Data", "..\\escape"]
        )
        assert result.exit_code != 0


# ─── share write ─────────────────────────────────────────────────────────────


class TestShareWrite:
    def test_write_content(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            0, "C:\\Shares\\Data\\config.ini", ""
        )
        result = runner.invoke(
            cli,
            ["share", "write", "Data", "config.ini", "--content", "[db]\nhost=10.0.0.1"],
        )
        assert result.exit_code == 0, result.output
        assert "Written" in result.output
        script = mock_env.exec_powershell.call_args[0][0]
        assert "FromBase64String" in script

    def test_write_source(self, runner, mock_env, cfg, tmp_path):
        src = tmp_path / "payload.txt"
        src.write_text("test content")
        mock_env.exec_powershell.return_value = ExecResult(
            0, "C:\\Shares\\Data\\payload.txt", ""
        )
        result = runner.invoke(
            cli,
            ["share", "write", "Data", "payload.txt", "--source", str(src)],
        )
        assert result.exit_code == 0, result.output
        assert "Uploaded" in result.output

    def test_write_neither(self, runner, mock_env):
        result = runner.invoke(
            cli, ["share", "write", "Data", "file.txt"]
        )
        assert result.exit_code != 0

    def test_write_both(self, runner, mock_env, tmp_path):
        src = tmp_path / "f.txt"
        src.write_text("x")
        result = runner.invoke(
            cli,
            ["share", "write", "Data", "file.txt",
             "--content", "x", "--source", str(src)],
        )
        assert result.exit_code != 0

    def test_write_traversal_rejected(self, runner, mock_env):
        result = runner.invoke(
            cli,
            ["share", "write", "Data", "../escape.txt", "--content", "pwned"],
        )
        assert result.exit_code != 0


# ─── share rm ────────────────────────────────────────────────────────────────


class TestShareRm:
    def test_rm(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            0, "C:\\Shares\\Data\\old", ""
        )
        result = runner.invoke(cli, ["share", "rm", "Data", "old"])
        assert result.exit_code == 0, result.output
        assert "Removed" in result.output

    def test_rm_traversal_rejected(self, runner, mock_env):
        result = runner.invoke(cli, ["share", "rm", "Data", "..\\..\\Windows"])
        assert result.exit_code != 0


# ─── user create ─────────────────────────────────────────────────────────────


class TestUserCreate:
    def test_create(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(
            cli, ["user", "create", "alice", "--password", "P@ssw0rd!"]
        )
        assert result.exit_code == 0, result.output
        assert "alice" in result.output
        script = mock_env.exec_powershell.call_args[0][0]
        assert "New-LocalUser" in script
        assert "FromBase64String" in script

    def test_create_with_full_name(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(
            cli,
            ["user", "create", "bob", "--password", "pass",
             "--full-name", "Bob Smith"],
        )
        assert result.exit_code == 0, result.output

    def test_create_invalid_username(self, runner, mock_env):
        result = runner.invoke(
            cli, ["user", "create", "bad/user", "--password", "pass"]
        )
        assert result.exit_code != 0

    def test_create_failure(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            1, "", "User already exists"
        )
        result = runner.invoke(
            cli, ["user", "create", "alice", "--password", "pass"]
        )
        assert result.exit_code != 0


# ─── user delete ─────────────────────────────────────────────────────────────


class TestUserDelete:
    def test_delete(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(cli, ["user", "delete", "alice"])
        assert result.exit_code == 0, result.output
        assert "deleted" in result.output.lower()

    def test_delete_failure(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            1, "", "User not found"
        )
        result = runner.invoke(cli, ["user", "delete", "alice"])
        assert result.exit_code != 0


# ─── user list ───────────────────────────────────────────────────────────────


class TestUserList:
    def test_list(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            0,
            "Name           Enabled LastLogon Description\n"
            "Administrator  True    2024-01-01\n"
            "alice          True    2024-01-02\n",
            "",
        )
        result = runner.invoke(cli, ["user", "list"])
        assert result.exit_code == 0, result.output
        assert "alice" in result.output

    def test_list_empty(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(cli, ["user", "list"])
        assert result.exit_code == 0
        assert "No users" in result.output


# ─── validation helpers ──────────────────────────────────────────────────────


class TestValidation:
    def test_share_name_valid(self):
        from winbox.cli.share import _validate_share_name
        _validate_share_name("My-Share_v2.0")

    def test_share_name_invalid_chars(self):
        from winbox.cli.share import _validate_share_name
        with pytest.raises(Exception):
            _validate_share_name("share with spaces!")

    def test_share_name_too_long(self):
        from winbox.cli.share import _validate_share_name
        with pytest.raises(Exception):
            _validate_share_name("a" * 81)

    def test_username_valid(self):
        from winbox.cli.share import _validate_username
        _validate_username("alice")
        _validate_username("Bob Smith")

    def test_username_invalid(self):
        from winbox.cli.share import _validate_username
        with pytest.raises(Exception):
            _validate_username("user/name")

    def test_relative_path_valid(self):
        from winbox.cli.share import _validate_relative_path
        assert _validate_relative_path("subdir/file.txt") == "subdir\\file.txt"
        assert _validate_relative_path("a\\b\\c") == "a\\b\\c"

    def test_relative_path_traversal(self):
        from winbox.cli.share import _validate_relative_path
        with pytest.raises(Exception):
            _validate_relative_path("../etc/passwd")

    def test_relative_path_absolute(self):
        from winbox.cli.share import _validate_relative_path
        with pytest.raises(Exception):
            _validate_relative_path("C:\\Windows\\System32")

    def test_relative_path_unc(self):
        from winbox.cli.share import _validate_relative_path
        with pytest.raises(Exception):
            _validate_relative_path("\\\\server\\share")

    def test_relative_path_bad_chars(self):
        from winbox.cli.share import _validate_relative_path
        with pytest.raises(Exception):
            _validate_relative_path('file<name>.txt')
