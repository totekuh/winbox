"""Tests for AD object CLI commands — DFS, user, group, OU, GPO, computer."""

from __future__ import annotations

import pytest

from winbox.cli import cli
from winbox.vm.guest import ExecResult


# ─── ad dfs ───────────────────────────────────────────────────────────────────


class TestAdDfsCreate:
    def test_create_success(self, runner, mock_env):
        mock_env.exec_powershell.side_effect = [
            ExecResult(0, "installed", ""),          # dfs feature install
            ExecResult(0, "SYSVOL\nready", ""),      # wait_for_dfsr
            ExecResult(0, "root created", ""),        # dfs create
        ]
        result = runner.invoke(
            cli, ["ad", "dfs", "create", "lab-dfs",
                  "--target", r"\\WIN-DC\Data"],
        )
        assert result.exit_code == 0, result.output
        assert "lab-dfs" in result.output

    def test_create_script_creates_root_share(self, runner, mock_env):
        mock_env.exec_powershell.side_effect = [
            ExecResult(0, "installed", ""),
            ExecResult(0, "ready", ""),
            ExecResult(0, "done", ""),
        ]
        runner.invoke(
            cli, ["ad", "dfs", "create", "myns",
                  "--target", r"\\DC\Share"],
        )
        script = mock_env.exec_powershell.call_args[0][0]
        assert "New-SmbShare" in script
        assert "DFSRoots" in script
        assert "DomainV2" in script

    def test_create_script_adds_target_as_folder(self, runner, mock_env):
        mock_env.exec_powershell.side_effect = [
            ExecResult(0, "installed", ""),
            ExecResult(0, "ready", ""),
            ExecResult(0, "done", ""),
        ]
        runner.invoke(
            cli, ["ad", "dfs", "create", "myns",
                  "--target", r"\\DC\Finance"],
        )
        script = mock_env.exec_powershell.call_args[0][0]
        assert "New-DfsnFolder" in script
        assert "Finance" in script

    def test_create_invalid_namespace(self, runner, mock_env):
        result = runner.invoke(
            cli, ["ad", "dfs", "create", "bad name!",
                  "--target", r"\\WIN-DC\Data"],
        )
        assert result.exit_code != 0

    def test_create_invalid_target(self, runner, mock_env):
        result = runner.invoke(
            cli, ["ad", "dfs", "create", "lab-dfs",
                  "--target", "not-a-unc-path"],
        )
        assert result.exit_code != 0

    def test_create_feature_install_fails(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            1, "", "feature error"
        )
        result = runner.invoke(
            cli, ["ad", "dfs", "create", "ns",
                  "--target", r"\\DC\S"],
        )
        assert result.exit_code != 0

    def test_create_namespace_creation_fails(self, runner, mock_env):
        mock_env.exec_powershell.side_effect = [
            ExecResult(0, "installed", ""),
            ExecResult(0, "ready", ""),
            ExecResult(1, "", "One or more parameter values invalid"),
        ]
        result = runner.invoke(
            cli, ["ad", "dfs", "create", "ns",
                  "--target", r"\\DC\S"],
        )
        assert result.exit_code != 0


class TestAdDfsList:
    def test_list_with_namespaces(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            0, r"Namespace: \\TESTLAB.LOCAL\lab-dfs  State: Online", "",
        )
        result = runner.invoke(cli, ["ad", "dfs", "list"])
        assert result.exit_code == 0
        assert "lab-dfs" in result.output

    def test_list_empty(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(cli, ["ad", "dfs", "list"])
        assert result.exit_code == 0
        assert "No DFS" in result.output

    def test_list_query_fails(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            1, "", "DFS error"
        )
        result = runner.invoke(cli, ["ad", "dfs", "list"])
        assert result.exit_code != 0


class TestAdDfsDelete:
    def test_delete_success(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(cli, ["ad", "dfs", "delete", "lab-dfs"])
        assert result.exit_code == 0
        assert "removed" in result.output.lower()

    def test_delete_script_has_fallback(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        runner.invoke(cli, ["ad", "dfs", "delete", "lab-dfs"])
        script = mock_env.exec_powershell.call_args[0][0]
        assert "Remove-ADObject" in script

    def test_delete_invalid_namespace(self, runner, mock_env):
        result = runner.invoke(cli, ["ad", "dfs", "delete", "bad name!"])
        assert result.exit_code != 0

    def test_delete_failure(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            1, "", "namespace not found"
        )
        result = runner.invoke(cli, ["ad", "dfs", "delete", "nope"])
        assert result.exit_code != 0


class TestAdDfsAddTarget:
    def test_add_target_success(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(
            cli, ["ad", "dfs", "add-target", "lab-dfs", "docs",
                  "--target", r"\\WIN-DC\Docs"],
        )
        assert result.exit_code == 0
        assert "docs" in result.output

    def test_add_target_script_uses_server_localhost(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        runner.invoke(
            cli, ["ad", "dfs", "add-target", "ns", "folder",
                  "--target", r"\\DC\X"],
        )
        script = mock_env.exec_powershell.call_args[0][0]
        assert "-Server localhost" in script

    def test_add_target_invalid_unc(self, runner, mock_env):
        result = runner.invoke(
            cli, ["ad", "dfs", "add-target", "ns", "folder",
                  "--target", "not-unc"],
        )
        assert result.exit_code != 0

    def test_add_target_failure(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            1, "", "namespace not found"
        )
        result = runner.invoke(
            cli, ["ad", "dfs", "add-target", "ns", "folder",
                  "--target", r"\\DC\X"],
        )
        assert result.exit_code != 0


# ─── ad user ──────────────────────────────────────────────────────────────────


class TestAdUserCreate:
    def test_create_basic(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(
            cli, ["ad", "user", "create", "jdoe", "--password", "P@ss1"],
        )
        assert result.exit_code == 0, result.output
        script = mock_env.exec_powershell.call_args[0][0]
        assert "New-ADUser" in script
        assert "jdoe" in script
        assert "-Server localhost" in script

    def test_create_with_ou(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(
            cli, ["ad", "user", "create", "svc", "--password", "P@ss",
                  "--ou", "OU=Service,DC=TEST,DC=LOCAL"],
        )
        assert result.exit_code == 0

    def test_create_invalid_name(self, runner, mock_env):
        result = runner.invoke(
            cli, ["ad", "user", "create", "a" * 25, "--password", "x"],
        )
        assert result.exit_code != 0

    def test_create_invalid_ou(self, runner, mock_env):
        result = runner.invoke(
            cli, ["ad", "user", "create", "jdoe", "--password", "x",
                  "--ou", "not-a-dn"],
        )
        assert result.exit_code != 0


class TestAdUserDelete:
    def test_delete_success(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(cli, ["ad", "user", "delete", "jdoe"])
        assert result.exit_code == 0
        script = mock_env.exec_powershell.call_args[0][0]
        assert "Remove-ADUser" in script
        assert "-Server localhost" in script

    def test_delete_nonexistent_user(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            1, "", "Cannot find an object with identity: 'ghost'"
        )
        result = runner.invoke(cli, ["ad", "user", "delete", "ghost"])
        assert result.exit_code != 0


class TestAdUserList:
    def test_list_users(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            0, "jdoe  True  jdoe@test.local", "",
        )
        result = runner.invoke(cli, ["ad", "user", "list"])
        assert result.exit_code == 0
        assert "jdoe" in result.output


# ─── ad group ─────────────────────────────────────────────────────────────────


class TestAdUserCreateFailure:
    def test_create_ps_failure(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            1, "", "password does not meet complexity"
        )
        result = runner.invoke(
            cli, ["ad", "user", "create", "weak", "--password", "x"],
        )
        assert result.exit_code != 0
        assert "Failed" in result.output


class TestAdGroupCreate:
    def test_create_default_scope(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(cli, ["ad", "group", "create", "IT-Admins"])
        assert result.exit_code == 0, result.output
        script = mock_env.exec_powershell.call_args[0][0]
        assert "New-ADGroup" in script
        assert "Global" in script
        assert "-Server localhost" in script

    def test_create_universal_scope(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(
            cli, ["ad", "group", "create", "AllUsers", "--scope", "Universal"],
        )
        assert result.exit_code == 0
        script = mock_env.exec_powershell.call_args[0][0]
        assert "Universal" in script


class TestAdGroupAddMember:
    def test_add_member(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(
            cli, ["ad", "group", "add-member", "IT-Admins", "jdoe"],
        )
        assert result.exit_code == 0
        script = mock_env.exec_powershell.call_args[0][0]
        assert "Add-ADGroupMember" in script
        assert "-Server localhost" in script


class TestAdGroupRemoveMember:
    def test_remove_member(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(
            cli, ["ad", "group", "remove-member", "IT-Admins", "jdoe"],
        )
        assert result.exit_code == 0
        script = mock_env.exec_powershell.call_args[0][0]
        assert "Remove-ADGroupMember" in script


# ─── ad ou ────────────────────────────────────────────────────────────────────


class TestAdOuCreate:
    def test_create_basic(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(cli, ["ad", "ou", "create", "TestOU"])
        assert result.exit_code == 0
        script = mock_env.exec_powershell.call_args[0][0]
        assert "New-ADOrganizationalUnit" in script
        assert "-Server localhost" in script

    def test_create_with_path(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(
            cli, ["ad", "ou", "create", "Sub",
                  "--path", "DC=TEST,DC=LOCAL"],
        )
        assert result.exit_code == 0


class TestAdOuDelete:
    def test_delete(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(
            cli, ["ad", "ou", "delete", "OU=Test,DC=TEST,DC=LOCAL"],
        )
        assert result.exit_code == 0
        script = mock_env.exec_powershell.call_args[0][0]
        assert "Remove-ADOrganizationalUnit" in script

    def test_delete_invalid_dn(self, runner, mock_env):
        result = runner.invoke(cli, ["ad", "ou", "delete", "not-a-dn"])
        assert result.exit_code != 0


# ─── ad gpo ───────────────────────────────────────────────────────────────────


class TestAdGroupDeleteFailure:
    def test_delete_nonexistent(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            1, "", "Cannot find an object"
        )
        result = runner.invoke(cli, ["ad", "group", "delete", "NoSuch"])
        assert result.exit_code != 0


class TestAdOuCreateFailure:
    def test_create_already_exists(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            1, "", "already exists"
        )
        result = runner.invoke(cli, ["ad", "ou", "create", "Dupe"])
        assert result.exit_code != 0


class TestAdGpoCreate:
    def test_create(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "GPO created", "")
        result = runner.invoke(cli, ["ad", "gpo", "create", "TestPolicy"])
        assert result.exit_code == 0, result.output
        script = mock_env.exec_powershell.call_args[0][0]
        assert "New-GPO" in script

    def test_create_invalid_name(self, runner, mock_env):
        result = runner.invoke(cli, ["ad", "gpo", "create", "x" * 200])
        assert result.exit_code != 0


class TestAdGpoEdit:
    def test_edit(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(
            cli, ["ad", "gpo", "edit", "TestPolicy",
                  "--key", r"HKLM\SOFTWARE\Test",
                  "--value-name", "Setting",
                  "--type", "DWord",
                  "--value", "1"],
        )
        assert result.exit_code == 0
        script = mock_env.exec_powershell.call_args[0][0]
        assert "Set-GPRegistryValue" in script

    def test_edit_dword_casts_to_number(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        runner.invoke(
            cli, ["ad", "gpo", "edit", "P",
                  "--key", r"HKLM\SOFTWARE\X",
                  "--value-name", "V",
                  "--type", "DWord",
                  "--value", "42"],
        )
        script = mock_env.exec_powershell.call_args[0][0]
        assert "[long]$v" in script


class TestAdGpoRemove:
    def test_remove(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(cli, ["ad", "gpo", "remove", "TestPolicy"])
        assert result.exit_code == 0
        script = mock_env.exec_powershell.call_args[0][0]
        assert "Remove-GPO" in script


class TestAdGpoLink:
    def test_link(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        result = runner.invoke(
            cli, ["ad", "gpo", "link", "TestPolicy",
                  "--target", "OU=Test,DC=TEST,DC=LOCAL"],
        )
        assert result.exit_code == 0
        script = mock_env.exec_powershell.call_args[0][0]
        assert "New-GPLink" in script

    def test_link_invalid_target(self, runner, mock_env):
        result = runner.invoke(
            cli, ["ad", "gpo", "link", "TestPolicy",
                  "--target", "not-a-dn"],
        )
        assert result.exit_code != 0


# ─── ad computer ──────────────────────────────────────────────────────────────


class TestAdComputerList:
    def test_list(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            0, "WIN-DC  WIN-DC.test.local  Windows Server 2022", "",
        )
        result = runner.invoke(cli, ["ad", "computer", "list"])
        assert result.exit_code == 0
        assert "WIN-DC" in result.output
