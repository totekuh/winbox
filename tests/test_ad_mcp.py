"""MCP unit tests for AD tools — promote, demote, status, objects, GPO, DFS."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from winbox.config import Config
from winbox.vm import VMState
from winbox.vm.guest import ExecResult


@pytest.fixture
def cfg(tmp_path):
    c = Config(winbox_dir=tmp_path / ".winbox")
    c.winbox_dir.mkdir(parents=True)
    c.shared_dir.mkdir(parents=True)
    c.tools_dir.mkdir(parents=True)
    c.loot_dir.mkdir(parents=True)
    return c


@pytest.fixture
def mock_mcp(cfg):
    """Patch MCP internals for AD tool unit tests."""
    import winbox.mcp._common as _common

    ga = MagicMock()
    ga.ping.return_value = True

    vm = MagicMock()
    vm.state.return_value = VMState.RUNNING

    _common._cfg = cfg
    _common._vm = vm
    _common._ga = ga
    _common._initialized = True

    yield ga, vm, cfg

    _common._cfg = None
    _common._vm = None
    _common._ga = None
    _common._initialized = False


# ─── server gate ──────────────────────────────────────────────────────────────


class TestMCPServerGate:
    def test_promote_rejected_on_client(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        cfg.vm_os = "win11"
        from winbox.mcp._ad import ad_promote
        with pytest.raises(ValueError, match="Windows Server"):
            ad_promote(domain="TEST.LOCAL", password="x")

    def test_status_rejected_on_client(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        cfg.vm_os = "win11"
        from winbox.mcp._ad import ad_status
        with pytest.raises(ValueError, match="Windows Server"):
            ad_status()

    def test_user_create_rejected_on_client(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        cfg.vm_os = "win11"
        from winbox.mcp._ad_objects import ad_user_create
        with pytest.raises(ValueError, match="Windows Server"):
            ad_user_create(sam="x", password="x")

    def test_gpo_create_rejected_on_client(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        cfg.vm_os = "win11"
        from winbox.mcp._ad_gpo import ad_gpo_create
        with pytest.raises(ValueError, match="Windows Server"):
            ad_gpo_create(name="x")

    def test_dfs_create_rejected_on_client(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        cfg.vm_os = "win11"
        from winbox.mcp._ad_dfs import ad_dfs_create
        with pytest.raises(ValueError, match="Windows Server"):
            ad_dfs_create(namespace="x", target=r"\\S\X")


# ─── validation ───────────────────────────────────────────────────────────────


class TestMCPValidation:
    def test_promote_invalid_domain(self, mock_mcp):
        from winbox.mcp._ad import ad_promote
        with pytest.raises(ValueError, match="FQDN"):
            ad_promote(domain="nodots", password="x")

    def test_user_create_invalid_sam(self, mock_mcp):
        from winbox.mcp._ad_objects import ad_user_create
        with pytest.raises(ValueError, match="SAM"):
            ad_user_create(sam="a" * 25, password="x")

    def test_user_create_invalid_ou(self, mock_mcp):
        from winbox.mcp._ad_objects import ad_user_create
        with pytest.raises(ValueError, match="distinguished"):
            ad_user_create(sam="ok", password="x", ou="bad")

    def test_gpo_edit_invalid_type(self, mock_mcp):
        from winbox.mcp._ad_gpo import ad_gpo_edit
        with pytest.raises(ValueError, match="reg_type"):
            ad_gpo_edit(name="P", key="K", value_name="V",
                        reg_type="BadType", value="1")

    def test_group_create_invalid_scope(self, mock_mcp):
        from winbox.mcp._ad_objects import ad_group_create
        with pytest.raises(ValueError, match="scope"):
            ad_group_create(name="G", scope="BadScope")

    def test_dfs_create_invalid_namespace(self, mock_mcp):
        from winbox.mcp._ad_dfs import ad_dfs_create
        with pytest.raises(ValueError, match="namespace"):
            ad_dfs_create(namespace="bad ns!", target=r"\\S\X")

    def test_dfs_create_invalid_unc(self, mock_mcp):
        from winbox.mcp._ad_dfs import ad_dfs_create
        with pytest.raises(ValueError, match="UNC"):
            ad_dfs_create(namespace="ok", target="not-unc")

    def test_gpo_link_invalid_target(self, mock_mcp):
        from winbox.mcp._ad_gpo import ad_gpo_link
        with pytest.raises(ValueError, match="distinguished"):
            ad_gpo_link(name="P", target="bad")

    def test_ou_delete_invalid_dn(self, mock_mcp):
        from winbox.mcp._ad_objects import ad_ou_delete
        with pytest.raises(ValueError, match="distinguished"):
            ad_ou_delete(dn="bad")


# ─── ad_promote ───────────────────────────────────────────────────────────────


class TestMCPPromote:
    def test_promote_success(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "done", "")
        ga.exec.return_value = ExecResult(0, "", "")
        ga.wait.return_value = None

        from winbox.mcp._ad import ad_promote
        with patch("winbox.mcp._ad.wait_for_adws", return_value="WIN-DC.TEST.LOCAL"), \
             patch("winbox.mcp._ad.wait_for_dfsr"):
            result = json.loads(ad_promote(domain="TEST.LOCAL", password="x"))

        assert result["promoted"] is True
        assert result["domain"] == "TEST.LOCAL"
        assert result["netbios"] == "TEST"
        script = ga.exec_powershell.call_args[0][0]
        assert "Install-ADDSForest" in script or "Install-WindowsFeature" in script

    def test_promote_install_fails(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(1, "", "feature error")

        from winbox.mcp._ad import ad_promote
        result = ad_promote(domain="TEST.LOCAL", password="x")
        assert "exit code" in result.lower() or "feature error" in result.lower()

    def test_promote_adws_timeout_still_succeeds(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "done", "")
        ga.exec.return_value = ExecResult(0, "", "")
        ga.wait.return_value = None

        from winbox.mcp._ad import ad_promote
        with patch("winbox.mcp._ad.wait_for_adws", side_effect=RuntimeError("timeout")), \
             patch("winbox.mcp._ad.wait_for_dfsr"):
            result = json.loads(ad_promote(domain="TEST.LOCAL", password="x"))

        assert result["promoted"] is True
        assert result["hostname"] == "unknown"


# ─── ad_demote ────────────────────────────────────────────────────────────────


class TestMCPDemote:
    def test_demote_success(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "demoted", "")
        ga.exec.return_value = ExecResult(0, "", "")
        ga.wait.return_value = None

        from winbox.mcp._ad import ad_demote
        result = json.loads(ad_demote(password="x"))
        assert result["demoted"] is True
        script = ga.exec_powershell.call_args[0][0]
        assert "Uninstall-ADDSDomainController" in script

    def test_demote_failure(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(1, "", "demotion error")

        from winbox.mcp._ad import ad_demote
        result = ad_demote(password="x")
        assert "exit code" in result.lower() or "demotion error" in result.lower()


# ─── ad_status ────────────────────────────────────────────────────────────────


class TestMCPStatus:
    def test_status_returns_json(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        info = json.dumps({"is_dc": True, "domain": "TEST.LOCAL"})
        ga.exec_powershell.return_value = ExecResult(0, info, "")

        from winbox.mcp._ad import ad_status
        result = ad_status()
        assert "TEST.LOCAL" in result


# ─── user CRUD ────────────────────────────────────────────────────────────────


class TestMCPUserCRUD:
    def test_create(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "", "")
        from winbox.mcp._ad_objects import ad_user_create
        result = json.loads(ad_user_create(sam="jdoe", password="P@ss"))
        assert result["created"] is True
        script = ga.exec_powershell.call_args[0][0]
        assert "New-ADUser" in script
        assert "-Server localhost" in script

    def test_delete(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "", "")
        from winbox.mcp._ad_objects import ad_user_delete
        result = json.loads(ad_user_delete(sam="jdoe"))
        assert result["deleted"] is True

    def test_list(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(
            0, '[{"sam":"jdoe","enabled":true}]', "",
        )
        from winbox.mcp._ad_objects import ad_user_list
        result = ad_user_list()
        assert "jdoe" in result


# ─── group CRUD ───────────────────────────────────────────────────────────────


class TestMCPGroupCRUD:
    def test_create(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "", "")
        from winbox.mcp._ad_objects import ad_group_create
        result = json.loads(ad_group_create(name="IT"))
        assert result["created"] is True
        script = ga.exec_powershell.call_args[0][0]
        assert "New-ADGroup" in script
        assert "-Server localhost" in script

    def test_delete(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "", "")
        from winbox.mcp._ad_objects import ad_group_delete
        result = json.loads(ad_group_delete(name="IT"))
        assert result["deleted"] is True

    def test_list(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "[]", "")
        from winbox.mcp._ad_objects import ad_group_list
        result = ad_group_list()
        assert "[]" in result

    def test_add_member(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "", "")
        from winbox.mcp._ad_objects import ad_group_add_member
        result = json.loads(ad_group_add_member(group="IT", member="jdoe"))
        assert result["added"] is True

    def test_remove_member(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "", "")
        from winbox.mcp._ad_objects import ad_group_remove_member
        result = json.loads(ad_group_remove_member(group="IT", member="jdoe"))
        assert result["removed"] is True


# ─── OU CRUD ──────────────────────────────────────────────────────────────────


class TestMCPOuCRUD:
    def test_create(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "", "")
        from winbox.mcp._ad_objects import ad_ou_create
        result = json.loads(ad_ou_create(name="TestOU"))
        assert result["created"] is True

    def test_delete(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "", "")
        from winbox.mcp._ad_objects import ad_ou_delete
        result = json.loads(ad_ou_delete(dn="OU=X,DC=T,DC=L"))
        assert result["deleted"] is True

    def test_list(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "[]", "")
        from winbox.mcp._ad_objects import ad_ou_list
        result = ad_ou_list()
        assert "[]" in result


# ─── computer ─────────────────────────────────────────────────────────────────


class TestMCPComputer:
    def test_list(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(
            0, '[{"name":"WINBOX"}]', "",
        )
        from winbox.mcp._ad_objects import ad_computer_list
        result = ad_computer_list()
        assert "WINBOX" in result


# ─── GPO CRUD ─────────────────────────────────────────────────────────────────


class TestMCPGpoCRUD:
    def test_create(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "", "")
        from winbox.mcp._ad_gpo import ad_gpo_create
        result = json.loads(ad_gpo_create(name="TestGPO"))
        assert result["created"] is True
        script = ga.exec_powershell.call_args[0][0]
        assert "New-GPO" in script

    def test_edit(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "", "")
        from winbox.mcp._ad_gpo import ad_gpo_edit
        result = json.loads(ad_gpo_edit(
            name="P", key="K", value_name="V", reg_type="DWord", value="1",
        ))
        assert result["updated"] is True
        script = ga.exec_powershell.call_args[0][0]
        assert "Set-GPRegistryValue" in script

    def test_remove(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "", "")
        from winbox.mcp._ad_gpo import ad_gpo_remove
        result = json.loads(ad_gpo_remove(name="P"))
        assert result["removed"] is True

    def test_list(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "[]", "")
        from winbox.mcp._ad_gpo import ad_gpo_list
        result = ad_gpo_list()
        assert "[]" in result

    def test_link(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "", "")
        from winbox.mcp._ad_gpo import ad_gpo_link
        result = json.loads(ad_gpo_link(
            name="P", target="DC=T,DC=L",
        ))
        assert result["linked"] is True


# ─── DFS CRUD ─────────────────────────────────────────────────────────────────


class TestMCPDfsCRUD:
    def test_create(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.side_effect = [
            ExecResult(0, "installed", ""),    # dfs feature
            ExecResult(0, "ready", ""),         # wait_for_dfsr
            ExecResult(0, "created", ""),        # dfs create
        ]
        from winbox.mcp._ad_dfs import ad_dfs_create
        result = json.loads(ad_dfs_create(
            namespace="ns", target=r"\\S\X",
        ))
        assert result["created"] is True

    def test_create_feature_fails(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(1, "", "feature error")
        from winbox.mcp._ad_dfs import ad_dfs_create
        result = ad_dfs_create(namespace="ns", target=r"\\S\X")
        assert "exit code" in result.lower() or "feature error" in result.lower()

    def test_add_target(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "", "")
        from winbox.mcp._ad_dfs import ad_dfs_add_target
        result = json.loads(ad_dfs_add_target(
            namespace="ns", folder="docs", target=r"\\S\X",
        ))
        assert result["added"] is True
        script = ga.exec_powershell.call_args[0][0]
        assert "-Server localhost" in script

    def test_delete(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "", "")
        from winbox.mcp._ad_dfs import ad_dfs_delete
        result = json.loads(ad_dfs_delete(namespace="ns"))
        assert result["deleted"] is True
        script = ga.exec_powershell.call_args[0][0]
        assert "Remove-ADObject" in script

    def test_list(self, mock_mcp):
        ga, vm, cfg = mock_mcp
        ga.exec_powershell.return_value = ExecResult(0, "[]", "")
        from winbox.mcp._ad_dfs import ad_dfs_list
        result = ad_dfs_list()
        assert "[]" in result
