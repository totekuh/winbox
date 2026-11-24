"""Integration tests for Active Directory provisioning.

Real VM operations throughout — no mocking. Promotes to DC, exercises
all AD object CRUD, DFS namespaces, GPOs, then demotes. Requires a
running Windows Server VM (server2022 or server2025).

Run with: pytest -m integration tests/test_ad_integration.py
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from winbox.cli import cli
from winbox.config import Config
from winbox.vm import VM, GuestAgent, VMState


pytestmark = pytest.mark.integration

_runner = CliRunner()


def _run(*args: str, expect_ok: bool = True):
    result = _runner.invoke(cli, list(args))
    if expect_ok:
        assert result.exit_code == 0, (
            f"winbox {' '.join(args)} exited {result.exit_code}\n"
            f"{result.output}\n{result.exception!r}"
        )
    return result


def _tool(name: str):
    import winbox.mcp as mcp_mod
    obj = mcp_mod.__dict__[name]
    return obj.fn if hasattr(obj, "fn") else obj


# ─── fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def cfg(bootstrapped_vm):
    return Config.load()


@pytest.fixture(scope="module")
def vm(cfg):
    return VM(cfg)


@pytest.fixture(scope="module")
def ga(cfg):
    return GuestAgent(cfg)


@pytest.fixture(scope="module", autouse=True)
def _require_running(vm):
    if vm.state() != VMState.RUNNING:
        pytest.skip("VM not running")


@pytest.fixture(scope="module", autouse=True)
def _require_server(cfg):
    if cfg.profile.client_sku:
        pytest.skip("AD DS requires Windows Server")


@pytest.fixture(scope="module")
def promoted_dc(cfg, ga):
    """Promote to DC for the module, demote on teardown."""
    status = ga.exec_powershell(
        "(Get-WindowsFeature AD-Domain-Services).Installed",
        timeout=30,
    )
    already_dc = False
    if status.exitcode == 0 and "True" in status.stdout:
        check = ga.exec_powershell(
            "try { (Get-ADDomainController -Server localhost).HostName } "
            "catch { 'not-dc' }",
            timeout=30,
        )
        if check.exitcode == 0 and "not-dc" not in check.stdout:
            already_dc = True

    if not already_dc:
        result = _tool("ad_promote")(
            domain="TESTLAB.LOCAL", password="SafeMode123!",
            timeout=600,
        )
        data = json.loads(result)
        assert data["promoted"] is True

    yield

    result = _tool("ad_demote")(
        password="WinboxP@ss123", timeout=600,
    )
    data = json.loads(result)
    assert data["demoted"] is True


# ─── DC lifecycle ─────────────────────────────────────────────────────────


class TestDCLifecycle:
    def test_promote_and_status(self, promoted_dc):
        result = _tool("ad_status")(timeout=60)
        info = json.loads(result.split("\n")[0])
        assert info["is_dc"] is True
        assert info["domain"] == "TESTLAB.LOCAL"
        assert info["netbios"] == "TESTLAB"
        assert info["services"]["NTDS"] == "Running"
        assert info["services"]["DNS"] == "Running"
        assert info["services"]["Kdc"] == "Running"

    def test_cli_status(self, promoted_dc):
        result = _run("ad", "status")
        assert "TESTLAB.LOCAL" in result.output
        assert "Domain Controller" in result.output


# ─── AD user CRUD ─────────────────────────────────────────────────────────


class TestADUserCRUD:
    def test_mcp_user_lifecycle(self, promoted_dc):
        result = _tool("ad_user_create")(
            sam="e2euser", password="E2e-Pass1!",
        )
        assert json.loads(result)["created"] is True
        try:
            listing = _tool("ad_user_list")()
            assert "e2euser" in listing
        finally:
            result = _tool("ad_user_delete")(sam="e2euser")
            assert json.loads(result)["deleted"] is True

    def test_mcp_user_with_ou(self, promoted_dc):
        _tool("ad_ou_create")(name="E2EUsers")
        try:
            result = _tool("ad_user_create")(
                sam="ouuser", password="Ou-Pass1!",
                ou="OU=E2EUsers,DC=TESTLAB,DC=LOCAL",
            )
            assert json.loads(result)["created"] is True
            listing = _tool("ad_user_list")(
                ou="OU=E2EUsers,DC=TESTLAB,DC=LOCAL",
            )
            assert "ouuser" in listing
            _tool("ad_user_delete")(sam="ouuser")
        finally:
            _tool("ad_ou_delete")(dn="OU=E2EUsers,DC=TESTLAB,DC=LOCAL")

    def test_cli_user_lifecycle(self, promoted_dc):
        _run("ad", "user", "create", "cliuser", "--password", "Cli-Pass1!")
        try:
            result = _run("ad", "user", "list")
            assert "cliuser" in result.output
        finally:
            _run("ad", "user", "delete", "cliuser")


# ─── AD group CRUD ────────────────────────────────────────────────────────


class TestADGroupCRUD:
    def test_mcp_group_lifecycle(self, promoted_dc):
        result = _tool("ad_group_create")(name="E2EGroup")
        assert json.loads(result)["created"] is True
        try:
            listing = _tool("ad_group_list")()
            assert "E2EGroup" in listing
        finally:
            result = _tool("ad_group_delete")(name="E2EGroup")
            assert json.loads(result)["deleted"] is True

    def test_mcp_group_membership(self, promoted_dc):
        _tool("ad_user_create")(sam="memberuser", password="Mem-Pass1!")
        _tool("ad_group_create")(name="E2EMember")
        try:
            result = _tool("ad_group_add_member")(
                group="E2EMember", member="memberuser",
            )
            assert json.loads(result)["added"] is True

            result = _tool("ad_group_remove_member")(
                group="E2EMember", member="memberuser",
            )
            assert json.loads(result)["removed"] is True
        finally:
            _tool("ad_group_delete")(name="E2EMember")
            _tool("ad_user_delete")(sam="memberuser")

    def test_cli_group_lifecycle(self, promoted_dc):
        _run("ad", "group", "create", "CLIGroup")
        try:
            result = _run("ad", "group", "list")
            assert "CLIGroup" in result.output
        finally:
            _run("ad", "group", "delete", "CLIGroup")


# ─── AD OU CRUD ───────────────────────────────────────────────────────────


class TestADOuCRUD:
    def test_mcp_ou_lifecycle(self, promoted_dc):
        result = _tool("ad_ou_create")(name="E2EOrg")
        assert json.loads(result)["created"] is True
        try:
            listing = _tool("ad_ou_list")()
            assert "E2EOrg" in listing
        finally:
            result = _tool("ad_ou_delete")(
                dn="OU=E2EOrg,DC=TESTLAB,DC=LOCAL",
            )
            assert json.loads(result)["deleted"] is True

    def test_cli_ou_lifecycle(self, promoted_dc):
        _run("ad", "ou", "create", "CLIOrg")
        try:
            result = _run("ad", "ou", "list")
            assert "CLIOrg" in result.output
        finally:
            _run("ad", "ou", "delete", "OU=CLIOrg,DC=TESTLAB,DC=LOCAL")


# ─── AD computer ──────────────────────────────────────────────────────────


class TestADComputer:
    def test_mcp_computer_list(self, promoted_dc):
        listing = _tool("ad_computer_list")()
        assert "WINBOX" in listing

    def test_cli_computer_list(self, promoted_dc):
        result = _run("ad", "computer", "list")
        assert "WINBOX" in result.output


# ─── GPO CRUD ─────────────────────────────────────────────────────────────


class TestGPOCRUD:
    def test_mcp_gpo_lifecycle(self, promoted_dc):
        result = _tool("ad_gpo_create")(name="E2EPolicy")
        assert json.loads(result)["created"] is True
        try:
            listing = _tool("ad_gpo_list")()
            assert "E2EPolicy" in listing

            result = _tool("ad_gpo_edit")(
                name="E2EPolicy",
                key=r"HKLM\SOFTWARE\Policies\E2ETest",
                value_name="TestVal",
                reg_type="DWord",
                value="42",
            )
            assert json.loads(result)["updated"] is True

            result = _tool("ad_gpo_link")(
                name="E2EPolicy",
                target="DC=TESTLAB,DC=LOCAL",
            )
            assert json.loads(result)["linked"] is True
        finally:
            result = _tool("ad_gpo_remove")(name="E2EPolicy")
            assert json.loads(result)["removed"] is True

    def test_cli_gpo_lifecycle(self, promoted_dc):
        _run("ad", "gpo", "create", "CLIPolicy")
        try:
            result = _run("ad", "gpo", "list")
            assert "CLIPolicy" in result.output

            _run("ad", "gpo", "edit", "CLIPolicy",
                 "--key", r"HKLM\SOFTWARE\Policies\CLITest",
                 "--value-name", "Val", "--type", "String",
                 "--value", "hello")

            _run("ad", "gpo", "link", "CLIPolicy",
                 "--target", "DC=TESTLAB,DC=LOCAL")
        finally:
            _run("ad", "gpo", "remove", "CLIPolicy")


# ─── DFS namespace ────────────────────────────────────────────────────────


class TestDFSNamespace:
    def test_mcp_dfs_lifecycle(self, promoted_dc):
        _tool("share_create")(name="E2EDFS")
        try:
            result = _tool("ad_dfs_create")(
                namespace="e2e-dfs",
                target=r"\\WINBOX\E2EDFS",
                timeout=120,
            )
            assert json.loads(result)["created"] is True

            listing = _tool("ad_dfs_list")()
            assert "e2e-dfs" in listing

            result = _tool("ad_dfs_add_target")(
                namespace="e2e-dfs",
                folder="docs",
                target=r"\\WINBOX\E2EDFS",
            )
            assert json.loads(result)["added"] is True

            listing = _tool("ad_dfs_list")()
            assert "docs" in listing

            result = _tool("ad_dfs_delete")(namespace="e2e-dfs")
            assert json.loads(result)["deleted"] is True

            listing = _tool("ad_dfs_list")()
            assert "e2e-dfs" not in listing
        finally:
            _tool("share_delete")(name="E2EDFS", purge=True, confirm=True)

    def test_mcp_dfs_multi_target_v2_referral_tree(self, promoted_dc, ga):
        """Full multi-target DFS V2 namespace — exercises the complete
        referral tree that snaffler-ng's get_dfs_targets() walks."""
        shares = ["DfsFinance", "DfsEng", "DfsHR", "DfsIT"]
        for s in shares:
            _tool("share_create")(name=s)
        try:
            result = _tool("ad_dfs_create")(
                namespace="multi-dfs",
                target=r"\\WINBOX\DfsFinance",
                timeout=120,
            )
            assert json.loads(result)["created"] is True

            for folder, share in [("eng", "DfsEng"), ("hr", "DfsHR"), ("it", "DfsIT")]:
                result = _tool("ad_dfs_add_target")(
                    namespace="multi-dfs", folder=folder,
                    target=f"\\\\WINBOX\\{share}",
                )
                assert json.loads(result)["added"] is True

            listing = _tool("ad_dfs_list")()
            # ad_dfs_list returns _format_exec_result — extract JSON line
            for line in listing.splitlines():
                line = line.strip()
                if line.startswith("[") or line.startswith("{"):
                    parsed = json.loads(line)
                    break
            else:
                parsed = json.loads(listing)
            if isinstance(parsed, dict):
                parsed = [parsed]
            ns = [n for n in parsed if "multi-dfs" in n["path"]]
            assert len(ns) == 1
            assert len(ns[0]["folders"]) == 4

            _tool("ad_dfs_delete")(namespace="multi-dfs")
        finally:
            for s in shares:
                _tool("share_delete")(name=s, purge=True, confirm=True)

    def test_mcp_dfs_v2_msdfs_targetlistv2_attribute(self, promoted_dc, ga):
        """Verify msDFS-TargetListv2 is populated as UTF-16 XML with BOM —
        the exact data path that triggers the snaffler-ng DFS v2 bug."""
        _tool("share_create")(name="DfsV2Attr")
        try:
            _tool("ad_dfs_create")(
                namespace="v2attr-dfs",
                target=r"\\WINBOX\DfsV2Attr",
                timeout=120,
            )
            try:
                result = ga.exec_powershell(
                    "$base = 'CN=Dfs-Configuration,CN=System,"
                    "DC=TESTLAB,DC=LOCAL'\n"
                    "$objs = Get-ADObject -Server localhost "
                    "-SearchBase $base -Filter * -SearchScope Subtree "
                    "-Properties 'msDFS-TargetListv2' -EA Stop\n"
                    "$found = $objs | Where-Object { "
                    "$_.'msDFS-TargetListv2' -and "
                    "$_.DistinguishedName -match 'v2attr' }\n"
                    "foreach ($o in $found) {\n"
                    "  $bytes = [byte[]]$o.'msDFS-TargetListv2'\n"
                    "  $text = [Text.Encoding]::Unicode.GetString($bytes)\n"
                    "  Write-Output \"SIZE=$($bytes.Length)\"\n"
                    "  Write-Output \"HAS_BOM=$($bytes[0] -eq 0xFF "
                    "-and $bytes[1] -eq 0xFE)\"\n"
                    "  Write-Output \"HAS_XML=$($text -match "
                    "'<targets.*majorVersion')\"\n"
                    "  Write-Output \"HAS_TARGET=$($text -match "
                    "'WINBOX')\"\n"
                    "}",
                    timeout=30,
                )
                assert result.exitcode == 0
                out = result.stdout
                assert "HAS_BOM=True" in out
                assert "HAS_XML=True" in out
                assert "HAS_TARGET=True" in out
            finally:
                _tool("ad_dfs_delete")(namespace="v2attr-dfs")
        finally:
            _tool("share_delete")(name="DfsV2Attr", purge=True, confirm=True)

    def test_cli_dfs_lifecycle(self, promoted_dc):
        _run("share", "create", "CLIDFS")
        try:
            _run("ad", "dfs", "create", "cli-dfs",
                 "--target", r"\\WINBOX\CLIDFS")

            result = _run("ad", "dfs", "list")
            assert "cli-dfs" in result.output

            _run("ad", "dfs", "delete", "cli-dfs")
        finally:
            _run("share", "delete", "CLIDFS", "--purge")

    def test_cli_dfs_multi_target(self, promoted_dc):
        _run("share", "create", "CLIDfsA")
        _run("share", "create", "CLIDfsB")
        try:
            _run("ad", "dfs", "create", "cli-multi",
                 "--target", r"\\WINBOX\CLIDfsA")

            _run("ad", "dfs", "add-target", "cli-multi", "extra",
                 "--target", r"\\WINBOX\CLIDfsB")

            result = _run("ad", "dfs", "list")
            assert "cli-multi" in result.output
            assert "extra" in result.output

            _run("ad", "dfs", "delete", "cli-multi")
        finally:
            _run("share", "delete", "CLIDfsA", "--purge")
            _run("share", "delete", "CLIDfsB", "--purge")


# ─── negative cases ───────────────────────────────────────────────────────


class TestADNegative:
    def test_create_duplicate_user(self, promoted_dc):
        _tool("ad_user_create")(sam="dupuser", password="Dup-Pass1!")
        try:
            result = _tool("ad_user_create")(sam="dupuser", password="X-Pass1!")
            assert "already exists" in result.lower() or "exit code" in result.lower()
        finally:
            _tool("ad_user_delete")(sam="dupuser")

    def test_delete_nonexistent_user(self, promoted_dc):
        result = _tool("ad_user_delete")(sam="nosuchuser")
        assert "exit code" in result.lower() or "cannot find" in result.lower()

    def test_create_duplicate_group(self, promoted_dc):
        _tool("ad_group_create")(name="DupGroup")
        try:
            result = _tool("ad_group_create")(name="DupGroup")
            assert "already exists" in result.lower() or "exit code" in result.lower()
        finally:
            _tool("ad_group_delete")(name="DupGroup")

    def test_add_nonexistent_member(self, promoted_dc):
        _tool("ad_group_create")(name="EmptyGrp")
        try:
            result = _tool("ad_group_add_member")(
                group="EmptyGrp", member="ghost",
            )
            assert "exit code" in result.lower() or "cannot find" in result.lower()
        finally:
            _tool("ad_group_delete")(name="EmptyGrp")

    def test_delete_nonexistent_ou(self, promoted_dc):
        result = _tool("ad_ou_delete")(
            dn="OU=NoSuch,DC=TESTLAB,DC=LOCAL",
        )
        assert "exit code" in result.lower() or "cannot find" in result.lower()

    def test_link_nonexistent_gpo(self, promoted_dc):
        result = _tool("ad_gpo_link")(
            name="NoSuchGPO",
            target="DC=TESTLAB,DC=LOCAL",
        )
        assert "exit code" in result.lower() or "not found" in result.lower()

    def test_dfs_add_target_nonexistent_namespace(self, promoted_dc):
        result = _tool("ad_dfs_add_target")(
            namespace="ghost-ns", folder="x",
            target=r"\\WINBOX\NoShare",
        )
        assert "exit code" in result.lower() or "not found" in result.lower()

    def test_dfs_delete_nonexistent_namespace(self, promoted_dc):
        result = _tool("ad_dfs_delete")(namespace="ghost-ns")
        assert "exit code" in result.lower() or "not found" in result.lower()
