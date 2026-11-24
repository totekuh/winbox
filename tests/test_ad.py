"""Tests for winbox.cli.ad — Active Directory provisioning commands."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from winbox.cli import cli
from winbox.vm.guest import ExecResult


# ─── server gate ──────────────────────────────────────────────────────────────


class TestServerGate:
    """AD commands must refuse to run on client SKUs (win10/win11)."""

    def test_promote_rejected_on_client(self, runner, mock_env, cfg):
        saved = cfg.vm_os
        cfg.vm_os = "win11"
        try:
            result = runner.invoke(
                cli, ["ad", "promote", "--domain", "TEST.LOCAL",
                      "--password", "P@ss"],
            )
            assert result.exit_code != 0
            assert "Windows Server" in result.output
        finally:
            cfg.vm_os = saved

    def test_status_rejected_on_client(self, runner, mock_env, cfg):
        saved = cfg.vm_os
        cfg.vm_os = "win11"
        try:
            result = runner.invoke(cli, ["ad", "status"])
            assert result.exit_code != 0
        finally:
            cfg.vm_os = saved


# ─── ad promote ───────────────────────────────────────────────────────────────


class TestAdPromote:
    def test_promote_success(self, runner, mock_env):
        mock_env.exec_powershell.side_effect = [
            ExecResult(0, "AD DS installed", ""),           # promote script
            ExecResult(0, "WIN-DC.TESTLAB.LOCAL", ""),      # wait_for_adws
            ExecResult(0, "SYSVOL\nready", ""),             # wait_for_dfsr
        ]
        with patch("winbox.cli.ad.reboot_and_wait"):
            result = runner.invoke(
                cli, ["ad", "promote", "--domain", "TESTLAB.LOCAL",
                      "--password", "SafeMode1!"],
            )
        assert result.exit_code == 0, result.output
        script = mock_env.exec_powershell.call_args_list[0][0][0]
        assert "Install-ADDSForest" in script or "Install-WindowsFeature" in script
        assert "TESTLAB.LOCAL" in script
        assert "TESTLAB" in script  # netbios

    def test_promote_install_fails(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            1, "", "Feature install failed"
        )
        result = runner.invoke(
            cli, ["ad", "promote", "--domain", "TESTLAB.LOCAL",
                  "--password", "P@ss"],
        )
        assert result.exit_code != 0
        assert "failed" in result.output.lower()

    def test_promote_invalid_domain(self, runner, mock_env):
        result = runner.invoke(
            cli, ["ad", "promote", "--domain", "nodots",
                  "--password", "P@ss"],
        )
        assert result.exit_code != 0

    def test_promote_netbios_derived_from_domain(self, runner, mock_env):
        mock_env.exec_powershell.side_effect = [
            ExecResult(0, "", ""),
            ExecResult(0, "DC", ""),
            ExecResult(0, "ready", ""),
        ]
        with patch("winbox.cli.ad.reboot_and_wait"):
            runner.invoke(
                cli, ["ad", "promote", "--domain", "my.corp.example.com",
                      "--password", "P@ss"],
            )
        script = mock_env.exec_powershell.call_args_list[0][0][0]
        assert "MY" in script

    def test_promote_password_base64_encoded(self, runner, mock_env):
        mock_env.exec_powershell.side_effect = [
            ExecResult(0, "", ""),
            ExecResult(0, "DC", ""),
            ExecResult(0, "ready", ""),
        ]
        with patch("winbox.cli.ad.reboot_and_wait"):
            runner.invoke(
                cli, ["ad", "promote", "--domain", "T.L",
                      "--password", "Secret!"],
            )
        script = mock_env.exec_powershell.call_args_list[0][0][0]
        assert "FromBase64String" in script

    def test_promote_adws_timeout_still_succeeds(self, runner, mock_env):
        mock_env.exec_powershell.side_effect = [
            ExecResult(0, "installed", ""),
        ]
        with patch("winbox.cli.ad.reboot_and_wait"), \
             patch("winbox.cli.ad.wait_for_adws", side_effect=RuntimeError("ADWS not responsive")), \
             patch("winbox.cli.ad.wait_for_dfsr", side_effect=RuntimeError("DFSR not ready")):
            result = runner.invoke(
                cli, ["ad", "promote", "--domain", "T.L",
                      "--password", "P@ss"],
            )
        assert result.exit_code == 0
        assert "ready" in result.output.lower()

    def test_promote_reboots(self, runner, mock_env):
        mock_env.exec_powershell.side_effect = [
            ExecResult(0, "done", ""),
            ExecResult(0, "WIN-DC", ""),
            ExecResult(0, "ready", ""),
        ]
        with patch("winbox.cli.ad.reboot_and_wait") as mock_reboot:
            runner.invoke(
                cli, ["ad", "promote", "--domain", "LAB.LOCAL",
                      "--password", "P@ss"],
            )
            mock_reboot.assert_called_once()
            _, kwargs = mock_reboot.call_args
            assert kwargs.get("wait_timeout", 0) >= 300


# ─── ad demote ────────────────────────────────────────────────────────────────


class TestAdDemote:
    def test_demote_success(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "demoted", "")
        with patch("winbox.cli.ad.reboot_and_wait"):
            result = runner.invoke(
                cli, ["ad", "demote", "--password", "LocalAdmin1!"],
            )
        assert result.exit_code == 0, result.output
        script = mock_env.exec_powershell.call_args[0][0]
        assert "Uninstall-ADDSDomainController" in script

    def test_demote_uses_credential(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        with patch("winbox.cli.ad.reboot_and_wait"):
            runner.invoke(
                cli, ["ad", "demote", "--password", "P@ss"],
            )
        script = mock_env.exec_powershell.call_args[0][0]
        assert "PSCredential" in script
        assert "-Credential" in script

    def test_demote_gets_domain_from_registry(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "", "")
        with patch("winbox.cli.ad.reboot_and_wait"):
            runner.invoke(
                cli, ["ad", "demote", "--password", "P@ss"],
            )
        script = mock_env.exec_powershell.call_args[0][0]
        assert "Tcpip\\Parameters" in script
        assert "Get-ADDomain" not in script

    def test_demote_failure(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            1, "", "demotion error"
        )
        result = runner.invoke(
            cli, ["ad", "demote", "--password", "P@ss"],
        )
        assert result.exit_code != 0

    def test_demote_reboots(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(0, "done", "")
        with patch("winbox.cli.ad.reboot_and_wait") as mock_reboot:
            runner.invoke(
                cli, ["ad", "demote", "--password", "P@ss"],
            )
            mock_reboot.assert_called_once()


# ─── ad status ────────────────────────────────────────────────────────────────


class TestAdStatus:
    def test_status_dc_active(self, runner, mock_env):
        import json
        info = {
            "is_dc": True,
            "feature_installed": True,
            "hostname": "WIN-DC.TESTLAB.LOCAL",
            "domain": "TESTLAB.LOCAL",
            "netbios": "TESTLAB",
            "forest": "TESTLAB.LOCAL",
            "site": "Default-First-Site-Name",
            "dfs_installed": True,
            "services": {"NTDS": "Running", "DNS": "Running", "Kdc": "Running"},
        }
        mock_env.exec_powershell.return_value = ExecResult(
            0, json.dumps(info), "",
        )
        result = runner.invoke(cli, ["ad", "status"])
        assert result.exit_code == 0, result.output
        assert "TESTLAB.LOCAL" in result.output
        assert "Domain Controller" in result.output

    def test_status_not_installed(self, runner, mock_env):
        import json
        info = {
            "is_dc": False,
            "feature_installed": False,
            "services": {"NTDS": "NotInstalled", "DNS": "NotInstalled", "Kdc": "NotInstalled"},
        }
        mock_env.exec_powershell.return_value = ExecResult(
            0, json.dumps(info), "",
        )
        result = runner.invoke(cli, ["ad", "status"])
        assert result.exit_code == 0
        assert "not installed" in result.output.lower()

    def test_status_feature_installed_not_promoted(self, runner, mock_env):
        import json
        info = {
            "is_dc": False,
            "feature_installed": True,
            "ad_error": "ADWS not running",
            "services": {"NTDS": "Stopped", "DNS": "NotInstalled", "Kdc": "NotInstalled"},
        }
        mock_env.exec_powershell.return_value = ExecResult(
            0, json.dumps(info), "",
        )
        result = runner.invoke(cli, ["ad", "status"])
        assert result.exit_code == 0
        assert "not promoted" in result.output.lower()

    def test_status_shows_services(self, runner, mock_env):
        import json
        info = {
            "is_dc": True,
            "feature_installed": True,
            "hostname": "DC",
            "domain": "T.L",
            "netbios": "T",
            "forest": "T.L",
            "site": "Default",
            "dfs_installed": False,
            "services": {"NTDS": "Running", "DNS": "Running", "Kdc": "Stopped"},
        }
        mock_env.exec_powershell.return_value = ExecResult(
            0, json.dumps(info), "",
        )
        result = runner.invoke(cli, ["ad", "status"])
        assert result.exit_code == 0
        assert "Kdc" in result.output
        assert "Stopped" in result.output

    def test_status_query_fails(self, runner, mock_env):
        mock_env.exec_powershell.return_value = ExecResult(
            1, "", "PowerShell error"
        )
        result = runner.invoke(cli, ["ad", "status"])
        assert result.exit_code != 0


# ─── wait_for_adws ────────────────────────────────────────────────────────────


class TestWaitForAdws:
    def test_success_first_try(self):
        from unittest.mock import MagicMock
        from winbox.ad import wait_for_adws
        ga = MagicMock()
        ga.exec_powershell.return_value = ExecResult(0, "DC.TEST.LOCAL", "")
        hostname = wait_for_adws(ga, retries=3, interval=0)
        assert hostname == "DC.TEST.LOCAL"
        assert ga.exec_powershell.call_count == 1

    def test_success_after_retries(self):
        from unittest.mock import MagicMock
        from winbox.ad import wait_for_adws
        ga = MagicMock()
        ga.exec_powershell.side_effect = [
            ExecResult(1, "", "SSPI failed"),
            ExecResult(1, "", "SSPI failed"),
            ExecResult(0, "DC.TEST.LOCAL", ""),
        ]
        hostname = wait_for_adws(ga, retries=3, interval=0)
        assert hostname == "DC.TEST.LOCAL"
        assert ga.exec_powershell.call_count == 3

    def test_all_retries_exhausted(self):
        from unittest.mock import MagicMock
        from winbox.ad import wait_for_adws
        ga = MagicMock()
        ga.exec_powershell.return_value = ExecResult(1, "", "ADWS down")
        with pytest.raises(RuntimeError, match="ADWS not responsive"):
            wait_for_adws(ga, retries=2, interval=0)
        assert ga.exec_powershell.call_count == 2

    def test_script_uses_server_localhost(self):
        from winbox.ad import _ADWS_VERIFY
        assert "-Server localhost" in _ADWS_VERIFY
        assert "Restart-Service ADWS" in _ADWS_VERIFY


# ─── validation ───────────────────────────────────────────────────────────────


class TestAdValidation:
    def test_domain_fqdn_valid(self):
        from winbox.validate import check_domain_fqdn
        assert check_domain_fqdn("TESTLAB.LOCAL") is None
        assert check_domain_fqdn("sub.domain.example.com") is None

    def test_domain_fqdn_invalid(self):
        from winbox.validate import check_domain_fqdn
        assert check_domain_fqdn("nodots") is not None
        assert check_domain_fqdn("") is not None
        assert check_domain_fqdn(".leading.dot") is not None

    def test_ou_dn_valid(self):
        from winbox.validate import check_ou_dn
        assert check_ou_dn("OU=Test,DC=LAB,DC=LOCAL") is None
        assert check_ou_dn("DC=LAB,DC=LOCAL") is None
        assert check_ou_dn("CN=Users,DC=LAB,DC=LOCAL") is None

    def test_ou_dn_invalid(self):
        from winbox.validate import check_ou_dn
        assert check_ou_dn("not-a-dn") is not None
        assert check_ou_dn("") is not None

    def test_gpo_name_valid(self):
        from winbox.validate import check_gpo_name
        assert check_gpo_name("Disable Defender") is None
        assert check_gpo_name("My-Policy_1") is None

    def test_gpo_name_invalid(self):
        from winbox.validate import check_gpo_name
        assert check_gpo_name("x" * 200) is not None

    def test_dfs_namespace_valid(self):
        from winbox.validate import check_dfs_namespace
        assert check_dfs_namespace("lab-dfs") is None

    def test_dfs_namespace_invalid(self):
        from winbox.validate import check_dfs_namespace
        assert check_dfs_namespace("bad name!") is not None

    def test_unc_path_valid(self):
        from winbox.validate import check_unc_path
        assert check_unc_path(r"\\SERVER\Share") is None
        assert check_unc_path(r"\\DC\Data\Sub") is None

    def test_unc_path_invalid(self):
        from winbox.validate import check_unc_path
        assert check_unc_path("not-unc") is not None
        assert check_unc_path(r"\single") is not None
