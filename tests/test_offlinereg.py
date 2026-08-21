"""Tests for winbox.offlinereg — host-side edits of a powered-off guest's hives.

This is the only mechanism that can change Defender state on a client SKU once
Defender has run, so its failure modes matter: a silent no-op would leave the
caller believing Defender is off when it isn't, and running guestfish against a
live disk risks corrupting it.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from winbox import offlinereg
from winbox.offlinereg import OfflineRegistryError


def _proc(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


class TestGuestfish:
    def test_prepends_run_and_joins_commands(self):
        with patch("winbox.offlinereg.subprocess.run", return_value=_proc()) as run:
            offlinereg.guestfish(Path("/d.qcow2"), ["mount /dev/sda3 /", "upload a b"])

        assert run.call_args.kwargs["input"] == "run\nmount /dev/sda3 /\nupload a b\n"
        assert run.call_args[0][0][:2] == ["guestfish", "--rw"]

    def test_uses_the_direct_backend(self):
        """The default libvirt backend wants to talk to a domain we have
        deliberately shut down."""
        with patch("winbox.offlinereg.subprocess.run", return_value=_proc()) as run:
            offlinereg.guestfish(Path("/d.qcow2"), ["mount /dev/sda3 /"])

        assert run.call_args.kwargs["env"]["LIBGUESTFS_BACKEND"] == "direct"

    def test_failure_carries_the_stderr(self):
        with patch(
            "winbox.offlinereg.subprocess.run",
            return_value=_proc(1, stderr="no such partition"),
        ):
            with pytest.raises(OfflineRegistryError, match="no such partition"):
                offlinereg.guestfish(Path("/d.qcow2"), ["mount /dev/sda9 /"])


class TestToolsAvailable:
    def test_none_when_both_present(self):
        with patch("winbox.offlinereg.shutil.which", return_value="/usr/bin/x"):
            assert offlinereg.tools_available() is None

    @pytest.mark.parametrize("missing", ["guestfish", "hivexregedit"])
    def test_names_the_missing_tool(self, missing):
        with patch(
            "winbox.offlinereg.shutil.which",
            side_effect=lambda n: None if n == missing else "/usr/bin/x",
        ):
            assert offlinereg.tools_available() == missing


def _simulate_download(script: str, *, contents: bytes = b"regf" + b"\0" * 508) -> None:
    """Write ``contents`` to the destination of any guestfish `download` line in
    ``script`` — the mocked guestfish otherwise never creates the local hive that
    merge_hive now validates before writing it back."""
    for line in script.splitlines():
        if line.startswith("download "):
            Path(line.split()[-1]).write_bytes(contents)


class TestMergeHive:
    def _run_merge(self, monkeypatch, *, merge_rc=0, download=b"regf" + b"\0" * 508,
                   post_merge_writes: bytes | None = None):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            if cmd[0] == "guestfish":
                _simulate_download(kw.get("input", ""), contents=download)
                return _proc()
            if cmd[0] == "hivexregedit":
                # hivexregedit merges the local hive in place; simulate it
                # optionally rewriting the file (e.g. to a corrupt one).
                if post_merge_writes is not None and merge_rc == 0:
                    Path(cmd[-2]).write_bytes(post_merge_writes)
                return _proc(merge_rc, stderr="merge blew up" if merge_rc else "")
            return _proc()

        monkeypatch.setattr(offlinereg.shutil, "which", lambda n: "/usr/bin/" + n)
        monkeypatch.setattr(offlinereg.subprocess, "run", fake_run)
        offlinereg.merge_hive(
            Path("/d.qcow2"),
            hive=offlinereg.SYSTEM_HIVE,
            prefix="HKEY_LOCAL_MACHINE\\SYSTEM",
            reg_body="Windows Registry Editor Version 5.00\r\n",
            win_part="/dev/sda3",
        )
        return calls

    def test_downloads_merges_and_uploads(self, monkeypatch):
        calls = self._run_merge(monkeypatch)

        guestfish_calls = [c for c in calls if c[0] == "guestfish"]
        assert len(guestfish_calls) == 2  # download, then upload
        assert any(c[0] == "hivexregedit" for c in calls)

    def test_clears_the_transaction_logs(self, monkeypatch):
        """Windows would otherwise replay stale log entries over the edit."""
        scripts = []

        def fake_run(cmd, **kw):
            if cmd[0] == "guestfish":
                scripts.append(kw["input"])
                _simulate_download(kw["input"])
            return _proc()

        monkeypatch.setattr(offlinereg.shutil, "which", lambda n: "/usr/bin/" + n)
        monkeypatch.setattr(offlinereg.subprocess, "run", fake_run)
        offlinereg.merge_hive(
            Path("/d.qcow2"), hive=offlinereg.SYSTEM_HIVE,
            prefix="HKEY_LOCAL_MACHINE\\SYSTEM", reg_body="x", win_part="/dev/sda3",
        )

        upload = scripts[-1]
        assert f"rm-f {offlinereg.SYSTEM_HIVE}.LOG1" in upload
        assert f"rm-f {offlinereg.SYSTEM_HIVE}.LOG2" in upload

    def test_uploads_via_staging_then_atomic_rename(self, monkeypatch):
        """The overwrite must be atomic: upload to a sidecar, drop logs, then
        rename over the live hive — so a killed upload never leaves a half-
        written hive with its logs already gone."""
        scripts = []

        def fake_run(cmd, **kw):
            if cmd[0] == "guestfish":
                scripts.append(kw["input"])
                _simulate_download(kw["input"])
            return _proc()

        monkeypatch.setattr(offlinereg.shutil, "which", lambda n: "/usr/bin/" + n)
        monkeypatch.setattr(offlinereg.subprocess, "run", fake_run)
        offlinereg.merge_hive(
            Path("/d.qcow2"), hive=offlinereg.SYSTEM_HIVE,
            prefix="HKEY_LOCAL_MACHINE\\SYSTEM", reg_body="x", win_part="/dev/sda3",
        )

        upload = scripts[-1]
        staging = f"{offlinereg.SYSTEM_HIVE}.winbox-new"
        assert f"upload " in upload and staging in upload
        assert f"mv {staging} {offlinereg.SYSTEM_HIVE}" in upload
        # The upload targets the staging path, not the live hive directly.
        assert f"upload " in upload
        up_line = next(ln for ln in upload.splitlines() if ln.startswith("upload "))
        assert up_line.endswith(staging)

    def test_a_failed_merge_raises_rather_than_uploading(self, monkeypatch):
        """Uploading an unmerged hive would silently do nothing at all."""
        with pytest.raises(OfflineRegistryError, match="merge blew up"):
            self._run_merge(monkeypatch, merge_rc=1)

    def test_corrupt_downloaded_hive_refuses_to_proceed(self, monkeypatch):
        """A download that isn't a real hive (regf magic) must abort before any
        merge/upload — never write garbage back over the guest's live hive."""
        with pytest.raises(OfflineRegistryError, match="not a valid registry hive"):
            self._run_merge(monkeypatch, download=b"<html>error</html>")

    def test_merge_that_corrupts_the_hive_refuses_to_upload(self, monkeypatch):
        """hivexregedit can exit 0 yet leave a truncated hive; that must not be
        uploaded over the live one."""
        with pytest.raises(OfflineRegistryError, match="not a valid registry hive"):
            self._run_merge(monkeypatch, post_merge_writes=b"\x00\x00\x00\x00garbage")

    def test_missing_tools_raise_before_touching_the_disk(self, monkeypatch):
        monkeypatch.setattr(offlinereg.shutil, "which", lambda n: None)
        with patch("winbox.offlinereg.subprocess.run") as run:
            with pytest.raises(OfflineRegistryError, match="libguestfs-tools"):
                offlinereg.merge_hive(
                    Path("/d.qcow2"), hive=offlinereg.SYSTEM_HIVE,
                    prefix="HKEY_LOCAL_MACHINE\\SYSTEM", reg_body="x",
                    win_part="/dev/sda3",
                )
        run.assert_not_called()


class TestMergeHiveHasNoStateCheck(TestMergeHive):
    def test_runs_even_though_nothing_indicates_the_vm_is_off(self, monkeypatch):
        """merge_hive only ever receives a disk path, never a domain to
        query, so it cannot refuse on VM state — it always runs guestfish.
        Enforcement lives with the caller (see cli/av.py's
        _power_off_or_refuse), not here."""
        calls = self._run_merge(monkeypatch)
        assert any(c[0] == "guestfish" for c in calls)

    def test_module_docstring_does_not_promise_a_refusal(self):
        """The module previously documented a guarantee merge_hive() never
        implemented; guard against that claim coming back without the code
        to back it."""
        assert "refuses if it can tell the domain is up" not in offlinereg.__doc__


class TestWindowsPartition:
    @pytest.mark.parametrize(
        "os_key,expected",
        [
            ("server2022", "/dev/sda2"),
            ("server2025", "/dev/sda3"),
            ("win11", "/dev/sda3"),
        ],
    )
    def test_follows_the_profile_layout(self, os_key, expected):
        from winbox.config import Config

        cfg = Config()
        cfg.vm_os = os_key
        assert offlinereg.windows_partition(cfg) == expected


class TestRegistryPayloads:
    def test_disable_sets_every_defender_service_to_disabled(self):
        from winbox.defender import DEFENDER_OFF_SYSTEM_REG

        for svc in ("WinDefend", "WdFilter", "WdNisSvc", "WdNisDrv"):
            assert svc in DEFENDER_OFF_SYSTEM_REG
        assert DEFENDER_OFF_SYSTEM_REG.count('"Start"=dword:00000004') == 4

    def test_enable_restores_the_shipped_start_types(self):
        from winbox.defender import DEFENDER_ON_SYSTEM_REG

        # WdFilter is boot-start (0), WinDefend automatic (2), NIS pair demand (3).
        assert '"Start"=dword:00000000' in DEFENDER_ON_SYSTEM_REG
        assert '"Start"=dword:00000002' in DEFENDER_ON_SYSTEM_REG
        assert DEFENDER_ON_SYSTEM_REG.count('"Start"=dword:00000003') == 2

    def test_tamper_payload_targets_software_not_system(self):
        from winbox.defender import TAMPER_OFF_SOFTWARE_REG

        assert "SOFTWARE\\Microsoft\\Windows Defender\\Features" in TAMPER_OFF_SOFTWARE_REG
        assert '"TamperProtection"=dword:00000004' in TAMPER_OFF_SOFTWARE_REG
        assert "SYSTEM\\ControlSet" not in TAMPER_OFF_SOFTWARE_REG

    @pytest.mark.parametrize(
        "payload",
        ["DEFENDER_OFF_SYSTEM_REG", "DEFENDER_ON_SYSTEM_REG", "TAMPER_OFF_SOFTWARE_REG"],
    )
    def test_payloads_are_valid_reg_documents(self, payload):
        import winbox.defender as d

        body = getattr(d, payload)
        assert body.startswith("Windows Registry Editor Version 5.00")
        assert "\r\n" in body  # regedit requires CRLF

    def test_disable_payload_unchanged_from_the_proven_build_time_bytes(self):
        """The build path is proven with exactly these bytes."""
        from winbox.defender import DEFENDER_OFF_SYSTEM_REG
        from winbox.setup.installer import _DEFENDER_OFF_SYSTEM_REG

        assert DEFENDER_OFF_SYSTEM_REG == _DEFENDER_OFF_SYSTEM_REG

    def test_control_set_parameter_changes_target(self):
        from winbox.defender import _system_services_reg
        reg = _system_services_reg({"WinDefend": 4}, control_set=2)
        assert "ControlSet002" in reg
        assert "ControlSet001" not in reg

    def test_control_set_default_is_001(self):
        from winbox.defender import _system_services_reg
        reg = _system_services_reg({"WinDefend": 4})
        assert "ControlSet001" in reg

    def test_control_set_3_digit_padding(self):
        from winbox.defender import _system_services_reg
        reg = _system_services_reg({"WinDefend": 4}, control_set=10)
        assert "ControlSet010" in reg


class TestReadCurrentControlSet:
    def test_parses_select_current_from_export(self):
        export_output = (
            'Windows Registry Editor Version 5.00\r\n\r\n'
            '[HKEY_LOCAL_MACHINE\\SYSTEM\\Select]\r\n'
            '"Current"=dword:00000001\r\n'
            '"Default"=dword:00000001\r\n'
        )
        with patch("winbox.offlinereg.tools_available", return_value=None), \
             patch("winbox.offlinereg.guestfish"), \
             patch("winbox.offlinereg.subprocess.run",
                   return_value=_proc(stdout=export_output)):
            cs = offlinereg.read_current_control_set(Path("/d.qcow2"), "/dev/sda3")
        assert cs == 1

    def test_returns_2_when_select_says_2(self):
        export_output = (
            '[HKEY_LOCAL_MACHINE\\SYSTEM\\Select]\r\n'
            '"Current"=dword:00000002\r\n'
        )
        with patch("winbox.offlinereg.tools_available", return_value=None), \
             patch("winbox.offlinereg.guestfish"), \
             patch("winbox.offlinereg.subprocess.run",
                   return_value=_proc(stdout=export_output)):
            cs = offlinereg.read_current_control_set(Path("/d.qcow2"), "/dev/sda3")
        assert cs == 2

    def test_raises_when_current_not_found(self):
        with patch("winbox.offlinereg.tools_available", return_value=None), \
             patch("winbox.offlinereg.guestfish"), \
             patch("winbox.offlinereg.subprocess.run",
                   return_value=_proc(stdout="[Select]\r\n")):
            with pytest.raises(OfflineRegistryError, match="Current not found"):
                offlinereg.read_current_control_set(Path("/d.qcow2"), "/dev/sda3")

    def test_raises_on_export_failure(self):
        with patch("winbox.offlinereg.tools_available", return_value=None), \
             patch("winbox.offlinereg.guestfish"), \
             patch("winbox.offlinereg.subprocess.run",
                   return_value=_proc(returncode=1, stderr="bad hive")):
            with pytest.raises(OfflineRegistryError, match="export Select failed"):
                offlinereg.read_current_control_set(Path("/d.qcow2"), "/dev/sda3")
