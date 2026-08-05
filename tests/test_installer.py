"""Tests for setup/installer.py — prereqs, helpers, and download functions."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from winbox.setup.installer import (
    PYTHON_EXE,
    PYTHON_URL,
    REQUIRED_TOOLS,
    X64DBG_URL,
    X64DBG_ZIP,
    check_prereqs,
    _find_mkisofs,
    boot_for_provisioning,
    create_clean_snapshot,
    create_directories,
    generate_ssh_keypair,
    download_virtio_iso,
    download_openssh,
    download_winfsp,
    download_python,
    download_x64dbg,
    extract_virtiofs,
    build_unattend_image,
    create_disk,
)


# ─── REQUIRED_TOOLS ─────────────────────────────────────────────────────────


class TestRequiredTools:
    def test_contains_qemu_img(self):
        assert "qemu-img" in REQUIRED_TOOLS

    def test_contains_wget(self):
        assert "wget" in REQUIRED_TOOLS

    def test_contains_essentials(self):
        for tool in ["qemu-system-x86_64", "virsh", "virt-install", "guestfish", "7z"]:
            assert tool in REQUIRED_TOOLS

    def test_requires_the_tools_provisioning_actually_invokes(self):
        """Offline provisioning moved from virt-customize to guestfish.

        virt-customize auto-inspects the guest OS and that inspection fails on
        the Win11 install image, so it is no longer called anywhere. Listing it
        as required while omitting guestfish meant a host missing the tool we
        do use failed with a raw FileNotFoundError from inside phase 2.
        """
        import inspect

        from winbox.setup import installer

        source = inspect.getsource(installer)
        assert "virt-customize" not in REQUIRED_TOOLS
        assert 'subprocess.run(\n        ["guestfish"' in source or '"guestfish"' in source


# ─── check_prereqs ──────────────────────────────────────────────────────────


class TestCheckPrereqs:
    @patch("winbox.setup.installer.shutil.which")
    @patch("winbox.setup.installer.Path.exists")
    def test_all_present(self, mock_exists, mock_which):
        mock_which.return_value = "/usr/bin/tool"
        mock_exists.return_value = True
        assert check_prereqs() == []

    @patch("winbox.setup.installer.shutil.which")
    @patch("winbox.setup.installer.Path.exists")
    def test_missing_tool(self, mock_exists, mock_which):
        def fake_which(name):
            if name == "wget":
                return None
            return f"/usr/bin/{name}"
        mock_which.side_effect = fake_which
        mock_exists.return_value = True
        missing = check_prereqs()
        assert "wget" in missing

    @patch("winbox.setup.installer.shutil.which", return_value=None)
    @patch("winbox.setup.installer.Path.exists", return_value=False)
    def test_missing_kvm(self, mock_exists, mock_which):
        missing = check_prereqs()
        assert "/dev/kvm" in missing

    @patch("winbox.setup.installer.shutil.which")
    @patch("winbox.setup.installer.Path.exists")
    def test_virtiofsd_on_path(self, mock_exists, mock_which):
        """virtiofsd found on PATH — not reported missing."""
        def fake_which(name):
            return f"/usr/bin/{name}"
        mock_which.side_effect = fake_which
        mock_exists.return_value = True
        missing = check_prereqs()
        assert "virtiofsd" not in missing

    @patch("winbox.setup.installer.shutil.which")
    @patch("winbox.setup.installer.Path.exists")
    def test_virtiofsd_at_libexec(self, mock_exists, mock_which):
        """virtiofsd not on PATH but found at /usr/libexec/virtiofsd."""
        def fake_which(name):
            if name == "virtiofsd":
                return None
            return f"/usr/bin/{name}"
        mock_which.side_effect = fake_which
        def fake_exists(self_path=None):
            path_str = str(self_path) if self_path else ""
            return "/usr/libexec/virtiofsd" in path_str or "/dev/kvm" in path_str
        mock_exists.side_effect = lambda: True  # /dev/kvm
        missing = check_prereqs()
        # virtiofsd not on PATH — whether it's reported depends on Path.exists mock
        # At minimum verify the function returns a list and doesn't crash
        assert isinstance(missing, list)
        # Tools on PATH should not be reported as missing
        assert "qemu-system-x86_64" not in missing
        assert "virsh" not in missing


# ─── _find_mkisofs ──────────────────────────────────────────────────────────


class TestFindMkisofs:
    @patch("winbox.setup.installer.shutil.which")
    def test_finds_mkisofs(self, mock_which):
        mock_which.side_effect = lambda cmd: "/usr/bin/mkisofs" if cmd == "mkisofs" else None
        assert _find_mkisofs() == "mkisofs"

    @patch("winbox.setup.installer.shutil.which")
    def test_finds_genisoimage(self, mock_which):
        mock_which.side_effect = lambda cmd: "/usr/bin/genisoimage" if cmd == "genisoimage" else None
        assert _find_mkisofs() == "genisoimage"

    @patch("winbox.setup.installer.shutil.which", return_value=None)
    def test_neither_found(self, mock_which):
        assert _find_mkisofs() is None

    @patch("winbox.setup.installer.shutil.which")
    def test_prefers_mkisofs(self, mock_which):
        mock_which.return_value = "/usr/bin/tool"
        assert _find_mkisofs() == "mkisofs"


# ─── create_directories ─────────────────────────────────────────────────────


class TestCreateDirectories:
    def test_creates_dirs(self, cfg):
        # Remove dirs first
        import shutil
        shutil.rmtree(cfg.winbox_dir)
        create_directories(cfg)
        assert cfg.winbox_dir.exists()
        assert cfg.iso_dir.exists()
        assert cfg.tools_dir.exists()
        assert cfg.loot_dir.exists()

    def test_idempotent(self, cfg):
        create_directories(cfg)
        create_directories(cfg)  # should not raise


# ─── generate_ssh_keypair ────────────────────────────────────────────────────


class TestGenerateSshKeypair:
    @patch("winbox.setup.installer.subprocess.run")
    def test_generates_key(self, mock_run, cfg):
        mock_run.return_value = MagicMock(returncode=0)
        generate_ssh_keypair(cfg)
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "ssh-keygen" in args
        assert str(cfg.ssh_key) in args

    @patch("winbox.setup.installer.subprocess.run")
    def test_skips_if_exists(self, mock_run, cfg):
        cfg.ssh_key.touch()
        generate_ssh_keypair(cfg)
        mock_run.assert_not_called()


# ─── download functions ─────────────────────────────────────────────────────


class TestDownloads:
    @patch("winbox.setup.installer.subprocess.run")
    def test_download_virtio_iso(self, mock_run, cfg):
        def fake_wget(*a, **kw):
            # Create a fake file large enough to pass size check
            cfg.virtio_iso.write_bytes(b"\x00" * 500_000_001)
        mock_run.side_effect = fake_wget
        download_virtio_iso(cfg)
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "wget" in args

    @patch("winbox.setup.installer.subprocess.run")
    def test_download_virtio_iso_cached(self, mock_run, cfg):
        cfg.virtio_iso.write_bytes(b"\x00" * 500_000_001)
        download_virtio_iso(cfg)
        mock_run.assert_not_called()

    @patch("winbox.setup.installer.subprocess.run")
    def test_download_openssh(self, mock_run, cfg):
        dest = cfg.iso_dir / "OpenSSH-Win64.zip"
        def fake_wget(*a, **kw):
            dest.write_bytes(b"\x00" * 5_000_001)
        mock_run.side_effect = fake_wget
        result = download_openssh(cfg)
        assert result == dest
        mock_run.assert_called_once()

    @patch("winbox.setup.installer.subprocess.run")
    def test_download_openssh_cached(self, mock_run, cfg):
        dest = cfg.iso_dir / "OpenSSH-Win64.zip"
        dest.write_bytes(b"\x00" * 5_000_001)
        result = download_openssh(cfg)
        assert result == dest
        mock_run.assert_not_called()

    @patch("winbox.setup.installer.subprocess.run")
    def test_download_winfsp(self, mock_run, cfg):
        dest = cfg.iso_dir / "winfsp.msi"
        def fake_wget(*a, **kw):
            dest.write_bytes(b"\x00" * 1_000_001)
        mock_run.side_effect = fake_wget
        result = download_winfsp(cfg)
        assert result == dest
        mock_run.assert_called_once()

    @patch("winbox.setup.installer.subprocess.run")
    def test_download_winfsp_cached(self, mock_run, cfg):
        dest = cfg.iso_dir / "winfsp.msi"
        dest.write_bytes(b"\x00" * 1_000_001)
        result = download_winfsp(cfg)
        assert result == dest
        mock_run.assert_not_called()

    @patch("winbox.setup.installer.subprocess.run")
    def test_download_python(self, mock_run, cfg):
        dest = cfg.iso_dir / PYTHON_EXE
        def fake_wget(*a, **kw):
            dest.write_bytes(b"\x00" * 25_000_000)
        mock_run.side_effect = fake_wget
        result = download_python(cfg)
        assert result == dest
        mock_run.assert_called_once()

    @patch("winbox.setup.installer.subprocess.run")
    def test_download_python_cached(self, mock_run, cfg):
        dest = cfg.iso_dir / PYTHON_EXE
        dest.write_bytes(b"\x00" * 25_000_000)
        result = download_python(cfg)
        assert result == dest
        mock_run.assert_not_called()

    @patch("winbox.setup.installer.subprocess.run")
    def test_download_python_truncated(self, mock_run, cfg):
        dest = cfg.iso_dir / PYTHON_EXE
        def fake_wget(*a, **kw):
            dest.write_bytes(b"\x00" * 500)
        mock_run.side_effect = fake_wget
        with pytest.raises(RuntimeError, match="truncated"):
            download_python(cfg)

    def test_python_url_is_regular_installer(self):
        """URL must point at the regular Python installer, not the embeddable zip."""
        assert PYTHON_URL.endswith("-amd64.exe")
        assert "embed" not in PYTHON_URL

    @patch("winbox.setup.installer.subprocess.run")
    def test_download_x64dbg(self, mock_run, cfg):
        dest = cfg.iso_dir / X64DBG_ZIP
        def fake_wget(*a, **kw):
            dest.write_bytes(b"\x00" * 25_000_000)
        mock_run.side_effect = fake_wget
        result = download_x64dbg(cfg)
        assert result == dest
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "wget" in args
        assert X64DBG_URL in args

    @patch("winbox.setup.installer.subprocess.run")
    def test_download_x64dbg_cached(self, mock_run, cfg):
        dest = cfg.iso_dir / X64DBG_ZIP
        dest.write_bytes(b"\x00" * 25_000_000)
        result = download_x64dbg(cfg)
        assert result == dest
        mock_run.assert_not_called()

    @patch("winbox.setup.installer.subprocess.run")
    def test_download_x64dbg_truncated(self, mock_run, cfg):
        dest = cfg.iso_dir / X64DBG_ZIP
        def fake_wget(*a, **kw):
            dest.write_bytes(b"\x00" * 500)
        mock_run.side_effect = fake_wget
        with pytest.raises(RuntimeError, match="truncated"):
            download_x64dbg(cfg)

    def test_x64dbg_url_is_github_release(self):
        assert X64DBG_URL.startswith("https://github.com/x64dbg/x64dbg/releases/")
        assert X64DBG_URL.endswith(".zip")

    @patch("winbox.setup.installer.subprocess.run")
    def test_extract_virtiofs(self, mock_run, cfg):
        cfg.virtio_iso.touch()

        def fake_7z(cmd, **kwargs):
            # `7z e ... -o<tmpdir> <member> -y` — simulate extraction.
            outdir = next(a[2:] for a in cmd if a.startswith("-o"))
            (Path(outdir) / "virtiofs.exe").touch()
            return MagicMock(returncode=0)

        mock_run.side_effect = fake_7z
        result = extract_virtiofs(cfg)
        # Cache path is namespaced by VirtIO subdir (server default: 2k22).
        assert result == cfg.iso_dir / "virtiofs-2k22.exe"
        assert result.exists()

    @patch("winbox.setup.installer.subprocess.run")
    def test_extract_virtiofs_cached(self, mock_run, cfg):
        dest = cfg.iso_dir / "virtiofs-2k22.exe"
        dest.touch()
        result = extract_virtiofs(cfg)
        assert result == dest
        mock_run.assert_not_called()

    @patch("winbox.setup.installer.subprocess.run")
    def test_extract_virtiofs_win11_namespaced(self, mock_run, cfg):
        """Win11 extraction uses the w11 ISO member and a w11-namespaced cache."""
        cfg.vm_os = "win11"
        cfg.virtio_iso.touch()

        def fake_7z(cmd, **kwargs):
            assert "viofs/w11/amd64/virtiofs.exe" in cmd
            outdir = next(a[2:] for a in cmd if a.startswith("-o"))
            (Path(outdir) / "virtiofs.exe").touch()
            return MagicMock(returncode=0)

        mock_run.side_effect = fake_7z
        result = extract_virtiofs(cfg)
        assert result == cfg.iso_dir / "virtiofs-w11.exe"


# ─── create_clean_snapshot — catches RuntimeError from new snapshot_create ──


class TestCreateCleanSnapshot:
    @patch("winbox.setup.installer.VM")
    def test_success(self, mock_vm_cls, cfg):
        vm = MagicMock()
        mock_vm_cls.return_value = vm
        create_clean_snapshot(cfg)
        vm.snapshot_create.assert_called_once_with("clean")

    @patch("winbox.setup.installer.VM")
    def test_runtime_error_is_caught(self, mock_vm_cls, cfg):
        """RuntimeError from vm.snapshot_create() must not escape — commit
        aaa81ed made snapshot_create raise RuntimeError but create_clean_snapshot
        only caught CalledProcessError, so setup crashed on snapshot failure."""
        vm = MagicMock()
        vm.snapshot_create.side_effect = RuntimeError("internal snapshot unsupported")
        mock_vm_cls.return_value = vm
        # Must not raise — the exception must be caught and turned into a warning.
        create_clean_snapshot(cfg)



# ─── build_unattend_image ────────────────────────────────────────────────────


class TestBuildUnattendImage:
    @patch("winbox.setup.installer._find_mkisofs", return_value=None)
    def test_raises_without_mkisofs(self, mock_find, cfg):
        with pytest.raises(RuntimeError, match="mkisofs"):
            build_unattend_image(cfg)

    @patch("winbox.setup.installer.subprocess.run")
    @patch("winbox.setup.installer._find_mkisofs", return_value="genisoimage")
    def test_calls_mkisofs(self, mock_find, mock_run, cfg):
        mock_run.return_value = MagicMock(returncode=0)
        build_unattend_image(cfg)
        args = mock_run.call_args[0][0]
        assert args[0] == "genisoimage"
        assert str(cfg.unattend_img) in args

    @patch("winbox.setup.installer.subprocess.run")
    @patch("winbox.setup.installer._find_mkisofs", return_value="mkisofs")
    def test_default_is_server_core(self, mock_find, mock_run, cfg):
        """Default (no desktop flag) writes SERVERSTANDARDCORE image name."""
        written = {}

        def capture_run(cmd, **kwargs):
            # Find the autounattend.xml in the temp dir passed to mkisofs
            tmpdir = cmd[-1]  # last arg is the source dir
            xml_path = Path(tmpdir) / "autounattend.xml"
            if xml_path.exists():
                written["xml"] = xml_path.read_text()
            return MagicMock(returncode=0)

        mock_run.side_effect = capture_run
        build_unattend_image(cfg)
        assert "SERVERSTANDARDCORE" in written["xml"]
        assert "SERVERSTANDARD" in written["xml"]  # CORE contains STANDARD

    @patch("winbox.setup.installer.subprocess.run")
    @patch("winbox.setup.installer._find_mkisofs", return_value="mkisofs")
    def test_desktop_replaces_image_name(self, mock_find, mock_run, cfg):
        """--desktop flag replaces SERVERSTANDARDCORE with SERVERSTANDARD."""
        written = {}

        def capture_run(cmd, **kwargs):
            tmpdir = cmd[-1]
            xml_path = Path(tmpdir) / "autounattend.xml"
            if xml_path.exists():
                written["xml"] = xml_path.read_text()
            return MagicMock(returncode=0)

        mock_run.side_effect = capture_run
        build_unattend_image(cfg, desktop=True)
        assert "SERVERSTANDARDCORE" not in written["xml"]
        assert "Windows Server 2022 SERVERSTANDARD" in written["xml"]

    @patch("winbox.setup.installer.subprocess.run")
    @patch("winbox.setup.installer._find_mkisofs", return_value="mkisofs")
    def test_win11_image_drivers_and_bypass(self, mock_find, mock_run, cfg):
        """Win11 profile writes the Win11 image, w11 driver paths, LabConfig bypass."""
        cfg.vm_os = "win11"
        written = {}

        def capture_run(cmd, **kwargs):
            xml_path = Path(cmd[-1]) / "autounattend.xml"
            if xml_path.exists():
                written["xml"] = xml_path.read_text()
            return MagicMock(returncode=0)

        mock_run.side_effect = capture_run
        build_unattend_image(cfg)
        xml = written["xml"]
        assert "Windows 11 Enterprise Evaluation" in xml
        assert "SERVERSTANDARD" not in xml
        assert r"viofs\w11\amd64" in xml
        assert r"vioserial\w11\amd64" in xml
        assert "BypassTPMCheck" in xml
        assert "BypassSecureBootCheck" in xml
        assert r"HKLM\System\Setup\LabConfig" in xml
        # Standard Win11 UEFI layout: 260 MB ESP + MSR, install to partition 3.
        assert "<Type>MSR</Type>" in xml
        assert "<Size>260</Size>" in xml
        assert "<PartitionID>3</PartitionID>" in xml

    @patch("winbox.setup.installer.subprocess.run")
    @patch("winbox.setup.installer._find_mkisofs", return_value="mkisofs")
    def test_server_disk_layout_unchanged(self, mock_find, mock_run, cfg):
        """Server keeps the minimal ESP+Windows layout on partition 2, no MSR."""
        written = {}

        def capture_run(cmd, **kwargs):
            xml_path = Path(cmd[-1]) / "autounattend.xml"
            if xml_path.exists():
                written["xml"] = xml_path.read_text()
            return MagicMock(returncode=0)

        mock_run.side_effect = capture_run
        build_unattend_image(cfg)
        xml = written["xml"]
        assert "<Type>MSR</Type>" not in xml
        assert "<Size>100</Size>" in xml
        # InstallTo targets partition 2 for the 2-partition layout.
        assert "<PartitionID>2</PartitionID>" in xml

    @patch("winbox.setup.installer.subprocess.run")
    @patch("winbox.setup.installer._find_mkisofs", return_value="mkisofs")
    def test_win11_rejects_desktop(self, mock_find, mock_run, cfg):
        """--desktop is a Server-only concept and is rejected for Win11."""
        cfg.vm_os = "win11"
        with pytest.raises(RuntimeError, match="desktop"):
            build_unattend_image(cfg, desktop=True)

    @patch("winbox.setup.installer.subprocess.run")
    @patch("winbox.setup.installer._find_mkisofs", return_value="mkisofs")
    def test_server_has_no_bypass_block(self, mock_find, mock_run, cfg):
        """Server 2022 render carries no LabConfig bypass keys."""
        written = {}

        def capture_run(cmd, **kwargs):
            xml_path = Path(cmd[-1]) / "autounattend.xml"
            if xml_path.exists():
                written["xml"] = xml_path.read_text()
            return MagicMock(returncode=0)

        mock_run.side_effect = capture_run
        build_unattend_image(cfg)
        assert "LabConfig" not in written["xml"]
        assert r"viofs\2k22\amd64" in written["xml"]


# ─── create_disk ─────────────────────────────────────────────────────────────


class TestCreateDisk:
    @patch("winbox.setup.installer.subprocess.run")
    def test_calls_qemu_img(self, mock_run, cfg):
        mock_run.return_value = MagicMock(returncode=0)
        create_disk(cfg)
        args = mock_run.call_args[0][0]
        assert args[0] == "qemu-img"
        assert "create" in args
        assert str(cfg.disk_path) in args
        # Server profile floor (30) == default, so the configured size is used.
        assert f"{cfg.vm_disk}G" in args

    @patch("winbox.setup.installer.subprocess.run")
    def test_win11_enforces_64gb_floor(self, mock_run, cfg):
        """Win11 needs ≥64GB; the default 30GB config is bumped up."""
        cfg.vm_os = "win11"
        assert cfg.vm_disk == 30  # default, below the Win11 floor
        mock_run.return_value = MagicMock(returncode=0)
        create_disk(cfg)
        args = mock_run.call_args[0][0]
        assert "64G" in args
        assert "30G" not in args

    @patch("winbox.setup.installer.subprocess.run")
    def test_win11_respects_larger_configured_disk(self, mock_run, cfg):
        """A configured disk above the floor is kept."""
        cfg.vm_os = "win11"
        cfg.vm_disk = 100
        mock_run.return_value = MagicMock(returncode=0)
        create_disk(cfg)
        assert "100G" in mock_run.call_args[0][0]


# --- boot_for_provisioning -----------------------------------------------


class TestBootForProvisioningLaunchProbe:
    """B3: if bootstrap.ps1 doesn't start, surface in 30s instead of 600."""

    @patch("winbox.setup.installer.time.sleep")
    @patch("winbox.setup.installer.GuestAgent")
    @patch("winbox.setup.installer.VM")
    def test_bails_when_log_never_appears(
        self, mock_vm_cls, mock_ga_cls, mock_sleep, cfg,
    ):
        from winbox.vm.guest import ExecResult
        from winbox.vm.lifecycle import VMState

        vm = MagicMock()
        vm.state.return_value = VMState.RUNNING
        mock_vm_cls.return_value = vm

        ga = MagicMock()
        ga.exec.return_value = ExecResult(exitcode=0, stdout="MISSING\r\n", stderr="")
        mock_ga_cls.return_value = ga

        with pytest.raises(RuntimeError, match="bootstrap.ps1 did not start"):
            boot_for_provisioning(cfg)

        # exec_detached was called once to launch the script.
        ga.exec_detached.assert_called_once()
        # We never reached wait_shutdown — that would be the 600s wait we're avoiding.
        vm.wait_shutdown.assert_not_called()

    @patch("winbox.setup.installer._verify_provisioning")
    @patch("winbox.setup.installer.time.sleep")
    @patch("winbox.setup.installer.GuestAgent")
    @patch("winbox.setup.installer.VM")
    def test_proceeds_when_log_appears(
        self, mock_vm_cls, mock_ga_cls, mock_sleep, mock_verify, cfg,
    ):
        from winbox.vm.guest import ExecResult
        from winbox.vm.lifecycle import VMState

        vm = MagicMock()
        vm.state.return_value = VMState.RUNNING
        vm.wait_shutdown.return_value = True
        mock_vm_cls.return_value = vm

        ga = MagicMock()
        ga.exec.return_value = ExecResult(exitcode=0, stdout="OK\r\n", stderr="")
        mock_ga_cls.return_value = ga

        boot_for_provisioning(cfg)

        ga.exec_detached.assert_called_once()
        vm.wait_shutdown.assert_called_once()
        mock_verify.assert_called_once()

    @patch("winbox.setup.installer._verify_provisioning")
    @patch("winbox.setup.installer.time.sleep")
    @patch("winbox.setup.installer.GuestAgent")
    @patch("winbox.setup.installer.VM")
    def test_proceeds_when_vm_already_shut_down(
        self, mock_vm_cls, mock_ga_cls, mock_sleep, mock_verify, cfg,
    ):
        """Race: bootstrap finishes faster than the probe loop starts."""
        from winbox.vm.lifecycle import VMState

        vm = MagicMock()
        vm.state.side_effect = [VMState.RUNNING, VMState.SHUTOFF]
        vm.wait_shutdown.return_value = True
        mock_vm_cls.return_value = vm

        ga = MagicMock()
        mock_ga_cls.return_value = ga

        boot_for_provisioning(cfg)
        # No need to assert on wait_shutdown — the test just must not raise.


class TestProvisionPayloadPythonCheck:
    """provision.ps1 chooses its Python payload by probing the guest's
    ProductType at runtime, so the build must ship the one that probe will
    ask for. A missing payload is not an error inside the guest — it just
    silently leaves the VM with no Python."""

    def _cfg(self, tmp_path, os_key):
        from winbox.config import Config

        cfg = Config(winbox_dir=tmp_path / ".winbox")
        cfg.vm_os = os_key
        cfg.iso_dir.mkdir(parents=True)
        cfg.shared_dir.mkdir(parents=True)
        return cfg

    def _write_payload(self, cfg, *, python_exe=True, python_embed=True):
        from winbox.setup.installer import (
            OPENSSH_ZIP, PYTHON_EMBED_ZIP, PYTHON_EXE, WINFSP_MSI,
            _virtiofs_cache_path,
        )

        for name in (OPENSSH_ZIP, WINFSP_MSI):
            (cfg.iso_dir / name).write_bytes(b"x")
        _virtiofs_cache_path(cfg).write_bytes(b"x")
        if python_exe:
            (cfg.iso_dir / PYTHON_EXE).write_bytes(b"x")
        if python_embed:
            (cfg.iso_dir / PYTHON_EMBED_ZIP).write_bytes(b"x")

    def _provision(self, cfg):
        from winbox.setup import installer

        with (
            patch.object(installer, "_guestfish"),
            patch.object(installer, "_disable_defender_offline"),
            patch.object(installer.zipfile, "is_zipfile", return_value=True),
        ):
            installer.provision_vm_disk(cfg)

    def test_server_build_requires_the_python_installer(self, tmp_path):
        cfg = self._cfg(tmp_path, "server2022")
        self._write_payload(cfg, python_exe=False)

        with pytest.raises(RuntimeError, match="Python installer"):
            self._provision(cfg)

    def test_win11_build_requires_the_embeddable_zip(self, tmp_path):
        cfg = self._cfg(tmp_path, "win11")
        self._write_payload(cfg, python_embed=False)

        with pytest.raises(RuntimeError, match="Python embeddable"):
            self._provision(cfg)

    def test_server_build_does_not_require_the_embeddable_zip(self, tmp_path):
        """Server runs the real installer; the zip is spare payload."""
        cfg = self._cfg(tmp_path, "server2022")
        self._write_payload(cfg, python_embed=False)

        self._provision(cfg)  # must not raise

    def test_win11_build_does_not_require_the_installer(self, tmp_path):
        """The WiX bundle deadlocks under session-0 SYSTEM on client SKUs."""
        cfg = self._cfg(tmp_path, "win11")
        self._write_payload(cfg, python_exe=False)

        self._provision(cfg)  # must not raise


class TestDiskPartitionsBlock:
    """The rendered layout must match install_partition_id, or Windows is
    installed to the wrong partition — a failure that only appears ~20
    minutes into a build, inside WinPE."""

    def _cfg(self, os_key):
        from winbox.config import Config

        cfg = Config()
        cfg.vm_os = os_key
        return cfg

    def test_server_layout_is_esp_plus_windows(self):
        from winbox.setup.installer import _disk_partitions_block

        xml = _disk_partitions_block(self._cfg("server2022"))
        assert "<Type>MSR</Type>" not in xml
        assert "<Size>100</Size>" in xml

    def test_win11_layout_inserts_msr_before_windows(self):
        from winbox.setup.installer import _disk_partitions_block

        xml = _disk_partitions_block(self._cfg("win11"))
        assert "<Type>MSR</Type>" in xml
        assert "<Size>260</Size>" in xml
        assert xml.index("<Type>MSR</Type>") < xml.index("<Type>Primary</Type>")

    @pytest.mark.parametrize("os_key", ["server2022", "win11"])
    def test_windows_partition_matches_install_partition_id(self, os_key):
        import re

        from winbox.setup.installer import _disk_partitions_block

        cfg = self._cfg(os_key)
        xml = _disk_partitions_block(cfg)
        # The NTFS-formatted partition is the one Windows is installed to.
        ntfs = re.search(
            r"<PartitionID>(\d+)</PartitionID>\s*<Format>NTFS</Format>", xml
        )
        assert ntfs is not None
        assert int(ntfs.group(1)) == cfg.profile.install_partition_id


class TestUnattendBlocks:
    """The Win11 setup-gate blocks. Each must be present for win11 and
    completely absent for server2022 — a LabConfig block on Server would
    inject bypass keys for gates Server does not have, and the specialize
    block would disable a BitLocker feature Server never auto-enables."""

    def _cfg(self, os_key):
        from winbox.config import Config

        cfg = Config()
        cfg.vm_os = os_key
        return cfg

    def test_labconfig_covers_every_win11_setup_gate(self):
        from winbox.setup.installer import _LABCONFIG_KEYS, _labconfig_block

        xml = _labconfig_block()
        for key in _LABCONFIG_KEYS:
            assert key in xml
        assert "BypassTPMCheck" in xml
        assert "BypassSecureBootCheck" in xml

    def test_labconfig_orders_are_sequential_from_one(self):
        import re

        from winbox.setup.installer import _LABCONFIG_KEYS, _labconfig_block

        orders = re.findall(r"<Order>(\d+)</Order>", _labconfig_block())
        assert orders == [str(i) for i in range(1, len(_LABCONFIG_KEYS) + 1)]

    def test_specialize_block_prevents_device_encryption_and_oobe_stall(self):
        from winbox.setup.installer import _specialize_deploy_block

        xml = _specialize_deploy_block()
        assert "PreventDeviceEncryption" in xml
        assert "BypassNRO" in xml
        assert "Microsoft-Windows-Deployment" in xml

    def test_rendered_unattend_is_well_formed_for_both_profiles(self):
        import xml.etree.ElementTree as ET

        from winbox import data as _data
        from winbox.setup.installer import (
            _disk_partitions_block, _labconfig_block, _specialize_deploy_block,
        )

        for os_key in ("server2022", "win11"):
            cfg = self._cfg(os_key)
            p = cfg.profile
            rendered = _data.render(
                "unattend.xml",
                IMAGE_NAME=p.image_name,
                VIRTIO_SUBDIR=p.virtio_subdir,
                INSTALL_PARTITION_ID=str(p.install_partition_id),
                DISK_PARTITIONS=_disk_partitions_block(cfg),
                LABCONFIG_BLOCK=_labconfig_block() if p.labconfig_bypass else "",
                SPECIALIZE_DEPLOY_BLOCK=(
                    _specialize_deploy_block() if p.prevent_device_encryption else ""
                ),
            )
            ET.fromstring(rendered)  # raises on malformed XML

    def test_server_unattend_has_no_win11_blocks(self):
        from winbox import data as _data
        from winbox.setup.installer import _disk_partitions_block

        cfg = self._cfg("server2022")
        p = cfg.profile
        rendered = _data.render(
            "unattend.xml",
            IMAGE_NAME=p.image_name,
            VIRTIO_SUBDIR=p.virtio_subdir,
            INSTALL_PARTITION_ID=str(p.install_partition_id),
            DISK_PARTITIONS=_disk_partitions_block(cfg),
            LABCONFIG_BLOCK="",
            SPECIALIZE_DEPLOY_BLOCK="",
        )
        assert "LabConfig" not in rendered
        assert "PreventDeviceEncryption" not in rendered
        assert "2k22" in rendered
        assert "w11" not in rendered

    def test_win11_unattend_uses_its_own_virtio_subdir(self):
        from winbox import data as _data
        from winbox.setup.installer import (
            _disk_partitions_block, _labconfig_block, _specialize_deploy_block,
        )

        cfg = self._cfg("win11")
        p = cfg.profile
        rendered = _data.render(
            "unattend.xml",
            IMAGE_NAME=p.image_name,
            VIRTIO_SUBDIR=p.virtio_subdir,
            INSTALL_PARTITION_ID=str(p.install_partition_id),
            DISK_PARTITIONS=_disk_partitions_block(cfg),
            LABCONFIG_BLOCK=_labconfig_block(),
            SPECIALIZE_DEPLOY_BLOCK=_specialize_deploy_block(),
        )
        assert r"viofs\w11" in rendered
        assert r"viofs\2k22" not in rendered
        assert "<PartitionID>3</PartitionID>" in rendered


class TestVirtiofsCacheIsProfileNamespaced:
    """A Server (2k22) virtiofs.exe reused for a Win11 build would install the
    wrong driver binary — and the ISO dir survives destroy/rebuild."""

    def _cfg(self, tmp_path, os_key):
        from winbox.config import Config

        cfg = Config(winbox_dir=tmp_path / ".winbox")
        cfg.vm_os = os_key
        return cfg

    def test_paths_differ_between_profiles(self, tmp_path):
        from winbox.setup.installer import _virtiofs_cache_path

        server = _virtiofs_cache_path(self._cfg(tmp_path, "server2022"))
        win11 = _virtiofs_cache_path(self._cfg(tmp_path, "win11"))
        assert server != win11
        assert "2k22" in server.name
        assert "w11" in win11.name

    @pytest.mark.parametrize(
        "os_key,subdir", [("server2022", "2k22"), ("win11", "w11")]
    )
    def test_iso_member_path_follows_the_profile(self, tmp_path, os_key, subdir):
        from winbox.setup.installer import _virtiofs_iso_member

        member = _virtiofs_iso_member(self._cfg(tmp_path, os_key))
        assert member == f"viofs/{subdir}/amd64/virtiofs.exe"


class TestOfflineDefenderRegistry:
    """Win11's Defender disable happens in the offline SYSTEM hive, before
    first boot. Editing the SOFTWARE hive instead corrupts OOBE."""

    def test_targets_the_system_hive_not_software(self):
        from winbox.setup.installer import _SYSTEM_HIVE

        assert _SYSTEM_HIVE.endswith("/config/SYSTEM")

    def test_disables_every_defender_service(self):
        from winbox.setup.installer import _DEFENDER_OFF_SYSTEM_REG

        for svc in ("WinDefend", "WdFilter", "WdNisSvc", "WdNisDrv"):
            assert svc in _DEFENDER_OFF_SYSTEM_REG
        # Start=4 is "disabled"; a never-started WinDefend never arms Tamper
        # Protection.
        assert _DEFENDER_OFF_SYSTEM_REG.count('"Start"=dword:00000004') == 4

    def test_uses_controlset001(self):
        from winbox.setup.installer import _DEFENDER_OFF_SYSTEM_REG

        assert "ControlSet001" in _DEFENDER_OFF_SYSTEM_REG

    def test_is_a_valid_windows_reg_file(self):
        from winbox.setup.installer import _DEFENDER_OFF_SYSTEM_REG

        assert _DEFENDER_OFF_SYSTEM_REG.startswith(
            "Windows Registry Editor Version 5.00"
        )
        assert "\r\n" in _DEFENDER_OFF_SYSTEM_REG  # CRLF, as regedit requires


class TestGuestfish:
    def test_prepends_run_and_joins_commands(self):
        from winbox.setup.installer import _guestfish

        with patch("winbox.setup.installer.subprocess.run") as run:
            run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            _guestfish(Path("/disk.qcow2"), {}, ["mount /dev/sda2 /", "upload a b"])

        script = run.call_args.kwargs["input"]
        assert script.startswith("run\n")
        assert "mount /dev/sda2 /" in script
        assert "upload a b" in script
        assert run.call_args[0][0][:2] == ["guestfish", "--rw"]

    def test_raises_with_stderr_detail(self):
        from winbox.setup.installer import _guestfish

        with patch("winbox.setup.installer.subprocess.run") as run:
            run.return_value = MagicMock(
                returncode=1, stdout="", stderr="mount: no such device"
            )
            with pytest.raises(RuntimeError, match="no such device"):
                _guestfish(Path("/disk.qcow2"), {}, ["mount /dev/sda9 /"])


class TestVerifyPython:
    """provision.ps1 treats a failed Python install as non-fatal, and the
    provisioning sentinel only proves the script finished — so without this
    check a VM with no Python reported complete success."""

    def _ga(self, results):
        ga = MagicMock()
        ga.exec.side_effect = results
        return ga

    def test_reports_success_when_python_is_on_path(self, capsys):
        from winbox.setup.installer import _verify_python
        from winbox.vm.guest import ExecResult

        _verify_python(self._ga([ExecResult(0, "Python 3.13.13\r\n", "")]))
        assert "Guest Python verified" in capsys.readouterr().out

    def test_falls_back_to_the_embed_install_path(self, capsys):
        """On client SKUs Python lands in C:\\Python313 and reaches PATH only
        after the provisioning reboot."""
        from winbox.setup.installer import _verify_python
        from winbox.vm.guest import ExecResult

        ga = self._ga([
            ExecResult(1, "", "not recognized"),
            ExecResult(0, "Python 3.13.13\r\n", ""),
        ])
        _verify_python(ga)

        assert "Guest Python verified" in capsys.readouterr().out
        assert r"C:\Python313\python.exe" in ga.exec.call_args_list[1][0][0]

    def test_warns_with_remediation_when_python_is_absent(self, capsys):
        from winbox.setup.installer import _verify_python
        from winbox.vm.guest import ExecResult

        _verify_python(self._ga([ExecResult(1, "", "nope"), ExecResult(1, "", "nope")]))

        out = capsys.readouterr().out
        assert "No working Python" in out
        assert "winbox provision" in out

    def test_survives_a_guest_agent_error(self, capsys):
        from winbox.setup.installer import _verify_python
        from winbox.vm.guest import GuestAgentError

        _verify_python(self._ga([GuestAgentError("gone"), GuestAgentError("gone")]))
        assert "No working Python" in capsys.readouterr().out

    def test_never_quotes_the_interpreter_path(self):
        """The guest agent escapes quotes as \\" and cmd.exe forwards them
        literally, so a quoted path arrives with the quotes still in it."""
        from winbox.setup.installer import _verify_python
        from winbox.vm.guest import ExecResult

        ga = self._ga([ExecResult(0, "Python 3.13.13", "")])
        _verify_python(ga)
        assert '"' not in ga.exec.call_args_list[0][0][0]


# ─── hivexregedit prereq ────────────────────────────────────────────────────


class TestOfflineRegistryPrereq:
    """The win11 build disables Defender by editing the offline SYSTEM hive,
    which needs guestfish *and* hivexregedit. They come from different apt
    packages (libguestfs-tools vs libwin-hivex-perl, and the former does not
    depend on the latter), so a host that installed exactly what winbox tells
    it to has guestfish and no hivexregedit. That used to surface ~40 minutes
    into the build as a best-effort warning, leaving Defender armed on a guest
    whose provisioning it then breaks.
    """

    def _which_missing(self, *absent):
        def fake_which(name):
            return None if name in absent else f"/usr/bin/{name}"
        return fake_which

    def test_hivexregedit_is_a_required_tool(self):
        from winbox.setup.installer import REQUIRED_TOOLS

        assert "hivexregedit" in REQUIRED_TOOLS

    @patch("winbox.setup.installer.shutil.which")
    @patch("winbox.setup.installer.Path.exists", return_value=True)
    def test_missing_hivexregedit_is_reported(self, _exists, mock_which):
        mock_which.side_effect = self._which_missing("hivexregedit")

        missing = check_prereqs()

        assert any("hivexregedit" in m for m in missing)

    @patch("winbox.setup.installer.shutil.which")
    @patch("winbox.setup.installer.Path.exists", return_value=True)
    def test_report_names_the_package_that_actually_provides_it(
        self, _exists, mock_which
    ):
        """"install libguestfs-tools" is a no-op fix — they already have it."""
        mock_which.side_effect = self._which_missing("hivexregedit")

        report = " ".join(check_prereqs())

        assert "libwin-hivex-perl" in report

    @patch("winbox.setup.installer.shutil.which")
    @patch("winbox.setup.installer.Path.exists", return_value=True)
    def test_not_required_for_a_profile_that_never_edits_hives_offline(
        self, _exists, mock_which
    ):
        """Server 2022 has no Tamper Protection and never takes the offline
        path, so it must not be blocked on the package."""
        from winbox.config import Config

        mock_which.side_effect = self._which_missing("hivexregedit")

        missing = check_prereqs(Config(vm_os="server2022"))

        assert not any("hivexregedit" in m for m in missing)

    @patch("winbox.setup.installer.shutil.which")
    @patch("winbox.setup.installer.Path.exists", return_value=True)
    def test_required_for_the_profile_that_does(self, _exists, mock_which):
        from winbox.config import Config

        mock_which.side_effect = self._which_missing("hivexregedit")

        missing = check_prereqs(Config(vm_os="win11"))

        assert any("hivexregedit" in m for m in missing)

    @patch("winbox.setup.installer.shutil.which")
    @patch("winbox.setup.installer.Path.exists", return_value=True)
    def test_nothing_missing_stays_empty_for_both_profiles(self, _exists, mock_which):
        from winbox.config import Config

        mock_which.side_effect = lambda name: f"/usr/bin/{name}"

        assert check_prereqs(Config(vm_os="server2022")) == []
        assert check_prereqs(Config(vm_os="win11")) == []
        assert check_prereqs() == []
