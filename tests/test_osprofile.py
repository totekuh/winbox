"""Tests for winbox.osprofile — the OS-target registry."""

import dataclasses

import pytest

from winbox.osprofile import DEFAULT_OS, OS_PROFILES, OSProfile, get_profile


def test_registry_has_all_targets():
    assert set(OS_PROFILES) == {"server2022", "server2025", "win11"}


def test_default_os_is_registered():
    assert DEFAULT_OS in OS_PROFILES
    assert DEFAULT_OS == "server2022"


def test_keys_match_registry():
    for key, profile in OS_PROFILES.items():
        assert profile.key == key


def test_profile_is_frozen():
    p = OS_PROFILES["server2022"]
    with pytest.raises(dataclasses.FrozenInstanceError):
        p.os_variant = "mutated"  # type: ignore[misc]


def test_get_profile():
    assert get_profile("win11").os_variant == "win11"
    with pytest.raises(KeyError):
        get_profile("nope")


class TestProfileInvariants:
    @pytest.mark.parametrize("key", ["server2022", "server2025", "win11"])
    def test_shape(self, key):
        p = OS_PROFILES[key]
        assert isinstance(p, OSProfile)
        assert p.os_variant
        assert p.image_name
        assert p.virtio_subdir
        assert "go.microsoft.com/fwlink" in p.iso_url
        assert p.iso_filename.endswith(".iso")
        assert p.iso_min_size > 0
        assert p.min_disk_gb > 0

    def test_server_flags(self):
        p = OS_PROFILES["server2022"]
        assert p.os_variant == "win2k22"
        assert p.virtio_subdir == "2k22"
        assert p.supports_core is True
        assert p.labconfig_bypass is False
        assert p.disable_defender_offline is False
        assert p.prevent_device_encryption is False
        assert p.min_disk_gb == 30
        # Minimal Server layout: 100 MB ESP, no MSR, Windows on partition 2.
        assert p.esp_size_mb == 100
        assert p.include_msr is False
        assert p.install_partition_id == 2

    def test_server2025_flags(self):
        p = OS_PROFILES["server2025"]
        assert p.os_variant == "win2k25"
        assert p.virtio_subdir == "2k25"
        assert p.supports_core is True
        assert p.client_sku is False
        # Genuinely-client workarounds stay off (no TPM gate, no auto-BitLocker).
        assert p.labconfig_bypass is False
        assert p.prevent_device_encryption is False
        # But its 24H2 Defender is aggressive like the client's, so the offline
        # Defender disable is ON — same as Win11, unlike Server 2022.
        assert p.disable_defender_offline is True
        # The 24H2 Setup engine rejects the minimal 2022 layout, so 2025 uses
        # the standard UEFI layout: 260 MB ESP + MSR, Windows on partition 3.
        assert p.esp_size_mb == 260
        assert p.include_msr is True
        assert p.install_partition_id == 3
        # Distinct local ISO name so it cannot clobber the 2022 SERVER_EVAL.
        assert p.iso_filename == "SERVER2025_EVAL_x64FRE_en-us.iso"
        assert "linkid=2293312" in p.iso_url

    def test_win11_flags(self):
        p = OS_PROFILES["win11"]
        assert p.os_variant == "win11"
        assert p.virtio_subdir == "w11"
        assert p.supports_core is False
        assert p.labconfig_bypass is True
        # Defender disabled via the offline SYSTEM hive (service Start=4) — the
        # only thing that survives Win11 Tamper Protection without breaking OOBE.
        assert p.disable_defender_offline is True
        assert p.prevent_device_encryption is True
        # Win11 Setup enforces a 64 GB system-drive minimum.
        assert p.min_disk_gb == 64
        # Standard Win11 UEFI layout: 260 MB ESP + MSR, Windows on partition 3.
        assert p.esp_size_mb == 260
        assert p.include_msr is True
        assert p.install_partition_id == 3


class TestClientSku:
    """`client_sku` decides which Python payload the build must ship.

    provision.ps1 chooses at runtime by probing Win32_OperatingSystem's
    ProductType, so the profile has to agree with what that probe will find
    or the guest ends up with no Python at all.
    """

    def test_server_is_not_client(self):
        assert OS_PROFILES["server2022"].client_sku is False

    def test_win11_is_client(self):
        assert OS_PROFILES["win11"].client_sku is True

    @pytest.mark.parametrize("key", ["server2022", "server2025", "win11"])
    def test_client_sku_is_the_inverse_of_server_core_support(self, key):
        """Server Core is a Server-only concept; a client SKU never has it."""
        p = OS_PROFILES[key]
        assert p.client_sku is not p.supports_core


class TestWin11GatesAreServerNoOps:
    """Every Win11 *client* workaround must be inert for the Server profiles.

    Server has no TPM gate and no Device Encryption, so these flags being True
    on Server would apply a fix for a problem it doesn't have.

    Two flags are deliberately NOT in this list because they track the *Setup
    engine* and *Defender generation*, not client-vs-server, and Server 2025
    (24H2) legitimately sets both: ``include_msr`` (the 24H2 Setup needs the
    standard UEFI layout) and ``disable_defender_offline`` (24H2 Defender is
    aggressive enough to quarantine tools at first boot).
    """

    @pytest.mark.parametrize("server", ["server2022", "server2025"])
    @pytest.mark.parametrize(
        "flag",
        [
            "labconfig_bypass",
            "prevent_device_encryption",
            "client_sku",
        ],
    )
    def test_flag_is_off_for_server(self, server, flag):
        assert getattr(OS_PROFILES[server], flag) is False

    def test_server_installs_to_partition_two(self):
        assert OS_PROFILES["server2022"].install_partition_id == 2

    def test_win11_installs_to_partition_three(self):
        """ESP=1, MSR=2, Windows=3 — the layout Win11 Setup accepts."""
        assert OS_PROFILES["win11"].install_partition_id == 3

    def test_install_partition_follows_msr(self):
        for p in OS_PROFILES.values():
            assert p.install_partition_id == (3 if p.include_msr else 2)
