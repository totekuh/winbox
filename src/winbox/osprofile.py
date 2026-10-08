"""Guest-OS profiles: everything that varies between the Windows targets.

winbox can build Windows Server 2022 (the historical default), Windows Server
2025, Windows 11, or Windows 10. They differ in a handful of build-time
details — the evaluation ISO to fetch, the ``install.wim`` image name the
unattend selects, the VirtIO driver subdirectory (``2k22`` / ``2k25`` /
``w11`` / ``w10``), the libvirt ``--os-variant``, and whether the Server
Core/Desktop toggle and the Win11 setup-gate bypass apply.

Rather than sprinkling ``if win11`` branches across ``iso.py``,
``installer.py``, and the CLI, all of that lives here as a frozen
:class:`OSProfile`. Call sites read ``cfg.profile`` (see
:pyattr:`winbox.config.Config.profile`) and pull what they need.

Selection is build-time only: one VM, one disk. Switching OS means
``winbox destroy`` followed by ``winbox setup --os <other>``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OSProfile:
    """Build-time knobs that differ between guest OS targets."""

    key: str
    """Registry key / ``--os`` value, e.g. ``"server2022"`` or ``"win11"``."""

    os_variant: str
    """libvirt ``virt-install --os-variant`` value."""

    image_name: str
    """The ``install.wim`` image the unattend selects (``/IMAGE/NAME``)."""

    virtio_subdir: str
    """VirtIO driver dir on the virtio-win ISO (``2k22`` for Server 2022,
    ``w11`` for Windows 11). Used for vioserial, viofs, and virtiofs.exe."""

    iso_url: str
    """``go.microsoft.com/fwlink`` redirect that HEAD-resolves to the
    evaluation ISO on Microsoft's CDN."""

    iso_filename: str
    """Local filename for the downloaded evaluation ISO."""

    iso_min_size: int
    """Truncation floor in bytes — a smaller file is treated as a partial
    download rather than a usable ISO."""

    min_disk_gb: int
    """Minimum system-disk size in GB. Windows 11 Setup enforces a 64 GB
    system-drive floor; the disk is created at ``max(cfg.vm_disk, min_disk_gb)``."""

    esp_size_mb: int
    """EFI System Partition size in MB. Server 2022 installs fine with a 100 MB
    ESP; Windows 11 Setup wants the standard ≥260 MB ESP."""

    include_msr: bool
    """Create a Microsoft Reserved (MSR) partition in the UEFI/GPT layout.
    Windows 11 Setup rejects the target partition ("There is an error selecting
    this partition for install") on the minimal ESP+Windows layout that Server
    2022 tolerates; the standard layout it expects is ESP + MSR + Windows. When
    True the Windows partition becomes partition 3 (ESP=1, MSR=2, Windows=3)."""

    supports_core: bool
    """Whether the Server Core vs Desktop Experience choice applies.
    Server 2022: True (``--desktop`` picks Desktop Experience).
    Windows 11: False (always a full desktop; ``--desktop`` is rejected)."""

    client_sku: bool
    """True for client Windows (``ProductType`` 1), False for Server.

    Drives which Python payload provisioning must have: client SKUs can't run
    the Python WiX bundle installer under the guest agent's session-0 SYSTEM
    context (it deadlocks / returns 1601), so they need the embeddable zip,
    while Server uses the normal installer. provision.ps1 picks between them
    by probing ``ProductType`` at runtime; this flag is what lets the *build*
    check the needed file is actually in the payload."""

    labconfig_bypass: bool
    """Inject ``HKLM\\System\\Setup\\LabConfig`` bypass keys in the WinPE
    pass so setup proceeds without TPM 2.0 / Secure Boot. Win11 only."""

    disable_defender_offline: bool
    """Clear Defender Tamper Protection in the offline SOFTWARE hive during
    provisioning so the runtime Defender-disable can take effect. Win11
    client SKUs ship with Tamper Protection on; Server 2022 does not."""

    prevent_device_encryption: bool
    """Set ``PreventDeviceEncryption`` + OOBE network bypass in the specialize
    pass. Win11 client auto-enables BitLocker Device Encryption (which breaks
    offline access and needs a TPM we don't have) and its OOBE can stall on the
    network screen; Server 2022 does neither."""

    locale: str = "en-US"
    """UI language / input / system / user locale written into every pass of
    the unattend (``{LOCALE}``). Must match a language the install media
    actually carries, or the WinPE pass cannot auto-select it and Setup stops
    on the interactive "Language to install" page. The Evaluation media winbox
    normally uses is en-US; the consumer Win10 media is the "EnglishInternational"
    (en-GB) ISO, so win10 sets ``en-GB``."""

    product_key: str = ""
    """Edition-selecting product key injected into the unattend ``<UserData>``.

    Empty for the Evaluation media (Server 2022/2025, Win11 Enterprise eval):
    those ISOs carry a single edition, so Setup picks it implicitly and a key
    is not needed. The consumer multi-edition Win10 ISO has no default edition,
    so its Setup *requires* a key in the answer file to choose one — without it
    the WinPE pass stops on "Windows cannot read the <ProductKey> setting from
    the unattend answer file". This is the public generic (KMS client setup)
    key for the target edition: it selects the edition and installs unactivated
    (fine for a throwaway research VM), it does not activate anything."""

    @property
    def install_partition_id(self) -> int:
        """1-based partition the OS image is installed to. With an MSR
        partition the order is ESP=1, MSR=2, Windows=3; without it, Windows=2."""
        return 3 if self.include_msr else 2


DEFAULT_OS = "server2022"

OS_PROFILES: dict[str, OSProfile] = {
    "server2022": OSProfile(
        key="server2022",
        os_variant="win2k22",
        image_name="Windows Server 2022 SERVERSTANDARDCORE",
        virtio_subdir="2k22",
        # Microsoft go.microsoft.com redirect for the Windows Server 2022
        # Evaluation ISO (en-US, x64).
        iso_url=(
            "https://go.microsoft.com/fwlink/p/"
            "?LinkID=2195280&clcid=0x409&culture=en-us&country=US"
        ),
        iso_filename="SERVER_EVAL_x64FRE_en-us.iso",
        # Server 2022 eval ISO is ~4.7GB.
        iso_min_size=4_500_000_000,
        # Server 2022 installs happily on a small disk.
        min_disk_gb=30,
        # Proven Server 2022 layout: 100 MB ESP + Windows, no MSR.
        esp_size_mb=100,
        include_msr=False,
        supports_core=True,
        client_sku=False,
        labconfig_bypass=False,
        disable_defender_offline=False,
        prevent_device_encryption=False,
    ),
    "server2025": OSProfile(
        key="server2025",
        os_variant="win2k25",
        # NOTE: verify against the real install.wim with `wiminfo` before a
        # build — a mismatch fails the WinPE image-select. Server 2025 Core
        # Standard is expected to be "Windows Server 2025 SERVERSTANDARDCORE".
        image_name="Windows Server 2025 SERVERSTANDARDCORE",
        # virtio-win ships a dedicated 2k25 driver subdir (verified present on
        # the pinned ISO). If a future virtio ISO drops it, 2k22 drivers work.
        virtio_subdir="2k25",
        # Microsoft evalcenter fwlink for the Windows Server 2025 Evaluation
        # ISO (en-US, x64). HEAD-resolves to build 26100 SERVER_EVAL (~6.0 GB);
        # if Microsoft rotates the link the HEAD resolve fails loudly and the
        # user can pass `--iso <path>`.
        iso_url=(
            "https://go.microsoft.com/fwlink/"
            "?linkid=2293312&clcid=0x409&culture=en-us&country=us"
        ),
        # Distinct local name: the CDN filename is the same SERVER_EVAL...iso
        # as the 2022 media, which would clobber the cached 2022 ISO.
        iso_filename="SERVER2025_EVAL_x64FRE_en-us.iso",
        # Real size ~6.01 GB; keep a conservative truncation floor.
        iso_min_size=5_800_000_000,
        # Server Core installs happily on a modest disk.
        min_disk_gb=32,
        # Server 2025 runs the rewritten Windows 11 24H2 Setup (build 26100),
        # which — like the Win11 client Setup — rejects the minimal 100 MB
        # ESP + Windows layout that Server 2022's older Setup tolerated
        # ("Windows can't be installed to this disk", with an aka.ms/SetupFaq
        # link). It needs the standard UEFI layout: 260 MB ESP + MSR + Windows
        # (partition 3). include_msr here is a Setup-engine requirement, not a
        # Win11-client gate.
        esp_size_mb=260,
        include_msr=True,
        supports_core=True,
        client_sku=False,
        labconfig_bypass=False,
        # Server 2025's 24H2-lineage Defender is aggressive like the client's:
        # left on, it quarantines winbox's tools (x64dbg trips
        # "file contains a virus") during the very first provisioning boot,
        # before provision.ps1 can disable it in-guest — the build fails with a
        # missing sentinel. So, like Win11, disable the Defender services in the
        # offline SYSTEM hive before first boot. This also makes the runtime av
        # offline paths apply (they gate on this flag, not client_sku).
        disable_defender_offline=True,
        # Server does not auto-enable BitLocker Device Encryption, so the Win11
        # OOBE-network / PreventDeviceEncryption workaround is not needed.
        prevent_device_encryption=False,
    ),
    "win11": OSProfile(
        key="win11",
        os_variant="win11",
        # NOTE: must match the exact image name in the ISO's install.wim.
        # Verify with `wiminfo` / `dism /Get-WimInfo` before a real build;
        # a mismatch fails the WinPE image-select step.
        image_name="Windows 11 Enterprise Evaluation",
        virtio_subdir="w11",
        # Windows 11 Enterprise Evaluation (en-US, x64). Same fwlink→CDN
        # HEAD-redirect shape as the Server link. linkid 2334167 is current
        # for the 25H2 eval; if Microsoft rotates it the HEAD resolve fails
        # loudly and the user can pass `--iso <path>` instead.
        iso_url=(
            "https://go.microsoft.com/fwlink/"
            "?linkid=2334167&clcid=0x409&culture=en-us&country=us"
        ),
        iso_filename="WIN11_ENT_EVAL_x64FRE_en-us.iso",
        # Win11 Enterprise eval ISO is ~6GB+; keep a conservative floor.
        iso_min_size=5_500_000_000,
        # Win11 Setup refuses a system drive under 64 GB.
        min_disk_gb=64,
        # Standard Win11 UEFI layout: 260 MB ESP + MSR + Windows (partition 3).
        esp_size_mb=260,
        include_msr=True,
        supports_core=False,
        client_sku=True,
        labconfig_bypass=True,
        # Win11 Tamper Protection blocks every in-VM Defender disable, and
        # editing the offline SOFTWARE hive corrupts OOBE. The one thing that
        # works: disable the Defender *services* in the offline SYSTEM hive
        # (Start=4) — SYSTEM doesn't hold OOBE state, so it boots clean, and a
        # never-started WinDefend never arms Tamper Protection. Without this,
        # Defender quarantines winbox's tools and breaks provisioning + exec.
        disable_defender_offline=True,
        prevent_device_encryption=True,
    ),
    "win10": OSProfile(
        key="win10",
        # libvirt osinfo-db id for Windows 10. VERIFY with
        # `osinfo-query os | grep -i win10` before a build — virt-install
        # fails if osinfo-db does not know the variant.
        os_variant="win10",
        # NOTE: must match the exact image name in the ISO's install.wim.
        # Verify with `wiminfo` / `dism /Get-WimInfo` before a real build;
        # a mismatch fails the WinPE image-select step. Microsoft pulled the
        # Windows 10 Enterprise *Evaluation* media after EOL (its evalcenter
        # page 301-redirects to a "move to Win11" blog), so the obtainable
        # media is the consumer multi-edition 22H2 ISO, whose install.wim
        # carries Home/Pro/Education images — use "Windows 10 Pro". It installs
        # unactivated, which is fine for a throwaway research VM, and is still
        # ProductType 1 (client), so the embeddable-Python path applies.
        image_name="Windows 10 Pro",
        # virtio-win ships a dedicated w10 driver subdir. VERIFY present on the
        # pinned virtio-win ISO; if a future ISO drops it, the w11/2k22 drivers
        # also load on Windows 10.
        virtio_subdir="w10",
        # Windows 10 reached end of life 2025-10-14 and auto-download is not
        # wired. The Enterprise eval media was pulled (its evalcenter page
        # 301-redirects to a "move to Win11" blog). The consumer 22H2 ISO is
        # still served, but only to non-Windows browsers and only as a
        # per-session *signed, time-limited* link minted by the software-
        # download page (software.download.prss.microsoft.com/...?P1=<expiry>
        # &P4=<sig>) — not a durable go.microsoft.com/fwlink like the other
        # profiles, so it cannot be baked in here. iso_url therefore points at
        # the stable software-download page (which does not HEAD-resolve to an
        # ISO), so auto-download fails loudly and the user passes `--iso <path>`
        # with a manually fetched ISO. (Wiring true auto-download would mean
        # emulating the browser flow: spoof a non-Windows UA, POST a session to
        # mint a fresh signed link each run — a separate feature.)
        iso_url="https://www.microsoft.com/en-us/software-download/windows10ISO",
        iso_filename="Win10_22H2_x64.iso",
        # Win10 22H2 consumer ISO is ~5.8 GB; keep a conservative floor.
        iso_min_size=4_500_000_000,
        # Windows 10 2004+ Setup wants a 32 GB system drive.
        min_disk_gb=32,
        # Standard UEFI layout: 260 MB ESP + MSR + Windows (partition 3). This
        # is the safe default; Win10's older (pre-24H2) Setup engine may also
        # tolerate the minimal 100 MB ESP / no-MSR layout that Server 2022
        # uses — if a build confirms that, esp_size_mb/include_msr can drop to
        # 100/False (Windows would then land on partition 2).
        esp_size_mb=260,
        include_msr=True,
        # Client SKU: no Server Core/Desktop toggle (`--desktop` is rejected).
        supports_core=False,
        # ProductType 1 — provision.ps1 installs the Python embeddable zip.
        client_sku=True,
        # Windows 10 has no TPM 2.0 / Secure Boot install gate, so the Win11
        # LabConfig bypass keys are not needed.
        labconfig_bypass=False,
        # Windows 10 does not auto-enable BitLocker Device Encryption without a
        # TPM, and its OOBE does not hard-block on the network screen the way
        # Win11 24H2 does, so the specialize-pass workaround is not needed.
        prevent_device_encryption=False,
        # Win10 Enterprise ships Defender with Tamper Protection on, which
        # blocks the in-guest registry disable. Like Win11/Server 2025, disable
        # the Defender services in the offline SYSTEM hive before first boot so
        # a never-started WinDefend never arms Tamper Protection and does not
        # quarantine winbox's tools during provisioning. VERIFY on a live build
        # that first-boot Defender stays quiet. (This also makes the runtime av
        # offline paths apply — they gate on this flag, not client_sku.)
        disable_defender_offline=True,
        # Consumer multi-edition media needs a key in the answer file to pick an
        # edition. This is Microsoft's public generic/KMS-client setup key for
        # Windows 10 Pro — it selects Pro and installs unactivated (no
        # activation), matching image_name above.
        product_key="W269N-WFGWX-YVC9B-4J6C9-T83GX",
        # The consumer media is the "EnglishInternational" (en-GB) ISO; the
        # WinPE pass must request en-GB or Setup stops on the language page.
        locale="en-GB",
    ),
}


def get_profile(key: str) -> OSProfile:
    """Return the :class:`OSProfile` for ``key`` (raises ``KeyError`` if unknown)."""
    return OS_PROFILES[key]
