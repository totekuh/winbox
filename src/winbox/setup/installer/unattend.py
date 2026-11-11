"""Unattend XML generation, disk partitioning, disk image creation, virt-install."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console

from winbox import data as _data
from winbox.setup.installer.prereqs import _find_mkisofs, ensure_default_network
from winbox.vm import virsh_run

if TYPE_CHECKING:
    from winbox.config import Config

console = Console()


def _product_key_block(product_key: str) -> str:
    """Render the ``<ProductKey>`` for the unattend ``<UserData>``.

    Emitted into ``{PRODUCT_KEY_BLOCK}`` right inside ``<UserData>`` (before
    ``<AcceptEula>``, the order the Setup schema expects). Empty for the
    Evaluation media, which carries a single edition and picks it implicitly —
    their rendered XML then stays byte-identical. The consumer multi-edition
    Win10 ISO needs a key here to choose an edition; ``WillShowUI=Never``
    suppresses the key prompt during the unattended install."""
    if not product_key:
        return ""
    return (
        "\n        <ProductKey>"
        f"\n          <Key>{product_key}</Key>"
        "\n          <WillShowUI>Never</WillShowUI>"
        "\n        </ProductKey>"
    )


# LabConfig bypass keys injected in the WinPE pass for Win11 so setup
# proceeds without TPM 2.0 / Secure Boot / the RAM/storage/CPU gates.
# Emitted into the {LABCONFIG_BLOCK} placeholder of unattend.xml; empty
# for Server 2022 (whose rendered XML is then byte-identical to before).
_LABCONFIG_KEYS = (
    "BypassTPMCheck",
    "BypassSecureBootCheck",
    "BypassRAMCheck",
    "BypassStorageCheck",
    "BypassCPUCheck",
)


def _specialize_deploy_block() -> str:
    """Microsoft-Windows-Deployment RunSynchronous for the specialize pass.

    Runs on first boot before OOBE, so the registry keys are in place before
    Win11 would auto-enable Device Encryption or stop OOBE on the network
    screen:
      * BitLocker\\PreventDeviceEncryption = 1 — never auto-encrypt the OS
        drive (we have no TPM, and encryption breaks offline provisioning /
        memory + kernel analysis).
      * OOBE\\BypassNRO = 1 — let OOBE proceed without a network / Microsoft
        account (Win11 24H2+ otherwise blocks on "Let's connect you to a
        network").
    (Defender is handled separately, in the offline SYSTEM hive — Tamper
    Protection ignores these specialize-pass reg writes.)
    Emitted into {SPECIALIZE_DEPLOY_BLOCK}; empty for Server 2022.
    """
    cmds = [
        r"reg add HKLM\SYSTEM\CurrentControlSet\Control\BitLocker "
        r"/v PreventDeviceEncryption /t REG_DWORD /d 1 /f",
        r"reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE "
        r"/v BypassNRO /t REG_DWORD /d 1 /f",
    ]
    lines = [
        "",
        "",
        '    <component name="Microsoft-Windows-Deployment"',
        '               processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"',
        '               language="neutral" versionScope="nonSxS"',
        '               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">',
        "      <RunSynchronous>",
    ]
    for order, cmd in enumerate(cmds, start=1):
        lines.append('        <RunSynchronousCommand wcm:action="add">')
        lines.append(f"          <Order>{order}</Order>")
        lines.append(f"          <Path>{cmd}</Path>")
        lines.append("        </RunSynchronousCommand>")
    lines.append("      </RunSynchronous>")
    lines.append("    </component>")
    return "\n".join(lines)


def _labconfig_block() -> str:
    """Render the <RunSynchronous> LabConfig-bypass block for the WinPE pass.

    Returned string leads with a blank line so it substitutes inline right
    after ``</DiskConfiguration>`` (the ``{LABCONFIG_BLOCK}`` placeholder);
    an empty value leaves the Server 2022 XML byte-identical.
    """
    lines = [
        "",
        "",
        "      <RunSynchronous>",
    ]
    for order, key in enumerate(_LABCONFIG_KEYS, start=1):
        lines.append('        <RunSynchronousCommand wcm:action="add">')
        lines.append(f"          <Order>{order}</Order>")
        lines.append(
            "          <Path>reg add HKLM\\System\\Setup\\LabConfig /v "
            f"{key} /t REG_DWORD /d 1 /f</Path>"
        )
        lines.append("        </RunSynchronousCommand>")
    lines.append("      </RunSynchronous>")
    return "\n".join(lines)


def _disk_partitions_block(cfg: Config) -> str:
    """Render the <CreatePartitions>/<ModifyPartitions> XML for the profile's
    UEFI/GPT disk layout.

    Server 2022 uses a minimal ESP + Windows layout (2 partitions). Windows 11
    Setup rejects that with "error selecting this partition for install" and
    needs the standard ESP + MSR + Windows layout, so ``include_msr`` inserts
    the Microsoft Reserved partition (unformatted) and pushes Windows to
    partition 3. ``esp_size_mb`` sizes the EFI System Partition (Win11 wants a
    larger ESP than the 100 MB that satisfies Server).
    """
    p = cfg.profile
    create: list[str] = []
    modify: list[str] = []
    order = 1

    # 1) EFI System Partition
    create.append(
        f'            <CreatePartition wcm:action="add">\n'
        f"              <Order>{order}</Order>\n"
        f"              <Size>{p.esp_size_mb}</Size>\n"
        f"              <Type>EFI</Type>\n"
        f"            </CreatePartition>"
    )
    modify.append(
        f'            <ModifyPartition wcm:action="add">\n'
        f"              <Order>{len(modify) + 1}</Order>\n"
        f"              <PartitionID>{order}</PartitionID>\n"
        f"              <Format>FAT32</Format>\n"
        f"              <Label>System</Label>\n"
        f"            </ModifyPartition>"
    )
    esp_id = order  # noqa: F841
    order += 1

    # 2) Microsoft Reserved partition (Win11) — created but never formatted.
    if p.include_msr:
        create.append(
            f'            <CreatePartition wcm:action="add">\n'
            f"              <Order>{order}</Order>\n"
            f"              <Size>128</Size>\n"
            f"              <Type>MSR</Type>\n"
            f"            </CreatePartition>"
        )
        order += 1

    # 3) Windows partition — rest of the disk.
    create.append(
        f'            <CreatePartition wcm:action="add">\n'
        f"              <Order>{order}</Order>\n"
        f"              <Extend>true</Extend>\n"
        f"              <Type>Primary</Type>\n"
        f"            </CreatePartition>"
    )
    modify.append(
        f'            <ModifyPartition wcm:action="add">\n'
        f"              <Order>{len(modify) + 1}</Order>\n"
        f"              <PartitionID>{order}</PartitionID>\n"
        f"              <Format>NTFS</Format>\n"
        f"              <Label>Windows</Label>\n"
        f"            </ModifyPartition>"
    )
    # Not an assert: under `python -O` this check would vanish, and a mismatch
    # here means the unattend installs Windows to the wrong partition — a
    # failure that only shows up 20 minutes into a build, inside WinPE.
    if order != p.install_partition_id:
        raise RuntimeError(
            f"disk layout bug: Windows landed on partition {order} but "
            f"{p.key}'s install_partition_id is {p.install_partition_id}"
        )

    return (
        "          <CreatePartitions>\n"
        + "\n".join(create)
        + "\n          </CreatePartitions>\n"
        + "          <ModifyPartitions>\n"
        + "\n".join(modify)
        + "\n          </ModifyPartitions>"
    )


def build_unattend_image(cfg: Config, *, desktop: bool = False) -> None:
    """Build an ISO image containing autounattend.xml for the active OS profile."""
    mkisofs = _find_mkisofs()
    if mkisofs is None:
        raise RuntimeError(
            "Neither mkisofs nor genisoimage found. "
            "Install with: apt install genisoimage"
        )

    profile = cfg.profile
    if desktop and not profile.supports_core:
        raise RuntimeError(
            f"--desktop is a Windows Server option (Core vs Desktop Experience); "
            f"{profile.key} is always a full desktop. Drop --desktop."
        )

    # Remove stale image (may be owned by libvirt-qemu from previous run)
    if cfg.unattend_img.exists():
        try:
            cfg.unattend_img.unlink()
        except PermissionError:
            if shutil.which("sudo"):
                subprocess.run(
                    ["sudo", "rm", "-f", str(cfg.unattend_img)],
                    check=False,
                )
            if cfg.unattend_img.exists():
                raise PermissionError(
                    f"{cfg.unattend_img} is owned by another user "
                    "(probably libvirt-qemu from a previous setup) and "
                    "couldn't be removed.\n"
                    f"    Manual cleanup: sudo rm -f {cfg.unattend_img}"
                )

    image_name = profile.image_name
    if profile.supports_core and desktop:
        # Server: swap the Core image for the Desktop Experience one.
        image_name = image_name.replace("SERVERSTANDARDCORE", "SERVERSTANDARD")

    if profile.supports_core:
        edition = "Desktop Experience" if desktop else "Server Core"
    else:
        edition = profile.key
    console.print(f"[blue][*][/] Building unattend image ({edition})...")
    with tempfile.TemporaryDirectory() as tmpdir:
        dst = Path(tmpdir) / "autounattend.xml"
        xml = _data.render(
            "unattend.xml",
            IMAGE_NAME=image_name,
            VIRTIO_SUBDIR=profile.virtio_subdir,
            INSTALL_PARTITION_ID=str(profile.install_partition_id),
            DISK_PARTITIONS=_disk_partitions_block(cfg),
            LABCONFIG_BLOCK=_labconfig_block() if profile.labconfig_bypass else "",
            SPECIALIZE_DEPLOY_BLOCK=(
                _specialize_deploy_block() if profile.prevent_device_encryption else ""
            ),
            PRODUCT_KEY_BLOCK=_product_key_block(profile.product_key),
            LOCALE=profile.locale,
        )
        dst.write_text(xml)

        subprocess.run(
            [mkisofs, "-o", str(cfg.unattend_img), "-J", "-r", tmpdir],
            capture_output=True,
            check=True,
        )
    console.print("[green][+][/] Unattend image created")


def create_disk(cfg: Config) -> None:
    """Create the QCOW2 disk image.

    Honors the OS profile's minimum disk size: Win11 Setup rejects a system
    drive under 64 GB, so we never create one smaller than ``min_disk_gb``
    regardless of the (Server-oriented) ``vm_disk`` default.
    """
    disk_gb = max(cfg.vm_disk, cfg.profile.min_disk_gb)
    if disk_gb != cfg.vm_disk:
        console.print(
            f"[yellow][!][/] {cfg.profile.key} needs ≥{cfg.profile.min_disk_gb}GB; "
            f"using {disk_gb}GB instead of the configured {cfg.vm_disk}GB."
        )
    console.print(f"[blue][*][/] Creating VM disk ({disk_gb}GB)...")
    result = subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", str(cfg.disk_path), f"{disk_gb}G"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"qemu-img create failed (exit {result.returncode}):\n"
            f"  stdout: {result.stdout.strip()}\n"
            f"  stderr: {result.stderr.strip()}"
        )
    console.print("[green][+][/] Disk created")


def run_virt_install(cfg: Config, windows_iso: str) -> None:
    """Run virt-install to create and boot the VM for Phase 1 (ISO install)."""
    ensure_default_network()
    console.print("[blue][*][/] Installing Windows VM (this takes ~10-15 minutes)...")
    console.print(f"    Monitor with: virsh console {cfg.vm_name}")
    console.print()

    cmd = [
        "virt-install",
        "--connect", "qemu:///system",
        "--name", cfg.vm_name,
        "--ram", str(cfg.vm_ram),
        "--vcpus", str(cfg.vm_cpus),
        "--memorybacking", "source.type=memfd,access.mode=shared",
        "--disk", f"path={cfg.disk_path},bus=sata",
        "--cdrom", windows_iso,
        "--disk", f"{cfg.unattend_img},device=cdrom",
        "--disk", f"{cfg.virtio_iso},device=cdrom",
        "--network", "network=default,model=e1000",
        "--channel", "unix,target.type=virtio,target.name=org.qemu.guest_agent.0",
        "--filesystem", (
            f"type=mount,accessmode=passthrough,driver.type=virtiofs,"
            f"driver.queue=1024,source.dir={cfg.shared_dir},"
            f"target.dir=winbox_share"
        ),
        "--os-variant", cfg.profile.os_variant,
        "--noautoconsole",
        "--boot", "uefi",
    ]
    if cfg.display == "spice":
        cmd += [
            "--graphics", "spice,listen=127.0.0.1",
            "--video", "qxl",
            "--channel",
            "spicevmc,target.type=virtio,target.name=com.redhat.spice.0",
        ]
    else:
        cmd += ["--graphics", "vnc,listen=127.0.0.1"]

    subprocess.run(cmd, check=True)
    console.print("[green][+][/] VM installation started")

    # UEFI shows "Press any key to boot from CD or DVD..." — send keypresses
    console.print("[blue][*][/] Sending boot keystroke...")
    for _ in range(5):
        time.sleep(3)
        result = virsh_run("send-key", cfg.vm_name, "KEY_ENTER", check=False)
        if result.returncode != 0:
            break
