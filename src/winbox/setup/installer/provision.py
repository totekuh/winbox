"""Disk injection, offline Defender disable, and provisioning boot."""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console

from winbox import data as _data
from winbox.setup.installer.downloads import (
    OPENSSH_ZIP, PYTHON_EMBED_ZIP, PYTHON_EXE, RUNEX_EXE, SPICE_TOOLS_EXE,
    VIRTIOFS_EXE, WINFSP_MSI, X64DBG_ZIP, _virtiofs_cache_path,
)
from winbox.vm import VM, GuestAgent, GuestAgentError

if TYPE_CHECKING:
    from winbox.config import Config

console = Console()

PROVISION_SENTINEL = "C:\\winbox-provisioned.ok"
BOOTSTRAP_LOG = "C:\\winbox-bootstrap.log"

# Path to the SYSTEM registry hive inside the mounted Windows partition.
_SYSTEM_HIVE = "/Windows/System32/config/SYSTEM"


def provision_vm_disk(cfg: Config) -> None:
    """Phase 2: Inject provision files into disk image via virt-customize."""
    console.print("[blue][*][/] Preparing provision payload...")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        # Build provision.zip: provision.ps1, .ssh_pubkey, OpenSSH, WinFsp, virtiofs.exe
        openssh_zip = cfg.iso_dir / OPENSSH_ZIP
        winfsp_msi = cfg.iso_dir / WINFSP_MSI
        virtiofs_exe = _virtiofs_cache_path(cfg)
        python_exe = cfg.iso_dir / PYTHON_EXE
        python_embed = cfg.iso_dir / PYTHON_EMBED_ZIP
        x64dbg_zip = cfg.iso_dir / X64DBG_ZIP
        runex_exe = cfg.iso_dir / RUNEX_EXE
        spice_tools_exe = cfg.iso_dir / SPICE_TOOLS_EXE
        # provision.ps1 picks its Python payload by probing the guest's
        # ProductType, so the build has to ship the one that probe will ask
        # for. Shipping the wrong one isn't an error there — it just quietly
        # leaves the VM with no Python, which only surfaces later as a broken
        # MCP `python` tool.
        if cfg.profile.client_sku:
            required_python = (python_embed, "Python embeddable zip")
        else:
            required_python = (python_exe, "Python installer")

        missing_files = []
        for path, label in [
            (openssh_zip, "OpenSSH"), (winfsp_msi, "WinFsp"), (virtiofs_exe, "virtiofs"),
            (runex_exe, "RunEx"),
            required_python,
        ]:
            if not path.exists():
                missing_files.append(f"{label}: {path}")
        if missing_files:
            raise RuntimeError(
                "Missing critical provisioning files (re-run setup):\n  "
                + "\n  ".join(missing_files)
            )

        # Sanity-check the zip-shaped downloads beyond size > N (the previous
        # check would happily reuse a partial download stuck above the
        # threshold — captive portal interstitial, MITM error page, etc.).
        for zpath, label in [
            (openssh_zip, "OpenSSH"),
            (x64dbg_zip, "x64dbg"),
            # provision.ps1 Expand-Archives this in-guest on client SKUs; a
            # size-only download gate can pass an HTML captive-portal page, and
            # without it here the VM silently ends up with no Python (broken
            # MCP `python` tool + kdbg) while setup still reports success.
            (python_embed, "Python embeddable zip"),
        ]:
            if zpath.exists() and not zipfile.is_zipfile(zpath):
                raise RuntimeError(
                    f"{label} download at {zpath} is not a valid zip "
                    "(probably truncated or an HTML error page). "
                    f"Delete it and re-run winbox setup."
                )
        zip_path = tmpdir_path / "provision.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(_data.path("provision.ps1"), "provision.ps1")
            if cfg.ssh_pubkey.exists():
                zf.write(cfg.ssh_pubkey, ".ssh_pubkey")
            if openssh_zip.exists():
                zf.write(openssh_zip, OPENSSH_ZIP)
            if winfsp_msi.exists():
                zf.write(winfsp_msi, WINFSP_MSI)
            if virtiofs_exe.exists():
                zf.write(virtiofs_exe, VIRTIOFS_EXE)
            if python_exe.exists():
                zf.write(python_exe, PYTHON_EXE)
            if python_embed.exists():
                zf.write(python_embed, PYTHON_EMBED_ZIP)
            if x64dbg_zip.exists():
                zf.write(x64dbg_zip, X64DBG_ZIP)
            zf.write(runex_exe, RUNEX_EXE)
            # SPICE display only, and best-effort: provision.ps1 self-gates on
            # the file's presence. Not in missing_files — spice is not
            # load-bearing, so a missing/failed install must never fail setup.
            if cfg.display == "spice" and spice_tools_exe.exists():
                zf.write(spice_tools_exe, SPICE_TOOLS_EXE)

        # Copy bootstrap.ps1 to temp dir
        bootstrap_src = _data.path("bootstrap.ps1")
        bootstrap_tmp = tmpdir_path / "bootstrap.ps1"
        bootstrap_tmp.write_bytes(Path(bootstrap_src).read_bytes())

        console.print("[blue][*][/] Injecting provision files into disk image...")
        env = {**os.environ, "LIBGUESTFS_BACKEND": "direct"}
        # virt-customize's automatic OS inspection (inspect_os) fails on the
        # Win11 image — the installer leaves Windows.old / $Windows.~BT behind,
        # which confuses libguestfs OS detection ("file exited with status 1").
        # Mount the Windows partition explicitly (its index comes from the
        # profile's disk layout) and upload; no inspection required.
        win_part = f"/dev/sda{cfg.profile.install_partition_id}"
        _guestfish(cfg.disk_path, env, [
            f"mount {win_part} /",
            f"upload {zip_path} /provision.zip",
            f"upload {bootstrap_tmp} /bootstrap.ps1",
        ])

        if cfg.profile.disable_defender_offline:
            _disable_defender_offline(cfg, tmpdir_path, env, win_part)

    console.print("[green][+][/] Provision files injected")


def _guestfish(disk_path: Path, env: dict[str, str], commands: list[str]) -> None:
    """Run a read-write guestfish script against ``disk_path``.

    ``run`` is prepended automatically; ``commands`` are the guestfish
    statements that follow (e.g. ``mount``/``upload``/``download``). Raises
    :class:`RuntimeError` on a non-zero exit. Used instead of virt-customize /
    virt-win-reg because those auto-inspect the OS, and inspection fails on the
    Win11 install image.
    """
    script = "run\n" + "\n".join(commands) + "\n"
    result = subprocess.run(
        ["guestfish", "--rw", "-a", str(disk_path)],
        input=script, text=True, capture_output=True, env=env, check=False,
    )
    if result.returncode != 0:
        msg = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise RuntimeError(f"guestfish failed: {msg}")


def _disable_defender_offline(
    cfg: Config, tmpdir_path: Path, env: dict[str, str], win_part: str
) -> None:
    """Disable the Defender services in the offline SYSTEM hive (Start=4).

    Delegates to :mod:`winbox.offlinereg`, which is the same machinery
    ``winbox av disable`` uses at runtime — a client SKU can only have its
    Defender state changed while the VM is off, so build time and run time
    genuinely want the same operation.

    Best-effort here, unlike the runtime path: a build should not abort over
    this, and the caller is not a user who explicitly asked for it.
    """
    from winbox import defender, offlinereg

    console.print("[blue][*][/] Disabling Defender in the offline SYSTEM hive...")
    try:
        offlinereg.merge_hive(
            cfg.disk_path,
            hive=offlinereg.SYSTEM_HIVE,
            prefix="HKEY_LOCAL_MACHINE\\SYSTEM",
            reg_body=defender.DEFENDER_OFF_SYSTEM_REG,
            win_part=win_part,
        )
    except offlinereg.OfflineRegistryError as e:
        console.print(
            f"[yellow][!][/] Offline Defender disable failed: {e}\n"
            "    Best-effort step — continuing; Defender may stay active on Win11."
        )
        return
    console.print("[green][+][/] Defender services disabled in offline SYSTEM hive")


def _settle_firstlogon_boot(cfg: "Config", vm: VM, ga: GuestAgent) -> None:
    """Boot once to let Win11's re-triggered OOBE FirstLogonCommands settle.

    After the offline SYSTEM-hive Defender edit, Win11 re-runs its
    FirstLogonCommands on the next boot (reinstalling the guest agent, ending in
    ``shutdown /s``). We boot and wait for that shutdown; if instead the guest
    agent comes up and stays (the edit didn't re-trigger OOBE that time), we
    shut down cleanly. Either way the VM is left shut off, ready for a clean
    provisioning boot.
    """
    console.print("[blue][*][/] Settling OOBE FirstLogon boot...")
    vm.start()
    deadline = time.monotonic() + 1200
    ga_stable = 0
    while time.monotonic() < deadline:
        # is_off(), not state()==SHUTOFF: state() folds "crashed"/"in shutdown"
        # onto SHUTOFF, but a crashed guest still holds the qcow2 open. Treating
        # that as "settled, shut down" made the next vm.start() hit "already
        # active" and fail 20+ minutes later with a misleading GA-unreachable
        # error. is_off() stays False for a crash, so the deadline/force_stop
        # path below recovers it instead.
        if vm.is_off():
            console.print("[green][+][/] FirstLogon settled (VM shut down)")
            return
        try:
            ga.wait(timeout=5)
            ga_stable += 1
        except GuestAgentError:
            ga_stable = 0
        # GA up and steady for ~30s => this boot didn't re-run OOBE; stop it.
        if ga_stable >= 3:
            console.print("[green][+][/] Boot came up clean; shutting down to provision")
            try:
                ga.shutdown()
            except GuestAgentError:
                pass
            vm.wait_shutdown(timeout=120) or vm.force_stop()
            return
        time.sleep(10)
    # Timed out waiting for a stable state — force it off and proceed.
    console.print("[yellow][!][/] Settle boot didn't reach a stable state; forcing off")
    vm.force_stop()
    vm.wait_shutdown(timeout=60)


def boot_for_provisioning(cfg: Config) -> None:
    """Phase 3: Boot VM, run bootstrap.ps1 via guest agent, wait for shutdown.

    VirtIO-FS is configured in the VM definition but WinFsp isn't installed yet,
    so provisioning reads from C:\\Provision\\ (injected by virt-customize).
    The provision script installs WinFsp + VirtioFsSvc so Z: works after setup.

    After the bootstrap shutdown we boot the VM one more time and verify the
    provision sentinel exists — bootstrap.ps1's finally-block shutdown runs
    regardless of whether provision.ps1 parse-errored or crashed, so "VM shut
    down cleanly" is not by itself proof that anything actually got installed.
    """
    from winbox.setup.installer.finalize import _verify_provisioning

    vm = VM(cfg)
    ga = GuestAgent(cfg)

    # Win11: the offline Defender edit (SYSTEM hive) makes OOBE re-run its
    # FirstLogonCommands on the very next boot — they reinstall the guest agent
    # and end in `shutdown /s`. If we booted straight into provisioning we'd
    # race that shutdown. Do one throwaway "settle" boot first and let it
    # finish, so the real provisioning boot comes up clean.
    if cfg.profile.disable_defender_offline:
        _settle_firstlogon_boot(cfg, vm, ga)

    console.print("[blue][*][/] Booting VM for provisioning...")
    vm.start()

    # Win11's OOBE finalization ("Installing…", "Just a moment…") can spill
    # into this boot and pushes the guest agent past the old 180s window;
    # give it longer (returns as soon as the agent answers, so Server 2022
    # isn't slowed).
    console.print("[blue][*][/] Waiting for guest agent...")
    ga.wait(timeout=420)
    console.print("[green][+][/] Guest agent responding")

    console.print("[blue][*][/] Running bootstrap.ps1 via guest agent...")
    console.print("    This may take 5-10 minutes.")
    bootstrap_pid = ga.exec_detached(
        'powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\\bootstrap.ps1',
    )

    # Sanity probe: bootstrap.ps1's first action is `Start-Transcript -Path
    # C:\winbox-bootstrap.log -Force`, so the file appears within seconds of
    # PowerShell loading the script. If it doesn't show up in 30s, something
    # blocked the launch (corrupt file, ExecutionPolicy, no PowerShell on
    # PATH) and waiting the full 600s for shutdown is wasted time.
    console.print("[blue][*][/] Probing bootstrap launch...")
    launched = False
    for _ in range(15):
        time.sleep(2)
        # is_off(), not state()==SHUTOFF — a crashed bootstrap boot must not read
        # as "bootstrap finished and shut down cleanly" (see _settle_firstlogon_boot).
        if vm.is_off():
            launched = True
            break
        try:
            probe = ga.exec(
                "if exist C:\\winbox-bootstrap.log (echo OK) else (echo MISSING)",
                timeout=10,
            )
        except GuestAgentError:
            # VM may be rebooting or GA may be momentarily unreachable
            # mid-provision; keep polling.
            continue
        if "OK" in probe.stdout:
            launched = True
            break

    if not launched:
        raise RuntimeError(
            "bootstrap.ps1 did not start within 30s — no transcript log appeared.\n"
            f"    Check with: virsh console {cfg.vm_name}\n"
            "    Common causes: ExecutionPolicy block, corrupt provision.zip,\n"
            "    or PowerShell missing/broken in the install image."
        )

    console.print("[blue][*][/] Waiting for VM to shut down...")
    # Win11 provisioning (Python 3.13 + x64dbg + OpenSSH + WinFsp installs) runs
    # slower than Server 2022, so allow more headroom before declaring a hang.
    if not vm.wait_shutdown(timeout=900):
        console.print(
            f"[yellow][!][/] Provisioning timed out (VM did not shut down in 600s)"
        )
        console.print(
            f"    bootstrap.ps1 PID inside VM: {bootstrap_pid} "
            f"(check with: virsh console {cfg.vm_name})"
        )
        # Try a clean kill before force-stopping the whole VM, so the user
        # can grep the bootstrap log on the share without worrying about
        # the VM having been hard-yanked mid-write.
        try:
            ga.exec(f"taskkill /pid {bootstrap_pid} /f", timeout=10)
        except Exception:
            pass
        console.print("[blue][*][/] Force-stopping hung VM...")
        try:
            vm.force_stop()
        except Exception:
            pass
        raise RuntimeError("Provisioning timed out")

    _verify_provisioning(cfg, vm, ga)
    console.print("[green][+][/] Provisioning complete")
