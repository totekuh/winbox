"""MSI install command — copies an MSI into the VM and runs msiexec /i /qn."""

from __future__ import annotations

import shutil
from pathlib import Path

import click

from winbox.cli import console, ensure_running, needs_vm
from winbox.config import Config
from winbox.vm import GuestAgent
from winbox.vm import VM

# Subdir on the VirtIO-FS share used as a staging area. Appears as
# Z:\.msi\ inside the VM. Leading dot keeps it out of tool/loot counts.
_STAGING_SUBDIR = ".msi"

# msiexec exit codes that mean "the install worked":
#   0    = success
#   3010 = success, reboot required
_SUCCESS_EXITCODES = {0, 3010}


@click.command("msi", context_settings=dict(
    ignore_unknown_options=True,
    allow_interspersed_args=False,
))
@click.argument("msi_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("extra", nargs=-1, type=click.UNPROCESSED)
@click.option("--timeout", default=600, help="Install timeout in seconds.")
@needs_vm()
def msi(
    cfg: Config, vm: VM, ga: GuestAgent,
    msi_path: str, extra: tuple[str, ...], timeout: int,
) -> None:
    """Install an MSI package on the VM.

    Copies the MSI into C:\\Windows\\Temp via the VirtIO-FS share, runs
    msiexec /i /qn, then removes both copies. Extra arguments after the
    MSI path are passed through to msiexec verbatim (e.g. PROPERTY=value
    or /norestart).

    Exit codes 0 and 3010 (reboot required) are treated as success.
    """
    src = Path(msi_path).resolve()
    basename = src.name
    staging_dir = cfg.shared_dir / _STAGING_SUBDIR
    staging_dir.mkdir(parents=True, exist_ok=True)
    staged = staging_dir / basename
    guest_staged = f"Z:\\{_STAGING_SUBDIR}\\{basename}"
    guest_local = f"C:\\Windows\\Temp\\{basename}"

    console.print(f"[blue][*][/] Staging {basename} on VirtIO-FS...")
    shutil.copy2(src, staged)

    try:
        console.print(f"[blue][*][/] Copying to {guest_local}...")
        copy_result = ga.exec_argv(
            "cmd.exe",
            ["/c", "copy", "/Y", guest_staged, guest_local],
            timeout=60,
        )
        if copy_result.exitcode != 0:
            console.print("[red][-][/] Failed to copy MSI into the VM:")
            console.print(copy_result.stdout.strip(), markup=False, highlight=False)
            console.print(copy_result.stderr.strip(), markup=False, highlight=False, style="red")
            raise SystemExit(1)

        console.print(f"[blue][*][/] Running msiexec /i /qn {basename} {' '.join(extra)}".rstrip())
        result = ga.exec_argv(
            "msiexec.exe",
            ["/i", guest_local, "/qn", *extra],
            timeout=timeout,
        )

        if result.stdout:
            console.print(result.stdout, end="", markup=False, highlight=False)
        if result.stderr:
            console.print(result.stderr, end="", markup=False, highlight=False, style="red")

        if result.exitcode in _SUCCESS_EXITCODES:
            note = " (reboot required)" if result.exitcode == 3010 else ""
            console.print(f"[green][+][/] MSI installed{note}")
            exit_status = 0
        else:
            console.print(f"[red][-][/] msiexec failed (exit {result.exitcode})")
            exit_status = result.exitcode
    finally:
        # Always clean up, even if the install failed.
        try:
            ga.exec_argv(
                "cmd.exe",
                ["/c", "del", "/f", "/q", guest_local],
                timeout=15,
            )
        except Exception:
            pass  # best-effort cleanup
        staged.unlink(missing_ok=True)

    raise SystemExit(exit_status)
