"""File upload command — copies a local file (or directory) into the VM.

Two modes:
  winbox upload <src>         -> copies to Z:\\<basename> and leaves it there
  winbox upload <src> <dst>   -> also copies from Z:\\ to the given Windows path
                                 (creating parent dirs if needed)

With ``-r``, SRC may be a directory — the tree is staged on the VirtIO-FS
share and (if DST is given) copied recursively inside the VM.

Mirrors the MCP ``upload`` tool so the CLI and AI agents use the same
primitive. For dropping tools permanently, prefer ``winbox tools add``
which targets ``Z:\\tools\\`` specifically.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import click

from winbox.cli import console, ensure_running, needs_vm
from winbox.config import Config
from winbox.vm import GuestAgent
from winbox.vm import VM


from winbox.ps import ps_quote as _ps_quote  # canonical, no local copy


def _stage_file(src_path: Path, staged: Path) -> int:
    """Copy a single file to the staging area. Returns size in bytes."""
    staged.parent.mkdir(parents=True, exist_ok=True)
    if src_path != staged.resolve():
        shutil.copy2(src_path, staged)
    return staged.stat().st_size


def _stage_directory(src_path: Path, staged: Path) -> tuple[int, int]:
    """Copy a directory tree to the staging area. Returns (file_count, total_bytes)."""
    if staged.exists():
        shutil.rmtree(staged)
    shutil.copytree(src_path, staged)
    count = 0
    total = 0
    for f in staged.rglob("*"):
        if f.is_file():
            count += 1
            total += f.stat().st_size
    return count, total


@click.command("upload")
@click.argument("src", type=click.Path(exists=True, readable=True))
@click.argument("dst", required=False)
@click.option("-r", "--recursive", is_flag=True,
              help="Upload a directory recursively.")
@click.option("--timeout", default=60, help="VM-side copy timeout in seconds.")
@needs_vm()
def upload(
    cfg: Config, vm: VM, ga: GuestAgent,
    src: str, dst: str | None, recursive: bool, timeout: int,
) -> None:
    """Upload a file (or directory with -r) from Kali to the Windows VM.

    Without DST, the file lands at Z:\\<basename> on the VirtIO-FS share
    and stays there. With DST, it's also copied from Z:\\ to the given
    Windows path inside the VM (parent dirs are created if needed).

    Use ``winbox tools add`` instead if you want the file to live in the
    shared tools dir permanently.
    """
    src_path = Path(src).resolve()
    basename = src_path.name

    if src_path.is_dir() and not recursive:
        raise click.UsageError(
            f"'{src}' is a directory. Use -r/--recursive to upload directories."
        )
    if not src_path.is_dir() and recursive:
        raise click.UsageError(
            f"'{src}' is a file, not a directory. Drop -r."
        )

    cfg.shared_dir.mkdir(parents=True, exist_ok=True)
    staged = cfg.shared_dir / basename

    if recursive:
        console.print(f"[blue][*][/] Staging {basename}/ on VirtIO-FS...")
        count, total = _stage_directory(src_path, staged)
        console.print(
            f"[blue][*][/] Staged {count} files ({total} bytes)"
        )

        if dst is None:
            console.print(
                f"[green][+][/] Uploaded [bold]{basename}/[/] to Z:\\{basename}\\"
            )
            return

        guest_staged = f"Z:\\{basename}"
        script = (
            f"$src = '{_ps_quote(guest_staged)}'\n"
            f"$dst = '{_ps_quote(dst)}'\n"
            "New-Item -ItemType Directory -Path $dst -Force | Out-Null\n"
            "Copy-Item -Path \"$src\\*\" -Destination $dst -Recurse -Force\n"
        )

        console.print(f"[blue][*][/] Copying to {dst}...")
        result = ga.exec_powershell(script, timeout=timeout)

        if result.exitcode != 0:
            console.print(
                f"[yellow][!][/] Staged at Z:\\{basename}\\ but copy to {dst} failed:"
            )
            if result.stdout:
                console.print(result.stdout.strip(), markup=False, highlight=False)
            if result.stderr:
                console.print(result.stderr.strip(), markup=False, highlight=False, style="red")
            raise SystemExit(result.exitcode or 1)

        console.print(
            f"[green][+][/] Uploaded [bold]{basename}/[/] -> {dst} ({count} files, {total} bytes)"
        )
    else:
        console.print(f"[blue][*][/] Staging {basename} on VirtIO-FS...")
        size = _stage_file(src_path, staged)

        if dst is None:
            console.print(
                f"[green][+][/] Uploaded [bold]{basename}[/] to Z:\\{basename} ({size} bytes)"
            )
            return

        guest_staged = f"Z:\\{basename}"
        script = (
            f"$src = '{_ps_quote(guest_staged)}'\n"
            f"$dst = '{_ps_quote(dst)}'\n"
            "$parent = Split-Path -Parent $dst\n"
            "if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }\n"
            "Copy-Item -Path $src -Destination $dst -Force\n"
        )

        console.print(f"[blue][*][/] Copying to {dst}...")
        result = ga.exec_powershell(script, timeout=timeout)

        if result.exitcode != 0:
            console.print(
                f"[yellow][!][/] Staged at Z:\\{basename} but copy to {dst} failed:"
            )
            if result.stdout:
                console.print(result.stdout.strip(), markup=False, highlight=False)
            if result.stderr:
                console.print(result.stderr.strip(), markup=False, highlight=False, style="red")
            raise SystemExit(result.exitcode or 1)

        console.print(
            f"[green][+][/] Uploaded [bold]{basename}[/] -> {dst} ({size} bytes)"
        )


REGISTER = ("Files", [upload])
