"""File upload command — copies a local file into the VM.

Two modes:
  winbox upload <src>         -> copies to Z:\\<basename> and leaves it there
  winbox upload <src> <dst>   -> also copies from Z:\\ to the given Windows path
                                 (creating parent dirs if needed)

Mirrors the MCP ``upload`` tool so the CLI and AI agents use the same
primitive. For dropping tools permanently, prefer ``winbox tools add``
which targets ``Z:\\tools\\`` specifically.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import click

from winbox.cli import console, ensure_running
from winbox.config import Config
from winbox.vm import GuestAgent
from winbox.vm import VM


def _ps_quote(s: str) -> str:
    """Escape a string for inclusion inside a PowerShell single-quoted literal."""
    return s.replace("'", "''")


@click.command("upload")
@click.argument("src", type=click.Path(exists=True, dir_okay=False, readable=True))
@click.argument("dst", required=False)
@click.option("--timeout", default=60, help="VM-side copy timeout in seconds.")
@click.pass_context
def upload(ctx: click.Context, src: str, dst: str | None, timeout: int) -> None:
    """Upload a file from Kali to the Windows VM.

    Without DST, the file lands at Z:\\<basename> on the VirtIO-FS share
    and stays there. With DST, it's also copied from Z:\\ to the given
    Windows path inside the VM (parent dirs are created if needed).

    Use ``winbox tools add`` instead if you want the file to live in the
    shared tools dir permanently.
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)

    src_path = Path(src).resolve()
    basename = src_path.name
    staged = cfg.shared_dir / basename

    console.print(f"[blue][*][/] Staging {basename} on VirtIO-FS...")
    cfg.shared_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src_path, staged)
    size = staged.stat().st_size

    if dst is None:
        console.print(
            f"[green][+][/] Uploaded [bold]{basename}[/] to Z:\\{basename} ({size} bytes)"
        )
        return

    # Copy from Z:\ to the final destination inside the VM. PowerShell handles
    # parent-dir creation cleanly; we single-quote both paths and escape any
    # embedded quotes to avoid injection surprises.
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
