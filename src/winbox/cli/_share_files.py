"""Share filesystem operations — ls, mkdir, write, rm."""

from __future__ import annotations

import base64
import shutil
from pathlib import Path

import click

from winbox.cli import console, needs_vm
from winbox.cli.share import share, _validate_share_name, _validate_relative_path, _guarded_path_script
from winbox.config import Config
from winbox.ps import ps_quote
from winbox.vm import GuestAgent, VM


@share.command("ls")
@click.argument("name")
@click.argument("path", default="")
@needs_vm()
def share_ls(cfg: Config, vm: VM, ga: GuestAgent, name: str, path: str) -> None:
    """List files inside a share.

    \b
    Examples:
        winbox share ls Data
        winbox share ls Data subdir/nested
    """
    _validate_share_name(name)

    if path:
        relpath = _validate_relative_path(path)
        script = _guarded_path_script(
            name, relpath,
            "Get-ChildItem -Path $full | "
            "Format-Table Name,Length,LastWriteTime -AutoSize | "
            "Out-String -Width 200",
        )
    else:
        script = (
            f"$base = (Get-SmbShare -Name '{ps_quote(name)}' -ErrorAction Stop).Path\n"
            "Get-ChildItem -Path $base | "
            "Format-Table Name,Length,LastWriteTime -AutoSize | "
            "Out-String -Width 200"
        )

    result = ga.exec_powershell(script, timeout=30)
    if result.exitcode != 0:
        console.print(f"[red][-][/] {result.stderr.strip()}")
        raise SystemExit(1)

    output = result.stdout.strip()
    if not output:
        console.print("(empty)")
        return
    console.print(output, highlight=False)


@share.command("mkdir")
@click.argument("name")
@click.argument("path")
@needs_vm()
def share_mkdir(cfg: Config, vm: VM, ga: GuestAgent, name: str, path: str) -> None:
    """Create a directory inside a share.

    \b
    Example: winbox share mkdir Data reports/2024
    """
    _validate_share_name(name)
    relpath = _validate_relative_path(path)

    script = _guarded_path_script(
        name, relpath,
        "New-Item -ItemType Directory -Path $full -Force | Out-Null\n"
        "Write-Host $full",
    )

    result = ga.exec_powershell(script, timeout=30)
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to create directory: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] Created {result.stdout.strip()}")


@share.command("write")
@click.argument("name")
@click.argument("path")
@click.option("--content", help="Inline text content to write.")
@click.option("--source", type=click.Path(exists=True, dir_okay=False),
              help="Upload a file from Kali.")
@needs_vm()
def share_write(
    cfg: Config,
    vm: VM,
    ga: GuestAgent,
    name: str,
    path: str,
    content: str | None,
    source: str | None,
) -> None:
    """Write a file inside a share.

    Provide either --content for inline text or --source to upload from Kali.

    \b
    Examples:
        winbox share write Data config.ini --content "[db]\\nhost=10.0.0.1"
        winbox share write Data tools/mimikatz.exe --source /opt/tools/mimikatz.exe
    """
    if content is None and source is None:
        raise click.UsageError("Provide either --content or --source")
    if content is not None and source is not None:
        raise click.UsageError("--content and --source are mutually exclusive")

    _validate_share_name(name)
    relpath = _validate_relative_path(path)

    if content is not None:
        content_b64 = base64.b64encode(content.encode()).decode()
        script = _guarded_path_script(
            name, relpath,
            "$dir = Split-Path $full -Parent\n"
            "if ($dir -and -not (Test-Path $dir)) {{ New-Item -ItemType Directory -Path $dir -Force | Out-Null }}\n"
            f"$bytes = [Convert]::FromBase64String('{content_b64}')\n"
            "[IO.File]::WriteAllBytes($full, $bytes)\n"
            "Write-Host $full",
        )
        result = ga.exec_powershell(script, timeout=30)
        if result.exitcode != 0:
            console.print(f"[red][-][/] Failed to write file: {result.stderr.strip()}")
            raise SystemExit(1)
        console.print(f"[green][+][/] Written {result.stdout.strip()}")

    else:
        src_path = Path(source)
        cfg.shared_dir.mkdir(parents=True, exist_ok=True)
        staged = cfg.shared_dir / src_path.name
        shutil.copy2(src_path, staged)

        vm_staged = f"Z:\\{src_path.name}"
        script = _guarded_path_script(
            name, relpath,
            "$dir = Split-Path $full -Parent\n"
            "if ($dir -and -not (Test-Path $dir)) {{ New-Item -ItemType Directory -Path $dir -Force | Out-Null }}\n"
            f"Copy-Item -Path '{ps_quote(vm_staged)}' -Destination $full -Force -ErrorAction Stop\n"
            "Write-Host $full",
        )
        result = ga.exec_powershell(script, timeout=60)
        staged.unlink(missing_ok=True)
        if result.exitcode != 0:
            console.print(f"[red][-][/] Failed to write file: {result.stderr.strip()}")
            raise SystemExit(1)
        console.print(f"[green][+][/] Uploaded {src_path.name} to {result.stdout.strip()}")


@share.command("rm")
@click.argument("name")
@click.argument("path")
@needs_vm()
def share_rm(cfg: Config, vm: VM, ga: GuestAgent, name: str, path: str) -> None:
    """Delete a file or directory inside a share.

    \b
    Example: winbox share rm Data old-reports
    """
    _validate_share_name(name)
    relpath = _validate_relative_path(path)

    script = _guarded_path_script(
        name, relpath,
        "Remove-Item -Path $full -Recurse -Force -ErrorAction Stop\n"
        "Write-Host $full",
    )

    result = ga.exec_powershell(script, timeout=30)
    if result.exitcode != 0:
        console.print(f"[red][-][/] Failed to remove: {result.stderr.strip()}")
        raise SystemExit(1)
    console.print(f"[green][+][/] Removed {result.stdout.strip()}")
