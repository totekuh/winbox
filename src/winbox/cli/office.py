"""Office installation command."""

from __future__ import annotations

import importlib.resources
from pathlib import Path

import click

from winbox.cli import console, ensure_running
from winbox.config import Config
from winbox.vm import GuestAgent, VM

ODT_URL = "https://officecdn.microsoft.com/pr/wsus/setup.exe"


def _data_file(name: str) -> Path:
    return importlib.resources.files("winbox.data").joinpath(name)  # type: ignore[return-value]


@click.command()
@click.pass_context
def office(ctx: click.Context) -> None:
    """Install Microsoft Office with macros enabled (needs --desktop VM)."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    ensure_running(vm, ga, cfg)

    # Copy config XML to shared dir so VM can read it as Z:\office-config.xml
    src = _data_file("office-config.xml")
    dst = cfg.shared_dir / "office-config.xml"
    dst.write_bytes(Path(src).read_bytes())

    try:
        # Download ODT setup.exe into VM
        console.print("[blue][*][/] Downloading Office Deployment Tool...")
        result = ga.exec_powershell(
            "New-Item -Path C:\\Office -ItemType Directory -Force | Out-Null\n"
            f"Invoke-WebRequest -Uri '{ODT_URL}' -OutFile 'C:\\Office\\setup.exe'",
            timeout=120,
        )
        if result.exitcode != 0:
            console.print("[red][-][/] Failed to download ODT")
            if result.stderr:
                console.print(result.stderr, style="red", highlight=False)
            raise SystemExit(1)
        console.print("[green][+][/] ODT downloaded")

        # Install Office (downloads from CDN + installs in one step)
        console.print("[blue][*][/] Installing Office (this takes 20-40 minutes)...")
        result = ga.exec(
            "C:\\Office\\setup.exe /configure Z:\\office-config.xml",
            timeout=3600,
        )
        if result.exitcode != 0:
            console.print("[red][-][/] Office installation failed")
            if result.stderr:
                console.print(result.stderr, style="red", highlight=False)
            raise SystemExit(1)
        console.print("[green][+][/] Office installed")

        # Enable macros for Word, Excel, PowerPoint
        console.print("[blue][*][/] Enabling macros...")
        ga.exec_powershell("""
$apps = @('Word', 'Excel', 'PowerPoint')
foreach ($app in $apps) {
    $p = "HKCU:\\Software\\Microsoft\\Office\\16.0\\$app\\Security"
    New-Item -Path $p -Force | Out-Null
    Set-ItemProperty -Path $p -Name VBAWarnings -Value 1 -Type DWord
}
""")
        console.print("[green][+][/] Macros enabled (Word, Excel, PowerPoint)")

    finally:
        # Clean up ODT files from VM and config from share
        ga.exec_powershell(
            "Remove-Item -Path C:\\Office -Recurse -Force -ErrorAction SilentlyContinue",
            timeout=60,
        )
        dst.unlink(missing_ok=True)
