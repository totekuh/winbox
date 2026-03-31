"""Office installation command."""

from __future__ import annotations

import importlib.resources
import subprocess
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

    # Verify Desktop Experience is available (Office needs it)
    result = ga.exec("where explorer.exe", timeout=30)
    if result.exitcode != 0:
        raise click.ClickException(
            "Office requires Desktop Experience. Rebuild VM with: winbox setup --desktop -y"
        )

    # Copy config XML to shared dir so VM can read it as Z:\office-config.xml
    src = _data_file("office-config.xml")
    dst = cfg.shared_dir / "office-config.xml"
    with importlib.resources.as_file(src) as src_path:
        dst.write_bytes(src_path.read_bytes())

    # Download ODT on host, copy to shared dir for VM access
    odt_path = cfg.shared_dir / "odt-setup.exe"

    try:
        if not odt_path.exists():
            console.print("[blue][*][/] Downloading Office Deployment Tool...")
            try:
                subprocess.run(
                    ["wget", "-q", "-O", str(odt_path), ODT_URL],
                    check=True,
                )
            except subprocess.CalledProcessError:
                raise click.ClickException("Failed to download ODT setup.exe")
        console.print("[green][+][/] ODT ready")

        # Install Office (downloads from CDN + installs in one step)
        console.print("[blue][*][/] Installing Office (this takes 20-40 minutes)...")
        result = ga.exec(
            "Z:\\odt-setup.exe /configure Z:\\office-config.xml",
            timeout=3600,
        )
        if result.exitcode != 0:
            console.print("[red][-][/] Office installation failed")
            if result.stderr:
                console.print(result.stderr, style="red", markup=False, highlight=False)
            raise SystemExit(1)
        console.print("[green][+][/] Office installed")

        # Enable macros for Word, Excel, PowerPoint
        console.print("[blue][*][/] Enabling macros...")
        result = ga.exec_powershell("""
$apps = @('Word', 'Excel', 'PowerPoint')
foreach ($app in $apps) {
    $p = "HKCU:\\Software\\Microsoft\\Office\\16.0\\$app\\Security"
    New-Item -Path $p -Force | Out-Null
    Set-ItemProperty -Path $p -Name VBAWarnings -Value 1 -Type DWord
}
""")
        if result.exitcode != 0:
            console.print("[yellow][!][/] Warning: macro registry keys may not have been set")
        else:
            console.print("[green][+][/] Macros enabled (Word, Excel, PowerPoint)")

    finally:
        # Clean up host-side files from shared dir
        for f in ["odt-setup.exe", "office-config.xml"]:
            (cfg.shared_dir / f).unlink(missing_ok=True)
