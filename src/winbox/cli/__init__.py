"""winbox CLI — click entry point."""

from __future__ import annotations

import time

import click
from rich.console import Console

from winbox.config import Config
from winbox.vm import GuestAgent, GuestAgentError
from winbox.vm import VM, VMState

console = Console()


def ensure_running(vm: VM, ga: GuestAgent, cfg: Config) -> None:
    """Make sure the VM is running and guest agent responding."""
    state = vm.state()

    if state == VMState.NOT_FOUND:
        console.print("[red][-][/] VM not found. Run [bold]winbox setup[/] first.")
        raise SystemExit(1)

    if state == VMState.RUNNING:
        if not ga.ping():
            console.print("[blue][*][/] Waiting for guest agent...")
            try:
                ga.wait(timeout=60)
            except GuestAgentError:
                console.print("[red][-][/] Guest agent not responding. Is the VM healthy?")
                raise SystemExit(1)
        _ensure_z_drive(ga)
        _ensure_sshd_running(ga)
        return

    if state == VMState.SHUTOFF:
        console.print("[blue][*][/] VM is off, starting...")
        vm.start()
    elif state == VMState.PAUSED:
        console.print("[blue][*][/] VM is paused, resuming...")
        vm.resume()
    elif state == VMState.SAVED:
        console.print("[blue][*][/] Restoring saved VM state...")
        vm.start()
    else:
        console.print(f"[red][-][/] VM is in unexpected state: {state.value}")
        raise SystemExit(1)

    console.print("[blue][*][/] Waiting for guest agent...")
    try:
        ga.wait(timeout=120)
    except GuestAgentError:
        console.print("[red][-][/] Guest agent not responding. Is the VM healthy?")
        raise SystemExit(1)
    _ensure_z_drive(ga)
    _ensure_sshd_running(ga)
    console.print("[green][+][/] VM ready")


def _ensure_z_drive(ga: GuestAgent) -> None:
    """Verify the VirtIO-FS Z: drive is accessible (VirtioFsSvc auto-mounts it)."""
    # Kick the service in case it hasn't started yet
    try:
        ga.exec("net start VirtioFsSvc", timeout=10)
    except Exception:
        pass

    for _ in range(15):
        try:
            result = ga.exec("dir Z:", timeout=5)
            if result.exitcode == 0:
                return
        except Exception:
            pass
        time.sleep(1)
    console.print("[yellow][!][/] Z: drive may not be ready")


def _ensure_sshd_running(ga: GuestAgent) -> None:
    """Start sshd if it's not running."""
    try:
        ga.exec("net start sshd", timeout=10)
    except Exception:
        pass  # Best effort — ssh will fail with a clear error if sshd is down


# ─── CLI Group ───────────────────────────────────────────────────────────────


class GroupedCli(click.Group):
    """Click Group that renders commands in labeled sections in --help.

    New top-level commands that aren't listed in SECTIONS fall into an "Other"
    bucket — that's a loud signal to add them here rather than a silent drop.
    """

    SECTIONS: list[tuple[str, list[str]]] = [
        ("VM Lifecycle", ["setup", "up", "down", "suspend", "destroy", "status", "snapshot", "restore", "provision"]),
        ("Execute", ["exec", "shell", "ssh", "vnc", "jobs", "msi"]),
        ("Files", ["tools", "upload", "iso"]),
        ("Network", ["net", "dns", "hosts", "domain"]),
        ("Target", ["av", "applocker", "autologin"]),
        ("Integrations", ["binfmt", "mcp", "office"]),
    ]

    def format_commands(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        commands: dict[str, click.Command] = {}
        for name in self.list_commands(ctx):
            cmd = self.get_command(ctx, name)
            if cmd is None or cmd.hidden:
                continue
            commands[name] = cmd

        listed: set[str] = set()
        for section, names in self.SECTIONS:
            rows: list[tuple[str, str]] = []
            for name in names:
                cmd = commands.get(name)
                if cmd is None:
                    continue
                listed.add(name)
                rows.append((name, cmd.get_short_help_str(limit=80)))
            if rows:
                with formatter.section(section):
                    formatter.write_dl(rows)

        leftover = [n for n in commands if n not in listed]
        if leftover:
            rows = [(n, commands[n].get_short_help_str(limit=80)) for n in leftover]
            with formatter.section("Other"):
                formatter.write_dl(rows)


@click.group(cls=GroupedCli)
@click.version_option(package_name="winbox")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """winbox — Transparent Windows execution proxy for Kali."""
    ctx.ensure_object(dict)
    ctx.obj["cfg"] = Config.load()


# ─── Register subcommands ────────────────────────────────────────────────────

from winbox.cli.vm import up, down, suspend, destroy, status, snapshot, restore, vnc  # noqa: E402
from winbox.cli.setup import setup, provision  # noqa: E402
from winbox.cli.exec import exec_cmd, shell, ssh  # noqa: E402
from winbox.cli.network import dns, domain, hosts, net  # noqa: E402
from winbox.cli.files import tools, iso  # noqa: E402
from winbox.cli.binfmt import binfmt  # noqa: E402
from winbox.cli.jobs import jobs  # noqa: E402
from winbox.cli.office import office  # noqa: E402
from winbox.cli.av import av  # noqa: E402
from winbox.cli.applocker import applocker  # noqa: E402
from winbox.cli.autologin import autologin  # noqa: E402
from winbox.cli.msi import msi  # noqa: E402
from winbox.cli.upload import upload  # noqa: E402
from winbox.cli.mcp import mcp_cmd  # noqa: E402

cli.add_command(up)
cli.add_command(down)
cli.add_command(suspend)
cli.add_command(destroy)
cli.add_command(status)
cli.add_command(snapshot)
cli.add_command(restore)
cli.add_command(setup)
cli.add_command(provision)
cli.add_command(exec_cmd)
cli.add_command(shell)
cli.add_command(ssh)
cli.add_command(dns)
cli.add_command(domain)
cli.add_command(hosts)
cli.add_command(net)
cli.add_command(tools)
cli.add_command(iso)
cli.add_command(binfmt)
cli.add_command(jobs)
cli.add_command(vnc)
cli.add_command(office)
cli.add_command(av)
cli.add_command(applocker)
cli.add_command(autologin)
cli.add_command(msi)
cli.add_command(upload)
cli.add_command(mcp_cmd)
