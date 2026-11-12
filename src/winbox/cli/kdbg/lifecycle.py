"""Stub lifecycle, status, doctor, and CET commands."""

from __future__ import annotations

import click

from winbox.cli import console, needs_vm
from winbox.cli.kdbg import kdbg, _hmp, _cheat_sheet
from winbox.config import Config
from winbox.vm import VM, GuestAgent, VMState
from winbox.kdbg.debugger import DaemonClient
from winbox.kdbg.debugger.reader import reader_info, stop_reader
from winbox.kdbg.hmp import probe_port
from winbox.kdbg.cet import (
    CetSafetyError,
    format_status as format_cet_status,
    prepare as prepare_cet,
    query_status as query_cet_status,
    restore as restore_cet_policy,
)
from winbox.kdbg.doctor import collect_doctor
from winbox import __version__
from winbox.kdbg.catalog import MCP_CATALOG_REVISION, MCP_TOOL_COUNT


@kdbg.command("start")
@click.option("--port", default=1234, show_default=True, help="TCP port for the gdb stub.")
@click.option(
    "--any-interface", is_flag=True,
    help="Bind to 0.0.0.0 instead of 127.0.0.1. Exposes full kernel r/w to the LAN — opt-in only.",
)
@click.pass_context
def kdbg_start(ctx: click.Context, port: int, any_interface: bool) -> None:
    """Start the QEMU gdb stub on the running VM.

    Hypervisor-level — the guest kernel never learns a debugger is attached.
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)

    if vm.state() != VMState.RUNNING:
        console.print(f"[yellow][!][/] VM is not running (state: {vm.state().value})")
        raise SystemExit(1)

    bind = "0.0.0.0" if any_interface else "127.0.0.1"
    device = f"tcp:{bind}:{port}"

    active_reader = reader_info(cfg)
    if active_reader is not None:
        owned_port = active_reader.get("port", 1234)
        console.print(
            f"[yellow][!][/] Persistent kdbg reader already owns the gdbstub "
            f"on port {owned_port}. Run [bold]winbox kdbg stop[/] first."
        )
        raise SystemExit(1)

    # Refuse to double-start — QEMU will happily try to bind again and error
    # in HMP output, which is ugly. Fail fast with a clearer message.
    if probe_port("127.0.0.1", port):
        console.print(f"[yellow][!][/] Something is already listening on 127.0.0.1:{port}")
        console.print("    Run [bold]winbox kdbg stop[/] first, or pick a different [bold]--port[/].")
        raise SystemExit(1)

    rc, out, err = _hmp(cfg.vm_name, f"gdbserver {device}")
    if rc != 0:
        console.print(f"[red][-][/] Failed to start gdb stub: {err or out}")
        raise SystemExit(1)

    # HMP prints "Waiting for gdb connection on device '<device>'" on success
    if "Waiting for gdb connection" not in out:
        console.print(f"[red][-][/] Unexpected HMP response: {out}")
        raise SystemExit(1)

    if any_interface:
        console.print(
            f"[yellow][!][/] [bold]Bound to 0.0.0.0:{port}[/] — "
            "anyone on this LAN can attach and control the guest kernel."
        )
    console.print(f"[green][+][/] gdb stub listening on {bind}:{port}")
    _cheat_sheet(port)


@kdbg.command("stop")
@click.pass_context
def kdbg_stop(ctx: click.Context) -> None:
    """Stop the QEMU gdb stub. Any attached gdb session gets EOF."""
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)

    if vm.state() != VMState.RUNNING:
        console.print(f"[yellow][!][/] VM is not running (state: {vm.state().value})")
        raise SystemExit(1)

    # The persistent reader owns QEMU's only RSP client. Release it before
    # asking QMP to remove the listening gdbserver chardev.
    stop_reader(cfg)
    rc, out, err = _hmp(cfg.vm_name, "gdbserver none")
    if rc != 0:
        console.print(f"[red][-][/] Failed to stop gdb stub: {err or out}")
        raise SystemExit(1)

    console.print("[green][+][/] gdb stub stopped")


@kdbg.command("pagewalk")
@click.argument("state", type=click.Choice(["on", "off", "status"]), default="status")
@click.pass_context
def kdbg_pagewalk(ctx: click.Context, state: str) -> None:
    """Toggle manual page-table walk mode for virtual memory reads.

    When ON, kdbg translates virtual addresses by walking x86-64 page
    tables through physical memory reads instead of relying on QEMU's
    gdbstub VA translation. Fixes E14 errors on KVM with Hyper-V
    enlightenments where the gdbstub cannot translate kernel VAs.
    """
    cfg: Config = ctx.obj["cfg"]
    if state == "status":
        mode = "ON" if cfg.kdbg_pagewalk else "OFF"
        console.print(f"pagewalk mode: [bold]{mode}[/bold]")
        return
    enabled = state == "on"
    cfg.persist("KDBG_PAGEWALK", "1" if enabled else "0")
    mode = "ON" if enabled else "OFF"
    console.print(f"[green][+][/] pagewalk mode set to [bold]{mode}[/bold]")
    console.print("Restart kdbg reader for the change to take effect.")


@kdbg.command("status")
@click.option("--port", default=1234, show_default=True, help="Port to probe.")
@click.pass_context
def kdbg_status(ctx: click.Context, port: int) -> None:
    """Show whether the gdb stub is listening, and whether kdbg holds it.

    Read-only in the strict sense: the listening check reads /proc rather
    than connecting, because QEMU's gdbstub halts the guest CPU as soon as a
    client attaches — a status command must not do that.
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)

    state = vm.state()
    if state != VMState.RUNNING:
        console.print(f"[yellow][!][/] VM is not running (state: {state.value})")
        if state == VMState.PAUSED:
            console.print(
                "    If a debug session left it paused: [bold]winbox kdbg resume[/]"
            )
        return

    active_reader = reader_info(cfg)
    if active_reader is not None:
        owned_port = active_reader.get("port", port)
        console.print(
            f"gdb stub: [green]connected[/] on 127.0.0.1:{owned_port} "
            "(persistent reader owns it)"
        )
        return

    if not probe_port("127.0.0.1", port):
        console.print(f"gdb stub: [red]not running[/] (nothing on 127.0.0.1:{port})")
        return

    console.print(f"gdb stub: [green]listening[/] on 127.0.0.1:{port}")
    if DaemonClient(cfg).session_alive():
        console.print("  a winbox kdbg session is attached — [bold]winbox kdbg session[/]")


@kdbg.command("cet-status")
@needs_vm()
def kdbg_cet_status(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Report whether this Windows boot is safe for QEMU debugging."""
    try:
        status = query_cet_status(ga)
    except CetSafetyError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    colour = "green" if status.safe_for_debug else "red"
    rendered = format_cet_status(status)
    state, rest = rendered.split(": ", 1)
    console.print(f"[{colour}]{state}[/]: {rest}")


@kdbg.command("doctor")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-safe JSON.")
@click.option("--verbose", is_flag=True, help="Show active admission and recent metadata-only operations.")
@click.option("--port", default=1234, show_default=True, help="GDB stub port to inspect.")
@click.pass_context
def kdbg_doctor(ctx: click.Context, as_json: bool, verbose: bool, port: int) -> None:
    """Report kdbg readiness without attaching to or stopping the guest."""
    import json as _json

    cfg: Config = ctx.obj["cfg"]
    report = collect_doctor(
        cfg, VM(cfg), GuestAgent(cfg), port=port,
        catalog_revision=MCP_CATALOG_REVISION,
        tool_count=MCP_TOOL_COUNT,
        version=__version__,
    )
    if as_json:
        click.echo(_json.dumps(report, indent=2))
        return

    status = "[green]ready[/]" if report["ready"] else "[yellow]not ready[/]"
    vm = report["vm"]
    agent = report["guest_agent"]
    symbols = report["symbols"]["nt"]
    debugger = report["debugger"]
    console.print(f"kdbg doctor: {status}")
    console.print(f"  VM: {vm['name']} ({vm['state']})")
    console.print(f"  agent: {'responding' if agent['responding'] else 'unavailable'}")
    console.print(f"  CET: {report['cet']['summary'] or report['cet']['error'] or 'not checked'}")
    console.print(
        f"  symbols: {'nt ' + str(symbols['build']) if symbols['available'] else 'not loaded'} "
        f"({symbols['identity']}; live base {symbols['live_base']})"
    )
    console.print(
        f"  debugger: {debugger['state']}"
        f"{(' (' + str(debugger['owner']) + ')') if debugger['owner'] else ''}"
    )
    mcp = report["mcp"]
    console.print(f"  MCP: {mcp['version']} / {mcp['catalog_revision']} ({mcp['tool_count']} tools)")
    decomp = report["decomp"]
    decomp_status = "ready" if decomp["available"] else f"unavailable — {decomp['reason']}"
    console.print(f"  decomp: {decomp_status}")
    if decomp.get("next_action"):
        console.print(f"    next: {decomp['next_action']}")
    runtime = report["runtime"]
    if not runtime["version_consistent"]:
        console.print(
            "[yellow][!][/] runtime/distribution/source versions differ; "
            "reload or reinstall before trusting a stale catalog[/]"
        )
    capabilities = report["capabilities"]
    console.print(
        "  capabilities: " + ", ".join(
            f"{name}={'yes' if item['available'] else 'no'}"
            for name, item in capabilities.items()
        )
    )
    operations = report["operations"]
    timing = operations["stop_duration_ms"]
    console.print(
        f"  recent operations: {operations['record_count']}/{operations['retention']} "
        f"(stop p50={timing['p50']} ms p95={timing['p95']} ms)"
    )
    captures = report["captures"]
    console.print(f"  captures: {captures['count']}")
    if verbose:
        active = debugger.get("reader", {}) or {}
        if active.get("snapshot"):
            console.print(f"  active snapshot admission: {active['snapshot']}")
        for record in operations["recent"]:
            snapshot = record.get("snapshot", {})
            console.print(
                f"    {record.get('at')} {record.get('operation')} {record.get('outcome')} "
                f"{snapshot.get('stop_duration_ms')}ms/{snapshot.get('read_count')} reads"
            )


@kdbg.command("prepare")
@click.option(
    "--confirm", is_flag=True,
    help="Confirm disabling Windows shadow stacks and the VM cet-ss CPU feature.",
)
@needs_vm()
def kdbg_prepare(cfg: Config, vm: VM, ga: GuestAgent, confirm: bool) -> None:
    """Prepare the VM for stable QEMU debugging; requires a reboot."""
    if not confirm:
        console.print(
            "[yellow][!][/] This disables Windows CET user shadow stacks and "
            "hides the VM cet-ss CPU feature. "
            "Re-run with --confirm, then reboot the VM."
        )
        raise SystemExit(1)
    stop_reader(cfg)
    try:
        backup = prepare_cet(cfg, ga)
    except CetSafetyError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    if backup is None:
        console.print("[green][+][/] CET is disabled for every running process; debugger is safe")
    else:
        console.print(f"[green][+][/] CET policy staged; original saved at {backup}")
        console.print("[yellow][!][/] Reboot the VM before using kdbg")


@kdbg.command("restore-cet")
@click.option(
    "--confirm", is_flag=True,
    help="Confirm restoring the original Windows CET mitigation policy.",
)
@needs_vm()
def kdbg_restore_cet(cfg: Config, vm: VM, ga: GuestAgent, confirm: bool) -> None:
    """Restore the CET policy saved by ``kdbg prepare``; requires reboot."""
    if not confirm:
        console.print("[yellow][!][/] Re-run with --confirm to restore CET policy")
        raise SystemExit(1)
    stop_reader(cfg)
    try:
        restore_cet_policy(cfg, ga)
    except CetSafetyError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    console.print("[green][+][/] Original CET policy restored")
    console.print("[yellow][!][/] Reboot the VM for the restored policy to take effect")
