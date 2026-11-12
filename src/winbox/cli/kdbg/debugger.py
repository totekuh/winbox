"""Daemon-backed interactive debugger — attach, session, target-status."""

from __future__ import annotations

import click

from winbox.cli import console
from winbox.cli.kdbg import kdbg
from winbox.config import Config
from winbox.kdbg import SymbolStore
from winbox.kdbg.debugger import (
    ClientError,
    DaemonClient,
    DaemonError,
    RspClient,
    RspError,
    fork_daemon,
    masquerade_cr3_candidates,
)
from winbox.kdbg.debugger.reader import reader_info, stop_reader
from winbox.kdbg.hmp import probe_port
from winbox.vm import VM, GuestAgent, VMState


def _client(cfg: Config) -> DaemonClient:
    return DaemonClient(cfg)


def _print_stop(reason: str, info: dict) -> None:
    """Render a stop summary returned by cont/step."""
    if reason == "timeout":
        console.print("[yellow][!][/] cont timed out (no hit in target)")
        liveness = info.get("target_liveness")
        if isinstance(liveness, dict):
            console.print(
                f"    target={liveness.get('state', 'unknown')} "
                f"({liveness.get('reason', 'no evidence')})"
            )
        return
    if reason == "interrupt":
        console.print("[yellow][!][/] interrupted")
    elif reason == "step":
        console.print("[dim]stepped[/]")
    elif reason == "bp":
        bp_id = info.get("bp_id")
        target = info.get("bp_target")
        tag = f" [bold green](bp #{bp_id} {target})[/]" if bp_id is not None else ""
        console.print(f"[green][+][/] HIT in target{tag}")
    elif reason == "signal":
        console.print(f"[yellow][!][/] signal {info.get('signal', '?')}")
    if "rip" in info:
        console.print(f"    vCPU={info['vcpu']} RIP={info['rip']} CR3={info['cr3']}")


@kdbg.command("attach")
@click.argument("pid", type=int)
@click.option("--port", default=1234, show_default=True,
              help="gdbstub port the daemon will connect to.")
@click.option(
    "--staging-policy", type=click.Choice(("full", "binaries", "cached-only")),
    default="full", show_default=True,
    help="Artifact work before attach; full preserves complete unwind quality.",
)
@click.option(
    "--preflight", is_flag=True,
    help="Print a bounded staging plan without copying artifacts or attaching.",
)
@click.option(
    "--prewarm", is_flag=True,
    help="Start offline Ghidra analysis in the background after attach.",
)
@click.option(
    "--apply-intents", is_flag=True,
    help="Explicitly resolve and install saved module-relative breakpoint intents.",
)
@click.pass_context
def kdbg_attach(
    ctx: click.Context, pid: int, port: int, staging_policy: str,
    preflight: bool, prewarm: bool, apply_intents: bool,
) -> None:
    """Attach a kdbg debugging session to PID via the gdbstub.

    Forks a daemon that holds the gdb connection alive across CLI
    invocations. Subsequent ``winbox kdbg bp / cont / regs / mem / bt
    / detach`` commands talk to it via Unix socket. Only one session
    can be active at a time (enforced by an fcntl lock).

    Requires:
      - VM running, gdbstub started (``winbox kdbg start``)
      - nt symbols loaded (``winbox kdbg symbols``)

    Exact user binaries and available PDB metadata are staged automatically
    before the daemon takes ownership of QEMU's single RSP connection.
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    if vm.state() != VMState.RUNNING:
        console.print(f"[red][-][/] VM not running ({vm.state().value})")
        raise SystemExit(1)
    client = _client(cfg)
    if client.session_alive():
        info = client.session_info() or {}
        console.print(
            f"[red][-][/] another session is active "
            f"(target {info.get('target_name', '?')}({info.get('target_pid', '?')}), "
            f"daemon pid {info.get('daemon_pid', '?')}). "
            f"Run [bold]winbox kdbg detach[/] first."
        )
        raise SystemExit(1)

    ga = GuestAgent(cfg)
    try:
        import json as _json
        from winbox.kdbg.breakpoint_intent import BreakpointIntentStore
        from winbox.kdbg.staging import (
            preflight_user_module_staging, prepare_user_module_manifest,
        )
        store = SymbolStore(cfg.symbols_dir)
        intent_snapshot = (
            BreakpointIntentStore(cfg).inventory()["intents"]
            if apply_intents else None
        )
        if preflight:
            plan = preflight_user_module_staging(
                cfg, store, pid, policy=staging_policy,
            )
            plan["prewarm_requested"] = bool(prewarm)
            plan["breakpoint_intents"] = {
                "apply_requested": bool(apply_intents),
                "count": len(intent_snapshot or []),
                "intents": intent_snapshot or [],
            }
            click.echo(_json.dumps(plan, indent=2))
            return

        def report(item: dict) -> None:
            console.print(
                f"    [dim]stage {item['index']}/{item['total']} "
                f"{item['name']}@{item['architecture']}: {item['state']} "
                f"({item['symbol_state']}, {item['elapsed_seconds']:.3f}s)[/]"
            )

        manifest = prepare_user_module_manifest(
            cfg, ga, store, pid, enrich_symbols=staging_policy == "full",
            policy=staging_policy, progress=report,
        )
    except Exception as e:
        console.print(f"[red][-][/] automatic module staging failed: {e}")
        raise SystemExit(1)

    stop_reader(cfg)
    if not probe_port("127.0.0.1", port):
        console.print(f"[red][-][/] gdbstub not listening on 127.0.0.1:{port}")
        console.print("    run [bold]winbox kdbg start[/] first")
        raise SystemExit(1)

    try:
        daemon_pid = fork_daemon(
            cfg, pid, gdbstub_port=port, module_manifest=manifest,
            breakpoint_intents=intent_snapshot,
        )
    except DaemonError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)

    info = client.session_info() or {}
    console.print(
        f"[green][+][/] attached to {info.get('target_name', f'pid={pid}')}"
        f"({info.get('target_pid', pid)}) "
        f"dtb={info.get('target_dtb', '?')}  "
        f"daemon_pid={daemon_pid}"
    )
    console.print(f"    [dim]bp / cont / regs / mem / stack / bt / detach[/]")
    summary = manifest.summary()
    console.print(
        f"    [dim]{summary['staging_policy']} policy staged "
        f"{summary['staged']} available artifact(s), "
        f"{summary['symbol_enriched']} symbol-enriched, "
        f"{summary['symbol_failed']} PDB miss(es), "
        f"{summary['symbol_warning_count']} symbol warning(s), "
        f"{summary['failed']} failed[/]"
    )
    intent_report = info.get("breakpoint_intents")
    if isinstance(intent_report, dict):
        console.print(
            f"    [dim]breakpoint intents: {intent_report.get('installed', 0)} installed, "
            f"{intent_report.get('unresolved', 0)} unresolved, "
            f"{intent_report.get('failed', 0)} failed[/]"
        )
        for record in intent_report.get("results", []):
            if record.get("status") != "installed":
                console.print(
                    f"    [yellow][!][/] intent {record.get('intent_id')}: "
                    f"{record.get('target')} — {record.get('error', record.get('status'))}"
                )
    if prewarm:
        from winbox.kdbg.decomp import DecompError, start_prepare_background
        modules = sorted({
            item.store_name for item in manifest.modules if item.store_build
        })
        try:
            if not modules:
                raise DecompError("no symbol-enriched exact modules are available")
            job = start_prepare_background(cfg, modules=modules)
            console.print(
                f"    [dim]offline Ghidra prewarm token={job['token']} "
                f"modules={len(modules)}[/]"
            )
        except DecompError as exc:
            console.print(f"[yellow][!][/] background prewarm not started: {exc}")

    try:
        from winbox import hvci as _hvci
        if _hvci.status(ga).hvci_enabled:
            console.print(
                "[yellow][!][/] HVCI is enabled — kernel breakpoints will not work. "
                "Run [bold]winbox hvci disable[/] first."
            )
    except Exception:
        pass


@kdbg.command("session")
@click.pass_context
def kdbg_session(ctx: click.Context) -> None:
    """Show current daemon session info, or 'no session' if none."""
    cfg: Config = ctx.obj["cfg"]
    client = _client(cfg)
    if not client.session_alive():
        console.print("[dim]no kdbg session attached[/]")
        return
    try:
        result = client.call("status")
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    t = result["target"]
    console.print(
        f"[green][+][/] {t['name']}({t['pid']})  dtb={t['dtb']}  "
        f"bps={result['bps']}  halted={result['halted']}  "
        f"uptime={result['uptime_s']:.1f}s  daemon_pid={result['daemon_pid']}"
    )


@kdbg.command("target-status")
@click.pass_context
def kdbg_target_status(ctx: click.Context) -> None:
    """Probe whether the originally attached process is alive, exiting, or gone."""
    import json as _json
    try:
        result = _client(ctx.obj["cfg"]).call("target_status")
    except ClientError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    click.echo(_json.dumps(result, indent=2))
