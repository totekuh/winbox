"""Capture, capture-diff, thread-baseline, and thread-diff CLI commands."""

from __future__ import annotations

import click

from winbox.cli import console
from winbox.cli.kdbg import kdbg, _get_store
from winbox.config import Config
from winbox.kdbg import SymbolStoreError
from winbox.kdbg.capture import CaptureError, CaptureStore, capture_live
from winbox.kdbg.capture_diff import diff_captures
from winbox.kdbg.debugger.reader import (
    ReaderError, debug_snapshot, snapshot_metadata as _snapshot_metadata,
)
from winbox.kdbg.hmp import HmpError
from winbox.kdbg.objects import ObjectEvidenceError
from winbox.kdbg.thread_baseline import (
    ThreadBaselineError, ThreadBaselineStore,
    capture_threads as capture_thread_baseline,
)
from winbox.kdbg.vad import VadError
from winbox.vm import VM, VMState


@kdbg.group("capture", invoke_without_command=True)
@click.option("--profile", type=click.Choice(["process", "system"]), default="process", show_default=True)
@click.option("--pid", type=int, help="Target PID (required for --profile process).")
@click.option("--name", help="Optional bounded host-side capture name.")
@click.option("--require-complete", is_flag=True, help="Refuse explicit partial capture evidence.")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-safe JSON.")
@click.pass_context
def kdbg_capture(
    ctx: click.Context, profile: str, pid: int | None, name: str | None,
    require_complete: bool, as_json: bool,
) -> None:
    """Capture one immutable process/system research artifact; `capture diff` is offline."""
    import json as _json

    if ctx.invoked_subcommand is not None:
        return
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        console.print(f"[red][-][/] VM not running ({vm.state().value})")
        raise SystemExit(1)
    try:
        store = _get_store(cfg)
        capture = capture_live(
            cfg, store, profile=profile, pid=pid, require_complete=require_complete,
        )
        saved = CaptureStore(cfg).save(name, capture) if name else None
        payload = {"capture": capture, "saved": saved}
    except (CaptureError, VadError, ObjectEvidenceError, SymbolStoreError, HmpError, ReaderError) as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    if as_json:
        click.echo(_json.dumps(payload, indent=2))
        return
    capture_info = capture["capture"]
    console.print(f"[green][+][/] captured {capture_info['profile']} evidence; complete={capture_info['complete']}")
    if saved:
        console.print(f"  saved: {saved['name']} -> {saved['path']}")
    metadata = capture["snapshot_metadata"]
    console.print(f"  stop: {metadata.get('stop_duration_ms')} ms, {metadata.get('read_count')} reads")


@kdbg_capture.command("diff")
@click.argument("left")
@click.argument("right")
@click.option("--limit", type=click.IntRange(1, 1024), default=128, show_default=True)
@click.option("--allow-identity-mismatch", is_flag=True, help="Permit a forensic comparison across different capture identities.")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-safe JSON.")
@click.pass_context
def kdbg_capture_diff(
    ctx: click.Context, left: str, right: str, limit: int,
    allow_identity_mismatch: bool, as_json: bool,
) -> None:
    """Diff two named capture artifacts entirely offline."""
    import json as _json

    cfg: Config = ctx.obj["cfg"]
    try:
        store = CaptureStore(cfg)
        payload = diff_captures(
            store.load(left), store.load(right), limit=limit,
            allow_identity_mismatch=allow_identity_mismatch,
        )
    except CaptureError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    if as_json:
        click.echo(_json.dumps(payload, indent=2))
        return
    console.print(f"capture diff ({payload['profile']}): identity_match={payload['identity_match']}")
    for key, value in payload.items():
        if isinstance(value, dict) and {"created", "removed", "changed"} <= set(value):
            console.print(f"  {key}: +{len(value['created'])} -{len(value['removed'])} ~{len(value['changed'])}")


def _thread_baseline_vm_ready(cfg: Config) -> None:
    state = VM(cfg).state()
    if state not in (VMState.RUNNING, VMState.PAUSED):
        raise ThreadBaselineError(f"VM is not running (state: {state.value})")


@kdbg.command("thread-baseline")
@click.argument("pid", type=int)
@click.option("--name", "baseline_name", default="default", show_default=True,
              help="Host-side baseline label (letters, digits, dot, dash, underscore).")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-safe JSON.")
@click.pass_context
def kdbg_thread_baseline(
    ctx: click.Context, pid: int, baseline_name: str, as_json: bool,
) -> None:
    """Save one explicit, complete host-side ETHREAD baseline for PID."""
    import json as _json

    cfg: Config = ctx.obj["cfg"]
    try:
        _thread_baseline_vm_ready(cfg)
        baseline = ThreadBaselineStore(cfg)
        baseline.validate_name(baseline_name)
        with debug_snapshot(cfg) as snapshot:
            store = _get_store(cfg)
            capture = capture_thread_baseline(cfg, store, pid)
            snapshot_metadata = _snapshot_metadata(snapshot)
        result = baseline.save(baseline_name, capture)
        result["snapshot_metadata"] = snapshot_metadata
    except (ThreadBaselineError, SymbolStoreError, HmpError, ReaderError) as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    if as_json:
        click.echo(_json.dumps(result, indent=2))
        return
    console.print(
        f"[green][+][/] baseline {baseline_name!r}: pid {result['process']['pid']} "
        f"({result['process']['name']}), {result['thread_count']} complete threads"
    )
    console.print(f"    captured: {result['captured_at']}")


@kdbg.command("thread-diff")
@click.argument("pid", type=int)
@click.option("--name", "baseline_name", default="default", show_default=True,
              help="Host-side baseline label to compare.")
@click.option("--limit", type=click.IntRange(1, 1024), default=128, show_default=True,
              help="Maximum rows returned per created/exited/changed category.")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-safe JSON.")
@click.pass_context
def kdbg_thread_diff(
    ctx: click.Context, pid: int, baseline_name: str, limit: int, as_json: bool,
) -> None:
    """Compare one explicit current ETHREAD snapshot to a named baseline."""
    import json as _json

    cfg: Config = ctx.obj["cfg"]
    baseline = ThreadBaselineStore(cfg)
    try:
        _thread_baseline_vm_ready(cfg)
        baseline.load(baseline_name)
        with debug_snapshot(cfg) as snapshot:
            store = _get_store(cfg)
            capture = capture_thread_baseline(cfg, store, pid)
            snapshot_metadata = _snapshot_metadata(snapshot)
        result = baseline.diff(baseline_name, capture, limit=limit)
        result["snapshot_metadata"] = snapshot_metadata
    except (ThreadBaselineError, SymbolStoreError, HmpError, ReaderError) as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    if as_json:
        click.echo(_json.dumps(result, indent=2))
        return
    console.print(
        f"[dim]baseline {baseline_name!r}: {result['baseline']['thread_count']} → "
        f"{result['current']['thread_count']} threads[/]"
    )
    console.print(
        f"  created={result['created_count']} exited={result['exited_count']} "
        f"changed={result['changed_count']}"
    )
    for category in ("created", "exited"):
        for thread in result[category]:
            console.print(f"  {category[:-1]:7} tid {thread['tid']:6d} {thread['ethread']}")
    for row in result["changed"]:
        thread = row["thread"]
        labels = ", ".join(row["changes"])
        console.print(f"  changed  tid {thread['tid']:6d} {thread['ethread']} — {labels}")
    if any(result[f"{category}_truncated"] for category in ("created", "exited", "changed")):
        console.print(f"[yellow][!][/] output limited to {limit} rows per category")
