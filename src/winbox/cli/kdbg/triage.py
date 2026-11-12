"""Process triage and global thread-triage CLI commands."""

from __future__ import annotations

import click

from winbox.cli import console
from winbox.cli.kdbg import kdbg, _get_store
from winbox.cli.kdbg.threads import _thread_json_record, _current_vcpu_json
from winbox.config import Config
from winbox.kdbg import (
    SymbolLoadError, SymbolStoreError, WalkCache, ensure_types_loaded,
)
from winbox.kdbg.debugger.reader import (
    ReaderError, debug_snapshot, snapshot_metadata as _snapshot_metadata,
)
from winbox.kdbg.hmp import HmpError
from winbox.kdbg.presentation import filetime_utc
from winbox.kdbg.thread_triage import (
    GlobalThreadTriageError, GlobalThreadTriageIncomplete,
    triage_all_process_threads,
)
from winbox.kdbg.vad import VadError, ensure_vad_layouts
from winbox.kdbg.walk import (
    ThreadWalkIncomplete, find_process, list_current_vcpu_threads,
    list_modules, list_threads, list_user_modules,
    resolve_thread_start_addresses, select_threads, thread_walk_truncation,
)
from winbox.vm import VM, VMState


def _module_json_record(module) -> dict:
    return {
        "base": f"0x{module.base:016x}",
        "size": f"0x{module.size:x}",
        "name": module.name,
        "full_path": getattr(module, "full_path", None),
        "architecture": getattr(module, "architecture", "kernel"),
    }


def _unmapped_start_rows(threads, attributions) -> list[dict]:
    """Show loader/module mismatches as leads, never as a malware verdict."""
    rows: list[dict] = []
    for thread in threads:
        attribution = attributions.get(thread.ethread)
        if attribution is None:
            continue
        for field, value in (
            ("start_address", attribution.start_address),
            ("win32_start_address", attribution.win32_start_address),
        ):
            if value.mapping not in {"kernel_unmapped", "user_not_in_loader_module"}:
                continue
            rows.append({
                "tid": thread.tid,
                "ethread": f"0x{thread.ethread:016x}",
                "field": field,
                "address": f"0x{value.address:016x}",
                "mapping": value.mapping,
            })
    return rows


@kdbg.command("triage")
@click.argument("pid", type=int)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-safe JSON.")
@click.option(
    "--thread-limit", type=click.IntRange(1, 64), default=16, show_default=True,
    help="Top context-switch thread rows to resolve and return.",
)
@click.option(
    "--require-complete", is_flag=True,
    help="Refuse a validated partial kernel-list prefix instead of returning it.",
)
@click.pass_context
def kdbg_triage(
    ctx: click.Context, pid: int, as_json: bool, thread_limit: int,
    require_complete: bool,
) -> None:
    """Capture one bounded, coherent kernel-research view for PID."""
    import json as _json

    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        console.print(f"[red][-][/] VM not running ({vm.state().value})")
        raise SystemExit(1)
    try:
        try:
            ensure_vad_layouts(cfg, _get_store(cfg))
        except (VadError, SymbolStoreError, SymbolLoadError):
            pass
        with debug_snapshot(cfg) as snapshot:
            store = _get_store(cfg)
            cache = WalkCache()
            target = find_process(cfg.vm_name, store, pid=pid, cache=cache)
            if target is None:
                console.print(f"[red][-][/] pid {pid} not found in process list")
                raise SystemExit(1)
            walked = list_threads(cfg.vm_name, store, target, cache=cache)
            if require_complete and not walked.complete:
                raise ThreadWalkIncomplete(walked)
            selected = select_threads(
                walked.threads, sort="context-switches", limit=thread_limit,
            )
            kernel_modules = list_modules(cfg.vm_name, store, cache=cache)
            module_error = None
            try:
                ensure_types_loaded(
                    cfg, store, ["_PEB", "_PEB_LDR_DATA", "_EWOW64PROCESS"], module="nt",
                )
                user_modules = list_user_modules(cfg.vm_name, store, target, cache=cache)
            except (SymbolStoreError, SymbolLoadError, HmpError) as exc:
                user_modules = []
                module_error = str(exc)
            attributions, attribution_warnings = resolve_thread_start_addresses(
                cfg.vm_name, store, target, selected.threads, cache=cache,
                kernel_modules=kernel_modules, user_modules=user_modules,
            )
            current_vcpus = []
            current_vcpus_error = None
            try:
                current_vcpus = list_current_vcpu_threads(
                    cfg.vm_name, store, target, threads=walked.threads, cache=cache,
                )
            except (SymbolStoreError, HmpError, ReaderError) as exc:
                current_vcpus_error = str(exc)
            snapshot_metadata = _snapshot_metadata(snapshot)
    except ThreadWalkIncomplete as exc:
        if as_json:
            click.echo(_json.dumps({
                "ok": False,
                "error": {
                    "code": exc.code, "retryable": exc.retryable,
                    "message": str(exc), "details": exc.details,
                },
            }, indent=2))
        else:
            console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    except (VadError, SymbolStoreError, SymbolLoadError, HmpError, ReaderError) as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)

    running_by_ethread: dict[int, list[int]] = {}
    for current in current_vcpus:
        if current.status == "current" and current.in_target_process and current.ethread is not None:
            running_by_ethread.setdefault(current.ethread, []).append(current.vcpu)
    module_limit = 64
    payload = {
        "snapshot": "single_rsp_stop",
        "process": {
            "pid": target.pid, "name": target.name,
            "eprocess": f"0x{target.eprocess:016x}",
            "dtb": f"0x{target.directory_table_base:012x}",
            "create_time": target.create_time,
            "create_time_filetime": target.create_time,
            "create_time_utc": filetime_utc(target.create_time),
        },
        "thread_summary": {
            "total_count": selected.total_count,
            "walk_complete": walked.complete,
            "truncated_reason": walked.truncated_reason,
            "truncation": thread_walk_truncation(walked),
            "states": selected.state_counts,
            "wait_reasons": selected.wait_reason_counts,
            "top_rows_returned": len(selected.threads),
            "top_rows_truncated": selected.output_truncated,
            "sort": "context-switches",
        },
        "threads": [
            _thread_json_record(
                thread, attribution=attributions.get(thread.ethread),
                running_on_vcpus=running_by_ethread.get(thread.ethread, ()),
            ) for thread in selected.threads
        ],
        "current_vcpus": [_current_vcpu_json(current) for current in current_vcpus],
        "user_modules": {
            "count": len(user_modules),
            "returned": min(len(user_modules), module_limit),
            "output_truncated": len(user_modules) > module_limit,
            "modules": [_module_json_record(module) for module in user_modules[:module_limit]],
        },
        "unmapped_starts": _unmapped_start_rows(selected.threads, attributions),
        "unmapped_starts_scope": "top_rows_only",
        "snapshot_metadata": snapshot_metadata,
    }
    if module_error:
        payload["user_modules"]["error"] = module_error
    if attribution_warnings:
        payload["attribution_warnings"] = list(attribution_warnings)
    if current_vcpus_error:
        payload["current_vcpus_error"] = current_vcpus_error
    if as_json:
        click.echo(_json.dumps(payload, indent=2))
        return

    console.print(f"[dim]pid {target.pid} ({target.name}) — EPROCESS 0x{target.eprocess:x}[/]")
    console.print(
        f"  threads: {selected.total_count} walked; {len(selected.threads)} top context-switch rows; "
        f"complete={walked.complete}"
    )
    console.print(f"  user modules: {len(user_modules)}")
    console.print(f"  current vCPUs: {len(current_vcpus)}")
    if payload["unmapped_starts"]:
        console.print("[yellow]  unmapped starts (top rows only):[/]")
        for row in payload["unmapped_starts"]:
            console.print(f"    tid {row['tid']} {row['field']} {row['address']} ({row['mapping']})")
    else:
        console.print("  unmapped starts (top rows only): none")
    if module_error:
        console.print(f"[yellow][!][/] user module view unavailable: {module_error}")
    if not walked.complete:
        console.print(f"[yellow][!][/] incomplete thread walk: {walked.truncated_reason}")


@kdbg.command("thread-triage")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-safe JSON.")
@click.option(
    "--process-cap", type=click.IntRange(1, 256), default=128, show_default=True,
    help="Maximum process records to examine from one active-process snapshot.",
)
@click.option(
    "--total-thread-cap", type=click.IntRange(1, 8192), default=4096, show_default=True,
    help="Maximum ETHREAD records examined across all selected processes.",
)
@click.option(
    "--sample-per-process", type=click.IntRange(1, 32), default=8, show_default=True,
    help="Top context-switch thread rows sampled per process for start attribution.",
)
@click.option(
    "--limit", "result_limit", type=click.IntRange(1, 64), default=32, show_default=True,
    help="Maximum rows returned in each ranking.",
)
@click.option(
    "--resolve/--no-resolve", default=True, show_default=True,
    help="Resolve only the bounded sample's thread starts against live modules.",
)
@click.option(
    "--require-complete", is_flag=True,
    help="Refuse a cap- or corruption-limited global scope instead of returning it.",
)
@click.pass_context
def kdbg_thread_triage(
    ctx: click.Context,
    as_json: bool,
    process_cap: int,
    total_thread_cap: int,
    sample_per_process: int,
    result_limit: int,
    resolve: bool,
    require_complete: bool,
) -> None:
    """Rank bounded process-wide scheduler evidence from one RSP stop."""
    import json as _json

    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        console.print(f"[red][-][/] VM not running ({vm.state().value})")
        raise SystemExit(1)
    try:
        if resolve:
            try:
                ensure_vad_layouts(cfg, _get_store(cfg))
            except (VadError, SymbolStoreError, SymbolLoadError):
                pass
        with debug_snapshot(cfg) as snapshot:
            store = _get_store(cfg)
            result = triage_all_process_threads(
                cfg.vm_name, store, cache=WalkCache(), process_cap=process_cap,
                total_thread_cap=total_thread_cap, sample_per_process=sample_per_process,
                result_limit=result_limit, resolve=resolve,
            )
            if require_complete and not result["scope"]["complete"]:
                raise GlobalThreadTriageIncomplete(result)
            result["snapshot_metadata"] = _snapshot_metadata(snapshot)
    except GlobalThreadTriageIncomplete as exc:
        if as_json:
            click.echo(_json.dumps({
                "ok": False,
                "error": {
                    "code": exc.code, "retryable": exc.retryable,
                    "message": str(exc), "details": exc.details,
                },
            }, indent=2))
        else:
            console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    except (GlobalThreadTriageError, VadError, SymbolStoreError, HmpError, ReaderError) as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)

    if as_json:
        click.echo(_json.dumps(result, indent=2))
        return
    scope = result["scope"]
    console.print(
        f"[dim]examined {scope['processes_examined']} processes / "
        f"{scope['total_threads_examined']} threads; complete={scope['complete']}[/]"
    )
    console.print("[dim]  PID     Threads  Run  Wait  Process[/]")
    for row in result["rankings"]["by_thread_count"]:
        console.print(
            f"  {row['pid']:6d}  {row['thread_count']:7d}  "
            f"{row['runnable_count']:3d}  {row['waiting_count']:4d}  {row['name']}"
        )
    if result["rankings"]["suspicious_starts"]:
        console.print("[yellow]  suspicious starts (bounded samples only):[/]")
        for row in result["rankings"]["suspicious_starts"]:
            console.print(
                f"    pid {row['pid']} tid {row['tid']} {row['field']} "
                f"{row['address']} ({row['mapping']})"
            )
    if not scope["complete"]:
        console.print(f"[yellow][!][/] scope incomplete: {'; '.join(scope['reasons'])}")
