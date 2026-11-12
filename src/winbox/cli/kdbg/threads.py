"""Thread listing command and formatting helpers."""

from __future__ import annotations

import click

from winbox.cli import console
from winbox.cli.kdbg import kdbg, _get_store
from winbox.config import Config
from winbox.kdbg import (
    SymbolLoadError, SymbolStoreError, WalkCache, ensure_types_loaded,
)
from winbox.kdbg.debugger.reader import (
    ReaderError, debug_snapshot, snapshot_metadata as _snapshot_metadata,
)
from winbox.kdbg.hmp import HmpError
from winbox.kdbg.presentation import filetime_utc, thread_presentation_fields
from winbox.kdbg.vad import VadError, ensure_vad_layouts
from winbox.kdbg.walk import (
    ThreadWalkIncomplete, find_process, list_current_vcpu_threads,
    list_threads, resolve_thread_start_addresses,
    resolve_thread_wait_objects, select_threads, thread_walk_truncation,
)
from winbox.vm import VM, VMState


def _thread_address_json(attribution) -> dict:
    """Serialize a conservative start-address attribution."""
    result = {
        "address": f"0x{attribution.address:016x}",
        "mapping": attribution.mapping,
        "module": attribution.module,
        "module_base": (
            f"0x{attribution.module_base:016x}"
            if attribution.module_base is not None else None
        ),
        "module_size": (
            f"0x{attribution.module_size:x}"
            if attribution.module_size is not None else None
        ),
        "rva": f"0x{attribution.rva:x}" if attribution.rva is not None else None,
        "architecture": attribution.architecture,
        "symbol": attribution.symbol,
        "symbol_offset": (
            f"0x{attribution.symbol_offset:x}"
            if attribution.symbol_offset is not None else None
        ),
    }
    if getattr(attribution, "vad", None) is not None:
        result["vad"] = attribution.vad
    return result


def _current_vcpu_json(record) -> dict:
    return {
        "vcpu": record.vcpu,
        "status": record.status,
        "ethread": f"0x{record.ethread:016x}" if record.ethread is not None else None,
        "eprocess": f"0x{record.eprocess:016x}" if record.eprocess is not None else None,
        "pid": record.pid,
        "process_name": record.process_name,
        "tid": record.tid,
        "in_target_process": record.in_target_process,
        "reason": record.reason,
    }


def _thread_json_record(
    thread, *, attribution=None, running_on_vcpus=(), wait_evidence=None,
) -> dict:
    """Render a ThreadRecord without losing raw scheduler enum values."""
    result = {
        "tid": thread.tid,
        "ethread": f"0x{thread.ethread:016x}",
        "state": {"raw": thread.state, "name": thread.state_name},
        "wait_reason": {
            "raw": thread.wait_reason,
            "name": thread.wait_reason_name,
        },
        "priority": thread.priority,
        "base_priority": thread.base_priority,
        "context_switches": thread.context_switches,
        "teb": f"0x{thread.teb:016x}",
        "kernel_stack": f"0x{thread.kernel_stack:016x}",
        "stack_limit": f"0x{thread.stack_limit:016x}",
        "stack_base": f"0x{thread.stack_base:016x}",
        "start_address": f"0x{thread.start_address:016x}",
        "win32_start_address": f"0x{thread.win32_start_address:016x}",
        "create_time": thread.create_time,
        "exit_status": thread.exit_status,
    }
    result.update(thread_presentation_fields(thread))
    if attribution is not None:
        result["start_attribution"] = {
            "start_address": _thread_address_json(attribution.start_address),
            "win32_start_address": _thread_address_json(
                attribution.win32_start_address,
            ),
        }
    if running_on_vcpus:
        result["running_on_vcpus"] = list(running_on_vcpus)
    if wait_evidence is not None:
        result["wait_object"] = wait_evidence
    return result


def _thread_address_text(address: int, attribution) -> str:
    if attribution is None or attribution.module is None:
        return f"0x{address:016x}"
    if attribution.symbol is not None:
        suffix = f"+0x{attribution.symbol_offset:x}" if attribution.symbol_offset else ""
        return f"{attribution.module}!{attribution.symbol}{suffix}"
    return f"{attribution.module}+0x{attribution.rva:x}"


@kdbg.command("threads")
@click.argument("pid", type=int)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-safe JSON.")
@click.option(
    "--detail", type=click.Choice(["full", "summary"]), default="full",
    show_default=True, help="Return thread rows or only bounded aggregate counts.",
)
@click.option("--state", default=None, help="Raw KTHREAD state byte or name (e.g. Waiting).")
@click.option(
    "--wait-reason", default=None,
    help="Raw KWAIT_REASON byte or name; only matches Waiting threads.",
)
@click.option(
    "--sort", type=click.Choice([
        "tid", "state", "wait", "priority", "context-switches", "start",
        "win32-start", "create-time",
    ]), default="tid", show_default=True,
)
@click.option(
    "--limit", type=click.IntRange(1, 1024), default=256, show_default=True,
    help="Maximum detailed rows; separate from a complete kernel-list walk.",
)
@click.option(
    "--resolve", "resolve_addresses", is_flag=True,
    help="Attribute returned start addresses to live modules and local symbols.",
)
@click.option(
    "--current/--no-current", "include_current", default=True, show_default=True,
    help="Map each halted vCPU to its validated current ETHREAD.",
)
@click.option(
    "--wait-objects", is_flag=True,
    help="Resolve exact-PDB wait-object and mutant-owner evidence for returned Waiting rows.",
)
@click.option(
    "--wait-object-limit", type=click.IntRange(1, 128), default=32, show_default=True,
    help="Maximum Waiting rows receiving wait-object evidence.",
)
@click.option(
    "--wait-owner-depth", type=click.IntRange(1, 4), default=2, show_default=True,
    help="Maximum proven mutant-owner hops per Waiting row.",
)
@click.option(
    "--require-complete", is_flag=True,
    help="Refuse a validated partial kernel-list prefix instead of returning it.",
)
@click.pass_context
def kdbg_threads(
    ctx: click.Context,
    pid: int,
    as_json: bool,
    detail: str,
    state: str | None,
    wait_reason: str | None,
    sort: str,
    limit: int,
    resolve_addresses: bool,
    include_current: bool,
    wait_objects: bool,
    wait_object_limit: int,
    wait_owner_depth: int,
    require_complete: bool,
) -> None:
    """Walk EPROCESS.ThreadListHead for PID without entering the guest.

    Shows bounded scheduler metadata, thread start addresses, and stack *bounds*.
    The displayed KernelStack is a KTHREAD field, not a fabricated saved RSP;
    registers/backtraces remain valid only for the debugger's firing thread.
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        console.print(f"[red][-][/] VM not running ({vm.state().value})")
        raise SystemExit(1)

    if wait_objects and detail != "full":
        console.print("[red][-][/] --wait-objects requires --detail full")
        raise SystemExit(1)
    if wait_objects:
        try:
            ensure_types_loaded(
                cfg, _get_store(cfg),
                ["_KWAIT_BLOCK", "_DISPATCHER_HEADER", "_KMUTANT"], module="nt",
            )
        except (SymbolStoreError, SymbolLoadError) as exc:
            console.print(f"[red][-][/] wait-object layouts unavailable: {exc}")
            raise SystemExit(1)
    if resolve_addresses:
        try:
            ensure_vad_layouts(cfg, _get_store(cfg))
        except (VadError, SymbolStoreError, SymbolLoadError):
            pass

    try:
        with debug_snapshot(cfg) as snapshot:
            store = _get_store(cfg)
            cache = WalkCache()
            target = find_process(cfg.vm_name, store, pid=pid, cache=cache)
            if target is None:
                console.print(f"[red][-][/] pid {pid} not found in process list")
                raise SystemExit(1)
            result = list_threads(cfg.vm_name, store, target, cache=cache)
            if require_complete and not result.complete:
                raise ThreadWalkIncomplete(result)
            selected = select_threads(
                result.threads, state=state, wait_reason=wait_reason,
                sort=sort, limit=limit,
            )
            displayed = selected.threads if detail == "full" else ()
            attributions = {}
            attribution_warnings = ()
            if resolve_addresses:
                attributions, attribution_warnings = resolve_thread_start_addresses(
                    cfg.vm_name, store, target, displayed, cache=cache,
                )
            wait_view = {"enabled": False}
            wait_records: dict[int, dict] = {}
            if wait_objects:
                wait_result = resolve_thread_wait_objects(
                    cfg.vm_name, store, target, displayed, cache=cache,
                    limit=wait_object_limit, owner_depth=wait_owner_depth,
                )
                wait_view = {"enabled": True, **wait_result["scope"]}
                wait_records = wait_result["records"]
            current_vcpus = []
            current_vcpus_error = None
            if include_current:
                try:
                    current_vcpus = list_current_vcpu_threads(
                        cfg.vm_name, store, target, threads=result.threads, cache=cache,
                    )
                except (SymbolStoreError, HmpError, ReaderError) as exc:
                    current_vcpus_error = str(exc)
            snapshot_metadata = _snapshot_metadata(snapshot)
    except ThreadWalkIncomplete as e:
        if as_json:
            import json as _json
            click.echo(_json.dumps({
                "ok": False,
                "error": {
                    "code": e.code,
                    "retryable": e.retryable,
                    "message": str(e),
                    "details": e.details,
                },
            }, indent=2))
        else:
            console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    except (VadError, SymbolStoreError, HmpError, ReaderError) as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)

    running_by_ethread: dict[int, list[int]] = {}
    for current in current_vcpus:
        if current.status == "current" and current.in_target_process and current.ethread is not None:
            running_by_ethread.setdefault(current.ethread, []).append(current.vcpu)

    payload = {
        "pid": target.pid,
        "name": target.name,
        "eprocess": f"0x{target.eprocess:016x}",
        "process_create_time": target.create_time,
        "process_create_time_filetime": target.create_time,
        "process_create_time_utc": filetime_utc(target.create_time),
        "threads": [
            _thread_json_record(
                thread,
                attribution=attributions.get(thread.ethread),
                running_on_vcpus=running_by_ethread.get(thread.ethread, ()),
                wait_evidence=wait_records.get(thread.ethread),
            )
            for thread in displayed
        ],
        "count": len(displayed),
        "total_count": selected.total_count,
        "matched_count": selected.matched_count,
        "filtered_out": selected.filtered_out,
        "returned": len(displayed),
        "output_truncated": selected.output_truncated,
        "detail_rows_omitted": detail == "summary" and selected.matched_count > 0,
        "detail": detail,
        "summary": {
            "states": selected.state_counts,
            "wait_reasons": selected.wait_reason_counts,
        },
        "complete": result.complete,
        "walk_complete": result.complete,
        "truncated_reason": result.truncated_reason,
        "truncation": thread_walk_truncation(result),
        "current_vcpus": [_current_vcpu_json(current) for current in current_vcpus],
        "wait_objects": wait_view,
        "snapshot_metadata": snapshot_metadata,
    }
    if attribution_warnings:
        payload["attribution_warnings"] = list(attribution_warnings)
    if current_vcpus_error is not None:
        payload["current_vcpus_error"] = current_vcpus_error
    if as_json:
        import json as _json
        click.echo(_json.dumps(payload, indent=2))
        return

    console.print(f"[dim]pid {target.pid} ({target.name}) — EPROCESS 0x{target.eprocess:x}[/]")
    if detail == "summary":
        states = ", ".join(f"{name}={count}" for name, count in sorted(selected.state_counts.items()))
        waits = ", ".join(f"{name}={count}" for name, count in sorted(selected.wait_reason_counts.items()))
        console.print(f"  states: {states or 'none'}")
        console.print(f"  waiting: {waits or 'none'}")
    else:
        console.print("[dim]  TID     State          Wait             Pri  CPU   Start address[/]")
        for thread in displayed:
            state_name = thread.state_name or f"unknown({thread.state})"
            wait = (
                thread.wait_reason_name or f"unknown({thread.wait_reason})"
                if thread.state == 5 else "—"
            )
            current = ",".join(str(vcpu) for vcpu in running_by_ethread.get(thread.ethread, ())) or "—"
            start = _thread_address_text(thread.start_address, attributions.get(thread.ethread).start_address if thread.ethread in attributions else None)
            console.print(
                f"  {thread.tid:6d}  {state_name:13.13}  {wait:15.15}  {thread.priority:3d}  "
                f"{current:4.4}  {start}"
            )
            evidence = wait_records.get(thread.ethread)
            if evidence is not None:
                obj = evidence.get("object") or {}
                owners = evidence.get("owner_chain") or []
                owner_text = (
                    f"owner tid {owners[0]['tid']} (pid {owners[0]['pid']})"
                    if owners else str(evidence.get("reason") or "unavailable")
                )
                console.print(f"           wait {obj.get('address') or 'unavailable'}: {owner_text}")
        if not displayed:
            console.print("[dim](no matching threads)[/]")
    console.print(
        f"[dim](returned {len(displayed)} of {selected.matched_count} matching; "
        f"{selected.total_count} walked)[/]"
    )
    if selected.output_truncated:
        console.print(f"[yellow][!][/] output limited to {limit} rows; kernel walk remains complete={result.complete}")
    if attribution_warnings:
        for warning in attribution_warnings:
            console.print(f"[yellow][!][/] {warning}")
    if current_vcpus_error:
        console.print(f"[yellow][!][/] current-vCPU attribution unavailable: {current_vcpus_error}")
    if wait_objects:
        console.print(
            f"[dim]wait objects: {wait_view['examined']}/{wait_view['waiting_threads']} "
            "Waiting rows (mutant-owner only)[/]"
        )
    if not result.complete:
        console.print(f"[yellow][!][/] incomplete thread walk: {result.truncated_reason}")
