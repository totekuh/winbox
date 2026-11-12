"""VAD, object-evidence, and handle-table CLI commands."""

from __future__ import annotations

import click

from winbox.cli import console
from winbox.cli.kdbg import kdbg, _get_store
from winbox.config import Config
from winbox.kdbg import WalkCache, SymbolStoreError
from winbox.kdbg.debugger.reader import (
    ReaderError, debug_snapshot, snapshot_metadata as _snapshot_metadata,
)
from winbox.kdbg.hmp import HmpError
from winbox.kdbg.objects import (
    ObjectEvidenceError, ensure_object_layouts, handle_table_status,
    object_header, token_evidence,
)
from winbox.kdbg.vad import VadError, ensure_vad_layouts, list_vads, lookup_vad
from winbox.kdbg.vad_extract import VadExtractError, VadExtractStore, extract_live as extract_vad_live
from winbox.kdbg.walk import find_process
from winbox.vm import VM, VMState


@kdbg.command("vad")
@click.argument("pid", type=int)
@click.option("--address", type=str, help="Resolve one canonical user virtual address.")
@click.option("--executable", is_flag=True, help="Return executable mappings only in map mode.")
@click.option("--limit", type=click.IntRange(1, 4096), default=128, show_default=True)
@click.option("--probe-header", is_flag=True, help="Probe each returned range base for MZ evidence.")
@click.option("--require-complete", is_flag=True, help="Refuse a map prefix at a cap/corruption boundary.")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-safe JSON.")
@click.pass_context
def kdbg_vad(
    ctx: click.Context, pid: int, address: str | None, executable: bool, limit: int,
    probe_header: bool, require_complete: bool, as_json: bool,
) -> None:
    """Resolve one user VAD or list a bounded executable VAD map."""
    import json as _json

    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        console.print(f"[red][-][/] VM not running ({vm.state().value})")
        raise SystemExit(1)
    parsed: int | None = None
    if address:
        try:
            parsed = int(address, 0)
        except ValueError as exc:
            raise click.BadParameter(f"invalid address: {address}") from exc
    try:
        store = _get_store(cfg)
        ensure_vad_layouts(cfg, store)
        with debug_snapshot(cfg, operation="vad") as snapshot:
            cache = WalkCache()
            target = find_process(cfg.vm_name, store, pid=pid, cache=cache)
            if target is None:
                raise VadError(f"pid {pid} not found")
            if parsed is not None:
                record = lookup_vad(
                    cfg.vm_name, store, target, parsed, cache=cache,
                    probe_header=probe_header,
                )
                payload = {
                    "pid": pid, "address": f"0x{parsed:016x}", "found": record is not None,
                    "vad": record.public() if record else None, "complete": True,
                }
            else:
                walked = list_vads(
                    cfg.vm_name, store, target, cache=cache, executable_only=executable,
                    limit=limit, probe_header=probe_header,
                )
                if require_complete and not walked.complete:
                    raise VadError(f"incomplete VAD map: {walked.truncation}")
                payload = {"pid": pid, "executable_only": executable, **walked.public()}
            payload["snapshot_metadata"] = _snapshot_metadata(snapshot)
    except (VadError, SymbolStoreError, HmpError, ReaderError) as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    if as_json:
        click.echo(_json.dumps(payload, indent=2))
        return
    if parsed is not None:
        if payload["vad"] is None:
            console.print(f"[yellow][!][/] 0x{parsed:x} is not covered by a validated user VAD")
        else:
            record = payload["vad"]
            console.print(f"0x{parsed:016x} -> {record['kind']} {record['start']}..{record['end']}")
            console.print(f"  protection: {record['protection']['name'] or record['protection']['raw']}")
        return
    console.print(f"[dim]pid {pid}: {payload['returned']} VAD row(s); complete={payload['complete']}[/]")
    for record in payload["records"]:
        protection = record["protection"]["name"] or str(record["protection"]["raw"])
        console.print(f"  {record['start']}..{record['end']}  {record['kind']:11}  {protection}")
    if not payload["complete"]:
        console.print(f"[yellow][!][/] VAD map incomplete: {payload['truncation']}")


@kdbg.command("vad-extract")
@click.argument("pid", type=int)
@click.argument("address", type=str)
@click.option(
    "--length", type=click.IntRange(1, 8 * 1024 * 1024),
    help="Bytes to extract from ADDRESS (default: up to 1 MiB within the VAD).",
)
@click.option("--name", required=True, help="Immutable bounded host-side artifact name.")
@click.option("--require-complete", is_flag=True, help="Refuse to publish an artifact with unreadable holes.")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-safe JSON; raw bytes stay host-side.")
@click.pass_context
def kdbg_vad_extract(
    ctx: click.Context, pid: int, address: str, length: int | None, name: str,
    require_complete: bool, as_json: bool,
) -> None:
    """Extract one proven process-VAD range into an immutable host artifact."""
    import json as _json

    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        console.print(f"[red][-][/] VM not running ({vm.state().value})")
        raise SystemExit(1)
    try:
        parsed_address = int(address, 0)
    except ValueError as exc:
        raise click.BadParameter(f"invalid address: {address}") from exc
    try:
        artifacts = VadExtractStore(cfg)
        artifacts.validate_name(name)
        artifacts.ensure_available(name)
        store = _get_store(cfg)
        extraction = extract_vad_live(
            cfg, store, pid=pid, address=parsed_address, length=length,
            require_complete=require_complete,
        )
        saved = artifacts.save(name, extraction)
        payload = {"extraction": extraction.manifest, "saved": saved}
    except (VadExtractError, VadError, SymbolStoreError, HmpError, ReaderError) as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    if as_json:
        click.echo(_json.dumps(payload, indent=2))
        return
    artifact = payload["extraction"]
    status = "complete" if artifact["complete"] else "partial"
    console.print(f"[green][+][/] extracted {artifact['blob']['size']} byte(s); {status}")
    console.print(f"  blob: {saved['blob_path']}")
    console.print(f"  manifest: {saved['manifest_path']}")
    if artifact["holes"]:
        console.print(f"[yellow][!][/] {len(artifact['holes'])} unreadable range(s) retained in manifest")
    metadata = artifact["snapshot_metadata"]
    console.print(f"  stop: {metadata.get('stop_duration_ms')} ms, {metadata.get('read_count')} reads")


@kdbg.command("token")
@click.argument("pid", type=int)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-safe JSON.")
@click.pass_context
def kdbg_token(ctx: click.Context, pid: int, as_json: bool) -> None:
    """Show exact-PDB primary-token identity and raw privilege masks."""
    import json as _json

    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        console.print(f"[red][-][/] VM not running ({vm.state().value})")
        raise SystemExit(1)
    try:
        store = _get_store(cfg)
        ensure_object_layouts(cfg, store)
        with debug_snapshot(cfg, operation="token") as snapshot:
            target = find_process(cfg.vm_name, store, pid=pid, cache=WalkCache())
            if target is None:
                raise ObjectEvidenceError(f"pid {pid} not found")
            payload = token_evidence(cfg.vm_name, store, target)
            payload["snapshot_metadata"] = _snapshot_metadata(snapshot)
    except (ObjectEvidenceError, SymbolStoreError, HmpError, ReaderError) as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    if as_json:
        click.echo(_json.dumps(payload, indent=2))
        return
    token = payload["token"]
    console.print(f"pid {payload['process']['pid']} ({payload['process']['name']}) token {token['body']}")
    console.print(f"  token-id={token['token_id']} auth-id={token['authentication_id']} session={token['session_id']}")
    console.print(f"  privileges: present={token['privileges']['present']} enabled={token['privileges']['enabled']}")


@kdbg.command("handles")
@click.argument("pid", type=int)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-safe JSON.")
@click.pass_context
def kdbg_handles(ctx: click.Context, pid: int, as_json: bool) -> None:
    """Show validated handle-table root and enumeration support state."""
    import json as _json

    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        console.print(f"[red][-][/] VM not running ({vm.state().value})")
        raise SystemExit(1)
    try:
        store = _get_store(cfg)
        ensure_object_layouts(cfg, store)
        with debug_snapshot(cfg, operation="handles") as snapshot:
            target = find_process(cfg.vm_name, store, pid=pid, cache=WalkCache())
            if target is None:
                raise ObjectEvidenceError(f"pid {pid} not found")
            payload = handle_table_status(cfg.vm_name, store, target)
            payload["snapshot_metadata"] = _snapshot_metadata(snapshot)
    except (ObjectEvidenceError, SymbolStoreError, HmpError, ReaderError) as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    if as_json:
        click.echo(_json.dumps(payload, indent=2))
        return
    table = payload["handle_table"]
    console.print(f"pid {pid}: handle table {table['address']} level={table['level']} root={table['root']}")
    state = payload["enumeration"]
    console.print(f"  enumeration: {'available' if state['available'] else 'refused'} — {state['reason']}")


@kdbg.command("object")
@click.argument("body", type=str)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-safe JSON.")
@click.pass_context
def kdbg_object(ctx: click.Context, body: str, as_json: bool) -> None:
    """Decode the header of a caller-proven kernel object body pointer."""
    import json as _json

    try:
        pointer = int(body, 0)
    except ValueError as exc:
        raise click.BadParameter(f"invalid object body: {body}") from exc
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        console.print(f"[red][-][/] VM not running ({vm.state().value})")
        raise SystemExit(1)
    try:
        store = _get_store(cfg)
        ensure_object_layouts(cfg, store)
        with debug_snapshot(cfg, operation="object") as snapshot:
            payload = object_header(cfg.vm_name, store, pointer).public()
            payload["snapshot_metadata"] = _snapshot_metadata(snapshot)
    except (ObjectEvidenceError, SymbolStoreError, HmpError, ReaderError) as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    if as_json:
        click.echo(_json.dumps(payload, indent=2))
        return
    console.print(f"object {payload['body']} header={payload['header']} type-index={payload['type_index']}")
