"""Low-level inspection and session recovery — mem, stack, context, bt, detach, resume, base."""

from __future__ import annotations

import click

from winbox.cli import console
from winbox.cli.kdbg import kdbg, _get_store
from winbox.cli.kdbg.debugger import _client
from winbox.config import Config
from winbox.kdbg import SymbolStore, SymbolStoreError, resolve_nt_base
from winbox.kdbg.debugger import ClientError, DaemonClient, RspClient, RspError
from winbox.kdbg.hmp import ensure_not_paused, probe_port
from winbox.vm import VM, VMState
from winbox import __version__
from winbox.kdbg.catalog import MCP_CATALOG_REVISION, MCP_TOOL_COUNT


@kdbg.command("mem")
@click.argument("address", metavar="VA")
@click.argument("length", type=int, default=64)
@click.pass_context
def kdbg_mem(ctx: click.Context, address: str, length: int) -> None:
    """Read LENGTH bytes at VA in target's address space."""
    cfg: Config = ctx.obj["cfg"]
    try:
        result = _client(cfg).call("mem", va=address, length=length)
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    raw = bytes.fromhex(result["bytes"])
    base = int(result["va"], 16)
    for i in range(0, len(raw), 16):
        chunk = raw[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        console.print(f"  0x{base + i:016x}  {hex_part:<48}  {ascii_part}")


@kdbg.command("stack")
@click.argument("n", type=int, default=16)
@click.pass_context
def kdbg_stack(ctx: click.Context, n: int) -> None:
    """Show N native words starting at RSP/ESP."""
    cfg: Config = ctx.obj["cfg"]
    try:
        result = _client(cfg).call("stack", n=n)
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    register = result.get("stack_register", "rsp").upper()
    console.print(f"[dim]{register} = {result.get('sp', result['rsp'])}[/]")
    for entry in result.get("entries", result.get("qwords", [])):
        console.print(f"  {entry['offset']}: {entry['value']}")


@kdbg.command("context")
@click.option("--disasm-count", type=click.IntRange(0, 32), default=8)
@click.option("--stack-qwords", type=click.IntRange(0, 32), default=16)
@click.option("--bt-depth", type=click.IntRange(0, 16), default=8)
@click.pass_context
def kdbg_context(
    ctx: click.Context, disasm_count: int, stack_qwords: int, bt_depth: int
) -> None:
    """Emit a bounded JSON triage bundle for the current stop."""
    import json as _json

    cfg: Config = ctx.obj["cfg"]
    try:
        result = _client(cfg).call(
            "context", disasm_count=disasm_count,
            stack_qwords=stack_qwords, bt_depth=bt_depth,
        )
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    click.echo(_json.dumps(result, indent=2))


@kdbg.command("bt")
@click.option("-n", "--depth", type=int, default=8, show_default=True)
@click.pass_context
def kdbg_bt(ctx: click.Context, depth: int) -> None:
    """Unwind Windows x64, WoW64 x86, or a validated mixed stack."""
    cfg: Config = ctx.obj["cfg"]
    try:
        result = _client(cfg).call("bt", depth=depth)
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    frames = result.get("frames", [])
    if not frames:
        console.print("[dim](no unwindable frames)[/]")
        if result.get("error"):
            console.print(f"[yellow][!][/] {result['error']}")
        return
    console.print(
        f"[dim]RSP = {result['rsp']}  method={result.get('method', 'unknown')}[/]"
    )
    for f in frames:
        sym = f.get("sym") or "?"
        location = f"{f.get('module', '?')}+{f.get('rva', '?')}"
        console.print(
            f"  #{f.get('index', '?'):<2}  {f['addr']}  {f.get('rsp', '?')}  "
            f"{location}  {sym}  [{f.get('unwind', 'partial')}]"
        )
    if result.get("error"):
        console.print(f"[yellow][!][/] partial: {result['error']}")


@kdbg.command("detach")
@click.pass_context
def kdbg_detach(ctx: click.Context) -> None:
    """Tear down kdbg; resume only with the daemon's safety certificate."""
    cfg: Config = ctx.obj["cfg"]
    client = _client(cfg)
    if not client.session_alive():
        console.print("[dim]no kdbg session attached[/]")
        return
    # A durable cont owns the daemon's heavy-operation slot. Interrupt it and
    # wait briefly so detach is not rejected as BUSY.
    from winbox.kdbg.debugger.continue_job import (
        ACTIVE_STATES, ContinueJobError, cancel_continue, poll_continue,
        wait_continue,
    )
    try:
        job = poll_continue(cfg)
        if job.get("state") in ACTIVE_STATES:
            cancel_continue(cfg, token=str(job["token"]))
            wait_continue(cfg, token=str(job["token"]), timeout=5.0)
    except ContinueJobError as exc:
        console.print(f"[yellow][!][/] async continue cleanup: {exc}")
    detach_result = None
    detach_error = None
    try:
        detach_result = client.call("detach")
    except ClientError as e:
        detach_error = e
        console.print(f"[yellow][!][/] {e}")
    # Daemon should exit shortly. Wait briefly for the lock to release.
    import time as _t
    deadline = _t.monotonic() + 5.0
    detached = False
    while _t.monotonic() < deadline:
        if not client.session_alive():
            console.print("[green][+][/] detached")
            detached = True
            break
        _t.sleep(0.1)
    if not detached:
        console.print("[yellow][!][/] daemon didn't exit within 5s; lock may be stale")
    resume_safe = bool(
        detach_result is not None and detach_result.get("resume_safe") is True
    )
    note = ensure_not_paused(cfg.vm_name) if detached and resume_safe else None
    if note:
        console.print(f"[yellow][!][/] {note}")
    recovery = detach_result.get("recovery") if detach_result else None
    if recovery:
        console.print(f"[yellow][!][/] {recovery}")
    if detach_error is not None and not detached:
        console.print(
            "[red][-][/] automatic resume skipped: daemon did not certify "
            "that resuming is safe"
        )
        raise SystemExit(1)


@kdbg.command("resume")
@click.option("--port", default=1234, show_default=True,
              help="gdbstub port to talk through.")
@click.pass_context
def kdbg_resume(ctx: click.Context, port: int) -> None:
    """Resume a VM stuck in 'paused (debug)' state.

    Recovery valve for when a daemon crashed mid-session or a script
    bailed without cleaning up. Connects briefly to the gdbstub, sends
    'continue' + 'detach' so QEMU's gdb_continue() runs and the VM
    resumes execution. Safe to run if VM is already running (no-op).
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    state = vm.state()

    if state != VMState.RUNNING and state != VMState.PAUSED:
        console.print(f"[yellow][!][/] VM state is {state.value}; nothing to do")
        return

    if state == VMState.RUNNING:
        # Already running: there is nothing to continue, and asking the
        # gdbstub to anyway blocks waiting for a stop reply that never comes
        # ("empty stop reply"). This is documented as a safe no-op, so it has
        # to actually be one — a recovery valve that errors on a healthy VM
        # is one people learn not to trust.
        console.print("[green][+][/] VM is already running; nothing to resume")
        return

    if not probe_port("127.0.0.1", port):
        console.print(f"[red][-][/] gdbstub not listening on 127.0.0.1:{port}")
        console.print("    if VM is paused but gdbstub is gone, try [bold]virsh resume winbox[/]")
        raise SystemExit(1)

    # Check if a daemon already holds the session — if so, defer to it.
    client = DaemonClient(cfg)
    if client.session_alive():
        console.print(
            "[yellow][!][/] a kdbg session is active; "
            "use [bold]winbox kdbg detach[/] to tear it down cleanly"
        )
        raise SystemExit(1)

    try:
        c = RspClient.connect("127.0.0.1", port, timeout=5)
    except (OSError, RspError) as e:
        console.print(f"[red][-][/] gdbstub connect failed: {e}")
        raise SystemExit(1)
    try:
        c.handshake()
        c.query_halt_reason()
        c.cont()
    finally:
        # close() does interrupt+detach which leaves VM running.
        c.close()

    # Verify
    import time as _t
    _t.sleep(0.3)
    final = vm.state()
    if final == VMState.RUNNING:
        console.print(f"[green][+][/] VM resumed")
    else:
        console.print(f"[yellow][!][/] VM state after release: {final.value}")


@kdbg.command("base")
@click.pass_context
def kdbg_base(ctx: click.Context) -> None:
    """Re-resolve and persist the nt load base from the live guest.

    Use this if ``kdbg symbols`` couldn't reach the guest or the VM was
    rebooted (ASLR re-randomizes the base each boot).
    """
    cfg: Config = ctx.obj["cfg"]
    store = _get_store(cfg)
    vm = VM(cfg)
    if vm.state() != VMState.RUNNING:
        console.print(f"[red][-][/] VM not running ({vm.state().value})")
        raise SystemExit(1)

    try:
        data = store.load("nt")
    except SymbolStoreError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)

    try:
        base = resolve_nt_base(cfg, data.get("symbols", {}))
    except Exception as e:
        console.print(f"[red][-][/] could not resolve nt base: {e}")
        raise SystemExit(1)
    store.set_base("nt", base)
    console.print(f"[green][+][/] nt base = 0x{base:x}")
