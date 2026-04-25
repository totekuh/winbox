"""Hypervisor-level kernel debug stub — start, stop, status, symbols, walks.

Uses QEMU's built-in gdbstub via the HMP `gdbserver` command. The stub
runs inside the QEMU process on the Kali host; nothing ever touches the
guest kernel, so flags like KdDebuggerEnabled / KdDebuggerNotPresent
stay pristine and in-guest anti-tamper checks don't see the debugger.

Default bind is 127.0.0.1 — the bare `tcp::<port>` chardev form binds
to 0.0.0.0, which would let anything on the LAN take full r/w on guest
RAM and registers. `--any-interface` is the explicit opt-out.

Beyond start/stop, this module exposes helpers that turn a raw gdbstub
into something actually usable for Windows kernel RE: symbol loading
from PDBs on msdl, struct offset lookups, process and module walks, and
cross-CR3 virtual memory reads for peeking into other processes while
halted.
"""

from __future__ import annotations

from pathlib import Path

import click

from winbox.cli import console, ensure_running
from winbox.config import Config
from winbox.kdbg import (
    SymbolStore,
    SymbolStoreError,
    WalkCache,
    load_from_ghidra,
    load_nt,
    read_cpu_state,
    read_virt_cr3,
    resolve_nt_base,
)
from winbox.kdbg.format import format_struct as _format_struct, format_sym as _format_sym
from winbox.kdbg.hmp import HmpError, hmp as hmp_call, probe_port
from winbox.kdbg.walk import list_modules, list_processes
from winbox.vm import VM, GuestAgent, VMState

# Use the canonical HMP wrapper in tuple-mode for start/stop/status so the
# raw virsh stderr lands in the user's terminal verbatim — the default
# raising mode would wrap it in "HMP '<cmd>' failed: ...".
def _hmp(vm_name: str, command: str) -> tuple[int, str, str]:
    return hmp_call(vm_name, command, mode="tuple")


def _cheat_sheet(port: int) -> None:
    """Print the gdb incantation so the user doesn't have to memorize it."""
    console.print()
    console.print("  Attach from Kali:")
    console.print(f"    [bold]gdb -ex 'set architecture i386:x86-64' -ex 'target remote :{port}'[/]")
    console.print()
    console.print("  Useful commands once attached:")
    console.print("    [dim]info registers rip rsp cr3[/]   show kernel state")
    console.print("    [dim]x/20i $rip[/]                    disassemble at current RIP")
    console.print("    [dim]hbreak *0xfffff80...[/]          hardware breakpoint (stealthy, 4 slots)")
    console.print("    [dim]break  *0xfffff80...[/]          software breakpoint (writes 0xCC, EDR-visible)")
    console.print("    [dim]c[/]                              resume the VM")
    console.print("    [dim]detach[/]                         release the VM")
    console.print()
    console.print("  Stop the stub when done: [bold]winbox kdbg stop[/]")


@click.group()
def kdbg() -> None:
    """Hypervisor-level kernel debug via QEMU gdbstub."""
    pass


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

    rc, out, err = _hmp(cfg.vm_name, "gdbserver none")
    if rc != 0:
        console.print(f"[red][-][/] Failed to stop gdb stub: {err or out}")
        raise SystemExit(1)

    console.print("[green][+][/] gdb stub stopped")


@kdbg.command("status")
@click.option("--port", default=1234, show_default=True, help="Port to probe.")
@click.pass_context
def kdbg_status(ctx: click.Context, port: int) -> None:
    """Show whether the gdb stub is listening.

    Probes 127.0.0.1:<port> with a TCP connect. QEMU's gdbstub only
    accepts a single client at a time, so "listening but probe fails" is
    the usual signal that a gdb session is already attached.
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)

    if vm.state() != VMState.RUNNING:
        console.print(f"[yellow][!][/] VM is not running (state: {vm.state().value})")
        return

    listening = probe_port("127.0.0.1", port)
    if listening:
        console.print(f"gdb stub: [green]listening[/] on 127.0.0.1:{port}")
    else:
        console.print(f"gdb stub: [red]not running[/] (nothing on 127.0.0.1:{port})")


# ── Symbol / struct / walker subcommands ────────────────────────────────


def _get_store(cfg: Config) -> SymbolStore:
    return SymbolStore(cfg.symbols_dir)


@kdbg.command("symbols")
@click.argument("module", default="nt")
@click.option(
    "--from-ghidra", "ghidra_json", type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Ingest a Ghidra-exported JSON instead of pulling from msdl.",
)
@click.option(
    "--base", type=str,
    help="Override module load base (hex). Useful with --from-ghidra when the "
    "driver is loaded at a fixed address you already know.",
)
@click.pass_context
def kdbg_symbols(
    ctx: click.Context,
    module: str,
    ghidra_json: Path | None,
    base: str | None,
) -> None:
    """Load or refresh symbols + struct offsets for a module.

    ``nt`` is the default and does the full PE+PDB dance against the
    running VM. Any other module name with ``--from-ghidra <path>``
    imports a user-supplied JSON.
    """
    cfg: Config = ctx.obj["cfg"]
    store = _get_store(cfg)

    if ghidra_json is not None:
        base_int = int(base, 16) if base else None
        info = load_from_ghidra(store, module, ghidra_json, base=base_int)
        console.print(
            f"[green][+][/] loaded {info.module} from {ghidra_json.name} — "
            f"{info.symbol_count} symbols, {info.type_count} types"
        )
        return

    if module != "nt":
        console.print(
            f"[red][-][/] automatic fetch only supported for 'nt' — "
            f"for {module} supply --from-ghidra"
        )
        raise SystemExit(1)

    # Stays raw (no @needs_vm): --from-ghidra above returns without touching
    # the VM. Decorating the function would boot the VM unnecessarily for
    # offline imports.
    vm = VM(cfg)
    ga = GuestAgent(cfg)
    ensure_running(vm, ga, cfg)
    with console.status("[blue]Copying ntoskrnl.exe, fetching PDB, parsing..."):
        info = load_nt(cfg, ga, store)

    base_text = f"base=[bold]0x{info.base:x}[/]" if info.base else "base=[red]unresolved[/]"
    console.print(
        f"[green][+][/] nt ({info.build}) — {info.symbol_count} symbols, "
        f"{info.type_count} types, {base_text}"
    )
    console.print(f"    stored at {info.path}")


@kdbg.command("sym")
@click.argument("name")
@click.option("-c", "--count", default=1, show_default=True, help="Max matches to return for substring search.")
@click.option("--rva", is_flag=True, help="Return RVA instead of absolute VA (no base required).")
@click.option("--search", is_flag=True, help="Substring search instead of exact lookup.")
@click.pass_context
def kdbg_sym(
    ctx: click.Context,
    name: str,
    count: int,
    rva: bool,
    search: bool,
) -> None:
    """Resolve a symbol to its address. Use ``mod!sym`` to pick a module.

    Examples::

        winbox kdbg sym nt!NtCreateFile
        winbox kdbg sym KiSystemCall64 --rva
        winbox kdbg sym PsActive --search -c 20
    """
    cfg: Config = ctx.obj["cfg"]
    store = _get_store(cfg)
    try:
        lines = _format_sym(store, name, search=search, limit=count, rva=rva)
    except SymbolStoreError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    if not lines:
        console.print(f"[red][-][/] no matches for {name}")
        raise SystemExit(1)
    for line in lines:
        console.print(line)


@kdbg.command("struct")
@click.argument("type_name")
@click.argument("field", required=False)
@click.option("--module", "-m", default="nt", show_default=True, help="Module to look up the type in.")
@click.pass_context
def kdbg_struct(
    ctx: click.Context,
    type_name: str,
    field: str | None,
    module: str,
) -> None:
    """Show struct layout or a single field offset.

    Examples::

        winbox kdbg struct _EPROCESS
        winbox kdbg struct _EPROCESS DirectoryTableBase
    """
    cfg: Config = ctx.obj["cfg"]
    store = _get_store(cfg)
    try:
        lines = _format_struct(store, type_name, field=field, module=module)
    except SymbolStoreError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)

    # First line is the header (or single-field summary). Bold it on the
    # CLI for the layout case so the caller can pick out the size at a
    # glance; rest passes through verbatim.
    if field is None and lines:
        console.print(f"[bold]{lines[0]}[/]")
        for line in lines[1:]:
            console.print(line)
    else:
        for line in lines:
            console.print(line)


@kdbg.command("ps")
@click.pass_context
def kdbg_ps(ctx: click.Context) -> None:
    """Walk ``PsActiveProcessHead`` and list all processes.

    Shows PID, DirectoryTableBase (CR3), EPROCESS VA, and image name.
    Use the DTB values as input to ``winbox kdbg read-va`` for
    cross-process reads.
    """
    cfg: Config = ctx.obj["cfg"]
    store = _get_store(cfg)
    vm = VM(cfg)
    if vm.state() != VMState.RUNNING:
        console.print(f"[red][-][/] VM not running ({vm.state().value})")
        raise SystemExit(1)

    try:
        procs = list_processes(cfg.vm_name, store)
    except SymbolStoreError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)

    console.print(
        f"[dim]  PID       DTB              EPROCESS            Name[/]"
    )
    for p in procs:
        console.print(
            f"  {p.pid:5d}  0x{p.directory_table_base:012x}  "
            f"0x{p.eprocess:016x}  {p.name}"
        )
    console.print(f"[dim]({len(procs)} processes)[/]")


@kdbg.command("lm")
@click.pass_context
def kdbg_lm(ctx: click.Context) -> None:
    """Walk ``PsLoadedModuleList`` and list loaded kernel modules.

    Shows base VA, image size, and driver/module name.
    """
    cfg: Config = ctx.obj["cfg"]
    store = _get_store(cfg)
    vm = VM(cfg)
    if vm.state() != VMState.RUNNING:
        console.print(f"[red][-][/] VM not running ({vm.state().value})")
        raise SystemExit(1)

    try:
        mods = list_modules(cfg.vm_name, store)
    except SymbolStoreError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)

    console.print("[dim]  Base              Size        Name[/]")
    for m in mods:
        console.print(f"  0x{m.base:016x}  0x{m.size:08x}  {m.name}")
    console.print(f"[dim]({len(mods)} modules)[/]")


@kdbg.command("read-va")
@click.argument("pid", type=int)
@click.argument("address", type=str)
@click.argument("length", type=int)
@click.option(
    "--output", "-o", type=click.Path(dir_okay=False, path_type=Path),
    help="Write bytes to file instead of hexdumping to stdout.",
)
@click.pass_context
def kdbg_read_va(
    ctx: click.Context,
    pid: int,
    address: str,
    length: int,
    output: Path | None,
) -> None:
    """Read virtual memory from a target process — the CR3-switching primitive.

    Looks up the target's EPROCESS via ``kdbg ps``, grabs its
    ``DirectoryTableBase``, and walks the page tables manually against
    that CR3. Works regardless of which process was scheduled on the CPU
    at halt time.

    Examples::

        winbox kdbg read-va 4712 0x7ff600001000 256
        winbox kdbg read-va 4712 0x7ff600001000 4096 -o /tmp/dump.bin
    """
    cfg: Config = ctx.obj["cfg"]
    store = _get_store(cfg)
    vm = VM(cfg)
    if vm.state() != VMState.RUNNING:
        console.print(f"[red][-][/] VM not running ({vm.state().value})")
        raise SystemExit(1)

    try:
        va = int(address, 0)
    except ValueError:
        # Argument-shape problem (not a runtime VM failure) -> Click exception
        # so the user gets the standard "Error: ..." prefix.
        raise click.BadParameter(f"invalid address: {address}")

    cache = WalkCache()
    procs = list_processes(cfg.vm_name, store, cache=cache)
    target = next((p for p in procs if p.pid == pid), None)
    if target is None:
        console.print(f"[red][-][/] pid {pid} not found in process list")
        raise SystemExit(1)

    try:
        data = read_virt_cr3(
            cfg.vm_name,
            target.directory_table_base,
            va,
            length,
            cache=cache,
        )
    except HmpError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)

    if output is not None:
        output.write_bytes(data)
        console.print(
            f"[green][+][/] wrote {len(data)} bytes from pid {pid} "
            f"@ 0x{va:x} -> {output}"
        )
        return

    # Hexdump 16 bytes per line
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        console.print(f"  0x{va + i:016x}  {hex_part:<48}  {ascii_part}")


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


REGISTER = ("Integrations", [kdbg])
