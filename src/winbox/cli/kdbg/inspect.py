"""Symbol lookup, struct layout, process/module list, and VA read commands."""

from __future__ import annotations

from pathlib import Path

import click

from winbox.cli import console, needs_vm
from winbox.cli.kdbg import kdbg, _get_store
from winbox.config import Config
from winbox.kdbg import (
    SymbolLoadError, SymbolStore, SymbolStoreError, WalkCache,
    load_nt, read_virt_cr3,
)
from winbox.kdbg.debugger.reader import debug_snapshot
from winbox.kdbg.format import format_struct as _format_struct, format_sym as _format_sym
from winbox.kdbg.hmp import HmpError
from winbox.kdbg.walk import find_process, list_modules, list_processes
from winbox.vm import VM, GuestAgent, VMState


@kdbg.command("symbols")
@needs_vm()
def kdbg_symbols(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Load or refresh symbols + struct offsets for nt.

    Does the full PE+PDB dance against the running VM: pulls
    ntoskrnl.exe out via VirtIO-FS, fetches the matching PDB from msdl,
    parses with llvm-pdbutil, persists per-build under ``~/.winbox/symbols/``.
    """
    store = _get_store(cfg)
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
    vm = VM(cfg)
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        console.print(f"[red][-][/] VM not running ({vm.state().value})")
        raise SystemExit(1)

    try:
        with debug_snapshot(cfg):
            store = _get_store(cfg)
            procs = list_processes(cfg.vm_name, store)
    except (SymbolStoreError, HmpError) as e:
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
    vm = VM(cfg)
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        console.print(f"[red][-][/] VM not running ({vm.state().value})")
        raise SystemExit(1)

    try:
        with debug_snapshot(cfg):
            store = _get_store(cfg)
            mods = list_modules(cfg.vm_name, store)
    except (SymbolStoreError, HmpError) as e:
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
    vm = VM(cfg)
    if vm.state() not in (VMState.RUNNING, VMState.PAUSED):
        console.print(f"[red][-][/] VM not running ({vm.state().value})")
        raise SystemExit(1)

    try:
        va = int(address, 0)
    except ValueError:
        # Argument-shape problem (not a runtime VM failure) -> Click exception
        # so the user gets the standard "Error: ..." prefix.
        raise click.BadParameter(f"invalid address: {address}")

    try:
        with debug_snapshot(cfg):
            store = _get_store(cfg)
            cache = WalkCache()
            target = find_process(cfg.vm_name, store, pid=pid, cache=cache)
            if target is None:
                console.print(f"[red][-][/] pid {pid} not found in process list")
                raise SystemExit(1)
            data = read_virt_cr3(
                cfg.vm_name,
                target.directory_table_base,
                va,
                length,
                cache=cache,
            )
    except (HmpError, SymbolStoreError) as e:
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
