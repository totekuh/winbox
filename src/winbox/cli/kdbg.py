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

from winbox.cli import console, ensure_running, needs_vm
from winbox.config import Config
from winbox.kdbg import (
    SymbolLoadError,
    SymbolStore,
    SymbolStoreError,
    WalkCache,
    cached_pdb_path,
    copy_user_module,
    ensure_types_loaded,
    load_module,
    load_nt,
    read_cpu_state,
    read_virt_cr3,
    resolve_nt_base,
)
from winbox.kdbg.debugger import (
    ClientError,
    DaemonClient,
    DaemonError,
    InstallError,
    RspClient,
    RspError,
    fork_daemon,
    install_user_breakpoint,
)
from winbox.kdbg.format import format_struct as _format_struct, format_sym as _format_sym
from winbox.kdbg.hmp import HmpError, hmp as hmp_call, parse_registers, probe_port
from winbox.kdbg.walk import list_modules, list_processes, list_user_modules
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


@kdbg.command("user-lm")
@click.argument("pid", type=int)
@needs_vm()
def kdbg_user_lm(cfg: Config, vm: VM, ga: GuestAgent, pid: int) -> None:
    """Walk PEB.Ldr for ``pid`` and list every loaded user-mode module.

    The user-space mirror of ``kdbg lm``. Shows the EXE plus every DLL
    Windows mapped into the target's address space, in load order.

    First call after a fresh VM may pull missing struct layouts (_PEB,
    _PEB_LDR_DATA) out of the cached PDB on demand — no re-run of
    ``kdbg symbols`` needed.
    """
    store = _get_store(cfg)
    try:
        # Lazy-extract the PEB structs if the store predates their addition.
        ensure_types_loaded(cfg, store, ["_PEB", "_PEB_LDR_DATA"], module="nt")
    except (SymbolStoreError, SymbolLoadError) as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)

    cache = WalkCache()
    try:
        procs = list_processes(cfg.vm_name, store, cache=cache)
    except SymbolStoreError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    target = next((p for p in procs if p.pid == pid), None)
    if target is None:
        console.print(f"[red][-][/] pid {pid} not found in process list")
        raise SystemExit(1)

    try:
        mods = list_user_modules(cfg.vm_name, store, target, cache=cache)
    except (SymbolStoreError, HmpError) as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)

    if not mods:
        console.print(f"[yellow][!][/] pid {pid} ({target.name}) has no user modules "
                      f"(kernel-only process or PEB not yet initialised)")
        return

    console.print(f"[dim]pid {pid} ({target.name}) — DTB 0x{target.directory_table_base:x}[/]")
    console.print("[dim]  Base              Size        Name[/]")
    for m in mods:
        console.print(f"  0x{m.base:016x}  0x{m.size:08x}  {m.name}")
    console.print(f"[dim]({len(mods)} modules)[/]")


@kdbg.command("user-symbols")
@click.argument("pid", type=int)
@click.argument("module_name", metavar="MODULE")
@needs_vm()
def kdbg_user_symbols(cfg: Config, vm: VM, ga: GuestAgent, pid: int, module_name: str) -> None:
    """Load PDB symbols for a user-mode MODULE in ``pid``.

    MODULE matches against PEB.Ldr entries (case-insensitive substring
    on BaseDllName, then on FullDllName). Examples::

        winbox kdbg user-symbols 4712 notepad.exe
        winbox kdbg user-symbols 4712 ntdll
        winbox kdbg user-symbols 4712 kernelbase

    Pulls the binary out of the VM via VirtIO-FS, reads its CodeView
    debug entry, fetches the PDB from msdl, parses it with llvm-pdbutil,
    and persists under ``~/.winbox/symbols/`` keyed by the user-supplied
    short name (e.g. ``notepad`` for notepad.exe). Subsequent
    ``kdbg sym notepad!WinMain`` will resolve against that store.
    """
    store = _get_store(cfg)
    try:
        ensure_types_loaded(cfg, store, ["_PEB", "_PEB_LDR_DATA"], module="nt")
    except (SymbolStoreError, SymbolLoadError) as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)

    cache = WalkCache()
    procs = list_processes(cfg.vm_name, store, cache=cache)
    target = next((p for p in procs if p.pid == pid), None)
    if target is None:
        console.print(f"[red][-][/] pid {pid} not found in process list")
        raise SystemExit(1)

    mods = list_user_modules(cfg.vm_name, store, target, cache=cache)
    needle = module_name.lower()
    match = next(
        (m for m in mods if needle in m.name.lower()),
        None,
    )
    if match is None:
        match = next(
            (m for m in mods if needle in m.full_path.lower()),
            None,
        )
    if match is None:
        console.print(f"[red][-][/] no module matching {module_name!r} in pid {pid}")
        console.print(f"    try [bold]winbox kdbg user-lm {pid}[/] to see what's loaded")
        raise SystemExit(1)

    short_name = match.name.rsplit(".", 1)[0].lower()
    cached_basename = match.name

    with console.status(f"[blue]Copying {match.name}, fetching PDB, parsing..."):
        try:
            pe_path = copy_user_module(cfg, ga, match.full_path, cached_basename)
            info = load_module(
                cfg, store,
                pe_path=pe_path,
                module_name=short_name,
                base=match.base,
                wanted_types=(),
            )
        except (SymbolLoadError, SymbolStoreError) as e:
            console.print(f"[red][-][/] {e}")
            raise SystemExit(1)

    console.print(
        f"[green][+][/] {short_name} ({info.build}) — {info.symbol_count} symbols, "
        f"base=[bold]0x{info.base:x}[/]"
    )
    console.print(f"    stored at {info.path}")
    console.print(f"    try [bold]winbox kdbg sym {short_name}!<name>[/]")


@kdbg.command("user-bp")
@click.argument("pid", type=int)
@click.argument("target", metavar="VA_OR_SYMBOL")
@click.option(
    "--port", default=1234, show_default=True,
    help="Port the gdbstub is listening on.",
)
@click.option(
    "--timeout", default=30.0, show_default=True, type=float,
    help="Wall-clock budget for the install dance (seconds).",
)
@click.option(
    "--max-hits", default=10, show_default=True, type=int,
    help="Number of bp fires to observe before detaching.",
)
@click.pass_context
def kdbg_user_bp(
    ctx: click.Context,
    pid: int,
    target: str,
    port: int,
    timeout: float,
    max_hits: int,
) -> None:
    """Install a software bp at a USER virtual address in PID via gdbstub.

    TARGET is either a hex VA (``0x7ffbded10000``) or ``module!symbol``
    (``ntdll!NtClose``, ``notepad!WinMain``). Symbols must be loaded
    via ``winbox kdbg user-symbols`` first.

    The install dance: bp on ``nt!SwapContext``, on each fire step
    inside until CR3 changes, when CR3 matches target's DTB install
    Z0 at the user VA. Then resumes the VM and reports the first
    ``--max-hits`` bp fires (filtered: shows whether each hit's CR3
    matched target's DTB).

    Requires:
      - gdbstub running (``winbox kdbg start``)
      - nt symbols loaded (``winbox kdbg symbols``)
      - The user VA must be paged in already; cold pages will fail
        with E22 from QEMU.
    """
    cfg: Config = ctx.obj["cfg"]
    store = _get_store(cfg)
    vm = VM(cfg)
    if vm.state() != VMState.RUNNING:
        console.print(f"[red][-][/] VM not running ({vm.state().value})")
        raise SystemExit(1)
    if not probe_port("127.0.0.1", port):
        console.print(f"[red][-][/] gdbstub not listening on 127.0.0.1:{port}")
        console.print("    run [bold]winbox kdbg start[/] first")
        raise SystemExit(1)

    # Find target process to get its DTB.
    procs = list_processes(cfg.vm_name, store)
    target_proc = next((p for p in procs if p.pid == pid), None)
    if target_proc is None:
        console.print(f"[red][-][/] pid {pid} not found")
        raise SystemExit(1)

    # Resolve TARGET to a VA.
    if "!" in target:
        try:
            user_va = store.resolve(target)
        except SymbolStoreError as e:
            console.print(f"[red][-][/] symbol resolution failed: {e}")
            raise SystemExit(1)
    else:
        try:
            user_va = int(target, 0)
        except ValueError:
            raise click.BadParameter(f"not a valid VA or module!symbol: {target!r}")

    console.print(
        f"[dim]target: pid={pid} ({target_proc.name}) "
        f"dtb=0x{target_proc.directory_table_base:x}  "
        f"user_va=0x{user_va:x}[/]"
    )

    cli = RspClient.connect("127.0.0.1", port, timeout=10.0)
    try:
        cli.handshake()
        cli.query_halt_reason()

        with console.status(f"[blue]Installing user bp via CR3 masquerade..."):
            try:
                report = install_user_breakpoint(
                    cli, cfg.vm_name, store,
                    target_dtb=target_proc.directory_table_base,
                    user_va=user_va,
                    timeout=timeout,
                )
            except InstallError as e:
                console.print(f"[red][-][/] install failed: {e}")
                raise SystemExit(1)

        console.print(
            f"[green][+][/] bp installed in {report.elapsed*1000:.1f}ms "
            f"via CR3 masquerade (target_dtb=0x{report.target_dtb:x})"
        )

        # Drain hits, silent-continue when firing CR3 != target (this
        # is the Day 4 stop-time CR3 filter, inlined here for the demo).
        target_dtb = target_proc.directory_table_base
        console.print(f"\n[dim]Waiting for {max_hits} hits in target's address space (silent-cont others)...[/]\n")
        target_hits = 0
        skipped = 0
        deadline = timeout * 6  # generous outer budget
        import time as _t
        start_drain = _t.monotonic()
        while target_hits < max_hits and _t.monotonic() - start_drain < deadline:
            cli.cont()
            try:
                sr = cli.wait_for_stop(timeout=timeout)
            except RspError as e:
                console.print(f"[yellow][!][/] wait_for_stop: {e}")
                break
            cli.select_thread(sr.thread or "01")
            cr3 = cli.read_cr3()
            if cr3 != target_dtb:
                skipped += 1
                continue
            target_hits += 1
            import struct as _struct
            regs = cli.read_registers()
            rip = _struct.unpack_from("<Q", regs, 16 * 8)[0]
            console.print(
                f"  hit #{target_hits}: vCPU={sr.thread} RIP=0x{rip:x} "
                f"CR3=0x{cr3:x}  [bold green]<-- IN NOTEPAD[/]"
            )
        console.print(f"\n[dim]({target_hits} target hits, {skipped} silent-continues from other processes)[/]")

        # Cleanup: remove user bp, resume VM, detach.
        try:
            cli.remove_breakpoint(user_va, kind=1)
        except RspError as e:
            console.print(f"[yellow][!][/] failed to remove user bp: {e}")
        console.print("\n[green][+][/] detaching, leaving VM running")
    finally:
        cli.close()


# ── daemon-backed interactive debugger ────────────────────────────────


def _client(cfg: Config) -> DaemonClient:
    return DaemonClient(cfg)


def _print_stop(reason: str, info: dict) -> None:
    """Render a stop summary returned by cont/step."""
    if reason == "timeout":
        console.print("[yellow][!][/] cont timed out (no hit in target)")
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
@click.pass_context
def kdbg_attach(ctx: click.Context, pid: int, port: int) -> None:
    """Attach a kdbg debugging session to PID via the gdbstub.

    Forks a daemon that holds the gdb connection alive across CLI
    invocations. Subsequent ``winbox kdbg bp / cont / regs / mem / bt
    / detach`` commands talk to it via Unix socket. Only one session
    can be active at a time (enforced by an fcntl lock).

    Requires:
      - VM running, gdbstub started (``winbox kdbg start``)
      - nt symbols loaded (``winbox kdbg symbols``)
    """
    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    if vm.state() != VMState.RUNNING:
        console.print(f"[red][-][/] VM not running ({vm.state().value})")
        raise SystemExit(1)
    if not probe_port("127.0.0.1", port):
        console.print(f"[red][-][/] gdbstub not listening on 127.0.0.1:{port}")
        console.print("    run [bold]winbox kdbg start[/] first")
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

    try:
        daemon_pid = fork_daemon(cfg, pid, gdbstub_port=port)
    except DaemonError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)

    # Daemon wrote session.json before signalling OK; safe to read now.
    info = client.session_info() or {}
    console.print(
        f"[green][+][/] attached to {info.get('target_name', f'pid={pid}')}"
        f"({info.get('target_pid', pid)}) "
        f"dtb={info.get('target_dtb', '?')}  "
        f"daemon_pid={daemon_pid}"
    )
    console.print(f"    [dim]bp / cont / regs / mem / stack / bt / detach[/]")


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


@kdbg.command("bp")
@click.argument("target", metavar="VA_OR_SYMBOL")
@click.option(
    "--mode", type=click.Choice(["hw", "soft", "auto"], case_sensitive=False),
    default="hw", show_default=True,
    help=(
        "Breakpoint mechanism. 'hw' uses CPU debug registers (Z1) — "
        "PG-safe and anti-debug-invisible, limit 4 per vCPU. "
        "'soft' uses 0xCC patches (Z0) — unlimited but PG/hash visible. "
        "'auto' tries hw first, falls back to soft on slot exhaustion."
    ),
)
@click.option(
    "--condition", "condition", default=None,
    help=(
        "Optional predicate evaluated server-side on every in-target "
        "fire. False -> silent-cont (no halt surfaced). True -> halt. "
        "Grammar: regs (rax..r15, rip, eflags), [reg+0xN] qword reads, "
        "== != < <= > >=, & (bitwise), && || (short-circuit), parens. "
        "Examples: 'rcx == 0xdeadbeef', '[rsp+0x18] == 0x226048', "
        "'(rax & 0x80000000) != 0'."
    ),
)
@click.pass_context
def kdbg_bp(
    ctx: click.Context, target: str, mode: str, condition: str | None,
) -> None:
    """Install a bp at TARGET (hex VA or ``module!symbol``).

    Default mode is hardware (Z1) — invisible to PatchGuard and
    anti-debug GetThreadContext checks because KVM virtualizes DR
    access. Use ``--mode soft`` for the legacy 0xCC behaviour
    (needed when >4 simultaneous bps required).

    With ``--condition`` the daemon only halts on fires that satisfy
    the predicate; other fires silent-cont. See ``winbox kdbg bps``
    for predicate hit/skip/error counters.
    """
    cfg: Config = ctx.obj["cfg"]
    if condition is not None and not condition.strip():
        condition = None
    try:
        result = _client(cfg).call(
            "bp_add", target=target, mode=mode, condition=condition,
        )
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    user_kernel = "user" if result["user_mode"] else "kernel"
    bp_kind = "hw" if result["hw"] else "soft"
    cond_suffix = ""
    if result.get("condition"):
        cond_suffix = f"  cond={result['condition']!r}"
    console.print(
        f"[green][+][/] bp #{result['id']} at {result['va']} "
        f"({user_kernel}-mode, {bp_kind}, {result['elapsed_ms']:.1f}ms)"
        f"{cond_suffix}"
    )


@kdbg.command("bps")
@click.pass_context
def kdbg_bps(ctx: click.Context) -> None:
    """List installed breakpoints."""
    cfg: Config = ctx.obj["cfg"]
    try:
        result = _client(cfg).call("bp_list")
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    bps = result.get("bps", [])
    if not bps:
        console.print("[dim](no bps)[/]")
        return
    console.print("[dim]  id  VA                 kind  hits  age      target[/]")
    for b in bps:
        kind = "hw" if b.get("hw") else "soft"
        console.print(
            f"  {b['id']:2d}  {b['va']:18s} {kind:4s}  {b['hits']:5d}  "
            f"{b['age_s']:6.1f}s  {b['target']}"
        )


@kdbg.command("rm")
@click.argument("bp_id", type=int)
@click.pass_context
def kdbg_rm(ctx: click.Context, bp_id: int) -> None:
    """Remove bp by id."""
    cfg: Config = ctx.obj["cfg"]
    try:
        result = _client(cfg).call("bp_remove", id=bp_id)
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    console.print(f"[green][+][/] removed bp #{result['removed']} ({result['va']})")


@kdbg.command("cont")
@click.option("--timeout", default=30.0, show_default=True, type=float,
              help="Wall-clock cap before returning 'timeout'.")
@click.pass_context
def kdbg_cont(ctx: click.Context, timeout: float) -> None:
    """Resume the VM. Blocks until next bp hit in target's CR3."""
    cfg: Config = ctx.obj["cfg"]
    try:
        result = _client(cfg).call(
            "cont",
            sock_timeout=float(timeout) + 10.0,
            timeout=float(timeout),
        )
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    _print_stop(result.get("reason", "?"), result)


@kdbg.command("step")
@click.pass_context
def kdbg_step(ctx: click.Context) -> None:
    """Single-step the firing vCPU once."""
    cfg: Config = ctx.obj["cfg"]
    try:
        result = _client(cfg).call("step")
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    _print_stop(result.get("reason", "step"), result)


@kdbg.command("interrupt")
@click.pass_context
def kdbg_interrupt(ctx: click.Context) -> None:
    """Async halt the running target (use during a stuck cont)."""
    cfg: Config = ctx.obj["cfg"]
    try:
        _client(cfg).call("interrupt")
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    console.print("[dim]interrupt queued[/]")


@kdbg.command("regs")
@click.pass_context
def kdbg_regs(ctx: click.Context) -> None:
    """Dump current register state."""
    cfg: Config = ctx.obj["cfg"]
    try:
        result = _client(cfg).call("regs")
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    order = ["rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx",
             "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
             "eflags", "cs", "cr0", "cr2", "cr3", "cr4"]
    for k in order:
        if k in result:
            console.print(f"  {k.upper():6s}= {result[k]}")


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
    """Show N qwords starting at RSP."""
    cfg: Config = ctx.obj["cfg"]
    try:
        result = _client(cfg).call("stack", n=n)
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    console.print(f"[dim]RSP = {result['rsp']}[/]")
    rsp_val = int(result['rsp'], 16)
    for i, qw in enumerate(result["qwords"]):
        offset = i * 8
        console.print(f"  rsp+0x{offset:02x}: {qw}")


@kdbg.command("bt")
@click.option("-n", "--depth", type=int, default=8, show_default=True)
@click.pass_context
def kdbg_bt(ctx: click.Context, depth: int) -> None:
    """Crude stack walk; symbolicate likely return addresses."""
    cfg: Config = ctx.obj["cfg"]
    try:
        result = _client(cfg).call("bt", depth=depth)
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    frames = result.get("frames", [])
    if not frames:
        console.print("[dim](no candidate code addresses near RSP)[/]")
        return
    console.print(f"[dim]RSP = {result['rsp']}[/]")
    for f in frames:
        sym = f.get("sym") or "?"
        console.print(f"  {f['stack_off']:6s}  {f['addr']}  {sym}")


@kdbg.command("detach")
@click.pass_context
def kdbg_detach(ctx: click.Context) -> None:
    """Tear down the kdbg session (removes bps, resumes VM, releases lock)."""
    cfg: Config = ctx.obj["cfg"]
    client = _client(cfg)
    if not client.session_alive():
        console.print("[dim]no kdbg session attached[/]")
        return
    try:
        client.call("detach")
    except ClientError as e:
        console.print(f"[yellow][!][/] {e}")
    # Daemon should exit shortly. Wait briefly for the lock to release.
    import time as _t
    deadline = _t.monotonic() + 5.0
    while _t.monotonic() < deadline:
        if not client.session_alive():
            console.print("[green][+][/] detached")
            return
        _t.sleep(0.1)
    console.print("[yellow][!][/] daemon didn't exit within 5s; lock may be stale")


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
        sr = c.query_halt_reason()
        if sr.signal != 0 and state == VMState.RUNNING:
            console.print(f"[dim]VM was running; gdb halted it on attach (signal={sr.signal})[/]")
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


REGISTER = ("Integrations", [kdbg])
