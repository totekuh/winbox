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

from winbox.cli import console, needs_vm
from winbox.config import Config
from winbox.kdbg import (
    SymbolLoadError,
    SymbolStore,
    SymbolStoreError,
    WalkCache,
    copy_user_module,
    ensure_types_loaded,
    load_module,
    load_nt,
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
    masquerade_cr3_candidates,
)
from winbox.kdbg.debugger.reader import (
    ReaderError,
    debug_snapshot,
    reader_info,
    stop_reader,
)
from winbox.kdbg.debugger.protocol import WATCHPOINT_SIZES, WATCHPOINT_TYPES
from winbox.kdbg.debugger.trace import MAX_SUMMARY_TOP, MAX_TRACE_RESULTS
from winbox.kdbg.cet import (
    CetSafetyError,
    format_status as format_cet_status,
    prepare as prepare_cet,
    query_status as query_cet_status,
    restore as restore_cet_policy,
)
from winbox.kdbg.format import format_struct as _format_struct, format_sym as _format_sym
from winbox.kdbg.hmp import (
    HmpError,
    ensure_not_paused,
    hmp as hmp_call,
    probe_port,
)
from winbox.kdbg.walk import (
    find_process,
    list_modules,
    list_processes,
    list_user_modules,
)
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


# ── Symbol / struct / walker subcommands ────────────────────────────────


def _get_store(cfg: Config) -> SymbolStore:
    """The symbol store, with its nt base re-pointed if ASLR moved it.

    See the MCP twin: a base from a previous boot makes every walker fail
    with an error that names the page-table layer, not the actual cause.
    """
    from winbox.kdbg.symbols import ensure_nt_base_current

    store = SymbolStore(cfg.symbols_dir)
    ensure_nt_base_current(cfg, store)
    return store


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


@kdbg.command("user-lm")
@click.argument("pid", type=int)
@needs_vm(auto_start=False)
def kdbg_user_lm(cfg: Config, vm: VM, ga: GuestAgent, pid: int) -> None:
    """Walk PEB.Ldr for ``pid`` and list every loaded user-mode module.

    The user-space mirror of ``kdbg lm``. Shows the EXE plus every DLL
    Windows mapped into the target's address space, in load order.

    First call after a fresh VM may pull missing struct layouts (_PEB,
    _PEB_LDR_DATA) out of the cached PDB on demand — no re-run of
    ``kdbg symbols`` needed.
    """
    try:
        with debug_snapshot(cfg):
            store = _get_store(cfg)
        # Lazy-extract the PEB structs if the store predates their addition.
        ensure_types_loaded(
            cfg, store, ["_PEB", "_PEB_LDR_DATA", "_EWOW64PROCESS"], module="nt"
        )
    except (SymbolStoreError, SymbolLoadError, ReaderError) as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)

    try:
        with debug_snapshot(cfg):
            cache = WalkCache()
            target = find_process(cfg.vm_name, store, pid=pid, cache=cache)
            if target is None:
                console.print(f"[red][-][/] pid {pid} not found in process list")
                raise SystemExit(1)
            mods = list_user_modules(cfg.vm_name, store, target, cache=cache)
    except (SymbolStoreError, HmpError, ReaderError) as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)

    if not mods:
        console.print(f"[yellow][!][/] pid {pid} ({target.name}) has no user modules "
                      f"(kernel-only process or PEB not yet initialised)")
        return

    console.print(f"[dim]pid {pid} ({target.name}) — DTB 0x{target.directory_table_base:x}[/]")
    console.print("[dim]  Base              Size        Arch  Name[/]")
    for m in mods:
        console.print(
            f"  0x{m.base:016x}  0x{m.size:08x}  {m.architecture:4}  {m.name}"
        )
    console.print(f"[dim]({len(mods)} modules)[/]")


@kdbg.command("user-symbols")
@click.argument("pid", type=int)
@click.argument("module_name", metavar="MODULE")
@click.option(
    "--architecture", type=click.Choice(["auto", "x86", "x64"]),
    default="auto", show_default=True,
)
@needs_vm(auto_start=False)
def kdbg_user_symbols(
    cfg: Config, vm: VM, ga: GuestAgent, pid: int, module_name: str,
    architecture: str,
) -> None:
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
    try:
        with debug_snapshot(cfg):
            store = _get_store(cfg)
        ensure_types_loaded(
            cfg, store, ["_PEB", "_PEB_LDR_DATA", "_EWOW64PROCESS"], module="nt"
        )
    except (SymbolStoreError, SymbolLoadError, ReaderError) as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)

    try:
        with debug_snapshot(cfg):
            cache = WalkCache()
            target = find_process(cfg.vm_name, store, pid=pid, cache=cache)
            if target is None:
                console.print(f"[red][-][/] pid {pid} not found in process list")
                raise SystemExit(1)
            mods = list_user_modules(cfg.vm_name, store, target, cache=cache)
    except (SymbolStoreError, HmpError, ReaderError) as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    needle = module_name.lower()
    matches = [m for m in mods if needle in m.name.lower()]
    if not matches:
        matches = [m for m in mods if needle in m.full_path.lower()]
    if architecture != "auto":
        matches = [m for m in matches if m.architecture == architecture]
    if not matches:
        console.print(f"[red][-][/] no module matching {module_name!r} in pid {pid}")
        console.print(f"    try [bold]winbox kdbg user-lm {pid}[/] to see what's loaded")
        raise SystemExit(1)
    identities = {(m.name.lower(), m.architecture) for m in matches}
    if architecture == "auto" and len(identities) > 1:
        choices = ", ".join(f"{name}@{arch}" for name, arch in sorted(identities))
        console.print(f"[red][-][/] ambiguous module; use --architecture ({choices})")
        raise SystemExit(1)
    match = matches[0]

    short_name = match.name.rsplit(".", 1)[0].lower()
    if match.architecture == "x86":
        short_name += "_x86"
    cached_basename = match.name

    with console.status(f"[blue]Copying {match.name}, fetching PDB, parsing..."):
        try:
            pe_path = copy_user_module(
                cfg, ga, match.full_path, cached_basename,
                architecture=match.architecture,
                expected_size=match.size,
            )
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
    vm = VM(cfg)
    if vm.state() != VMState.RUNNING:
        console.print(f"[red][-][/] VM not running ({vm.state().value})")
        raise SystemExit(1)
    if reader_info(cfg) is None and not probe_port("127.0.0.1", port):
        console.print(f"[red][-][/] gdbstub not listening on 127.0.0.1:{port}")
        console.print("    run [bold]winbox kdbg start[/] first")
        raise SystemExit(1)

    # Find target process to get its DTB from one coherent VM snapshot.
    try:
        with debug_snapshot(cfg):
            store = _get_store(cfg)
            target_proc = find_process(cfg.vm_name, store, pid=pid)
    except (SymbolStoreError, HmpError) as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
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

    # The lookup above used the shared reader; this legacy foreground flow
    # now needs QEMU's one RSP client for itself. CET was checked before the
    # snapshot opened, and stop_reader hands ownership over without removing
    # the gdbserver listener.
    stop_reader(cfg)
    cli = RspClient.connect("127.0.0.1", port, timeout=10.0)
    try:
        cli.handshake()
        cli.query_halt_reason()

        # KVA-Shadow/KPTI builds split a process's page tables into two
        # roots; only retry the second when it was actually read off
        # KPROCESS (never guess — a wrong CR3 write here could patch the
        # wrong physical page). Shared rule — see masquerade_cr3_candidates.
        cr3_candidates = masquerade_cr3_candidates(
            target_proc.directory_table_base,
            target_proc.user_directory_table_base,
        )

        with console.status(f"[blue]Installing user bp via CR3 masquerade..."):
            try:
                report = install_user_breakpoint(
                    cli, cfg.vm_name, store,
                    cr3_candidates=cr3_candidates,
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
                # select_thread/read_cr3/read_registers are inside the guard too:
                # a transient RspError on any of them must break the drain so the
                # bp-removal cleanup after the loop still runs, not abort the whole
                # command and leave the software breakpoint patched in the guest.
                cli.select_thread(sr.thread or "01")
                cr3 = cli.read_cr3()
                if cr3 != target_dtb:
                    skipped += 1
                    continue
                import struct as _struct
                regs = cli.read_registers()
                rip = _struct.unpack_from("<Q", regs, 16 * 8)[0]
            except RspError as e:
                console.print(f"[yellow][!][/] drain step: {e}")
                break
            target_hits += 1
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
        from winbox.kdbg.staging import prepare_user_module_manifest
        manifest = prepare_user_module_manifest(
            cfg, ga, SymbolStore(cfg.symbols_dir), pid, enrich_symbols=True,
        )
    except Exception as e:
        console.print(f"[red][-][/] automatic module staging failed: {e}")
        raise SystemExit(1)

    # Hand the one-client gdbstub from the background read broker to the
    # interactive daemon only after the immutable artifact snapshot exists.
    stop_reader(cfg)
    if not probe_port("127.0.0.1", port):
        console.print(f"[red][-][/] gdbstub not listening on 127.0.0.1:{port}")
        console.print("    run [bold]winbox kdbg start[/] first")
        raise SystemExit(1)

    try:
        daemon_pid = fork_daemon(
            cfg, pid, gdbstub_port=port, module_manifest=manifest,
        )
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
    summary = manifest.summary()
    console.print(
        f"    [dim]auto-staged {summary['staged']} exact module(s), "
        f"{summary['symbol_enriched']} symbol-enriched, "
        f"{summary['symbol_failed']} PDB miss(es), "
        f"{summary['symbol_warning_count']} symbol warning(s), "
        f"{summary['failed']} failed[/]"
    )

    # Warn if HVCI is on — kernel breakpoints will not fire.
    try:
        from winbox import hvci as _hvci
        if _hvci.status(ga).hvci_enabled:
            console.print(
                "[yellow][!][/] HVCI is enabled — kernel breakpoints will not work. "
                "Run [bold]winbox hvci disable[/] first."
            )
    except Exception:
        pass  # Best-effort; GA might be busy after gdbstub connected


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
    "--mode", type=click.Choice(["hw", "soft"], case_sensitive=False),
    default="hw", show_default=True,
    help=(
        "Breakpoint mechanism. 'hw' uses CPU debug registers (Z1) — "
        "PG-safe and anti-debug-invisible, limit 4 per vCPU. "
        "'soft' uses 0xCC patches (Z0) — unlimited but PG/hash visible."
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
@click.option(
    "--watch", "wp_type",
    type=click.Choice(WATCHPOINT_TYPES, case_sensitive=False),
    default=None,
    help="Install a hardware watchpoint (Z2/Z3/Z4) instead of an execution bp.",
)
@click.option(
    "--size", "wp_size", type=click.Choice(WATCHPOINT_SIZES),
    default=1, show_default=True,
    help="Watched byte width; meaningful only with --watch.",
)
@click.option(
    "--action", "actions", multiple=True,
    help="Expression/capture to log on every hit; repeat up to 16 times.",
)
@click.pass_context
def kdbg_bp(
    ctx: click.Context,
    target: str,
    mode: str,
    condition: str | None,
    wp_type: str | None,
    wp_size: int,
    actions: tuple[str, ...],
) -> None:
    """Install a bp at TARGET (hex VA or ``module!symbol``).

    Default mode is hardware (Z1) — invisible to PatchGuard and
    anti-debug GetThreadContext checks because KVM virtualizes DR
    access. Use ``--mode soft`` for the legacy 0xCC behaviour
    (needed when >4 simultaneous bps required).

    ``--watch`` selects a hardware data watchpoint. Repeat ``--action``
    to log expressions/captures and auto-continue instead of halting.
    With ``--condition`` only matching hits are surfaced or logged.
    """
    cfg: Config = ctx.obj["cfg"]
    if condition is not None and not condition.strip():
        condition = None
    try:
        kwargs = {
            "target": target,
            "mode": mode,
            "condition": condition,
        }
        if wp_type is not None:
            kwargs.update({"wp_type": wp_type, "wp_size": wp_size})
        if actions:
            kwargs["actions"] = list(actions)
        result = _client(cfg).call("bp_add", **kwargs)
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    user_kernel = "user" if result["user_mode"] else "kernel"
    if result.get("wp_type"):
        bp_kind = f"watch-{result['wp_type']}/{result['wp_size']}"
    else:
        bp_kind = "hw" if result["hw"] else "soft"
    cond_suffix = ""
    if result.get("condition"):
        cond_suffix = f"  cond={result['condition']!r}"
    action_suffix = ""
    if result.get("actions"):
        action_suffix = f"  actions={len(result['actions'])}"
    console.print(
        f"[green][+][/] bp #{result['id']} at {result['va']} "
        f"({user_kernel}-mode, {bp_kind}, {result['elapsed_ms']:.1f}ms)"
        f"{cond_suffix}{action_suffix}"
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
        if b.get("wp_type"):
            kind = f"{b['wp_type']}/{b.get('wp_size', '?')}"
        else:
            kind = "hw" if b.get("hw") else "soft"
        console.print(
            f"  {b['id']:2d}  {b['va']:18s} {kind:4s}  {b['hits']:5d}  "
            f"{b['age_s']:6.1f}s  {b['target']}"
        )


@kdbg.command("bp-trace")
@click.argument("bp_id", type=int)
@click.option(
    "--tail", type=click.IntRange(1, MAX_TRACE_RESULTS),
    default=20, show_default=True,
)
@click.option("--from-hit", type=click.IntRange(min=0), default=None)
@click.option(
    "--limit", type=click.IntRange(1, MAX_TRACE_RESULTS),
    default=20, show_default=True,
)
@click.option("--expression", default=None, help="Filter/project one exact action.")
@click.option("--value", default=None, help="Filter an exact numeric or string value.")
@click.option("--errors-only", is_flag=True, help="Return only action errors.")
@click.option("--summary", is_flag=True, help="Include bounded value distributions.")
@click.option(
    "--top", type=click.IntRange(1, MAX_SUMMARY_TOP),
    default=10, show_default=True,
)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-safe JSON.")
@click.pass_context
def kdbg_bp_trace(
    ctx: click.Context,
    bp_id: int,
    tail: int,
    from_hit: int | None,
    limit: int,
    expression: str | None,
    value: str | None,
    errors_only: bool,
    summary: bool,
    top: int,
    as_json: bool,
) -> None:
    """Query bounded action-trace records for BP_ID."""
    cfg: Config = ctx.obj["cfg"]
    kwargs = {
        "id": bp_id,
        "tail": tail,
        "limit": limit,
        "errors_only": errors_only,
        "summary": summary,
        "top": top,
    }
    if from_hit is not None:
        kwargs["from_hit"] = from_hit
    if expression is not None:
        kwargs["expression"] = expression
    if value is not None:
        kwargs["value"] = value
    try:
        result = _client(cfg).call("bp_trace", **kwargs)
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)

    if as_json:
        import json as _json
        click.echo(_json.dumps(result, indent=2))
        return

    entries = result.get("entries", [])
    if not entries:
        console.print("[dim](no matching trace entries)[/]")
    for entry in entries:
        values = entry.get("values") or {}
        rendered = "  ".join(f"{key}={val}" for key, val in values.items())
        console.print(
            f"  #{entry.get('hit', '?'):<6} {entry.get('rip', '?'):18s} {rendered}"
        )
    suffix = " truncated" if result.get("truncated") else ""
    cursor = (
        f" next_hit={result['next_hit']}" if result.get("next_hit") is not None else ""
    )
    console.print(
        f"[dim]returned={result.get('returned', len(entries))} "
        f"total={result.get('total', '?')}{cursor}{suffix}[/]"
    )
    if result.get("summary") is not None:
        import json as _json
        console.print("[dim]summary[/]")
        click.echo(_json.dumps(result["summary"], indent=2))


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


@kdbg.command("cont-start")
@click.option(
    "--timeout", default=300.0, show_default=True, type=float,
    help="Wall-clock budget for the detached continue operation.",
)
@click.pass_context
def kdbg_cont_start(ctx: click.Context, timeout: float) -> None:
    """Start a durable continue operation and return immediately as JSON."""
    import json as _json
    from winbox.kdbg.debugger.continue_job import ContinueJobError, start_continue

    try:
        result = start_continue(ctx.obj["cfg"], timeout=timeout)
    except ContinueJobError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(_json.dumps(result, indent=2))


@kdbg.command("cont-poll")
@click.argument("token", required=False, default="")
@click.pass_context
def kdbg_cont_poll(ctx: click.Context, token: str) -> None:
    """Poll the current durable continue operation as JSON."""
    import json as _json
    from winbox.kdbg.debugger.continue_job import ContinueJobError, poll_continue

    try:
        result = poll_continue(ctx.obj["cfg"], token=token)
    except ContinueJobError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(_json.dumps(result, indent=2))


@kdbg.command("cont-cancel")
@click.argument("token", required=False, default="")
@click.pass_context
def kdbg_cont_cancel(ctx: click.Context, token: str) -> None:
    """Interrupt and cancel the current durable continue operation."""
    import json as _json
    from winbox.kdbg.debugger.continue_job import ContinueJobError, cancel_continue

    try:
        result = cancel_continue(ctx.obj["cfg"], token=token)
    except ContinueJobError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(_json.dumps(result, indent=2))


@kdbg.command("step")
@click.option("--over", is_flag=True, default=False,
              help="Step OVER call/syscall — temp hw bp at next instruction.")
@click.option("--out", is_flag=True, default=False,
              help="Step OUT of current function — temp hw bp at [rsp] return address.")
@click.pass_context
def kdbg_step(ctx: click.Context, over: bool, out: bool) -> None:
    """Single-step the firing vCPU."""
    if over and out:
        console.print("[red][-][/] --over and --out are mutually exclusive")
        raise SystemExit(1)
    cfg: Config = ctx.obj["cfg"]
    op = "step_out" if out else ("step_over" if over else "step")
    try:
        result = _client(cfg).call(op)
    except ClientError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    _print_stop(result.get("reason", op), result)


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


@kdbg.command("decomp")
@click.argument("address", required=False, default="")
@click.option("--symbol", default="", help="Loaded module!symbol to decompile.")
@click.option("--module", default="", help="Live module name (requires --rva).")
@click.option("--rva", default="", help="Module-relative address (requires --module).")
@click.option("--cursor", default="", help="Continuation cursor from a prior page.")
@click.option("--before", type=click.IntRange(0, 20), default=3, show_default=True)
@click.option("--after", type=click.IntRange(0, 20), default=5, show_default=True)
@click.option("--full", is_flag=True, help="Include the complete containing function.")
@click.option(
    "--binary", type=click.Path(path_type=Path, exists=True, dir_okay=False),
    default=None, help="Exact host-side PE; otherwise use the symbols cache.",
)
@click.option("--timeout", type=click.IntRange(5, 300), default=60, show_default=True)
@click.option(
    "--detail",
    type=click.Choice(["compact", "standard", "diagnostic"]),
    default="compact",
    show_default=True,
    help="Response evidence level.",
)
@click.option(
    "--lines",
    default="",
    metavar="N[-M]",
    help="Absolute pseudocode line or range; overrides before/after context.",
)
@click.option(
    "--assembly",
    type=click.Choice(["nearby", "mapped"]),
    default="nearby",
    show_default=True,
    help="Attach assembly to each selected mapped pseudocode line.",
)
@click.option("--instruction-bytes", is_flag=True, help="Include raw instruction bytes.")
@click.option("--runtime-vas", is_flag=True, help="Include repeated static/runtime VAs.")
@click.pass_context
def kdbg_decomp(
    ctx: click.Context,
    address: str,
    symbol: str,
    module: str,
    rva: str,
    cursor: str,
    before: int,
    after: int,
    full: bool,
    binary: Path | None,
    timeout: int,
    detail: str,
    lines: str,
    assembly: str,
    instruction_bytes: bool,
    runtime_vas: bool,
) -> None:
    """Show Ghidra pseudocode at ADDRESS, or at the current RIP.

    Resolves the live loaded module, converts the runtime VA to an RVA,
    verifies the cached PE against live CodeView/PE identity, and queries an
    isolated persistent PyGhidra worker. The first request for a binary runs
    Ghidra analysis; later requests reuse its project cache.
    """
    import json as _json
    from winbox.kdbg.decomp import DecompError, query_decomp

    cfg: Config = ctx.obj["cfg"]
    try:
        result = query_decomp(
            cfg,
            addr=address,
            symbol=symbol,
            module=module,
            rva=rva,
            cursor=cursor,
            before=before,
            after=after,
            full=full,
            binary=str(binary) if binary else "",
            timeout=timeout,
            detail=detail,
            lines=lines,
            assembly=assembly,
            instruction_bytes=instruction_bytes,
            runtime_vas=runtime_vas,
        )
    except DecompError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    # Rich wraps long strings at terminal width, which can insert literal
    # newlines inside JSON string values and corrupt piped output. This command
    # is an API-like evidence surface, so emit the serialized bytes verbatim.
    click.echo(_json.dumps(result, indent=2))


@kdbg.command("decomp-status")
@click.pass_context
def kdbg_decomp_status(ctx: click.Context) -> None:
    """Show Docker/PyGhidra API, JVM, and project-cache status."""
    import json as _json
    from winbox.kdbg.decomp import worker_status

    cfg: Config = ctx.obj["cfg"]
    # This is an API-like JSON surface. Rich wraps long string values at the
    # terminal width, which makes redirected output invalid JSON.
    click.echo(_json.dumps(worker_status(cfg), indent=2))


@kdbg.group("ghidra")
def kdbg_ghidra() -> None:
    """Install and manage the isolated headless Ghidra service."""
    pass


def _ghidra_lifecycle(ctx: click.Context, operation: str, **kwargs) -> None:
    import json as _json
    from winbox.kdbg.decomp import (
        DecompError, install_service, start_service, stop_service, worker_status,
    )

    cfg: Config = ctx.obj["cfg"]
    actions = {
        "install": lambda: install_service(cfg, **kwargs),
        "run": lambda: start_service(cfg),
        "stop": lambda: stop_service(cfg),
        "status": lambda: worker_status(cfg),
    }
    try:
        result = actions[operation]()
    except DecompError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    # Keep every lifecycle command safe to pipe through jq/json.tool even
    # when COLUMNS is tiny. Human-facing errors above still use Rich.
    click.echo(_json.dumps(result, indent=2))


@kdbg_ghidra.command("install")
@click.option("--pull/--no-pull", default=True, help="Refresh the pinned base image.")
@click.pass_context
def kdbg_ghidra_install(ctx: click.Context, pull: bool) -> None:
    """Build the pinned Ghidra + PyGhidra Docker image."""
    _ghidra_lifecycle(ctx, "install", pull=pull)


@kdbg_ghidra.command("run")
@click.pass_context
def kdbg_ghidra_run(ctx: click.Context) -> None:
    """Start the persistent local decompilation API."""
    _ghidra_lifecycle(ctx, "run")


@kdbg_ghidra.command("stop")
@click.pass_context
def kdbg_ghidra_stop(ctx: click.Context) -> None:
    """Stop and remove the managed service container."""
    _ghidra_lifecycle(ctx, "stop")


@kdbg_ghidra.command("status")
@click.pass_context
def kdbg_ghidra_status(ctx: click.Context) -> None:
    """Show image, container, API, JVM, and cache status."""
    _ghidra_lifecycle(ctx, "status")


@kdbg_ghidra.command("cache")
@click.pass_context
def kdbg_ghidra_cache(ctx: click.Context) -> None:
    """List content-keyed binary/project cache usage and LRU age."""
    import json as _json
    from winbox.kdbg.decomp import cache_inventory
    click.echo(_json.dumps(cache_inventory(ctx.obj["cfg"]), indent=2))


@kdbg_ghidra.command("prune")
@click.option("--max-bytes", type=click.IntRange(min=0), default=0)
@click.option("--older-than-days", type=click.FloatRange(min=0), default=0.0)
@click.option("--apply", is_flag=True, help="Delete selected entries; default is dry-run.")
@click.pass_context
def kdbg_ghidra_prune(
    ctx: click.Context, max_bytes: int, older_than_days: float, apply: bool,
) -> None:
    """Preview or apply bounded LRU cache pruning."""
    import json as _json
    from winbox.kdbg.decomp import DecompError, prune_cache
    try:
        result = prune_cache(
            ctx.obj["cfg"], max_bytes=max_bytes,
            older_than_days=older_than_days, dry_run=not apply,
        )
    except DecompError as exc:
        console.print(f"[red][-][/] {exc}")
        raise SystemExit(1)
    click.echo(_json.dumps(result, indent=2))


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


REGISTER = ("Integrations", [kdbg])
