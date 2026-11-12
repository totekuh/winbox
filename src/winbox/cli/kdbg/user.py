"""User-mode debugging commands — user-lm, user-symbols, user-bp."""

from __future__ import annotations

import click

from winbox.cli import console, needs_vm
from winbox.cli.kdbg import kdbg, _get_store
from winbox.config import Config
from winbox.kdbg import (
    SymbolLoadError,
    SymbolStore,
    SymbolStoreError,
    WalkCache,
    copy_user_module,
    ensure_types_loaded,
    load_module,
)
from winbox.kdbg.debugger import (
    InstallError,
    RspClient,
    RspError,
    install_user_breakpoint,
    masquerade_cr3_candidates,
)
from winbox.kdbg.debugger.reader import (
    ReaderError,
    debug_snapshot,
    reader_info,
    stop_reader,
)
from winbox.kdbg.hmp import HmpError, probe_port
from winbox.kdbg.walk import find_process, list_user_modules
from winbox.vm import VM, GuestAgent, VMState


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
