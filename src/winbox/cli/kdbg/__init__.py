"""Hypervisor-level kernel debug stub — start, stop, status, symbols, walks.

Uses QEMU's built-in gdbstub via the HMP ``gdbserver`` command. The stub
runs inside the QEMU process on the Kali host; nothing ever touches the
guest kernel, so flags like KdDebuggerEnabled / KdDebuggerNotPresent
stay pristine and in-guest anti-tamper checks don't see the debugger.

Default bind is 127.0.0.1 — the bare ``tcp::<port>`` chardev form binds
to 0.0.0.0, which would let anything on the LAN take full r/w on guest
RAM and registers. ``--any-interface`` is the explicit opt-out.

Beyond start/stop, this module exposes helpers that turn a raw gdbstub
into something actually usable for Windows kernel RE: symbol loading
from PDBs on msdl, struct offset lookups, process and module walks, and
cross-CR3 virtual memory reads for peeking into other processes while
halted.
"""

from __future__ import annotations

import click

from winbox.cli import console
from winbox.config import Config
from winbox.kdbg import SymbolStore
from winbox.kdbg.hmp import hmp as hmp_call


@click.group()
def kdbg() -> None:
    """Hypervisor-level kernel debug via QEMU gdbstub."""
    pass


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


def _get_store(cfg: Config) -> SymbolStore:
    """The symbol store, with its nt base re-pointed if ASLR moved it.

    See the MCP twin: a base from a previous boot makes every walker fail
    with an error that names the page-table layer, not the actual cause.
    """
    from winbox.kdbg.symbols import ensure_nt_base_current

    store = SymbolStore(cfg.symbols_dir)
    ensure_nt_base_current(cfg, store)
    return store


# Import submodules to trigger Click command registration.
# Order matters: debugger defines _client/_print_stop used by later modules.
from winbox.cli.kdbg import lifecycle  # noqa: E402, F401
from winbox.cli.kdbg import inspect  # noqa: E402, F401
from winbox.cli.kdbg import evidence  # noqa: E402, F401
from winbox.cli.kdbg import threads  # noqa: E402, F401
from winbox.cli.kdbg import triage  # noqa: E402, F401
from winbox.cli.kdbg import snapshots  # noqa: E402, F401
from winbox.cli.kdbg import debugger  # noqa: E402, F401
from winbox.cli.kdbg import breakpoints  # noqa: E402, F401
from winbox.cli.kdbg import execution  # noqa: E402, F401
from winbox.cli.kdbg import user  # noqa: E402, F401
from winbox.cli.kdbg import decomp  # noqa: E402, F401
from winbox.cli.kdbg import session  # noqa: E402, F401


REGISTER = ("Integrations", [kdbg])
