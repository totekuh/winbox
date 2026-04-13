"""Hypervisor-level kernel debug stub — start, stop, status.

Uses QEMU's built-in gdbstub via the HMP `gdbserver` command. The stub
runs inside the QEMU process on the Kali host; nothing ever touches the
guest kernel, so flags like KdDebuggerEnabled / KdDebuggerNotPresent
stay pristine and in-guest anti-tamper checks don't see the debugger.

Default bind is 127.0.0.1 — the bare `tcp::<port>` chardev form binds
to 0.0.0.0, which would let anything on the LAN take full r/w on guest
RAM and registers. `--any-interface` is the explicit opt-out.
"""

from __future__ import annotations

import socket
import subprocess

import click

from winbox.cli import console
from winbox.config import Config
from winbox.vm import VM, VMState


def _hmp(vm_name: str, command: str) -> tuple[int, str, str]:
    """Send an HMP command to the VM and return (rc, stdout, stderr)."""
    result = subprocess.run(
        [
            "virsh", "-c", "qemu:///system",
            "qemu-monitor-command", vm_name,
            "--hmp", command,
        ],
        capture_output=True, text=True, check=False,
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def _probe_port(host: str, port: int, timeout: float = 0.5) -> bool:
    """True if something is listening on host:port (can accept a TCP connect)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


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
    if _probe_port("127.0.0.1", port):
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
            f"[red][!][/] [bold]Bound to 0.0.0.0:{port}[/] — "
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

    listening = _probe_port("127.0.0.1", port)
    if listening:
        console.print(f"gdb stub: [green]listening[/] on 127.0.0.1:{port}")
    else:
        console.print(f"gdb stub: [red]not running[/] (nothing on 127.0.0.1:{port})")
