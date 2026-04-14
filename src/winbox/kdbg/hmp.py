"""HMP (QEMU Human Monitor Protocol) helpers used by the kdbg package.

Everything kdbg does past the gdb-stub start/stop flows through HMP:
  * `info registers` — pull LSTAR/CR3/RIP
  * `x`  — examine virtual memory in the current CPU's CR3
  * `xp` — examine physical memory (CR3-agnostic, needed for cross-process)

A single choke point keeps the virsh subprocess handling in one place.
"""

from __future__ import annotations

import re
import socket
import subprocess


class HmpError(RuntimeError):
    pass


def hmp(vm_name: str, command: str, *, timeout: int = 15) -> str:
    """Send an HMP command to the VM, return stdout, raise on failure."""
    result = subprocess.run(
        [
            "virsh", "-c", "qemu:///system",
            "qemu-monitor-command", vm_name,
            "--hmp", command,
        ],
        capture_output=True, text=True, check=False, timeout=timeout,
    )
    if result.returncode != 0:
        raise HmpError(
            f"HMP {command!r} failed: {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout


def probe_port(host: str, port: int, timeout: float = 0.5) -> bool:
    """True if something is accepting TCP on host:port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


_REG_RE = re.compile(r"([A-Z][A-Z0-9_]*)\s*=\s*([0-9a-fA-F]+)")
# `IDT=     fffff80558f1a000 00000fff` — two hex fields, label is IDT/GDT.
_TABLE_RE = re.compile(
    r"^(IDT|GDT)\s*=\s*([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s*$",
    re.MULTILINE,
)


def parse_registers(info_registers_out: str) -> dict[str, int]:
    """Parse the `info registers` text into {name: int}.

    QEMU prints RAX/RIP/CR3/... in ``REG=HEX`` pairs, sometimes several
    per line. We accept any ``NAME=HEX`` token and let callers ask for
    what they want. Note: LSTAR is intentionally NOT in this output on
    modern QEMU builds — callers who need the syscall dispatcher resolve
    it via the IDT instead (see ``parse_idt``).
    """
    out: dict[str, int] = {}
    for match in _REG_RE.finditer(info_registers_out):
        name = match.group(1)
        try:
            out[name] = int(match.group(2), 16)
        except ValueError:
            continue
    return out


def parse_idt(info_registers_out: str) -> tuple[int, int]:
    """Pull (base, limit) for the IDT out of the `info registers` dump."""
    for match in _TABLE_RE.finditer(info_registers_out):
        if match.group(1) == "IDT":
            return int(match.group(2), 16), int(match.group(3), 16)
    raise HmpError("IDT entry not found in `info registers` output")


def read_cpu_state(vm_name: str) -> dict[str, int]:
    """Convenience wrapper: return a merged dict of registers + IDT base.

    Adds a synthetic ``IDT_BASE`` key alongside the normal register names.
    """
    text = hmp(vm_name, "info registers")
    regs = parse_registers(text)
    idt_base, _ = parse_idt(text)
    regs["IDT_BASE"] = idt_base
    return regs
