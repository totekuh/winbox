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


def hmp(
    vm_name: str,
    command: str,
    *,
    timeout: int = 15,
    mode: str = "raise",
):
    """Send an HMP command to the VM via virsh ``qemu-monitor-command --hmp``.

    Two return shapes:
      * ``mode='raise'`` (default) -- returns stdout (str). Non-zero exit
        raises :class:`HmpError` with stderr or stdout in the message.
      * ``mode='tuple'`` -- returns ``(rc, stdout.strip(), stderr.strip())``
        and never raises on a non-zero exit. Use this when the caller
        wants to render virsh's own error text directly (e.g. the
        ``kdbg start/stop`` CLI commands and the matching MCP tools).

    Both old in-tree wrappers (``cli/kdbg._hmp`` and ``mcp._kdbg_hmp``)
    routed through this — keep them out of new code.
    """
    try:
        result = subprocess.run(
            [
                "virsh", "-c", "qemu:///system",
                "qemu-monitor-command", vm_name,
                "--hmp", command,
            ],
            capture_output=True, text=True, check=False, timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        # Surface as HmpError so walkers (which catch HmpError/PageWalkError to
        # log a truncation and return partial data) don't die on an unhandled
        # TimeoutExpired escaping the whole MCP tool call.
        raise HmpError(f"HMP {command!r} timed out after {timeout}s") from e
    if mode == "tuple":
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    if mode != "raise":
        raise ValueError(f"hmp(mode={mode!r}): expected 'raise' or 'tuple'")
    if result.returncode != 0:
        raise HmpError(
            f"HMP {command!r} failed: {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout


def _hex_to_ipv4(hex_addr: str) -> str | None:
    """Decode /proc's little-endian hex IPv4 (``0100007F`` -> ``127.0.0.1``)."""
    if len(hex_addr) != 8:
        return None
    try:
        octets = [int(hex_addr[i:i + 2], 16) for i in (6, 4, 2, 0)]
    except ValueError:
        return None
    return ".".join(str(o) for o in octets)


def _listening_sockets() -> set[tuple[str | None, int]] | None:
    """``(address, port)`` pairs in LISTEN state, read passively from /proc.

    Address is the decoded dotted-quad for IPv4, or ``None`` for IPv6 and
    anything unparseable — callers treat ``None`` as "matches any host", which
    keeps a v6 wildcard listener from reading as absent.

    Returns None if /proc is unavailable, so callers can fall back.
    """
    listen_state = "0A"  # TCP_LISTEN
    sockets: set[tuple[str | None, int]] = set()
    found_any = False
    for proc_file, is_v4 in (("/proc/net/tcp", True), ("/proc/net/tcp6", False)):
        try:
            with open(proc_file, "r") as fh:
                lines = fh.readlines()[1:]
        except OSError:
            continue
        found_any = True
        for line in lines:
            fields = line.split()
            if len(fields) < 4 or fields[3] != listen_state:
                continue
            local = fields[1]
            if ":" not in local:
                continue
            addr_hex, _, port_hex = local.rpartition(":")
            try:
                port = int(port_hex, 16)
            except ValueError:
                continue
            sockets.add((_hex_to_ipv4(addr_hex) if is_v4 else None, port))
    return sockets if found_any else None


def probe_port(host: str, port: int, timeout: float = 0.5) -> bool:
    """True if something is listening on host:port.

    Deliberately does **not** open a connection. QEMU's gdbstub halts the
    guest CPU the moment a client attaches, so the obvious implementation —
    ``socket.create_connection`` — turned a read-only ``kdbg status`` into
    something that paused the VM. Worse, ``kdbg stop`` then refused to run
    ("VM is not running"), so a status check could wedge the guest until
    someone found ``kdbg resume``.

    Reads LISTEN sockets out of /proc instead, which is passive. Falls back
    to a connect probe only where /proc is unavailable.
    """
    sockets = _listening_sockets()
    if sockets is not None:
        return any(
            sock_port == port
            # None (IPv6/unparsed) and 0.0.0.0 both cover the requested host.
            and (sock_addr is None or sock_addr in (host, "0.0.0.0"))
            for sock_addr, sock_port in sockets
        )
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


def ensure_not_paused(vm_name: str, port: int = 1234) -> str | None:
    """Resume ``vm_name`` if a debug session left it paused.

    Detaching is supposed to resume the VM, but that only happens if the
    daemon shuts down cleanly — when it doesn't, the gdbstub keeps the CPU
    stopped and the VM is left in ``paused`` with no indication beyond a
    warning. Every later winbox command then hangs or reports the VM as
    down. Called at the end of the detach paths as a safety net.

    Returns a short description of what it did, or ``None`` if the VM was
    already running (the overwhelmingly common case). Never raises: this
    runs during teardown, where masking the original problem would be worse
    than failing to tidy up.
    """
    try:
        state = subprocess.run(
            ["virsh", "-c", "qemu:///system", "domstate", vm_name],
            capture_output=True, text=True, check=False,
        )
        if state.stdout.strip() != "paused":
            return None

        if probe_port("127.0.0.1", port):
            # Preferred: let the stub run gdb_continue() so the CPU resumes
            # through the same path a clean detach would have used. Imported
            # here because the debugger package imports this module.
            try:
                from winbox.kdbg.debugger import RspClient

                client = RspClient.connect("127.0.0.1", port, timeout=5)
                try:
                    client.handshake()
                    client.cont()
                finally:
                    client.close()
                return "VM was left paused by the debug session; resumed via gdbstub"
            except Exception:
                pass

        # Stub is gone or unreachable — fall back to libvirt.
        resumed = subprocess.run(
            ["virsh", "-c", "qemu:///system", "resume", vm_name],
            capture_output=True, text=True, check=False,
        )
        if resumed.returncode == 0:
            return "VM was left paused by the debug session; resumed via virsh"
        return (
            "VM is left PAUSED and could not be resumed automatically — "
            f"run `virsh -c qemu:///system resume {vm_name}`"
        )
    except Exception:
        return None
