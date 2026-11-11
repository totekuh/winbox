"""Passive network probing for QEMU gdbstub and listening sockets.

Reads /proc/net/tcp{,6} to avoid connecting to the gdbstub (which would
halt the guest CPU) and falls back to a connect probe only when /proc
is unavailable.
"""

from __future__ import annotations

import ipaddress
import socket


def _hex_to_ipv4(hex_addr: str) -> str | None:
    """Decode /proc's little-endian hex IPv4 (``0100007F`` -> ``127.0.0.1``)."""
    if len(hex_addr) != 8:
        return None
    try:
        octets = [int(hex_addr[i:i + 2], 16) for i in (6, 4, 2, 0)]
    except ValueError:
        return None
    return ".".join(str(o) for o in octets)


def _hex_to_ipv6(hex_addr: str) -> str | None:
    """Decode Linux ``/proc/net/tcp6``'s four little-endian 32-bit words."""
    if len(hex_addr) != 32:
        return None
    try:
        raw = bytes.fromhex(hex_addr)
        network_order = b"".join(
            raw[index:index + 4][::-1] for index in range(0, 16, 4)
        )
        return str(ipaddress.IPv6Address(network_order))
    except (ValueError, ipaddress.AddressValueError):
        return None


def _listening_sockets() -> set[tuple[str, int]] | None:
    """``(address, port)`` pairs in LISTEN state, read passively from /proc.

    Addresses retain their family. Malformed rows are ignored rather than
    becoming wildcard matches; confusing an unrelated listener for QEMU's
    gdbstub is worse than reporting the stub absent.

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
            address = _hex_to_ipv4(addr_hex) if is_v4 else _hex_to_ipv6(addr_hex)
            if address is not None:
                sockets.add((address, port))
    return sockets if found_any else None


def gdbstub_has_client(port: int) -> bool:
    """True if an ESTABLISHED TCP connection exists to the gdbstub port.

    QEMU's gdbstub accepts only one client. If one is already connected,
    a second connect will either drop the first or produce undefined
    behavior. This check reads /proc/net/tcp passively (no connect).
    """
    established = "01"
    for proc_file, is_v4 in (("/proc/net/tcp", True), ("/proc/net/tcp6", False)):
        try:
            with open(proc_file, "r") as fh:
                lines = fh.readlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 4 or fields[3] != established:
                continue
            local = fields[1]
            if ":" not in local:
                continue
            _, _, port_hex = local.rpartition(":")
            try:
                if int(port_hex, 16) == port:
                    return True
            except ValueError:
                continue
    return False


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
        try:
            requested = ipaddress.ip_address(host)
        except ValueError:
            return False
        wildcard = "0.0.0.0" if requested.version == 4 else "::"
        return any(
            sock_port == port
            and sock_addr in (requested.compressed, wildcard)
            and ipaddress.ip_address(sock_addr).version == requested.version
            for sock_addr, sock_port in sockets
        )
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False
