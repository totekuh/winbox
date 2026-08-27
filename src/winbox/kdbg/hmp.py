"""QMP/HMP control helpers used by the kdbg package.

The debugger safety boundary is strict: this module bootstraps/stops QEMU's
gdbserver and handles non-debugger monitor control, while registers, memory,
halt/resume, and CR3 work go through RSP.  HMP ``x``/``xp`` are never issued
by Winbox's debugger implementation.

A persistent QMP connection is used when libvirt's monitor socket is
accessible.  Virsh remains as a compatibility fallback for installations
where the socket is hidden or its permissions do not allow direct access.
"""

from __future__ import annotations

import atexit
from contextlib import contextmanager
import glob
import importlib
import json
import logging
import os
import re
import socket
import ipaddress
import subprocess
import threading
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


class HmpError(RuntimeError):
    pass


class _QmpUnavailable(Exception):
    """The direct QMP transport cannot be used; falling back is safe."""


class _QmpCommandError(Exception):
    """QEMU returned a structured error for a successfully sent command."""


class _QmpConnection:
    """A serialized, newline-framed QMP connection."""

    def __init__(self, sock: socket.socket, path: str):
        self.sock = sock
        self.path = path
        self.lock = threading.Lock()
        self._buffer = bytearray()
        self._next_id = 1

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def _read_message(self) -> dict[str, Any]:
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                raw = bytes(self._buffer[:newline]).strip()
                del self._buffer[:newline + 1]
                if not raw:
                    continue
                try:
                    message = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise _QmpUnavailable(
                        f"invalid JSON from QMP socket {self.path}: {exc}"
                    ) from exc
                if not isinstance(message, dict):
                    raise _QmpUnavailable(
                        f"unexpected QMP message on {self.path}: {message!r}"
                    )
                return message

            try:
                chunk = self.sock.recv(65536)
            except (OSError, TimeoutError) as exc:
                raise _QmpUnavailable(f"QMP receive failed on {self.path}: {exc}") from exc
            if not chunk:
                raise _QmpUnavailable(f"QMP socket {self.path} closed")
            self._buffer.extend(chunk)

    def _execute(self, execute: str, arguments: dict[str, Any] | None = None) -> Any:
        request_id = self._next_id
        self._next_id += 1
        request: dict[str, Any] = {"execute": execute, "id": request_id}
        if arguments is not None:
            request["arguments"] = arguments
        payload = json.dumps(request, separators=(",", ":")).encode() + b"\n"
        try:
            self.sock.sendall(payload)
        except (OSError, TimeoutError) as exc:
            raise _QmpUnavailable(f"QMP send failed on {self.path}: {exc}") from exc

        while True:
            response = self._read_message()
            # Events are asynchronous and may be delivered between request and reply.
            if "event" in response:
                continue
            if response.get("id") != request_id:
                raise _QmpUnavailable(
                    f"mismatched QMP response id on {self.path}: {response!r}"
                )
            if "error" in response:
                error = response["error"]
                if isinstance(error, dict):
                    description = error.get("desc") or error.get("class") or str(error)
                else:
                    description = str(error)
                raise _QmpCommandError(description)
            if "return" not in response:
                raise _QmpUnavailable(
                    f"malformed QMP response on {self.path}: {response!r}"
                )
            return response["return"]

    def negotiate(self) -> None:
        greeting = self._read_message()
        if "QMP" not in greeting:
            raise _QmpUnavailable(
                f"missing QMP greeting on {self.path}: {greeting!r}"
            )
        self._execute("qmp_capabilities")

    def hmp(self, command: str, timeout: int) -> str:
        with self.lock:
            self.sock.settimeout(timeout)
            result = self._execute(
                "human-monitor-command", {"command-line": command}
            )
        if not isinstance(result, str):
            raise _QmpUnavailable(
                f"non-text HMP response on {self.path}: {result!r}"
            )
        return result


_qmp_connections: dict[str, _QmpConnection] = {}
_qmp_connections_lock = threading.Lock()


class _LibvirtConnection:
    """Persistent libvirt RPC connection for FD-backed QEMU monitors."""

    def __init__(self, connection: Any, qemu_module: Any):
        self.connection = connection
        self.qemu_module = qemu_module
        self.lock = threading.Lock()

    def close(self) -> None:
        try:
            self.connection.close()
        except Exception:
            pass

    def hmp(self, vm_name: str, command: str) -> str:
        # VIR_DOMAIN_QEMU_MONITOR_COMMAND_HMP == 1.  Use the exported constant
        # when available, while remaining compatible with older bindings.
        flags = getattr(self.qemu_module, "VIR_DOMAIN_QEMU_MONITOR_COMMAND_HMP", 1)
        try:
            with self.lock:
                domain = self.connection.lookupByName(vm_name)
                result = self.qemu_module.qemuMonitorCommand(domain, command, flags)
        except Exception as exc:
            raise _QmpUnavailable(f"persistent libvirt monitor failed: {exc}") from exc
        if not isinstance(result, str):
            raise _QmpUnavailable(f"non-text libvirt HMP response: {result!r}")
        return result


_libvirt_connection: _LibvirtConnection | None = None
_libvirt_connection_lock = threading.Lock()


@contextmanager
def paused_snapshot(vm_name: str):
    """Compatibility alias for the safe RSP snapshot transaction.

    This name used to issue HMP ``stop``/``cont`` around monitor memory reads.
    Keep callers source-compatible while ensuring the unsafe monitor debugger
    path cannot be reached accidentally.
    """
    from winbox.kdbg.debugger.reader import debug_snapshot_for_vm
    with debug_snapshot_for_vm(vm_name) as snapshot:
        yield snapshot


def snapshot_operation(func):
    """Compatibility alias for the RSP-backed operation decorator."""
    from winbox.kdbg.debugger.reader import snapshot_operation as rsp_operation
    return rsp_operation(func)


def _get_libvirt_connection() -> _LibvirtConnection:
    global _libvirt_connection
    with _libvirt_connection_lock:
        if _libvirt_connection is None:
            try:
                libvirt = importlib.import_module("libvirt")
                libvirt_qemu = importlib.import_module("libvirt_qemu")
                connection = libvirt.open("qemu:///system")
            except Exception as exc:
                raise _QmpUnavailable(f"libvirt Python binding unavailable: {exc}") from exc
            if connection is None:
                raise _QmpUnavailable("libvirt.open('qemu:///system') returned no connection")
            _libvirt_connection = _LibvirtConnection(connection, libvirt_qemu)
        return _libvirt_connection


def _discard_libvirt_connection(connection: _LibvirtConnection) -> None:
    global _libvirt_connection
    with _libvirt_connection_lock:
        if _libvirt_connection is connection:
            _libvirt_connection = None
    connection.close()


def _qmp_socket_paths(vm_name: str) -> list[str]:
    """Return live libvirt monitor socket candidates for ``vm_name``."""
    escaped_name = glob.escape(vm_name)
    candidates: list[str] = []
    for run_dir in ("/run/libvirt/qemu", "/var/run/libvirt/qemu"):
        pattern = f"{run_dir}/domain-*-{escaped_name}/monitor.sock"
        for path in glob.glob(pattern):
            if path not in candidates and Path(path).is_socket():
                candidates.append(path)
    return candidates


def _new_qmp_connection(vm_name: str, timeout: int) -> _QmpConnection:
    paths = _qmp_socket_paths(vm_name)
    if not paths:
        raise _QmpUnavailable(f"QMP monitor socket for {vm_name!r} was not found")

    failures: list[str] = []
    for path in paths:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        connection = _QmpConnection(sock, path)
        try:
            sock.connect(path)
            connection.negotiate()
            return connection
        except (_QmpUnavailable, _QmpCommandError, OSError, TimeoutError) as exc:
            connection.close()
            failures.append(f"{path}: {exc}")
    raise _QmpUnavailable("; ".join(failures))


def _get_qmp_connection(vm_name: str, timeout: int) -> _QmpConnection:
    with _qmp_connections_lock:
        connection = _qmp_connections.get(vm_name)
        if connection is None:
            connection = _new_qmp_connection(vm_name, timeout)
            _qmp_connections[vm_name] = connection
        return connection


def _discard_qmp_connection(vm_name: str, connection: _QmpConnection) -> None:
    with _qmp_connections_lock:
        if _qmp_connections.get(vm_name) is connection:
            del _qmp_connections[vm_name]
    connection.close()


def _close_qmp_connections() -> None:
    global _libvirt_connection
    with _qmp_connections_lock:
        connections = list(_qmp_connections.values())
        _qmp_connections.clear()
    for connection in connections:
        connection.close()
    with _libvirt_connection_lock:
        libvirt_connection = _libvirt_connection
        _libvirt_connection = None
    if libvirt_connection is not None:
        libvirt_connection.close()


def _libvirt_hmp(vm_name: str, command: str) -> str:
    connection = _get_libvirt_connection()
    try:
        return connection.hmp(vm_name, command)
    except _QmpUnavailable:
        _discard_libvirt_connection(connection)
        raise


atexit.register(_close_qmp_connections)


def _virsh_hmp(vm_name: str, command: str, timeout: int):
    """Run the compatibility transport and preserve its CompletedProcess API."""
    try:
        return subprocess.run(
            [
                "virsh", "-c", "qemu:///system",
                "qemu-monitor-command", vm_name,
                "--hmp", command,
            ],
            capture_output=True, text=True, check=False, timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise HmpError(f"HMP {command!r} timed out after {timeout}s") from exc


def hmp(
    vm_name: str,
    command: str,
    *,
    timeout: int = 15,
    mode: str = "raise",
):
    """Send HMP over persistent QMP, falling back to ``virsh`` if unavailable.

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
    if mode not in ("raise", "tuple"):
        raise ValueError(f"hmp(mode={mode!r}): expected 'raise' or 'tuple'")

    try:
        connection = _get_qmp_connection(vm_name, timeout)
        try:
            stdout = connection.hmp(command, timeout)
        except _QmpUnavailable:
            # Never reuse a connection whose framing or transport is uncertain.
            _discard_qmp_connection(vm_name, connection)
            raise
    except _QmpCommandError as exc:
        if mode == "tuple":
            return 1, "", str(exc).strip()
        raise HmpError(f"HMP {command!r} failed: {exc}") from exc
    except _QmpUnavailable as direct_exc:
        try:
            stdout = _libvirt_hmp(vm_name, command)
        except _QmpUnavailable as libvirt_exc:
            logger.warning(
                "persistent QMP unavailable for %s; using virsh: direct=%s; libvirt=%s",
                vm_name, direct_exc, libvirt_exc,
            )
            result = _virsh_hmp(vm_name, command, timeout)
        else:
            if mode == "tuple":
                return 0, stdout.strip(), ""
            return stdout
    else:
        if mode == "tuple":
            return 0, stdout.strip(), ""
        return stdout

    if mode == "tuple":
        return result.returncode, result.stdout.strip(), result.stderr.strip()
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
