"""QMP and libvirt transport layer for QEMU monitor access.

Manages persistent QMP socket connections and a libvirt RPC fallback.
Connection pooling is handled per-VM with automatic cleanup on exit.
"""

from __future__ import annotations

import atexit
import glob
import importlib
import json
import logging
import os
import socket
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
