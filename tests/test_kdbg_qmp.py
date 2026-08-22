"""Persistent QMP transport tests, including a real Unix-socket peer."""

from __future__ import annotations

import json
import importlib
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from winbox.kdbg.hmp import HmpError, _QmpConnection, hmp

hmp_module = importlib.import_module("winbox.kdbg.hmp")


@pytest.fixture(autouse=True)
def clean_qmp_cache():
    hmp_module._close_qmp_connections()
    yield
    hmp_module._close_qmp_connections()


def test_qmp_connection_handles_fragmented_messages_and_events():
    sock = MagicMock()
    sock.recv.side_effect = [
        b'{"event":"STOP"}\r\n{"ret',
        b'urn":"registers","id":1}\r\n',
    ]
    connection = _QmpConnection(sock, "/qmp.sock")

    assert connection.hmp("info registers", 3) == "registers"
    sent = json.loads(sock.sendall.call_args.args[0])
    assert sent == {
        "execute": "human-monitor-command",
        "arguments": {"command-line": "info registers"},
        "id": 1,
    }
    sock.settimeout.assert_called_once_with(3)


def test_qmp_command_error_preserves_raise_and_tuple_modes():
    connection = MagicMock()
    connection.hmp.side_effect = hmp_module._QmpCommandError("bad command")
    with patch.object(hmp_module, "_get_qmp_connection", return_value=connection):
        with pytest.raises(HmpError, match="bad command"):
            hmp("vm", "bad")
        assert hmp("vm", "bad", mode="tuple") == (1, "", "bad command")


def test_unavailable_qmp_falls_back_to_virsh(caplog):
    result = MagicMock(returncode=0, stdout="answer\n", stderr="")
    with (
        patch.object(
            hmp_module,
            "_get_qmp_connection",
            side_effect=hmp_module._QmpUnavailable("permission denied"),
        ),
        patch.object(
            hmp_module,
            "_libvirt_hmp",
            side_effect=hmp_module._QmpUnavailable("binding missing"),
        ),
        patch.object(hmp_module, "_virsh_hmp", return_value=result) as virsh,
    ):
        assert hmp("vm", "info version") == "answer\n"
    virsh.assert_called_once_with("vm", "info version", 15)
    assert "permission denied" in caplog.text


def test_failed_cached_connection_is_discarded_before_fallback():
    connection = MagicMock()
    connection.hmp.side_effect = hmp_module._QmpUnavailable("broken pipe")
    result = MagicMock(returncode=0, stdout="fallback", stderr="")
    with (
        patch.object(hmp_module, "_get_qmp_connection", return_value=connection),
        patch.object(hmp_module, "_discard_qmp_connection") as discard,
        patch.object(
            hmp_module,
            "_libvirt_hmp",
            side_effect=hmp_module._QmpUnavailable("binding missing"),
        ),
        patch.object(hmp_module, "_virsh_hmp", return_value=result),
    ):
        assert hmp("vm", "info version") == "fallback"
    discard.assert_called_once_with("vm", connection)


def test_fd_backed_monitor_uses_persistent_libvirt_before_virsh():
    with (
        patch.object(
            hmp_module,
            "_get_qmp_connection",
            side_effect=hmp_module._QmpUnavailable("no socket"),
        ),
        patch.object(hmp_module, "_libvirt_hmp", return_value="fast\n") as libvirt_hmp,
        patch.object(hmp_module, "_virsh_hmp") as virsh,
    ):
        assert hmp("vm", "info version") == "fast\n"
        assert hmp("vm", "info version", mode="tuple") == (0, "fast", "")
    assert libvirt_hmp.call_count == 2
    virsh.assert_not_called()


def test_invalid_mode_fails_without_opening_a_transport():
    with patch.object(hmp_module, "_get_qmp_connection") as get_connection:
        with pytest.raises(ValueError, match="expected 'raise' or 'tuple'"):
            hmp("vm", "info version", mode="invalid")
    get_connection.assert_not_called()


class _QmpTestServer:
    def __init__(self, path: Path):
        self.path = path
        self.commands: list[str] = []
        self.connections = 0
        self.ready = threading.Event()
        self.failure: BaseException | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()
        assert self.ready.wait(2), "test QMP server failed to start"

    def stop(self) -> None:
        self._stop.set()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as wake:
                wake.connect(str(self.path))
        except OSError:
            pass
        self._thread.join(2)
        if self.failure:
            raise self.failure

    @staticmethod
    def _receive_line(conn: socket.socket, buffer: bytearray) -> dict:
        while b"\n" not in buffer:
            chunk = conn.recv(4096)
            if not chunk:
                raise EOFError
            buffer.extend(chunk)
        raw, _, rest = buffer.partition(b"\n")
        buffer[:] = rest
        return json.loads(raw)

    def _run(self) -> None:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(self.path))
                server.listen()
                server.settimeout(0.1)
                self.ready.set()
                while not self._stop.is_set():
                    try:
                        conn, _ = server.accept()
                    except TimeoutError:
                        continue
                    if self._stop.is_set():
                        conn.close()
                        break
                    self.connections += 1
                    with conn:
                        buffer = bytearray()
                        try:
                            conn.sendall(b'{"QMP":{"version":{},"capabilities":[]}}\r\n')
                            capability = self._receive_line(conn, buffer)
                            conn.sendall(
                                json.dumps({"return": {}, "id": capability["id"]}).encode()
                                + b"\r\n"
                            )
                            while not self._stop.is_set():
                                request = self._receive_line(conn, buffer)
                                command = request["arguments"]["command-line"]
                                self.commands.append(command)
                                # Exercise event skipping and packet fragmentation.
                                conn.sendall(b'{"event":"RESUME"}\r\n')
                                result = (
                                    "VM status: running\n"
                                    if command == "info status"
                                    else f"reply:{command}"
                                )
                                response = json.dumps(
                                    {"return": result, "id": request["id"]}
                                ).encode() + b"\r\n"
                                midpoint = len(response) // 2
                                conn.sendall(response[:midpoint])
                                time.sleep(0.001)
                                conn.sendall(response[midpoint:])
                        except (EOFError, BrokenPipeError, ConnectionResetError):
                            pass
        except BaseException as exc:
            self.failure = exc
            self.ready.set()


def test_real_unix_qmp_socket_reuses_connection_and_serializes_calls(tmp_path):
    path = tmp_path / "monitor.sock"
    server = _QmpTestServer(path)
    server.start()
    try:
        with (
            patch.object(hmp_module, "_qmp_socket_paths", return_value=[str(path)]),
            patch.object(hmp_module, "_virsh_hmp") as virsh,
        ):
            commands = [f"info test-{number}" for number in range(8)]
            with ThreadPoolExecutor(max_workers=4) as pool:
                replies = list(pool.map(lambda command: hmp("vm", command), commands))

        assert replies == [f"reply:{command}" for command in commands]
        assert sorted(server.commands) == sorted(commands)
        assert server.connections == 1
        virsh.assert_not_called()
    finally:
        hmp_module._close_qmp_connections()
        server.stop()


def test_gdbserver_bootstrap_runs_over_real_unix_qmp_socket(tmp_path):
    path = tmp_path / "monitor.sock"
    server = _QmpTestServer(path)
    server.start()
    try:
        with (
            patch.object(hmp_module, "_qmp_socket_paths", return_value=[str(path)]),
            patch.object(hmp_module, "_virsh_hmp") as virsh,
        ):
            assert hmp("vm", "gdbserver tcp:127.0.0.1:1234") == (
                "reply:gdbserver tcp:127.0.0.1:1234"
            )

        assert server.commands == [
            "gdbserver tcp:127.0.0.1:1234",
        ]
        assert server.connections == 1
        virsh.assert_not_called()
    finally:
        hmp_module._close_qmp_connections()
        server.stop()
