"""Tests for exec/shell.py — ConPTY reverse shell helpers and open_shell."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch, call

import pytest

from winbox.exec.shell import (
    CONPTY_SCRIPT,
    DEFAULT_PORT,
    RESIZE_MAGIC,
    _ensure_conpty_on_share,
    open_shell,
)


# ─── Constants ───────────────────────────────────────────────────────────────


class TestConstants:
    def test_conpty_script_name(self):
        assert CONPTY_SCRIPT == "Invoke-ConPtyShell.ps1"

    def test_default_port(self):
        assert DEFAULT_PORT == 4444

    def test_resize_magic(self):
        assert RESIZE_MAGIC == b"\x00RSIZ"
        assert len(RESIZE_MAGIC) == 5


# ─── _ensure_conpty_on_share ─────────────────────────────────────────────────


class TestEnsureConptyOnShare:
    @patch("winbox.exec.shell.shutil.copy2")
    @patch("winbox.exec.shell.resources")
    def test_copies_script(self, mock_resources, mock_copy2, cfg):
        mock_file = MagicMock()
        mock_resources.files.return_value.joinpath.return_value = mock_file
        mock_resources.as_file.return_value.__enter__ = MagicMock(return_value="/tmp/script.ps1")
        mock_resources.as_file.return_value.__exit__ = MagicMock(return_value=False)

        _ensure_conpty_on_share(cfg)

        mock_resources.files.assert_called_with("winbox.data")
        mock_resources.files.return_value.joinpath.assert_called_with(CONPTY_SCRIPT)
        mock_copy2.assert_called_once()
        dest = mock_copy2.call_args[0][1]
        assert str(dest).endswith(CONPTY_SCRIPT)


# ─── open_shell ──────────────────────────────────────────────────────────────


class TestOpenShell:
    @patch("winbox.exec.shell._ensure_conpty_on_share")
    @patch("winbox.exec.shell.os.get_terminal_size")
    @patch("winbox.exec.shell.socket.socket")
    def test_bind_failure(self, mock_socket_cls, mock_termsize, mock_ensure, cfg):
        """open_shell prints error and returns on bind failure."""
        mock_termsize.return_value = MagicMock(lines=24, columns=80)
        mock_sock = MagicMock()
        mock_sock.bind.side_effect = OSError("Address in use")
        mock_socket_cls.return_value = mock_sock
        ga = MagicMock()

        open_shell(cfg, ga)

        mock_sock.close.assert_called()

    @patch("winbox.exec.shell._ensure_conpty_on_share")
    @patch("winbox.exec.shell.os.get_terminal_size")
    @patch("winbox.exec.shell.socket.socket")
    def test_ga_launch_failure(self, mock_socket_cls, mock_termsize, mock_ensure, cfg):
        """open_shell returns if guest agent fails to launch shell."""
        mock_termsize.return_value = MagicMock(lines=24, columns=80)
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        ga = MagicMock()
        ga.exec_detached.side_effect = Exception("GA failed")

        open_shell(cfg, ga)

        mock_sock.close.assert_called()

    @patch("winbox.exec.shell._relay")
    @patch("winbox.exec.shell._ensure_conpty_on_share")
    @patch("winbox.exec.shell.os.get_terminal_size")
    @patch("winbox.exec.shell.socket.socket")
    def test_timeout_waiting_for_connection(self, mock_socket_cls, mock_termsize,
                                            mock_ensure, mock_relay, cfg):
        """open_shell handles socket.timeout when no connection arrives."""
        mock_termsize.return_value = MagicMock(lines=24, columns=80)
        mock_sock = MagicMock()
        mock_sock.accept.side_effect = socket.timeout("timed out")
        mock_socket_cls.return_value = mock_sock
        ga = MagicMock()

        open_shell(cfg, ga)

        mock_relay.assert_not_called()
        mock_sock.close.assert_called()

    @patch("winbox.exec.shell.VM")
    @patch("winbox.exec.shell._relay")
    @patch("winbox.exec.shell._ensure_conpty_on_share")
    @patch("winbox.exec.shell.os.get_terminal_size")
    @patch("winbox.exec.shell.socket.socket")
    def test_successful_conpty_connection(self, mock_socket_cls, mock_termsize,
                                          mock_ensure, mock_relay, mock_vm_cls, cfg):
        """open_shell calls _relay on successful connection."""
        mock_termsize.return_value = MagicMock(lines=24, columns=80)
        mock_server = MagicMock()
        mock_client = MagicMock()
        mock_server.accept.return_value = (mock_client, ("192.168.122.100", 5555))
        mock_socket_cls.return_value = mock_server
        mock_vm_cls.return_value.ip.return_value = "192.168.122.100"
        ga = MagicMock()

        open_shell(cfg, ga)

        mock_relay.assert_called_once_with(mock_client)

    @patch("winbox.exec.shell.VM")
    @patch("winbox.exec.shell._relay_pipe")
    @patch("winbox.exec.shell._ensure_conpty_on_share")
    @patch("winbox.exec.shell.os.get_terminal_size")
    @patch("winbox.exec.shell.socket.socket")
    def test_pipe_mode(self, mock_socket_cls, mock_termsize,
                       mock_ensure, mock_relay_pipe, mock_vm_cls, cfg):
        """open_shell calls _relay_pipe in pipe mode."""
        mock_termsize.return_value = MagicMock(lines=24, columns=80)
        mock_server = MagicMock()
        mock_client = MagicMock()
        mock_server.accept.return_value = (mock_client, ("192.168.122.100", 5555))
        mock_socket_cls.return_value = mock_server
        mock_vm_cls.return_value.ip.return_value = "192.168.122.100"
        ga = MagicMock()

        open_shell(cfg, ga, pipe_mode=True)

        mock_relay_pipe.assert_called_once_with(mock_client)

    @patch("winbox.exec.shell._ensure_conpty_on_share")
    @patch("winbox.exec.shell.os.get_terminal_size", side_effect=OSError)
    @patch("winbox.exec.shell.socket.socket")
    def test_fallback_terminal_size(self, mock_socket_cls, mock_termsize,
                                     mock_ensure, cfg):
        """Falls back to 24x80 when terminal size unavailable."""
        import base64
        mock_sock = MagicMock()
        mock_sock.accept.side_effect = socket.timeout("timed out")
        mock_socket_cls.return_value = mock_sock
        ga = MagicMock()

        open_shell(cfg, ga)  # should not crash

        # Decode the base64 UTF-16LE encoded command and check for 24x80
        cmd_arg = ga.exec_detached.call_args[0][0]
        encoded = cmd_arg.split("-EncodedCommand ")[-1]
        decoded = base64.b64decode(encoded).decode("utf-16-le")
        assert "-Rows 24" in decoded
        assert "-Cols 80" in decoded

    @patch("winbox.exec.shell.VM")
    @patch("winbox.exec.shell._relay")
    @patch("winbox.exec.shell._ensure_conpty_on_share")
    @patch("winbox.exec.shell.os.get_terminal_size")
    @patch("winbox.exec.shell.socket.socket")
    def test_custom_port(self, mock_socket_cls, mock_termsize,
                         mock_ensure, mock_relay, mock_vm_cls, cfg):
        """open_shell binds to custom port."""
        mock_termsize.return_value = MagicMock(lines=24, columns=80)
        mock_server = MagicMock()
        mock_client = MagicMock()
        mock_server.accept.return_value = (mock_client, ("192.168.122.100", 9999))
        mock_socket_cls.return_value = mock_server
        mock_vm_cls.return_value.ip.return_value = "192.168.122.100"
        ga = MagicMock()

        open_shell(cfg, ga, port=9999)

        mock_server.bind.assert_called_once_with((cfg.host_ip, 9999))

    @patch("winbox.exec.shell.VM")
    @patch("winbox.exec.shell._relay")
    @patch("winbox.exec.shell._ensure_conpty_on_share")
    @patch("winbox.exec.shell.os.get_terminal_size")
    @patch("winbox.exec.shell.socket.socket")
    def test_encodes_command(self, mock_socket_cls, mock_termsize,
                             mock_ensure, mock_relay, mock_vm_cls, cfg):
        """open_shell sends base64-encoded PowerShell command."""
        mock_termsize.return_value = MagicMock(lines=30, columns=120)
        mock_server = MagicMock()
        mock_client = MagicMock()
        mock_server.accept.return_value = (mock_client, ("192.168.122.100", 5555))
        mock_socket_cls.return_value = mock_server
        mock_vm_cls.return_value.ip.return_value = "192.168.122.100"
        ga = MagicMock()

        open_shell(cfg, ga)

        cmd = ga.exec_detached.call_args[0][0]
        assert "-EncodedCommand" in cmd
        assert "-ExecutionPolicy Bypass" in cmd


# ─── _relay TTY guard ────────────────────────────────────────────────────────


class TestRelayGuards:
    @patch("winbox.exec.shell.sys.stdin")
    def test_relay_non_tty(self, mock_stdin):
        """_relay returns early for non-TTY stdin."""
        from winbox.exec.shell import _relay
        mock_stdin.isatty.return_value = False
        sock = MagicMock()
        _relay(sock)
        sock.close.assert_not_called()  # didn't enter main loop

    @patch("winbox.exec.shell.sys.stdin")
    def test_relay_pipe_non_tty(self, mock_stdin):
        """_relay_pipe returns early for non-TTY stdin."""
        from winbox.exec.shell import _relay_pipe
        mock_stdin.isatty.return_value = False
        sock = MagicMock()
        _relay_pipe(sock)
        sock.close.assert_not_called()
