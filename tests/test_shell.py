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
    @patch("winbox.exec.shell._data")
    def test_copies_script(self, mock_data, mock_copy2, cfg):
        mock_data.path.return_value = "/tmp/Invoke-ConPtyShell.ps1"

        _ensure_conpty_on_share(cfg)

        mock_data.path.assert_called_with(CONPTY_SCRIPT)
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
                                            mock_ensure, mock_relay, cfg, capsys):
        """open_shell handles socket.timeout and surfaces guest-side diagnostic."""
        mock_termsize.return_value = MagicMock(lines=24, columns=80)
        mock_sock = MagicMock()
        mock_sock.accept.side_effect = socket.timeout("timed out")
        mock_socket_cls.return_value = mock_sock
        ga = MagicMock()
        ga.exec_detached.return_value = 9999
        ga.exec_status.return_value = {
            "exited": True, "exitcode": 1,
            "stdout": "", "stderr": "Z:\\Invoke-ConPtyShell.ps1 not found",
        }

        open_shell(cfg, ga)

        mock_relay.assert_not_called()
        mock_sock.close.assert_called()
        # Diagnostic from exec_status should be surfaced.
        out = capsys.readouterr().out
        assert "Timed out" in out
        # Either the exit-rc info or the stderr tail must be in the output.
        assert "9999" in out or "ConPtyShell" in out

    @patch("winbox.exec.shell._relay")
    @patch("winbox.exec.shell._ensure_conpty_on_share")
    @patch("winbox.exec.shell.os.get_terminal_size")
    @patch("winbox.exec.shell.socket.socket")
    def test_timeout_with_running_pid_suggests_firewall(
        self, mock_socket_cls, mock_termsize, mock_ensure, mock_relay, cfg, capsys,
    ):
        """If exec_status says the shell is still running, point at firewall."""
        mock_termsize.return_value = MagicMock(lines=24, columns=80)
        mock_sock = MagicMock()
        mock_sock.accept.side_effect = socket.timeout("timed out")
        mock_socket_cls.return_value = mock_sock
        ga = MagicMock()
        ga.exec_detached.return_value = 9999
        ga.exec_status.return_value = {
            "exited": False, "exitcode": -1, "stdout": "", "stderr": "",
        }

        open_shell(cfg, ga)
        out = capsys.readouterr().out
        assert "firewall" in out.lower()

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


    @patch("winbox.exec.shell.VM")
    @patch("winbox.exec.shell._relay")
    @patch("winbox.exec.shell._ensure_conpty_on_share")
    @patch("winbox.exec.shell.os.get_terminal_size")
    @patch("winbox.exec.shell.socket.socket")
    def test_user_password_forwarded_to_exec_detached(
        self, mock_socket_cls, mock_termsize, mock_ensure, mock_relay,
        mock_vm_cls, cfg,
    ):
        """open_shell forwards user/password kwargs to ga.exec_detached."""
        mock_termsize.return_value = MagicMock(lines=24, columns=80)
        mock_server = MagicMock()
        mock_client = MagicMock()
        mock_server.accept.return_value = (mock_client, ("192.168.122.100", 5555))
        mock_socket_cls.return_value = mock_server
        mock_vm_cls.return_value.ip.return_value = "192.168.122.100"
        ga = MagicMock()

        open_shell(cfg, ga, user="alice", password="secret")

        _, kwargs = ga.exec_detached.call_args
        assert kwargs["user"] == "alice"
        assert kwargs["password"] == "secret"

    @patch("winbox.exec.shell.VM")
    @patch("winbox.exec.shell._relay")
    @patch("winbox.exec.shell._ensure_conpty_on_share")
    @patch("winbox.exec.shell.os.get_terminal_size")
    @patch("winbox.exec.shell.socket.socket")
    def test_no_user_passes_none(
        self, mock_socket_cls, mock_termsize, mock_ensure, mock_relay,
        mock_vm_cls, cfg,
    ):
        """Without user/password, exec_detached gets None for both."""
        mock_termsize.return_value = MagicMock(lines=24, columns=80)
        mock_server = MagicMock()
        mock_client = MagicMock()
        mock_server.accept.return_value = (mock_client, ("192.168.122.100", 5555))
        mock_socket_cls.return_value = mock_server
        mock_vm_cls.return_value.ip.return_value = "192.168.122.100"
        ga = MagicMock()

        open_shell(cfg, ga)

        _, kwargs = ga.exec_detached.call_args
        assert kwargs["user"] is None
        assert kwargs["password"] is None

    @patch("winbox.exec.shell.VM")
    @patch("winbox.exec.shell._relay")
    @patch("winbox.exec.shell._ensure_conpty_on_share")
    @patch("winbox.exec.shell.os.get_terminal_size")
    @patch("winbox.exec.shell.socket.socket")
    def test_status_shows_username_when_user_set(
        self, mock_socket_cls, mock_termsize, mock_ensure, mock_relay,
        mock_vm_cls, cfg, capsys,
    ):
        """Status messages show username instead of SYSTEM when user is set."""
        mock_termsize.return_value = MagicMock(lines=24, columns=80)
        mock_server = MagicMock()
        mock_client = MagicMock()
        mock_server.accept.return_value = (mock_client, ("192.168.122.100", 5555))
        mock_socket_cls.return_value = mock_server
        mock_vm_cls.return_value.ip.return_value = "192.168.122.100"
        ga = MagicMock()

        open_shell(cfg, ga, user="alice", password="secret")

        out = capsys.readouterr().out
        assert "alice" in out
        assert "SYSTEM" not in out


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


# ─── LineEditor ────────────────────────────────────────────────────────────────


from winbox.exec.shell import LineEditor


class TestLineEditor:

    def _ed(self, cols=80):
        return LineEditor(term_cols=cols)

    # -- construction --

    def test_default_state(self):
        ed = self._ed()
        assert ed.buf == bytearray()
        assert ed.pos == 0
        assert ed.history == []
        assert ed.hist_idx == -1
        assert ed.start_col == 0
        assert ed.term_cols == 80

    # -- screen geometry --

    def test_screen_geometry(self):
        ed = self._ed()
        ed.start_col = 3
        assert ed.screen(5) == (0, 8)

    def test_screen_wraps(self):
        ed = self._ed()
        ed.start_col = 3
        assert ed.screen(78)[0] == 1

    # -- insert --

    def test_insert_at_end(self):
        ed = self._ed()
        ed.insert(b"abc")
        assert ed.buf == bytearray(b"abc")
        assert ed.pos == 3

    def test_insert_in_middle(self):
        ed = self._ed()
        ed.insert(b"ac")
        ed.pos = 1
        ed.insert(b"b")
        assert ed.buf == bytearray(b"abc")
        assert ed.pos == 2

    # -- backspace / delete --

    def test_backspace(self):
        ed = self._ed()
        ed.insert(b"abc")
        ed.backspace()
        assert ed.buf == bytearray(b"ab")
        assert ed.pos == 2

    def test_backspace_at_start(self):
        ed = self._ed()
        assert ed.backspace() == b""

    def test_delete(self):
        ed = self._ed()
        ed.insert(b"abc")
        ed.pos = 1
        ed.delete()
        assert ed.buf == bytearray(b"ac")

    def test_delete_at_end(self):
        ed = self._ed()
        ed.insert(b"abc")
        assert ed.delete() == b""

    # -- cursor movement --

    def test_cursor_left(self):
        ed = self._ed()
        ed.insert(b"abc")
        ed.cursor_left()
        assert ed.pos == 2

    def test_cursor_right(self):
        ed = self._ed()
        ed.insert(b"abc")
        ed.pos = 1
        ed.cursor_right()
        assert ed.pos == 2

    def test_cursor_left_at_start(self):
        ed = self._ed()
        assert ed.cursor_left() == b""
        assert ed.pos == 0

    def test_cursor_right_at_end(self):
        ed = self._ed()
        ed.insert(b"abc")
        assert ed.cursor_right() == b""
        assert ed.pos == 3

    def test_home(self):
        ed = self._ed()
        ed.insert(b"abc")
        ed.home()
        assert ed.pos == 0

    def test_end(self):
        ed = self._ed()
        ed.insert(b"abc")
        ed.home()
        ed.end()
        assert ed.pos == 3

    # -- word movement --

    def test_word_left(self):
        ed = self._ed()
        ed.insert(b"hello world")
        ed.word_left()
        assert ed.pos == 6

    def test_word_right(self):
        ed = self._ed()
        ed.insert(b"hello world")
        ed.pos = 0
        ed.word_right()
        assert ed.pos == 5

    # -- kill commands --

    def test_ctrl_k(self):
        ed = self._ed()
        ed.insert(b"abcdef")
        ed.pos = 3
        ed.ctrl_k()
        assert ed.buf == bytearray(b"abc")

    def test_ctrl_u(self):
        ed = self._ed()
        ed.insert(b"abcdef")
        ed.pos = 3
        ed.ctrl_u()
        assert ed.buf == bytearray(b"def")
        assert ed.pos == 0

    def test_ctrl_w(self):
        ed = self._ed()
        ed.insert(b"hello world")
        ed.ctrl_w()
        assert ed.buf == bytearray(b"hello ")

    # -- history --

    def test_history_up(self):
        ed = self._ed()
        ed.insert(b"first")
        ed.enter()
        ed.insert(b"second")
        ed.enter()
        ed.history_up()
        assert ed.buf == bytearray(b"second")

    def test_history_down(self):
        ed = self._ed()
        ed.insert(b"first")
        ed.enter()
        ed.insert(b"second")
        ed.enter()
        ed.history_up()
        ed.history_up()
        ed.history_down()
        assert ed.buf == bytearray(b"second")

    def test_history_down_restores_saved(self):
        ed = self._ed()
        ed.insert(b"done")
        ed.enter()
        ed.insert(b"partial")
        ed.history_up()
        assert ed.buf == bytearray(b"done")
        ed.history_down()
        assert ed.buf == bytearray(b"partial")

    def test_history_up_at_top(self):
        ed = self._ed()
        ed.insert(b"only")
        ed.enter()
        ed.history_up()
        buf_before = bytes(ed.buf)
        ed.history_up()
        assert bytes(ed.buf) == buf_before

    # -- enter / special --

    def test_enter(self):
        ed = self._ed()
        ed.insert(b"ls")
        stdout, sock = ed.enter()
        assert b"\r\n" in stdout
        assert sock == b"ls\n"
        assert ed.buf == bytearray()
        assert ed.pos == 0

    def test_enter_adds_to_history(self):
        ed = self._ed()
        ed.insert(b"cmd")
        ed.enter()
        assert ed.history == [b"cmd"]

    def test_enter_skips_blank_history(self):
        ed = self._ed()
        ed.insert(b"   ")
        ed.enter()
        assert ed.history == []

    def test_ctrl_c(self):
        ed = self._ed()
        ed.insert(b"partial")
        stdout, sock = ed.ctrl_c()
        assert b"^C" in stdout
        assert sock == b"\n"
        assert ed.buf == bytearray()

    def test_clear_screen(self):
        ed = self._ed()
        ed.insert(b"text")
        out = ed.clear_screen()
        assert b"\x1b[2J" in out
        assert b"\x1b[H" in out
        assert ed.start_col == 0

    def test_tab(self):
        ed = self._ed()
        assert ed.tab() == b"\x07"

    # -- track_col --

    def test_track_col_printable(self):
        ed = self._ed()
        ed.track_col(b"abc")
        assert ed.start_col == 3

    def test_track_col_newline(self):
        ed = self._ed()
        ed.track_col(b"x\n")
        assert ed.start_col == 0

    def test_track_col_carriage_return(self):
        ed = self._ed()
        ed.track_col(b"x\r")
        assert ed.start_col == 0

    def test_track_col_backspace(self):
        ed = self._ed()
        ed.start_col = 5
        ed.track_col(b"\x08")
        assert ed.start_col == 4

    def test_track_col_wraps(self):
        ed = self._ed(cols=10)
        ed.track_col(b"x" * 12)
        assert ed.start_col == 2

    def test_track_col_skips_csi(self):
        ed = self._ed()
        ed.track_col(b"\x1b[32mhi")
        assert ed.start_col == 2

    # -- resize --

    def test_resize_updates_term_cols(self):
        ed = self._ed()
        ed.resize(120)
        assert ed.term_cols == 120

    def test_resize_redraws_when_buf_nonempty(self):
        ed = self._ed()
        ed.insert(b"text")
        out = ed.resize(120)
        assert len(out) > 0
