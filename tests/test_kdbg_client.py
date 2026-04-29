"""Tests for ``winbox.kdbg.debugger.client.DaemonClient`` error paths.

We focus on the daemon-not-running surface — without these, every
CLI/MCP tool that fronts the daemon used to surface a raw
``[Errno 2] No such file or directory: '...'`` or
``[Errno 111] Connection refused`` instead of an actionable
"run kdbg attach first" hint.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import pytest

from winbox.kdbg.debugger.client import ClientError, DaemonClient


@dataclass
class _Cfg:
    """Minimal Config stand-in. The client only reads paths off it."""
    state_dir: Path

    @property
    def kdbg_sock_path(self) -> Path:
        return self.state_dir / "kdbg.sock"

    @property
    def kdbg_lock_path(self) -> Path:
        return self.state_dir / "kdbg.lock"

    @property
    def kdbg_session_path(self) -> Path:
        return self.state_dir / "kdbg.session"


def _patch_paths(monkeypatch, cfg: _Cfg) -> None:
    """The client reads paths via module-level helpers; route them at cfg."""
    from winbox.kdbg.debugger import client as client_mod
    monkeypatch.setattr(client_mod, "sock_path", lambda c: cfg.kdbg_sock_path)
    monkeypatch.setattr(client_mod, "lock_path", lambda c: cfg.kdbg_lock_path)
    monkeypatch.setattr(client_mod, "session_path", lambda c: cfg.kdbg_session_path)


def test_call_no_daemon_raises_actionable_message(tmp_path, monkeypatch):
    """Nothing on disk → the very first daemon-backed call should
    surface the friendly attach-first hint, not a raw ENOENT."""
    cfg = _Cfg(tmp_path)
    _patch_paths(monkeypatch, cfg)
    client = DaemonClient(cfg)
    with pytest.raises(ClientError) as ei:
        client.call("status")
    msg = str(ei.value)
    assert "no kdbg session" in msg
    assert "kdbg attach" in msg


def test_call_stale_sock_without_daemon_raises_actionable_message(tmp_path, monkeypatch):
    """Daemon was killed without unlinking its sock. The lock should
    no longer be held (kernel auto-released on death). The client
    must detect this via session_alive() and give the same friendly
    message — not a raw ECONNREFUSED."""
    cfg = _Cfg(tmp_path)
    _patch_paths(monkeypatch, cfg)
    # Drop a stale .sock file (would have been left by a crashing
    # daemon). It's just an empty regular file — connect() against
    # it will fail, but we shouldn't even try because session_alive
    # returns False (lock not held).
    cfg.kdbg_sock_path.touch()

    client = DaemonClient(cfg)
    with pytest.raises(ClientError) as ei:
        client.call("status")
    msg = str(ei.value)
    assert "no kdbg session" in msg
    assert "kdbg attach" in msg


def test_session_alive_false_with_unlocked_lock_file(tmp_path, monkeypatch):
    """A leftover lock file that nobody holds means no daemon. The
    fcntl-based check is the source of truth (kernel auto-releases on
    process death)."""
    cfg = _Cfg(tmp_path)
    _patch_paths(monkeypatch, cfg)
    cfg.kdbg_lock_path.touch()
    client = DaemonClient(cfg)
    assert client.session_alive() is False


def test_session_alive_true_when_someone_holds_lock(tmp_path, monkeypatch):
    """A live daemon would hold LOCK_EX on the lock file. Simulate by
    locking it ourselves in this process and verify the client sees it."""
    import fcntl
    cfg = _Cfg(tmp_path)
    _patch_paths(monkeypatch, cfg)
    fd = os.open(str(cfg.kdbg_lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        client = DaemonClient(cfg)
        # We hold the lock ourselves, so a non-blocking try-lock from
        # another fd will fail → client correctly reports "alive".
        assert client.session_alive() is True
    finally:
        os.close(fd)
