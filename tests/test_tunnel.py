"""Tests for the ligolo-ng tunnel integration."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

from winbox.config import Config
from winbox.tunnel import (
    AGENT_VM_PATH,
    API_PORT,
    API_USER,
    API_PASS,
    PROXY_PORT,
    TUN_INTERFACE,
    pidfile_path,
    tunnel_dir,
)


@pytest.fixture
def cfg(tmp_path):
    c = Config(winbox_dir=tmp_path / ".winbox")
    c.winbox_dir.mkdir(parents=True)
    c.iso_dir.mkdir(parents=True)
    c.shared_dir.mkdir(parents=True)
    return c


# ─── proxy lifecycle ──────────────────────────────────────────────────────


class TestProxyLifecycle:
    def test_find_proxy_on_path(self, cfg):
        from winbox.tunnel import proxy
        with patch("shutil.which", return_value="/usr/bin/ligolo-proxy"):
            assert proxy.find_proxy() == "/usr/bin/ligolo-proxy"

    def test_find_proxy_missing(self, cfg):
        from winbox.tunnel import proxy
        with patch("shutil.which", return_value=None):
            with pytest.raises(proxy.ProxyNotFound):
                proxy.find_proxy()

    def test_read_pidfile_missing(self, cfg):
        from winbox.tunnel import proxy
        assert proxy.read_pidfile(cfg) is None

    def test_read_pidfile_valid(self, cfg):
        from winbox.tunnel import proxy
        pf = pidfile_path(cfg)
        pf.parent.mkdir(parents=True, exist_ok=True)
        pf.write_text("12345\n")
        assert proxy.read_pidfile(cfg) == 12345

    def test_read_pidfile_garbage(self, cfg):
        from winbox.tunnel import proxy
        pf = pidfile_path(cfg)
        pf.parent.mkdir(parents=True, exist_ok=True)
        pf.write_text("not-a-pid\n")
        assert proxy.read_pidfile(cfg) is None

    def test_is_running_no_pidfile(self, cfg):
        from winbox.tunnel import proxy
        assert proxy.is_running(cfg) is None

    def test_is_running_stale_pid(self, cfg):
        from winbox.tunnel import proxy
        pf = pidfile_path(cfg)
        pf.parent.mkdir(parents=True, exist_ok=True)
        pf.write_text("99999\n")
        with patch.object(proxy, "_pid_alive", return_value=False):
            assert proxy.is_running(cfg) is None
        assert not pf.exists()

    def test_is_running_live_proxy(self, cfg):
        from winbox.tunnel import proxy
        pf = pidfile_path(cfg)
        pf.parent.mkdir(parents=True, exist_ok=True)
        pf.write_text("12345\n")
        with patch.object(proxy, "_pid_alive", return_value=True), \
             patch.object(proxy, "_is_proxy_proc", return_value=True):
            assert proxy.is_running(cfg) == 12345

    def test_is_running_recycled_pid(self, cfg):
        from winbox.tunnel import proxy
        pf = pidfile_path(cfg)
        pf.parent.mkdir(parents=True, exist_ok=True)
        pf.write_text("12345\n")
        with patch.object(proxy, "_pid_alive", return_value=True), \
             patch.object(proxy, "_is_proxy_proc", return_value=False):
            assert proxy.is_running(cfg) is None
        assert not pf.exists()

    def test_stop_no_pidfile(self, cfg):
        from winbox.tunnel import proxy
        assert proxy.stop(cfg) is False

    def test_stop_stale_pid(self, cfg):
        from winbox.tunnel import proxy
        pf = pidfile_path(cfg)
        pf.parent.mkdir(parents=True, exist_ok=True)
        pf.write_text("99999\n")
        with patch.object(proxy, "_pid_alive", return_value=False):
            assert proxy.stop(cfg) is False
        assert not pf.exists()

    def test_stop_live_proxy(self, cfg):
        from winbox.tunnel import proxy
        pf = pidfile_path(cfg)
        pf.parent.mkdir(parents=True, exist_ok=True)
        pf.write_text("12345\n")
        killed = []
        with patch.object(proxy, "_pid_alive", side_effect=[True, True, False]), \
             patch.object(proxy, "_is_proxy_proc", return_value=True), \
             patch("os.kill", side_effect=lambda pid, sig: killed.append((pid, sig))):
            assert proxy.stop(cfg) is True
        assert (12345, 15) in killed  # SIGTERM
        assert not pf.exists()


# ─── API client ───────────────────────────────────────────────────────────


class TestApiClient:
    def test_ping_success(self, cfg):
        from winbox.tunnel import api
        resp = b'{"token": "jwt123"}'
        with patch("urllib.request.urlopen") as m:
            m.return_value.__enter__ = lambda s: MagicMock(read=lambda: resp)
            m.return_value.__exit__ = MagicMock(return_value=False)
            assert api.ping(cfg) is True

    def test_ping_failure(self, cfg):
        from winbox.tunnel import api
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
            assert api.ping(cfg) is False

    def test_auth_returns_token(self, cfg):
        from winbox.tunnel import api
        resp = b'{"token": "jwt-test-token"}'
        with patch("urllib.request.urlopen") as m:
            m.return_value.__enter__ = lambda s: MagicMock(read=lambda: resp)
            m.return_value.__exit__ = MagicMock(return_value=False)
            assert api.auth(cfg) == "jwt-test-token"


# ─── MCP tools ────────────────────────────────────────────────────────────


class TestMcpTunnelStatus:
    def test_status_proxy_not_running(self, cfg):
        from winbox.mcp._tunnel import tunnel_status
        with patch("winbox.mcp._tunnel._get_state", return_value=(cfg, MagicMock(), MagicMock())), \
             patch("winbox.tunnel.proxy.is_running", return_value=None):
            import json
            result = json.loads(tunnel_status())
            assert result["proxy_running"] is False
            assert result["tunnel_active"] is False

    def test_status_proxy_running(self, cfg):
        from winbox.mcp._tunnel import tunnel_status
        from winbox.tunnel import api
        mock_agents = [{"Name": "test", "SessionID": "abc123", "Running": True, "id": 1}]
        with patch("winbox.mcp._tunnel._get_state", return_value=(cfg, MagicMock(), MagicMock())), \
             patch("winbox.tunnel.proxy.is_running", return_value=12345), \
             patch("winbox.tunnel.api.auth", return_value="tok"), \
             patch("winbox.tunnel.api.agents", return_value=mock_agents), \
             patch("winbox.tunnel.api.list_interfaces", return_value={}):
            import json
            result = json.loads(tunnel_status())
            assert result["proxy_running"] is True
            assert result["proxy_pid"] == 12345
            assert result["tunnel_active"] is True


class TestMcpTunnelDown:
    def test_down_idempotent(self, cfg):
        from winbox.mcp._tunnel import tunnel_down
        ga = MagicMock()
        with patch("winbox.mcp._tunnel._get_state", return_value=(cfg, MagicMock(), ga)), \
             patch("winbox.tunnel.proxy.is_running", return_value=None), \
             patch("winbox.tunnel.proxy.stop", return_value=False):
            import json
            result = json.loads(tunnel_down())
            assert result["status"] == "tunnel_down"


# ─── downloads ────────────────────────────────────────────────────────────


class TestDownloads:
    def test_ligolo_constants_defined(self):
        from winbox.setup.installer.downloads import (
            LIGOLO_AGENT_EXE,
            LIGOLO_AGENT_SHA256,
            LIGOLO_AGENT_URL,
            LIGOLO_AGENT_ZIP,
        )
        assert LIGOLO_AGENT_EXE == "ligolo-agent.exe"
        assert len(LIGOLO_AGENT_SHA256) == 64
        assert "ligolo-ng" in LIGOLO_AGENT_URL
        assert LIGOLO_AGENT_ZIP == "ligolo-agent.zip"

    def test_ligolo_cached(self, cfg):
        from winbox.setup.installer.downloads import (
            LIGOLO_AGENT_EXE,
            LIGOLO_AGENT_SHA256,
            download_ligolo_agent,
        )
        dest = cfg.iso_dir / LIGOLO_AGENT_EXE
        dest.write_bytes(b"fake")
        with patch("winbox.setup.installer.downloads._sha256", return_value=LIGOLO_AGENT_SHA256):
            result = download_ligolo_agent(cfg)
            assert result == dest


# ─── provision ────────────────────────────────────────────────────────────


class TestProvision:
    def test_ligolo_included_in_provision_imports(self):
        from winbox.setup.installer.provision import LIGOLO_AGENT_EXE
        assert LIGOLO_AGENT_EXE == "ligolo-agent.exe"
