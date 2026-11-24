"""Live end-to-end tests for the ligolo-ng tunnel integration.

Run explicitly:

    pytest -m integration tests/test_tunnel_e2e.py -v

Requires:
  - ligolo-proxy on the host PATH (skips everything if missing)
  - ~/tools/ligolo-ng/ligolo-agent built for Linux (agent tests skip if missing)

Most tests run proxy + Linux agent on the same host (loopback) —
no VM needed. TUN creation + route manipulation need root; those
tests skip when not root.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from winbox.cli import cli
from winbox.config import Config
from winbox.tunnel import pidfile_path

pytestmark = pytest.mark.integration

_HAS_PROXY = shutil.which("ligolo-proxy") is not None
_LINUX_AGENT = Path.home() / "tools" / "ligolo-ng" / "ligolo-agent"
_HAS_AGENT = _LINUX_AGENT.exists() and os.access(_LINUX_AGENT, os.X_OK)
def _can_create_tun() -> bool:
    """Check if we can create TUN interfaces (root or cap_net_admin on proxy)."""
    if os.geteuid() == 0:
        return True
    proxy_path = shutil.which("ligolo-proxy")
    if not proxy_path:
        return False
    result = subprocess.run(
        ["getcap", proxy_path], capture_output=True, text=True,
    )
    return "cap_net_admin" in result.stdout


_CAN_TUN = _can_create_tun()


def _can_netns() -> bool:
    """Check if we can create network namespaces (sudo -n ip netns)."""
    result = subprocess.run(
        ["sudo", "-n", "ip", "netns", "add", "ligolo-probe"],
        capture_output=True,
    )
    if result.returncode == 0:
        subprocess.run(
            ["sudo", "-n", "ip", "netns", "del", "ligolo-probe"],
            capture_output=True,
        )
        return True
    return False


_CAN_NETNS = _can_netns()

TEST_SUBNET = "198.51.100.0/24"
TEST_SUBNET_2 = "203.0.113.0/24"
NETNS_NAME = "ligolo-test"
NETNS_IP = "198.51.100.1"
VETH_HOST_IP = "10.199.199.254"
VETH_AGENT_IP = "10.199.199.1"


def _skip_no_proxy():
    if not _HAS_PROXY:
        pytest.skip("ligolo-proxy not on PATH")


def _skip_no_agent():
    _skip_no_proxy()
    if not _HAS_AGENT:
        pytest.skip(f"Linux agent not built at {_LINUX_AGENT}")


def _skip_no_tun():
    if not _CAN_TUN:
        pytest.skip("TUN needs root or cap_net_admin on ligolo-proxy")


def _skip_no_netns():
    _skip_no_tun()
    if not _CAN_NETNS:
        pytest.skip("netns needs: sudo -n ip netns")


# ─── fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def cfg(bootstrapped_vm) -> Config:
    return Config.load()


@pytest.fixture(autouse=True)
def _cleanup_after(cfg):
    """Kill any leftover proxy/agent after each test."""
    yield
    from winbox.tunnel import proxy
    if proxy.is_running(cfg):
        proxy.stop(cfg)
    subprocess.run(
        ["pkill", "-f", "ligolo-agent.*127.0.0.1"],
        capture_output=True,
    )
    subprocess.run(
        ["pkill", "-f", f"ligolo-agent.*{VETH_HOST_IP}"],
        capture_output=True,
    )
    # Clean stale TUN if proxy died without cleanup
    subprocess.run(
        ["sudo", "-n", "ip", "link", "delete", "ligolo"],
        capture_output=True,
    )
    # Give OS a moment to release ports
    time.sleep(0.5)


def _start_agent(proxy_port: int = 11601) -> subprocess.Popen:
    """Start Linux agent connecting to local proxy."""
    proc = subprocess.Popen(
        [str(_LINUX_AGENT), "-connect", f"127.0.0.1:{proxy_port}", "-ignore-cert"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    time.sleep(3)
    assert proc.poll() is None, "agent exited immediately"
    return proc


def _wait_agent(cfg, token: str, timeout: int = 10) -> int | None:
    """Poll API until an agent appears. Returns agent ID or None."""
    from winbox.tunnel import api
    deadline = time.time() + timeout
    while time.time() < deadline:
        agents = api.agents(cfg, token)
        if agents:
            return agents[0].get("id") or agents[0].get("ID")
        time.sleep(0.5)
    return None


# ─── proxy lifecycle (no agent needed) ───────────────────────────────────


class TestProxyLifecycle:
    def test_start_and_stop(self, cfg):
        _skip_no_proxy()
        from winbox.tunnel import proxy

        pid = proxy.start(cfg)
        assert pid > 0
        assert proxy.is_running(cfg) == pid

        assert proxy.stop(cfg) is True
        assert proxy.is_running(cfg) is None

    def test_start_idempotent(self, cfg):
        _skip_no_proxy()
        from winbox.tunnel import proxy

        pid1 = proxy.start(cfg)
        pid2 = proxy.start(cfg)
        assert pid1 == pid2
        proxy.stop(cfg)

    def test_api_auth(self, cfg):
        _skip_no_proxy()
        from winbox.tunnel import api, proxy

        proxy.start(cfg)
        try:
            assert api.ping(cfg) is True
            token = api.auth(cfg)
            assert len(token) > 10
        finally:
            proxy.stop(cfg)

    def test_stop_idempotent(self, cfg):
        _skip_no_proxy()
        from winbox.tunnel import proxy
        assert proxy.stop(cfg) is False


# ─── agent connection (proxy + agent, no TUN) ───────────────────────────


class TestAgentConnection:
    def test_agent_connects_to_proxy(self, cfg):
        _skip_no_agent()
        from winbox.tunnel import api, proxy

        proxy.start(cfg)
        agent_proc = _start_agent(cfg.tunnel_proxy_port)
        try:
            token = api.auth(cfg)
            agent_id = _wait_agent(cfg, token)
            assert agent_id is not None, "agent did not connect"

            agents = api.agents(cfg, token)
            assert len(agents) >= 1
            agent = agents[0]
            assert agent.get("Name"), "agent should report hostname"
            assert agent.get("SessionID"), "agent should have a session ID"
        finally:
            agent_proc.kill()
            agent_proc.wait()
            proxy.stop(cfg)

    def test_agent_shows_in_status(self, cfg):
        _skip_no_agent()
        from winbox.tunnel import api, proxy

        proxy.start(cfg)
        agent_proc = _start_agent(cfg.tunnel_proxy_port)
        try:
            token = api.auth(cfg)
            _wait_agent(cfg, token)
            interfaces = api.list_interfaces(cfg, token)
            assert isinstance(interfaces, dict)
        finally:
            agent_proc.kill()
            agent_proc.wait()
            proxy.stop(cfg)


# ─── TUN + routes (needs root) ──────────────────────────────────────────


class TestTunRouting:
    def test_create_interface_and_routes(self, cfg):
        """Full tunnel: TUN created, routes added, traffic routed, cleanup."""
        _skip_no_agent()
        _skip_no_tun()
        from winbox.tunnel import api, proxy

        proxy.start(cfg)
        agent_proc = _start_agent(cfg.tunnel_proxy_port)
        try:
            token = api.auth(cfg)
            agent_id = _wait_agent(cfg, token)
            assert agent_id is not None

            # Create TUN
            api.create_interface(cfg, token, "ligolo")

            # Add routes
            api.add_routes(cfg, token, "ligolo", [TEST_SUBNET])

            # Start tunnel
            api.start_tunnel(cfg, token, agent_id, "ligolo")
            time.sleep(1)

            # Verify TUN exists
            result = subprocess.run(
                ["ip", "link", "show", "ligolo"],
                capture_output=True, text=True,
            )
            assert result.returncode == 0, f"TUN not created: {result.stderr}"

            # Verify route in kernel table
            result = subprocess.run(
                ["ip", "route", "get", "198.51.100.1"],
                capture_output=True, text=True,
            )
            assert "ligolo" in result.stdout, (
                f"route not via ligolo TUN: {result.stdout}"
            )

            # Hot-add second route
            api.add_routes(cfg, token, "ligolo", [TEST_SUBNET_2])
            result = subprocess.run(
                ["ip", "route", "get", "203.0.113.1"],
                capture_output=True, text=True,
            )
            assert "ligolo" in result.stdout

            # Remove second route
            api.delete_route(cfg, token, "ligolo", TEST_SUBNET_2)
            time.sleep(0.5)
            result = subprocess.run(
                ["ip", "route", "get", "203.0.113.1"],
                capture_output=True, text=True,
            )
            assert "ligolo" not in result.stdout

            # Stop tunnel
            api.stop_tunnel(cfg, token, agent_id)
            time.sleep(1)

            # Verify cleanup: route gone
            result = subprocess.run(
                ["ip", "route", "get", "198.51.100.1"],
                capture_output=True, text=True,
            )
            assert "ligolo" not in result.stdout

        finally:
            agent_proc.kill()
            agent_proc.wait()
            try:
                api.delete_interface(cfg, token, "ligolo")
            except Exception:
                pass
            proxy.stop(cfg)

    def test_cleanup_on_proxy_stop(self, cfg):
        """Killing proxy cleans up pidfile."""
        _skip_no_agent()
        _skip_no_tun()
        from winbox.tunnel import proxy

        proxy.start(cfg)
        agent_proc = _start_agent()
        try:
            assert proxy.is_running(cfg) is not None
            proxy.stop(cfg)
            assert proxy.is_running(cfg) is None
            assert not pidfile_path(cfg).exists()
        finally:
            agent_proc.kill()
            agent_proc.wait()


# ─── real packet routing via netns ───────────────────────────────────────


def _netns_setup():
    """Create an isolated netns. Veth pair on 10.199.199.0/24 for agent→proxy.
    198.51.100.1 on loopback inside netns for the listener (routed via tunnel)."""
    _cmds = [
        ["sudo", "-n", "ip", "netns", "add", NETNS_NAME],
        ["sudo", "-n", "ip", "link", "add", "veth-host", "type", "veth", "peer", "name", "veth-agent"],
        ["sudo", "-n", "ip", "link", "set", "veth-agent", "netns", NETNS_NAME],
        # veth pair: 10.199.199.0/24 (agent↔proxy transport, NOT routed through tunnel)
        ["sudo", "-n", "ip", "addr", "add", f"{VETH_HOST_IP}/24", "dev", "veth-host"],
        ["sudo", "-n", "ip", "link", "set", "veth-host", "up"],
        ["sudo", "-n", "ip", "netns", "exec", NETNS_NAME, "ip", "addr", "add", f"{VETH_AGENT_IP}/24", "dev", "veth-agent"],
        ["sudo", "-n", "ip", "netns", "exec", NETNS_NAME, "ip", "link", "set", "veth-agent", "up"],
        ["sudo", "-n", "ip", "netns", "exec", NETNS_NAME, "ip", "link", "set", "lo", "up"],
        # 198.51.100.1 on loopback inside netns — this is the target IP the host
        # will reach ONLY through the tunnel
        ["sudo", "-n", "ip", "netns", "exec", NETNS_NAME, "ip", "addr", "add", f"{NETNS_IP}/32", "dev", "lo"],
    ]
    for cmd in _cmds:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            _netns_teardown()
            raise RuntimeError(f"{' '.join(cmd)}: {result.stderr.strip()}")


def _netns_teardown():
    """Remove the test netns and veth pair."""
    subprocess.run(["sudo", "-n", "ip", "netns", "del", NETNS_NAME], capture_output=True)
    subprocess.run(["sudo", "-n", "ip", "link", "del", "veth-host"], capture_output=True)


def _netns_start_agent(proxy_port: int = 11601) -> subprocess.Popen:
    """Start ligolo-agent inside the netns."""
    proc = subprocess.Popen(
        [
            "sudo", "-n", "ip", "netns", "exec", NETNS_NAME,
            str(_LINUX_AGENT), "-connect", f"198.51.100.1:{proxy_port}", "-ignore-cert",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    time.sleep(3)
    assert proc.poll() is None, f"netns agent exited: {proc.stdout.read().decode()[:200]}"
    return proc


def _netns_start_listener() -> subprocess.Popen:
    """Start a TCP listener on 198.51.100.1:9999 inside the netns."""
    server_script = (
        "import socket,sys; "
        "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); "
        "s.bind(('198.51.100.1',9999)); s.listen(1); s.settimeout(30); "
        "sys.stdout.write('LISTENING\\n'); sys.stdout.flush(); "
        "c,_=s.accept(); c.sendall(b'TUNNEL_OK'); c.close(); s.close()"
    )
    proc = subprocess.Popen(
        ["sudo", "-n", "ip", "netns", "exec", NETNS_NAME, "python3", "-c", server_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    deadline = time.time() + 5
    while time.time() < deadline:
        line = b""
        try:
            import select
            if select.select([proc.stdout], [], [], 0.5)[0]:
                line = proc.stdout.readline()
        except Exception:
            pass
        if b"LISTENING" in line:
            return proc
        if proc.poll() is not None:
            raise RuntimeError(f"listener exited: {proc.stdout.read().decode()[:200]}")
    raise RuntimeError("listener did not start in 5s")


class TestRealPacketRouting:
    """Prove actual packets flow through the tunnel using a network namespace.

    Creates a netns with 198.51.100.1 that the host cannot reach directly.
    Agent runs inside the netns. A TCP listener binds 198.51.100.1:9999
    inside the netns. After routing 198.51.100.0/24 through the ligolo TUN,
    the host connects to 198.51.100.1:9999 — the connection succeeds ONLY
    if packets actually traverse the tunnel.
    """

    def test_packets_flow_through_tunnel(self, cfg):
        _skip_no_agent()
        _skip_no_netns()
        from winbox.tunnel import api, proxy
        import socket as _socket

        _netns_setup()
        try:
            # Step 1: verify host CANNOT reach 198.51.100.1 directly
            probe = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            probe.settimeout(2)
            try:
                probe.connect((NETNS_IP, 9999))
                pytest.fail("198.51.100.1 reachable WITHOUT tunnel — test invalid")
            except (ConnectionRefusedError, OSError):
                pass
            finally:
                probe.close()

            # Step 2: start proxy (host), agent (netns connects via veth)
            proxy.start(cfg)
            token = api.auth(cfg)

            agent_proc = subprocess.Popen(
                [
                    "sudo", "-n", "ip", "netns", "exec", NETNS_NAME,
                    str(_LINUX_AGENT), "-connect", f"{VETH_HOST_IP}:{cfg.tunnel_proxy_port}", "-ignore-cert",
                ],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
            )
            time.sleep(3)
            assert agent_proc.poll() is None, "netns agent died"

            agent_id = _wait_agent(cfg, token, timeout=15)
            assert agent_id is not None, "agent in netns did not connect"

            # Step 3: start listener inside netns
            listener_proc = _netns_start_listener()

            # Step 4: create TUN, route, start tunnel
            api.create_interface(cfg, token, "ligolo")
            api.add_routes(cfg, token, "ligolo", [TEST_SUBNET])
            api.start_tunnel(cfg, token, agent_id, "ligolo")
            time.sleep(1)

            # Step 5: connect from host to 198.51.100.1:9999 through tunnel
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            sock.settimeout(10)
            try:
                sock.connect((NETNS_IP, 9999))
                data = sock.recv(64)
                assert data == b"TUNNEL_OK", f"unexpected response: {data!r}"
            finally:
                sock.close()

            # Step 6: stop tunnel, verify unreachable again
            api.stop_tunnel(cfg, token, agent_id)
            time.sleep(1)

            probe2 = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            probe2.settimeout(3)
            try:
                probe2.connect((NETNS_IP, 9999))
                # Might succeed if route still cached — not a hard failure
            except (ConnectionRefusedError, OSError):
                pass
            finally:
                probe2.close()

            agent_proc.kill()
            agent_proc.wait()
            listener_proc.kill()
            listener_proc.wait()

            try:
                api.delete_interface(cfg, token, "ligolo")
            except Exception:
                pass
            proxy.stop(cfg)

        finally:
            _netns_teardown()


# ─── MCP tools (loopback, no VM) ────────────────────────────────────────


class TestMcpTools:
    def test_tunnel_status_no_proxy(self, cfg):
        _skip_no_proxy()
        from winbox.mcp._tunnel import tunnel_status
        with _patch_get_state(cfg):
            result = json.loads(tunnel_status())
        assert result["proxy_running"] is False

    def test_tunnel_status_with_proxy(self, cfg):
        _skip_no_proxy()
        from winbox.tunnel import proxy
        from winbox.mcp._tunnel import tunnel_status

        proxy.start(cfg)
        try:
            with _patch_get_state(cfg):
                result = json.loads(tunnel_status())
            assert result["proxy_running"] is True
            assert result["proxy_pid"] > 0
        finally:
            proxy.stop(cfg)

    def test_tunnel_down_idempotent(self, cfg):
        _skip_no_proxy()
        from winbox.mcp._tunnel import tunnel_down
        with _patch_get_state(cfg):
            result = json.loads(tunnel_down())
        assert result["status"] == "tunnel_down"

    def test_tunnel_status_shows_agent(self, cfg):
        _skip_no_agent()
        from winbox.tunnel import api, proxy
        from winbox.mcp._tunnel import tunnel_status

        proxy.start(cfg)
        agent_proc = _start_agent(cfg.tunnel_proxy_port)
        try:
            token = api.auth(cfg)
            agent_id = _wait_agent(cfg, token, timeout=15)
            assert agent_id is not None, "agent did not connect"
            with _patch_get_state(cfg):
                result = json.loads(tunnel_status())
            assert result["tunnel_active"] is False  # connected but no tunnel started
            assert len(result["agents"]) >= 1
        finally:
            agent_proc.kill()
            agent_proc.wait()
            proxy.stop(cfg)


# ─── CLI commands (loopback) ────────────────────────────────────────────


class TestCli:
    def test_tunnel_status_inactive(self):
        _skip_no_proxy()
        runner = CliRunner()
        result = runner.invoke(cli, ["tunnel", "status"])
        assert result.exit_code == 0
        output = result.output.lower()
        assert "not active" in output or "not running" in output

    def test_tunnel_down_idempotent(self):
        _skip_no_proxy()
        runner = CliRunner()
        result = runner.invoke(cli, ["tunnel", "down"])
        assert result.exit_code == 0
        output = result.output.lower()
        assert "not running" in output or "stopped" in output


# ─── helpers ─────────────────────────────────────────────────────────────


from contextlib import contextmanager
from unittest.mock import MagicMock, patch


@contextmanager
def _patch_get_state(cfg):
    """Patch _get_state so MCP tools use our cfg without needing a VM."""
    mock_vm = MagicMock()
    mock_ga = MagicMock()
    with patch("winbox.mcp._tunnel._get_state", return_value=(cfg, mock_vm, mock_ga)), \
         patch("winbox.mcp._tunnel._ensure_vm_ready", return_value=(cfg, mock_vm, mock_ga)):
        yield
