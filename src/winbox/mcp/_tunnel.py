"""Ligolo-ng tunnel MCP tools — route host traffic through the Windows VM."""

from __future__ import annotations

import json as _json
import time

from winbox.mcp import mcp
from winbox.mcp._common import _ensure_vm_ready, _get_state, GuestAgentError
from winbox.tunnel import AGENT_VM_PATH, TUN_INTERFACE


@mcp.tool()
def tunnel_up(subnets: list[str], interface: str = TUN_INTERFACE) -> str:
    """Start a ligolo-ng tunnel through the Windows VM.

    Launches ligolo-proxy on the host (daemon mode, REST API), uploads and
    starts the ligolo agent on the VM, creates a TUN interface, and routes
    the given subnets through it. After this, Linux tools (nxc, impacket,
    ldapsearch, etc.) can reach target subnets transparently — no
    proxychains needed.

    Requires ``ligolo-proxy`` on the host PATH (operator-installed).

    Args:
        subnets: Target subnets to route, e.g. ["10.0.0.0/8", "172.16.0.0/12"].
        interface: TUN interface name on the host (default "ligolo").
    """
    from winbox.tunnel import api, proxy

    if not subnets:
        return "error: at least one subnet required"

    cfg, vm, ga = _ensure_vm_ready()

    try:
        proxy.find_proxy()
    except proxy.ProxyNotFound as e:
        return str(e)

    try:
        pid = proxy.start(cfg)
    except proxy.ProxyError as e:
        return f"error: proxy failed to start: {e}"

    try:
        token = api.auth(cfg)
    except api.ApiError as e:
        return f"error: API auth failed: {e}"

    try:
        check = ga.exec(f'if exist "{AGENT_VM_PATH}" (echo OK) else (echo MISSING)', timeout=10)
        if "MISSING" in check.stdout:
            from winbox.tunnel import tunnel_dir
            import shutil
            from pathlib import Path
            from winbox.setup.installer.downloads import LIGOLO_AGENT_EXE
            cached = cfg.iso_dir / LIGOLO_AGENT_EXE
            if not cached.exists():
                return (
                    f"error: ligolo-agent.exe not on VM and not cached at {cached}. "
                    "Run 'winbox setup' or download it manually."
                )
            shared_dest = cfg.shared_dir / LIGOLO_AGENT_EXE
            cfg.shared_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(cached, shared_dest)
            ga.exec(
                f'copy "Z:\\{LIGOLO_AGENT_EXE}" "{AGENT_VM_PATH}"',
                timeout=30,
            )
    except GuestAgentError as e:
        return f"error: checking/uploading agent: {e}"

    try:
        ga.exec(f'taskkill /im ligolo-agent.exe /f 2>nul', timeout=10)
    except GuestAgentError:
        pass
    time.sleep(0.5)

    try:
        ga.exec_background(
            f'"{AGENT_VM_PATH}" -connect {cfg.host_ip}:{cfg.tunnel_proxy_port} -ignore-cert -retry',
        )
    except GuestAgentError as e:
        return f"error: failed to start agent on VM: {e}"

    agent_id = None
    for _ in range(30):
        time.sleep(1)
        try:
            agent_list = api.agents(cfg, token)
            if agent_list:
                agent_id = agent_list[0].get("id") or agent_list[0].get("ID")
                break
        except api.ApiError:
            pass

    if agent_id is None:
        return (
            "error: agent did not connect within 30s. "
            "Check VM firewall/connectivity and proxy log."
        )

    try:
        api.create_interface(cfg, token, interface)
    except api.ApiError as e:
        if "already" not in str(e).lower():
            return f"error: create interface: {e}"

    try:
        api.add_routes(cfg, token, interface, subnets)
    except api.ApiError as e:
        return f"error: add routes: {e}"

    try:
        api.start_tunnel(cfg, token, agent_id, interface)
    except api.ApiError as e:
        return f"error: start tunnel: {e}"

    return _json.dumps({
        "status": "tunnel_up",
        "proxy_pid": pid,
        "agent_id": agent_id,
        "interface": interface,
        "subnets": subnets,
    })


@mcp.tool()
def tunnel_down() -> str:
    """Stop the ligolo-ng tunnel — kill agent, stop tunnel, clean up routes.

    Tears down the tunnel, kills the agent on the VM, and optionally stops
    the proxy daemon. Idempotent — safe to call even if no tunnel is active.
    """
    from winbox.tunnel import api, proxy

    cfg, vm, ga = _get_state()
    results = []

    try:
        if proxy.is_running(cfg):
            token = api.auth(cfg)
            agent_list = api.agents(cfg, token)
            for agent in agent_list:
                aid = agent.get("id") or agent.get("ID")
                if aid is not None and agent.get("Running"):
                    try:
                        api.stop_tunnel(cfg, token, aid)
                        results.append(f"tunnel {aid} stopped")
                    except api.ApiError:
                        pass
    except Exception:
        pass

    try:
        ga.exec('taskkill /im ligolo-agent.exe /f 2>nul', timeout=10)
        results.append("agent killed")
    except GuestAgentError:
        results.append("agent not running or VM unreachable")

    stopped = proxy.stop(cfg)
    if stopped:
        results.append("proxy stopped")
    else:
        results.append("proxy was not running")

    return _json.dumps({"status": "tunnel_down", "details": results})


@mcp.tool()
def tunnel_route(add: str | None = None, remove: str | None = None,
                 interface: str = TUN_INTERFACE) -> str:
    """Add or remove a subnet route on a running ligolo tunnel.

    Args:
        add: Subnet to add, e.g. "172.16.0.0/12".
        remove: Subnet to remove, e.g. "172.16.0.0/12".
        interface: TUN interface name (default "ligolo").
    """
    from winbox.tunnel import api, proxy

    if not add and not remove:
        return "error: specify add or remove (or both)"

    cfg, vm, ga = _get_state()
    if not proxy.is_running(cfg):
        return "error: proxy not running — start tunnel first"

    try:
        token = api.auth(cfg)
    except api.ApiError as e:
        return f"error: API auth: {e}"

    results = []
    if add:
        try:
            api.add_routes(cfg, token, interface, [add])
            results.append(f"added {add}")
        except api.ApiError as e:
            results.append(f"add {add} failed: {e}")

    if remove:
        try:
            api.delete_route(cfg, token, interface, remove)
            results.append(f"removed {remove}")
        except api.ApiError as e:
            results.append(f"remove {remove} failed: {e}")

    return _json.dumps({"status": "ok", "results": results})


@mcp.tool()
def tunnel_status() -> str:
    """Report tunnel state — proxy, agent, routes, interface."""
    from winbox.tunnel import api, proxy

    cfg, vm, ga = _get_state()
    pid = proxy.is_running(cfg)

    status = {
        "proxy_running": pid is not None,
        "proxy_pid": pid,
        "agents": [],
        "interfaces": {},
        "tunnel_active": False,
    }

    if pid:
        try:
            token = api.auth(cfg)
            status["agents"] = api.agents(cfg, token)
            status["interfaces"] = api.list_interfaces(cfg, token)
            status["tunnel_active"] = any(
                a.get("Running") for a in status["agents"]
            )
        except api.ApiError:
            status["api_error"] = "could not reach API"

    return _json.dumps(status)
