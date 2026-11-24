"""Ligolo-ng tunnel commands — route Linux traffic through the Windows VM."""

from __future__ import annotations

import json
import time

import click

from winbox.cli import console
from winbox.config import Config
from winbox.vm import VM, GuestAgent, GuestAgentError, VMState


@click.group("tunnel")
def tunnel() -> None:
    """Ligolo-ng tunnel — route host traffic through the VM's VPN/Zscaler."""
    pass


@tunnel.command("up")
@click.argument("subnets", nargs=-1, required=True)
@click.option("--interface", "-i", default="ligolo", help="TUN interface name.")
@click.pass_context
def tunnel_up(ctx: click.Context, subnets: tuple[str, ...], interface: str) -> None:
    """Start tunnel and route SUBNETS through the VM.

    Example: winbox tunnel up 10.0.0.0/8 172.16.0.0/12
    """
    from winbox.tunnel import AGENT_VM_PATH, api, proxy

    cfg: Config = ctx.obj["cfg"]
    vm = VM(cfg)
    ga = GuestAgent(cfg)

    if vm.state() != VMState.RUNNING:
        console.print(f"[red][-][/] VM not running (state: {vm.state().value})")
        raise SystemExit(1)

    try:
        proxy.find_proxy()
    except proxy.ProxyNotFound as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)

    console.print("[blue][*][/] Starting ligolo proxy...")
    try:
        pid = proxy.start(cfg)
    except proxy.ProxyError as e:
        console.print(f"[red][-][/] {e}")
        raise SystemExit(1)
    console.print(f"[green][+][/] Proxy running (PID {pid})")

    token = api.auth(cfg)

    try:
        check = ga.exec(
            f'if exist "{AGENT_VM_PATH}" (echo OK) else (echo MISSING)', timeout=10,
        )
        if "MISSING" in check.stdout:
            console.print("[blue][*][/] Uploading ligolo-agent.exe to VM...")
            import shutil
            from winbox.setup.installer.downloads import LIGOLO_AGENT_EXE
            cached = cfg.iso_dir / LIGOLO_AGENT_EXE
            if not cached.exists():
                console.print(f"[red][-][/] {LIGOLO_AGENT_EXE} not cached. Run winbox setup or download it.")
                raise SystemExit(1)
            shared_dest = cfg.shared_dir / LIGOLO_AGENT_EXE
            cfg.shared_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(cached, shared_dest)
            ga.exec(f'copy "Z:\\{LIGOLO_AGENT_EXE}" "{AGENT_VM_PATH}"', timeout=30)
            console.print("[green][+][/] Agent uploaded")
    except GuestAgentError as e:
        console.print(f"[red][-][/] Agent check/upload failed: {e}")
        raise SystemExit(1)

    try:
        ga.exec('taskkill /im ligolo-agent.exe /f 2>nul', timeout=10)
    except GuestAgentError:
        pass
    time.sleep(0.5)

    console.print("[blue][*][/] Starting agent on VM...")
    try:
        ga.exec_background(
            f'"{AGENT_VM_PATH}" -connect {cfg.host_ip}:{cfg.tunnel_proxy_port} -ignore-cert -retry',
        )
    except GuestAgentError as e:
        console.print(f"[red][-][/] Failed to start agent: {e}")
        raise SystemExit(1)

    console.print("[blue][*][/] Waiting for agent to connect...")
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
        console.print("[red][-][/] Agent did not connect within 30s")
        raise SystemExit(1)
    console.print(f"[green][+][/] Agent connected (ID {agent_id})")

    try:
        api.create_interface(cfg, token, interface)
    except api.ApiError as e:
        if "already" not in str(e).lower():
            console.print(f"[red][-][/] Create interface: {e}")
            raise SystemExit(1)

    api.add_routes(cfg, token, interface, list(subnets))
    console.print(f"[green][+][/] Routes added: {', '.join(subnets)}")

    api.start_tunnel(cfg, token, agent_id, interface)
    console.print(f"[green][+][/] Tunnel active on {interface}")


@tunnel.command("down")
@click.pass_context
def tunnel_down(ctx: click.Context) -> None:
    """Stop the tunnel and clean up."""
    from winbox.tunnel import api, proxy

    cfg: Config = ctx.obj["cfg"]
    ga = GuestAgent(cfg)

    if proxy.is_running(cfg):
        try:
            token = api.auth(cfg)
            for agent in api.agents(cfg, token):
                aid = agent.get("id") or agent.get("ID")
                if aid is not None and agent.get("Running"):
                    api.stop_tunnel(cfg, token, aid)
                    console.print(f"[green][+][/] Tunnel {aid} stopped")
        except Exception:
            pass

    try:
        ga.exec('taskkill /im ligolo-agent.exe /f 2>nul', timeout=10)
        console.print("[green][+][/] Agent killed")
    except GuestAgentError:
        pass

    if proxy.stop(cfg):
        console.print("[green][+][/] Proxy stopped")
    else:
        console.print("[dim]Proxy was not running[/]")


@tunnel.command("status")
@click.pass_context
def tunnel_status(ctx: click.Context) -> None:
    """Show tunnel state."""
    from winbox.tunnel import api, proxy

    cfg: Config = ctx.obj["cfg"]
    pid = proxy.is_running(cfg)

    if not pid:
        console.print("[dim]Tunnel not active (proxy not running)[/]")
        return

    console.print(f"[green][+][/] Proxy running (PID {pid})")
    try:
        token = api.auth(cfg)
        agents = api.agents(cfg, token)
        interfaces = api.list_interfaces(cfg, token)
        for agent in agents:
            name = agent.get("Name", "?")
            alive = agent.get("SessionID", "") != ""
            running = agent.get("Running", False)
            status = "[green]active[/]" if running else ("[yellow]connected[/]" if alive else "[red]offline[/]")
            console.print(f"  Agent: {name} — {status}")
        if interfaces:
            console.print(f"  Interfaces: {json.dumps(interfaces, indent=2)}")
    except api.ApiError as e:
        console.print(f"[yellow][!][/] API error: {e}")


@tunnel.group("route")
def tunnel_route() -> None:
    """Manage routes on a running tunnel."""
    pass


@tunnel_route.command("add")
@click.argument("subnet")
@click.option("--interface", "-i", default="ligolo")
@click.pass_context
def route_add(ctx: click.Context, subnet: str, interface: str) -> None:
    """Add a subnet route."""
    from winbox.tunnel import api, proxy

    cfg: Config = ctx.obj["cfg"]
    if not proxy.is_running(cfg):
        console.print("[red][-][/] Proxy not running")
        raise SystemExit(1)
    token = api.auth(cfg)
    api.add_routes(cfg, token, interface, [subnet])
    console.print(f"[green][+][/] Route added: {subnet}")


@tunnel_route.command("rm")
@click.argument("subnet")
@click.option("--interface", "-i", default="ligolo")
@click.pass_context
def route_rm(ctx: click.Context, subnet: str, interface: str) -> None:
    """Remove a subnet route."""
    from winbox.tunnel import api, proxy

    cfg: Config = ctx.obj["cfg"]
    if not proxy.is_running(cfg):
        console.print("[red][-][/] Proxy not running")
        raise SystemExit(1)
    token = api.auth(cfg)
    api.delete_route(cfg, token, interface, subnet)
    console.print(f"[green][+][/] Route removed: {subnet}")


REGISTER = ("Tunnel", [tunnel])
