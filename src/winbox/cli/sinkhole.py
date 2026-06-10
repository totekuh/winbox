"""DNS sinkhole / fake-internet for malware detonation.

When a sample is detonated in the isolated VM and tries to resolve its C2
domain, this sinkhole answers EVERY A query with the Kali bridge IP and logs
the queried name — so the C2 domain is captured without the sample ever
reaching the real internet. Point the guest's resolver at the sink with the
existing ``winbox dns set <bridge-ip>`` first.

Thin CLI: all the DNS / process logic lives in ``winbox.sinkhole``.
"""

from __future__ import annotations

import os
import subprocess
import sys

import click

from winbox import sinkhole as sk
from winbox.cli import console
from winbox.config import Config


def _err(msg: str) -> None:
    console.print(msg)


@click.group("sinkhole")
def sinkhole() -> None:
    """DNS sinkhole — answer every C2 lookup with the bridge IP and log it.

    Workflow:

      1. winbox net isolate            # cut the guest off from the internet
      2. winbox sinkhole start         # (as root) bind udp/53 on the bridge
      3. winbox dns set 192.168.122.1  # point the guest's resolver at the sink
      4. detonate the sample
      5. winbox sinkhole log           # read the captured C2 domains
    """
    pass


@sinkhole.command("start")
@click.option(
    "--sink-ip", default=None,
    help="IP returned for every A query (default: the Kali bridge IP, host_ip).",
)
@click.option(
    "--ttl", default=sk.DEFAULT_TTL, show_default=True,
    help="TTL (seconds) on sinkholed A records.",
)
@click.option(
    "--port", default=sk.DNS_PORT, show_default=True,
    help="UDP port to bind. The default (53) is privileged; pass a high "
         "port to run unprivileged (the guest then needs a :53->port redirect).",
)
@click.pass_context
def start(ctx: click.Context, sink_ip: str | None, ttl: int, port: int) -> None:
    """Launch the DNS sinkhole detached (binds udp/<port> on the bridge).

    Binding the default port 53 needs privilege (root, a lowered
    ``net.ipv4.ip_unprivileged_port_start``, or ``cap_net_bind_service`` on
    the interpreter). The bind is probed first, so you get an accurate error
    rather than a guess based on your uid. Pair with `winbox dns set
    <bridge-ip>` so the guest sends its lookups here.
    """
    cfg: Config = ctx.obj["cfg"]
    bind_ip = cfg.host_ip
    sink = sink_ip or cfg.host_ip

    existing = sk.is_running(cfg)
    if existing is not None:
        _err(f"[yellow][!][/] Sinkhole already running (pid {existing})")
        _err(f"    Query log: {sk.query_log_path(cfg)}")
        raise SystemExit(1)

    # Probe the bind up front so the detached server doesn't die silently
    # after we've already reported success — and so a privilege failure on
    # the privileged port gives an actionable message instead of "needs root".
    status = sk.try_bind(bind_ip, port)
    if status == "in_use":
        _err(
            f"[red][-][/] Something already holds udp/{port} on {bind_ip} "
            "(systemd-resolved? dnsmasq? another sinkhole?)."
        )
        _err("    Stop it first, e.g.: systemctl stop systemd-resolved")
        _err("    (libvirt's own dnsmasq owns it by default — disable the network's")
        _err("     DNS with <dns enable='no'/> in `virsh net-edit default`, keep DHCP.)")
        raise SystemExit(1)
    if status == "denied":
        _err(f"[red][-][/] Permission denied binding {bind_ip}:{port}.")
        if port < 1024:
            _err(f"    Port {port} is privileged. Options:")
            _err("      • run as root:   [bold]sudo --preserve-env=HOME winbox sinkhole start[/]")
            _err("      • allow it once: [bold]sudo sysctl net.ipv4.ip_unprivileged_port_start=53[/]")
            _err("      • or high port:  [bold]winbox sinkhole start --port 5353[/]"
                 "  (needs a :53->5353 redirect for the guest)")
        raise SystemExit(1)
    if status.startswith("error:"):
        _err(f"[red][-][/] Cannot bind {bind_ip}:{port} — {status[len('error:'):]}")
        raise SystemExit(1)

    sk.sinkhole_dir(cfg).mkdir(parents=True, exist_ok=True)
    server_log = sk.server_log_path(cfg)

    # Re-invoke ourselves as the hidden foreground server, detached into its
    # own session so it outlives this CLI invocation.
    cmd = [
        sys.executable, "-m", "winbox", "sinkhole", "_serve",
        "--sink-ip", sink, "--ttl", str(ttl), "--port", str(port),
    ]
    log_fh = open(server_log, "ab", buffering=0)
    proc = subprocess.Popen(
        cmd,
        stdout=log_fh,
        stderr=log_fh,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    sk.write_pidfile(cfg, proc.pid, port)

    # Wait for the detached server to log a successful bind before claiming
    # success — otherwise the first guest lookup can race the bind and get a
    # connection-refused.
    if not sk.wait_ready(server_log, proc):
        _err("[red][-][/] Sinkhole process exited or never bound — "
             f"check {server_log}")
        sk.stop(cfg)
        raise SystemExit(1)

    _err(f"[green][+][/] DNS sinkhole started (pid {proc.pid})")
    _err(f"    Bind:      {bind_ip}:{port} (UDP)")
    _err(f"    Sink IP:   {sink}  (every A query answers this)")
    _err(f"    Query log: {sk.query_log_path(cfg)}")
    if port == sk.DNS_PORT:
        _err("    Point the guest at it: [bold]winbox dns set " + bind_ip + "[/]")
    else:
        _err(f"    [yellow]Non-standard port {port}[/] — add a :53->{port} redirect so the guest reaches it.")
    _err("    Read captured domains: [bold]winbox sinkhole log[/]")


@sinkhole.command("stop")
@click.pass_context
def stop(ctx: click.Context) -> None:
    """Stop the detached sinkhole and clean up the pidfile."""
    cfg: Config = ctx.obj["cfg"]
    try:
        stopped = sk.stop(cfg)
    except PermissionError:
        _err("[red][-][/] Cannot signal the sinkhole process (root-owned?). "
             "Re-run with sudo.")
        raise SystemExit(1)

    if stopped:
        _err("[green][+][/] Sinkhole stopped")
    else:
        _err("[dim]·[/] Sinkhole not running")


@sinkhole.command("status")
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show whether the sinkhole is running, its bind/sink, and log stats."""
    cfg: Config = ctx.obj["cfg"]
    pid = sk.is_running(cfg)
    log_path = sk.query_log_path(cfg)
    count = sk.line_count(log_path)
    port = sk.read_port(cfg)

    if pid is not None:
        console.print(f"State:     [green]running[/] (pid {pid})")
    else:
        console.print("State:     [red]stopped[/]")

    console.print(f"Bind:      {cfg.host_ip}:{port} (UDP)")
    console.print(f"Sink IP:   {cfg.host_ip} (default; A queries answer this)")
    console.print(f"Query log: {log_path}")
    console.print(f"Queries:   {count} logged")


@sinkhole.command("log")
@click.option("-n", "--lines", "n", default=0, show_default=False,
              help="Show only the last N lines (default: all).")
@click.option("-f", "--follow", is_flag=True,
              help="Follow the log as new queries arrive (Ctrl-C to stop).")
@click.pass_context
def log(ctx: click.Context, n: int, follow: bool) -> None:
    """Print the captured DNS queries — the C2 domains.

    Columns: timestamp, qname, qtype, client IP (tab-separated, greppable).
    """
    cfg: Config = ctx.obj["cfg"]
    log_path = sk.query_log_path(cfg)

    if not log_path.exists():
        _err("[dim]·[/] No queries logged yet "
             f"(log will appear at {log_path})")
        return

    text = log_path.read_text(errors="replace")
    out_lines = text.splitlines()
    if n > 0:
        out_lines = out_lines[-n:]
    for line in out_lines:
        click.echo(line)

    if follow:
        import time as _time
        with open(log_path, "r", errors="replace") as f:
            f.seek(0, os.SEEK_END)
            try:
                while True:
                    chunk = f.readline()
                    if chunk:
                        click.echo(chunk.rstrip("\n"))
                    else:
                        _time.sleep(0.5)
            except KeyboardInterrupt:
                pass


@sinkhole.command("inetsim")
@click.option("--sink-ip", default=None,
              help="IP INETSim hands out / binds against (default: bridge IP).")
@click.pass_context
def inetsim(ctx: click.Context, sink_ip: str | None) -> None:
    """Optional fake-services layer (HTTP/HTTPS/FTP/SMTP/...) via INETSim.

    Generates an INETSim config bound to the bridge IP (with INETSim's own
    DNS disabled — the built-in sinkhole owns udp/53) and prints the launch
    command. If INETSim isn't installed, prints the install hint.
    """
    cfg: Config = ctx.obj["cfg"]
    binary = sk.inetsim_installed()

    if binary is None:
        _err("[yellow][!][/] INETSim is not installed.")
        _err("    Install it with: [bold]sudo apt install inetsim[/]")
        _err("    It adds canned fake services (HTTP, HTTPS, FTP, SMTP, POP3,")
        _err("    IRC, ...) so a sample that connects AFTER resolving its C2")
        _err("    to the sink IP gets a believable response — capturing the")
        _err("    full URI / payload, not just the domain. The built-in DNS")
        _err("    sinkhole works without it; INETSim is an enhancement.")
        raise SystemExit(1)

    conf_path = sk.write_inetsim_conf(cfg, sink_ip=sink_ip)
    data_dir = sk.inetsim_data_dir(cfg)

    _err(f"[green][+][/] INETSim found: {binary}")
    _err(f"[green][+][/] Config written: {conf_path}")
    _err(f"    Data dir:  {data_dir}")
    _err(f"    Bind:      {cfg.host_ip} (DNS left to the winbox sinkhole)")
    _err("    Launch it with:")
    _err(f"      [bold]sudo inetsim --conf {conf_path} --data-dir {data_dir}[/]")
    _err("    Then point the guest at the sinkhole: "
         f"[bold]winbox dns set {cfg.host_ip}[/]")


@sinkhole.command("_serve", hidden=True)
@click.option("--sink-ip", default=None)
@click.option("--ttl", default=sk.DEFAULT_TTL)
@click.option("--port", default=sk.DNS_PORT)
@click.pass_context
def _serve(ctx: click.Context, sink_ip: str | None, ttl: int, port: int) -> None:
    """Hidden foreground entrypoint re-invoked by `start` in a detached
    process. Blocks serving DNS until SIGTERM."""
    cfg: Config = ctx.obj["cfg"]
    sk.serve(cfg, sink_ip=sink_ip, ttl=ttl, port=port)


REGISTER = ("Malware Analysis", [sinkhole])
