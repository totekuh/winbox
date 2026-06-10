"""Detonation preflight — verify the lab is safe before running malware.

`winbox detonate check` is READ-ONLY: it runs no sample and changes no
state. It answers one question — "is it safe to detonate right now?" — by
inspecting the pieces that matter for malware analysis:

  * HARD GATE: the guest must NOT be able to reach the real internet
    (nwfilter attached via `net isolate`, or the NIC unplugged via
    `net unplug`). If the guest can still route out, the check fails red:
    detonating here would contact live C2 from your real egress IP.
  * Capture running   (so the C2 traffic lands in a pcap)
  * Sinkhole running  (so C2 lookups resolve to the bridge and get logged)
  * Guest DNS pointed at the sink (so the guest actually asks the sinkhole)
  * Defender disabled (so the sample isn't quarantined before it runs)
  * A snapshot exists (so you can revert afterwards)

Everything except the internet gate is advisory: a WARN tells you the run
will be less useful, not that it's dangerous.
"""

from __future__ import annotations

import click

from winbox import nwfilter
from winbox import sinkhole as sk
from winbox.cli import console, needs_vm
from winbox.cli.capture import pid_alive as _cap_pid_alive
from winbox.cli.capture import read_pidfile as _cap_read_pidfile
from winbox.config import Config
from winbox.vm import GuestAgent, GuestAgentError, VM


def _ok(label: str, detail: str = "") -> None:
    console.print(f"  [green]PASS[/]  {label}" + (f" — {detail}" if detail else ""))


def _warn(label: str, detail: str = "") -> None:
    console.print(f"  [yellow]WARN[/]  {label}" + (f" — {detail}" if detail else ""))


def _fail(label: str, detail: str = "") -> None:
    console.print(f"  [red]FAIL[/]  {label}" + (f" — {detail}" if detail else ""))


def _guest_dns_servers(ga: GuestAgent) -> list[str] | None:
    """IPv4 DNS servers configured in the guest, or None if unknown."""
    try:
        result = ga.exec_powershell(
            "(Get-DnsClientServerAddress -AddressFamily IPv4"
            " | Where-Object { $_.ServerAddresses }).ServerAddresses",
            timeout=15,
        )
    except GuestAgentError:
        return None
    if result.exitcode != 0:
        return None
    return [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]


def _defender_realtime_on(ga: GuestAgent) -> bool | None:
    """True/False if Defender real-time protection is on, None if unknown."""
    try:
        result = ga.exec_powershell(
            "(Get-MpComputerStatus).RealTimeProtectionEnabled", timeout=15,
        )
    except GuestAgentError:
        return None
    if result.exitcode != 0:
        return None
    out = result.stdout.strip().lower()
    if out.startswith("true"):
        return True
    if out.startswith("false"):
        return False
    return None


@click.group()
def detonate() -> None:
    """Detonation safety — preflight checks before running a sample.

    This group runs NO malware. `check` only inspects state.
    """
    pass


@detonate.command("check")
@needs_vm(auto_start=False)
def detonate_check(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Preflight the lab. Exits non-zero if it is unsafe to detonate.

    The single hard requirement is that the guest cannot reach the real
    internet. Everything else is reported as a warning so you know what
    you'll be missing, not that you must stop.
    """
    console.print("[bold]Detonation preflight[/]\n")

    safe = True

    # ── HARD GATE: guest must not reach the real internet ────────────────
    link = vm.net_link_state()
    isolated = nwfilter.has_filter(vm.name)
    if link == "down":
        _ok("Internet blocked", "NIC unplugged (full air-gap)")
    elif isolated:
        _ok("Internet blocked", "nwfilter attached (net isolate)")
    else:
        _fail(
            "Internet REACHABLE",
            "guest can route to the real internet — run `winbox net isolate` "
            "(or `net unplug`) first",
        )
        safe = False

    # ── Capture (advisory) ───────────────────────────────────────────────
    cap = _cap_read_pidfile(cfg)
    if cap and _cap_pid_alive(cap[0]):
        _ok("Capture running", f"pcap: {cap[1]}")
    else:
        _warn("Capture not running", "no pcap — start with `winbox capture start` (as root)")

    # ── Sinkhole (advisory) ──────────────────────────────────────────────
    sink_pid = sk.is_running(cfg)
    if sink_pid is not None:
        _ok("Sinkhole running", f"pid {sink_pid}, log: {sk.query_log_path(cfg)}")
    else:
        _warn(
            "Sinkhole not running",
            "C2 lookups won't be answered/logged — start with `winbox sinkhole start`",
        )

    # ── Guest DNS → sink (advisory; only meaningful with a sinkhole) ─────
    servers = _guest_dns_servers(ga)
    if servers is None:
        _warn("Guest DNS unknown", "could not query the guest resolver")
    elif cfg.host_ip in servers:
        _ok("Guest DNS → sink", f"{cfg.host_ip}")
    else:
        _warn(
            "Guest DNS not pointed at sink",
            f"configured: {', '.join(servers) or 'none'} — run "
            f"`winbox dns set {cfg.host_ip}`",
        )

    # ── Defender disabled (advisory) ─────────────────────────────────────
    rtp = _defender_realtime_on(ga)
    if rtp is True:
        _warn("Defender real-time ON", "sample may be quarantined — run `winbox av disable`")
    elif rtp is False:
        _ok("Defender disabled")
    else:
        _warn("Defender status unknown", "could not query Get-MpComputerStatus")

    # ── Snapshot exists (advisory) ───────────────────────────────────────
    try:
        snaps = vm.snapshot_list()
    except Exception:
        snaps = []
    if snaps:
        _ok("Snapshot exists", f"{len(snaps)} found — revert with `winbox restore`")
    else:
        _warn("No snapshot", "no revert point — create one with `winbox snapshot <name>`")

    console.print()
    if safe:
        console.print("[green][+][/] Safe to detonate — the guest cannot reach the internet.")
        console.print("    Review any WARN lines above; they limit what you'll capture.")
    else:
        console.print("[red][-][/] NOT safe to detonate — isolate the guest first.")
        raise SystemExit(1)


REGISTER = ("Malware Analysis", [detonate])
