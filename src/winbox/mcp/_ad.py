"""Active Directory promote / demote / status MCP tools."""

from __future__ import annotations

import json as _json
import time as _time

from winbox.ad import encode_password, netbios_from_fqdn, require_server, wait_for_adws, wait_for_dfsr
from winbox.mcp import mcp
from winbox.mcp import _common as _mcp_common
from winbox.mcp._common import (
    _format_exec_result,
    _guest_errors,
)
from winbox.validate import check_domain_fqdn


def _validate_domain(name: str) -> None:
    err = check_domain_fqdn(name)
    if err:
        raise ValueError(err)


@mcp.tool()
def ad_promote(domain: str, password: str, timeout: int = 600) -> str:
    """Promote the Windows VM to a domain controller (new forest).

    Installs AD DS, promotes to DC, reboots, and verifies.

    Args:
        domain: FQDN for the new forest root (e.g. TESTLAB.LOCAL).
        password: Directory Services Restore Mode (DSRM) password.
        timeout: Execution timeout in seconds (default 600).
    """
    from winbox.ps import render_ps

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    _validate_domain(domain)
    netbios = netbios_from_fqdn(domain)
    pass_b64 = encode_password(password)

    with _guest_errors(vm):
        result = ga.exec_powershell(
            render_ps("ad_promote", domain=domain, netbios=netbios,
                      pass_b64=pass_b64),
            timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)

    with _guest_errors(vm):
        ga.exec("shutdown /r /t 0", timeout=10)
    _time.sleep(15)
    with _guest_errors(vm):
        ga.wait(timeout=300)

    try:
        hostname = wait_for_adws(ga)
    except RuntimeError:
        hostname = "unknown"

    try:
        wait_for_dfsr(ga)
    except RuntimeError:
        pass

    return _json.dumps({
        "domain": domain,
        "netbios": netbios,
        "hostname": hostname,
        "promoted": True,
    })


@mcp.tool()
def ad_demote(password: str, admin_password: str | None = None, timeout: int = 600) -> str:
    """Demote the domain controller back to a standalone server.

    Runs demotion, reboots, and waits for the VM to come back.

    Args:
        password: Local administrator password after demotion.
        admin_password: Domain admin password for the demotion credential
            (default: the VM's configured password).
        timeout: Execution timeout in seconds (default 600).
    """
    from winbox.ps import render_ps

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)
    pass_b64 = encode_password(password)
    admin_b64 = encode_password(admin_password or cfg.vm_password)

    with _guest_errors(vm):
        result = ga.exec_powershell(
            render_ps("ad_demote", pass_b64=pass_b64, admin_b64=admin_b64),
            timeout=timeout,
        )
    if result.exitcode != 0:
        return _format_exec_result(result)

    with _guest_errors(vm):
        ga.exec("shutdown /r /t 0", timeout=10)
    _time.sleep(15)
    with _guest_errors(vm):
        ga.wait(timeout=300)

    return _json.dumps({"demoted": True})


@mcp.tool()
def ad_status(timeout: int = 30) -> str:
    """Show Active Directory status on the Windows VM.

    Returns JSON with DC info, feature state, and service status.

    Args:
        timeout: Execution timeout in seconds (default 30).
    """
    from winbox.ps import render_ps

    cfg, vm, ga = _mcp_common._ensure_vm_ready()
    require_server(cfg)

    with _guest_errors(vm):
        result = ga.exec_powershell(
            render_ps("ad_status"), timeout=timeout,
        )
    return _format_exec_result(result)
