"""Shared Active Directory helpers for CLI and MCP surfaces."""

from __future__ import annotations

import base64
import time

from winbox.config import Config
from winbox.vm import GuestAgent


def require_server(cfg: Config) -> None:
    """Raise if the current profile is a client SKU (win10/win11)."""
    if cfg.profile.client_sku:
        raise ValueError(
            "AD DS requires Windows Server (server2022 or server2025). "
            f"Current profile: {cfg.profile.key}"
        )


def netbios_from_fqdn(domain: str) -> str:
    """Derive a NetBIOS name from a domain FQDN (first label, uppercase)."""
    return domain.split(".")[0].upper()


def encode_password(password: str) -> str:
    """Base64-encode a password for safe transport to the guest."""
    return base64.b64encode(password.encode()).decode()


_ADWS_VERIFY = (
    "Restart-Service ADWS -Force -ErrorAction SilentlyContinue; "
    "Import-Module ActiveDirectory -ErrorAction Stop; "
    "(Get-ADDomainController -Server localhost -ErrorAction Stop).HostName"
)

_DFSR_READINESS = (
    "ipconfig /registerdns | Out-Null; "
    "Restart-Service DFSR -Force -ErrorAction SilentlyContinue; "
    "Start-Sleep 5; "
    "net share SYSVOL 2>$null | Select-String 'SYSVOL'; "
    "if ($?) { 'ready' } else { exit 1 }"
)


def wait_for_adws(ga: GuestAgent, retries: int = 12, interval: int = 10) -> str:
    """Wait for AD Web Services to become responsive after DC promotion.

    Retries with backoff. Returns the DC hostname on success, raises
    RuntimeError if ADWS never comes up.
    """
    for attempt in range(retries):
        result = ga.exec_powershell(_ADWS_VERIFY, timeout=30)
        if result.exitcode == 0 and result.stdout.strip():
            return result.stdout.strip()
        if attempt < retries - 1:
            time.sleep(interval)
    raise RuntimeError(
        f"ADWS not responsive after {retries * interval}s. "
        f"Last error: {result.stderr.strip()}"
    )


def wait_for_dfsr(ga: GuestAgent, retries: int = 6, interval: int = 10) -> None:
    """Wait for DFSR to be ready (SYSVOL share available).

    DomainV2 DFS namespaces require DFSR. On a fresh DC, DFSR needs
    DNS re-registration and a service restart before it can initialize.
    """
    for attempt in range(retries):
        result = ga.exec_powershell(_DFSR_READINESS, timeout=30)
        if result.exitcode == 0 and "ready" in result.stdout:
            return
        if attempt < retries - 1:
            time.sleep(interval)
    raise RuntimeError(
        f"DFSR not ready after {retries * interval}s. "
        "SYSVOL share not available — DomainV2 DFS will fail."
    )
