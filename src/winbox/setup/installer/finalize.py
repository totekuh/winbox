"""Post-provision verification, shutdown, snapshot, and network filter."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from rich.console import Console

from winbox.setup.installer.downloads import RUNEX_SHA256
from winbox.setup.installer.provision import BOOTSTRAP_LOG, PROVISION_SENTINEL
from winbox.vm import VM, GuestAgent, GuestAgentError

if TYPE_CHECKING:
    from winbox.config import Config

console = Console()


def _verify_python(ga: GuestAgent) -> None:
    """Warn loudly if the guest has no working Python.

    provision.ps1 treats a failed Python install as non-fatal and continues,
    and the provisioning sentinel only proves the script *finished* — so a
    build with no Python previously reported complete success. Python in the
    guest is what the MCP ``python`` tool and parts of kdbg run on, so that
    silence turned a broken VM into a puzzle discovered much later.
    """
    # On client SKUs Python comes from the embeddable zip extracted to
    # C:\Python313 and put on the machine PATH — which a process started
    # before the PATH write would not see. Check the explicit path too so a
    # working install is never reported as missing.
    candidates = ["python.exe", r"C:\Python313\python.exe"]
    for candidate in candidates:
        try:
            # No quotes: the guest agent escapes them as \" and cmd.exe has no
            # backslash-escape rule, so they arrive as literal characters.
            # Neither candidate path contains a space.
            result = ga.exec(f"{candidate} --version", timeout=30)
        except GuestAgentError:
            continue
        if result.exitcode == 0 and "Python" in (result.stdout + result.stderr):
            version = (result.stdout or result.stderr).strip()
            console.print(f"[green][+][/] Guest Python verified ({version})")
            return

    console.print(
        "[yellow][!][/] No working Python in the guest — the MCP [bold]python[/] "
        "tool and parts of kdbg will not work.\n"
        "    Provisioning otherwise completed, so the VM is usable for "
        "everything else.\n"
        "    Check the install log in the VM: "
        "[bold]winbox exec 'type C:\\winbox-python-install.log'[/]\n"
        "    Then re-run provisioning with: [bold]winbox provision[/]"
    )


def _verify_runex(ga: GuestAgent) -> None:
    result = ga.exec_powershell(
        "(Get-FileHash -Algorithm SHA256 'C:\\Tools\\RunEx.exe').Hash.ToLowerInvariant()",
        timeout=30,
    )
    if result.exitcode != 0 or RUNEX_SHA256 not in result.stdout.lower():
        raise RuntimeError(
            "RunEx is missing or corrupt in the guest. Re-run 'winbox provision'."
        )
    console.print("[green][+][/] Guest RunEx verified")


def _verify_provisioning(cfg: Config, vm: VM, ga: GuestAgent) -> None:
    """Boot the VM once more and assert provision.ps1 actually finished.

    On failure, dumps the bootstrap log from inside the VM so the user sees
    the actual PowerShell error. Shuts the VM back down before returning so
    the caller can create the clean snapshot.
    """
    console.print("[blue][*][/] Booting VM to verify provisioning...")
    vm.start()
    try:
        ga.wait(timeout=420)
    except GuestAgentError as e:
        raise RuntimeError(
            f"VM came back up but guest agent is unreachable: {e}"
        ) from e

    sentinel_check = ga.exec(
        f"if exist {PROVISION_SENTINEL} (echo OK) else (echo MISSING)",
        timeout=30,
    )

    if "OK" in sentinel_check.stdout:
        console.print("[green][+][/] Provisioning sentinel verified")
        _verify_python(ga)
        _verify_runex(ga)
        _shutdown_and_wait(vm, ga)
        return

    console.print("[red][-][/] Provisioning sentinel missing — provision.ps1 did not finish")
    console.print("[blue][*][/] Dumping bootstrap log from VM:")
    console.print("─" * 60)
    try:
        log = ga.exec(f"type {BOOTSTRAP_LOG}", timeout=30)
        if log.stdout:
            console.print(log.stdout, markup=False, highlight=False, end="")
        else:
            console.print("[yellow](bootstrap log is empty)[/]")
    except GuestAgentError:
        console.print("[yellow](could not read bootstrap log)[/]")
    console.print("─" * 60)

    # Best-effort shutdown before bailing so we don't leave a running VM behind
    try:
        _shutdown_and_wait(vm, ga)
    except Exception:
        try:
            vm.force_stop()
        except Exception:
            pass

    raise RuntimeError(
        "Provisioning did not complete — see bootstrap log above. "
        "Fix the underlying issue and re-run `winbox setup -y`."
    )


def _shutdown_and_wait(vm: VM, ga: GuestAgent, timeout: int = 300) -> None:
    """Ask the guest to shut down and wait for the VM to reach SHUTOFF."""
    console.print("[blue][*][/] Shutting VM down...")
    try:
        ga.shutdown()
    except GuestAgentError:
        pass  # expected — VM dies before GA can reply
    if not vm.wait_shutdown(timeout=timeout):
        console.print("[yellow][!][/] VM did not shut down in time, force-stopping")
        vm.force_stop()


def create_clean_snapshot(cfg: Config) -> None:
    """Create a 'clean' snapshot after setup."""
    vm = VM(cfg)
    console.print("[blue][*][/] Creating 'clean' snapshot...")
    try:
        vm.snapshot_create("clean")
        console.print("[green][+][/] Snapshot 'clean' created")
    except RuntimeError as e:
        console.print(f"[yellow][!][/] Could not create snapshot: {e}")


def register_nwfilter(cfg: Config) -> None:
    """Register the 'winbox-isolate' libvirt nwfilter (idempotent).

    Ensures `winbox net isolate` can attach the filter without needing
    a separate registration step. Safe to re-run.
    """
    from winbox.nwfilter import ensure_filter_defined, FILTER_NAME

    console.print(f"[blue][*][/] Registering libvirt nwfilter '{FILTER_NAME}'...")
    try:
        ensure_filter_defined(cfg)
        console.print(f"[green][+][/] nwfilter '{FILTER_NAME}' registered")
    except RuntimeError as e:
        console.print(f"[yellow][!][/] Could not register nwfilter: {e}")
        console.print("    `winbox net isolate` will retry on first use.")


def attach_default_filter(cfg: Config) -> None:
    """Attach 'winbox-isolate' to the persistent domain config at setup time.

    The VM is shut down at this point (end of Phase 3), so we pass
    ``live=False, config=True`` — libvirt rejects ``--live`` on a stopped
    domain. On the VM's next boot the filter is active; the Phase 4 snapshot
    captures the already-filtered config so ``winbox restore clean`` stays
    isolated too.

    Idempotent. Failures are a warning, not a hard abort — the user can
    always `winbox net isolate` manually later.
    """
    from winbox.nwfilter import attach_filter, FILTER_NAME

    vm = VM(cfg)
    console.print(f"[blue][*][/] Isolating VM by default (attaching '{FILTER_NAME}')...")
    try:
        changed = attach_filter(vm.name, live=False, config=True)
        if changed:
            console.print("[green][+][/] VM boots isolated by default")
        else:
            console.print("[green][+][/] VM already isolated by default")
        console.print("    Run [bold]winbox net connect[/] when you need internet.")
    except RuntimeError as e:
        console.print(f"[yellow][!][/] Could not attach default filter: {e}")
        console.print("    Use `winbox net isolate` manually after first boot.")
