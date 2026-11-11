"""QMP/HMP control helpers used by the kdbg package.

The debugger safety boundary is strict: this module bootstraps/stops QEMU's
gdbserver and handles non-debugger monitor control, while registers, memory,
halt/resume, and CR3 work go through RSP.  HMP ``x``/``xp`` are never issued
by Winbox's debugger implementation.

A persistent QMP connection is used when libvirt's monitor socket is
accessible.  Virsh remains as a compatibility fallback for installations
where the socket is hidden or its permissions do not allow direct access.
"""

from __future__ import annotations

import logging
import re
import subprocess
from contextlib import contextmanager

from winbox.kdbg.hmp_qmp import (  # noqa: F401 — re-exported
    HmpError,
    _LibvirtConnection,
    _QmpCommandError,
    _QmpConnection,
    _QmpUnavailable,
    _discard_qmp_connection,
    _get_qmp_connection,
    _libvirt_hmp,
)
from winbox.kdbg.hmp_probe import (  # noqa: F401 — re-exported
    gdbstub_has_client,
    probe_port,
)


logger = logging.getLogger(__name__)


@contextmanager
def paused_snapshot(vm_name: str):
    """Compatibility alias for the safe RSP snapshot transaction.

    This name used to issue HMP ``stop``/``cont`` around monitor memory reads.
    Keep callers source-compatible while ensuring the unsafe monitor debugger
    path cannot be reached accidentally.
    """
    from winbox.kdbg.debugger.reader import debug_snapshot_for_vm
    with debug_snapshot_for_vm(vm_name) as snapshot:
        yield snapshot


def snapshot_operation(func):
    """Compatibility alias for the RSP-backed operation decorator."""
    from winbox.kdbg.debugger.reader import snapshot_operation as rsp_operation
    return rsp_operation(func)


def _virsh_hmp(vm_name: str, command: str, timeout: int):
    """Run the compatibility transport and preserve its CompletedProcess API."""
    try:
        return subprocess.run(
            [
                "virsh", "-c", "qemu:///system",
                "qemu-monitor-command", vm_name,
                "--hmp", command,
            ],
            capture_output=True, text=True, check=False, timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise HmpError(f"HMP {command!r} timed out after {timeout}s") from exc


def hmp(
    vm_name: str,
    command: str,
    *,
    timeout: int = 15,
    mode: str = "raise",
):
    """Send HMP over persistent QMP, falling back to ``virsh`` if unavailable.

    Two return shapes:
      * ``mode='raise'`` (default) -- returns stdout (str). Non-zero exit
        raises :class:`HmpError` with stderr or stdout in the message.
      * ``mode='tuple'`` -- returns ``(rc, stdout.strip(), stderr.strip())``
        and never raises on a non-zero exit. Use this when the caller
        wants to render virsh's own error text directly (e.g. the
        ``kdbg start/stop`` CLI commands and the matching MCP tools).

    Both old in-tree wrappers (``cli/kdbg._hmp`` and ``mcp._kdbg_hmp``)
    routed through this — keep them out of new code.
    """
    if mode not in ("raise", "tuple"):
        raise ValueError(f"hmp(mode={mode!r}): expected 'raise' or 'tuple'")

    try:
        connection = _get_qmp_connection(vm_name, timeout)
        try:
            stdout = connection.hmp(command, timeout)
        except _QmpUnavailable:
            _discard_qmp_connection(vm_name, connection)
            raise
    except _QmpCommandError as exc:
        if mode == "tuple":
            return 1, "", str(exc).strip()
        raise HmpError(f"HMP {command!r} failed: {exc}") from exc
    except _QmpUnavailable as direct_exc:
        try:
            stdout = _libvirt_hmp(vm_name, command)
        except _QmpUnavailable as libvirt_exc:
            logger.warning(
                "persistent QMP unavailable for %s; using virsh: direct=%s; libvirt=%s",
                vm_name, direct_exc, libvirt_exc,
            )
            result = _virsh_hmp(vm_name, command, timeout)
        else:
            if mode == "tuple":
                return 0, stdout.strip(), ""
            return stdout
    else:
        if mode == "tuple":
            return 0, stdout.strip(), ""
        return stdout

    if mode == "tuple":
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    if result.returncode != 0:
        raise HmpError(
            f"HMP {command!r} failed: {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout


_REG_RE = re.compile(r"([A-Z][A-Z0-9_]*)\s*=\s*([0-9a-fA-F]+)")
_TABLE_RE = re.compile(
    r"^(IDT|GDT)\s*=\s*([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s*$",
    re.MULTILINE,
)


def parse_registers(info_registers_out: str) -> dict[str, int]:
    """Parse the `info registers` text into {name: int}.

    QEMU prints RAX/RIP/CR3/... in ``REG=HEX`` pairs, sometimes several
    per line. We accept any ``NAME=HEX`` token and let callers ask for
    what they want. Note: LSTAR is intentionally NOT in this output on
    modern QEMU builds — callers who need the syscall dispatcher resolve
    it via the IDT instead (see ``parse_idt``).
    """
    out: dict[str, int] = {}
    for match in _REG_RE.finditer(info_registers_out):
        name = match.group(1)
        try:
            out[name] = int(match.group(2), 16)
        except ValueError:
            continue
    return out


def parse_idt(info_registers_out: str) -> tuple[int, int]:
    """Pull (base, limit) for the IDT out of the `info registers` dump."""
    for match in _TABLE_RE.finditer(info_registers_out):
        if match.group(1) == "IDT":
            return int(match.group(2), 16), int(match.group(3), 16)
    raise HmpError("IDT entry not found in `info registers` output")


def read_cpu_state(vm_name: str) -> dict[str, int]:
    """Convenience wrapper: return a merged dict of registers + IDT base.

    Adds a synthetic ``IDT_BASE`` key alongside the normal register names.
    """
    text = hmp(vm_name, "info registers")
    regs = parse_registers(text)
    idt_base, _ = parse_idt(text)
    regs["IDT_BASE"] = idt_base
    return regs


def ensure_not_paused(vm_name: str, port: int = 1234) -> str | None:
    """Resume ``vm_name`` if a debug session left it paused.

    Detaching is supposed to resume the VM, but that only happens if the
    daemon shuts down cleanly — when it doesn't, the gdbstub keeps the CPU
    stopped and the VM is left in ``paused`` with no indication beyond a
    warning. Every later winbox command then hangs or reports the VM as
    down. Called at the end of the detach paths as a safety net.

    Returns a short description of what it did, or ``None`` if the VM was
    already running (the overwhelmingly common case). Never raises: this
    runs during teardown, where masking the original problem would be worse
    than failing to tidy up.
    """
    try:
        state = subprocess.run(
            ["virsh", "-c", "qemu:///system", "domstate", vm_name],
            capture_output=True, text=True, check=False,
        )
        if state.stdout.strip() != "paused":
            return None

        if probe_port("127.0.0.1", port):
            try:
                from winbox.kdbg.debugger import RspClient

                client = RspClient.connect("127.0.0.1", port, timeout=5)
                try:
                    client.handshake()
                    client.cont()
                finally:
                    client.close()
                return "VM was left paused by the debug session; resumed via gdbstub"
            except Exception:
                pass

        resumed = subprocess.run(
            ["virsh", "-c", "qemu:///system", "resume", vm_name],
            capture_output=True, text=True, check=False,
        )
        if resumed.returncode == 0:
            return "VM was left paused by the debug session; resumed via virsh"
        return (
            "VM is left PAUSED and could not be resumed automatically — "
            f"run `virsh -c qemu:///system resume {vm_name}`"
        )
    except Exception:
        return None
