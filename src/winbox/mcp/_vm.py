"""VM lifecycle and IOCTL tools."""

from __future__ import annotations

import json as _json
import textwrap

from winbox.mcp import mcp
from winbox.mcp import _common as _mcp_common
from winbox.mcp._common import (

    _format_exec_result,
    _get_state,

)
from winbox.vm import GuestAgentError, VMState


@mcp.tool()
def vm_up() -> str:
    """Start the VM (or confirm it is already running).

    Boots the VM from SHUTOFF/SAVED or resumes from PAUSED state, then
    waits for the guest agent to respond.  Returns the VM IP on success.
    """
    cfg, vm, ga = _get_state()
    state = vm.state()

    if state == VMState.RUNNING:
        ip = vm.ip()
        return f"VM is already running{f' — IP: {ip}' if ip else ''}"
    if state == VMState.NOT_FOUND:
        raise RuntimeError("VM not found. Run 'winbox setup' first.")
    if state == VMState.PAUSED:
        vm.resume()
    else:
        vm.start()

    try:
        ga.wait(timeout=120)
    except GuestAgentError:
        return (
            "VM started but guest agent did not respond within 120s. "
            f"Check with: virsh console {cfg.vm_name}"
        )

    ip = vm.ip()
    return f"VM started{f' — IP: {ip}' if ip else ''}"


@mcp.tool()
def vm_down(force: bool = False) -> str:
    """Shut down the VM.

    Graceful shutdown by default (ACPI signal, waits up to 60s).  Pass
    ``force=True`` for an immediate power-off (virsh destroy).

    Args:
        force: Hard power-off instead of graceful shutdown.
    """
    cfg, vm, ga = _get_state()
    state = vm.state()

    if state in (VMState.SHUTOFF, VMState.NOT_FOUND):
        return f"VM is not running (state: {state.value})"

    if force:
        vm.force_stop()
        return "VM powered off (forced)"

    if state == VMState.PAUSED:
        return "VM is paused — use force=True to power off, or resume first"

    if ga.ping():
        try:
            ga.exec("shutdown /s /t 0", timeout=10)
        except GuestAgentError:
            pass
    else:
        vm.shutdown()

    import time as _time
    for _ in range(60):
        if vm.state() in (VMState.SHUTOFF, VMState.NOT_FOUND):
            return "VM shut down"
        _time.sleep(1)

    vm.force_stop()
    return "Graceful shutdown timed out — forced power-off"


@mcp.tool()
def vm_status() -> str:
    """Report VM state, IP, agent health, disk, tools, and snapshots.

    Returns a JSON object with the current status.  Works whether the VM
    is running or off.
    """
    cfg, vm, ga = _get_state()
    state = vm.state()
    running = state == VMState.RUNNING

    ip = None
    agent_ok = False
    if running:
        ip = vm.ip()
        agent_ok = ga.ping()

    disk_mb = None
    try:
        raw = vm.disk_usage()
        if raw is not None:
            disk_mb = round(raw / (1024 * 1024))
    except OSError:
        pass

    tools_count = 0
    loot_count = 0
    try:
        tools_dir = cfg.shared_dir / "tools"
        if tools_dir.is_dir():
            tools_count = sum(1 for _ in tools_dir.iterdir())
    except OSError:
        pass
    try:
        loot_dir = cfg.shared_dir / "loot"
        if loot_dir.is_dir():
            loot_count = sum(1 for _ in loot_dir.iterdir())
    except OSError:
        pass

    snaps = []
    try:
        snaps = vm.snapshot_list()
    except Exception:
        pass

    return _json.dumps({
        "vm_name": cfg.vm_name,
        "os": cfg.vm_os,
        "state": state.value,
        "ip": ip,
        "agent": agent_ok,
        "disk_mb": disk_mb,
        "tools": tools_count,
        "loot": loot_count,
        "snapshots": snaps,
    })


@mcp.tool()
def ioctl(
    device: str,
    code: int,
    input_hex: str = "",
    output_size: int = 0,
    timeout: int = 30,
) -> str:
    """Send an IOCTL to a Windows device driver.

    Opens the device with CreateFileW, sends DeviceIoControl with the given
    control code and input buffer, returns the output buffer as hex.

    Args:
        device: Device path, e.g. '\\\\.\\C:' or '\\\\.\\PhysicalDrive0'.
        code: IOCTL control code (integer, e.g. 0x222000).
        input_hex: Input buffer as hex string (e.g. 'deadbeef'). Empty for no input.
        output_size: Expected output buffer size in bytes. 0 for no output.
        timeout: Execution timeout in seconds (default 30).
    """
    script = textwrap.dedent("""\
        import ctypes
        from ctypes import wintypes
        import json
        import sys

        args = json.load(open(r'Z:\\.mcp\\args.json'))
        device = args['device']
        ioctl_code = args['code']
        input_hex = args.get('input_hex', '')
        output_size = args.get('output_size', 0)

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        kernel32.DeviceIoControl.restype = wintypes.BOOL
        kernel32.DeviceIoControl.argtypes = [
            wintypes.HANDLE, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
        ]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        FILE_SHARE_READ = 1
        FILE_SHARE_WRITE = 2
        OPEN_EXISTING = 3
        INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

        handle = kernel32.CreateFileW(
            device,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if handle == INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            print(f"CreateFileW failed: error {err}", file=sys.stderr)
            sys.exit(1)

        try:
            in_buf = bytes.fromhex(input_hex) if input_hex else None
            in_size = len(in_buf) if in_buf else 0
            out_buf = ctypes.create_string_buffer(output_size) if output_size > 0 else None
            bytes_returned = wintypes.DWORD(0)

            ok = kernel32.DeviceIoControl(
                handle,
                ioctl_code,
                in_buf, in_size,
                out_buf, output_size,
                ctypes.byref(bytes_returned),
                None,
            )
            if not ok:
                err = ctypes.get_last_error()
                print(f"DeviceIoControl failed: error {err}", file=sys.stderr)
                sys.exit(1)

            returned = bytes_returned.value
            if out_buf and returned > 0:
                print(out_buf.raw[:returned].hex())
            else:
                print(f"ok ({returned} bytes returned)")
        finally:
            kernel32.CloseHandle(handle)
    """)

    result = _mcp_common._exec_python(
        script,
        timeout=timeout,
        args={"device": device, "code": code, "input_hex": input_hex, "output_size": output_size},
    )
    return _format_exec_result(result)
