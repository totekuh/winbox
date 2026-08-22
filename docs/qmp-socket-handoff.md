# Item 48: QMP Socket — Handoff

## Problem

Every HMP call in `hmp.py` forks a virsh subprocess:

```
Python → subprocess.run(["virsh"]) → libvirtd → QEMU QMP → read → unwind all the way back
```

~5-10ms per call. Process walk does ~400-500 of these. Total: 2-5 seconds.

## Fix

Open a persistent Unix socket to QEMU's QMP monitor directly. Skip virsh
and libvirtd entirely.

```
Python → Unix socket → QEMU QMP → read → JSON response back on same socket
```

~0.1-0.5ms per call. Same walk: 40-250ms. 10-20x faster.

## What changes

Only `src/winbox/kdbg/hmp.py`. One file.

### Current

```python
result = subprocess.run(
    ["virsh", "-c", "qemu:///system",
     "qemu-monitor-command", vm_name,
     "--hmp", command],
    capture_output=True, text=True, check=False, timeout=timeout,
)
```

### Target

```python
# Persistent socket, opened once, reused across calls
sock.send(json.dumps({
    "execute": "human-monitor-command",
    "arguments": {"command-line": command}
}).encode() + b"\n")
response = json.loads(sock.recv(65536))
return response["return"]
```

## QMP socket location

```bash
virsh qemu-monitor-command win11 --hmp "info version"   # proves HMP works
virsh dominfo win11                                      # get domain ID

# Socket path pattern:
# /var/run/libvirt/qemu/domain-<id>-<name>/monitor.sock
# or query libvirt for the exact path
```

## QMP protocol

1. Connect to Unix socket
2. Read server greeting: `{"QMP": {"version": ..., "capabilities": [...]}}`
3. Send capabilities negotiation: `{"execute": "qmp_capabilities"}`
4. Read `{"return": {}}`
5. Now send commands:
   - `{"execute": "human-monitor-command", "arguments": {"command-line": "xp /8bx 0x1234"}}`
   - Response: `{"return": "0000000000001234: 0x48 0x89 0x5c 0x24 ..."}`
6. Same hex text `parse_hex_dump()` already handles — no parser changes

## Socket lifecycle

- Open on first `hmp()` call for a given `vm_name`
- Cache per vm_name (module-level dict or similar)
- Reconnect on `BrokenPipeError` / `ConnectionResetError` (VM reboot)
- Close on process exit (atexit or __del__)

## What stays the same

- `hmp()` function signature: `hmp(vm_name, command, *, timeout, mode)`
- Return type: same string
- `parse_hex_dump()`: untouched, same input format
- All callers (`memory.py`, `walk.py`, `store.py`, `daemon.py`): untouched
- `mode="tuple"` return shape: same `(rc, stdout, stderr)` — map QMP errors accordingly
- `HmpError` on failure: same

## Fallback

If QMP socket not found or connection fails, fall back to virsh subprocess.
Log a warning so it's visible, not silent degradation.

## Edge cases

- VM reboot: socket drops, reconnect on next call
- VM not running: same error path as today (virsh fails → HmpError)
- Multiple VMs: one cached socket per vm_name
- Concurrent calls: QMP is not multiplexed — serialize with a lock per socket
- `mode="tuple"` callers expect `(rc, stdout, stderr)`: QMP errors don't have
  rc/stderr — synthesize rc=1 and put the error in stderr position

## Test

```bash
# Before: time a process walk
time python -c "from winbox.kdbg.walk import list_processes; ..."

# After: same call, should be 10-20x faster
```

## Files to read before starting

- `src/winbox/kdbg/hmp.py` — the only file that changes (~70 lines today)
- `src/winbox/kdbg/memory.py` — biggest caller, verify nothing assumes subprocess semantics
- `src/winbox/kdbg/walk.py` — process/module walker, verify no direct subprocess use

## Implemented debugger boundary

Live stress testing isolated a QEMU/KVM state-corruption bug in debugger
stop/resume. Under Windows process churn, repeated RSP interrupt/continue cycles
with no memory reads, register writes, or page walks were sufficient to lose
`IA32_PL3_SSP` while Windows still considered CET user shadow stacks active.
The next kernel `WRUSSQ` then bugchecked at address `0xfffffffffffffff8`.
Neither switching the reads from HMP to RSP nor pausing around HMP reads fixed
the underlying hypervisor state bug.

The final transport split is therefore:

- Persistent QMP Unix socket: bootstrap/stop the gdbserver and non-debugger VM
  control only.
- Persistent GDB RSP broker: halt/resume, register access, CR3 masquerade,
  virtual/physical memory, process/module walks, and kernel-base discovery.

Before either the broker or interactive daemon opens GDB, winbox queries the
effective user-shadow-stack policy of every process through
`GetProcessMitigationPolicy(PROCESS_QUERY_LIMITED_INFORMATION)`. It requires
the system default to be OFF, zero active processes, and zero still-live
unqueryable processes. System OFF alone is not enough: Windows binaries can
opt in, which live validation observed in 34 processes.

`winbox kdbg prepare --confirm` (or MCP `kdbg_prepare(confirm=true)`) saves the
original raw mitigation registry values and exact libvirt CPU XML on the host,
sets the Windows default OFF, and persistently hides the VM's `cet-ss` CPU
feature; the VM must then reboot. `restore-cet`/`kdbg_restore_cet` restores both
layers exactly. This explicit safety gate is required because disabling CET is
the only configuration that survived the stop/resume stress test on the
affected stack.

The broker owns QEMU's single GDB client across CLI and MCP processes. One
Unix client connection represents one coherent read transaction. It saves the
selected vCPU's complete register block, may keep one requested CR3 installed
across related reads, restores the exact original block in cleanup, and only
then resumes. A failed restore poisons the broker and leaves the VM halted.
Client disconnects restore/resume in `finally`; a VM reboot drops the broker so
the next operation reconnects cleanly.
