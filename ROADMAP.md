# winbox — known issues and roadmap

Everything currently known to be wrong, ranked. Each entry says what breaks,
how it was found, and what fixing it involves. Items are removed when fixed,
not ticked — `git log` is the record of what was done.

Ordering is risk × tractability, not severity alone: an unreproducible crash
outranks a typo on severity but cannot be worked on, and there is no value in
a roadmap whose top item nobody can start.

---

## Open

Items 1-8 have all been worked — `git log` is the record. Item 8 is addressed
at its source (below) but stays listed as *Watching* because it is
intermittent by nature.
at its source (below) but stays listed as *Watching* because it is intermittent
by nature.

One finding from the breakpoint work is worth keeping, because it shapes any
future kdbg change: **neither breakpoint mechanism installs on both images.**
Windows 11 runs HVCI by default, which exists precisely to stop the `0xCC`
patch a software breakpoint writes into a kernel code page, so `--mode soft`
cannot work there. Server 2022 has instead been seen exhausting the four
per-vCPU DR0..3 slots, which is the hardware path's ceiling. `--mode auto`
tries hardware first and falls back, so it works on both, and the failure
messages now name the wall you actually hit instead of guessing at one.

Items 10-19 below all came out of one audit pass over `src/winbox/kdbg` and
the MCP `kdbg_*` wiring (2026-08-10), not from a specific repro. They're
ordered by risk × tractability: silent-wrong-result bugs with a known fix
shape first, pure capability gaps and cross-cutting rewrites last.

Items 9, 10, 20, 21, 22, 23 were fixed on 2026-08-19/20 — `git log` is the
record. Item 21 (bp_remove E22) was addressed by storing `installed_cr3` in
the Breakpoint. Items 28-34 below came from the same live debugging session
that verified those fixes.

**28. Fixed.** `fork_daemon` now retries up to 3 times on "empty stop reply":
raw-closes the socket, restarts the gdbstub via HMP, reconnects. After all
attempts exhausted, raises a clear error naming the recovery. Supersedes old
item 12. Verified live — first attach reliably hits the bug and auto-recovers
on attempt 2.

**29. Fixed.** PID-not-found path now uses `rsp.cont()` + `time.sleep(0.1)` +
`rsp._sock.close()` (raw close, no D-packet dance) — same safe pattern as
`DaemonSession.shutdown()`. The old `rsp.close()` did interrupt+wait+D which
halted-resumed-halted the VM and corrupted the virtio-serial GA channel.
After resuming, checks `agent_channel_connected()` and appends a warning if
the channel dropped. Verified live — GA survives the failed attach.

**30. Fixed (two parts).** Part A: one-time hw bp verification probe on first
hw bp install. Installs a temp hw bp on `nt!KiPageFault` (or
`nt!KeQueryPerformanceCounter`), does a 300ms cont, checks for SIGTRAP. If
the probe times out, returns `hw_probe_warning` in the response. Runs once
per session. Part B: `op_cont` now includes `unfired_hw_bps` in its response
listing all hw bps with `hits==0` after a cont that ran longer than 5
seconds. Verified live — probe fires immediately, unfired warning appears
correctly when bp fires in non-target CR3.

**31. Fixed.** `list_processes` now switches to System's DTB (PID 4's
`DirectoryTableBase`) after reading the first EPROCESS, eliminating mid-walk
KPTI CR3 races on a running VM. `list_modules` also gained the initial KPTI
retry. Verified live — 60 processes returned consistently on a running VM.

### 21. `bp_remove` on a private user-mode soft breakpoint can fail with E22 while the breakpoint is still live

Removing a soft breakpoint just installed via `kdbg_bp(mode="soft")` on a
private (non-shared) user VA (`ntdll!NtClose` in a freshly attached process)
returned `RuntimeError: z0 failed: z0 remove at <va> failed: b'E22'; bp
still tracked, retry bp_remove`. CR3 state afterward was clean (no
`_cr3_corrupted`), so the restore-safety invariant this file is built around
held — but the byte itself was correctly restored by the time the session
was torn down via `kdbg_detach` (confirmed with `kdbg_read_va`), which
didn't go through the same `bp_remove` path that failed. Likely cause, not
yet confirmed: `bp_remove`'s `z0` send may not re-apply the same
CR3-masquerade `bp_add`'s install path uses, translating the VA through
whichever CR3 happens to be active rather than the target's. Needs a repro
against the actual code path before fixing — this is one live observation,
not a bisected cause.

### 22. Background jobs have no result-identity protection against PID recycling

`exec()` (nonce) and `exec_argv()` (look-behind) both verify that a
guest-exec result actually belongs to the command that asked for it — the
guard against qemu-ga handing back an abandoned result parked on a recycled
Windows PID. Background jobs skip that entirely: `run_command_bg` →
`exec_background`/`exec_detached` return a raw PID, and `JobStore` later
polls `exec_status(pid)` with no nonce and no look-behind, so a buffered job
whose short-lived PID gets recycled can read a foreign result. `--log` mode
sidesteps it (output is redirected to files on VirtIO-FS, not the agent's
buffered slot); the buffered (`JobMode.BUFFERED`) path is the exposure. The
guest-layer launch retry added on 2026-08-10 (`_start_guest_exec`) covers
these paths' *launch* but not their *result identity* — a real fix needs a
job-scoped nonce echoed at spawn and checked at status-read, which is a
bigger change than the foreground path took. Not yet reproduced;
audit-derived from the same PID-recycle mechanism `git log` already fixed for
the foreground path.

The same raw-PID weakness has a second consequence on the *write* side:
`winbox jobs kill <id>` runs `taskkill /PID <job.pid> /T /F`, so a job that
finished and had its PID recycled onto an unrelated guest process gets that
innocent process's whole tree force-killed. Both consequences (wrong output
read, wrong process killed) are the same missing-identity-token root and want
the same fix.

### 23. The named-pipe broker is killed by raw PID with no ownership check — recycle → collateral kill

`pipe_open`'s `_abort` and `pipe_close` run `taskkill /F /PID <broker_pid>`
against the stored broker PID with no verification that the PID still belongs
to the broker. A broker that crashes right after spawn and has its Windows PID
recycled onto an unrelated process gets that process force-killed instead. This
is the pipe-subsystem twin of item 22's kill side (same PID-recycle root). The
broker now self-writes its `broker.pid` at startup (2026-08-10), which fixed
the *unkillable-leak* half — the host can always find the PID — but not this
*wrong-PID-kill* half, which needs an identity token (e.g. verify the target is
the `python.exe` we launched, or tag the broker and check the tag before
killing). PLAUSIBLE, audit-derived, not reproduced.

### 24. `pipe_recv` can silently lose bytes when the host times out after the broker already read them

The broker's `do_read` peeks then `ReadFile`s N bytes off the real pipe and
writes `result.<seq>.json`. If the host-side `_poll_result` deadline passes in
the window before that file is read (VirtIO-FS write latency under load),
`pipe_recv` returns "timeout waiting for read result" — but the bytes are
already gone from the pipe, the result file is orphaned (the no-sweep policy
leaves it, by design, so a concurrent in-flight call's live result isn't
deleted), and the next `pipe_recv` uses a fresh seq. The dequeued bytes are
lost for good and any length-prefixed stream parse desyncs. The broker gets a
budget `timeout - 1s` shorter than the host to make this rare, but it is not
eliminated. A real fix needs a two-phase read (peek-and-hold until the host
ACKs) or a bounded sweep that reclaims a still-unread result for the *same*
logical read before issuing the next — a broker-protocol change. CONFIRMED,
audit-derived.

### 25. `JobStore.claim` spawns the guest process before it persists the Job

`claim()` runs `build(job_id)` — which launches the VM-side process via
`exec_background`/`exec_detached` — and only then calls `_save()`. If `_save()`
raises (disk full, tmpfile/rename error), the process is already running but
has no ledger entry, so `winbox jobs list`/`kill` never see it and it holds its
exec slot / log handles until the VM reboots. Low-probability (needs a disk-
level `_save` failure). The clean fix is persist-placeholder → spawn → update,
which also removes the deliberately-accepted flock-held-across-spawn window
(documented in `claim`'s docstring — a `jobs list` blocks for the spawn
duration), but it restructures the `claim(build)` API and the `run_command_bg`
caller, so it is logged rather than rushed. CONFIRMED, audit-derived.

### 27. Offline Defender disable hardcodes ControlSet001 instead of resolving the active control set

`defender._system_services_reg` writes `Services\*\Start` under a literal
`HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001`. On a freshly-installed guest the
current control set *is* 001, but if `HKLM\SYSTEM\Select\Current` is 2 (e.g.
after a Last-Known-Good rollback), the offline edit lands in an inactive
control set while the operation prints its green success line, and Windows
boots from ControlSet002 with Defender fully armed — the user believes it is
off while it quarantines winbox's tools. The correct fix reads `Select\Current`
out of the SYSTEM hive first (an extra guestfish/hivex read before rendering
the `.reg`) and targets `ControlSet00<N>`. Deferred because it needs hive
introspection the current render-static-`.reg` path doesn't do, and the common
fresh-VM case (ControlSet001) works. PLAUSIBLE, audit-derived (2026-08-10).

### 26. kdbg read-surface residuals from the 2026-08-10 audit (accepted / minor)

Three findings from the read-surface audit were left as-is, deliberately:

* **`probe_port` treats every IPv6/unparsed listener as matching any host**
  (`hmp.py`). `_listening_sockets` records tcp6 LISTEN sockets as `(None,
  port)` and `probe_port` matches `None` against any host — a *deliberate*
  false-positive-over-false-negative choice (documented in the function's
  docstring) so a v6-wildcard gdbstub isn't read as absent. The cost is that an
  unrelated tcp6 listener on the same port reads as "stub up", and
  `ensure_not_paused` may connect to a foreign socket. A proper fix decodes the
  v6 address and does host-family-aware matching; until then the trade-off
  stands.
* **`DirectoryTableBase` is recorded with no sanity check** (`walk.py`) while
  the adjacent `UserDirectoryTableBase` gets a page-aligned/`<2^52` guard. This
  is the same class as item 18 (offset assumptions with no runtime check).
  Unlike `user_dtb`, the primary `dtb` has no safe fallback (0 is useless), and
  a wrong `DirectoryTableBase` offset breaks the whole store loudly elsewhere,
  so a targeted guard here is low-value — folded into item 18.
* **`find_process` materializes the whole process table for a single lookup**
  (`walk.py`). A lazy generator that stops at the first match would save the
  per-EPROCESS reads after the target. Minor perf; the per-walk cost dropped
  sharply once `SymbolStore.load` was memoized (2026-08-10), so this is a low
  priority.

### 10. Conditional breakpoints fail closed and indistinguishably from a real null

`_mem_qword_reader` (`daemon.py:883-941`) returns `0` both when a VA is
genuinely unmapped and when the RSP read itself fails (session flakiness). A
predicate like `[rcx+0x10] != 0` can silently never fire for the wrong
reason, with nothing telling the operator the condition — not the target —
is why nothing happened. This is a documented tradeoff, not an oversight,
but it's indistinguishable from "the bug just didn't repro." Fix: propagate
a distinct sentinel/exception for read failure vs. unmapped VA through
predicate evaluation instead of coercing both to 0.

### 11. `pdb.py` silently drops structs its regex parser can't match

`parse_types` swallows any struct it fails to fully match (`missing = ...;
pass`); `parse_publics` raises on the equivalent failure. An `llvm-pdbutil`
output-format drift would silently degrade struct data, surfacing later as
an unrelated-looking error ("field not found") several calls downstream in
a walker, far from the real cause. Fix: make `parse_types` raise (or at
least warn loudly) the same way `parse_publics` does.

### 12. WoW64 module list is silently incomplete

`list_user_modules` (`walk.py:294-315`) doesn't walk `PEB.Wow64Process`'s
32-bit loader. Against a 32-bit-on-64-bit process, `kdbg_user_lm` /
`kdbg_user_symbols_load` quietly return only the 64-bit `ntdll`/`wow64.dll`
and none of the process's real 32-bit DLLs, with no flag that the result is
partial. Minimum fix: detect WoW64 and return a warning in the result even
before implementing the 32-bit walk; full fix adds the `Wow64Process` walk.

### 13. Two RSP clients, one dead but indistinguishable from live

`gdbstub.py`'s `GdbStubClient` raises `NotImplementedError` on
`read_registers`/`single_step`/`cont`/`set_hw_breakpoint`, and nothing in
`mcp.py` or `cli/kdbg.py` calls it — `debugger/rsp.py`'s `RspClient` is the
real, working implementation and reimplements the same RSP framing
independently. `gdbstub.py` still has its own passing test suite
(`test_kdbg_gdbstub.py`), so it reads as live code to anyone searching the
repo. Fix: delete `gdbstub.py` and its tests, or fold anything still useful
into `rsp.py`, so there's one RSP client, not two.

### 14. No watchpoints

`RspClient.insert_breakpoint`/`remove_breakpoint` (`rsp.py:529-554`) only
ever send `Z0`/`Z1` (software/hardware execution breakpoint). QEMU's
gdbstub supports `Z2`/`Z3`/`Z4` (write/read/access watchpoints) but nothing
here emits them — no equivalent of WinDbg's `ba`, no way to break on a
struct-field write, which matters for the hooking/instrumentation research
this tool targets. Fix: extend the existing `Z0`/`Z1` path to accept
watchpoint types and thread them through the `kdbg_bp` MCP surface.

### 15. `kdbg_bt` is a stack-scan heuristic, not a real unwinder

`op_bt` (`daemon.py:806-833`) walks RSP-relative stack qwords and treats
anything that looks like a canonical code address as a return address
(`_looks_like_code_va`). There's no `.pdata`/`RUNTIME_FUNCTION` parsing
anywhere in the codebase, and x64 Windows release binaries are
frame-pointer-omitted almost everywhere non-leaf — so against real targets
(AV/EDR components, optimized code) this backtrace will systematically drop
or fabricate frames. Already flagged as best-effort in the function's own
docstring. Largest capability gap versus a WinDbg-class debugger, and the
least tractable item here — a real fix means parsing `.pdata` and doing
table-based unwind, not a local patch.

### 16. No step-over/step-out

`kdbg_step`/`op_step` only single-instruction trace-into. Stepping over a
`call` (to avoid diving into a syscall stub or a hot loop) currently
requires disassembling by hand, computing the return address, and planting
a temporary breakpoint manually. Fix: add a step-over mode that disassembles
the current instruction and, if it's a `call`, plants a temp breakpoint at
the next instruction and continues instead of stepping in.

### 17. SMP is tuned for `-smp 1`, not a first-class case

`_last_selected_vcpu` caching and the `sr.thread or "01"` default throughout
`daemon.py` assume a single vCPU. `list_threads`/`select_thread` exist, but
nothing scopes a breakpoint's fire-tracking to a specific core or
distributes hardware breakpoints per-vCPU. Low tractability relative to
impact — this is cross-cutting, not a local patch — hence listed near last.

### 18. Hardcoded register/CR3 offsets have no runtime sanity check

`RspClient._CR3_OFFSET = 204` and the g-packet field offsets in
`_decode_regs` are hardcoded, "verified against QEMU 8.x/9.x," with no
cross-check at runtime — unlike `resolve_nt_base`, which sanity-checks its
result (page-aligned, canonical). A future QEMU register-XML change would
misdecode CR3/RIP silently instead of erroring. Fix: add the same kind of
plausibility check `resolve_nt_base` already does, and raise instead of
proceeding on a value that fails it.

### 19. `kdbg_attach` doesn't detect a concurrent interactive `gdb` session

QEMU's gdbstub accepts only one client. `gdbstub.py`'s own docstring flags
the risk of a human `gdb` already attached to the same port, but
`kdbg_attach` doesn't check for or warn about it. Fix: probe the port or
track attach state before forking the daemon, and fail with a clear message
if something's already attached.
### Edge cases to harden (2026-08-20)

These are not bugs — they're untested edge cases that could surface real bugs.
Each needs a live test and, where it breaks, a fix.

**32. Tested 2026-08-21 — PASS.** Double attach refused cleanly: "VM is halted
by a kdbg debug session." Existing session unaffected.

**33. Tested 2026-08-21 — PASS.** `kdbg_interrupt` during blocked `kdbg_cont`
queues correctly, detach works, GA survives, VM resumes. Note: interrupt may
race with cont timeout (observed `reason: timeout` instead of `reason:
interrupt` when both expire at the same wall-clock moment — not a bug, timing).

**34. Tested 2026-08-21 — PASS.** 5th hw breakpoint fails with clear error
naming DR slot limit. Existing 4 unaffected and tracked correctly.

**35. Attach to a process that exits mid-session** — NOT YET TESTED. Target
exits while breakpoints are set. Cont should time out (target gone), detach
should clean up without crash.

**36. Tested 2026-08-21 — PASS.** `kdbg_bp nt!FakeFunction` fails with "symbol
not found" before any gdbstub operation.

**37. Tested 2026-08-21 — PASS.** `kdbg_mem 0xdeadbeefdeadbeef` returns clean
`RspError: m failed` error. Session state intact.

**38. Tested 2026-08-21 — PASS.** 5 consecutive attach/detach cycles on same
process. GA survived all cycles.

### Findings from 2026-08-21 live testing session

**39. PID mismatch between GA `ps` and kernel process walker.** GA-based `ps`
reports different PIDs than `kdbg_ps` (kernel EPROCESS walk via HMP). Observed
with lsass.exe: GA reported PID 860, kernel walk reported PID 856. Also seen
with svchost.exe (GA: 1808, not in kernel walk at all). Root cause is likely
item 31 (KPTI walker truncation on running VM) — `kdbg_ps` runs on a running
VM and the user-mode CR3 doesn't map all kernel structures. The `kdbg_attach`
daemon walks after halting the VM (stable CR3), so it sees the true PIDs. The
GA `ps` uses `Get-Process` inside the guest, which sees the true PIDs too.
The mismatch means `kdbg_attach` with a PID from GA `ps` can fail with
"pid not found." Workaround: use PIDs from `kdbg_ps` for `kdbg_attach`.
Fix: same as item 31 — now fixed (walker uses System DTB).

**40. Fixed.** Probe timeout increased from 300ms to 1s, added
`nt!KeQueryInterruptTimePrecise` (fires on every timer interrupt) as first
probe symbol. Verified live — no false positive on fresh-booted VM.

**41. `kdbg_cont` is a blocking MCP operation.** The cont tool blocks for up
to `timeout` seconds. The daemon internally services `interrupt` and `status`
ops via `_pump_client`, but the MCP client is stuck waiting. A non-blocking
design — cont returns immediately, `kdbg_status` polls for bp hits — would
let the operator do other work (read memory, check state) while waiting for a
rare breakpoint. This is a design gap, not a bug, and would require changes to
the daemon protocol, MCP handler, and the `_wait_for_stop_serving` loop.

### Debugger (kdbg) gaps — collected from a live MsMpEng RPC session

Found while single-stepping a user-mode RPC call inside `MsMpEng.exe`. Ranked
risk × tractability. The fire-and-forget gap that surfaced in the same session
(synchronous `python`/`powershell` blocking and throwing "domain is not
running" the moment a triggered call halts the guest) is **already closed** —
`exec`/`python`/`powershell` now take `background=True` and return a job handle,
retrieved with `job_result`. The rest below are open.

**9. Fixed.** `kdbg_cont` timeout now captures the interrupt's stop reply via
`_capture_stop(sr)`. Initial attach also captures halt state from
`query_halt_reason()`. `halted` is now trustworthy. See commit `a2373bc`.

**10. Fixed.** `kdbg_stack` returns `{offset, va, value}` per qword.
`kdbg_mem` gained `decode='qwords'`. See commit `9009a49`.

**11. Fixed.** `mode='auto'` now returns `downgrade_warning` in the response
when falling back from hw to soft, explaining the reason and noting that
software breakpoints are PatchGuard-visible and hash-detectable.

**12. Fixed.** Superseded by item 28 — `fork_daemon` now auto-retries with
gdbstub restart via HMP.

**13. Fixed (two parts).** Dead `gdbstub.py` + tests deleted — it was an
unused RSP client with `NotImplementedError` stubs alongside the real
`rsp.py`. `kdbg_detach` test now mocks `ensure_not_paused` so it no longer
touches the real VM.

*Workflow note (not a tool defect):* prefer live `kdbg_disasm` against the
running process over tracking a module's ASLR base and cross-referencing a
static off-VM copy with `objdump`. The live path is faster and removes any
"is this the right build" doubt. `kdbg_disasm` and `kdbg_user_symbols_load`
already exist and went unused.

---

## Watching

### 8. The guest agent drops shortly after a reboot — addressed, watched

The shape: a command runs fine, and the *next* one — a few seconds later,
after a reboot earlier in the sequence — gets
`Guest agent is not responding: QEMU guest agent is not connected`. Seen
several times, usually the command right after a reboot (e.g. `autologin
status` after the AppLocker test's reboot). The channel comes up, answers
once, and drops again before it settles.

**Fixed at the source.** Readiness now reads libvirt's channel-state
attribute (`agent_channel_connected` in `vm/lifecycle.py`, consulted by
`GuestAgent.ping()`), and `reboot_and_wait` waits for several consecutive
channel-up reads rather than the first answered ping. libvirt is the
authority on channel state — the exact thing that flaps — so the gate reads
the drop directly instead of inferring it from a failed round-trip.

**Still Watching, not Closed**, because it is intermittent: a clean run does
not prove absence. The channel-state gate closes the window it was measured
in, but a sufficiently slow settle could still slip past a bounded wait.

**Do not "fix" the residue with a blanket retry.** Retrying a command that may
already have run in the guest is exactly what item 1's typed exceptions exist
to prevent. If more is needed, the only safe retry is a bounded one on
`GuestAgentUnreachable` for *read-only* operations — a deliberate decision,
not a reflex.

**If it recurs:** note what ran immediately before, whether a reboot happened
within the previous minute, and whether `vm.agent_connected()` reads
connected at that moment.

---

## Environment notes

* `/tmp` is a 16 GB tmpfs. Tests that write ISO-sized files fill it —
  `tests/test_iso.py` shrinks the profile floor to 4 KB for this reason.
* **Fixed at the source.** `pyproject.toml`'s `mcp` extra was unbounded
  (`mcp>=1.0`), so a plain reinstall could silently resolve to `mcp` 2.0.0,
  which dropped `mcp.server.fastmcp` — the import `winbox.mcp` relies on —
  and broke every `mcp`-dependent test with no warning until import time.
  Now pinned `mcp>=1.0,<2`. If a test run still fabricates `mcp`-import
  errors, the environment's Python has a stale/wrong `mcp` install outside
  this constraint (e.g. a system-wide `pip install mcp` from before this fix)
  — reinstall it (`pip install 'mcp>=1.0,<2'`) rather than chasing the
  symptom per-test.
