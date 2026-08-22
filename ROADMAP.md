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
at its source (below) but stays listed as *Watching* because it is intermittent
by nature.

One finding from the breakpoint work is worth keeping, because it shapes any
future kdbg change: **neither breakpoint mechanism installs on both images.**
Windows 11 runs HVCI by default, which exists precisely to stop the `0xCC`
patch a software breakpoint writes into a kernel code page, so `--mode soft`
cannot work there. Server 2022 has instead been seen exhausting the four
per-vCPU DR0..3 slots, which is the hardware path's ceiling. There is no
`--mode auto` — breakpoints must carry their type explicitly. The failure
messages name the wall you actually hit instead of guessing at one.

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

The *kill* side is now guarded: `jobs kill` queries `tasklist` for the PID's
image name before `taskkill`. If the PID is no longer `cmd.exe`/`runex.exe`
(the expected process), kill is refused and the job is marked LOST. The
*result-identity* side (wrong output read) still has no nonce guard — the
full fix needs a job-scoped nonce echoed at spawn and checked at status-read.

**23. Fixed.** `pipe_close` and `_abort` already verify the PID is still
`python.exe` via `_is_broker_alive()` before `taskkill`. If the PID was
recycled to a different process, taskkill is skipped. The guard was added
during the broker self-write fix (2026-08-10) and covers both `_abort`
and `pipe_close` paths.

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

**25. Fixed.** `claim()` now persists a placeholder Job (pid=0,
command="(spawning)") *before* calling `build()`. If `build()` fails, the
placeholder is cleaned up. If `_save()` after spawn fails, the placeholder
still exists — the job is visible in `jobs list` even though it has pid=0.
No more orphan processes invisible to the ledger.

**27. Fixed.** `disable_offline`/`enable_offline` now read
`SYSTEM\Select\Current` via `hivexregedit --export` before rendering the
`.reg`, and target the active ControlSet (001, 002, etc.) instead of
hardcoding 001. `_system_services_reg` accepts a `control_set` parameter.
Module-level constants still default to 001 for the build-time path (fresh
images). `read_current_control_set` added to `offlinereg.py`.

### 26. kdbg read-surface residuals from the 2026-08-10 audit (accepted / minor)

Two findings from the read-surface audit were left as-is, deliberately:

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
**10. Fixed.** See item 44 — `_mem_qword_reader` now distinguishes unmapped
VA (returns 0, counts on bp) from transport failure (raises). Operator sees
`predicate_read_errors` in `bp_list` instead of wondering why the bp never
fires.

**11 (pdb). Fixed.** `parse_types` raises on zero-field structs and warns on
suspiciously sparse structs (sizeof >= 64, < 3 fields). Catches regex drift
at parse time instead of as a confusing downstream error.

**12. Partially fixed.** `is_wow64()` detects WoW64 via `PEB.Wow64Process`.
`kdbg_user_lm` adds a warning when WoW64 detected ("only 64-bit modules
listed"). The 32-bit module walk itself is not implemented yet — that's
the full fix. Detection is the minimum useful step.

**14. Fixed.** `kdbg_bp` now accepts `wp_type` ("write"/"read"/"access") and
`wp_size` (1/2/4/8) parameters. `insert_breakpoint`/`remove_breakpoint`
route to Z2/Z3/Z4 packets. Watchpoints share the DR0..3 pool with hw exec
bps. Z3 (read-only) is unsupported by QEMU on x86-64 — hardware DR registers
only support write (Z2) and access (Z4). Verified live — write and access
watchpoints install/remove/list correctly; invalid type/size rejected at add
time; 5th DR slot correctly refused.

### 15. `kdbg_bt` is a stack-scan heuristic, not a real unwinder

`op_bt` walks RSP-relative stack qwords and treats anything that looks like
a canonical code address as a return address (`_looks_like_code_va`). There's
no `.pdata`/`RUNTIME_FUNCTION` parsing anywhere in the codebase, and x64
Windows release binaries are frame-pointer-omitted almost everywhere non-leaf
— so against real targets (AV/EDR components, optimized code) this backtrace
will systematically drop or fabricate frames. Already flagged as best-effort
in the function's own docstring. Largest capability gap versus a WinDbg-class
debugger, and the least tractable item here — a real fix means parsing
`.pdata` and doing table-based unwind, not a local patch.

### 17. SMP is tuned for `-smp 1`, not a first-class case

`_last_selected_vcpu` caching and the `sr.thread or "01"` default throughout
`daemon.py` assume a single vCPU. `list_threads`/`select_thread` exist, but
nothing scopes a breakpoint's fire-tracking to a specific core or distributes
hardware breakpoints per-vCPU. Low tractability relative to impact — this is
cross-cutting, not a local patch — hence listed near last.

**18. Fixed.** `_validate_register_layout` checks RIP (canonical), CS
(recognized selector), CR3 (non-zero, <52-bit cap) from the first g-packet
at attach time. Catches QEMU register-XML drift before it silently corrupts
CR3 filters and bp targeting.

**19. Fixed.** `gdbstub_has_client()` reads `/proc/net/tcp` for ESTABLISHED
connections to the gdbstub port. `kdbg_attach` refuses if another client is
already connected. Verified live — raw TCP connect blocked subsequent attach.

### 41. `kdbg_cont` is a blocking MCP operation

The cont tool blocks for up to `timeout` seconds. The daemon internally
services `interrupt` and `status` ops via `_pump_client`, but the MCP client
is stuck waiting. A non-blocking design — cont returns immediately,
`kdbg_status` polls for bp hits — would let the operator do other work (read
memory, check state) while waiting for a rare breakpoint. This is a design
gap, not a bug, and would require changes to the daemon protocol, MCP handler,
and the `_wait_for_stop_serving` loop.

### Performance roadmap (2026-08-21)

**49. CR3 masquerade overhead: 3 RSP round-trips per read in daemon path**

Every in-session memory read (`op_mem`, `_mem_qword_reader` in predicates)
does: G-packet write (swap CR3) → `m` read → G-packet write (restore CR3).
That's 3 socket round-trips for 1 logical read. A `poi(poi(rcx+0x10)+0x8)`
predicate does 6 round-trips for 2 reads.

Fix: batch multiple reads under one masquerade. `_cr3_masqueraded_call`
already takes a `fn` callable — callers could pass a multi-read lambda.
For predicates: evaluate the full expression tree, collect all addresses
that need reading, do them all under one masquerade, then resolve.
Complication: `poi()` chains are data-dependent (second address depends on
first read), so only independent reads can batch. Still helps `op_stack`
(already batched) and action-list evaluation (multiple independent
expressions per bp fire).

Expected gain: ~30-50% faster predicate evaluation for multi-expression
action breakpoints. Moderate complexity — predicate evaluator needs a
two-pass design for the non-dependent case.

### Edge cases to harden (2026-08-20)

**35. Tested 2026-08-21 — PASS.** Target killed mid-session (scheduled
`Stop-Process` fires while cont running). Cont timed out (target gone),
detach cleaned up without crash, GA survived.

### Capability roadmap (2026-08-21)

**42. Fixed.** `kdbg_step(out=True)` reads `[rsp]`, plants temp hw bp at
return address, conts until hit. Shares `_run_to` helper with step-over.

**43. Fixed.** `kdbg_bt` already resolved all loaded modules (including
user-mode) via `_best_symbol_for_va`. `kdbg_disasm` now annotates call/jmp
targets with a `"sym"` field via `symbolicate_va` (extracted to `format.py`
for reuse). Verified live — `call 0x7fff7f324940` renders as
`ntdll!LdrpLogInternal+0x0`.

**44. Fixed.** `_mem_qword_reader` now distinguishes unmapped VA (return 0,
count `predicate_read_errors` on bp) from transport failure (raise
`PredicateRuntimeError`). `bp_list` surfaces the read error count.

**45. Fixed.** `poi()` function added to predicate grammar. Evaluates inner
expression, reads qword at result. Nests: `poi(poi(rcx+0x10)+0x8) == 0x1234`
chases two pointers. Offset arithmetic inside: `poi(rax+0x10)`,
`poi(rax-0x8)`. 13 unit tests (parse + eval + nesting + errors). Verified
live — conditional bp with poi() installs and evaluates; bad syntax rejected.

**46. Already works.** `DaemonClient` is stateless — each MCP tool call
opens a fresh Unix socket to the daemon, which survives MCP restarts as a
separate setsid process. `session_alive()` checks the fcntl lock, not
in-process state. Verified: fresh Python process connects to running daemon
and gets full status. No code change needed — the architecture solved it.

**47. Fixed.** `kdbg_bp` accepts `actions` — a list of expression strings
(same grammar as conditions). On each in-target fire, expressions are
evaluated and results appended to a JSONL trace file. The bp auto-continues
instead of halting. `kdbg_bp_trace(bp_id)` reads the trace. Turns kdbg into
a lightweight tracer: "log every IOCTL code through this dispatcher" is now
`kdbg_bp(target, actions=["[rsp+0x18]"])` + `kdbg_bp_trace(id)`.

---

## Fixed

*`git log` is the authoritative record. This section exists so the roadmap
is self-contained — readers don't have to search git for "was this done?"*

**9.** `kdbg_cont` timeout / halt state tracking. See commit `a2373bc`.

**10.** `kdbg_stack` returns `{offset, va, value}` per qword. `kdbg_mem`
gained `decode='qwords'`. See commit `9009a49`.

**11 (auto mode).** `mode='auto'` removed entirely. Breakpoints must carry
their type explicitly — only `mode='hw'` and `mode='soft'` accepted.

**12.** Superseded by item 28 — `fork_daemon` auto-retries with gdbstub
restart via HMP.

**13.** Dead `gdbstub.py` + tests deleted. `kdbg_detach` test mocks
`ensure_not_paused` — no longer touches the real VM.

**28.** `fork_daemon` retries up to 3 times on "empty stop reply": raw-closes
socket, restarts gdbstub via HMP, reconnects.

**29.** PID-not-found path uses safe socket close pattern (no D-packet dance).
GA channel survives failed attach.

**30.** Active probe removed (false-positived on fresh boot — no kernel
symbol reliably fires within 1s on quiet VM). Replaced with passive
verification: `_hw_bp_verified` set when any hw bp fires during `op_cont`
(any CR3). `unfired_hw_bps` warning in cont response covers the case where
hw bps genuinely never fire.

**31.** `list_processes` switches to System's DTB after first EPROCESS read,
eliminating mid-walk KPTI CR3 races. `list_modules` gained KPTI retry.

**40.** Active probe removed entirely — superseded by passive verification
in item 30. The probe false-positived because no kernel symbol fires
reliably within any timeout on a quiet freshly-booted VM.

**48.** Persistent debugger transport shipped in v1.5.20. `hmp()` now uses a
serialized persistent QMP connection (with libvirt/virsh fallback), while a
process-safe persistent RSP broker exclusively owns debugger halt/resume,
register, CR3, memory, and process/module-walk operations. CET preparation is
an explicit fail-closed preflight with exact policy backup/restore.

Final live validation on 2026-08-22 passed all nine release checks: the fresh
MCP catalog exposed 64 tools; CET reported `UserShadowStack=OFF` and
`StrictMode=OFF`; both unconfirmed policy-changing calls refused; the reader
owned the connected gdbstub; process, kernel-module, and LSASS PE reads were
correct; four concurrent debugger requests completed through broker
serialization; and the System log contained zero event ID 1001 bugchecks
since boot. See `docs/v1.5.20-final-check-handoff.md` for the full checklist
and stress evidence.

**21.** Private user-mode software breakpoint removal now records the exact
CR3 used by `install_user_breakpoint` and re-enters that CR3 before sending
`z0`; legacy tracked breakpoints without the recorded value retain safe
candidate fallback. Unit coverage checks direct and fallback removal,
registry retention on failure, exact CR3 restoration, and shutdown cleanup.
Live validation on 2026-08-22 completed three consecutive
`ntdll!NtClose` soft-breakpoint add/remove cycles, restored the original byte
after every removal, left no tracked breakpoints, and kept the VM running.

**50.** Process walking now derives compact read spans from the live
PDB-backed EPROCESS layout and coalesces genuinely adjacent fields, including
`UniqueProcessId` with `ActiveProcessLinks` on the validated Server 2025
layout. It deliberately does not read the entire min/max field range: the
real fields span about 1.4 KiB, and live benchmarking proved that sparse
over-read was slower than compact RSP requests. Bounds, a 64 KiB sanity cap,
short reads, pre-KPTI layouts, invalid user DTBs, and KPTI switching are
covered. Warm `kdbg_ps` median improved from 232.1 ms to 226.7 ms across the
same live VM rather than taking the initially measured 266 ms regression.

**51.** `list_processes` and `find_process` now share a lazy internal walker;
the latter returns immediately after a PID/name match without materializing
the process table. PID 4 stabilization and boot-scoped CR3 caching happen
before yielding, so an early return preserves the full-walk invariant. All
single-PID CLI, MCP, and debugger-daemon consumers use the early lookup.
Live integration proved a PID 4 lookup reads exactly one EPROCESS and takes
about 22 ms warm on the validation VM.

**11 (pdb).** `parse_types` raises `ValueError` on zero-field structs instead
of returning useless empty layouts. Catches `llvm-pdbutil` format drift.

**16.** Step-over: `kdbg_step(over=True)` steps over `call`/`syscall`/`sysenter`
by planting a temp hw bp at the next instruction and continuing. Falls back to
regular step for non-call instructions. Verified live — stepped over a
`call rel32` inside `nt!NtClose`, landed at the correct return point.

**18.** Register layout validation at attach time: `_validate_register_layout`
checks RIP (canonical), CS (recognized selector), CR3 (non-zero, <52-bit cap).
Catches QEMU register-XML drift before it silently corrupts everything.

### Edge cases tested (2026-08-21)

**32.** Double attach — PASS. Clean refusal, existing session unaffected.

**33.** Interrupt during cont — PASS. Interrupt+detach works, GA survives.

**34.** DR slot exhaustion — PASS. 5th hw bp fails with clear error.

**36.** Nonexistent symbol — PASS. Fails before any gdbstub operation.

**37.** Unmapped VA read — PASS. Clean error, session intact.

**38.** Rapid attach/detach x5 — PASS. GA survived all cycles.

**39.** PID mismatch between GA `ps` and kernel walker — root cause was
item 31 (KPTI truncation). Fixed by walker using System DTB.

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

*Workflow note (not a tool defect):* prefer live `kdbg_disasm` against the
running process over tracking a module's ASLR base and cross-referencing a
static off-VM copy with `objdump`. The live path is faster and removes any
"is this the right build" doubt. `kdbg_disasm` and `kdbg_user_symbols_load`
already exist and went unused.
