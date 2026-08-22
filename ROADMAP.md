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

### 53. Predicates/actions need typed reads and bounded buffer capture

The expression language reads only unsigned little-endian qwords. Masking a
qword can approximate a byte/dword, but it is wrong at page boundaries and
cannot capture the buffers, strings, lengths, and narrow fields that dominate
IOCTL/RPC/parser research.

Add scalar `byte()`, `word()`, `dword()`, and `qword()` reads first, preserving
short-circuiting, batching, candidate retry, unmapped counters, and exact CR3
restore semantics. Then add action-only bounded `bytes(addr,len)`, ASCII, and
UTF-16 capture with strict per-hit/per-trace size caps. Conditions must remain
scalar and side-effect free. Moderate implementation effort, broad research
payoff.

### 41. `kdbg_cont` is a blocking MCP operation

The cont tool blocks for up to `timeout` seconds. The daemon already services
`interrupt` and `status` through `_pump_client`, but the initiating MCP request
remains occupied. That is especially awkward for an AI agent waiting on a rare
breakpoint: it cannot naturally poll progress, inspect accumulating action
traces, or survive an MCP transport restart.

The smallest robust design is a durable host-side cont worker:
`kdbg_cont_start` records a session token and returns immediately,
`kdbg_cont_poll` reads a bounded persisted result/status, and interrupt/detach
cancel it. The worker talks to the existing daemon protocol, so the RSP state
machine does not need to become multithreaded. Guard concurrent starts, stale
workers, daemon death, detach, and MCP restart. Moderate effort and the highest
orchestration payoff for autonomous research.

### 54. Stop triage is fragmented across too many MCP calls

After a breakpoint or exception, an AI must separately request registers,
nearby disassembly, stack qwords, the heuristic backtrace, breakpoint metadata,
and often pointed-to memory. The halt is stable, but the repeated protocol
round-trips waste time and context, and agents frequently omit one of the
pieces needed to reason about the stop.

Add a bounded `kdbg_context`/`kdbg_triage` response containing the stop reason,
target/vCPU/CR3, registers, symbolized RIP, nearby disassembly, labeled stack,
active breakpoint metadata, and an explicitly labeled heuristic backtrace.
Optional memory follows must be caller-selected and tightly capped. This is a
small composition layer over existing operations; it improves ergonomics more
than raw capability, so it ranks below items 52/53/41.

### 12. WoW64 detection is currently ineffective; 32-bit modules are absent

`is_wow64()` looks for `Wow64Process` in `_PEB`, but that field is absent from
the current Server 2025 PDB maps, so the function returns false. The live PDB
does expose `_EPROCESS.WoW64Process` (offset `0x310` on the current build),
which is the kernel-side detection path that should be used. The roadmap's
previous claim that detection was already fixed was incorrect.

After correcting detection, implement the 32-bit loader walk through
`_EWOW64PROCESS`/PEB32 using 32-bit pointers and 32-bit UNICODE_STRING/LDR
layouts. Keep native and WoW64 module results explicitly labeled; do not mix
same-named 32/64-bit DLLs in the symbol store. Moderate effort, high payoff for
legacy user-mode targets, but narrower than items 52/53/41.

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

### 17. SMP behavior is under-tested despite the four-vCPU default

`Config.vm_cpus` defaults to 4, so the old description of `-smp 1` as the
default was wrong. Item 49 now carries the firing vCPU explicitly through
predicate/action evaluation, and `_last_selected_vcpu` is a round-trip cache,
not itself proof of a single-core assumption. The unresolved risk is narrower
but real: `sr.thread or "01"` remains a fallback, and there is no focused live
coverage for target-thread migration between vCPUs, simultaneous stops, or
hardware breakpoint/watchpoint slot behavior across cores. Audit and test the
actual QEMU semantics before redesigning anything; do not assume per-vCPU
distribution is required. Cross-cutting and not an easy win.

---

## Fixed

*`git log` is the authoritative record. This section exists so the roadmap
is self-contained — readers don't have to search git for "was this done?"*

**9.** `kdbg_cont` timeout / halt state tracking. See commit `a2373bc`.

**10.** `kdbg_stack` returns `{offset, va, value}` per qword. `kdbg_mem`
gained `decode='qwords'`. See commit `9009a49`.

**11 (auto mode).** `mode='auto'` removed entirely. Breakpoints must carry
their type explicitly — only `mode='hw'` and `mode='soft'` accepted.

**12 (daemon retry).** Superseded by item 28 — `fork_daemon` auto-retries
with gdbstub restart via HMP.

**13.** Dead `gdbstub.py` + tests deleted. `kdbg_detach` test mocks
`ensure_not_paused` — no longer touches the real VM.

**14.** `kdbg_bp` supports Z2/Z3/Z4 watchpoint packets, validated type/size,
and the shared four-slot DR budget. Live write/access watchpoints passed; QEMU
x86-64 does not provide a true read-only hardware watchpoint.

**19.** `gdbstub_has_client()` detects established gdbstub connections and
prevents a second attach from contending for QEMU's single client.

**22.** Buffered CLI and MCP background jobs carry a unique echoed nonce.
Every result path verifies it before accepting qemu-ga output; mismatch marks
the job LOST instead of attributing a recycled PID's output. Unit coverage and
the 2026-08-22 live `PID recycled — nonce mismatch` result confirm the guard.
See commit `e5a44f2`.

**23.** Pipe broker cleanup verifies that a recorded PID is still
`python.exe` before taskkill, so PID recycling cannot kill a foreign process.

**24.** `pipe_recv` reclaims the oldest orphaned successful read result before
issuing a new read. Sequence-number correlation prevents one caller from
stealing another's result; write results are never misread as bytes. The
timeout/desynchronization scenario has dedicated regression coverage. See
commit `e5a44f2`.

**25.** Job creation persists a visible spawning placeholder before launch,
preventing an untracked guest process when build or final persistence fails.

**27.** Offline registry changes resolve `SYSTEM\Select\Current` and target
the active ControlSet instead of assuming ControlSet001.

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

**35.** Target death during an active continue was tested live: continue
timed out, detach cleaned up, and the guest agent survived.

**42.** Step-out uses the return address at `[rsp]` and the shared `_run_to`
temporary-breakpoint path.

**43.** Backtrace candidates resolve across loaded kernel/user modules, and
disassembly annotates immediate call/jump targets with symbols.

**44.** Predicate reads distinguish an unmapped VA (zero plus read-error
counter) from transport/runtime failure (explicit predicate error).

**45.** `poi()` supports nested pointer chasing and offsets in predicates and
actions, with parser/runtime error coverage.

**46.** The daemon protocol is already stateless per client connection and
survives MCP restarts; no implementation change was needed.

**47.** Breakpoint actions auto-continue and append structured JSONL traces,
retrievable through `kdbg_bp_trace`. Item 49 later batched their reads and
fixed trace-file lifecycle.

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

The later item 49 live pass found that the original CET check was incomplete:
the system default reported OFF while 34 running processes had effective user
shadow stacks enabled, and a zero-breakpoint-hit session reproduced the known
`WRUSSQ` bugcheck. The gate now queries every process through
`GetProcessMitigationPolicy` with limited handles (including protected
processes), fails closed on any active/unqueryable process, and refuses before
opening GDB. Preparation also hides libvirt's `cet-ss` CPU feature so a new
process cannot opt in after the one-time scan; the exact original CPU XML and
Windows mitigation values are restored from a mode-0600 backup.

**49.** Breakpoint conditions and action lists now evaluate as one pure batch
inside a single CR3 masquerade, including data-dependent nested `poi()` chains.
Register-only and runtime-short-circuited paths perform no CR3 swap. Candidate
retry reruns the side-effect-free evaluation under the alternate verified KPTI
CR3; mixed mappings and fully unmapped reads retain the established per-read
fallback, exact counters, and zero semantics. Restore failure poisons the
daemon and never retries. The firing vCPU is explicit rather than inherited
from possibly stale stop state.

Action trace files are also truncated when a new session reuses a breakpoint
id, before anything is installed in QEMU, so old entries cannot contaminate
`total` or survive an initialization failure. Unit coverage checks exact
G-packet counts (three reads and nested dereferences use one swap/restore),
candidate retry, mixed mappings, short reads, unmapped values, poison behavior,
short-circuit zero-swap behavior, trace-once semantics, and trace lifecycle. A
real Unix-socket daemon/RSP integration test covers the public protocol.

Final live validation on 2026-08-22 used a CET-free boot and a warmed
PowerShell target at `ntdll!NtClose`: 70/70 predicate hits produced 70 trace
records with coherent independent/nested reads; the short-circuit edge made 45
skips with zero reads/traces; the unmapped edge made 39 hits, 39 read-error
counters, and 39 zero-valued records. Cleanup removed every breakpoint and
target, stopped the gdbstub, retained zero active/unqueryable CET processes,
and left System events 1001/41/6008 empty since boot.

**52.** Action traces now support a backwards-seeking fast tail,
inclusive `from_hit`/`limit` pagination, exact expression projection,
numeric-aware value filtering, error-only filtering, and streaming bounded
summaries. Summaries report exact matched/error counts and numeric min/max,
plus capped distinct values, top counts, and representative hit ids; every
count, byte, expression, distinct-value, and display-text bound reports its
own truncation state. Malformed, oversized, missing, CRLF, block-boundary,
and unterminated-line cases are covered without loading the JSONL file.

Unit tests cover query semantics and adversarial bounds, the real Unix-socket
integration test composes filtering/pagination/summary through the daemon,
and MCP tests cover the public argument surface. Final live validation on
2026-08-22 traced 144 `ntdll!NtClose` hits in a CET-free PowerShell target:
tailing returned hits 139–143, pagination returned 0–6 with `next_hit=7`,
summary counts/min/max/top values matched all 144 records, decimal `1888`
matched recorded hex `0x760`, expression projection and error-only filtering
were correct, and `limit=201` was rejected. Cleanup removed the breakpoint,
daemon, target, and gdbstub; the VM and guest agent remained healthy with no
recent System 1001/41/6008 events. After the required MCP restart, a second
through-MCP live pass traced 114 hits, returned hits 0–3 with `next_hit=4`,
matched decimal `940` to hex `0x3ac`, projected only `rcx`, summarized all
114 records, returned zero error-only matches, and rejected `limit=201`.
Cleanup through MCP again left CET safe, the VM/agent healthy, the gdbstub
stopped, and the same System event query empty. A final restarted-server edge
pass captured 104 hits across two distinct live handle values: `top=1`
returned one bucket with `top_values_complete=false`, while exact counts and
min/max still covered the full trace.

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
