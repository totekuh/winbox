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

Items 20-21 jump that queue: they came out of actually driving a live kdbg
session on 2026-08-10 to verify item 9's fix, not from static reading, and
20 in particular is now the highest-confidence hazard in this file — it
crashed the guest twice in one session, once destructively.

### 20. Calling a guest-agent-dependent tool while a kdbg session holds the VM halted corrupts guest state — reproduced twice, once destructively

`kdbg_attach` halts the VM's vCPUs for the session's duration (standard
gdbstub all-stop behavior; libvirt reports the domain `paused` while
attached). Any MCP tool that depends on the in-guest QEMU guest agent (e.g.
`kdbg_user_symbols_load`, which pulls the target binary via
VirtIO-FS/guest agent) cannot get a response while the guest's CPUs aren't
running — the agent process itself needs to execute to answer. Calling one
of these between `kdbg_attach` and `kdbg_detach` was reproduced twice in one
session: the first time, it was followed by more calls and an extended
real-world pause before detach, and the VM came back from that corrupted —
Windows dropped into WinRE ("It looks like Windows didn't load correctly")
and needed recovery from a libvirt snapshot. The second time, detaching
immediately after the failure avoided lasting damage, but `kdbg_regs` on the
same still-attached session then timed out (`RspError: read timed out`), and
the gdbstub itself needed a stop/start cycle before a fresh attach worked
again. Fix: at minimum, document this prominently — no guest-agent-dependent
tool call between attach and detach; better, have `kdbg_attach` write
session state that those tools check and refuse to run against with a clear
error, instead of timing out into the guest agent and leaving the
session/VM in an unknown state.

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
