# Test Coverage Roadmap

Audit date: 2026-11-10 (v1.8.1, commit 40e97e3)

## Current State

| Metric | Value |
|--------|-------|
| Source modules | 96 |
| Source lines (coverable) | 23,665 |
| Overall line coverage | 75% |
| Test files | 94 |
| Unit tests | 3,074 |
| Integration tests | 169 |
| CLI commands tracked | 162 (116 live, 27 excluded, 19 groups) |
| MCP tools tracked | 109 (96 live, 13 excluded) |
| CLI live ratio | 81% |
| MCP live ratio | 88% |

The e2e manifest (e2e_manifest.py + test_e2e_coverage.py) is self-enforcing:
new commands/tools fail the build until they appear with a coverage decision,
every exclusion must name a backing unit test, every LIVE claim is verified
textually against test_e2e_live.py. This makes "quietly untested" impossible
for the public surface.

---

## Priority 1 — Critical Gaps (safety/correctness risk)

### P1.1: Daemon bootstrap has no unit test
- **Module:** `kdbg/debugger/daemon.py` lines 4037-4256 (220 lines)
- **What:** `_fork_daemon()` — fork, RSP attach with retry, gdbstub restart,
  module base validation, session file write, Unix socket bind, signal
  handlers, cleanup on shutdown
- **Risk:** Regression breaks all interactive debugging. CR3 restore error
  paths are safety-critical (poisoned guest state).
- **Action:** Extract fork/attach/validate into testable functions. Test
  startup signaling, attach retry logic, and CR3 restore error paths with a
  fake RSP.

### P1.2: QMP protocol (production fast-path) untested
- **Module:** `kdbg/hmp.py` lines 62-234 (99 missed of 360)
- **What:** `_QmpConnection._read_message()`, `._execute()`, `hmp()` QMP
  path, `_open_qmp()` handshake, `_try_qmp()` transport selection
- **Risk:** QMP is what runs in production. Only the virsh fallback is tested.
  Malformed JSON, send failure, mismatched response IDs have no test.
- **Action:** Mock QMP socket. Test handshake, execute, error paths, fallback
  selection.

### P1.3: Core memory primitives only tested indirectly
- **Module:** `kdbg/memory.py` lines 67-337 (43 missed of 143)
- **What:** `read_phys()` chunking, `read_virt_cr3()` CR3 masquerade,
  `read_virt_current()`, typed helpers (`read_u64`, `read_u32`, `read_cstr`,
  `read_unicode_string`)
- **Risk:** Every walker depends on these. Walkers mock `read_phys` in their
  tests, so the actual chunking/error logic is never exercised.
- **Action:** Direct unit tests with a mock RSP snapshot. Test chunk
  boundaries, partial reads, error propagation.

### P1.4: Docker security hardening untested
- **Module:** `kdbg/decomp/docker.py` lines 240-354 (86 missed of 224)
- **What:** `_start()` creates container with 14+ security flags (read-only
  root, no-new-privileges, cap-drop ALL, network none, pids-limit, memory
  limit). None verified by test.
- **Risk:** A flag removal or typo silently widens the Ghidra JVM attack
  surface.
- **Action:** Test that `_start()` passes correct flags to Docker. Snapshot
  test: assert the exact `docker create` args include all security flags.

### P1.5: Continue worker never live-tested
- **Module:** `kdbg/debugger/continue_job.py` lines 325-358
- **What:** `_run_worker()` — the code that actually calls `client.call("cont")`
  and waits for a breakpoint hit. Session mismatch, timeout, cancel race
  untested.
- **Risk:** The actual guest-continue-and-wait code has zero tests at any level.
- **Action:** Unit test with mock DaemonClient. Test normal hit, timeout,
  cancel race, session mismatch.

---

## Priority 2 — Significant Gaps (functional risk)

### P2.1: Ghidra decompiler worker (44% coverage, 622 missed lines)
- **Module:** `kdbg/decomp/worker.py`
- **What:** Entire decompilation pipeline — JVM bootstrap, binary validation,
  program cache, analysis orchestration, function recovery, DecompInterface
  with cancellation, source-line mapping, assembly extraction, LRU cache,
  enrichment application, server socket loop
- **Current:** Only tested through Docker integration (1 test)
- **Action:** Break into testable units. Test program cache management, LRU
  eviction, enrichment application, cancellation coordination, and server
  protocol independently of a live JVM.

### P2.2: Interactive shell line editor (23% coverage, 344 missed lines)
- **Module:** `exec/shell.py`
- **What:** 360-line pipe-mode readline with history, keybindings (Ctrl+A/E/K/U/W/C/D/L),
  cursor math, escape sequences, multi-line wrapping, resize handling, batch
  paste
- **Current:** Only TTY guards and connection setup tested
- **Action:** Factor line editor state into a testable class (no real TTY
  needed). Test keybindings, history navigation, cursor math, resize, batch
  insert against a mock socket.

### P2.3: Capture orchestration (52% coverage, 108 missed lines)
- **Module:** `kdbg/capture.py`
- **What:** `capture_process_in_snapshot()`, `capture_system_in_snapshot()`,
  `capture_live()` — the code that reads kernel memory and assembles evidence
- **Current:** Only diff and storage tested in unit tests; capture logic
  tested only via e2e
- **Action:** Test with a mock RSP snapshot. Verify record assembly, error
  paths for missing threads/modules/VADs.

### P2.4: New share/user MCP handlers thin on unit tests
- **Module:** `mcp.py` (share_write 71% uncovered, share_delete 64%,
  share_create 45%, share_grant 51%, user_create 49%)
- **What:** Recently added in commit 89cc6bc. E2e-covered but unit tests
  only cover validation paths, not handler bodies.
- **Action:** Add unit tests for handler logic with mocked GuestAgent. Focus
  on encoding handling, confirmation guards, error messages.

### P2.5: Daemon verified_static_reader (lines 1680-1775)
- **Module:** `kdbg/debugger/daemon.py`
- **What:** PE identity verification for static unwind — attach-manifest
  lookup, symbol-store fallback, SHA256 verification, section-based reads,
  CodeView decommit fallback
- **Risk:** Silent wrong-binary identification corrupts stack unwinding
- **Action:** Test with known PE fixtures. Verify SHA256 match/mismatch
  paths, section fallback.

### P2.6: Doctor readiness formula (63% coverage)
- **Module:** `kdbg/doctor.py`
- **What:** The boolean `ready` formula (VM + agent + CET + symbols + no
  interactive), capability computation (thread_research,
  live_decompilation, offline_preparation), decomp Docker status
- **Risk:** Readiness gate logic drives what AI agents are told they can do.
  A false positive = agent tries impossible operation.
- **Action:** Parameterized unit test: each combination of
  VM/agent/CET/symbols/session state. Verify ready and capabilities match.

---

## Priority 3 — Depth Gaps (tested but shallow)

### P3.1: No automated breakpoint-hit-and-step cycle
- **What:** No test anywhere sets a bp, continues, waits for a real hit, reads
  post-hit state, and single-steps. The e2e cont_start immediately cancels.
  The wow64 integration test hits a bp but doesn't single-step afterward.
- **Action:** Integration test: set bp on a known-hot function (e.g.
  NtDelayExecution), continue, wait for hit (bounded timeout), read regs,
  single-step, verify IP advanced, resume. This is the full debugger loop.

### P3.2: No multi-profile CI
- **What:** Suite runs against whichever VM is configured. All three profiles
  (server2022, server2025, win11) theoretically supported but depends on
  manual runs.
- **Action:** Weekly CI matrix with all three profiles. Even a nightly run
  against one profile catches regressions before they land.

### P3.3: No reboot-tolerant harness for av_disable/hvci_enable
- **What:** These reboot the guest and are excluded from e2e because they
  break mid-suite ordering. Shared code tested via CLI, but MCP serialization
  around reboot is not.
- **Action:** Run reboot-causing tests last in a dedicated phase. Re-wait for
  guest agent after reboot. Mark phase clearly so manual runners know what to
  expect.

### P3.4: Sinkhole never resolves DNS
- **What:** Sinkhole starts and stops but no test resolves a domain from the
  guest to verify the sinkhole responds.
- **Action:** Start sinkhole on test port, exec `nslookup test.example
  <sinkhole-ip>` in guest, verify response.

### P3.5: Error recovery paths untested
- **What:** What happens when gdbstub disconnects mid-walk, Docker dies during
  decomp, guest reboots during kdbg walk.
- **Action:** Targeted fault-injection tests. Kill gdbstub socket mid-read,
  docker stop mid-decompile, verify graceful error not hang.

### P3.6: Concurrent MCP operations
- **What:** Parallel walker admission is tested (4 concurrent), but concurrent
  MCP tool calls, concurrent kdbg operations, race between CLI and MCP are
  not.
- **Action:** ThreadPoolExecutor with N concurrent MCP calls. Verify no data
  corruption, no socket leak, no stale daemon state.

### P3.7: kdbg_write_mem has no test at any level
- **What:** Excluded from e2e for safety. RSP-level write tested but actual
  MCP handler and write-then-verify-read path untested.
- **Action:** Unit test with mock RSP. Verify write request formation, read-
  back verification, error paths.

---

## Priority 4 — Completeness (low risk, coverage tracking)

### P4.1: Five modules with no dedicated test file
| Module | Coverage | Risk |
|--------|----------|------|
| ps.py | 92% | Low — 13 lines, transitively tested |
| kdbg/catalog.py | 80% | Low — 5 lines, constant file |
| kdbg/presentation.py | 86% | Low — 28 lines, formatting |
| kdbg/provenance.py | 69% | Low — read-only reporting |
| kdbg/decomp/locking.py | 84% | Moderate — file lock correctness matters |

Action: Add dedicated tests for locking.py (race/contention paths) and
provenance.py (git fallback). Others are fine as transitive.

### P4.2: Frame unwinder edge cases (unit only)
- `kdbg/unwind.py` (76%) and `kdbg/x86_unwind.py` (81%) — unit tested but
  never exercised against real hardware outside the wow64 mixed integration
  test.
- Action: Add PE fixtures with known unwind tables. Test boundary cases
  (leaf functions, exception handlers, dynamic frames).

### P4.3: Static search offline PE discovery (77%, unit only)
- `kdbg/static_search.py` — offline PE search never integration-tested.
- Action: Low priority. Unit coverage is reasonable and this runs offline.

### P4.4: State cleanup hardening
- Snapshot "e2e-snap" created but never deleted post-test
- Defender state can drift on Win11 (Tamper Protection blocks cleanup)
- DNS state left wrong if sync fails
- Guest user `_winbox_e2e_user` persists if fixture teardown times out
- Action: Add defensive cleanup in session-scoped fixtures. Accept that Win11
  Defender drift is a known limitation.

---

## Coverage Targets

| Metric | Current | Target | Notes |
|--------|---------|--------|-------|
| Overall line coverage | 75% | 80% | P1+P2 items get us there |
| Modules below 70% | 8 | 3 | shell.py stays low (TTY), reduce the rest |
| CLI live ratio | 81% | 85% | Promote cont-start/poll/cancel to LIVE |
| MCP live ratio | 88% | 90% | Few promotions needed |
| Integration test files | 9 | 11 | Add bp-hit cycle + reboot-tolerant suite |
| Automated CI profiles | 0 | 1+ | Even one nightly run is a big improvement |

---

## Not Worth Pursuing

- **shell.py to 80%:** Interactive TTY code. Factor out the line editor
  state for testing (P2.2) but the raw I/O relay will stay low.
- **100% mcp.py:** Most missed lines are `return _format(result)` at handler
  ends that need a real VM. Expected and benign.
- **worker.py to 80%:** Most code requires a live JVM. Extract testable units
  (P2.1) but the core Ghidra calls will stay integration-only.
- **setup/destroy e2e:** These rebuild/delete the VM. Correctly excluded.
