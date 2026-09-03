# winbox — known issues and roadmap

Everything currently known to be wrong, ranked. Each open entry says what
breaks, how it was found, and what fixing it involves. Completed entries are
retained where their design and live evidence are useful context; `git log`
remains the authoritative implementation record.

Ordering is risk × tractability, not severity alone: an unreproducible crash
outranks a typo on severity but cannot be worked on, and there is no value in
a roadmap whose top item nobody can start.

---

## Current status

Items 1-70 have all been worked — `git log` is the record. Item 8 is addressed
at its source (below) but stays listed as *Watching* because it is intermittent
by nature.

The major kdbg execution, symbol, decompilation, exact-artifact staging, x64
unwind, ordinary WoW64 x86 unwind, and bidirectional transition stitching paths
are implemented and live-verified. A post-v1.6.0 stability/usability review on
2026-08-25 opened items 71-84; items 71-73 and 76-78 were implemented the same
day, items 75 and 79-83 were completed on 2026-08-26, and items 74 and 84's
bounded first phase were completed on 2026-08-27. Item 26's IPv6 listener
residual is fixed; its `DirectoryTableBase` trade-off remains accepted. Item 8
remains a watch condition. A follow-up review the same day opened and completed
items 85-87 for cache ownership, subprocess bounds, and prepare-job lifecycle.
A live thread-research review after the PDB-backed `kdbg_threads` launch opened
items 88-101 below. Items 88-91 and 96-97 and 100-101 were completed and live-verified
the same day; the remaining items are deliberately scoped to make stopped-kernel
thread evidence more intelligible and bounded without requiring an in-guest Frida agent.
The follow-up research-control-plane pass completed items 95, 102, and 103 on
2026-08-28: it now refuses cold decompilation by default, makes both snapshot
and decomp contention explicit rather than silently queueing, and exposes
runtime/decompiler provenance in the doctor report.
A second pass completed items 93, 94, and 98: the ETHREAD walker now proves
its backward links and ownership assumptions, strict callers can reject any
partial prefix, and one capped global scheduler view makes cross-process work
visible without presenting a subset as the whole kernel.
The final thread-evidence hardening pass completed items 92, 99, and 104:
wait relationships are exact-PDB and evidence-only, symbol/paging assumptions
fail closed, and every persistent-reader stop now has broker-enforced time,
read, and byte limits with accounting visible in results and doctor admission.

The investigation-evidence/control-plane pass completed items 105–109 on
2026-08-29. It adds exact-PDB VAD/token/object evidence, immutable one-stop
captures, metadata-only operation telemetry, and transport accounting without
turning a loader miss or public-PDB omission into invented certainty.
The focused byte-evidence pass completed item 110 on 2026-08-30: a selected
process VAD can now be proven and extracted during the same bounded stop into
a mode-0600 immutable host artifact, without leaking raw bytes through CLI or
MCP.
The static-research and durable-intent pass completed items 111–112: exact
cached PEs now expose bounded offline search/direct-call leads, attached
sessions accept manifest-relative breakpoint targets, and detached symbolic
intents are applied only through an explicit fresh-manifest attach.

### 111. Completed — static research leads and staged-relative breakpoints

The mpengine reverse-engineering pass exposed a tight loop of repeat ASLR
math, host-side scripts, and noisy breakpoint handling. `kdbg_bp` now accepts
case-insensitive `module+0xoffset` only when exactly one module from the
attach-time staged manifest matches; it bounds-checks the offset, records the
canonical module name, and `kdbg_bps` shows that target rather than forcing
manual base subtraction. Missing manifests, absent modules, ambiguous x86/x64
names, and out-of-range RVAs refuse before touching the target.

`kdbg_search(module, query, limit?, sha256?)` is a deliberately separate
offline exact-PE discovery surface: it falls back from a symbol-store record to
named persistent decomp-cache artifacts (including a copied module with failed
PDB enrichment), and an exact digest resolves intentional same-name ambiguity.
It returns bounded ASCII/UTF-16 `.rdata` matches, exported-name leads, validated
MSVC x64 TypeDescriptor→COL→vftable chains, and direct
RIP-relative string xrefs mapped through `.pdata` function boundaries. It
checks the cached artifact digest before parsing and never opens an RSP socket.
`kdbg_decomp(callers?, callees?)` adds bounded direct relative-call evidence
from the exact immutable decomp input; indirect calls, dynamic dispatch, tail
jumps, imports, and guessed symbol names remain explicit non-results. Existing
action breakpoints were documented with their scalar/capture grammar, JSONL
trace path, resource caps, and automatic continue behavior.

Local unit and exact-PE integration coverage exercise string/RIP xrefs, RTTI,
direct-call edges, digest tampering, ambiguity, adapter parity, and target
validation. Live Win11 verification resolved the exact cached `ntdll` export,
installed and removed its staged-relative breakpoint, then repeated the install
from a durable intent on a fresh attach. Cleanup left the guest running and
responsive, the gdbstub stopped, and the intent store empty.

### 112. Completed — detached breakpoint intents, revalidated at attach

`kdbg_bp_intent_add`, `kdbg_bp_intents`, and `kdbg_bp_intent_remove` preserve
only canonical `module+0xoffset` requests plus their mode, condition,
watchpoint, and action configuration in an atomic mode-0600 host store. They
never resolve or touch the VM. A normal attach ignores the store;
`kdbg_attach(..., apply_intents=true)` / `winbox kdbg attach --apply-intents`
explicitly snapshots it, stages a fresh loader manifest, and only then asks
the halted daemon to resolve and install each unique in-range module match.
Unresolved, ambiguous, out-of-range, and installation failures are retained in
the attach/session report rather than guessed or made fatal to the session.

### 110. Completed — one-stop VAD byte-evidence extraction

`winbox kdbg vad-extract PID ADDRESS --name CASE` and `kdbg_vad_extract` bind
an exact-PDB VAD lookup to a bounded process-CR3 byte read in the same snapshot.
They preserve at most 8 MiB as an append-only mode-0600 blob plus atomic JSON
manifest: target/boot/PDB identity, VAD evidence, selected range, per-segment
and whole-blob SHA-256, unreadable/short-read/RSP-partial holes, and snapshot accounting.
Bytes are never returned in terminal or MCP JSON. A normal partial extraction
retains its explicit holes; `--require-complete` rejects it before any artifact
is published. Invalid names, addresses, and bounds fail before the VM stops.

The extractor reuses the VAD preflight, persistent-reader limits, phase timing,
and host evidence conventions; it does not quietly widen normal process
captures. Unit coverage exercises range proof, caps, short reads, holes,
strict non-publication, immutable atomic storage, tampering, CLI/MCP parity,
and manifest accounting. Live Win11 validation extracted a real executable VAD
page through both transports, verified the persisted digest/permissions, and
left the guest running with the gdbstub stopped.

### Completed sequence — investigation evidence and operator visibility

| Rank | Item | Ease | ROI | Status |
|---:|---|---:|---:|---|
| 1 | **105 — VAD-backed executable-memory and thread-start attribution** | 3 | 5 | Completed — bounded exact-PDB VAD lookup/map plus selected `--resolve` enrichment. |
| 2 | **106 — atomic kdbg evidence captures and offline comparison** | 4 | 5 | Completed — versioned one-stop process/system artifacts and offline diff. |
| 3 | **107 — human control-plane visibility and recent-operation telemetry** | 5 | 5 | Completed — doctor/capture metadata and a redacted timing ring. |

### 105. Completed — VAD-backed executable-memory and thread-start attribution

Implemented as exact-PDB x64 `kdbg_vad` / `winbox kdbg vad`: validated AVL
links/ranges, raw VAD flags/protection, bounded map/lookup behavior, and an
optional MZ probe. Selected non-loader user starts in `--resolve` preserve the
loader lead and add bounded VAD evidence only when it can be proven. Live Win11
validation returned an executable image VAD with MZ evidence and resumed cleanly.

`kdbg_threads`, `kdbg_triage`, and `kdbg_thread_triage` correctly label a
start outside the PEB loader lists as `user_not_in_loader_module`, not as
private, JIT, injected, or malicious.  That is a deliberately conservative
lead, but it leaves the most valuable follow-up entirely manual.  Add a
PDB-backed, x64-only `kdbg_vad(pid, address?, executable?, limit?)` / `winbox
kdbg vad` view.  An address lookup is the default; full executable-map
enumeration is explicit and hard-capped.

The walker must validate the exact `_EPROCESS.VadRoot` representation and each
balanced-tree link before following it.  For each proven range return its
inclusive bounds, allocation kind (`private`, `mapped`, `image`, or
`unknown`), protection and executable/writable properties, and file/section
identity only when the relevant kernel object is structurally validated.  An
optional bounded first-page probe may report PE-header evidence and a digest;
it must never imply that a missing header is benign.  Integrate only selected,
presentation-bounded thread starts into existing `--resolve` output and retain
the raw loader result plus explicit VAD confidence/provenance.

Test short/cyclic/malformed VAD trees, version/layout variants, user and WoW64
addresses, private RX/RWX, mapped images, absent backing names, caps, and all
partial/error paths.  Live validation must leave the guest resumed and prove
that a normal loader miss remains a lead when no VAD conclusion is available.

### 106. Completed — atomic kdbg evidence captures and offline comparison

Implemented as one-stop process/system captures with versioned mode-0600
artifacts, boot/PDB identity, completion boundaries, VAD/token/handle evidence,
and phase/read metadata. Named capture diffs are offline-only and identity-gated.
Live same-boot captures were complete in 372–397 ms; their offline diff made no
RSP connection and returned an empty delta.

Individual read surfaces are each coherent, but a manual investigation often
chains process, thread, module, scheduler, and future VAD queries across
separate stops.  Add `kdbg_capture(profile, pid?, output?, require_complete?)`
and `winbox kdbg capture --profile process PID|system`; each profile declares
its complete, bounded read plan before Windows is stopped.  Persist an
immutable, versioned host-side evidence artifact containing only facts already
captured during that one snapshot: scope/caps, raw and rendered records,
snapshot accounting, VM/boot/process identity, active symbol/PDB identity,
runtime/catalog provenance, and any partial evidence.

Add `kdbg_capture_diff(left, right)` / `winbox kdbg capture diff` as a purely
offline operation.  It should compare matching VM/boot identities by default,
report process/thread/module/VAD changes with the same identity constraints as
thread baselines, and refuse an unsafe cross-boot or incomplete comparison
unless an explicit forensic override is supplied.  Captures do not retain a
live RSP handle and must never read target memory after the guest has resumed.
Existing thread baselines remain supported; this is the general case-artifact
layer above them.

Test deterministic serialization, atomic write/locking, corrupt artifact
refusal, identity mismatch, bounded profiles, strict incomplete captures, and
offline diffs with no VM/RSP access.  Live tests must prove one halt/resume per
capture and no hidden extra snapshot during diffing.

### 107. Completed — human control-plane visibility and recent-operation telemetry

Implemented as logical-vs-transport read/byte/cache accounting, phase timing,
and a redacted 50-record local operation ring. Doctor reports p50/p95, recent
records, capture inventory, reader/admission, and runtime drift; `--verbose`
exposes recent records without collecting memory, paths, arguments, or errors.

MCP/JSON results already carry snapshot IDs, admission ownership, queue delay,
budget consumption, partial-result evidence, decompiler capability, and
runtime provenance.  Normal CLI output reduces much of that to a few lines,
making an operator hunt through JSON to answer why a command was slow, busy,
or incomplete.  Add one shared compact status footer for every snapshot-backed
CLI command, plus `--verbose` for the full control-plane record.  It must show
snapshot ID, stop duration, read/byte budget use, lease owner/admission,
completeness, source/PDB/boot identity, and the precise next recovery action.

Extend doctor/status with active snapshot/decomp admission details, capability
blockers, baseline/capture inventory summaries, and source-versus-installed
runtime drift.  Maintain a bounded local, metadata-only operation ring (for
example the last 50 records) with operation, timings, budget reason,
admission/busy outcome, and result completeness.  Expose aggregate count and
p50/p95 timings through doctor; raw memory, module paths, and dumped evidence
never enter this telemetry by default.

Test CLI/JSON/MCP parity, bounded retention, concurrent writer safety,
redaction, malformed old records, and that status/doctor never attach to the
gdbstub.  The human renderer must never turn an incomplete/busy/error result
green through a lossy summary.

### 108. Completed (safe public-PDB phase) — bounded handle, token, and kernel-object relationships

`kdbg_token`, `kdbg_object`, and `kdbg_handles` prove the primary token,
caller-proven object header, and handle-table root from exact public-PDB fields.
This Win11 public nt PDB omits `_HANDLE_TABLE_ENTRY`, so entry decoding is
explicitly refused rather than guessing a private slot layout.

Thread and VAD evidence explains execution; it does not explain who can
control whom.  Add exact-PDB `kdbg_handles(pid, type?, access?, limit?)`,
`kdbg_token(pid)`, and a narrowly scoped object-reference resolver for already
validated object pointers.  Prioritize process/thread, token, section, file,
ALPC, registry, and synchronization-object facts.  Every returned object must
carry a proven type, access-mask interpretation, and name/target only when
the corresponding object-header and pointer chain validate.

Handle-table traversal is a hostile-memory parser: hard-cap entries and object
name bytes, validate encoded table levels and object-header boundaries, expose
unknown types/accesses as raw values, and retain partial boundaries.  Do not
promise a complete global handle graph or infer that a handle is exploitably
usable from a raw access mask.  This should reuse the VAD/object validation
machinery where possible and integrate selected cross-process handles into
process captures.

### 109. Completed — phase-accounted snapshot transport optimization

The broker now uses a bounded per-stop exact-range virtual cache. Cache fills
consume real RSP budgets, while metadata separately reports logical requests,
transport reads/bytes, and hits. A broker integration test proves a repeated
read succeeds under a one-read budget with one physical transport read; live
process captures showed 282 cache hits while remaining below 400 ms.

The reader currently reports aggregate duration, read count, and bytes, while
walkers already coalesce known nearby ETHREAD fields.  Add named per-phase
accounting (halt/setup, process walk, ETHREAD walk, loader joins, VAD lookup,
wait-object resolution, serialization) to captures and operation telemetry
before changing the transport.  Use that data to choose the actual hot path.

If reads—not guest stop latency or rendering—are the cost, add a bounded
per-snapshot virtual-range cache and vector/coalesced reads keyed by CR3.  It
exists only while the guest is halted, has an explicit byte cap, counts both
logical and transport reads, and is discarded before resume.  Preserve the
broker's duration/read/byte contract: cache fills count against real transport
budget, hits are visible in accounting, and no optimization may extend a stop
or hide a budget failure.  Benchmark against representative system and
high-thread captures; retain it only if the measured stop-time reduction is
material.

### Completed top-three sequence (2026-08-25)

The implementation landed as one coherent state-safety change because all
three paths share the same halt/ownership invariants.

| Rank | Item | Ease | ROI | Status |
|---:|---|---:|---:|---|
| 1 | **73 — preserve a truthful halt at filtered-stop timeout** | 5 | 5 | Completed for CR3, predicate, and action filtering boundaries. |
| 2 | **71 — poison-safe detach without out-of-band resume** | 4 | 5 | Completed with pre-certificate cleanup and caller-side resume gating. |
| 3 | **72 — enforce one debugger run-state operation matrix** | 4 | 5 | Completed in dispatch with explicit interrupt recovery. |

Verification: the complete default suite passes (`2562 passed, 5 skipped, 141
deselected`); the focused daemon/transport/MCP/CLI/decomp set passes (`573
passed, 1 skipped`); and real Docker/PyGhidra integration passes. Three safe
live-VM lifecycle checks passed and left the Server 2022 guest running, the
agent responsive, the gdbstub stopped, and no daemon attached. Full live attach
correctly refused because that boot had CET user shadow stacks active; the
subsequent explicitly authorized prepared-boot validation is recorded below.

### Completed second top-three sequence (2026-08-25)

With the immediate debugger state hazards closed, the next batch favors one
small operator-facing win and two stability foundations that unblock later
cache and lifecycle work.

| Rank | Item | Ease | ROI | Status |
|---:|---|---:|---:|---|
| 1 | **78 — CLI parity for watchpoints, actions, and trace queries** | 5 | 5 | Completed with shared bounds, human rendering, and machine-safe JSON. |
| 2 | **76 — serialize Ghidra cache maintenance with worker lifecycle** | 4 | 5 | Completed with one re-entrant cross-process maintenance lock. |
| 3 | **77 — bounded and reaped debugger child-process lifecycle** | 3 | 5 | Completed with capped startup handshakes and deterministic reaping. |

Verification: the complete default suite passes (`2589 passed, 5 skipped, 141
deselected`) and the focused cache/process/socket/CLI set passes (`740 passed,
1 skipped`). The real Docker/PyGhidra integration passed against the existing
API-5 image. With the live worker holding five projects, a dry run selected
four entries and an applied prune correctly refused without deleting any of
them. After MCP reload, the public status/cache endpoints reported the worker
responsive and the public dry-run prune selected the same four entries, removed
zero, and left the cache unchanged at 387,050,786 bytes; the same worker stayed
healthy with no active operation. Three safe live-VM lifecycle checks passed;
the Server 2022 guest remained running and agent-responsive with no daemon or
gdbstub left active. An explicitly authorized CET preparation and reboot then
reported `UserShadowStack=OFF`, attached the real daemon to `services.exe`, and
staged and symbol-enriched all 25 loader entries with zero failures or warnings.
Live register capture and a complete five-frame pdata unwind succeeded; a
durable continue entered running state, an interrupt returned a truthful halt
at stop ID 2, and detach certified `resume_safe=true` and `cr3_poisoned=false`.
Final cleanup stopped the gdbstub, reaped both observed host child PIDs, retained
no attached session, and left the VM running and guest agent responsive.

### Completed third top-three sequence (2026-08-26)

This batch establishes the observable and typed control plane needed before the
larger cancellation/prewarming and corrupt-project recovery changes. It also
finishes the smallest high-return cache usability gap while item 76's locking
work is fresh.

| Rank | Item | Ease | ROI | Status |
|---:|---|---:|---:|---|
| 1 | **80 — non-blocking decompiler status with phase and progress** | 4 | 5 | Completed with atomic heartbeats, phase progress, and immediate sidecar-only status. |
| 2 | **79 — typed errors from daemon and worker through MCP** | 3 | 5 | Completed with additive versioned errors and bounded legacy fallback. |
| 3 | **81 — targeted cache removal and accounting reconciliation** | 5 | 4 | Completed with exact selectors, reconciled ownership, and explicit residuals. |

Item 75 is the narrow miss: its reliability payoff is high, but implementing
typed worker errors and exact cache targeting first makes exact reset/rebuild
safer and its recovery contract substantially cleaner. Item 74 remains the
largest payoff and largest effort; item 80 now supplies the progress model it
needs.

Verification: the complete default suite passes (`2618 passed, 5 skipped, 141
deselected`) and the focused daemon/decompiler/cache/CLI set passes (`616
passed, 1 skipped`). Real-process heartbeat/cancellation coverage and the real
Docker/PyGhidra integration both pass against the rebuilt API-5 image. The
public MCP status endpoint reports a fresh, idle, responsive heartbeat without
starting the JVM. Its cache inventory attributes all 339,766,562 bytes across
four entries with zero unexplained overhead; exact module, SHA-256, and project
dry runs each selected only the intended `services.exe` entry and removed
nothing. After MCP reload, the public exact-module selector again selected one
entry, and a malformed digest returned the new bounded `invalid_argument`
envelope. A live Server 2022 attach staged and symbol-enriched all 26 exact
modules with zero misses, warnings, or failures; an invalid memory address then
crossed the real daemon and public MCP boundary as typed `invalid_argument`
with `retryable=false` and `operation=mem`. Final detach stopped the gdbstub and
left the VM running with its guest agent responsive; no cache data was deleted.

### Completed fourth top-three sequence (2026-08-26)

This batch closes the next three high-return reliability and operator-feedback
gaps while preserving the existing safe defaults.

| Rank | Item | Ease | ROI | Status |
|---:|---|---:|---:|---|
| 1 | **75 — exact corrupt-project reset and deterministic rebuild** | 4 | 5 | Completed with hash revalidation, exact deletion, one rebuild, and explicit repair. |
| 2 | **82 — observable and selectable attach-time artifact staging** | 4 | 4 | Completed with three policies, bounded progress, and non-mutating preflight. |
| 3 | **83 — target-liveness and exit diagnostics** | 4 | 4 | Completed with captured EPROCESS/create-time identity and PID-reuse refusal. |

Verification: the complete default suite passes (`2653 passed, 5 skipped, 141
deselected`), the focused changed-surface set passes (`583 passed, 1 skipped`),
the Docker worker unit suite passes (`13 passed`), and real Docker/PyGhidra
corruption/reset/rebuild integration passes against the rebuilt API-5 image.
Live Server 2022 checks exercised full, binaries-only, and cached-only staging;
all three attached successfully, and preflight performed no guest copies or
network enrichment. A temporary `PING.EXE` target then exited during a durable
continue: the timeout reported the original captured EPROCESS as `exiting`
with a real exit time rather than silently following the PID. Cleanup stopped
the gdbstub and left the VM running and agent-responsive. The corruption test
used only disposable test cache state; no operator cache was deleted.

### Completed fifth top-three sequence (2026-08-27)

This batch removes the final false-positive listener hazard and moves expensive
Ghidra work out of live stop time while improving exact-PDB output.

| Rank | Item | Ease | ROI | Status |
|---:|---|---:|---:|---|
| 1 | **26a — exact IPv6 listener matching** | 5 | 4 | Completed with address-family-aware `/proc/net/tcp6` decoding and malformed-row rejection. |
| 2 | **74 — cancellable offline Ghidra preparation** | 2 | 5 | Completed with API-6 phases, cancellable analysis monitors, durable jobs, attach prewarming, and partial-project resume. |
| 3 | **84 — exact-PDB signatures and named globals** | 2 | 5 | Completed as the bounded first enrichment profile with per-decision provenance and conflict preservation. |

Verification: the complete default suite passes (`2682 passed, 5 skipped, 141
deselected`), the focused changed-surface set passes (`802 passed`), the API-6
Docker policy suite passes (`13 passed`), and a real PyGhidra fixture stripped
of ELF/DWARF names and types passes. Live Server
2022 validation analyzed `services` without halting the running VM, applied
1,417 exact function names and 1,716 named globals, persisted 3,359 bounded
provenance events, and reused the warm project in 0.006 seconds. A detached
prewarm job completed with a durable token. A cold `apphelp` analysis was
cancelled by exact request ID during `analyzing_program`, returned typed
`cancelled`, then safely resumed the same partial project and completed. A real
IPv6-only listener matched `::1` and did not falsely match `127.0.0.1`.

### Completed sixth top-three sequence (2026-08-27)

This follow-up closes the concrete correctness gaps exposed by the first live
use of enrichment sidecars and detached preparation jobs.

| Rank | Item | Ease | ROI | Status |
|---:|---|---:|---:|---|
| 1 | **85 — enrichment cache ownership and exact pruning** | 5 | 5 | Completed; every digest sidecar/result is owned, inventoried, and removed by the same exact selector. |
| 2 | **86 — truly bounded PDB extraction** | 4 | 5 | Completed with concurrent capped drains, cooperative cancellation, timeout termination, and exact child reaping. |
| 3 | **87 — durable prepare-job lifecycle** | 3 | 5 | Completed with nonce/start-time identity, heartbeats, lost detection, token cancellation, and terminal retention. |

Verification: the complete default suite passes (`2692 passed, 5 skipped, 141
deselected`), focused changed-surface coverage passes (`812 passed`), the API-6
Docker policy suite passes (`13 passed`), and real Docker/PyGhidra integration passes. Live cache
inventory moved from 1,842,202 unexplained bytes/four files to zero without
deletion. Real `services` extraction completed through the bounded path. A
background cold `ntdll` job exposed the same request ID in its token record and
worker heartbeat, transitioned `running` → `cancelling` → `cancelled`, and
returned typed `cancelled`; resuming its partial project then completed and
applied 2,431 function names and 1,809 globals. The live VM remained running
and agent-responsive throughout.

### Completed top-three sequence — thread research visibility and stability (2026-08-27)

`kdbg_threads` now supplies bounded triage evidence rather than a raw unbounded
ETHREAD dump. These three had the largest immediate research payoff; item 88's
small rendering correction shipped alongside item 89.

| Rank | Item | Ease | ROI | Status |
|---:|---|---:|---:|---|
| 1 | **89 — bounded thread result profiles and filters** | 4 | 5 | Completed with full/summary profiles, filters, sort, 1..1024 limit, and separate walk/output truth. |
| 2 | **90 — module/symbol attribution for thread starts** | 4 | 5 | Completed with opt-in live module joins and already-local nearest-public symbols. |
| 3 | **91 — vCPU-to-current-ETHREAD attribution** | 3 | 5 | Completed through validated KPCR→KPRCB→KTHREAD identity, including IdleThreads. |

### Completed quick research views (2026-08-27)

| Rank | Item | Ease | ROI | Status |
|---:|---|---:|---:|---|
| 1 | **100 — kdbg doctor readiness report** | 5 | 5 | Completed as a non-disruptive VM/agent/CET/symbol/ownership/catalog report. |
| 2 | **101 — one-snapshot process triage** | 4 | 5 | Completed with bounded threads, vCPU ownership, user modules, and scoped unmapped-start leads. |

### 100. Completed — kdbg doctor readiness report

The reload and debugging lifecycle previously required correlating separate VM,
CET, symbol, reader, daemon, and MCP status calls. `kdbg doctor` now returns a
single read-only report for both CLI and MCP. It never opens QEMU's RSP socket,
so it cannot halt the guest merely to inspect health. Cached PDB identity is
explicitly marked `cached_unverified` and the live base `not_checked`; a walker
or base refresh remains the authoritative live verification path.

### 101. Completed — one-snapshot process triage

`kdbg_triage(pid, thread_limit=16)` and `winbox kdbg triage PID` collect the
process, complete ETHREAD walk summary, top context-switch rows with module
attribution, current-vCPU ETHREAD identities, and a capped PEB module view
inside one RSP stop. Loader/module misses are returned as bounded leads only
for those top rows (`unmapped_starts_scope=top_rows_only`), never a claim that
a private/JIT mapping is malicious. Missing PEB metadata and current-vCPU
attribution degrade visibly without hiding an otherwise valid thread walk.

### 88. Completed — truthful non-waiting thread presentation

The walker correctly omits a wait-reason name unless `KTHREAD.State` is
`Waiting`, but the human CLI currently formats the missing name as
`unknown(<raw>)`. A terminated or ready thread can therefore look as if it has
an unknown active wait. Render `—` for non-waiting rows, retain the raw byte in
JSON, and expose stale/raw scheduler fields only in an explicit verbose view.
Cover waiting, known non-waiting, unknown-state, and unknown-wait-value output.

Implemented the human renderer as `—` for non-Waiting rows while retaining the
raw byte in JSON. A stale scheduler byte therefore cannot masquerade as an
active unknown wait.

### 89. Completed — bounded thread result profiles, filters, and complete semantics

`MAX_THREADS_PER_PROCESS=8192` bounds traversal but can still serialize several
megabytes of rows while the guest is stopped. The persistent reader serves one
snapshot at a time, so an unbounded response also delays unrelated research.
Add `summary|full` detail profiles, state/wait/address filters, deterministic
sorting, and a bounded result limit for CLI and MCP. Distinguish a completed
kernel walk from a deliberately shortened response with `walk_complete`,
`returned`, `filtered_out`, and `output_truncated`; never label a client limit
as a corrupted list. Test a high-thread fixture, no-match filters, stable sort,
MCP response-size bounds, and live timing/cleanup.

Implemented `detail=full|summary`, raw-or-named state/wait filters,
deterministic sort keys, and a 1..1024 detail-row limit across CLI and MCP.
Responses now distinguish `walk_complete`, total/matched/filtered/returned
counts, `output_truncated`, and summary-only row omission. The legacy
`complete` field remains the kernel-walk truth.

### 90. Completed — module and symbol attribution for thread start addresses

Raw `StartAddress` and `Win32StartAddress` force every consumer to repeat the
same loader/module joins. Add opt-in `--resolve` / `resolve=true` enrichment
that returns address domain (kernel/user), owning module, RVA, and a verified
symbol where one exists. Explicitly label addresses as `private`, `jit`,
`unmapped`, or `not_checked` rather than guessing. Keep the raw address and
identity/provenance beside every resolved result; test native, WoW64, kernel,
private, and stale-loader cases.

Implemented opt-in `--resolve` / `resolve=true`: returned start rows carry
live kernel/user module, base, image size, RVA, architecture where applicable,
and a nearest already-local public symbol. Unmatched user VAs are labelled
`user_not_in_loader_module`, not guessed as private/JIT; no network or symbol
loading occurs during resolution.

### 91. Completed — map the halted vCPUs to their current ETHREADs

The list identifies every thread but not which one each halted vCPU was
executing. Read each `_KPRCB.CurrentThread` through exact PDB offsets, validate
its owning process/ETHREAD identity, and annotate matching rows with
`running_on_vcpus`. Return a separate bounded current-vCPU list for threads
outside the selected process. This is scheduler evidence, not a claim that
arbitrary listed threads have recoverable register contexts. Cover SMP, a
foreign current process, migration, and a halted vCPU whose metadata is unreadable.

The snapshot broker now preserves candidate KPCR bases per vCPU. The walker
validates KPCR self, KPRCB, current ETHREAD, KTHREAD owner, EPROCESS identity,
and CLIENT_ID before returning `current_vcpus` and annotating target rows with
`running_on_vcpus`. Per-CPU IdleThreads are returned explicitly as `status=idle`
with zero PID/TID rather than misreported as broken user threads.

Verification: focused walker/reader/CLI tests pass (`69 passed`); full default
coverage passes (`2720 passed, 144 deselected`); five real CLI integration
tests and the live MCP/CLI parity test pass. A fresh installed MCP stdio server
advertised all seven new inputs and live-validated a complete 174-thread PID 4
summary, four IdleThread vCPUs, and eight intentionally bounded resolved rows.
The guest was left running, agent-responsive, and with the gdbstub stopped.

### 93. Completed — strengthen thread-list integrity invariants

The walker now refuses a nonzero exact-PDB `_EPROCESS.Pcb` before treating
`KTHREAD.Process` as an EPROCESS pointer. It verifies every `LIST_ENTRY.Blink`
against its predecessor, verifies the head's final `Blink`, and rejects a
duplicate live client TID. A malformed walk preserves only the prior validated
prefix and identifies the exact failure stage, link, and ETHREAD. Nonzero-Pcb,
bad entry/head back-links, duplicate TIDs, cycles, foreign owner/CID, and cap
fixtures are covered; live PID 4 and a complete 82-process sweep passed these
invariants on the running Windows 11 guest.

### 94. Completed — strict partial-result controls and structured truncation

`kdbg_threads` and per-process `kdbg_triage` now retain their legacy
`truncated_reason` while adding `{stage, link, ethread, returned, reason}`
evidence. CLI `--require-complete` and MCP `require_complete=true` reject a
partial prefix with retryable typed `incomplete_result`, instead of making an
automation consumer inspect a successful response. The global triage uses the
same rule for process-list, process-cap, thread-budget, and per-process thread
walk boundaries. Unit contracts cover legacy/manual prefixes, every strict
error path, cap boundaries, and structured error detail; live checks exercised
both an accepted complete scope and an intentionally cap-refused one.

### 95. Completed — nonqueueing snapshot/decomp admission and ownership visibility

The RSP broker and decomp worker now take independent, per-runtime operation
leases before beginning work. A concurrent caller gets a stable retryable
`busy` response immediately—no invisible socket or JVM backlog. Snapshot
results include a unique snapshot ID, persistent-reader owner, explicit
admission, queue delay (`0` by design), and stop duration. Decomp results carry
the matching worker lease/timing metadata; `kdbg_decomp_status` and doctor
expose an active admission. Same-process and cross-process contention,
reader-cleanup, and the guarantee that a rejected second snapshot cannot retire
the live reader are covered by focused tests.

### 102. Completed — default cold-analysis interlock for stopped targets

`kdbg_decomp` verifies exact cached analysis readiness after the live module
identity check. If the Ghidra project/profile is absent or stale, its default
path returns retryable `analysis_required` before invoking the worker, with the
digest, readiness reason, and offline preparation recovery action. This avoids
holding a stopped target through first-open analysis. `allow_cold=true` remains
an explicit escape hatch and response metadata states whether cold analysis was
allowed. Tests cover absent project data, stale/missing metadata, profile
mismatch, malformed cache artifacts, explicit opt-in, and exact project
identity.

### 103. Completed — doctor capability matrix and runtime provenance

`kdbg_doctor` now separates basic snapshot readiness from thread research,
interactive debugging, live decompilation, and offline preparation. It reports
the selected decomp backend, its next recovery action, worker/admission state,
and source-manifest versus installed-package versions, paths, PID, git revision,
and dirty state. This makes an editable-install/version drift and a missing
PyGhidra image visible rather than presenting a deceptively green generic
readiness bit. Tests cover unavailable decomp prerequisites and deliberate
source/installed version mismatch.

### 96. Completed — normalized timestamp, status, and pointer presentation

Thread JSON retains legacy raw `create_time`, signed `exit_status`, and pointer
strings for compatibility while adding explicit FILETIME/UTC pairs, normalized
unsigned NTSTATUS hex plus a small exact-name map, and null-aware pointer
values. `KernelStack` is annotated as a `KTHREAD.KernelStack` field, never a
fabricated saved RSP; zero/unavailable values stay `null` in the additive typed
view rather than becoming fake addresses or dates.

### 97. Completed — explicit baseline and diffable thread snapshots

`kdbg_thread_baseline(pid, name?)` / `winbox kdbg thread-baseline PID` saves a
complete bounded host-side ETHREAD set only after one validated stop. The later
`kdbg_thread_diff` / `winbox kdbg thread-diff` performs one new explicit stop
and reports bounded created/exited threads, state/wait/priority/exit changes,
and wrap-aware 32-bit context-switch deltas. Baselines bind VM, target
PID/EPROCESS/CreateTime, System/boot identity, and active nt symbol-store
revision; a mismatch returns typed `baseline_expired` rather than comparing
across reboot, PID reuse, or changed symbol data. Neither command polls.

### 98. Completed — all-process thread triage summary

`kdbg_thread_triage` / `winbox kdbg thread-triage` takes one RSP stop and
returns bounded rankings by thread count and runnable count, newest threads,
high-context-switch samples, and conservatively attributed loader/module
mismatches. It never claims arbitrary-thread registers or turns an untrusted
loader failure into a suspicious start. `process_cap`, `total_thread_cap`,
`sample_per_process`, and `result_limit` all have hard bounds; the response
states whether the active process list, selected process scope, and every
thread walk completed. Tests cover cap exhaustion, partial process lists,
untrusted attribution, empty/filter-like edge cases, CLI/MCP propagation, and
strict refusal. Live validation found 82 complete process records / 705 threads
in a 1.2-second stopped snapshot, while a 64-process run truthfully refused
strict mode rather than claiming global coverage.

### 92. Completed — bounded wait-object and owner-chain evidence

`kdbg_threads(..., wait_objects=true)` / `winbox kdbg threads --wait-objects`
adds PDB-derived evidence only for the displayed Waiting rows. It accepts only
the thread's embedded `_KWAIT_BLOCK`, confirms that block names that exact
ETHREAD, labels the actual `_DISPATCHER_HEADER.Type`, and follows only a real
`_KMUTANT.OwnerThread` relation. External/multi-object blocks, unknown
dispatcher types, stale owner IDs, cycles, and configured-depth exhaustion stay
explicit reasons — never a made-up lock graph. The scan and owner chain are
hard-capped (128 rows, four hops), PDB extraction happens before the RSP stop,
and live validation returned a real synchronization-event wait with no claimed
owner.

### 99. Completed — malformed-PDB and architecture-assumption hardening

Layout derivation now rejects malformed/boolean/implausible offsets, missing or
zero-sized structures, incompatible declared scalar widths, non-zero `_EPROCESS`
`Pcb` embeddings, and non-x64 symbol stores as `SymbolStoreError`. The page
walker rejects non-canonical / LA57 virtual addresses rather than treating them
as four-level x64. Focused malformed-layout and paging-policy tests cover the
refusal paths; live process/thread walks still completed with the active nt PDB.

### 104. Completed — broker-enforced snapshot stop budgets and accounting

Every persistent-reader snapshot carries a hard broker-enforced 15-second,
16,384-read, 16-MiB contract by default. The broker accounts reads and returned
bytes, treats client idle time as part of the stop budget, resumes Windows on
expiry, and returns typed retryable `snapshot_budget_exceeded` evidence instead
of silently stranding the guest. Snapshot results expose the budget, counters,
exhaustion state, and error; the active reader admission shown by doctor also
identifies its budget. Unit socket tests cover read-count and idle-duration
expiry plus guest resume, while live checks record the normal stop accounting.

### Completed final unwind batch (2026-08-24)

| Rank | Item | Ease | ROI | Status |
|---:|---|---:|---:|---|
| 1 | **69 — automatic exact-binary staging** | 4 | 5 | Completed and live-verified with all 17 PING loader entries. |
| 2 | **70 — mixed-mode WoW64 transition-stack stitching** | 1 | 3 | Completed for exact-build validated x64↔x86 transitions. |

Final verification for items 69-70: complete default suite `2544
passed, 5 skipped, 141 deselected`; all 11 direct QEMU RSP integrations; all
three live walk integrations; and the dedicated real-daemon mixed WoW64 test.
That live test automatically staged `PING.EXE`, hit
`wow64cpu!CpupSyscallStub`, returned two identical mixed x64→x86 traces,
detached, and confirmed VM resume. After installing the workspace build and
reloading MCP, the actual endpoints discovered/staged/symbol-enriched all 17
modules with zero warnings or failures, returned the same 19-frame trace (nine
x64 plus ten x86), preserved the explicit boundary and exact build provenance,
and omitted the transition truthfully at depth four. A subsequent x86
`NtDelayExecution` stop retained the established nine-frame hybrid trace.
Detach left no daemon, the gdbstub listening, and qemu-ga responsive.

One finding from the breakpoint work is worth keeping, because it shapes any
future kdbg change: **neither breakpoint mechanism installs on both images.**
Windows 11 runs HVCI by default, which exists precisely to stop the `0xCC`
patch a software breakpoint writes into a kernel code page, so `--mode soft`
cannot work there. Server 2022 has instead been seen exhausting the four
per-vCPU DR0..3 slots, which is the hardware path's ceiling. There is no
`--mode auto` — breakpoints must carry their type explicitly. The failure
messages name the wall you actually hit instead of guessing at one.

### Completed top-five batch (2026-08-23)

This shortlist ranks implementation effort against research payoff while still
putting security and state correctness ahead of convenience. Scores are
relative (`5` is easiest/highest). The first three close correctness holes;
the last two remove repeated agent round-trips and address arithmetic.

| Rank | Item | Ease | ROI | Status |
|---:|---|---:|---:|---|
| 1 | **56 — harden guest-derived module paths** | 5 | 5 | Completed and edge-tested. |
| 2 | **59 — repair decomp mapping edge cases** | 4 | 5 | Completed and edge-tested. |
| 3 | **57 — explicit run/stop epoch + pinned decomp snapshot** | 3 | 5 | Completed and concurrency-tested. |
| 4 | **63 — RVA/symbol inputs and decomp pagination** | 4 | 5 | Completed with API 4 continuation caching. |
| 5 | **54 — one bounded stop-triage response** | 4 | 5 | Completed in daemon, CLI, and MCP. |

### Completed second top-five batch (2026-08-23)

| Rank | Item | Ease | ROI | Status |
|---:|---|---:|---:|---|
| 1 | **67 — machine-safe lifecycle JSON** | 5 | 3 | Completed with narrow-terminal coverage. |
| 2 | **64 — structured, compact MCP evidence** | 4 | 5 | Completed across every `kdbg_*` MCP tool. |
| 3 | **60 — worker API isolation** | 4 | 4 | Completed with protocol-family namespaces. |
| 4 | **53 — typed reads and bounded captures** | 3 | 5 | Completed in predicates/actions and trace metadata. |
| 5 | **41 — durable asynchronous continue** | 3 | 5 | Completed in CLI/MCP with process/socket integration coverage. |

### Completed third top-five batch (2026-08-23)

| Rank | Item | Ease | ROI | Status |
|---:|---|---:|---:|---|
| 1 | **66 — truthful runtime verification** | 4 | 5 | Completed with immutable input snapshots and scoped evidence claims. |
| 2 | **58 — build-keyed PE/symbol publication** | 3 | 5 | Completed with exact-build selection and concurrent atomic publication. |
| 3 | **61 — Ghidra resource controls and request liveness** | 3 | 5 | Completed in worker API 5 and the constrained Docker runtime. |
| 4 | **62 — verified PDB enrichment and provenance** | 3 | 5 | Completed with function-public metadata, naming, and durable recovery provenance. |
| 5 | **65 — cache visibility, pruning, and LRU** | 4 | 4 | Completed through CLI/MCP with legacy-project inventory and dry-run-first pruning. |

Verification: the complete default suite passes (`2443 passed, 5 skipped`),
and the real Docker/PyGhidra integration passes against worker API 5. The final
image runs with a 4 GiB memory ceiling, equal swap ceiling, two CPUs, bounded
logs, and a configurable two-program LRU. Live Server 2025 validation mapped
`services!RQueryServiceStatus` through runtime RVA `0xfae0` to Ghidra RVA
`0xfae0`, matched CodeView GUID+age and current instruction bytes, applied the
verified PDB name without hiding Ghidra's original name, and returned warm
project/decompile-cache hits. The reloaded MCP catalog exposes 75 structured
tools; cache inventory grouped current and legacy projects sharing one SHA,
dry-run pruning selected entries without deletion, and applying while the
worker was live was refused.

### Completed top-three sequence (2026-08-23)

Completed on 2026-08-23. Item 26 remains explicitly accepted/minor and item 8
remains a watched intermittent condition rather than active implementation
work.

| Rank | Item | Ease | ROI | Why next |
|---:|---|---:|---:|---|
| 1 | **17 — SMP correctness audit and live coverage** | 4 | 4 | Completed; tested migration on CPUs 2, 3, and 4 plus same-vCPU stepping. |
| 2 | **12 — real WoW64 detection/module support** | 2 | 4 | Completed; live-tested against a SysWOW64 `cmd.exe`. |
| 3 | **15 — Windows x64 `.pdata` unwinding** | 1 | 5 | Completed; live-tested in kernel and user/RPC stacks. |

The implemented order was 17 → 12 → 15, followed by live edge fixes for unwind
v2 epilogs, discarded image metadata, and hardware-breakpoint stepping.
Final verification passed the complete default suite (`2473 passed, 5 skipped,
140 deselected`), the explicit daemon/socket integration suite (`7 passed`),
and the reloaded MCP live workflow against `services.exe` on vCPU 3. The live
step advanced `RQueryServiceStatus+0x0` to `+0x5` while preserving the hardware
breakpoint, and the metadata-driven trace reached RPC runtime frames before
truthfully stopping at an unstaged exact `ntdll.dll` image.

### 56. Completed — guest-derived module path hardening

`kdbg_user_symbols_load` obtains `FullDllName` and `BaseDllName` from the
target's writable PEB, then `_copy_via_share` interpolates them inside a
single-quoted PowerShell `Copy-Item` command executed by the privileged guest
agent. A hostile process can place a quote in either string and inject
PowerShell. Host-side path containment does not make source-code interpolation
safe. `_resolve_binary` also joins the live module name to `symbols_dir`
without proving the resolved path remains below that directory, so an absolute
or `..`-bearing spoofed name can select an unintended host file before PE
validation rejects or accepts it.

Implemented with UTF-16LE/base64 path data, `-LiteralPath`, strict cached-name
validation, cache containment, random staging/partial names, mode-0600 atomic
publication, and unconditional cleanup. Hostile quote/NUL/traversal, symlink
escape, concurrent same-name, publication failure, and PowerShell-error paths
are covered.

### 57. Completed — explicit debugger state and stop-pinned decomp evidence

`DaemonSession.stop` is populated on a halt but never invalidated before
`cont`, step, step-over, or step-out resumes the VM. `op_status` therefore
reports `halted=true` while execution is in progress, `op_regs` can return the
previous stop's register blob, and failed timeout recovery can leave stale stop
data attached to an indeterminate run state. The mid-`cont` status test proves
the call is serviced but does not assert the `halted` value.

The decomp bridge compounds this: status, RIP, module walk, PE identity reads,
minutes of Ghidra work, and the final live-byte comparison are separate calls.
Another client can continue, step, detach, or stop elsewhere while Ghidra is
running, producing one response assembled from different stops.

Implemented `running|halted|indeterminate`, random `session_id`, monotonic
`stop_id`, resume-time invalidation, epoch-checked memory reads, an atomic
address/module snapshot, and final stop revalidation. Failed recovery clears
stale evidence. Mid-cont status, stale reads, stop changes, invalid coordinates,
and recovery failures are covered.

### 58. Completed — build-keyed, atomic PE/symbol publication

User binaries are published as `symbols/<BaseDllName>`, and decomp binary
resolution searches primarily by basename. A second Windows build, snapshot,
side-by-side DLL, or unrelated executable with the same name overwrites the
first. The PE copy uses `shutil.copy2` directly at the visible destination, so
concurrent readers can also observe a partial or replaced file. The symbol
store points at only one active build even though the Ghidra cache itself is
content-addressed.

Publish verified PEs atomically under a CodeView/build-key or full SHA-256,
persist that PE identity/path beside each symbol-store build, and select it
from the fresh loader identity rather than the filename. Preserve a convenient
basename index only as a lookup hint. Cover same-name/different-build modules,
two snapshots, concurrent publication, interrupted copies, and rollback.
Implemented atomic `symbols/pe/<basename>/<CodeView-build>_<SHA-256>` publication
(full SHA-256 for stripped inputs), build-record PE path/hash and function
metadata, and lock-serialized symbol indexing. Decomp now selects same-name
candidates against live identity and snapshots the winner into immutable
content-addressed storage before parsing and hashing. Concurrent publication
and source replacement are covered.

### 59. Completed — truthful decomp source/assembly edge behavior

Four bounded-output cases need one coordinated fix:

* The worker truncates C at 256 KiB before mapping untruncated Ghidra markup.
  A reproduced exact token on original line 300 was reported as line 100 with
  `candidate_lines=[300]` and no related excerpt line. Map against complete C;
  truncate only the optional `full=true` payload.
* Compact `full=true` omits `analysis.code_truncated`, so callers cannot tell
  that the returned function is incomplete. Surface an explicit warning and
  returned/original byte and line counts.
* The global 512 assembly-association cap stops processing later source lines.
  Those lines then look identical to genuinely unmapped declarations. Return
  `assembly_complete` per line plus the exact truncation line/range.
* If an address is inside a function body but not a decoded instruction,
  `_nearby_instructions` walks to the end and returns the final two function
  instructions as "nearby." Select nearest before/after by address and label
  the requested location as undecoded.

Mapping now always uses complete C while only the optional full-code payload is
truncated with explicit byte/line counts and warnings. Every addressed line
reports `assembly_complete`, truncation names the affected line range, and
undecoded gaps return nearest before/after instructions with an explicit label.
Oversized-code, gaps, cap boundaries, later lines, shared instructions, and all
response detail contracts are covered.

### 60. Completed — worker API migration is isolated across installed clients

Any `DecompClient` whose expected worker API differs from the lock owner sends
`shutdown` and starts its selected version. A stale MCP process can therefore
downgrade an API 3 worker to API 2; a newer CLI then upgrades it again. This
was observed live during the API 3 rollout. Projects survive, but the JVM,
open-program cache, and in-flight work do not.

Namespace sockets, locks, session files, and container names by worker API (or
package protocol family), and garbage-collect old idle versions explicitly.
At minimum, refuse automatic downgrades and return an actionable reload/version
error. Test old/new clients in both call orders and during an active request.
Small-to-moderate effort, high rollout stability payoff.

Implemented protocol-family namespacing for worker sockets, locks, session
records, logs, Docker lifecycle locks, and container names. Old/new API clients
now start independently and preserve one another's JVM/in-flight work. A
worker declaring the wrong API inside a namespace is refused; it is never
automatically shut down or downgraded. Container ownership includes the worker
API label. Immutable binary copies remain full-SHA keyed and durable Ghidra
projects remain Ghidra-version/full-SHA keyed across ordinary worker restarts.

### 61. Completed — bounded resources and request liveness

The container sets a PID cap but no memory, swap, CPU, or Docker log-rotation
limits. Inspection found all compute/memory limits unset; the warm worker used
about 502 MiB before heavy analysis. A hostile or pathological PE can exhaust
the host, while three ordinary cached projects already consume 268 MiB.

The serialized worker also performs a blocking `recv()` with no request-read
deadline. One client that connects and never finishes a JSON line wedges every
status/decomp request. A client timeout closes only its socket: Ghidra keeps
analyzing, retries can queue duplicate work, `shutdown` cannot be processed
until the analysis finishes, and Docker eventually may SIGKILL a project being
written.

Add configurable memory/CPU limits, log rotation, a short request-read timeout,
request IDs, current-operation status, disconnect-aware cancellation where
Ghidra permits it, and deduplication by binary/function/options. Make forced
termination and corrupt-project recovery explicit and tested. Moderate effort,
high stability payoff for hostile-input research.

Worker API 5 now correlates request IDs, bounds half-open reads to five seconds,
publishes active operation/elapsed time, records client-timeout cancellation,
and bounds a configurable open-program LRU. Docker defaults to 4 GiB RAM, an
equal swap ceiling, 2 CPUs, rotating 10 MiB logs, and a bounded stop timeout.
Protocol, timeout, cancellation, and configuration edges are covered.

### 62. Completed — verified PDB enrichment and durable provenance

The PDB currently proves identity and supplies one nearest-public hint; it is
not imported into Ghidra and does not enrich function/global names, prototypes,
or types. Agent output consequently contains `FUN_*`, `DAT_*`, and `param_*`
even when an exact cached PDB exists. Public parsing also discards the PDB
`function` flag, so the nearest symbol used for recovery is not guaranteed to
be a function.

Recovery then mutates the durable Ghidra project. The first query labels a
created function `pdb-public-recovery` or `pdb-public-split-recovery`, but the
next query finds it through `getFunctionContaining` and reports ordinary
`analysis`, permanently laundering an inferred boundary into an analyzed one.

Import the identity-matched PDB where practical, or apply the existing verified
public/type maps through a versioned analysis profile. Retain function flags,
persist winbox recovery provenance in program properties or a sidecar, and
include the analysis-profile version in project cache keys. Never present a
synthetic boundary as native analysis on reuse. Moderate-to-large effort, very
high decompiler-quality payoff.

PDB parsing now retains the exact-build `function` flag. Only verified function
publics may create missed boundaries; agent output prefers their verified names
while retaining the Ghidra name/source. Synthetic recovery provenance persists
across reopen/restart, and analysis profile v2 is part of project identity.

### 63. Completed — direct coordinates and stop-bound continuation

Mapped pseudocode may display `CALL 0x140010580`, a Ghidra preferred-base VA,
while `kdbg_decomp(addr=...)` accepts only a live runtime VA. Feeding the output
back into the tool fails or targets the wrong coordinate. Agents also cannot
request a symbol or `module+rva` directly.

`lines="1-22"` returns neither total line count, `has_more`, nor `next_start`.
Paging therefore requires speculative calls, and every page repeats the loader
walk, PE parsing/hashing, identity checks, and `decompileFunction` call.

Implemented direct symbol and fresh-loader `module+rva` resolution, labelled
flow targets, total/remaining line metadata, and a bounded opaque cursor tied
to binary SHA, Ghidra version/profile, function RVA, session, and stop. API 4
keeps up to 32 successful function decompilations per open program so later
pages avoid another `decompileFunction` call while still revalidating live
identity. Malformed/oversized/forged/stale cursors and coordinate conflicts are
covered.

### 64. Completed — compact structured MCP responses and actionable errors

A live 68-line mapped response occupied 21,443 bytes. Compact JSON plus omission
of repeated per-instruction `va` and `bytes` fields was 9,973 bytes, a 53.5%
reduction. MCP still pretty-prints JSON, repeats runtime VAs derivable from one
module base plus RVA, and always includes raw instruction bytes. At the same
time, success is JSON but failure is a prose string prefixed with `error:`.
Agents cannot reliably distinguish missing prerequisites, worker busy, stale
stop, identity mismatch, timeout, or corrupt cache.

Every `kdbg_*` MCP tool now returns a versioned `winbox.mcp/1`
`{schema,ok,result,error}` structured object. Errors have stable codes,
retryability, operation names, bounded messages, and at most three recovery
hints. Decomp schema 5 omits raw instruction bytes and repeated runtime VAs by
default; both remain explicit opt-ins. Interactive CLI output stays readable.

### 65. Completed — cache inventory, dry-run pruning, and configurable LRU

There is no cache inventory, byte count, age, pruning, or size policy. The live
validation cache contains three projects totaling 268 MiB, including one
202 MiB project. `MAX_OPEN_PROGRAMS=1` bounds RAM but repeatedly closes and
reopens projects when an agent alternates across an EXE, RPC runtime, and system
DLLs.

Expose per-project SHA/build/name, size, last-used time, analysis profile, and
open state. Add explicit prune/dry-run operations and an optional total-size
LRU. Replace the fixed one-program slot with a configurable memory-aware LRU;
keep one as the safe low-memory default. Moderate effort, medium-to-high
long-session efficiency payoff.

CLI/MCP inventory now reports SHA, original name, project/profile, Ghidra
version, size, presence, and LRU order. Age/size pruning previews by default,
validates exact paths, and refuses selected deletion while the worker is live.
The warm-program LRU defaults to two and is bounded from one through four.

### 66. Completed — truthful build and instruction verification

Compact output hardcodes `verified.exact_binary=true`. What is actually proven
is a matching CodeView build (or weaker machine/timestamp/image-size tuple), a
host-file SHA for the analyzed copy, and—when a current decoded instruction
exists—one live/static instruction comparison. Runtime patches elsewhere in
the function are not checked, and ordinary base relocations can make the one
comparison warn without distinguishing relocation from mutation. Static PE
metadata and the later SHA are also collected through separate path opens, so
a concurrent replacement can combine headers from one file with a hash from
another.

Rename the claims to `build_identity_match`, `analyzed_file_sha256`, and
`current_instruction_match`; report `not_checked` explicitly. Snapshot/copy the
host PE once before parsing and hashing. A later enhancement can compare all
function bytes while masking verified PE base relocations, producing bounded
changed ranges. Moderate effort, high evidence-honesty payoff.

Schema 5 now reports `build_identity_match`, `identity_method`,
`analyzed_file_sha256`, and three-state `current_instruction_match`; it no
longer claims whole-binary runtime equality. Inputs are snapshotted once into
immutable content-addressed storage before PE parsing and hashing.

### 67. Completed — Ghidra lifecycle JSON is pipe-safe at narrow widths

`winbox kdbg decomp-status` and `winbox kdbg ghidra status` serialize JSON and
then send it through Rich. At `COLUMNS=40`, both reproduced
`Invalid control character` when piped into `python -m json.tool`, because Rich
wraps inside JSON string values. `kdbg decomp` already fixed this exact defect.

All decompiler lifecycle/status JSON now bypasses Rich wrapping through
`click.echo`. Pipe tests run at `COLUMNS=20` with long string values and cover
decomp status plus Ghidra install, run, stop, and status.

### 53. Completed — typed reads and bounded action-only buffer capture

The expression language reads only unsigned little-endian qwords. Masking a
qword can approximate a byte/dword, but it is wrong at page boundaries and
cannot capture the buffers, strings, lengths, and narrow fields that dominate
IOCTL/RPC/parser research.

Predicates/actions now support exact-width `byte()`, `word()`, `dword()`, and
`qword()` reads. Actions additionally support `bytes()`, `ascii()`, and
`utf16()` captures with a 256-byte expression cap, 1024 raw bytes per hit,
16 MiB per trace, and 16 actions per breakpoint. Captures are rejected in
conditions and nested scalar expressions; batching, candidate retry,
short-circuiting, and page-boundary behavior remain covered.

### 41. Completed — durable asynchronous continue jobs

The cont tool blocks for up to `timeout` seconds. The daemon already services
`interrupt` and `status` through `_pump_client`, but the initiating MCP request
remains occupied. That is especially awkward for an AI agent waiting on a rare
breakpoint: it cannot naturally poll progress, inspect accumulating action
traces, or survive an MCP transport restart.

`kdbg_cont_start` now launches a detached host worker and immediately returns a
durable token; `kdbg_cont_poll` and `kdbg_cont_cancel` can be used by a newly
started MCP process. Jobs pin the daemon session, persist bounded mode-0600
state atomically, reject concurrent starts, detect dead workers, and handle
cancel/completion and spawn/exec races. Interrupt and detach cancel active jobs
before operating on the daemon.

### 54. Completed — bounded one-call stop triage

After a breakpoint or exception, an AI must separately request registers,
nearby disassembly, stack qwords, the heuristic backtrace, breakpoint metadata,
and often pointed-to memory. The halt is stable, but the repeated protocol
round-trips waste time and context, and agents frequently omit one of the
pieces needed to reason about the stop.

`kdbg_context` now returns an epoch-pinned target/stop, registers, symbolized
RIP and branch targets, architecture-correct nearby assembly and stack, Windows
x64 metadata or WoW64 x86 hybrid backtrace, and bounded breakpoint metadata.
Callers may request at most four
memory follows, 256 bytes each and 1024 bytes total. Zero-sized components,
bad integer/bool inputs, missing stop state, unreadable evidence, and every cap
are covered in daemon/MCP/CLI tests.

### 12. Completed — real WoW64 detection and 32-bit module support

Detection now follows `_EPROCESS.WoW64Process` to `_EWOW64PROCESS.Peb`. The
walker handles PEB32, 32-bit pointers, bounded UNICODE_STRING32 values, corrupt
cycles, zero/invalid pointers, and both native and x86 loader views. Results
carry `architecture`; the duplicate native-view main EXE is removed, same-name
x86/x64 DLLs remain explicit, auto symbol loading refuses ambiguity, and x86
stores use a separate `<module>_x86` key. Live Server 2025 validation against
`C:\Windows\SysWOW64\cmd.exe` returned the x86 executable plus x86 ntdll,
KERNEL32, KERNELBASE, ucrtbase, and sechost beside the native WoW64 support
DLLs. The native services process remained x64-only.

### 26. kdbg read-surface residuals from the 2026-08-10 audit (partly fixed / minor)

Two findings came from the read-surface audit:

* **Fixed 2026-08-27 — exact IPv6 listener matching.** `_listening_sockets`
  now decodes Linux tcp6's four little-endian words into a real IPv6 address,
  ignores malformed rows, and `probe_port` matches only within the requested
  address family (including that family's wildcard). Unit edge cases and a
  real IPv6-only listener verify that `::1` no longer makes `127.0.0.1` appear
  occupied.
* **`DirectoryTableBase` is recorded with no sanity check** (`walk.py`) while
  the adjacent `UserDirectoryTableBase` gets a page-aligned/`<2^52` guard. This
  is the same class as item 18 (offset assumptions with no runtime check).
  Unlike `user_dtb`, the primary `dtb` has no safe fallback (0 is useless), and
  a wrong `DirectoryTableBase` offset breaks the whole store loudly elsewhere,
  so a targeted guard here is low-value — folded into item 18.

### 15. Completed — Windows x64 `.pdata` unwinding

`kdbg_bt` and `kdbg_context` now parse PE32+ exception directories,
RUNTIME_FUNCTION entries, unwind v1/v2 xdata, chained records, prolog state,
nonvolatile saves, frame registers, small/large allocations, machine frames,
and bounded v2 epilog instruction sequences. Leaf functions pop the ABI return
slot; malformed/unsupported metadata returns an explicit partial trace instead
of falling back to candidate-address scanning.

Metadata comes from live mapped images when present. Windows decommits
discardable `.pdata` in user processes, so the fallback requires a hash-bound
cached PE and validates its machine, timestamp, SizeOfImage, and CodeView key
when the RSDS page remains mapped; if RSDS was also discarded it reports the
weaker header-identity confidence. Stack values always come from the pinned
live stop. Live kernel validation produced the complete
HalProcessorIdle → PpmIdleDefaultExecute → PpmIdleExecuteTransition → PoIdle →
KiIdleLoop chain. Live user validation at `services!RQueryServiceStatus`
produced 13 exact services/RPCRT4 frames before truthfully stopping at an
uncached ntdll image.

### 17. Completed — SMP correctness audit and four-vCPU live coverage

All silent `sr.thread or "01"` fallbacks are gone. T-stop vCPU ids are
syntax-checked; minimal S-stops resolve through RSP `qC`; explicit step targets
remain authoritative; snapshots reject a stop CPU absent from the enumerated
set (while accepting equivalent zero padding). Breakpoint migration tests prove
that unrelated-CR3 hits on one CPU cannot make the accepted hit sample another
CPU's registers, and accepted hits no longer send a redundant second `Hg`.

QEMU's all-stop four-vCPU behavior was verified live: the same user hardware
breakpoint fired correctly on vCPUs 2, 4, and 3 across separate runs, with the
target CR3 and stop epoch preserved. Single-step stays on the firing CPU.
Because QEMU checks Z1 before instruction execution, stepping at the breakpoint
now temporarily removes that exact hardware execution breakpoint, steps once,
and reinstalls it; live RIP advanced from `services+0xfae0` to `+0xfae5` on
vCPU 3 and the breakpoint remained installed with its hit count intact.

### 68. Completed — conservative WoW64 x86 hybrid unwinding

`kdbg_bt`, `kdbg_context`, stack display, disassembly, step-over, and step-out
now switch to x86 semantics at a compatibility-mode (`CS=0x23`) stop. Exact
build PDB old-FPO and modern frame-data records are extracted with
`llvm-pdbutil`, persisted with their original programs, and classified into a
finite safe recipe set. The walker prefers those records, then strict monotonic
EBP chains, then bounded straight-line prologue simulation. A PDB-directed
return search is bounded and call-site validated; ordinary stack hits remain a
separate `confidence=candidate` list and are never silently promoted to frames.

Live testing found and fixed three prerequisites: 64-bit PowerShell bypassed
WoW64 redirection and copied the x64 System32 image, so x86 loads now translate
System32 to SysWOW64 and verify PE machine plus live SizeOfImage; QEMU's
full-register `G` packet loses hidden compatibility-mode state, so active-CR3
reads and unchanged snapshot restores issue no redundant `G`; and attach-time
ASLR validation keys same-name native/x86 modules by architecture rather than
letting two `ntdll.dll` images overwrite one another's bases.

Live Server 2025 validation stopped SysWOW64 `PING.EXE` at
`ntdll_x86!_NtDelayExecution@8` on vCPU 3 and produced nine repeatable frames:
`NtDelayExecution` → `RtlDelayExecution` → `SleepEx` → `Sleep` → two
`PING!wmain` frames → `BaseThreadInitThunk` → two `RtlUserThreadStart` frames.
The trace combined old FPO, modern frame data, EBP, and verified PDB identity;
it stopped truthfully at the zero root and exposed only two residual stack
candidates. Repeated context/stack/backtrace reads stayed stable, x86
step-over crossed `call edx`, x86 step-out reached its caller, and the original
hardware breakpoint remained installed. Final verification passed the complete
default suite (`2512 passed, 5 skipped, 140 deselected`), all eleven direct
QEMU RSP integrations, and all three repeated/parallel live walk integrations.

### 69. Completed — immutable automatic exact-binary staging

Before the debugger daemon takes QEMU's single RSP connection, attach now walks
both loader views, bounds module count/per-image/aggregate size, copies each PE
through inert base64/`LiteralPath` handling, verifies architecture and live
SizeOfImage, and freezes content-addressed path/hash/build provenance. Matching
PDB publics and x86 frame data are enriched automatically; missing PDBs leave a
usable exact PE and a bounded per-module warning instead of failing attach.
Copy failures also remain in the immutable loader inventory, allowing live
metadata to keep working without pretending an exact static artifact exists.
The daemon uses that inventory for user unwind and exact staged artifacts for
discarded `.pdata`, while live headers/CodeView still validate that the mapped
image is the same artifact. Summary counts remain exact while failure and
warning detail arrays and strings are capped.

Live SysWOW64 `PING.EXE` staging captured all 17 native/x86 loader entries,
symbol-enriched all 17, copied 11.3 MB, and reported zero failures. The cold
path took 36 seconds while fetching previously absent PDBs; the fully warm,
revalidated path took 11 seconds. Newly discovered NSI/IPHLPAPI artifacts then
contributed real frames without any manual `kdbg_user_symbols_load` call.

### 70. Completed — exact-build bidirectional WoW64 transition stitching

The bridge does not trust a fixed Windows-build offset table. It requires the
exact manifest/PDB pair for `wow64cpu.dll`, locates `RunSimulatedCode` and
`CpupReturnFromSimulatedCode`, decodes their x64 instruction streams, and
derives the TEB CPU-area pointer, context bias, saved EIP/ESP/EBP/EBX fields,
and native/x86 stack exchange relationship. Live recovery accepts R13 or a
TEB64 self-pointer-validated CPU area, then requires a module-backed EIP and a
bounded aligned ESP before invoking the existing conservative x86 walker. A
changed build/pattern/context preserves the native trace and reports
`transition_error` rather than fabricating a boundary.

Live Server 2025 validation stopped at `wow64cpu!CpupSyscallStub` and produced
one repeatable 19-frame `windows-wow64-mixed` trace: nine x64 frames through
wow64cpu/wow64/native ntdll, followed by ten x86 frames through
`NtDeviceIoControlFile`, NSI, IPHLPAPI, PING, kernel32, and x86 ntdll. The
transition record named exact build `359FC42CD05DC3DAEF1A6B476716FB481`,
instruction-derived layout, R13 context `0x70fc00`, saved EIP `0x772c846c`,
and saved ESP `0x74eec8`. Repeated traces were identical; bounded depth omitted
the bridge truthfully; ordinary x86 `NtDelayExecution` unwinding remained
unchanged afterward.

The reverse direction no longer depends on QEMU exposing hidden compatibility-
mode registers. At an arbitrary x86 stop, exact nt PDB layouts resolve the
firing CPU's KPCR, current KTHREAD, and persisted x64 user trap frame. Recovery
requires KPCR self identity, target EPROCESS identity, kernel-stack containment,
native TEB self identity and stack bounds, x64 CS, an exact-manifest
`wow64cpu` RIP, and an initial unwind into suspended `wow64cpu` code. The
already-returned syscall-stub frame is discarded before appending the live
native callers at `boundary=wow64-x86-to-x64`; no stack scan is used.

After hard-reset recovery from the unsafe first prototype, the corrected
read-only implementation passed the real-daemon integration against
SysWOW64 `PING.EXE`: the original x64→x86 trace remained repeatable, an
arbitrary x86 `NtDelayExecution` stop produced a repeatable x86→x64 mixed
trace, detach resumed the VM, qemu-ga remained responsive, and the gdbstub was
listening. After installing the workspace build and reloading MCP, the public
endpoints reproduced a complete 17-frame trace (nine x86 plus eight x64) with
the boundary at `wow64cpu!ReadWriteFileFault+0x31`, exact build provenance,
and `context_source=current-kthread-trap-frame`. A second depth-24 call was
identical, depth ten returned exactly nine x86 frames plus the first x64
boundary with a truthful depth-limit result, and `kdbg_context` returned the
same mixed trace from the pinned stop. Final detach resumed the VM; Windows
10.0.26100.1742 answered through qemu-ga and the gdbstub was listening. The
complete default suite passes (`2544 passed, 5 skipped, 141 deselected`).

### 71. Completed — poison-safe detach without out-of-band resume

A failed CR3 restore correctly poisons the daemon because resuming that vCPU
can immediately bugcheck the guest. The dispatch guard then rejects every
operation except `status`, including `detach`, even though its error tells the
operator to detach. Both CLI and MCP detach suppress the resulting client
error, wait for a lock that cannot be released, and unconditionally call
`ensure_not_paused`. That recovery helper may continue through a second GDB
connection or `virsh resume`, bypassing the poison barrier and running the
known-bad CR3. The same out-of-band resume is unsafe whenever a still-live
daemon is stuck inside any CR3-sensitive operation.

Implemented on 2026-08-25. Status and detach now expose `cr3_poisoned`,
`resume_safe`, permitted operations, and explicit recovery. Poisoned and
indeterminate teardown close ownership without RSP cleanup or resume. CLI and
MCP call `ensure_not_paused` only after the daemon is gone and its detach reply
explicitly certified resume safety. Breakpoint cleanup runs before that
certificate, closing the edge case where user-software-breakpoint removal
itself fails to restore CR3. Unit coverage proves clean, poisoned,
transport-error, and cleanup-time-poison paths; real JSON-line socket coverage
proves the poison-safe response crosses the transport unchanged.

### 72. Completed — one enforced debugger run-state operation matrix

`running|halted|indeterminate` is recorded, but enforcement remains local and
incomplete. `_require_stop_epoch` deliberately lets an unpinned memory read
continue when state is indeterminate and no stop exists, for compatibility
with tests/custom embedders; a production daemon always captures its initial
stop before serving, so that escape hatch is unsafe after failed recovery.
`write_mem`, breakpoint insertion/removal, and `cont` also lack one central
halted-state policy and can issue RSP traffic when execution or stream state is
unknown.

Implemented on 2026-08-25. Dispatch now owns one operation matrix: a proven
halt permits normal operations; running permits status, interrupt, passive
breakpoint/trace reads, and detach; indeterminate permits status, complete
interrupt recovery, and safe detach; poison permits only status and detach.
The pre-stop memory fallback is gone, writes require a stop, passive reads can
cross the busy socket boundary, and a standalone interrupt must drain and
capture a fresh stop before restoring normal access. Tests cover all operation
families, an already-halted no-op, active-continue queuing, successful recovery,
failed recovery, unknown-state shutdown, and real-socket enforcement.

### 73. Completed — preserve a truthful halt at filtered-stop timeout

After QEMU reports a breakpoint in an unrelated CR3, or a target hit fails its
predicate, `op_cont` silently filters it and returns to the top of its loop.
If handling that stop consumed the remaining deadline, the top-level deadline
branch returns `{reason: timeout}` without capturing the stop or resuming.
QEMU is physically halted, while the daemon reports `run_state=running` and
`stop=None`. This was reproduced with a deterministic clock; the current tests
cover ordinary timeout recovery and silent filtering separately but not their
deadline boundary.

Implemented on 2026-08-25. Budget expiry after a received stop now captures
that stop from the already-read register blob and returns the normal halt
summary/epoch with `reason=timeout`; interrupt-and-drain remains limited to a
timeout while QEMU is running. Deterministic-clock tests cover an unrelated
CR3, a false predicate, action auto-continue, and expiry before another resume.
Every branch now leaves `run_state=halted`, a non-null stop, and truthful target
membership in the returned summary.

### 74. Completed — cancellable asynchronous Ghidra analysis and offline prewarming

The public timeout bounds `decompileFunction`, but the client allows another
840 seconds for first-use work. Cancellation checks bracket `_open`, while
`_open` calls `open_program(..., analyze=True)` synchronously; the cancellation
watcher is created only afterward around `decompileFunction`. Cancelling or
disconnecting during import/auto-analysis therefore leaves the one serialized
worker busy, and forced container stop can kill a project mid-write. A normal
first query also keeps the VM halted for minutes to perform work that does not
need a live stop.

Split import/analysis/decompile into durable request phases with separate
budgets, progress, and cancellation where Ghidra permits it. Add
`kdbg_decomp_prepare(module|all)` to analyze exact staged artifacts while the
VM runs, plus attach-time optional background prewarming. Preserve completed
cache work if the live stop changes, but make the eventual live mapping and
byte check a short stop-pinned operation. Test disconnect, cancel, worker
restart, forced termination, stale-stop completion, and cold/warm latency.
Large effort, very high stability and usability payoff.

Implemented on 2026-08-27 in worker API 6. Import, analysis, enrichment,
decompilation, mapping, and saving publish distinct heartbeat phases. Ghidra
auto-analysis runs under a cancellable task monitor with its own 5-1800 second
budget; exact request markers handle explicit cancellation and client
disconnects. A cancelled/terminated partial project is retained without being
marked analyzed, so the next exact request resumes it rather than deleting or
trusting incomplete work.

`kdbg_decomp_prepare(module|all)` and `winbox kdbg ghidra prepare` perform exact
PDB extraction/import/analysis while the VM runs. Detached jobs persist a
bounded token/status record, attach has opt-in `prewarm`, and warm live queries
reuse the completed project. Tests cover phase monitors, cancellation,
timeouts, exact request identity, disconnect markers, invalid budgets,
background option forwarding, warm reuse, cache residue/rebuild, Docker
isolation, and real PyGhidra. Live cold/cancel/resume and background workflows
completed without stopping the running Server 2022 VM.

### 75. Completed — corrupt-project reset and deterministic rebuild

Implemented on 2026-08-26. A bounded corruption classifier separates malformed
or truncated Ghidra project state from permissions, cancellation, resource
exhaustion, and other ordinary open failures. Proven corruption deletes only
the exact digest/profile-keyed `.gpr`, `.rep`, `.lock`, and `.lock~` entries,
retains and revalidates the hash-addressed binary, and attempts exactly one
clean rebuild under the existing project lock. A second failure returns typed
`cache_rebuild_failed`; reset failures are typed and partial deletion is
reported rather than hidden. There is no backup or alternate cache area.

`winbox kdbg ghidra repair --sha256 DIGEST` and
`kdbg_decomp_cache_repair(sha256)` provide the same exact operation explicitly.
Tests cover truncated metadata, malformed and repository-only forced-kill
residue, lock remnants, partial reset, failed rebuild without looping,
non-corruption failures without deletion, digest validation, symlink refusal,
retained binary identity, CLI/MCP forwarding, and real Docker/PyGhidra rebuild
and reuse.

### 76. Completed — serialize Ghidra cache maintenance with worker lifecycle

Applied pruning inventories entries, checks `worker_alive()`, and then deletes
projects and binaries. Worker startup/project open does not share that lock, so
a request can start after the point-in-time check and race deletion. Automatic
budget enforcement has the same maintenance path immediately before startup,
and concurrent callers can interleave those decisions.

Implemented on 2026-08-25. One protocol-family flock now spans staged inputs,
automatic budget enforcement, host/container startup, every mutating worker
transaction, backend migration, and applied pruning. It is re-entrant within a
thread, serialized across local threads and processes, and treats kernel flock
ownership—not stale file contents—as authoritative. Applied prune inventories,
checks worker ownership, and deletes under the same lock; dry-run inventory
stays concurrent. Tests cover start-vs-prune, project-open-vs-prune, concurrent
starters, nested acquisition, stale files, process death, and live refusal.

### 77. Completed — bounded and reaped debugger child-process lifecycle

The interactive daemon and persistent reader both use a direct `os.fork` and
make the parent block on an unbounded status-pipe read. Neither path registers
or calls `waitpid`. A long-lived MCP parent can therefore retain exited daemon
or reader zombies, and a child wedged during symbol/bootstrap/RSP setup can
block attach or the first read indefinitely. CLI parents normally exit soon,
which hides the lifecycle defect.

Implemented on 2026-08-25. Both fork paths use a shared supervisor with an
absolute startup deadline, 64-KiB status cap, exact-child termination, and
synchronous failure reaping; successful long-lived children get a dedicated
background `waitpid` reaper. Startup SIGTERM/SIGINT unwinds through each
child's safe cleanup path, and reader handshake failure best-effort resumes
before raw close. Real-process tests cover success, explicit error, timeout,
oversized status, parent cancellation, already-reaped/PID-reuse safety,
process death, and repeated children without zombies.

### 78. Completed — CLI parity for watchpoints, actions, and trace queries

The daemon and MCP expose hardware watchpoints, typed predicates, bounded
action captures, and paged/filtered trace queries. The interactive CLI `bp`
surface accepts only execution mode and condition, and there is no CLI
`bp-trace`, so operators must switch to MCP or write protocol calls for shipped
features.

Implemented on 2026-08-25. `kdbg bp` now supports `--watch`, shared validated
sizes, repeatable `--action`, conditions, and readable watch/action results;
`kdbg bps` labels watchpoint kind and width. New `kdbg bp-trace` exposes bounded
tail/cursor/filter/error/summary/top queries, compact human rows, continuation
metadata, and `--json` output that bypasses Rich wrapping. Protocol constants
are shared with daemon validation. Unit tests cover exact forwarding, repeated
actions, watch widths, ignored execution-bp size, every query bound, compact
rendering, JSON parseability, and watchpoint list rendering; the existing real
daemon-socket trace integration covers the backend query path.

### 79. Completed — typed errors from daemon and worker through MCP

The MCP envelope advertises stable error codes, but daemon and PyGhidra worker
errors are prose. `_research_error` infers categories from substrings such as
`busy`, `timeout`, `stale`, and `not found`; wording changes or an incidental
word can silently change retryability and recovery advice. Worker protocol
version mismatch is structured only indirectly through its message.

Implemented on 2026-08-26. Daemon and worker replies retain the legacy `error`
string and add a validated `winbox.error/1` object containing stable code,
message, retryability, and bounded details. New clients preserve that object
through CLI rendering and MCP; old peers remain readable, and new clients use
the bounded `operation_failed` fallback for old string-only replies. Producer-
side classifications cover state, poison, argument, timeout, transport,
identity, cancellation, worker lifecycle, and generic failures without message
keyword inference. Tests cover mixed peers in both directions, misleading
keywords, malformed schemas, oversized messages/details, and real JSON-line
daemon/worker transport.

### 80. Completed — non-blocking decompiler status with phase and progress

While the serialized worker is analyzing, status first attempts to queue an
API request and waits five seconds before declaring the worker busy. The
session sidecar names only the current operation and start time, so it cannot
distinguish staging, JVM startup, import, auto-analysis, decompilation,
mapping, cancellation, or project save. Operators see a delay followed by
little evidence about whether progress is healthy.

Implemented on 2026-08-26. A dedicated worker heartbeat publishes atomic
session snapshots while the serialized request thread is inside JVM startup,
project import/analysis, decompilation, mapping, or save. Status reads only
that bounded sidecar and returns immediately with health, request/phase elapsed
time, last-progress age, coarse phase progress, cancellation state, safe binary
identity, worker/JVM state, and redacted last failure. It never queues a worker
API call. Fresh, stale, legacy, invalid, and dead-worker sidecars are classified
explicitly. A real-process integration holds the worker in a two-second JVM
phase, observes status in under 0.5 seconds, and sees cancellation transition to
`requested` without leaking the supplied host path.

### 81. Completed — targeted cache removal and accounting reconciliation

Cache inventory is useful, but mutation selects only by aggregate byte target
or age. Recovering one known-bad digest, removing one obsolete build, or
reclaiming an unexpectedly large entry requires contrived limits. Aggregate
usage also includes unowned metadata/log/temporary overhead that per-entry
sizes cannot reclaim, so `estimated_remaining_bytes` may not reach the
requested ceiling without explaining why.

Implemented on 2026-08-26. CLI and MCP pruning accept repeatable exact SHA-256,
project, and case-insensitive module selectors in addition to age/LRU limits.
Inventory accounts for binaries, verified snapshots, metadata, provenance,
projects, repositories, and project lock files per entry; it reports owned and
overhead bytes plus a bounded, relative-path-only unattributed-file inventory.
Prune results expose unmatched selectors, remaining owned/overhead bytes, and
the residual above `max_bytes`. Preview remains the default, applied selection
is recomputed under item 76's maintenance lock, and a live worker still blocks
all deletion. Tests cover exact union behavior, malformed selectors, symlink
escapes, corrupt/non-finite LRU metadata, bounded unattributed output, targeted
apply, live refusal, concurrency, and unreclaimable overhead.

### 82. Completed — observable and selectable attach-time artifact staging

Implemented on 2026-08-26. Attach accepts `full`, `binaries`, or `cached-only`.
`full` remains the default and preserves copy plus symbol enrichment;
`binaries` copies exact guest images but only reuses existing symbols; and
`cached-only` performs no guest copy or network download, accepting only
self-consistent hash-bound store artifacts. Every frozen manifest records its
policy and per-module artifact source, so later unwind provenance stays honest.
CLI and MCP return bounded per-module progress, failures, truncation, and
elapsed time. `--preflight` freezes only the bounded loader inventory and
predicts work without copying, downloading, mutating types, or attaching.
Tests cover all policies, unchanged default behavior, invalid policy before
guest work, callback and copy interruption, partial completion, bounded
progress, cached misses, and later full enrichment. All three policies and the
non-mutating preflight were also exercised against the live Server 2022 VM.

### 83. Completed — target-liveness and exit diagnostics

Implemented on 2026-08-26. Attach captures the target EPROCESS and optional
exact-PDB `_EPROCESS.CreateTime`; the process walker also exposes `ExitTime`.
`kdbg target-status` and `kdbg_target_status()` perform a bounded advisory
identity probe and return `alive|exiting|gone|unknown`. They compare the
original object and create time against both the active list and a direct read,
so an unlinked exiting process remains identifiable and a reused numeric PID is
reported as replacement evidence without rebinding the debugger session.
Every continue timeout path includes the same evidence, including CR3,
predicate, and action filtering. Tests cover live, unlinked/exiting, gone, PID
reuse, unreadable/unknown, running-state refusal, optional PDB fields, and all
timeout renderers. Live target termination returned `exiting` with the captured
EPROCESS and nonzero exit time.

### 84. Completed (bounded first phase) — deeper exact-PDB enrichment for Ghidra

Exact PDB function-public flags and durable synthetic-boundary provenance now
improve names without laundering inferred analysis. Ghidra still receives few
of the types, globals, prototypes, parameter names, and data symbols already
available in exact Microsoft PDBs, so pseudocode retains avoidable `FUN_*`,
`DAT_*`, and weak signatures.

Build a versioned, bounded enrichment profile that imports verified symbols
and types where the PDB parser can prove identity and semantics. Record every
applied source and conflict, preserve Ghidra originals, include the profile in
project identity, and make the cost separately controllable during prewarming.
Start with function signatures and named globals before broad type graphs.
Large effort, high analysis-quality payoff.

Implemented on 2026-08-27 as profile `winbox-pdb-enrichment-v3`. The host
extracts a hash-bound, size/count-capped sidecar from the exact cached PE/PDB;
only a finite primitive/pointer signature grammar is accepted. The isolated
worker applies exact public/private function names, safe signatures, and named
globals while preserving non-default Ghidra names and signatures. Project
identity includes the profile. Every applied, reused, invalid, or conflicting
decision and its source is atomically persisted in a digest-keyed bounded
provenance record. Broad recursive type graphs and heuristic parameter recovery
remain deliberately outside this first profile rather than being presented as
exact evidence.

Unit cases cover malformed/truncated signatures, pointer/parameter limits,
section RVA conversion, changed PE identity, sidecar bounds/symlinks, conflicts,
and atomic provenance. A stripped real Docker/PyGhidra fixture verifies one
signature and named global actually alter decompilation. Microsoft's public
`services` PDB exposed no procedure type records, truthfully producing zero
signatures while still applying 1,417 function names and 1,716 globals.

### 85. Completed — enrichment cache ownership and exact pruning

The v3 input sidecars and per-decision result provenance were introduced after
cache accounting was reconciled, so they appeared as global overhead and
survived exact SHA/module/project pruning. A live inventory reproduced four
unattributed files totaling 1,842,202 bytes.

Digest-suffixed enrichment, enrichment-result, and recovery-provenance files
now belong to the same entry as its immutable binary and projects. Orphan
sidecars without metadata still create a digest-addressable inventory entry.
Exact applied pruning removes only matching regular files, refuses symlinks,
and leaves other digests untouched. Unit coverage exercises accounting,
orphan discovery, dry-run estimates, exact apply, unrelated files, and symlink
boundaries. The same live inventory now reconciles every byte with zero
unattributed overhead.

### 86. Completed — truly bounded PDB extraction

The old `subprocess.run(capture_output=True)` checked the 64-MiB limit only
after `llvm-pdbutil` had allocated its complete output. The nominal cap did not
bound memory, and timeout/interrupt cleanup depended on the convenience API.

Extraction now concurrently drains stdout and stderr while retaining at most
their explicit caps. Overflow, timeout, caller cancellation, interruption, and
abnormal pipe lifetime terminate and deterministically reap the exact child;
stderr remains bounded for diagnostics. Real-process tests cover success,
output amplification, oversized stderr, nonzero exit, timeout, cancellation,
and reaping. Live forced extraction of the exact `services` PDB completed
through this path with unchanged enrichment evidence.

### 87. Completed — durable prepare-job lifecycle

The first detached job record carried a token and PID but no process birth
identity or heartbeat. A killed/reused child could leave `starting`/`running`
forever; active cancellation addressed only a worker request ID, and terminal
records/logs accumulated without a bound.

Version-2 records bind token+nonce to PID plus `/proc` start ticks and publish
one-second heartbeats with the current exact worker request. Status detects
dead/reused launchers and children and atomically marks them `lost`.
`kdbg_decomp_cancel(token=...)` and CLI `ghidra cancel --token` use a nonce-bound
marker that the child forwards only to its own request; cancellation also
interrupts bounded PDB extraction before Ghidra starts. Signals use the same
cooperative path. Terminal jobs are capped at 128/30 days on subsequent starts,
while active and untrusted/symlink records are never removed. Tests cover
starting/running/terminal states, PID reuse, real child death, marker identity,
mutually exclusive selectors, exact request forwarding, cancellation cleanup,
retention pairs, and CLI/MCP envelopes. Live cold cancellation and safe partial
project resume both completed.

---

## Fixed

*`git log` is the authoritative record. This section exists so the roadmap
is self-contained — readers don't have to search git for "was this done?"*

**9.** `kdbg_cont` timeout recovery was made to re-halt before returning. See
commit `a2373bc`. The 2026-08-23 audit found the separate run-transition/stale
stop-generation gap now tracked as item 57; that does not reopen the original
timeout fix, but the old heading's broader "halt state tracking" claim was too
strong.

**10.** `kdbg_stack` returns `{offset, va, value}` per native word (x64 qword
or WoW64 x86 dword). `kdbg_mem` gained `decode='qwords'`. See commit `9009a49`.

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

**55.** Live kdbg state now composes with headless Ghidra through
`kdbg_decomp`: current RIP or an explicit runtime VA is resolved against a
fresh target PEB/kernel loader walk, converted to an ASLR-independent RVA, and
accepted only after the cached PE matches live machine, loader/header image
size, timestamp, and (when present) CodeView GUID+age. Same-named wrong builds
fail closed. Ghidra token provenance returns a bounded statement-level excerpt
with honest `exact`/`range`/`nearest-forward`/`nearest-backward`/`ambiguous`/
`unmapped` relationships, containing function metadata, nearby instructions,
and a live-vs-static instruction-byte warning. The agent-facing response is
compact by default and uses RVA as the common coordinate between assembly and
every address-bearing pseudocode line; direction and byte distance prevent a
compiler prologue from being falsely presented as a current C statement. Full
PE/PDB identities, loader records, hashes, Ghidra internals, and cache evidence
are returned only with `detail=standard` or `detail=diagnostic`. `full=true`
remains independent and controls only complete-function pseudocode.
`lines="N-M", assembly="mapped"` returns up to 100 absolute pseudocode lines
with bounded corresponding instructions nested per line, preserving disjoint
ranges, shared optimized instructions, unmapped declarations, clamped function
ends, and explicit truncation warnings. Worker API 4 prevents a stale Docker
image from serving the older mapping/batch contract.

PyGhidra now runs in a pinned, persistent Docker service rather than requiring
host Java/Ghidra or entering the MCP/debugger processes. Install/run/stop/status
lifecycle commands and MCP tools manage an exactly labelled current-UID
container; its mode-0600 Unix API has no published port, runtime networking is
disabled, every capability is dropped, `no-new-privileges` and a read-only root
are enforced, and only private cache/project/runtime mounts are writable.
Artifacts are version-pinned and checksum-verified during build. Full-SHA
atomic binary staging, a second worker SHA check, Ghidra-versioned durable
projects, one-program memory bound, concurrent serialization, image-ID-aware
upgrade/restart handling, and full-register restore poisoning keep the JVM
outside safety-critical RSP state. Unit coverage exercises malformed/bounded PE
parsing, identity mismatches, stripped images, RVA/file bounds, address/context
validation, user/kernel/overlapping/unmapped loader entries, and restore
poisoning. A real PyGhidra integration compiles and analyzes a binary, checks
focused/full output, concurrent requests, bad-request survival, warm reuse,
worker shutdown races, container restart, and durable project reuse. See
`docs/kdbg-decomp.md`.

Final live validation on 2026-08-23 used Server 2025 and winlogon. User-mode
`ntdll!NtClose` mapped from `0x7ffe1f99efd0` to RVA `0x15efd0`, matched the
live/static CodeView key `219D0663E9DBAD581E64D9EC8618F5421`, decompiled as
`NtClose`, and matched live instruction bytes. A real software breakpoint made
only the byte comparison fail with the intended patch warning; removal restored
the original bytes. A wrong 32-bit PE and an unmapped VA failed before Ghidra.
Eight concurrent end-to-end queries serialized cleanly in 0.61 seconds, and a
SIGKILLed worker restarted and reopened its durable project on the next query.

Batch-mapping live validation on 2026-08-23 kept Server 2025
`services.exe` halted at the hardware breakpoint on
`services!RQueryServiceStatus`. `lines="1-22", assembly="mapped"` returned all
22 requested pseudocode lines, nested 12 corresponding instructions beneath
seven address-bearing lines, preserved the `nearest-forward` prologue mapping
at a 21-byte distance, matched the exact PDB-guid-age identity and live bytes,
and emitted no warnings or truncation. Worker API 2 migrated automatically to
API 3 with its durable project warm, the real Docker integration passed in
12.58 seconds, and installed CLI JSON remained parseable without terminal-width
workarounds.

Docker validation on the same date built Ghidra 12.1.3/PyGhidra 3.1.0 from the
pinned artifacts and inspected the actual runtime hardening. A compiled-binary
integration exercised cold/focused/full decompilation, eight concurrent calls,
malformed-request survival, immediate shutdown/restart, and durable reuse in
11.66 seconds. Live Docker `ntdll!NtClose` analysis took 48.066 seconds cold;
the next mid-instruction lookup took 0.124 seconds with exact identity and
matching bytes. Docker kernel `nt!NtCreateFile` analysis took 623.329 seconds
cold and 0.165 seconds warm with exact identity/bytes. Current-RIP
`nt!HalProcessorIdle+0xf` exercised explicitly labelled PDB split recovery in
0.173 seconds. A real software breakpoint produced the intended byte-divergence
warning, and removal restored an exact match. Direct current-code MCP
status/run/decomp/stop/restart/reopen calls all passed; final cleanup left zero
breakpoints, detached/stopped the debugger, kept the VM/guest agent healthy,
and found no System 1001/41/6008 events in the previous hour.

Kernel `nt!NtCreateFile` independently mapped to RVA `0x9409b0`, matched
CodeView key `953A8DE880B0818C32DA2DEC1D79C2D91`, decompiled as
`NtCreateFile`, and matched live bytes. Its multi-minute first analysis became
a 0.28-second warm query. Default-RIP lookup at `nt!HalProcessorIdle+0xf`
exercised the missed-function edge: the bounded PDB-guided split recovery was
explicitly labeled, mapped the recovered `return` token exactly, and matched
live bytes. Direct MCP wrapper calls passed without restarting the configured
server. Cleanup left zero breakpoints, detached the daemon, stopped the
gdbstub, kept the VM/guest agent healthy, and found no System 1001/41/6008
events in the previous hour.

**54/56/57/59/63.** The 2026-08-23 AI-research UX batch completed the five
highest-return audit findings. Guest-derived loader paths are inert encoded
data with unique atomic publication; debugger state has explicit run state and
stop epochs; decomp mapping remains truthful under oversized output, decoded
gaps, and association caps; symbol/module+RVA navigation and stop-bound paging
reuse cached function results; and `kdbg_context` returns bounded one-call stop
triage. Worker API 4 and its pinned Docker image carry the new contract.

Live validation reattached Server 2025 `services.exe`, halted on the hardware
breakpoint at `services!RQueryServiceStatus`, and returned an epoch-consistent
context including an eight-byte memory follow. Status observed during a real
continue reported `state=running`, `halted=false`, and no current `stop_id`,
then timeout recovery produced a new halted generation. A cursor created at
one generation was rejected after a live step. Direct symbol and
`services.exe+0xfae0` requests both resolved the exact CodeView-matched PE.
Mapped RVA `0xfaf5` connected pseudocode line 14 to its call instruction and
labelled the target as RVA `0x10580`, static VA `0x140010580`, runtime VA
`0x7ff744f10580`, and `services!?ScSetTcpKeepalive@@YAXXZ`. The next page
returned in 0.178 seconds with `decompile_cache_hit=true`. The final API 4
image ID was verified as the running container and the compiled-binary Docker
integration passed in 12.32 seconds. The target was left halted at the restored
hardware breakpoint for the post-reload MCP check.

After the MCP reload, the registered schema exposed `kdbg_context` and the
expanded symbol/module/RVA/cursor decomp inputs. MCP returned the same pinned
epoch from triage and mapped decomp, including the eight-byte live memory
follow and labelled call/branch targets. Cursor paging returned lines 17–19
with a decompile-cache hit. A live MCP step advanced `stop_id` from 2 to 3;
the old cursor then failed as stale, `disasm_count=33` and conflicting address
coordinates failed at their documented bounds, and MCP continue restored the
target to the hardware breakpoint at stop 4.

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
