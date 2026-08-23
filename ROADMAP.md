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

Items 1-8 have all been worked — `git log` is the record. Item 8 is addressed
at its source (below) but stays listed as *Watching* because it is intermittent
by nature.

The major kdbg execution, symbol, decompilation, x64 unwind, and ordinary
WoW64 x86 unwind paths are implemented and live-verified. Two capability items
remain: automatic exact-binary staging for deeper user traces (69), followed
by build-sensitive x86/x64 transition-stack stitching (70). Item 26 is an
accepted minor trade-off rather than scheduled work, and item 8 remains a
watch condition rather than an active implementation item.

### Current actionable backlog (2026-08-24)

| Rank | Item | Ease | ROI | Status |
|---:|---|---:|---:|---|
| 1 | **69 — automatic exact-binary staging** | 4 | 5 | Next. Remove the preload requirement with an immutable attach-time manifest or non-contending staging broker. |
| 2 | **70 — mixed-mode WoW64 transition-stack stitching** | 1 | 3 | Backlog. Valuable for stops inside the WoW64 transition layer; normal x86 application traces already work. |

Latest verification after item 68: complete default suite `2512 passed, 5
skipped, 140 deselected`; all 11 direct QEMU RSP integrations; all three live
walk integrations; and reloaded-MCP validation against SysWOW64 `PING.EXE`,
including x86 context, stack, nine-frame unwind, step-over, step-out, detach,
and VM resume. Commit `775b2c8` is the implementation baseline.

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

### Next top-three sequence

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

### 69. User unwind depth depends on pre-staged exact binaries

Windows may decommit `.pdata` and even the RSDS page after registering a user
image. An attached daemon cannot safely invoke the guest agent to copy a newly
encountered dependency, so the trace stops explicitly when neither live
metadata nor a hash-bound cached PE exists. Preloading symbols/binaries solves
it (live RPCRT4 depth grew from two to thirteen frames), but agent UX would be
better with an attach-time immutable binary manifest or a separate broker that
can stage exact module artifacts without contending for the gdbstub.

### 70. Mixed-mode WoW64 transition-stack stitching remains unsupported

Dispatch is truthful for a stop in either x86 compatibility code or ordinary
x64 code, but one trace does not yet cross an active x86 ↔ x64 WoW64 CPU
transition (for example, a stop inside `wow64cpu.dll` while both stack domains
are live). Implementing that requires validated knowledge of the current
Windows build's transition/context records; guessing across the boundary would
be worse than the present explicit partial trace. Normal x86 application
call-chain research, including syscall stubs stopped before or after the
transition, is covered by item 68.

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
