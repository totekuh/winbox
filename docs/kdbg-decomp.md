# Live kdbg + PyGhidra decompilation

`kdbg_decomp` answers the question that normally costs several manual debugger
and reverse-engineering round trips: “what pseudocode corresponds to the
instruction where this target is halted?”

```text
current RIP / runtime VA / symbol / module+RVA / continuation cursor
  -> atomic halted-session + stop_id snapshot
  -> fresh kernel or target PEB loader walk
  -> live module base + bounded PE/CodeView identity read
  -> RVA = runtime VA - live module base
  -> cached PE build-identity check + immutable content snapshot
  -> Ghidra address = program image base + RVA
  -> containing function + address-provenance tokens
  -> focused pseudocode, nearby static instructions, live-byte comparison
```

The load bases never need to match. ASLR changes the runtime base on every boot
and often between processes; the RVA remains the invariant. A filename is not
treated as identity. The bridge refuses concrete machine, `SizeOfImage`, PE
timestamp, or CodeView GUID+age disagreements before Ghidra is queried. When
both live and static CodeView records exist, the response reports
`verified.identity_method = "pdb-guid-age"`; stripped binaries can use the weaker
`"pe-headers"` fallback only when their timestamp is nonzero.

## Setup and lifecycle

Ghidra remains optional for the rest of winbox. The bridge has no host Java,
Ghidra, or PyGhidra dependency: Docker builds the pinned JDK 21 + Ghidra +
PyGhidra service and verifies the upstream Ghidra and PyGhidra SHA-256 values.

```bash
winbox kdbg ghidra install       # one-time image build (~570 MB download)
winbox kdbg ghidra run           # optional; decomp starts it lazily
winbox kdbg ghidra status
winbox kdbg ghidra prepare all   # analyze/enrich exact artifacts offline
winbox kdbg ghidra prepare-status
winbox kdbg ghidra cancel --token TOKEN  # cancel one exact background job
winbox kdbg ghidra stop          # keeps analyzed projects and binaries
```

The runtime container publishes no port, has networking disabled, runs as the
calling UID/GID, drops every capability, enables `no-new-privileges`, and uses
a read-only root filesystem. Its only API is a mode-0600, worker-API-namespaced
Unix socket under `~/.winbox/decomp/`. Sockets, locks, session records, logs,
Docker lifecycle locks, and container names include `apiN`, so concurrently
installed old/new clients cannot shut down or downgrade one another. An API
mismatch inside a namespace is refused with reload/version guidance. Immutable
full-SHA binary copies and Ghidra-version/profile-keyed
projects live in mode-0700 `cache/` and `projects/` directories there.

For local worker development only, `WINBOX_DECOMP_BACKEND=host` restores the
old external-interpreter path; `WINBOX_PYGHIDRA_PYTHON` and
`WINBOX_GHIDRA_PROJECT_DIR` then apply. Production/default operation is Docker.

## Use

`kdbg_attach` automatically walks both native and WoW64 loader views before it
takes the gdbstub. Its default `full` policy copies every bounded user image
into content-addressed storage and enriches exact PDB metadata when available.
Choose `binaries` to copy images while reusing only already-present symbols, or
`cached-only` for no guest copy and no download. `preflight=true` returns a
bounded, non-mutating work summary without attaching. The frozen manifest
records the policy and artifact source so reduced staging cannot masquerade as
a complete snapshot. Manual
`kdbg_user_symbols_load(pid, module)` is now optional prewarming or an explicit
single-module lookup. An exact host path can still be supplied for a private
binary that is not present in the live loader inventory.

```bash
winbox kdbg attach 1234
winbox kdbg attach 1234 --prewarm
winbox kdbg attach 1234 --staging-policy cached-only --preflight
winbox kdbg cont --timeout 30
winbox kdbg target-status
winbox kdbg decomp                             # current RIP
winbox kdbg decomp 0x7ff712341234 --before 5 --after 8
winbox kdbg decomp --symbol 'services!RQueryServiceStatus'
winbox kdbg decomp --module services.exe --rva 0xfae0
winbox kdbg decomp --lines 1-22 --assembly mapped
winbox kdbg decomp --analysis-timeout 900
winbox kdbg decomp --full --binary /path/to/exact.exe
```

The MCP equivalents are:

```text
kdbg_decomp(addr="", symbol="", module="", rva="", cursor="", before=3,
            after=5, full=false, binary="", timeout=60, analysis_timeout=900,
            detail="compact",
            lines="", assembly="nearby", instruction_bytes=false,
            runtime_vas=false)
kdbg_decomp_status()
kdbg_decomp_prepare(module="all", analysis_timeout=900, background=false,
                     force_enrichment=false)
kdbg_decomp_prepare_status(token="")
kdbg_decomp_cancel(request_id="", token="")
kdbg_decomp_cache()
kdbg_decomp_cache_prune(max_bytes=0, older_than_days=0,
                         sha256=[], project=[], module=[], dry_run=true)
kdbg_decomp_cache_repair(sha256)
kdbg_ghidra_install(pull=true)
kdbg_ghidra_run()
kdbg_ghidra_stop()
```

All `kdbg_*` MCP calls return structured content using the common
`winbox.mcp/1` envelope: `{schema, ok, result, error}`. Daemon and worker
protocols carry additive `winbox.error/1` objects, so new clients preserve a
stable `code`, message, `retryable` flag, bounded details, operation, and at
most three recovery hints without inferring meaning from prose. The legacy
error string remains present during mixed-version upgrades. Interactive CLI
errors prefix the stable code; MCP does not send indented JSON strings.

The first request for a binary starts the container/JVM lazily. Import and
auto-analysis have a separate 5-1800 second `analysis_timeout`, publish distinct
heartbeat phases, and run under a cooperative Ghidra task monitor. Explicit
cancel, a disconnected client, or timeout leaves partial work unmarked so the
next exact request can resume it safely. `kdbg_decomp_prepare` moves that work
out of debugger stop time; background mode and attach's optional `prewarm`
return durable status tokens. Later queries reuse the open program, and worker
restarts reuse its durable SHA-256/Ghidra/profile-keyed project. Requests remain
serialized because Ghidra projects and decompiler APIs are not safely
concurrent. The warm-program LRU defaults to two entries and is bounded to four
via `WINBOX_GHIDRA_OPEN_PROGRAMS`. Docker defaults to 4 GiB and 2 CPUs with
bounded logs; `WINBOX_GHIDRA_MEMORY` and `WINBOX_GHIDRA_CPUS` tune those limits.

Exact-PDB prewarming also builds the bounded
`winbox-pdb-enrichment-v3` profile. It imports verified function names, named
globals, and only finite primitive/pointer signatures that the PDB records
render unambiguously. Existing non-default Ghidra names/signatures win every
conflict. Every applied, reused, invalid, and preserved-conflict decision is
written atomically to a digest-keyed `cache/enrichment-results/` provenance
record. Public Microsoft PDBs often omit private procedure types; zero applied
signatures is therefore an honest result, not a fallback to guessed types.

`llvm-pdbutil` output is drained concurrently through hard-capped stdout and
stderr buffers. Crossing the symbol-output cap terminates and reaps the exact
child immediately; timeout and abnormal-exit paths do the same, so the cap is
an allocation bound rather than a check performed after unbounded capture.

Background prepare records bind their random token and nonce to the child PID
plus Linux process start time and a periodic heartbeat. Status classifies a
dead or PID-reused child as `lost` instead of leaving `starting`/`running`
forever. `kdbg_decomp_cancel(token=...)` and `winbox kdbg ghidra cancel
--token TOKEN` forward cancellation only to that job's current exact worker
request. Completed, partial, failed, cancelled, and lost records are retained
at most 30 days/128 jobs; starting or running jobs are never retention-pruned.

Use `winbox kdbg ghidra cache` to inspect content-keyed usage and
`winbox kdbg ghidra prune --older-than-days 30` to preview reclamation. Add
`--sha256`, `--project`, or `--module` for exact targeted recovery; each option
is repeatable and combines as a union with age/size selection. Inventory
separates entry-owned bytes from overhead and lists bounded unattributed files
using relative paths. Prune previews report unmatched selectors and any
residual that cannot meet `--max-bytes`. Add `--apply` only after stopping the
worker. MCP pruning is likewise a dry-run unless `dry_run=false` is explicit.
Exact digest ownership includes enrichment input sidecars and per-decision
result provenance, so SHA/module/project pruning removes those files together
and no longer leaves them as unexplained overhead.

If Ghidra proves that an exact digest/profile project is malformed or
truncated, the worker deletes only that project's `.gpr`, `.rep`, `.lock`, and
`.lock~`, revalidates and retains the content-addressed binary, and rebuilds
once. It never loops and does not create a backup cache area. Non-corruption
open failures do not trigger deletion. Use
`winbox kdbg ghidra repair --sha256 DIGEST` or
`kdbg_decomp_cache_repair(sha256)` to request the same exact reset explicitly.

Every live read is pinned to the daemon's random `session_id` and monotonic
`stop_id`. Resuming immediately clears the current stop; a query fails as stale
if another client continues, steps, detaches, or reaches a different stop while
Ghidra is working. It never combines loader/register evidence from one halt
with bytes from another.

For the first look at any halt, use `kdbg_context()` (or `winbox kdbg
context`). It returns registers, symbolized nearby assembly, labelled stack,
architecture-correct Windows x64 or WoW64 x86 backtrace, active breakpoints,
and optional caller-selected memory in one stop-pinned response. Disassembly is
capped at 32 instructions, stack at 32 native words, backtrace at 16 frames,
and optional memory at four reads of 256
bytes each/1024 bytes combined.

At a native stop inside an active WoW64 transition, the same response can carry
a `windows-wow64-mixed` backtrace. Its `transition` object identifies the exact
`wow64cpu` build, instruction-derived layout, saved-context source and x86
EIP/ESP; the first x86 frame has `boundary=wow64-x64-to-x86`.
At an arbitrary x86 stop, exact nt PDB layouts instead validate the current
KTHREAD's persisted x64 trap frame and native TEB stack bounds. The first
suspended native caller is marked `boundary=wow64-x86-to-x64`; the historical
syscall-stub frame used only to recover that caller is not presented as live.

For rare breakpoints, prefer `kdbg_cont_start(timeout)`. It launches a tiny
detached host client, atomically persists a token and daemon session identity,
and returns immediately. `kdbg_cont_poll(token)` reads its bounded state after
ordinary calls or an MCP reload; `kdbg_cont_cancel(token)`, `kdbg_interrupt`,
and detach cooperatively halt it. Duplicate starts, stale/dead workers, daemon
replacement, mismatched tokens, 24-hour timeout bounds, cancellation races,
and oversized persisted results are handled explicitly. CLI equivalents are
`cont-start`, `cont-poll`, and `cont-cancel`.

## Response detail and mapping honesty

`detail="compact"` is the default agent response. It includes only the target,
live symbol/VA/RVA, containing function, a small assembly window, bounded
pseudocode, explicit assembly-to-pseudocode mapping, concise verification,
cache state, warnings, and whole-function code when `full=true`. RVAs are the
shared coordinate: runtime and Ghidra image bases can differ without making the
assembly/source relationship ambiguous.

Compact MCP output omits raw instruction bytes and repeated runtime/static VAs
by default. Set `instruction_bytes=true` or `runtime_vas=true` only when that
evidence is needed. The main live location and every instruction/flow-target
RVA remain present, and `assembly_fields` records exactly what was included.

Larger evidence is opt-in:

- `detail="standard"` adds module inventory, full live/static identity,
  symbol hints, Ghidra addresses, and cache-analysis metadata.
- `detail="diagnostic"` returns the complete internal evidence record for
  troubleshooting and compatibility with the original response contract.

`full=true` controls pseudocode scope only; it does not silently enable verbose
metadata. This keeps normal agent calls token-efficient while preserving every
identity and cache diagnostic when explicitly requested.

### Batch source/assembly mapping

Use `lines="N-M"` with `assembly="mapped"` to retrieve an absolute pseudocode
line batch with corresponding instructions nested under every address-bearing
source line:

```text
kdbg_decomp(lines="1-22", assembly="mapped")
```

`lines` accepts `N` or an ascending `N-M` range and overrides the relative
`before`/`after` excerpt. A request may contain at most 100 pseudocode lines;
an end beyond the function is safely clamped and reported by
`line_selection.truncated`, while a start beyond the function is rejected.
Mapped assembly is bounded to 512 source-line/instruction associations and
reports a warning if truncated. Braces, declarations, and other lines without
machine-code provenance simply omit `assembly`. An optimized instruction may
legitimately appear beneath more than one pseudocode line.

`line_selection` also returns `total_lines`, `has_more`, and `next_start`.
When more lines exist, `next_cursor` is an opaque bounded continuation tied to
the binary SHA-256, Ghidra version, analysis profile, function RVA, debugger
session, and stop. Passing it back as `cursor` selects the next equal-sized
page, revalidates live evidence, and reuses the worker's in-memory decompile
result. It is mutually exclusive with other locations and `lines`.

The small top-level `assembly` window remains anchored at RIP in both modes.
With `assembly="mapped"`, selected pseudocode entries additionally carry an
`assembly` array whose instruction RVAs use the same coordinate as their
`rva_ranges`. This preserves immediate debugger context while making multi-line
static/dynamic review possible in one bounded call.

Decompiler statements are not one-to-one with machine instructions. Mapping
uses Ghidra's decompiler token address provenance and labels the actual
relationship in `rip_mapping.kind`:

- `exact`: a single-address token directly owns the requested instruction.
- `range`: the instruction lies within a token address range contributing to
  the statement.
- `nearest-forward`: no token owns the instruction; the mapped statement is
  later in the function (commonly a compiler-generated prologue).
- `nearest-backward`: no token owns the instruction; the mapped statement is
  earlier (commonly an epilogue or alignment).
- `ambiguous`: multiple pseudocode lines have equally valid provenance.
- `unmapped`: the function decompiled, but no defensible source mapping exists.

Every mapped pseudocode line carries `rva_ranges`; nearby assembly carries an
`rva`, and `rip_mapping` names the selected/candidate source lines, direction,
and byte distance. An instruction in a prologue is therefore never mislabeled
as already executing the first semantic C statement. Diagnostic output retains
the legacy coarse `mapping.confidence` (`exact`, `nearest`, `function-only`)
alongside the more precise mapping kind.

Call and branch targets always carry `rva` and a nearest verified module symbol
when available. `static_va` and `runtime_va` are added when
`runtime_vas=true`.
Addressed lines report `assembly_complete`; if the global mapping cap is hit,
the response identifies the affected pseudocode line range. An address in an
undecoded function gap is labelled `undecoded-gap` and shows the nearest
preceding/following instructions instead of incorrectly returning the tail.

`function.source` is normally `analysis`. If Ghidra missed a function that a
nearby exact PDB public identifies, it may be `pdb-public-existing`,
`pdb-public-recovery`, or `pdb-public-split-recovery`; the latter explicitly
means winbox had to disassemble and create a synthetic function at the queried
instruction because Ghidra's function at the true public entry was truncated.
The response retains the original `symbol_hint` RVA/offset so an agent can see
both boundaries instead of confusing the synthetic entry with the real one.

The current instruction's static bytes are compared with live memory after the
identity check. A mismatch is a warning, not silently ignored: it may be a
software breakpoint (`0xCC`), hotpatch, runtime hook, relocation, unpacked code,
or self-modification. JIT/private executable pages and addresses outside loader
modules are rejected because no trustworthy PE+RVA identity exists yet.

Compact verification deliberately distinguishes proof scopes:
`build_identity_match` covers PE/CodeView identity,
`analyzed_file_sha256` identifies the immutable host content, and
`current_instruction_match` is `match`, `mismatch`, or `not_checked`. It does
not claim that every runtime byte in the function equals the file.

## Isolation and recovery

The JVM is never loaded into the MCP server or kdbg daemon. The container owns
it through the Unix socket, re-verifies the staged SHA-256 to close file-change
races, keeps a bounded configurable LRU (two programs by default), and
serializes requests. A JVM or
container crash therefore cannot corrupt debugger RSP state; the next request
recreates the service and reopens the durable project. Image/container labels
and a state-root fingerprint prevent lifecycle commands from touching an
unrelated container that happens to use a reserved name.

Every lifecycle/status CLI JSON surface bypasses Rich and is byte-for-byte safe
to pipe through `jq` or `python -m json.tool`, including at narrow terminal
widths.

The kdbg module walk restores the complete selected-vCPU register packet,
invalidates its thread-selection cache, and poisons the debugger session if
restoration fails so the VM can never resume under a borrowed CR3.
`~/.winbox/decomp/docker-build.log` contains bounded build diagnostics;
`decomp-status`/`ghidra status` do not start the JVM or enter the serialized
worker request queue. They read an atomic heartbeat sidecar and immediately
report `idle|busy|stale|unknown|stopped`, the active phase, coarse phase
progress, elapsed/progress age, cancellation state, safe binary identity, and
bounded last failure. Caller-supplied host paths are not published there.

## Performance expectations

Auto-analysis is intentionally paid once per Ghidra version and binary SHA.
On the reference Server 2025 lab, Dockerized Ghidra 12.1.3 analyzed ntdll in
48 seconds and the Windows kernel in 623 seconds. Warm ntdll/kernel address
queries returned in 0.12–0.17 seconds; eight concurrent compiled-binary calls
serialized successfully. `cache_hit` and `analysis.project_cached` let agents
distinguish cold import from normal interactive operation.
`decompile_cache_hit` distinguishes a reused in-memory function result, which
is expected on continuation pages.
