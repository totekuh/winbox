# Live kdbg + PyGhidra decompilation

`kdbg_decomp` answers the question that normally costs several manual debugger
and reverse-engineering round trips: “what pseudocode corresponds to the
instruction where this target is halted?”

```text
current RIP / supplied runtime VA
  -> fresh kernel or target PEB loader walk
  -> live module base + bounded PE/CodeView identity read
  -> RVA = runtime VA - live module base
  -> exact cached PE identity check
  -> Ghidra address = program image base + RVA
  -> containing function + address-provenance tokens
  -> focused pseudocode, nearby static instructions, live-byte comparison
```

The load bases never need to match. ASLR changes the runtime base on every boot
and often between processes; the RVA remains the invariant. A filename is not
treated as identity. The bridge refuses concrete machine, `SizeOfImage`, PE
timestamp, or CodeView GUID+age disagreements before Ghidra is queried. When
both live and static CodeView records exist, the response reports
`identity.confidence = "pdb-guid-age"`; stripped binaries can use the weaker
`"pe-headers"` fallback only when their timestamp is nonzero.

## Setup and lifecycle

Ghidra remains optional for the rest of winbox. The bridge has no host Java,
Ghidra, or PyGhidra dependency: Docker builds the pinned JDK 21 + Ghidra +
PyGhidra service and verifies the upstream Ghidra and PyGhidra SHA-256 values.

```bash
winbox kdbg ghidra install       # one-time image build (~570 MB download)
winbox kdbg ghidra run           # optional; decomp starts it lazily
winbox kdbg ghidra status
winbox kdbg ghidra stop          # keeps analyzed projects and binaries
```

The runtime container publishes no port, has networking disabled, runs as the
calling UID/GID, drops every capability, enables `no-new-privileges`, and uses
a read-only root filesystem. Its only API is a mode-0600 Unix socket under
`~/.winbox/decomp/`. Immutable full-SHA binary copies and Ghidra-versioned
projects live in mode-0700 `cache/` and `projects/` directories there.

For local worker development only, `WINBOX_DECOMP_BACKEND=host` restores the
old external-interpreter path; `WINBOX_PYGHIDRA_PYTHON` and
`WINBOX_GHIDRA_PROJECT_DIR` then apply. Production/default operation is Docker.

## Use

Prepare the exact module binary before attaching. Kernel symbol loading already
caches `ntoskrnl.exe`; `kdbg_user_symbols_load(pid, module)` caches a user DLL.
An exact host path can be supplied explicitly for private binaries.

```bash
winbox kdbg user-symbols 1234 ntdll.dll        # before attach, if needed
winbox kdbg attach 1234
winbox kdbg cont --timeout 30
winbox kdbg decomp                             # current RIP
winbox kdbg decomp 0x7ff712341234 --before 5 --after 8
winbox kdbg decomp --full --binary /path/to/exact.exe
```

The MCP equivalents are:

```text
kdbg_decomp(addr="", before=3, after=5, full=false, binary="", timeout=60)
kdbg_decomp_status()
kdbg_ghidra_install(pull=true)
kdbg_ghidra_run()
kdbg_ghidra_stop()
```

The first request for a binary starts the container/JVM lazily and runs Ghidra
analysis, which can take minutes for a kernel image. Later queries reuse the
open program; worker restarts reuse its durable SHA-256-and-Ghidra-version keyed
project. Requests are serialized because Ghidra projects and decompiler APIs
are not safely concurrent.

## Response and mapping honesty

The result includes target PID/name, live module/base/VA/RVA, both identities,
Ghidra's image address, containing function/signature/offset, a bounded source
excerpt, nearby instructions, a symbol-store hint, and warnings.

Decompiler statements are not one-to-one with machine instructions. Mapping
uses Ghidra's decompiler token address provenance and labels its confidence:

- `exact`: a token's address range contains the requested instruction.
- `nearest`: no token owns the instruction (common for prologues, epilogues,
  spills, and compiler glue); the closest address-bearing statement is shown.
- `function-only`: Ghidra provided a containing function but no address-bearing
source tokens.

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

## Isolation and recovery

The JVM is never loaded into the MCP server or kdbg daemon. The container owns
it through the Unix socket, re-verifies the staged SHA-256 to close file-change
races, keeps at most one large program open, and serializes requests. A JVM or
container crash therefore cannot corrupt debugger RSP state; the next request
recreates the service and reopens the durable project. Image/container labels
and a state-root fingerprint prevent lifecycle commands from touching an
unrelated container that happens to use a reserved name.

The kdbg module walk restores the complete selected-vCPU register packet,
invalidates its thread-selection cache, and poisons the debugger session if
restoration fails so the VM can never resume under a borrowed CR3.
`~/.winbox/decomp/docker-build.log` contains bounded build diagnostics;
`decomp-status`/`ghidra status` do not start the JVM.

## Performance expectations

Auto-analysis is intentionally paid once per Ghidra version and binary SHA.
On the reference Server 2025 lab, Dockerized Ghidra 12.1.3 analyzed ntdll in
48 seconds and the Windows kernel in 623 seconds. Warm ntdll/kernel address
queries returned in 0.12–0.17 seconds; eight concurrent compiled-binary calls
serialized successfully. `cache_hit` and `analysis.project_cached` let agents
distinguish cold import from normal interactive operation.
