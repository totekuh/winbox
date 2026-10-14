# MCP Tools

The MCP server is the platform's agent control plane, not only a remote shell.
AI agents can manage and contain the VM, run code, instrument live targets from
the hypervisor, resolve PDB symbols, inspect protected address spaces, exercise
drivers and named pipes, change defenses, and retrieve bounded evidence without
constructing one-off transport glue.

## Install

```bash
pip install -e '.[mcp]'
```

## Add to Claude Code

```bash
claude mcp add winbox -- winbox mcp
```

## Available tools (97)

### User-mode primitives

| Tool | Description |
|------|-------------|
| `exec(command, user?, password?, background?)` | Execute a cmd.exe command, optionally as a local Windows user, in the background, or both |
| `python(code, user?, password?, background?)` | Execute Python code, optionally as a local Windows user, in the background, or both |
| `powershell(script, user?, password?, background?)` | Execute encoded PowerShell, optionally as a local Windows user, in the background, or both |
| `job_result(job_id)` | Retrieve output of a background `exec`/`python`/`powershell` job (non-blocking poll; also visible to `winbox jobs`) |
| `ioctl(device, code, input_hex, output_size)` | Send DeviceIoControl to a driver — no ctypes boilerplate |
| `reg_query(key, value?)` | Query registry key or value |
| `reg_set(key, value, data, value_type)` | Set registry value (creates key if needed) |
| `reg_delete(key, value?)` | Delete registry value or entire key tree |
| `ps(filter?)` | List processes with PID, name, path, memory usage (JSON) |
| `upload(src, dst?)` | Upload file from Kali to VM via VirtIO-FS (optionally copy to dst inside VM) |
| `file_copy(src, dst)` | Copy file within the VM (DLL sideloading, staging binaries) |
| `mem_read(pid, address, length)` | Read memory from a process (enables SeDebugPrivilege, address as hex string, 1MB cap) |
| `service_start(name)` | Start a Windows service |
| `service_stop(name)` | Stop a Windows service |
| `net_isolate()` | Disconnect VM from network (host-VM channels stay up; also clears a persistent unplug) |
| `net_connect()` | Reconnect VM to network (restarts adapter, renews DHCP, clears the next-boot link state) |
| `net_unplug()` | Full air-gap (NIC link down live + persistent — survives a reboot, BSOD or power cycle) |
| `eventlogs(log?, since?, ids?, provider?, level?, max_events?)` | Query Windows event logs via Get-WinEvent (returns JSON array; CLI defaults to CSV) |
| `eventlogs_clear(log?, all_logs?, confirm)` | Clear event channels via wevtutil cl. `confirm=True` required (destructive). |

### Defender

| Tool | Description |
|------|-------------|
| `av_status(timeout?)` | Report Defender/AMSI protection state (Get-MpComputerStatus + Get-MpPreference) |
| `av_enable()` | Re-enable Defender real-time protection, AMSI, and behavior monitoring |
| `av_disable(confirm)` | Disable Defender completely — sets GP registry keys then reboots the VM. `confirm=True` required. |

### HVCI / Virtualization Based Security

| Tool | Description |
|------|-------------|
| `hvci_status(timeout?)` | Report HVCI/VBS state (DeviceGuard registry keys + bcdedit hypervisorlaunchtype) |
| `hvci_disable(confirm)` | Disable HVCI and VBS — sets registry keys + bcdedit then reboots the VM. `confirm=True` required. |
| `hvci_enable(confirm)` | Re-enable HVCI and VBS. Reboots the VM. `confirm=True` required. |

### Named pipes

| Tool | Description |
|------|-------------|
| `pipe_list(filter?)` | Enumerate named pipes matching a pattern (JSON array) |
| `pipe_info(name)` | JSON: DACL/SDDL, mode, buffer sizes, max instances for a pipe |
| `pipe_connect(name, access?)` | One-shot pipe handle open; returns result or Win32 error |
| `pipe_open(name, access)` | Start a session — spawns a detached broker in the VM that holds the handle open |
| `pipe_send(session_id, data_hex)` | WriteFile through the session broker |
| `pipe_recv(session_id, size, timeout?)` | ReadFile through the session broker |
| `pipe_close(session_id)` | Close session + taskkill the broker |

The `pipe_open` + `pipe_send`/`recv`/`close` family uses a persistent broker process per session (spawned as DETACHED_PROCESS | CREATE_NO_WINDOW inside the VM). IPC happens via `cmd.json`/`result.json` files on the VirtIO-FS share, so there's no VM round-trip on the polling path. This matters for protocols where a write on one handle must be answered on the same handle (stateless `send`/`recv` open fresh handles and never see each other's messages).

### Hypervisor-level kernel debug (via QEMU gdbstub, EDR-invisible)

On affected QEMU/KVM versions, debugger stop/resume corrupts Windows CET user
shadow-stack state. The debugger therefore fails closed unless
`UserShadowStack` is OFF. Preparation is explicit, saves the original policy,
and requires a reboot.

#### Stateless walks and symbol management

Work against the live VM without an attached session:

| Tool | Description |
|------|-------------|
| `kdbg_doctor(port?)` | Fast non-disruptive readiness report: VM/agent, CET, cached symbol identity, reader/admission ownership, decomp capability, exact runtime/package provenance, and MCP catalog revision; labels live-base verification as not checked rather than guessing |
| `kdbg_cet_status()` | Report whether the current Windows boot is safe for QEMU GDB stop/resume |
| `kdbg_prepare(confirm)` | Back up the original mitigation policy and disable CET user shadow stacks; reboot required |
| `kdbg_restore_cet(confirm)` | Restore the backed-up mitigation policy; reboot required |
| `kdbg_start(port?, any_interface?)` | Start the gdbstub listener |
| `kdbg_stop()` | Stop the gdbstub listener |
| `kdbg_status(port?)` | Show stub state + reachability |
| `kdbg_symbols_load()` | Pull ntoskrnl.exe out, fetch PDB from msdl, persist symbols + struct layouts to `~/.winbox/symbols/` |
| `kdbg_user_symbols_load(pid, module, architecture?)` | Pull an x86/x64 module loaded in `pid`, fetch its matching PDB, and persist a separate architecture-correct symbol map |
| `kdbg_search(module, query, limit?, sha256?)` | Offline search over one exact symbol-store or persistent decomp-cache PE: ASCII/UTF-16 strings, exported names, validated MSVC x64 RTTI vtables, and direct RIP-relative string-xref leads. `sha256` disambiguates same-named cached builds. Never opens the debugger socket or changes VM state. |
| `kdbg_sym(name, search?, limit?, rva?)` | Resolve `mod!sym` to VA or RVA; substring search supported |
| `kdbg_struct(type_name, field?, module?)` | Dump full struct layout or one field offset |
| `kdbg_ps()` | Walk `PsActiveProcessHead` (JSON: pid, dtb, eprocess, name) and return snapshot admission/timing metadata |
| `kdbg_vad(pid, address?, executable?, limit?, probe_header?, require_complete?)` | Exact-PDB, x64-only user VAD lookup or bounded map. Proves a range/protection/private-or-image fact, exposes explicit tree/output boundaries, and never treats a loader miss as a verdict. |
| `kdbg_vad_extract(pid, address, name, length?, require_complete?)` | In one bounded stop, prove the selected user VAD and preserve up to 8 MiB of its process-CR3 bytes as a mode-0600 immutable host artifact. Returns segment hashes/hole evidence and provenance, never raw bytes over MCP. |
| `kdbg_token(pid)` | Decode the target primary token through the exact `_EPROCESS.Token` fast reference: IDs, session, flags, raw privilege masks, and its proven object header. |
| `kdbg_handles(pid)` | Return the validated process handle-table root and build-specific entry-enumeration support. Public PDBs without the private entry union explicitly refuse slot decoding. |
| `kdbg_object(body)` | Decode an exact-PDB `_OBJECT_HEADER` only for a caller-proven canonical kernel object-body pointer. |
| `kdbg_capture(profile?, pid?, name?, require_complete?)` | One bounded RSP stop for an immutable process or system evidence artifact. A named artifact is atomically stored host-side; its snapshot phases/read accounting travel with it. |
| `kdbg_capture_diff(left, right, limit?, allow_identity_mismatch?)` | Purely offline bounded diff of matching capture identities; no RSP connection or target-memory read. |
| `kdbg_threads(pid, detail?, state?, wait_reason?, sort?, limit?, resolve?, include_current?, wait_objects?, wait_object_limit?, wait_owner_depth?, require_complete?)` | Bounded validated ETHREAD walk with validated head/link back-links, duplicate-TID rejection, structured partial evidence, optional strict completeness, scheduler summaries/filters, optional live module+local-symbol start attribution, exact KPCR→KPRCB current-vCPU identities, and optional exact-PDB wait-object / mutant-owner evidence. Every stop reports hard duration/read/byte budgets and actual read accounting; never claims arbitrary-thread registers, stacks, or speculative lock owners. |
| `kdbg_thread_triage(process_cap?, total_thread_cap?, sample_per_process?, result_limit?, resolve?, require_complete?)` | One bounded RSP snapshot ranking process-wide thread/runnable counts, newest and high-context-switch threads, and explicitly scoped suspicious starts. Every process-list, thread-budget, and per-process partial boundary is returned; strict callers can refuse any incomplete scope. |
| `kdbg_thread_baseline(pid, name?)` | Save one explicit complete host-side ETHREAD baseline, bound to VM boot, target PID/EPROCESS/CreateTime, and active nt symbol-store revision; includes snapshot admission/timing metadata |
| `kdbg_thread_diff(pid, name?, limit?)` | One explicit bounded comparison against a named baseline: created/exited threads, scheduler transitions, and wrap-aware context-switch deltas; refuses cross-boot/reuse/store comparisons and includes snapshot timing |
| `kdbg_triage(pid, thread_limit?, require_complete?)` | One bounded RSP snapshot: process identity, thread summary/top context-switch rows, current vCPUs, capped user modules, explicitly scoped unmapped-start leads, structured partial evidence/strict completeness, and stop-duration metadata |
| `kdbg_lm()` | Walk `PsLoadedModuleList` (JSON: base, size, name) |
| `kdbg_user_lm(pid)` | Walk native and WoW64 PEB loader views; every module is labelled x64 or x86 |
| `kdbg_read_va(pid, address, length)` | CR3-switching arbitrary-process read; works against PPL targets (1MB cap, hex bytes) |
| `kdbg_base_refresh()` | Re-resolve nt load base after ASLR reboot |

#### Session daemon — long-running debug session

Attach once, drive across many tool calls.

Every `kdbg_*` MCP tool returns structured `winbox.mcp/1` content:
`{schema, ok, result, error}`. Failures use stable error codes, retryability,
and bounded recovery hints instead of prose that an agent must parse.

At a WoW64 compatibility-mode stop, the daemon uses 32-bit disassembly,
native-width stack entries, and a conservative hybrid call-chain walker.
Exact-build PDB FPO/frame records are preferred, followed by validated EBP
chains and bounded prologue simulation. Raw module-looking stack values remain
separate speculative candidates. Attach freezes native and x86 loader entries
into a bounded content-addressed manifest before the daemon takes QEMU's one
RSP connection. `full` remains the safe default; `binaries` skips network
enrichment, while `cached-only` performs no guest copy or download. A dry
preflight predicts bounded per-module work without mutation. PE machine, live
image size, hash, and PDB identity are verified before unwind metadata is
trusted; manual per-DLL preloading is no longer required.

At an active native WoW64 transition stop, `kdbg_bt` additionally derives the
CPU-area/context offsets from the exact `wow64cpu.dll` instruction stream and
PDB public symbols. A validated saved x86 context is stitched after the x64
transition frames, producing one explicitly marked `windows-wow64-mixed`
trace. An unrecognized build or invalid context remains a truthful native
partial trace with `transition_error` rather than guessed frames.
At an arbitrary x86 stop, QEMU does not expose the suspended native registers
directly. kdbg now recovers them without scanning: exact nt PDB layouts resolve
the firing CPU's self-validated KPCR, current KTHREAD, and persisted x64 user
trap frame; process identity, kernel-stack containment, native TEB identity and
stack bounds, x64 CS, exact `wow64cpu` image, and the first unwind step must all
agree. The already-returned syscall-stub frame is discarded, and the suspended
native callers are appended at `boundary=wow64-x86-to-x64`. Any failed
invariant preserves the ordinary x86 trace with `transition_error`.

| Tool | Description |
|------|-------------|
| `kdbg_attach(pid, port?, staging_policy?, preflight?, prewarm?, apply_intents?)` | Preflight or attach with `full`, `binaries`, or `cached-only` staging; optional Ghidra prewarming and explicit fresh-manifest application of saved breakpoint intents |
| `kdbg_detach()` | Tear down the session and leave the VM running |
| `kdbg_session()` | Show current daemon state (target pid, attach time, bp count, halted vs running) |
| `kdbg_target_status()` | Probe the captured EPROCESS/create-time identity as alive, exiting, gone, or unknown without rebinding PID reuse |
| `kdbg_bp_intent_add(target, mode?, condition?, wp_type?, wp_size?, actions?)` | Persist a detached `module+0xoffset` intent without resolving or touching the VM |
| `kdbg_bp_intents()` | List saved symbolic breakpoint intents without touching the VM |
| `kdbg_bp_intent_remove(intent_id)` | Remove one saved breakpoint intent by stable ID |
| `kdbg_bp(target, mode?, condition?, wp_type?, wp_size?, actions?)` | Install an explicit hardware/software breakpoint or hardware watchpoint. Targets also accept case-insensitive staged `module+0xoffset`; predicates support exact-width `byte`/`word`/`dword`/`qword` reads; actions additionally support bounded `bytes`/`ascii`/`utf16` capture. Action hits append JSONL traces and auto-continue. |
| `kdbg_bps()` | List installed bps with hit/skip/error counters and canonical module+offset targets |
| `kdbg_bp_trace(bp_id, tail?, from_hit?, limit?, expression?, value?, errors_only?, summary?, top?)` | Bounded backward tail or cursor pagination over action traces, with projection/filtering and AI-sized value/error/distribution summaries |
| `kdbg_rm(bp_id)` | Remove an installed bp |
| `kdbg_cont(timeout?)` | Resume; block until next stop in target's CR3 set (KPTI-aware: kernel + user PML4) |
| `kdbg_cont_start(timeout?)` | Start a durable host-side continue and return a token immediately; survives MCP reloads |
| `kdbg_cont_poll(token?)` | Poll the current/tokenized continue job and retrieve its bounded terminal stop |
| `kdbg_cont_cancel(token?)` | Interrupt and cancel the durable continue job |
| `kdbg_step(over?, out?)` | Single-step, step over calls/syscalls, or step out via a temporary return-address breakpoint |
| `kdbg_interrupt()` | Halt a running cont via raw `\x03` on the RSP socket |
| `kdbg_resume(port?)` | Recovery valve for a VM left paused after a debugger/client failure |
| `kdbg_regs()` | Dump GPRs + control regs from the firing vCPU |
| `kdbg_stack(n?)` | Hex-dump the top `n` native stack words (x64 qwords or WoW64 x86 dwords) |
| `kdbg_bt(depth?)` | Windows x64 `.pdata`, WoW64 x86 hybrid, or exact-build validated bidirectional mixed x64↔x86 transition backtrace, with explicit provenance and speculative candidates kept separate |
| `kdbg_context(disasm_count?, stack_qwords?, bt_depth?, memory?)` | Return one stop-epoch-pinned triage bundle with registers, symbolized assembly, stack, metadata-driven backtrace, breakpoints, and bounded optional memory reads |
| `kdbg_mem(va, length?, decode?)` | Read in target's CR3 (CR3-masquerade); bounded decode modes for hex, UTF-8, UTF-16LE, ASCII, C strings, and qwords |
| `kdbg_write_mem(va, hex)` | Write into target's CR3 (used for buffer-swap / agent-driven MITM workflows) |
| `kdbg_disasm(addr?, count?, instruction_bytes?)` | Symbol-annotated Capstone disassembly; raw bytes are opt-in |
| `kdbg_decomp(addr?, symbol?, module?, rva?, cursor?, before?, after?, full?, binary?, timeout?, analysis_timeout?, detail="compact", lines?, assembly="nearby", instruction_bytes?, runtime_vas?, callers?, callees?, allow_cold?)` | Resolve current RIP, runtime VA, symbol, or module+RVA, verify PE build identity, snapshot exact host content, and return stop-pinned RVA-linked assembly/pseudocode with bounded pagination. `callers`/`callees` add exact-PE direct-call evidence only; indirect flow is never invented. Cold Ghidra analysis is refused by default so a stopped target is never held while analysis runs; prepare offline first or explicitly opt in with `allow_cold=true`. |
| `kdbg_decomp_status()` | Report PyGhidra discovery, isolated worker/JVM state, durable project-cache status, and current decomp admission without starting the JVM |
| `kdbg_decomp_cache()` | List content-keyed binary/project sizes, analysis profiles, and LRU timestamps |
| `kdbg_decomp_cache_prune(max_bytes?, older_than_days?, sha256?, project?, module?, dry_run?)` | Dry-run-first exact/LRU pruning with reconciled accounting; applying requires the worker to be stopped |
| `kdbg_decomp_cache_repair(sha256)` | Delete one exact corrupt project cache and attempt one deterministic rebuild from its retained hash-addressed binary |
| `kdbg_decomp_prepare(module?, analysis_timeout?, background?, force_enrichment?)` | Analyze and exact-PDB-enrich cached modules without a debugger stop; background mode returns a durable token |
| `kdbg_decomp_prepare_status(token?)` | Read the latest or selected durable preparation result |
| `kdbg_decomp_cancel(request_id?, token?)` | Cooperatively cancel one active request or exact background preparation token; identities are mutually exclusive |
| `kdbg_ghidra_install(pull?)` | Build the checksum-pinned JDK 21 + Ghidra + PyGhidra Docker image |
| `kdbg_ghidra_run()` | Start and API-check the private, networkless persistent decompilation container |
| `kdbg_ghidra_stop()` | Stop/remove the labelled container while preserving analyzed projects and binary cache |
