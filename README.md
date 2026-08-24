# winbox

**An isolated Windows vulnerability-research platform for Kali and AI agents.**

winbox turns a headless Windows VM (Server Core 2022/2025 or Windows 11) into
an automation, instrumentation, and analysis environment controlled from
Kali. Execute tools, drive a PDB-aware hypervisor debugger, inspect protected
memory, exercise drivers and IPC, change security posture, contain malware,
and collect evidence through one CLI and a 75-tool MCP surface.

Transparent execution is still the shortest path in: type
`winbox exec SharpHound.exe -c All -d corp.local` and winbox boots the VM,
runs the command, and returns its output. It is now one workflow within the
larger platform rather than the product's whole identity.

## Quick Demo

```console
$ winbox setup -y                                    # one-time: builds the VM (~20 min)
$ winbox tools add Rubeus.exe SharpHound.exe         # drop in your tools
$ winbox exec Rubeus.exe kerberoast /domain:corp.local
[*] VM is off, starting...
[+] VM ready
[*] Running: Rubeus.exe kerberoast /domain:corp.local

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/
  ...

$ winbox exec --bg --log Seatbelt.exe -group=all     # run in background
[+] Job 1 started (PID 4532)
$ winbox shell                                       # SYSTEM shell with full PTY
PS C:\Windows\system32>
```

## Platform capabilities

- **MCP server** — 75 tools form a bounded, AI-native research control plane
  for autonomous agents, covering VM lifecycle, execution, memory, symbols,
  debugging, drivers, IPC, defenses, networking, event logs, and evidence
  collection.
- **Hypervisor instrumentation** — a persistent QMP/RSP transport, PDB-backed
  symbols and Windows structure walks, CR3-aware reads/writes, breakpoints,
  watchpoints, stepping, disassembly, exact-binary live decompilation,
  predicates, and action traces operate below the guest and across PPL
  boundaries.
- **Target interaction** — send IOCTLs, inspect and hold named pipes, manage
  services/registry/Defender/HVCI/AppLocker, run tools as SYSTEM or alternate
  local users, and keep long-running jobs observable.
- **Containment and detonation** — host-enforced network isolation, full NIC
  unplug, packet capture, DNS sinkholing, optional INETSim services, snapshots,
  and a fail-closed detonation preflight. See
  [docs/malware-detonation.md](docs/malware-detonation.md).
- **Reproducible Windows lab** — build and operate Server 2022, Server 2025,
  or Windows 11 guests with automatic provisioning, VirtIO-FS staging,
  snapshots, VNC, x64dbg, Python, and host-side dependency delivery.
- **Transparent execution** — run `.exe` files like native Kali commands,
  including background/logged jobs, one-shot uploads, MSI installation,
  ConPTY SYSTEM shells, SSH, and optional `binfmt_misc` dispatch.
- **Network and domain integration** — NAT through Kali, manage DNS/hosts,
  join Active Directory domains, or isolate the target without losing the
  guest-agent and VirtIO-FS control channels.

## Prerequisites

Install on Kali (most are pre-installed):

```bash
sudo apt install qemu-system-x86 qemu-utils libvirt-daemon-system virtinst \
    libguestfs-tools virtiofsd p7zip-full genisoimage sshpass wget
```

Required:
- `qemu-system-x86_64`, `qemu-img`, `virsh`, `virt-install`, `virt-customize`
- `7z` (p7zip-full)
- `virtiofsd` (at `/usr/libexec/virtiofsd` or on PATH)
- `/dev/kvm` (hardware virtualization must be enabled)
- `mkisofs` or `genisoimage`
- `wget`
- `default` libvirt network (active)

Optional:
- `sshpass` — auto-auth for `winbox ssh` (falls back to manual password entry)
- `virt-manager` — required for `winbox vnc` (VM display — plain VNC, no clipboard/resize)
- Docker — optional; `winbox kdbg ghidra install` builds the pinned, isolated
  headless Ghidra/PyGhidra service used by kdbg's live address-to-pseudocode
  bridge. No host Java or Ghidra install is needed. See
  [docs/kdbg-decomp.md](docs/kdbg-decomp.md).

## Installation

```bash
git clone https://github.com/totekuh/winbox.git
cd winbox
pip install -e .
```

Then build the VM (downloads the eval ISO + VirtIO drivers):

```bash
winbox iso download          # ~4.7 GB, supports resume
winbox setup -y              # builds and provisions the VM
```

### Choosing the guest OS

`winbox setup` builds **Windows Server 2022** by default. Pass `--os` to build a
different target — **Windows Server 2025** or **Windows 11 Enterprise (Evaluation)**:

```bash
winbox setup --os server2025 -y   # Windows Server 2025 (Core, Evaluation)
winbox setup --os win11 -y        # Windows 11 Enterprise (Evaluation)
```

The choice is build-time and there is one VM at a time — switching OS means
`winbox destroy -y` then `winbox setup --os <other> -y`. Setup records the choice as
`VM_OS=` in `~/.winbox/config`, so every later command (`status`, `av`, `exec`, the
MCP server) resolves the same profile as the VM on disk; you can also set that key
yourself to change the default for a bare `winbox setup`. The right ISO is downloaded
automatically for the selected OS (or pass `--iso <path>` to use your own).

Notes for Server 2025:
- Same server-minimal build as 2022 (Server Core, no TPM/Secure-Boot gate, 100 MB
  ESP layout), but on the Windows 11 24H2 kernel (build 26100). `--desktop` selects
  Desktop Experience, same as 2022.
- Because it shares the 24H2 kernel, HVCI/VBS and Defender behavior can differ from
  2022 — `winbox av status` reports the real Tamper-Protection state. For `kdbg`,
  use explicit hardware breakpoints when HVCI is on; it blocks software 0xCC bps.

Notes for Win11:
- No TPM / Secure Boot required — setup injects the `LabConfig` bypass keys so the
  install proceeds on plain UEFI. `--desktop` is Server-only and rejected for Win11.
- Win11 needs a 64 GB system drive and the standard UEFI layout (larger ESP + MSR
  partition); setup handles both automatically (the disk is grown to 64 GB and the
  Windows partition lands on partition 3).
- **Defender:** Win11 client ships with Tamper Protection on, which normally blocks
  the registry-based disable. Setup clears it in the offline registry hive before
  first boot so Defender can be turned off during provisioning. This is best-effort
  (Defender's cloud component can re-arm it on a networked boot); `winbox av status`
  reports the Tamper-Protection state, and `winbox av disable` refuses honestly rather
  than falsely reporting success if TP is still on.
- If Microsoft rotates the eval ISO's download link, the auto-download fails loudly;
  grab the ISO manually and pass `--iso <path>`.

## Commands

`winbox --help` groups commands into seven sections:

```
VM Lifecycle       setup  provision  up  down  suspend  destroy  status  snapshot  restore  vnc
Execute            eventlogs  exec  shell  ssh  jobs  msi
Files              tools  upload  iso
Network            net  dns  hosts  domain
Target             applocker  autologin  av      (bidirectional — flip on to test bypass tools)
Malware Analysis   capture  detonate  sinkhole   (detonation lab — capture C2, sinkhole DNS, preflight)
Integrations       binfmt  kdbg  mcp  office
```

Each command supports `--help` for its own flags and subcommands.

## Usage

### Executing Commands

```bash
winbox exec whoami
winbox exec ipconfig /all
winbox exec Rubeus.exe kerberoast /domain:corp.local
winbox exec --timeout 300 SharpHound.exe -c All     # --timeout must come BEFORE the command
winbox exec --user alice --password secret whoami   # run as a local Windows user
```

The VM starts automatically if it's not running.

### Background Jobs

Long-running tools can run in the background:

```bash
winbox exec --bg Seatbelt.exe -group=all             # output buffered in guest agent memory
winbox exec --bg --log Certify.exe find /vulnerable   # output redirected to log files (tail -f)
winbox exec --bg --user alice --password secret whoami # background job as a local Windows user
winbox jobs list                                      # check status
winbox jobs output <job-id>                           # print output
winbox jobs kill <job-id>                             # kill a running job
```

With `--log`, output files are at `~/.winbox/shared/loot/.jobs/<id>.stdout` and `.stderr`.

### Interactive Shells

```bash
winbox shell                 # ConPTY reverse shell — runs as SYSTEM, supports terminal resize
winbox ssh                   # SSH into PowerShell (auto-auth via sshpass)
```

### Managing Tools

Tools placed in the shared directory are available at `Z:\tools\` in the VM and automatically on PATH:

```bash
winbox tools add Rubeus.exe SharpHound.exe Certify.exe
winbox tools list
winbox tools remove Rubeus.exe
```

### One-shot Uploads and MSI Installs

For files that shouldn't live permanently in the tools dir:

```bash
winbox upload payload.exe                         # stage at Z:\payload.exe
winbox upload payload.exe C:\Windows\Temp\p.exe   # also copy into the VM path

winbox msi VMware-tools.msi ADDLOCAL=ALL /norestart   # extra args pass through to msiexec
```

Both stage through the VirtIO-FS share and clean up on failure. `winbox msi` treats exit code 3010 (reboot required) as success.

### Event Logs

Query Windows event logs from inside the VM. Useful right after running a tool to see what Defender / Sysmon / Security audit logged in response.

```bash
winbox eventlogs                                              # Security log, last 1h, max 100 (CSV)
winbox eventlogs --since 5m --max 20                          # last 5 minutes
winbox eventlogs --log "Microsoft-Windows-Sysmon/Operational" # Sysmon channel
winbox eventlogs --log Security --id 4624 --id 4625 --since 1d
winbox eventlogs --level Error --since 1d --json | jq '.[0]'
winbox eventlogs --since 1h | csvgrep -c Id -m 4624           # pipe into csvkit
```

Default output is CSV (RFC 4180, fields `Time,Log,Level,Id,Provider,Message`). `--json` emits the raw `Get-WinEvent` JSON. Status messages go to stderr so stdout stays clean for piping. Newlines/tabs in Message are flattened to ` | ` so each event is exactly one CSV row. `--log` is repeatable for multi-channel queries; `--id` is repeatable and OR'd inside the filter.

Clear channels (destructive, prompts for confirmation unless `-y`):

```bash
winbox eventlogs clear --log Security                       # one channel
winbox eventlogs clear --log Security --log System -y       # multiple
winbox eventlogs clear --all -y                             # nuke (read-only / system-protected channels are skipped)
```

### Network

```bash
# Isolation
winbox net isolate           # disconnect VM from network (host-VM channels stay up)
winbox net connect           # reconnect VM to network
winbox net status            # show link state

# DNS
winbox dns view              # show DNS on Kali and VM
winbox dns set 10.10.10.2    # set VM DNS nameserver
winbox dns sync              # push Kali's resolv.conf nameservers to VM

# Hosts file
winbox hosts view
winbox hosts add 10.10.10.5 dc01.corp.local
winbox hosts set 10.10.10.5 dc01.corp.local   # idempotent — replaces existing entry
winbox hosts delete dc01.corp.local

# Active Directory
winbox domain join corp.local --ns 10.10.10.2 --user admin
# password is prompted interactively
winbox domain leave
```

### VM Lifecycle

```bash
winbox up                    # start or resume
winbox up --reboot           # graceful shutdown + start in one command
winbox down                  # graceful shutdown (needs a running, agent-responsive guest)
winbox down --force          # hard power-off (virsh destroy) — works on a paused or wedged VM
winbox suspend               # save state to disk (instant resume)
winbox status                # state, IP, disk usage, tool/loot counts
winbox destroy -y            # delete VM and all storage (clears jobs.json too)
winbox provision             # re-run provisioning script
```

### Snapshots

```bash
winbox snapshot              # list existing snapshots
winbox snapshot pre-attack   # create named snapshot (auto-shuts VM down first)
# ... do your thing ...
winbox restore pre-attack    # revert to clean state
```

### Office Installation

For testing macro-based payloads, install Office on a Desktop Experience VM:

```bash
winbox setup --desktop -y    # build VM with Desktop Experience
winbox autologin enable      # enable auto-login as Administrator (persistent across reboots)
winbox office                # install Word, Excel, PowerPoint with macros enabled
```

Requires a Microsoft 365 subscription. Macros are enabled (VBAWarnings=1) for Word, Excel, and PowerPoint.

### Persistent Autologin

```bash
winbox autologin enable      # writes all 6 Winlogon+PasswordLess keys Server 2022 needs
winbox autologin status
winbox autologin disable
```

Unlike the old 3-key approach, this actually survives reboots on Server 2022 (which otherwise silently wipes `DefaultPassword` on first boot without `ForceAutoLogon=1` and the `PasswordLess\Device\DevicePasswordLessBuildVersion=0` gate).

### AppLocker

Test application whitelisting bypass techniques:

```bash
winbox applocker enable      # enable AppLocker with default rules (Exe, Script, MSI, Appx)
winbox applocker status      # show enforcement status
winbox applocker disable     # disable AppLocker, clear policy, reboot
```

### Antivirus (Windows Defender)

```bash
winbox av disable            # disable Defender completely (reboot required — WinDefend is PPL)
winbox av status             # show Defender/AMSI protection status
winbox av enable             # re-enable Defender + AMSI (adds QEMU GA/VirtIO-FS exclusions)
```

### Transparent .exe Execution (binfmt_misc)

Register a binfmt_misc handler so `.exe` files run through winbox automatically:

```bash
sudo winbox binfmt enable
./SharpHound.exe -c All      # runs via winbox exec
sudo winbox binfmt disable
winbox binfmt status
```

### MCP Server (AI-driven vulnerability research)

The MCP server is the platform's agent control plane, not only a remote shell.
AI agents can manage and contain the VM, run code, instrument live targets from
the hypervisor, resolve PDB symbols, inspect protected address spaces, exercise
drivers and named pipes, change defenses, and retrieve bounded evidence without
constructing one-off transport glue.

**Install:**

```bash
pip install -e '.[mcp]'
```

**Add to Claude Code:**

```bash
claude mcp add winbox -- winbox mcp
```

**Available tools (75):**

User-mode primitives:

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
| `net_isolate()` | Disconnect VM from network (host-VM channels stay up) |
| `net_connect()` | Reconnect VM to network (restarts adapter, renews DHCP) |
| `net_unplug()` | Full air-gap (link down via virsh) |
| `eventlogs(log?, since?, ids?, provider?, level?, max_events?)` | Query Windows event logs via Get-WinEvent (returns JSON array; CLI defaults to CSV) |
| `eventlogs_clear(log?, all_logs?, confirm)` | Clear event channels via wevtutil cl. `confirm=True` required (destructive). |

Defender:

| Tool | Description |
|------|-------------|
| `av_status(timeout?)` | Report Defender/AMSI protection state (Get-MpComputerStatus + Get-MpPreference) |
| `av_enable()` | Re-enable Defender real-time protection, AMSI, and behavior monitoring |
| `av_disable(confirm)` | Disable Defender completely — sets GP registry keys then reboots the VM. `confirm=True` required. |

HVCI / Virtualization Based Security:

| Tool | Description |
|------|-------------|
| `hvci_status(timeout?)` | Report HVCI/VBS state (DeviceGuard registry keys + bcdedit hypervisorlaunchtype) |
| `hvci_disable(confirm)` | Disable HVCI and VBS — sets registry keys + bcdedit then reboots the VM. `confirm=True` required. |
| `hvci_enable(confirm)` | Re-enable HVCI and VBS. Reboots the VM. `confirm=True` required. |

Named pipes:

| Tool | Description |
|------|-------------|
| `pipe_list(filter?)` | Enumerate named pipes matching a pattern (JSON array) |
| `pipe_info(name)` | JSON: DACL/SDDL, mode, buffer sizes, max instances for a pipe |
| `pipe_connect(name, access?)` | One-shot pipe handle open; returns result or Win32 error |
| `pipe_open(name, access)` | Start a session — spawns a detached broker in the VM that holds the handle open |
| `pipe_send(session_id, data_hex)` | WriteFile through the session broker |
| `pipe_recv(session_id, size, timeout?)` | ReadFile through the session broker |
| `pipe_close(session_id)` | Close session + taskkill the broker |

Hypervisor-level kernel debug (via QEMU gdbstub, EDR-invisible):

On affected QEMU/KVM versions, debugger stop/resume corrupts Windows CET user
shadow-stack state. The debugger therefore fails closed unless
`UserShadowStack` is OFF. Preparation is explicit, saves the original policy,
and requires a reboot.

*Stateless walks and symbol management — work against the live VM without an attached session:*

| Tool | Description |
|------|-------------|
| `kdbg_cet_status()` | Report whether the current Windows boot is safe for QEMU GDB stop/resume |
| `kdbg_prepare(confirm)` | Back up the original mitigation policy and disable CET user shadow stacks; reboot required |
| `kdbg_restore_cet(confirm)` | Restore the backed-up mitigation policy; reboot required |
| `kdbg_start(port?, any_interface?)` | Start the gdbstub listener |
| `kdbg_stop()` | Stop the gdbstub listener |
| `kdbg_status(port?)` | Show stub state + reachability |
| `kdbg_symbols_load()` | Pull ntoskrnl.exe out, fetch PDB from msdl, persist symbols + struct layouts to `~/.winbox/symbols/` |
| `kdbg_user_symbols_load(pid, module, architecture?)` | Pull an x86/x64 module loaded in `pid`, fetch its matching PDB, and persist a separate architecture-correct symbol map |
| `kdbg_sym(name, search?, limit?, rva?)` | Resolve `mod!sym` to VA or RVA; substring search supported |
| `kdbg_struct(type_name, field?, module?)` | Dump full struct layout or one field offset |
| `kdbg_ps()` | Walk `PsActiveProcessHead` (JSON: pid, dtb, eprocess, name) |
| `kdbg_lm()` | Walk `PsLoadedModuleList` (JSON: base, size, name) |
| `kdbg_user_lm(pid)` | Walk native and WoW64 PEB loader views; every module is labelled x64 or x86 |
| `kdbg_read_va(pid, address, length)` | CR3-switching arbitrary-process read; works against PPL targets (1MB cap, hex bytes) |
| `kdbg_base_refresh()` | Re-resolve nt load base after ASLR reboot |

*Session daemon — long-running debug session (attach once, drive across many tool calls):*

Every `kdbg_*` MCP tool returns structured `winbox.mcp/1` content:
`{schema, ok, result, error}`. Failures use stable error codes, retryability,
and bounded recovery hints instead of prose that an agent must parse.

At a WoW64 compatibility-mode stop, the daemon uses 32-bit disassembly,
native-width stack entries, and a conservative hybrid call-chain walker.
Exact-build PDB FPO/frame records are preferred, followed by validated EBP
chains and bounded prologue simulation. Raw module-looking stack values remain
separate speculative candidates. Attach now freezes every native and x86
loader entry into a bounded content-addressed manifest before the daemon takes
QEMU's one RSP connection. PE machine, live image size, hash, and PDB identity
are verified before unwind metadata is trusted; manual per-DLL preloading is
no longer required.

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
| `kdbg_attach(pid, port?)` | Snapshot and symbol-enrich exact user binaries, then fork the session daemon and attach. Returns bounded `auto_stage` counts/failures |
| `kdbg_detach()` | Tear down the session and leave the VM running |
| `kdbg_session()` | Show current daemon state (target pid, attach time, bp count, halted vs running) |
| `kdbg_bp(target, mode?, condition?, wp_type?, wp_size?, actions?)` | Install an explicit hardware/software breakpoint or hardware watchpoint. Predicates support exact-width `byte`/`word`/`dword`/`qword` reads; actions additionally support bounded `bytes`/`ascii`/`utf16` capture. Action hits append JSONL traces and auto-continue. |
| `kdbg_bps()` | List installed bps with hit/skip/error counters |
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
| `kdbg_decomp(addr?, symbol?, module?, rva?, cursor?, before?, after?, full?, binary?, timeout?, detail="compact", lines?, assembly="nearby", instruction_bytes?, runtime_vas?)` | Resolve current RIP, runtime VA, symbol, or module+RVA, verify PE build identity, snapshot exact host content, and return stop-pinned RVA-linked assembly/pseudocode with bounded pagination; repeated VAs and raw bytes are opt-in |
| `kdbg_decomp_status()` | Report PyGhidra discovery, isolated worker/JVM state, and durable project-cache status without starting the JVM |
| `kdbg_decomp_cache()` | List content-keyed binary/project sizes, analysis profiles, and LRU timestamps |
| `kdbg_decomp_cache_prune(max_bytes?, older_than_days?, dry_run?)` | Dry-run-first LRU pruning; applying requires the worker to be stopped |
| `kdbg_ghidra_install(pull?)` | Build the checksum-pinned JDK 21 + Ghidra + PyGhidra Docker image |
| `kdbg_ghidra_run()` | Start and API-check the private, networkless persistent decompilation container |
| `kdbg_ghidra_stop()` | Stop/remove the labelled container while preserving analyzed projects and binary cache |

The `pipe_open` + `pipe_send`/`recv`/`close` family uses a persistent broker process per session (spawned as DETACHED_PROCESS | CREATE_NO_WINDOW inside the VM). IPC happens via `cmd.json`/`result.json` files on the VirtIO-FS share, so there's no VM round-trip on the polling path. This matters for protocols where a write on one handle must be answered on the same handle (stateless `send`/`recv` open fresh handles and never see each other's messages).

**Requires** Python installed in the VM — this is now done automatically as part of `winbox setup`.

## Architecture

```
Kali Linux
├── winbox control plane
│   ├── CLI (Python/Click)
│   └── MCP server (75 bounded agent tools)
├── hypervisor research plane
│   ├── QMP/HMP ────────────> VM + gdbstub lifecycle
│   ├── persistent RSP ─────> vCPUs, memory, break/watchpoints, stepping
│   ├── PDB/symbol store ───> Windows types, processes, modules, disassembly
│   └── Docker PyGhidra ────> private Unix API + exact RVA-focused pseudocode
├── guest interaction plane
│   ├── virtio-serial ──────> QEMU Guest Agent (execution + management)
│   ├── VirtIO-FS ──────────> ~/.winbox/shared/ <=> Z:\ in VM
│   ├── SSH ────────────────> OpenSSH Server (interactive PowerShell)
│   └── TCP listener ───────< ConPTY reverse shell (SYSTEM, resizable PTY)
├── containment/evidence plane
│   ├── libvirt nwfilter/link control
│   ├── bridge packet capture
│   └── DNS sinkhole + optional INETSim
│
└── Windows guest — Server Core 2022/2025 or Win11 (headless QEMU/KVM, plain VNC display)
    ├── QEMU Guest Agent          ← primary exec channel
    ├── VirtioFsSvc (WinFsp)      ← auto-mounts Z:\ on boot
    ├── OpenSSH Server            ← interactive sessions
    ├── Python 3.13               ← required for MCP Python/ioctl/mem_read tools
    ├── x64dbg (C:\Tools\x64dbg)  ← in-VM user-mode debugger
    ├── Defender disabled         ← no AV interference
    ├── Firewall disabled         ← no port blocking
    └── NAT via libvirt           ← reaches anything Kali can reach
```

The separation is deliberate: QMP owns lifecycle, one serialized RSP owner
controls debugger state, the guest agent handles in-guest automation, and
host-side networking enforces containment even when the guest is hostile.

## Configuration

Override defaults in `~/.winbox/config` (shell-style `KEY=VALUE`):

```bash
# VM resources
VM_NAME=winbox
VM_RAM=4096          # MB
VM_CPUS=4
VM_DISK=30           # GB

# Network
HOST_IP=192.168.122.1

# Credentials
VM_USER=Administrator
VM_PASSWORD=WinboxP@ss123

# Paths
WINBOX_DIR=~/.winbox
VIRTIO_ISO_URL=https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso
```

## Filesystem Layout

```
~/.winbox/
├── config                              # user config overrides (optional)
├── decomp/                             # private Docker/PyGhidra API state
│   ├── cache/binaries/                 # immutable full-SHA-256 PE copies
│   ├── projects/                       # durable version+SHA Ghidra projects
│   └── docker-build.log                # image-build diagnostics
├── jobs.json                           # background job state (cleared on winbox destroy)
├── .setup.lock                         # fcntl lock — serializes concurrent winbox setup
├── id_ed25519 / .pub                   # SSH keypair (generated during setup)
├── disk.qcow2                          # VM disk image
├── iso/
│   ├── SERVER_EVAL_x64FRE_en-us.iso    # Windows Server 2022 eval ISO
│   ├── SERVER2025_EVAL_x64FRE_en-us.iso # Windows Server 2025 eval ISO (--os server2025)
│   ├── WIN11_ENT_EVAL_x64FRE_en-us.iso # Windows 11 Enterprise eval ISO (--os win11)
│   ├── virtio-win.iso                  # VirtIO drivers
│   ├── OpenSSH-Win64.zip               # bundled OpenSSH
│   ├── winfsp.msi                      # WinFsp installer
│   ├── virtiofs.exe                    # VirtIO-FS service binary
│   ├── python-3.13.13-amd64.exe        # Python 3.13 installer for the guest
│   ├── x64dbg.zip                      # x64dbg snapshot (extracted to C:\Tools\x64dbg)
│   └── unattend.img                    # built during setup
├── captures/                           # winbox capture — host-side pcaps
│   ├── capture-<ts>.pcap
│   └── capture.pid                     # pidfile for the running capture
├── sinkhole/                           # winbox sinkhole — DNS sinkhole state
│   ├── queries.log                     # captured C2 domains (tab-sep)
│   ├── sinkhole.pid
│   └── inetsim.conf                    # written by `sinkhole inetsim`
└── shared/                             # VirtIO-FS share <=> Z:\ in VM
    ├── tools/                          # your pentest tools
    ├── .msi/                           # staging dir for winbox msi (cleaned up per-run)
    └── loot/                           # output directory
        └── .jobs/                      # background job log files
```

## Testing

```bash
pytest                                  # unit + coverage tests, no VM required
pytest -m integration                   # live end-to-end suite, drives the real VM
```

A bare `pytest` deselects everything marked `integration`, so it never touches a
VM you are using.

The live suite (`tests/test_e2e_live.py`) exercises every CLI command and every
MCP tool against whichever image `~/.winbox/config` points at, and is written to
pass on **all three** profiles (`server2022`, `server2025`, `win11`) — where they
genuinely differ (Tamper Protection, Server Core's smaller service set, the
Python payload) it asserts the profile-appropriate behavior instead of skipping.

`tests/e2e_manifest.py` records how each command and tool is covered — live, or
excluded with a stated reason — and `tests/test_e2e_coverage.py` checks that
manifest against the real click tree and MCP registry. Adding a command or tool
fails the build until you say how it gets exercised, which is what keeps "we
test everything" a claim you can verify rather than one that quietly rots.

To validate a change across both images:

```bash
winbox setup --os server2022 -y && pytest -m integration
winbox setup --os server2025 -y && pytest -m integration
winbox setup --os win11 -y      && pytest -m integration
```

## License

MIT
