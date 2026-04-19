# winbox

Run Windows pentest tools from Kali. Transparently.

winbox manages a headless Windows Server Core 2022 VM via QEMU/KVM. Type `winbox exec SharpHound.exe -c All -d corp.local` on your Kali box and it Just Works — the VM starts automatically, runs the command, and prints the output.

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

## Features

- **Transparent execution** — run `.exe` files as if they were native Kali commands
- **Auto-start** — VM boots on demand, use `winbox suspend` to save state
- **Shared filesystem** — `~/.winbox/shared/tools/` maps to `Z:\tools\` in Windows via VirtIO-FS
- **One-shot upload & MSI** — `winbox upload` stages files on Z:\, `winbox msi` installs an MSI and cleans up
- **Background jobs** — `--bg` for long-running tools, `--log` for persistent output
- **Interactive shells** — ConPTY SYSTEM shell with resize support, or SSH into PowerShell
- **Network integration** — VM traffic is NAT'd through Kali; push DNS, manage hosts file, join AD domains
- **Snapshots** — save and restore VM state (auto-shuts VM down, bare `winbox snapshot` lists)
- **AV toggle** — disable/enable Windows Defender on demand (`winbox av disable/enable`)
- **AppLocker** — enable AppLocker with default rules for bypass testing
- **Autologin** — persistent Administrator auto-login that survives reboots on Server 2022
- **Network isolation** — disconnect/reconnect VM NIC while keeping host-VM channels alive
- **binfmt_misc** — register `.exe` so you can run `./SharpHound.exe` directly from Kali
- **MCP server** — 31 tools that expose the VM to AI agents (Claude Code) for assisted vulnerability research, including a session-based named-pipe broker and hypervisor-level kernel debug
- **Hypervisor-level kernel debug** — `winbox kdbg` drives QEMU's gdbstub from outside the VM, with PDB-backed symbol cache, EPROCESS/module walkers, and CR3-switching memory reads (PPL-resistant, EDR-invisible)
- **VNC display** via virt-manager (`winbox vnc`) — plain VGA, no clipboard/resize
- **x64dbg in the guest** — bundled in setup, extracted to `C:\Tools\x64dbg`, both x32 and x64 on PATH
- **Python in the guest** — Python 3.13 installed during setup (pip, PATH, py.exe launcher) for MCP-driven research
- **No VM internet needed for setup** — all tools and dependencies are staged from the host side

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

## Installation

```bash
git clone https://github.com/totekuh/winbox.git
cd winbox
pip install -e .
```

Then build the VM (downloads Windows Server 2022 eval ISO + VirtIO drivers):

```bash
winbox iso download          # ~4.7 GB, supports resume
winbox setup -y              # builds and provisions the VM
```

## Commands

`winbox --help` groups commands into six sections:

```
VM Lifecycle   setup  up  down  suspend  destroy  status  snapshot  restore  provision
Execute        exec  shell  ssh  vnc  jobs  msi  eventlogs  kdbg
Files          tools  upload  iso
Network        net  dns  hosts  domain
Target         av  applocker  autologin     (bidirectional — flip on to test bypass tools)
Integrations   binfmt  mcp  office
```

Each command supports `--help` for its own flags and subcommands.

## Usage

### Executing Commands

```bash
winbox exec whoami
winbox exec ipconfig /all
winbox exec Rubeus.exe kerberoast /domain:corp.local
winbox exec --timeout 300 SharpHound.exe -c All     # --timeout must come BEFORE the command
```

The VM starts automatically if it's not running.

### Background Jobs

Long-running tools can run in the background:

```bash
winbox exec --bg Seatbelt.exe -group=all             # output buffered in guest agent memory
winbox exec --bg --log Certify.exe find /vulnerable   # output redirected to log files (tail -f)
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
winbox down                  # graceful shutdown
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

### MCP Server (AI-assisted vulnerability research)

winbox exposes an MCP server so AI agents (Claude Code, etc.) can interact with the Windows VM directly — run Python code, send IOCTLs to drivers, query/set registry, list processes, talk to named pipes.

**Install:**

```bash
pip install -e '.[mcp]'
```

**Add to Claude Code:**

```bash
claude mcp add winbox -- winbox mcp
```

**Available tools (33):**

User-mode primitives:

| Tool | Description |
|------|-------------|
| `python(code)` | Execute Python code in the VM (ctypes, winreg, COM, WMI — full Win32 access) |
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

Hypervisor-level kernel debug (via QEMU gdbstub + HMP, EDR-invisible):

| Tool | Description |
|------|-------------|
| `kdbg_start(port?, any_interface?)` | Start the gdbstub listener |
| `kdbg_stop()` | Stop the gdbstub listener |
| `kdbg_status(port?)` | Show stub state + reachability |
| `kdbg_symbols_load(module?, from_ghidra?, base?)` | Pull ntoskrnl.exe out, fetch PDB from msdl, persist symbols + struct layouts to `~/.winbox/symbols/` |
| `kdbg_sym(name, search?, limit?, rva?)` | Resolve `mod!sym` to VA or RVA; substring search supported |
| `kdbg_struct(type_name, field?, module?)` | Dump full struct layout or one field offset |
| `kdbg_ps()` | Walk `PsActiveProcessHead` (JSON: pid, dtb, eprocess, name) |
| `kdbg_lm()` | Walk `PsLoadedModuleList` (JSON: base, size, name) |
| `kdbg_read_va(pid, address, length)` | CR3-switching arbitrary-process read; works against PPL targets (1MB cap, hex bytes) |
| `kdbg_base_refresh()` | Re-resolve nt load base after ASLR reboot |

The `pipe_open` + `pipe_send`/`recv`/`close` family uses a persistent broker process per session (spawned as DETACHED_PROCESS | CREATE_NO_WINDOW inside the VM). IPC happens via `cmd.json`/`result.json` files on the VirtIO-FS share, so there's no VM round-trip on the polling path. This matters for protocols where a write on one handle must be answered on the same handle (stateless `send`/`recv` open fresh handles and never see each other's messages).

**Requires** Python installed in the VM — this is now done automatically as part of `winbox setup`.

## Architecture

```
Kali Linux
├── winbox CLI (Python/Click)
│   ├── virtio-serial ──────> QEMU Guest Agent (command execution, VM management)
│   ├── VirtIO-FS ──────────> ~/.winbox/shared/ <=> Z:\ in VM
│   ├── SSH ────────────────> OpenSSH Server (interactive PowerShell)
│   └── TCP listener ───────< ConPTY reverse shell (SYSTEM, resizable PTY)
│
└── Windows Server Core 2022 (headless QEMU/KVM, plain VNC display)
    ├── QEMU Guest Agent          ← primary exec channel
    ├── VirtioFsSvc (WinFsp)      ← auto-mounts Z:\ on boot
    ├── OpenSSH Server            ← interactive sessions
    ├── Python 3.13               ← required for MCP Python/ioctl/mem_read tools
    ├── x64dbg (C:\Tools\x64dbg)  ← in-VM user-mode debugger
    ├── Defender disabled         ← no AV interference
    ├── Firewall disabled         ← no port blocking
    └── NAT via libvirt           ← reaches anything Kali can reach
```

**Four channels:**
- **Guest Agent** (virtio-serial) — command execution for `winbox exec`, VM management
- **VirtIO-FS** — shared filesystem, zero-copy via shared memory
- **SSH** — interactive PowerShell sessions (`winbox ssh`)
- **ConPTY** — SYSTEM-level interactive shell with full PTY (`winbox shell`)

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
├── jobs.json                           # background job state (cleared on winbox destroy)
├── .setup.lock                         # fcntl lock — serializes concurrent winbox setup
├── id_ed25519 / .pub                   # SSH keypair (generated during setup)
├── disk.qcow2                          # VM disk image
├── iso/
│   ├── SERVER_EVAL_x64FRE_en-us.iso    # Windows Server 2022 eval ISO
│   ├── virtio-win.iso                  # VirtIO drivers
│   ├── OpenSSH-Win64.zip               # bundled OpenSSH
│   ├── winfsp.msi                      # WinFsp installer
│   ├── virtiofs.exe                    # VirtIO-FS service binary
│   ├── python-3.13.13-amd64.exe        # Python 3.13 installer for the guest
│   ├── x64dbg.zip                      # x64dbg snapshot (extracted to C:\Tools\x64dbg)
│   └── unattend.img                    # built during setup
└── shared/                             # VirtIO-FS share <=> Z:\ in VM
    ├── tools/                          # your pentest tools
    ├── .msi/                           # staging dir for winbox msi (cleaned up per-run)
    └── loot/                           # output directory
        └── .jobs/                      # background job log files
```

## License

MIT
