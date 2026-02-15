# winbox — Transparent Windows Execution Proxy for Kali

## What It Is

Python package that manages a headless Windows Server Core 2022 VM via QEMU/KVM.
Uses QEMU Guest Agent for command execution and VM management, VirtIO-FS for shared
filesystem, SSH for interactive sessions, and ConPTY for SYSTEM shells.
Type `winbox exec SharpHound.exe -c All -d corp.local` on Kali and it Just Works.

## Current State

- **Package:** installed editable (`pip install -e .`), `winbox` CLI works
- **Windows ISO:** downloaded at `~/.winbox/iso/SERVER_EVAL_x64FRE_en-us.iso` (4.7GB)
- **VM:** created, setup works end-to-end (`winbox setup -y`)
- **Tests:** 161 passing (shared conftest.py fixtures, mocked CLI tests)
- **Git:** `master` branch

## Package Structure

```
pyproject.toml              # hatchling build, click+rich deps, entry point: winbox.cli:cli
src/winbox/
  __init__.py               # version
  __main__.py               # python -m winbox
  binfmt.py                 # binfmt_misc registration for transparent .exe execution
  config.py                 # Config dataclass, ~/.winbox/config shell-style overrides
  tools.py                  # Shared tools dir management (add/list/remove)
  utils.py                  # human_size() — single shared utility
  cli/                      # CLI commands (Click)
    __init__.py             #   entry point, ensure_running, _ensure_z_drive
    vm.py                   #   up, down, suspend, destroy, status, snapshot, restore
    setup.py                #   setup, provision
    exec.py                 #   exec, shell, ssh
    network.py              #   dns (set, sync, view), hosts (view, add, set, delete), domain (join, leave)
    files.py                #   tools (add, list, remove), iso (download, status)
    binfmt.py               #   binfmt enable/disable/status CLI commands
  vm/                       # VM infrastructure
    __init__.py             #   re-exports: VM, VMState, GuestAgent, GuestAgentError, ExecResult
    lifecycle.py            #   VM class, VMState enum (virsh lifecycle)
    guest.py                #   GuestAgent, ExecResult (virtio-serial)
  setup/                    # Setup pipeline
    __init__.py             #   re-exports: check_prereqs, ..., download_iso, ISO_FILENAME
    installer.py            #   4-phase setup, download_openssh, download_winfsp, extract_virtiofs
    iso.py                  #   Windows ISO downloader (Microsoft CDN, resume)
  exec/                     # Execution
    __init__.py             #   re-exports: run_command, resolve_exe, open_shell
    executor.py             #   run_command, resolve_exe (tool path resolution)
    shell.py                #   open_shell (ConPTY reverse connection, SIGWINCH resize)
  data/                     # Bundled files for VM setup
    unattend.xml            # Windows unattended install (disk, OOBE, vioserial, viofs, guest agent, shutdown)
    bootstrap.ps1           # Provision wrapper: unpack provision.zip, run provision.ps1, shutdown
    provision.ps1           # Post-install script (disable Defender, install OpenSSH, WinFsp, VirtioFsSvc)
    tools.txt               # Tool download URLs (downloaded on Kali side during setup)
    config.default          # Default VM config values
    Invoke-ConPtyShell.ps1  # ConPTY reverse shell module (modified: ResizePseudoConsole support)
tests/
  conftest.py               # Shared fixtures: runner, cfg, mock_env (VM/GA/ensure_running)
  test_binfmt.py            # 41 tests — handler generation, registration, CLI commands
  test_config.py            # 29 tests — defaults, properties, config file parsing
  test_executor.py          # 9 tests — resolve_exe path resolution
  test_guest.py             # 12 tests — base64 decoding, ExecResult dataclass
  test_iso.py               # 4 tests — constants, URL resolution (live)
  test_network.py           # 20 tests — dns (set, sync, view), hosts (view, add, set, delete)
  test_status.py            # 22 tests — status output for all VM states
  test_tools.py             # 11 tests — add/remove/list with real filesystem
  test_utils.py             # 7 tests — human_size conversions
  test_vm.py                # 6 tests — VMState enum, disk_usage
```

## CLI Commands

```
winbox setup [--iso PATH] [-y]       # Build Windows VM (one-time, shows elapsed time)
winbox up                            # Start or resume VM
winbox down                          # Graceful shutdown
winbox suspend                       # Save state to disk (instant resume)
winbox destroy [-y]                  # Delete VM + storage
winbox status                        # VM state, IP, disk, tool/loot counts
winbox exec <cmd> [args]             # Execute in VM (via guest agent, auto-starts)
  [--timeout SEC]                    #   timeout flag must come BEFORE the command
winbox shell [--port PORT] [--pipe]  # Interactive SYSTEM shell via ConPTY (default 4444)
winbox tools add <file>...           # Copy to shared tools dir
winbox tools list                    # List tools
winbox tools remove <name>           # Remove tool
winbox iso download [-f]             # Download Windows Server 2022 eval ISO
winbox iso status                    # Check if ISO exists
winbox snapshot <name>               # Create named snapshot
winbox restore <name>                # Revert to snapshot
winbox provision                     # Re-run provisioning script (cleans up after)
winbox ssh                           # Interactive PowerShell via SSH (auto-auth)
winbox dns set <ip>                  # Set VM DNS nameserver
winbox dns sync                      # Push Kali's resolv.conf nameservers to VM
winbox dns view                      # Show DNS settings on both Kali and VM
winbox hosts view                    # Show VM hosts file entries
winbox hosts add <ip> <name>         # Append hosts entry
winbox hosts set <ip> <name>         # Add or replace hosts entry (idempotent)
winbox hosts delete <name>           # Remove hosts entries for hostname
winbox domain join <name>            # Join VM to AD domain (--ns, --user, --password)
winbox domain leave                  # Leave domain, reset DNS, return to workgroup
winbox binfmt enable [--no-persist]  # Register .exe handler for transparent execution
winbox binfmt disable                # Unregister .exe handler
winbox binfmt status                 # Show binfmt_misc registration status
```

## Setup Flow (4-phase)

```
Pre-setup downloads (Kali side, cached):
  VirtIO drivers ISO, OpenSSH-Win64.zip, WinFsp MSI, virtiofs.exe (from VirtIO ISO), tools from tools.txt

Phase 1: ISO Install
  virt-install --cdrom (Windows ISO + VirtIO ISO + unattend)
    with --memorybacking (memfd/shared) and --filesystem (virtiofs)
  → unattend.xml (as Administrator):
    1. pnputil install vioserial driver
    2. pnputil install viofs driver
    3. reg add disable MSI policy
    4. msiexec install guest agent
    5. net start QEMU-GA
    6. shutdown
  → wait for VM to shut down

Phase 2: Offline Injection
  virt-customize on disk.qcow2:
    --upload provision.zip:/provision.zip   (provision.ps1, tools.txt, .ssh_pubkey, OpenSSH-Win64.zip, winfsp.msi, virtiofs.exe)
    --upload bootstrap.ps1:/bootstrap.ps1

Phase 3: Provisioning via Guest Agent
  virsh start winbox
  Wait for guest agent
  guest-exec: powershell -File C:\bootstrap.ps1
  → bootstrap.ps1 (try/finally — always shuts down):
    unpack provision.zip, run provision.ps1, cleanup, Stop-Computer
  → provision.ps1 (ErrorAction Continue, per-section try/catch):
    disable Defender, disable firewall, install OpenSSH (from bundled zip),
    configure SSH keys, install WinFsp + VirtioFsSvc (mounts Z: via VirtIO-FS)
  → wait for VM to shut down

Phase 4: Snapshot
  Create 'clean' snapshot
```

## Architecture

```
Kali Linux
├── winbox CLI (Python/Click)
│   ├── virtio-serial ──────> QEMU Guest Agent (exec, VM management)
│   ├── VirtIO-FS ──────────> ~/.winbox/shared/ <=> Z:\ in VM (virtiofsd + memfd)
│   ├── SSH ────────────────> sshd in Windows VM (interactive session)
│   └── TCP listener ───────< ConPTY reverse shell (SYSTEM, interactive, resizable)
│
└── Windows Server Core 2022 (headless QEMU/KVM)
    ├── QEMU Guest Agent (exec + VM management channel)
    ├── VirtioFsSvc (WinFsp + virtiofs.exe, auto-mounts Z: on boot)
    ├── OpenSSH Server (installed from bundled zip, not Windows Update)
    ├── ConPTY reverse shell (Invoke-ConPtyShell.ps1 from Z:\, supports resize)
    ├── VirtIO viostor (disk) + vioserial (agent) + viofs (filesystem)
    ├── e1000 NIC (libvirt default NAT, 192.168.122.x)
    └── Defender/Firewall disabled
```

Three channels:
- **Guest agent** — command execution (primary for `winbox exec`) + VM management (ping, wait, provisioning, shutdown)
- **VirtIO-FS** — shared filesystem (virtiofsd on host, VirtioFsSvc on guest, Z: auto-mounted via shared memory)
- **SSH** — interactive PowerShell session (`winbox ssh` only, auto-auth via sshpass)
- **ConPTY** — interactive SYSTEM shell via TCP reverse connection (guest agent fires, Kali listens)

Network: libvirt default NAT. VM traffic is masqueraded through host IP —
tools in the VM can reach any target the Kali host can reach.

## Key Design Decisions

- `winbox exec` passes all flags through to Windows commands (ignore_unknown_options + UNPROCESSED)
- `--timeout` is long-form only on exec (no `-t`) to avoid conflicts with tool flags
- `winbox exec` uses guest agent for command execution (output captured, printed on completion)
- `winbox ssh` uses SSH with sshpass auto-auth, drops into PowerShell (not cmd.exe)
- bootstrap.ps1 uses try/finally — Stop-Computer always runs regardless of errors
- provision.ps1 uses ErrorAction Continue with per-section try/catch — never aborts
- unattend.xml auto-logon as Administrator (built-in admin bypasses UAC entirely)
- VirtIO serial + VirtIO-FS drivers installed in FirstLogonCommands before guest agent MSI
- MSI policy disabled via reg add before msiexec (Server 2022 blocks MSI by default)
- VirtIO-FS: virtiofsd managed by libvirt (auto-starts/stops with VM), memfd shared memory
- VirtioFsSvc registered as auto-start service — Z: available immediately on boot
- `winbox setup -y` auto-destroys previous VM, orphaned disk/unattend files
- Provisioning files (provision.ps1, tools.txt) cleaned from tools dir after re-provision
- Rich markup disabled on command output (tools like Rubeus output bracket syntax)
- Config stores vm_user (Administrator) and vm_password — single source of truth
- `.exe` resolution is case-insensitive (`Tool.EXE` resolves to `Z:\tools\Tool.EXE`)
- `human_size()` lives in `utils.py` (single source, used by executor/tools/iso/vm)
- Config silently skips invalid int values (`VM_RAM=abc` keeps default)
- TYPE_CHECKING guarded imports for Config across modules (avoids circular imports)
- ISO download supports resume via HTTP Range headers
- `winbox shell` uses ConPTY reverse shell — GA fires detached PowerShell, Kali listens on virbr0
- ConPTY script always refreshed on VirtIO-FS share (no stale cache)
- `winbox shell` supports terminal resize — SIGWINCH sends in-band `\x00RSIZ` + rows/cols over socket, C# side calls ResizePseudoConsole
- `exec_detached` used for bootstrap provisioning and shell launch — prevents GA timeout on long ops
- OpenSSH installed from bundled Win32-OpenSSH zip (no Windows Update dependency)
- WinFsp MSI + virtiofs.exe bundled in provision.zip (extracted from VirtIO ISO on Kali side)
- Tools downloaded on Kali side during setup (not inside VM) — eliminates VM network dependency
- `winbox dns sync` reads /etc/resolv.conf nameservers and pushes them to VM via guest agent
- `winbox hosts set` is idempotent — replaces existing entry for hostname or adds new
- `winbox domain join` validates credentials via LDAP bind + checks ms-DS-MachineAccountQuota before join
- `winbox domain leave` unjoins cleanly (Remove-Computer), resets DNS to DHCP, reboots
- binfmt_misc handler copies .exe to tools dir if not there, then runs `winbox exec`

## Filesystem Layout (runtime)

```
~/.winbox/
├── config                              # User config overrides (optional)
├── id_ed25519 / .pub                   # SSH keypair
├── disk.qcow2                          # VM disk
├── iso/
│   ├── SERVER_EVAL_x64FRE_en-us.iso    # Windows ISO (4.7GB)
│   ├── virtio-win.iso                  # VirtIO drivers (downloaded during setup)
│   ├── OpenSSH-Win64.zip               # Bundled OpenSSH (downloaded during setup)
│   ├── winfsp.msi                      # WinFsp installer (downloaded during setup)
│   ├── virtiofs.exe                    # VirtIO-FS service binary (extracted during setup)
│   └── unattend.img                    # Built during setup
└── shared/                             # VirtIO-FS share <=> Z:\ in VM
    ├── Invoke-ConPtyShell.ps1          # ConPTY script (refreshed each shell invocation)
    ├── tools/                          # Pentest tools (.exe files, downloaded during setup)
    └── loot/                           # Output directory
```

## Prerequisites

- `qemu-system-x86_64`, `virsh`, `virt-install`, `virt-customize`, `7z`, `jq`
- `virtiofsd` (at `/usr/libexec/virtiofsd` or on PATH)
- `/dev/kvm` (KVM hardware virtualization)
- `mkisofs` or `genisoimage` (for unattend image)
- `sshpass` (optional, for auto-auth SSH — falls back to manual password)
- `default` libvirt network must exist and be active
