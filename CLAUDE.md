# winbox — Transparent Windows Execution Proxy for Kali

## What It Is

Python package that manages a headless Windows Server Core 2022 VM via QEMU/KVM.
Uses QEMU Guest Agent (virtio-serial) for command execution and SMB for shared filesystem.
Type `winbox exec SharpHound.exe -c All -d corp.local` on Kali and it Just Works.

## Current State

- **Package:** installed editable (`pip install -e .`), `winbox` CLI works
- **Windows ISO:** downloaded at `~/.winbox/iso/SERVER_EVAL_x64FRE_en-us.iso` (4.7GB)
- **VM:** not yet created — `winbox setup` has not been run
- **Tests:** 78 passing, no mocking needed
- **Git:** `master` branch

## Package Structure

```
pyproject.toml              # hatchling build, click+rich deps, entry point: winbox.cli:cli
src/winbox/
  __init__.py               # version
  __main__.py               # python -m winbox
  cli.py                    # Click CLI — all subcommands, all imports at top level
  config.py                 # Config dataclass, ~/.winbox/config shell-style overrides
  vm.py                     # VM lifecycle via virsh (start/stop/suspend/destroy/snapshot/wait_shutdown)
  guest.py                  # QEMU Guest Agent over virtio-serial (exec, ping, wait)
  executor.py               # winbox exec logic — tool path resolution, output file detection
  installer.py              # winbox setup pipeline — virt-install, virt-customize, firstboot
  smb.py                    # impacket-smbserver lifecycle (start/stop/is_running)
  iso.py                    # Windows ISO downloader — Microsoft CDN, resume, progress bar
  tools.py                  # Shared tools dir management (add/list/remove)
  utils.py                  # human_size() — single shared utility
  data/                     # Bundled files for VM setup
    unattend.xml            # Windows unattended install (minimal: disk + OOBE + guest agent + shutdown)
    bootstrap.ps1           # Firstboot wrapper: unpack provision.zip, run provision.ps1, shutdown
    provision.ps1           # Post-install script (disable Defender, SSH, SMB, download tools)
    tools.txt               # Tool download URLs
    config.default          # Default VM config values
tests/
  test_config.py            # 29 tests — defaults, properties, config file parsing
  test_executor.py          # 9 tests — resolve_exe path resolution
  test_guest.py             # 12 tests — base64 decoding, ExecResult dataclass
  test_iso.py               # 4 tests — constants, URL resolution (live)
  test_tools.py             # 11 tests — add/remove/list with real filesystem
  test_utils.py             # 7 tests — human_size conversions
  test_vm.py                # 6 tests — VMState enum, disk_usage
```

## CLI Commands

```
winbox setup [--iso PATH] [-y]     # Build Windows VM (one-time)
winbox up                          # Start or resume VM
winbox down                        # Graceful shutdown
winbox suspend                     # Save state to disk (instant resume)
winbox destroy [-y]                # Delete VM + storage
winbox status                      # VM state, IP, disk, tool/loot counts
winbox exec <cmd> [args] [-t SEC]  # Execute in VM (auto-starts if needed)
winbox tools add <file>...         # Copy to shared tools dir
winbox tools list                  # List tools
winbox tools remove <name>         # Remove tool
winbox iso download [-f]           # Download Windows Server 2022 eval ISO
winbox iso status                  # Check if ISO exists
winbox snapshot <name>             # Create named snapshot
winbox restore <name>              # Revert to snapshot
winbox provision                   # Re-run provisioning script
winbox ssh                         # Fallback interactive SSH
```

## Setup Flow (4-phase grayline approach)

```
Phase 1: ISO Install
  virt-install --cdrom (Windows ISO + VirtIO ISO + unattend)
  → unattend.xml: disk layout, OOBE, admin account, install guest agent, shutdown
  → wait for VM to shut down

Phase 2: Offline Provision
  virt-customize on disk.qcow2:
    --upload provision.zip:/provision.zip
    --upload bootstrap.ps1:/bootstrap.ps1
    --firstboot-command 'powershell -File C:\bootstrap.ps1'

Phase 3: Firstboot
  Start SMB server (so guest can map Z: during provision)
  virsh start winbox
  → bootstrap.ps1: unpack provision.zip, run provision.ps1, cleanup, shutdown
  → wait for VM to shut down

Phase 4: Snapshot
  Create 'clean' snapshot
```

## Architecture

```
Kali Linux
├── winbox CLI (Python/Click)
│   ├── virtio-serial ──> QEMU Guest Agent ──> cmd.exe in Windows VM
│   └── SMB share ──────> ~/.winbox/shared/ <=> Z:\ in Windows VM
│
└── Windows Server Core 2022 (headless QEMU/KVM)
    ├── QEMU Guest Agent (command execution)
    ├── VirtIO viostor (disk driver, SATA bus)
    ├── e1000 NIC (libvirt default NAT, 192.168.122.x)
    └── Defender/Firewall disabled
```

Two channels: guest agent for execution (virtio-serial),
SMB share for files (impacket-smbserver on host, net use Z: in guest).
Networking via libvirt default NAT for SMB + AD targets.

## Key Design Decisions

- `exec_powershell()` uses `-EncodedCommand` (base64 UTF-16LE) to avoid quote hell
- `.exe` resolution is case-insensitive (`Tool.EXE` resolves to `Z:\tools\Tool.EXE`)
- `_decode_b64` catches only `binascii.Error`/`ValueError`, not bare Exception
- `human_size()` lives in `utils.py` (single source, used by executor/tools/iso/vm)
- Config silently skips invalid int values (`VM_RAM=abc` keeps default)
- TYPE_CHECKING guarded imports for Config across modules (avoids circular imports)
- ISO download supports resume via HTTP Range headers
- All CLI imports are at the top of cli.py (no lazy imports)
- SMB share (impacket-smbserver) replaces virtiofs — no root, no system config, no guest drivers
- SMB server starts/stops with VM lifecycle (winbox up/down), PID tracked in ~/.winbox/smb.pid
- Networking: `--network network=default,model=e1000` (NAT, no VirtIO NIC driver needed)
- Provisioning: virt-customize injects files offline, firstboot runs provision.ps1
- provision.ps1 detects its context (C:\Provision\ for firstboot, Z:\tools\ for re-provision)

## Filesystem Layout (runtime)

```
~/.winbox/
├── config                              # User config overrides (optional)
├── id_ed25519 / .pub                   # SSH keypair (fallback)
├── disk.qcow2                          # VM disk
├── iso/
│   ├── SERVER_EVAL_x64FRE_en-us.iso    # Windows ISO (4.7GB)
│   ├── virtio-win.iso                  # VirtIO drivers (downloaded during setup)
│   └── unattend.img                    # Built during setup
└── shared/                             # SMB share <=> Z:\ in VM
    ├── tools/                          # Pentest tools (.exe files)
    ├── loot/                           # Output directory (exec CWDs here)
    └── .ssh_pubkey                     # SSH pub key for provisioning
```

## Prerequisites

- `qemu-system-x86_64`, `virsh`, `virt-install`, `virt-customize`, `jq`, `impacket-smbserver`
- `/dev/kvm` (KVM hardware virtualization)
- `mkisofs` or `genisoimage` (for unattend image)
- `default` libvirt network must exist and be active

## What's Next

1. Run `winbox setup` to create the VM (ISO is ready)
2. Test end-to-end: `winbox exec cmd.exe /c "echo hello"`
3. Test with real tools (SharpHound, Rubeus)
