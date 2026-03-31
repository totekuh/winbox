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
- **Auto-start** — VM boots on demand, suspends when idle
- **Shared filesystem** — `~/.winbox/shared/tools/` maps to `Z:\tools\` in Windows via VirtIO-FS
- **Background jobs** — `--bg` for long-running tools, `--log` for persistent output
- **Interactive shells** — ConPTY SYSTEM shell with resize support, or SSH into PowerShell
- **Network integration** — VM traffic is NAT'd through Kali; push DNS, manage hosts file, join AD domains
- **Snapshots** — save and restore VM state
- **binfmt_misc** — register `.exe` so you can run `./SharpHound.exe` directly from Kali
- **No internet in VM** — all tools and dependencies are staged from the host side

## Prerequisites

Install on Kali (most are pre-installed):

```bash
sudo apt install qemu-system-x86 qemu-utils libvirt-daemon-system virtinst \
    libguestfs-tools p7zip-full genisoimage sshpass wget
```

Required:
- `qemu-system-x86_64`, `virsh`, `virt-install`, `virt-customize`
- `7z` (p7zip-full)
- `virtiofsd` (at `/usr/libexec/virtiofsd` or on PATH)
- `/dev/kvm` (hardware virtualization must be enabled)
- `mkisofs` or `genisoimage`
- `wget`
- `default` libvirt network (active)

Optional:
- `sshpass` — auto-auth for `winbox ssh` (falls back to manual password entry)

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

### Network

```bash
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
winbox down                  # graceful shutdown
winbox suspend               # save state to disk (instant resume)
winbox status                # state, IP, disk usage, tool/loot counts
winbox destroy -y            # delete VM and all storage
winbox provision             # re-run provisioning script
```

### Snapshots

```bash
winbox snapshot pre-attack
# ... do your thing ...
winbox restore pre-attack    # revert to clean state
```

### Office Installation

For testing macro-based payloads, install Office on a Desktop Experience VM:

```bash
winbox setup --desktop -y    # build VM with Desktop Experience
winbox office                # install Word, Excel, PowerPoint with macros enabled
```

Requires a Microsoft 365 subscription. Macros are enabled (VBAWarnings=1) for Word, Excel, and PowerPoint.

### Transparent .exe Execution (binfmt_misc)

Register a binfmt_misc handler so `.exe` files run through winbox automatically:

```bash
sudo winbox binfmt enable
./SharpHound.exe -c All      # runs via winbox exec
sudo winbox binfmt disable
winbox binfmt status
```

## Architecture

```
Kali Linux
├── winbox CLI (Python/Click)
│   ├── virtio-serial ──────> QEMU Guest Agent (command execution, VM management)
│   ├── VirtIO-FS ──────────> ~/.winbox/shared/ <=> Z:\ in VM
│   ├── SSH ────────────────> OpenSSH Server (interactive PowerShell)
│   └── TCP listener ───────< ConPTY reverse shell (SYSTEM, resizable PTY)
│
└── Windows Server Core 2022 (headless QEMU/KVM)
    ├── QEMU Guest Agent          ← primary exec channel
    ├── VirtioFsSvc (WinFsp)      ← auto-mounts Z:\ on boot
    ├── OpenSSH Server            ← interactive sessions
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
├── jobs.json                           # background job state
├── id_ed25519 / .pub                   # SSH keypair (generated during setup)
├── disk.qcow2                          # VM disk image
├── iso/
│   ├── SERVER_EVAL_x64FRE_en-us.iso    # Windows Server 2022 eval ISO
│   ├── virtio-win.iso                  # VirtIO drivers
│   ├── OpenSSH-Win64.zip               # bundled OpenSSH
│   ├── winfsp.msi                      # WinFsp installer
│   ├── virtiofs.exe                    # VirtIO-FS service binary
│   └── unattend.img                    # built during setup
└── shared/                             # VirtIO-FS share <=> Z:\ in VM
    ├── tools/                          # your pentest tools
    └── loot/                           # output directory
        └── .jobs/                      # background job log files
```

## License

MIT
