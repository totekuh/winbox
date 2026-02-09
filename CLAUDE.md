# Plan: `winbox` — Transparent Windows Execution Proxy for Kali

## Context

SharpHound and many other offensive Windows tools (Rubeus, Certify, Seatbelt, etc.) are .NET Framework 4.7.2 apps deeply tied to Windows APIs (P/Invoke into samlib.dll, netapi32.dll, advapi32.dll, etc.). Wine can't run them. Porting is impractical. But this Kali box has KVM, QEMU, libvirt all installed with 30GB RAM and 16 cores.

**The idea:** A lightweight, headless Windows VM that acts as a transparent execution proxy. You type `winbox exec SharpHound.exe -c All -d corp.local` on Kali and it Just Works — output appears instantly on your Kali filesystem.

## What We're Building

`winbox` — a bash CLI that manages a headless Windows Server Core VM via QEMU/KVM. Uses **QEMU Guest Agent** for command execution (no SSH needed, no network dependency) and **virtiofs** for shared filesystem (no SCP, instant file access).

```bash
winbox setup                                        # One-time: build VM, install tools
winbox up                                           # Start/resume VM
winbox exec SharpHound.exe -c All -d corp.local     # Run tool — output instant at ~/.winbox/shared/loot/
winbox exec Rubeus.exe kerberoast                   # Any Windows binary
winbox tools add ./custom-tool.exe                  # Drop a tool into shared tools dir
winbox suspend                                      # Save VM state (instant resume)
winbox down                                         # Shutdown VM
winbox destroy                                      # Delete VM + disk (OPSEC cleanup)
winbox status                                       # VM state, IP, uptime
winbox snapshot <name>                              # Create named snapshot
winbox restore <name>                               # Restore to snapshot
winbox ssh                                          # Fallback: interactive SSH shell
```

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Kali Linux                                                  │
│                                                              │
│  ┌──────────┐  virtio-serial   ┌──────────────────────────┐  │
│  │ winbox   │─────────────────>│ Windows Server Core 2022 │  │
│  │ CLI      │  (qemu-ga)       │ (headless QEMU/KVM VM)   │  │
│  │          │<─────────────────│                          │  │
│  └────┬─────┘  guest-exec +    │ - QEMU Guest Agent       │  │
│       │        stdout/stderr   │ - .NET Framework 4.7.2   │  │
│       │                        │ - VirtIO drivers         │  │
│       │   virtiofs             │ - WinFsp + virtiofs svc  │  │
│       │   (shared mount)       │                          │  │
│  ~/.winbox/shared/ <==========>│ Z:\ drive                │  │
│  ├── tools/                    │ ├── Z:\tools\            │  │
│  │   ├── SharpHound.exe        │ │   ├── SharpHound.exe   │  │
│  │   ├── Rubeus.exe            │ │   ├── Rubeus.exe       │  │
│  │   └── ...                   │ │   └── ...              │  │
│  └── loot/                     │ └── Z:\loot\             │  │
│      └── (output appears       │     └── (tools write     │  │
│          instantly here)       │         output here)     │  │
│                                └──────────────────────────┘  │
│                                       │                      │
│                                bridged network               │
│                                (reaches AD targets)          │
└──────────────────────────────────────────────────────────────┘
                                        │
                                        v
                                ┌───────────────┐
                                │  Target AD    │
                                │  Environment  │
                                └───────────────┘
```

**Two communication channels, zero network dependency for execution:**
- **QEMU Guest Agent** (virtio-serial) — command execution, no TCP/IP needed
- **virtiofs** (shared memory) — instant file access, no transfer overhead

Networking is only needed for the VM to reach AD targets.

## Components

### 1. `winbox` CLI — `/home/tr1x/tools/winbox/winbox`

Single bash script, ~400-500 lines. Subcommands:

| Command | What it does |
|---------|-------------|
| `setup` | Build Windows VM with unattend.xml, install QEMU-GA + virtiofs + tools |
| `up` | `virsh start` or `virsh restore` (from managedsave) |
| `down` | `guest-exec shutdown.exe /s /t 0` via guest agent |
| `suspend` | `virsh managedsave` — saves RAM to disk, instant resume |
| `destroy` | `virsh undefine --remove-all-storage --managed-save` — full cleanup |
| `exec <cmd>` | `guest-exec` via virtio-serial, poll for output, decode+print |
| `tools add <file>` | `cp` file to `~/.winbox/shared/tools/` (instant via virtiofs) |
| `tools list` | `ls ~/.winbox/shared/tools/` |
| `status` | `virsh domstate` + `virsh domifaddr` + disk usage |
| `snapshot <name>` | `virsh snapshot-create-as winbox <name>` |
| `restore <name>` | `virsh snapshot-revert winbox <name>` |
| `ssh` | Fallback interactive SSH session |

### 2. `winbox exec` — The core feature

```bash
winbox_exec() {
    ensure_running  # auto-start/resume if VM is off

    # Timestamp marker for detecting new output files
    touch "$SHARED_DIR/.exec_marker"

    # Resolve tool path: bare "SharpHound.exe" -> "Z:\tools\SharpHound.exe"
    local exe="$1"; shift
    if [[ "$exe" == *.exe ]] && [[ "$exe" != *\\* ]]; then
        exe="Z:\\tools\\$exe"
    fi

    # Build full command: cd to loot dir, then run
    local full_cmd="cd /d Z:\\loot && $exe $*"

    # Execute via QEMU Guest Agent (virtio-serial, no network)
    local result=$(virsh qemu-agent-command "$VM_NAME" \
        "$(jq -n --arg cmd "$full_cmd" \
        '{"execute":"guest-exec","arguments":{"path":"cmd.exe","arg":["/c",$cmd],"capture-output":true}}')" \
        2>/dev/null)

    local pid=$(echo "$result" | jq -r '.return.pid')
    [ "$pid" = "null" ] && { echo "[!] Failed to execute"; return 1; }

    # Poll for completion
    local status
    while true; do
        status=$(virsh qemu-agent-command "$VM_NAME" \
            "$(jq -n --argjson pid "$pid" \
            '{"execute":"guest-exec-status","arguments":{"pid":$pid}}')" \
            2>/dev/null)
        [ "$(echo "$status" | jq -r '.return.exited')" = "true" ] && break
        sleep 0.5
    done

    # Decode and print stdout/stderr (base64 encoded by guest agent)
    local out_b64=$(echo "$status" | jq -r '.return."out-data" // empty')
    local err_b64=$(echo "$status" | jq -r '.return."err-data" // empty')
    local exitcode=$(echo "$status" | jq -r '.return.exitcode')

    [ -n "$out_b64" ] && echo "$out_b64" | base64 -d
    [ -n "$err_b64" ] && echo "$err_b64" | base64 -d >&2

    # List new output files (already on host via virtiofs — no pulling needed)
    local new_files=$(find "$SHARED_DIR/loot" -newer "$SHARED_DIR/.exec_marker" -type f 2>/dev/null)
    if [ -n "$new_files" ]; then
        echo ""
        echo "[+] Output files:"
        echo "$new_files" | while read f; do
            echo "    $f ($(du -h "$f" | cut -f1))"
        done
    fi

    return "${exitcode:-1}"
}
```

**How output works:**
1. Before exec: touch a timestamp marker
2. Command CWDs to `Z:\loot\` (= `~/.winbox/shared/loot/` on host)
3. Tool runs, drops output in CWD
4. After exec: `find` files newer than marker — they're already on Kali. Just list them.

### 3. VM Setup — `winbox setup` flow

```
1. Check prereqs: qemu-system-x86_64, virsh, virt-install, jq, /dev/kvm
2. Create dirs: ~/.winbox/{iso,shared/tools,shared/loot}
3. Prompt for Windows Server 2022 Evaluation ISO path
4. Download VirtIO drivers ISO from Fedora if not cached:
   https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso
5. Generate SSH keypair at ~/.winbox/id_ed25519 (for fallback SSH)
6. Build floppy image containing unattend.xml (for automated Windows install)
7. Run virt-install with:
   --name winbox
   --ram 4096 --vcpus 4
   --disk path=$HOME/.winbox/disk.qcow2,size=30,bus=virtio
   --cdrom <windows.iso>
   --disk <virtio-win.iso>,device=cdrom
   --disk <floppy.img>,device=floppy
   --network bridge=virbr0,model=virtio
   --channel unix,target.type=virtio,target.name=org.qemu.guest_agent.0
   --memorybacking source.type=memfd,access.mode=shared
   --filesystem type=mount,driver.type=virtiofs,source.dir=$HOME/.winbox/shared,target.dir=winbox_share
   --os-variant win2k22
   --graphics none --noautoconsole
8. Wait for install (~10-15 min unattended)
9. Post-install provision via guest-agent (run provision.ps1)
10. Snapshot clean state: virsh snapshot-create-as winbox clean
```

### 4. `unattend.xml` — automated Windows install

Key sections:
- Server Core: `SERVERSTANDARDCORE` (no GUI)
- Single NTFS partition, full disk, VirtIO driver ref from CD
- Create `winbox` admin user, auto-logon
- FirstLogonCommands (runs once after install):
  - Install QEMU Guest Agent MSI from VirtIO CD: `msiexec /i D:\guest-agent\qemu-ga-x86_64.msi /qn`
  - Install VirtIO FS driver: `pnputil /add-driver D:\viofs\w11\amd64\viofs.inf /install`
  - Install WinFsp (download URL or bundle on shared drive)
  - Create+start VirtioFsSvc: `sc create VirtioFsSvc binPath=... start=auto depend=VirtioFsDrv`
  - Enable OpenSSH Server (fallback access)
  - Disable Defender + Firewall
  - Run provision.ps1 (tool downloads)

### 5. `provision.ps1`

```powershell
# Disable Defender (tools get flagged)
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true

# Disable firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# OpenSSH fallback
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic

# SSH key (read from shared mount)
$pubkey = Get-Content "Z:\tools\.ssh_pubkey"
$authKeys = "C:\ProgramData\ssh\administrators_authorized_keys"
Set-Content -Path $authKeys -Value $pubkey
icacls $authKeys /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"

# Download tools to shared mount
$urls = @(
    "https://github.com/SpecterOps/SharpHound/releases/download/v2.9.0/SharpHound-v2.9.0.zip"
)
foreach ($url in $urls) {
    $tmp = "$env:TEMP\tool.zip"
    Invoke-WebRequest -Uri $url -OutFile $tmp
    Expand-Archive -Path $tmp -DestinationPath Z:\tools\ -Force
    Remove-Item $tmp
}
```

### 6. Helper functions

```bash
vm_state()       # virsh domstate $VM_NAME
vm_ip()          # virsh domifaddr $VM_NAME | parse IP
ga_cmd()         # virsh qemu-agent-command $VM_NAME "$1" --timeout 30
ensure_running() # check state, start/restore if needed, wait for guest-agent ping
wait_for_ga()    # loop: ga_cmd '{"execute":"guest-ping"}' until success
load_config()    # source config.default, then ~/.winbox/config overrides
```

## File Structure

```
/home/tr1x/tools/winbox/
├── winbox                    # Main CLI (single bash script)
├── setup/
│   ├── unattend.xml          # Windows unattended install answer file
│   ├── provision.ps1         # Post-install config script
│   └── tools.txt             # Tool download URLs
└── config.default            # Default VM config
```

```
~/.winbox/                    # User state (created by setup)
├── config                    # User config overrides
├── id_ed25519 / .pub         # SSH keypair (fallback)
├── iso/                      # Cached ISOs
├── disk.qcow2                # VM disk
└── shared/                   # virtiofs mount <-> Z:\ in VM
    ├── tools/                # Pentest tools
    ├── loot/                 # Output directory
    └── .ssh_pubkey           # SSH pub key for provisioning
```

## Config — `config.default`

```bash
VM_NAME=winbox
VM_RAM=4096
VM_CPUS=4
VM_DISK=30
VM_BRIDGE=virbr0
SHARED_DIR=$HOME/.winbox/shared
```

## Design Decisions

1. **QEMU Guest Agent** — commands go over virtio-serial, not TCP/IP. Works even if VM networking is broken.
2. **virtiofs** — shared folder, tools+output live on host filesystem. Zero transfer. Drop exe on Kali, it's in Windows instantly.
3. **SSH as fallback only** — for interactive debug sessions.
4. **Single bash script** — only dependency beyond standard Kali is `jq`.
5. **Auto-start on exec** — VM suspended/off? `winbox exec` brings it up first.
6. **CWD = Z:\loot\** — exec commands cd there first so output lands in shared dir.
7. **VirtIO everything** — disk, network, serial (guest agent), fs (virtiofs).

## Prerequisites

On this Kali (verified):
- `/dev/kvm` ✅ | `qemu-system-x86_64` ✅ | `virsh` ✅

Need to install/obtain:
- `virt-install`: `apt install virtinst`
- `jq`: `apt install jq` (probably already present)
- Windows Server 2022 Evaluation ISO (~5GB, free from Microsoft)
- VirtIO drivers ISO (auto-downloaded during setup from Fedora)

## Implementation Order

1. **CLI skeleton + helpers** — subcommand dispatch, config, `ga_cmd()`, `ensure_running()`, `wait_for_ga()`
2. **`exec`** — guest-exec, poll, decode stdout/stderr, list new loot files
3. **`up`, `down`, `suspend`, `destroy`, `status`, `snapshot`, `restore`** — lifecycle via virsh
4. **`tools add/list`** — cp/ls on shared dir
5. **`setup`** — unattend.xml, virt-install with virtiofs+guest-agent, provision.ps1
6. **`ssh`** — fallback interactive session
7. **Polish** — error handling, colors, `--help`

## Verification

```bash
chmod +x winbox/winbox
./winbox setup                                    # builds VM (~15 min)
./winbox status                                   # shows "running"
./winbox exec cmd.exe /c "echo hello"             # prints "hello"
./winbox exec SharpHound.exe --help               # prints SharpHound help
ls ~/.winbox/shared/tools/                        # SharpHound.exe visible
./winbox suspend && ./winbox up                   # instant resume
./winbox destroy                                  # clean removal
```
