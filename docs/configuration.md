# Configuration

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
│   ├── Win10_22H2_x64.iso              # Windows 10 22H2 consumer ISO (--os win10, pass --iso)
│   ├── virtio-win.iso                  # VirtIO drivers
│   ├── OpenSSH-Win64.zip               # bundled OpenSSH
│   ├── winfsp.msi                      # WinFsp installer
│   ├── virtiofs.exe                    # VirtIO-FS service binary
│   ├── python-3.13.13-amd64.exe        # Python 3.13 installer for the guest
│   ├── x64dbg.zip                      # x64dbg snapshot (extracted to C:\Tools\x64dbg)
│   ├── spice-guest-tools.exe           # QXL driver + vdagent (--display spice only)
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
