# winbox

**An isolated Windows vulnerability-research platform for Kali and AI agents.**

winbox turns a headless Windows VM (Server Core 2022/2025, Windows 11, or
Windows 10) into
an automation, instrumentation, and analysis environment controlled from
Kali. Execute tools, drive a PDB-aware hypervisor debugger, inspect protected
memory, exercise drivers and IPC, change security posture, contain malware,
and collect evidence through one CLI and a 97-tool MCP surface.

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

- **MCP server** — 97 tools form a bounded, AI-native research control plane
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
  Windows 11, or Windows 10 guests with automatic provisioning, VirtIO-FS staging,
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
    libguestfs-tools virtiofsd p7zip-full genisoimage sshpass wget \
    libwin-hivex-perl
```

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

Pass `--os` for a different guest: `server2025`, `win11`, or `win10`.
See [Guest OS Targets](docs/guest-os.md) for per-OS notes and display options.

## Documentation

| Guide | Description |
|-------|-------------|
| [Usage](docs/usage.md) | CLI commands, shells, tools, network, snapshots, event logs |
| [MCP Tools](docs/mcp-tools.md) | 97-tool AI agent surface — full reference |
| [Guest OS Targets](docs/guest-os.md) | Server 2022/2025, Win11, Win10 notes; display stack |
| [Malware Detonation](docs/malware-detonation.md) | Containment, preflight, capture, sinkhole |
| [Architecture](docs/architecture.md) | Platform layers, control planes |
| [Configuration](docs/configuration.md) | Config keys, filesystem layout |
| [KDBG Decompilation](docs/kdbg-decomp.md) | PyGhidra setup, live decompilation |
| [Testing](docs/testing.md) | Unit tests, live E2E suite, coverage manifest |

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

## License

MIT
