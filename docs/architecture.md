# Architecture

```
Kali Linux
├── winbox control plane
│   ├── CLI (Python/Click)
│   └── MCP server (97 bounded agent tools)
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
