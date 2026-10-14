# Guest OS Targets

`winbox setup` builds **Windows Server 2022** by default. Pass `--os` to build a
different target — **Windows Server 2025**, **Windows 11 Enterprise (Evaluation)**,
or **Windows 10 (consumer 22H2)**:

```bash
winbox setup --os server2025 -y             # Windows Server 2025 (Core, Evaluation)
winbox setup --os win11 -y                  # Windows 11 Enterprise (Evaluation)
winbox setup --os win10 --iso <path> -y     # Windows 10 22H2 — ISO is manual, see note
```

The choice is build-time and there is one VM at a time — switching OS means
`winbox destroy -y` then `winbox setup --os <other> -y`. Setup records the choice as
`VM_OS=` in `~/.winbox/config`, so every later command (`status`, `av`, `exec`, the
MCP server) resolves the same profile as the VM on disk; you can also set that key
yourself to change the default for a bare `winbox setup`. The right ISO is downloaded
automatically for the selected OS (or pass `--iso <path>` to use your own).

## Server 2025

- Same server-minimal build as 2022 (Server Core, no TPM/Secure-Boot gate, 100 MB
  ESP layout), but on the Windows 11 24H2 kernel (build 26100). `--desktop` selects
  Desktop Experience, same as 2022.
- Because it shares the 24H2 kernel, HVCI/VBS and Defender behavior can differ from
  2022 — `winbox av status` reports the real Tamper-Protection state. For `kdbg`,
  use explicit hardware breakpoints when HVCI is on; it blocks software 0xCC bps.

## Win11

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

## Win10 (client SKU)

- **No TPM / Secure Boot gate** — unlike Win11, Windows 10 needs no `LabConfig`
  bypass, so none is injected. `--desktop` is Server-only and rejected for Win10.
- Same client provisioning as Win11 (Python embeddable payload, standard UEFI
  layout: larger ESP + MSR, Windows on partition 3, 32 GB system drive).
- Media is the **consumer 22H2 multi-edition ISO**; the build selects the
  `Windows 10 Pro` image. It installs unactivated (fine for a throwaway research
  VM) and is still ProductType 1, so the client provisioning path applies.
- **Defender:** Win10 ships Tamper Protection on; setup disables the Defender
  services in the offline registry hive before first boot, same as Win11.
  `winbox av status` / `winbox av disable` behave identically.
- **Auto-download is not available.** Windows 10 reached end of life
  (2025-10-14). The Enterprise eval media was pulled (its evalcenter page
  redirects to a "move to Win11" blog), and the consumer ISO is served only as a
  per-session *signed, time-limited* link (not a durable `go.microsoft.com/fwlink`
  like the other profiles). So `--os win10`'s auto-download deliberately fails
  loudly — get the Win10 22H2 ISO from
  `https://www.microsoft.com/en-us/software-download/windows10ISO` (served to
  non-Windows browsers) and pass `--iso <path>`.

## Display Stack

`winbox setup` builds with plain **VNC** and the default video model, which is
fine for headless/research use (connect with `winbox vnc`). The guest is then
locked to a single low resolution — the libvirt-default `bochs` display has no
Windows mode-setting driver.

For a VM you actually sit in front of (a workstation / report-writing box), pass
`--display spice`:

```bash
winbox setup --os win10 --display spice -y   # SPICE + QXL + spice-guest-tools
```

This builds the VM with SPICE graphics + the QXL video model and installs
**spice-guest-tools** (QXL WDDM display driver + spice-vdagent) during
provisioning. You get a resizable resolution picker, window-size auto-resize,
and host↔guest clipboard in `virt-manager` / `remote-viewer`. The choice is
build-time (the video hardware is fixed at VM creation) and is recorded as
`VM_DISPLAY=` in `~/.winbox/config`; the default is `vnc`.

spice-guest-tools is installed **best-effort** — it is not load-bearing for any
winbox function, so a failed install logs and continues rather than aborting
setup.

> **⚠ Isolation caveat — do not use `--display spice` for detonation.** The
> spice vdagent runs over a `spicevmc` *serial* channel (host↔guest), **not** the
> network. winbox's `winbox-isolate` nwfilter is network-level, so it does **not**
> block that channel — clipboard (and potentially files) can cross it even while
> the VM is network-isolated. `--display spice` is for workstation VMs only. For
> malware analysis / detonation, keep the default `vnc`.
