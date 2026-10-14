# Usage

## Executing Commands

```bash
winbox exec whoami
winbox exec ipconfig /all
winbox exec Rubeus.exe kerberoast /domain:corp.local
winbox exec --timeout 300 SharpHound.exe -c All     # --timeout must come BEFORE the command
winbox exec --user alice --password secret whoami   # run as a local Windows user
```

The VM starts automatically if it's not running.

## Background Jobs

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

## Interactive Shells

```bash
winbox shell                 # ConPTY reverse shell — runs as SYSTEM, supports terminal resize
winbox shell --user alice --password secret   # shell as a local Windows user (via RunEx)
winbox ssh                   # SSH into PowerShell (auto-auth via sshpass)
```

## Managing Tools

Tools placed in the shared directory are available at `Z:\tools\` in the VM and automatically on PATH:

```bash
winbox tools add Rubeus.exe SharpHound.exe Certify.exe
winbox tools list
winbox tools remove Rubeus.exe
```

## One-shot Uploads and MSI Installs

For files that shouldn't live permanently in the tools dir:

```bash
winbox upload payload.exe                         # stage at Z:\payload.exe
winbox upload payload.exe C:\Windows\Temp\p.exe   # also copy into the VM path

winbox msi VMware-tools.msi ADDLOCAL=ALL /norestart   # extra args pass through to msiexec
```

Both stage through the VirtIO-FS share and clean up on failure. `winbox msi` treats exit code 3010 (reboot required) as success.

## Event Logs

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

## Network

```bash
# Isolation
winbox net isolate           # block internet via nwfilter (host-VM channels stay up)
winbox net unplug            # full air-gap: NIC link down, live + next boot
winbox net connect           # reconnect VM to network (clears both scopes)
winbox net status            # link (live and next boot), filter, internet

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

## VM Lifecycle

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

## Snapshots

```bash
winbox snapshot              # list existing snapshots
winbox snapshot pre-attack   # create named snapshot (auto-shuts VM down first)
# ... do your thing ...
winbox restore pre-attack    # revert to clean state
```

## Office Installation

For testing macro-based payloads, install Office on a Desktop Experience VM:

```bash
winbox setup --desktop -y    # build VM with Desktop Experience
winbox autologin enable      # enable auto-login as Administrator (persistent across reboots)
winbox office                # install Word, Excel, PowerPoint with macros enabled
```

Requires a Microsoft 365 subscription. Macros are enabled (VBAWarnings=1) for Word, Excel, and PowerPoint.

## Persistent Autologin

```bash
winbox autologin enable      # writes all 6 Winlogon+PasswordLess keys Server 2022 needs
winbox autologin status
winbox autologin disable
```

Unlike the old 3-key approach, this actually survives reboots on Server 2022 (which otherwise silently wipes `DefaultPassword` on first boot without `ForceAutoLogon=1` and the `PasswordLess\Device\DevicePasswordLessBuildVersion=0` gate).

## AppLocker

Test application whitelisting bypass techniques:

```bash
winbox applocker enable      # enable AppLocker with default rules (Exe, Script, MSI, Appx)
winbox applocker status      # show enforcement status
winbox applocker disable     # disable AppLocker, clear policy, reboot
```

## Antivirus (Windows Defender)

```bash
winbox av disable            # disable Defender completely (reboot required — WinDefend is PPL)
winbox av status             # show Defender/AMSI protection status
winbox av enable             # re-enable Defender + AMSI (adds QEMU GA/VirtIO-FS exclusions)
```

## Transparent .exe Execution (binfmt_misc)

Register a binfmt_misc handler so `.exe` files run through winbox automatically:

```bash
sudo winbox binfmt enable
./SharpHound.exe -c All      # runs via winbox exec
sudo winbox binfmt disable
winbox binfmt status
```

## Breakpoint Action Traces

Use a staged relative target when symbols are absent, then attach one or more
actions to collect a bounded trace without stopping on every hit:

```console
winbox kdbg bp mpengine+0xb52c40 --action rip --action rcx --action 'ascii(rcx,96)'
winbox kdbg bp-trace 0 --summary
```

Scalar actions use the predicate expression grammar (`rax`, `rcx == 4`,
`qword(rdx+0x10)`, `poi(rcx)`); capture actions are `bytes(addr,n)`,
`ascii(addr,n)`, or `utf16(addr,n)`. There are at most 16 actions, captures
are bounded to 256 bytes each/1024 bytes per hit/16 MiB per trace, and every
action hit is appended as JSONL then auto-continues. Use `kdbg_bps` to see the
canonical target and counters, and `kdbg_bp_trace` to page/filter the evidence.

**Requires** Python installed in the VM — this is now done automatically as part of `winbox setup`.
