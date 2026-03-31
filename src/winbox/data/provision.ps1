# winbox post-install provisioning script
# Runs inside Windows VM via:
#   - bootstrap.ps1 (firstboot) - files in C:\Provision\
#   - winbox provision (re-run) - files in Z:\tools\

$ErrorActionPreference = "Continue"

Write-Host "[*] winbox provisioning started"

# Determine where our files are (firstboot vs re-provision)
if (Test-Path "C:\Provision\provision.ps1") {
    $provDir = "C:\Provision"
} else {
    $provDir = "Z:\tools"
}

# --- Disable Defender (tools get flagged) ---
Write-Host "[*] Disabling Windows Defender..."
try {
    Set-MpPreference -DisableRealtimeMonitoring $true
    Set-MpPreference -DisableIOAVProtection $true
    Set-MpPreference -DisableBehaviorMonitoring $true
    Set-MpPreference -DisableBlockAtFirstSeen $true
    Set-MpPreference -DisableScriptScanning $true
    # Disable via registry for persistence across reboots
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
        -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
        -Name DisableRealtimeMonitoring -Value 1 -PropertyType DWORD -Force | Out-Null
    Write-Host "[+] Defender disabled"
} catch {
    Write-Host "[!] Could not fully disable Defender: $_"
}

# --- Disable Firewall ---
Write-Host "[*] Disabling firewall..."
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    Write-Host "[+] Firewall disabled"
} catch {
    Write-Host "[!] Could not disable firewall: $_"
}

# --- Disable DNS reverse lookups (kills performance over NAT/VPN) ---
Write-Host "[*] Disabling DNS reverse lookups..."
try {
    # Disable netbios over TCP/IP on all adapters (stops NBNS broadcast spam)
    Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true" | ForEach-Object {
        $_.SetTcpipNetbios(2) | Out-Null  # 2 = disable
    }
    # Disable DNS registration and reverse lookup via registry
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        -Name DisableReverseAddressRegistrations -Value 1 -PropertyType DWORD -Force | Out-Null
    # Disable LLMNR (Link-Local Multicast Name Resolution)
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        -Name EnableMulticast -Value 0 -PropertyType DWORD -Force | Out-Null
    Write-Host "[+] Reverse lookups and LLMNR disabled"
} catch {
    Write-Host "[!] Could not disable reverse lookups: $_"
}

# --- OpenSSH Server (from bundled zip, no Windows Update dependency) ---
Write-Host "[*] Installing OpenSSH Server..."
$opensshZip = "$provDir\OpenSSH-Win64.zip"
try {
    if (Test-Path $opensshZip) {
        $installDir = "$env:ProgramFiles\OpenSSH"
        Expand-Archive -Path $opensshZip -DestinationPath $env:ProgramFiles -Force
        # The zip extracts to OpenSSH-Win64/, rename to OpenSSH
        if (Test-Path "$env:ProgramFiles\OpenSSH-Win64") {
            if (Test-Path $installDir) { Remove-Item $installDir -Recurse -Force }
            Rename-Item "$env:ProgramFiles\OpenSSH-Win64" $installDir
        }
        & "$installDir\install-sshd.ps1" | Out-Null
        if ($env:Path -notlike "*$installDir*") {
            $machPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
            if ($machPath -notlike "*$installDir*") {
                [Environment]::SetEnvironmentVariable("Path", "$machPath;$installDir", [EnvironmentVariableTarget]::Machine)
            }
            $env:Path += ";$installDir"
        }
    } else {
        # Fallback: install from Windows Update (re-provision without bundled zip)
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
    }
    Start-Service sshd
    Set-Service -Name sshd -StartupType Automatic
    Write-Host "[+] OpenSSH Server running"
} catch {
    Write-Host "[!] Could not install/start OpenSSH: $_"
}

# --- SSH key auth ---
Write-Host "[*] Configuring SSH key auth..."
$pubkeyPath = "$provDir\.ssh_pubkey"
if (Test-Path $pubkeyPath) {
    try {
        $pubkey = Get-Content $pubkeyPath -Raw
        $authKeys = "C:\ProgramData\ssh\administrators_authorized_keys"
        Set-Content -Path $authKeys -Value $pubkey.Trim()
        icacls $authKeys /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F" | Out-Null
        Write-Host "[+] SSH key configured"
    } catch {
        Write-Host "[!] Could not configure SSH key: $_"
    }
} else {
    Write-Host "[!] No SSH pubkey found at $pubkeyPath - skipping key auth"
}

# --- VirtIO-FS (host filesystem via shared memory, replaces SMB) ---
Write-Host "[*] Setting up VirtIO-FS..."
$winfspMsi = "$provDir\winfsp.msi"
try {
    # Install WinFsp (user-mode filesystem framework required by VirtIO-FS)
    Write-Host "[*] Installing WinFsp..."
    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$winfspMsi`" /qn /norestart INSTALLLEVEL=1000" -Wait -PassThru -NoNewWindow
    Write-Host "[+] WinFsp installed (exit code: $($proc.ExitCode))"

    # Find virtiofs.exe - bundled in provision payload or already installed
    $viofsExe = $null
    if (Test-Path "$provDir\virtiofs.exe") {
        $viofsExe = "$provDir\virtiofs.exe"
    } elseif (Test-Path "C:\virtiofs\virtiofs.exe") {
        $viofsExe = "C:\virtiofs\virtiofs.exe"
    }

    if ($viofsExe) {
        # Copy virtiofs.exe to a permanent location
        $viofsDir = "C:\virtiofs"
        New-Item -ItemType Directory -Path $viofsDir -Force | Out-Null
        if ($viofsExe -ne "$viofsDir\virtiofs.exe") {
            Copy-Item $viofsExe "$viofsDir\virtiofs.exe" -Force
        }

        # Register the VirtioFsSvc service - mounts VirtIO-FS as a drive letter
        $svcName = "VirtioFsSvc"
        $existing = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($existing) {
            Stop-Service $svcName -Force -ErrorAction SilentlyContinue
            sc.exe delete $svcName | Out-Null
            Start-Sleep -Seconds 2
        }
        sc.exe create $svcName binPath= "`"$viofsDir\virtiofs.exe`" -m Z: -t winbox_share" start= auto depend= "WinFsp.Launcher/VirtioFsDrv" | Out-Null
        Write-Host "[+] VirtioFsSvc registered (Z: = winbox_share)"

        # Start the service (will mount Z: if the VirtIO-FS device is present)
        Start-Service $svcName -ErrorAction SilentlyContinue
        if ((Get-Service $svcName).Status -eq "Running") {
            Write-Host "[+] VirtioFsSvc running - Z: mounted"
        } else {
            Write-Host "[!] VirtioFsSvc did not start (normal during firstboot provisioning)"
        }
    } else {
        Write-Host "[!] virtiofs.exe not found - VirtIO-FS will not be available"
    }
} catch {
    Write-Host "[!] VirtIO-FS setup error: $_"
}

# --- Add Z:\tools to system PATH ---
Write-Host "[*] Adding Z:\tools to system PATH..."
try {
    $machPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
    if ($machPath -notlike '*Z:\tools*') {
        [Environment]::SetEnvironmentVariable("Path", "$machPath;Z:\tools", [EnvironmentVariableTarget]::Machine)
        Write-Host "[+] Z:\tools added to system PATH"
    } else {
        Write-Host "[+] Z:\tools already in system PATH"
    }
} catch {
    Write-Host "[!] Could not add Z:\tools to PATH: $_"
}

Write-Host "[+] winbox provisioning complete"
