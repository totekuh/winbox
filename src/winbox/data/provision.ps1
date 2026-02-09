# winbox post-install provisioning script
# Runs inside Windows VM via:
#   - bootstrap.ps1 (firstboot) — files in C:\Provision\
#   - winbox provision (re-run) — files in Z:\tools\

$ErrorActionPreference = "Stop"

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
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
        -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
        -Name DisableRealtimeMonitoring -Value 1 -PropertyType DWORD -Force | Out-Null
    Write-Host "[+] Defender disabled"
} catch {
    Write-Host "[!] Could not fully disable Defender: $_"
}

# --- Disable Firewall ---
Write-Host "[*] Disabling firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Write-Host "[+] Firewall disabled"

# --- OpenSSH Server (fallback access) ---
Write-Host "[*] Installing OpenSSH Server..."
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
Write-Host "[+] OpenSSH Server running"

# --- SSH key auth ---
Write-Host "[*] Configuring SSH key auth..."
$pubkeyPath = "$provDir\.ssh_pubkey"
if (Test-Path $pubkeyPath) {
    $pubkey = Get-Content $pubkeyPath -Raw
    $authKeys = "C:\ProgramData\ssh\administrators_authorized_keys"
    Set-Content -Path $authKeys -Value $pubkey.Trim()
    icacls $authKeys /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F" | Out-Null
    Write-Host "[+] SSH key configured"
} else {
    Write-Host "[!] No SSH pubkey found at $pubkeyPath - skipping key auth"
}

# --- Map SMB share (host on virbr0) ---
Write-Host "[*] Mapping SMB share..."
net use Z: \\192.168.122.1\winbox /persistent:yes 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[*] Z: already mapped or mapping failed, continuing..."
}
Write-Host "[+] Z: drive mapped"

# --- Download tools ---
Write-Host "[*] Downloading tools..."
$toolsFile = "$provDir\tools.txt"
if (Test-Path $toolsFile) {
    $urls = Get-Content $toolsFile | Where-Object { $_ -match "^https?://" }
    foreach ($url in $urls) {
        $filename = [System.IO.Path]::GetFileName(([URI]$url).AbsolutePath)
        Write-Host "    Downloading $filename..."
        $tmp = "$env:TEMP\$filename"
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
            if ($filename -match '\.zip$') {
                Expand-Archive -Path $tmp -DestinationPath "Z:\tools\" -Force
                Remove-Item $tmp -Force
                Write-Host "    [+] Extracted $filename"
            } else {
                Move-Item $tmp "Z:\tools\$filename" -Force
                Write-Host "    [+] Saved $filename"
            }
        } catch {
            Write-Host "    [!] Failed to download $filename : $_"
        }
    }
} else {
    Write-Host "[!] No tools.txt found - skipping tool downloads"
}

# --- Create loot directory ---
if (-not (Test-Path "Z:\loot")) {
    New-Item -Path "Z:\loot" -ItemType Directory -Force | Out-Null
}

Write-Host "[+] winbox provisioning complete"
