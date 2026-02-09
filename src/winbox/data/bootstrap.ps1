# winbox bootstrap — firstboot wrapper (injected by virt-customize)
# Unpacks provision.zip, runs provision.ps1, cleans up, shuts down.

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force C:\Provision | Out-Null
Expand-Archive -Force C:\provision.zip C:\Provision
& C:\Provision\provision.ps1

# Schedule self-deletion on next boot
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v DeleteBootstrap /t REG_SZ /d "cmd.exe /c del /f /q C:\bootstrap.ps1" /f

# Clean up
Remove-Item C:\provision.zip -Force -ErrorAction SilentlyContinue
Remove-Item C:\Provision -Recurse -Force -ErrorAction SilentlyContinue

Stop-Computer -Force
