# winbox bootstrap - firstboot wrapper (injected by virt-customize)
# Unpacks provision.zip, runs provision.ps1, cleans up, shuts down.
# MUST always reach Stop-Computer regardless of errors.

$logFile = "C:\winbox-bootstrap.log"
Start-Transcript -Path $logFile -Force

try {
    New-Item -ItemType Directory -Force C:\Provision | Out-Null
    Expand-Archive -Force C:\provision.zip C:\Provision
    & C:\Provision\provision.ps1
} catch {
    Write-Host "[!] Bootstrap error: $_"
} finally {
    # Schedule self-deletion on next boot
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v DeleteBootstrap /t REG_SZ /d "cmd.exe /c del /f /q C:\bootstrap.ps1" /f 2>$null

    # Clean up
    Remove-Item C:\provision.zip -Force -ErrorAction SilentlyContinue
    Remove-Item C:\Provision -Recurse -Force -ErrorAction SilentlyContinue

    Stop-Transcript -ErrorAction SilentlyContinue

    # ALWAYS shut down
    Stop-Computer -Force
}
