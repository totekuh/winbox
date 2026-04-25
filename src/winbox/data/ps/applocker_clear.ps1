# Clear AppLocker policy + stop the AppIDSvc stack.
# Renders with one placeholder: {path} -> guest path to the empty-policy XML.
$xmlPath = '{path}'
if (-not (Test-Path $xmlPath)) {{
    Write-Error "Policy file not found: $xmlPath"
    exit 1
}}
# Clear policy while service is running (service must be up to process the change)
Set-AppLockerPolicy -XmlPolicy $xmlPath
Remove-Item $xmlPath -ErrorAction SilentlyContinue

# Restart service so it processes the empty policy and notifies appid.sys
Restart-Service -Name AppIDSvc -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Delete compiled rule cache
Remove-Item 'C:\Windows\System32\AppLocker\*.AppLocker' -Force -ErrorAction SilentlyContinue

# Stop the service
appidtel.exe stop
Stop-Service -Name AppIDSvc -Force -ErrorAction SilentlyContinue
Stop-Service -Name AppIDSvc -Force -ErrorAction SilentlyContinue
Set-Service -Name AppIDSvc -StartupType Manual -ErrorAction SilentlyContinue
