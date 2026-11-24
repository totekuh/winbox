# Demote domain controller to standalone server with full cleanup.
# Params: {pass_b64}, {admin_b64}
$b = [Convert]::FromBase64String('{pass_b64}')
$p = [Text.Encoding]::UTF8.GetString($b)
$sp = ConvertTo-SecureString $p -AsPlainText -Force

$ab = [Convert]::FromBase64String('{admin_b64}')
$ap = [Text.Encoding]::UTF8.GetString($ab)
$asp = ConvertTo-SecureString $ap -AsPlainText -Force

$domain = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name Domain -EA SilentlyContinue).Domain
if (-not $domain) {{ $domain = 'WORKGROUP' }}
$cred = New-Object System.Management.Automation.PSCredential("$domain\Administrator", $asp)

Import-Module ADDSDeployment -ErrorAction Stop
Uninstall-ADDSDomainController `
    -LastDomainControllerInDomain `
    -RemoveApplicationPartitions `
    -LocalAdministratorPassword $sp `
    -Credential $cred `
    -Force `
    -NoRebootOnCompletion

# Clean stale artifacts so re-promote works
Stop-Service NTDS -Force -ErrorAction SilentlyContinue
Stop-Service DNS -Force -ErrorAction SilentlyContinue
Remove-Item 'C:\Windows\NTDS\*' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item 'C:\Windows\System32\dns\*.dns' -Force -ErrorAction SilentlyContinue
Remove-Item 'C:\Windows\System32\dns\*.log' -Force -ErrorAction SilentlyContinue

Uninstall-WindowsFeature AD-Domain-Services -IncludeManagementTools -ErrorAction SilentlyContinue
Uninstall-WindowsFeature DNS -ErrorAction SilentlyContinue
