# Promote to domain controller.
# Params: {domain}, {netbios}, {pass_b64}
$b = [Convert]::FromBase64String('{pass_b64}')
$p = [Text.Encoding]::UTF8.GetString($b)
$sp = ConvertTo-SecureString $p -AsPlainText -Force

$feat = Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -ErrorAction Stop
if (-not $feat.Success) {{
    Write-Error "Failed to install AD-Domain-Services: $($feat.ExitCode)"
    exit 1
}}

Import-Module ADDSDeployment -ErrorAction Stop
Install-ADDSForest `
    -DomainName '{domain}' `
    -DomainNetbiosName '{netbios}' `
    -SafeModeAdministratorPassword $sp `
    -InstallDns `
    -Force `
    -NoRebootOnCompletion
