# Create a domain-based DFS namespace (DomainV2).
# Auto-creates a root share on the DC. The caller's target becomes the
# first folder target under the namespace root.
# Params: {namespace}, {target}
$domain = (Get-ADDomain -Server localhost).DNSRoot
$fqdn = "$env:COMPUTERNAME.$domain"
$rootSharePath = "C:\DFSRoots\{namespace}"

# DFS root needs its own dedicated share
$existingShare = Get-SmbShare -Name '{namespace}' -ErrorAction SilentlyContinue
if (-not $existingShare) {{
    New-Item -ItemType Directory -Path $rootSharePath -Force | Out-Null
    New-SmbShare -Name '{namespace}' -Path $rootSharePath -FullAccess Everyone -ErrorAction Stop | Out-Null
}}

New-DfsnRoot `
    -TargetPath "\\$fqdn\{namespace}" `
    -Path "\\$domain\{namespace}" `
    -Type DomainV2 `
    -ErrorAction Stop

# Add the caller's target as the first folder link
$targetName = ('{target}' -split '\\')[-1]
New-DfsnFolder `
    -Path "\\$domain\{namespace}\$targetName" `
    -TargetPath '{target}' `
    -ErrorAction Stop

Write-Output "DFS V2 namespace \\$domain\{namespace} created with folder $targetName -> {target}"
