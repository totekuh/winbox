# Create an SMB share with access controls.
# Placeholders: {share_name}     -> share name (ps_quote'd)
#               {path}           -> backing folder path (ps_quote'd)
#               {access_params}  -> pre-built access flags, e.g.
#                   -FullAccess 'Everyone' -ReadAccess 'bob','alice'
$p = '{path}'
if (-not (Test-Path $p)) {{ New-Item -ItemType Directory -Path $p -Force | Out-Null }}
New-SmbShare -Name '{share_name}' -Path $p {access_params} -ErrorAction Stop
Write-Host "NAME={share_name}"
Write-Host "PATH=$p"
