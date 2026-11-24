# Create a domain user account.
# Params: {sam}, {pass_b64}, {upn}, {ou}
$b = [Convert]::FromBase64String('{pass_b64}')
$p = [Text.Encoding]::UTF8.GetString($b)
$sp = ConvertTo-SecureString $p -AsPlainText -Force

$params = @{{
    SamAccountName    = '{sam}'
    Name              = '{sam}'
    AccountPassword   = $sp
    Enabled           = $true
    PasswordNeverExpires = $true
}}

$upn = '{upn}'
if ($upn) {{
    $params.UserPrincipalName = $upn
}} else {{
    $domain = (Get-ADDomain -Server localhost).DNSRoot
    $params.UserPrincipalName = "{sam}@$domain"
}}

$ou = '{ou}'
if ($ou) {{
    $params.Path = $ou
}}

New-ADUser @params -Server localhost -ErrorAction Stop
