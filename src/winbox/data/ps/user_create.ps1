# Create a local Windows user.
# Placeholders: {username}  -> account name (ps_quote'd)
#               {pass_b64}  -> base64-encoded UTF-8 password
#               {full_name} -> display name (ps_quote'd, may be empty)
#               {no_expire} -> $true or $false
$b = [Convert]::FromBase64String('{pass_b64}')
$p = [Text.Encoding]::UTF8.GetString($b)
$sp = ConvertTo-SecureString $p -AsPlainText -Force
$params = @{{
    Name                 = '{username}'
    Password             = $sp
    FullName             = '{full_name}'
    PasswordNeverExpires = {no_expire}
}}
New-LocalUser @params -ErrorAction Stop
