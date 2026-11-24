# List domain users.
# Params: {search_base}
Get-ADUser -Server localhost -Filter *{search_base} -Properties SamAccountName, Enabled, UserPrincipalName, DistinguishedName |
    Select-Object SamAccountName, Enabled, UserPrincipalName, DistinguishedName |
    Format-Table -AutoSize
