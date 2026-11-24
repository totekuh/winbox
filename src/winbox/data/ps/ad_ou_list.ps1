# List organizational units.
Get-ADOrganizationalUnit -Server localhost -Filter * -Properties Description |
    Select-Object Name, DistinguishedName, Description |
    Format-Table -AutoSize
