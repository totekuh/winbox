# List AD groups (non-builtin).
Get-ADGroup -Server localhost -Filter * -Properties GroupScope, Description |
    Where-Object {{ $_.DistinguishedName -notmatch 'CN=Builtin,' }} |
    Select-Object Name, GroupScope, Description, DistinguishedName |
    Format-Table -AutoSize
