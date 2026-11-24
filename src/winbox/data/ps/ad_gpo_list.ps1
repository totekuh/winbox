# List all Group Policy objects.
Get-GPO -All -ErrorAction Stop |
    Select-Object DisplayName, Id, GpoStatus, CreationTime |
    Format-Table -AutoSize
