# List domain computer accounts.
Get-ADComputer -Server localhost -Filter * -Properties OperatingSystem, Enabled, DNSHostName |
    Select-Object Name, DNSHostName, OperatingSystem, Enabled, DistinguishedName |
    Format-Table -AutoSize
