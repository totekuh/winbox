# Set DNS server addresses on the first up-state network adapter.
# Renders with one placeholder: {servers} -> a PS array literal, e.g.
# "'10.0.0.1'" or "@('10.0.0.1', '10.0.0.2')".
$a = Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' }} | Select-Object -First 1
Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses {servers}
Clear-DnsClientCache
