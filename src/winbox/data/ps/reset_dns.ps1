# Reset DNS to DHCP-supplied servers on the first up-state adapter.
$a = Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' }} | Select-Object -First 1
Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses
