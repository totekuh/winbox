# List non-special SMB shares with name, path, and description.
# No placeholders.
Get-SmbShare | Where-Object {{ $_.Special -eq $false }} |
  Select-Object Name, Path, Description |
  Format-Table -AutoSize | Out-String -Width 200
