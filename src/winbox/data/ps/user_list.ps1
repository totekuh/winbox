# List local Windows users.
# No placeholders.
Get-LocalUser | Select-Object Name, Enabled, LastLogon, Description |
  Format-Table -AutoSize | Out-String -Width 200
