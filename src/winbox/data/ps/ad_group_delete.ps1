# Delete an AD group.
# Params: {group_name}
Remove-ADGroup -Identity '{group_name}' -Server localhost -Confirm:$false -ErrorAction Stop
