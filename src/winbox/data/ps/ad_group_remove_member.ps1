# Remove a member from an AD group.
# Params: {group}, {member}
Remove-ADGroupMember -Identity '{group}' -Members '{member}' -Server localhost -Confirm:$false -ErrorAction Stop
