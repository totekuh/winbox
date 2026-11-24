# Add a member to an AD group.
# Params: {group}, {member}
Add-ADGroupMember -Identity '{group}' -Members '{member}' -Server localhost -ErrorAction Stop
