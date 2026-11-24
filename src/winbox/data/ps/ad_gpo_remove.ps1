# Delete a Group Policy object.
# Params: {gpo_name}
Remove-GPO -Name '{gpo_name}' -Confirm:$false -ErrorAction Stop
