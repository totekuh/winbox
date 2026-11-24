# Delete a domain user account.
# Params: {sam}
Remove-ADUser -Identity '{sam}' -Server localhost -Confirm:$false -ErrorAction Stop
