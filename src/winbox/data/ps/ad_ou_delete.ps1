# Delete an organizational unit.
# Params: {dn}
Set-ADOrganizationalUnit -Identity '{dn}' -Server localhost -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
Remove-ADOrganizationalUnit -Identity '{dn}' -Server localhost -Confirm:$false -Recursive -ErrorAction Stop
