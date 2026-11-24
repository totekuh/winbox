# Create a Group Policy object.
# Params: {gpo_name}
New-GPO -Name '{gpo_name}' -ErrorAction Stop | Select-Object DisplayName, Id | Format-List
