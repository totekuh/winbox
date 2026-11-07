# Revoke an account's access to an SMB share.
# Placeholders: {share_name} -> share name (ps_quote'd)
#               {account}    -> account name (ps_quote'd)
Revoke-SmbShareAccess -Name '{share_name}' -AccountName '{account}' -Force -ErrorAction Stop
