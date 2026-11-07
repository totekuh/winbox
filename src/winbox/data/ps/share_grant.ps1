# Grant access to an SMB share.
# Placeholders: {share_name} -> share name (ps_quote'd)
#               {account}    -> account name (ps_quote'd)
#               {permission} -> Full, Change, or Read
Grant-SmbShareAccess -Name '{share_name}' -AccountName '{account}' -AccessRight {permission} -Force -ErrorAction Stop
