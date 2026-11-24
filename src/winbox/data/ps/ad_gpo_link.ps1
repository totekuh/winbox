# Link a GPO to an OU.
# Params: {gpo_name}, {target}
New-GPLink -Name '{gpo_name}' -Target '{target}' -ErrorAction Stop
