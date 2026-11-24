# Set a registry-based GPO setting.
# Params: {gpo_name}, {key}, {value_name}, {reg_type}, {value}
$v = '{value}'
if ('{reg_type}' -in @('DWord','QWord')) {{ $v = [long]$v }}
Set-GPRegistryValue `
    -Name '{gpo_name}' `
    -Key '{key}' `
    -ValueName '{value_name}' `
    -Type {reg_type} `
    -Value $v `
    -ErrorAction Stop
