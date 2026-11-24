# Create an AD security group.
# Params: {group_name}, {scope}, {ou}
$params = @{{
    Name           = '{group_name}'
    GroupScope     = '{scope}'
    GroupCategory  = 'Security'
}}

$ou = '{ou}'
if ($ou) {{
    $params.Path = $ou
}}

New-ADGroup @params -Server localhost -ErrorAction Stop
