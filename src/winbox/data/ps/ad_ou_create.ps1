# Create an organizational unit.
# Params: {ou_name}, {path}
$params = @{{
    Name                    = '{ou_name}'
    ProtectedFromAccidentalDeletion = $false
}}

$path = '{path}'
if ($path) {{
    $params.Path = $path
}}

New-ADOrganizationalUnit @params -Server localhost -ErrorAction Stop
