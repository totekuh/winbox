# List DFS namespaces and their folder targets.
$domain = (Get-ADDomain -Server localhost -ErrorAction Stop).DNSRoot
$roots = Get-DfsnRoot -ErrorAction SilentlyContinue | Where-Object {{ $_.Path -match $domain }}
if (-not $roots) {{
    exit 0
}}
foreach ($root in $roots) {{
    Write-Output "Namespace: $($root.Path)  State: $($root.State)"
    $folders = Get-DfsnFolder -Path "$($root.Path)\*" -ErrorAction SilentlyContinue
    foreach ($f in $folders) {{
        $targets = Get-DfsnFolderTarget -Path $f.Path -ErrorAction SilentlyContinue
        foreach ($t in $targets) {{
            Write-Output "  Folder: $($f.Path)  Target: $($t.TargetPath)  State: $($t.State)"
        }}
    }}
}}
