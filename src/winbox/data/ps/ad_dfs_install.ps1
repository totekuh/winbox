# Install DFS Namespace + Replication features (idempotent).
$features = @('FS-DFS-Namespace', 'FS-DFS-Replication')
foreach ($f in $features) {{
    $feat = Get-WindowsFeature $f
    if (-not $feat.Installed) {{
        $r = Install-WindowsFeature $f -ErrorAction Stop
        if (-not $r.Success) {{
            Write-Error "Install $f failed: $($r.ExitCode)"
            exit 1
        }}
        Write-Output "$f installed"
    }}
}}
Write-Output 'DFS features ready'
