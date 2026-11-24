# Report AD DS status as JSON.
$out = @{{ is_dc = $false }}

$feat = Get-WindowsFeature AD-Domain-Services -ErrorAction SilentlyContinue
$out.feature_installed = ($null -ne $feat -and $feat.Installed)

if ($out.feature_installed) {{
    try {{
        Import-Module ActiveDirectory -ErrorAction Stop
        # Try default discovery first, fall back to localhost (fresh DC
        # may not have SRV records propagated yet).
        try {{
            $dc = Get-ADDomainController -ErrorAction Stop
        }} catch {{
            $dc = Get-ADDomainController -Server localhost -ErrorAction Stop
        }}
        $dom = Get-ADDomain -Server localhost -ErrorAction Stop
        $forest = Get-ADForest -Server localhost -ErrorAction Stop
        $out.is_dc = $true
        $out.hostname = $dc.HostName
        $out.domain = $dom.DNSRoot
        $out.netbios = $dom.NetBIOSName
        $out.forest = $forest.Name
        $out.forest_level = $forest.ForestMode.ToString()
        $out.domain_level = $dom.DomainMode.ToString()
        $out.site = $dc.Site

        $dfs = Get-WindowsFeature FS-DFS-Namespace -ErrorAction SilentlyContinue
        $out.dfs_installed = ($null -ne $dfs -and $dfs.Installed)
    }} catch {{
        $out.ad_error = $_.Exception.Message
    }}
}}

$svc = @{{}}
foreach ($s in @('NTDS', 'DNS', 'Kdc')) {{
    $obj = Get-Service $s -ErrorAction SilentlyContinue
    $svc[$s] = if ($obj) {{ $obj.Status.ToString() }} else {{ 'NotInstalled' }}
}}
$out.services = $svc

$out | ConvertTo-Json -Depth 3 -Compress
