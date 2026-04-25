# Apply an AppLocker policy XML staged on the VirtIO-FS share.
# Renders with one placeholder: {path} -> guest path to the XML.
$xmlPath = '{path}'
if (-not (Test-Path $xmlPath)) {{
    Write-Error "Policy file not found: $xmlPath"
    exit 1
}}
Set-AppLockerPolicy -XmlPolicy $xmlPath
