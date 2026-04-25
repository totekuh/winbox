# Enable VBA macros (VBAWarnings=1) for Word/Excel/PowerPoint under
# HKCU. Office 16.0 covers all current/Microsoft 365 versions.
$apps = @('Word', 'Excel', 'PowerPoint')
foreach ($app in $apps) {{
    $p = "HKCU:\Software\Microsoft\Office\16.0\$app\Security"
    New-Item -Path $p -Force | Out-Null
    Set-ItemProperty -Path $p -Name VBAWarnings -Value 1 -Type DWord
}}
