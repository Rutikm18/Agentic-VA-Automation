# Remove the netagent service. Run as Administrator. Leaves ProgramData (identity) by default.
param([switch]$Purge)
$ErrorActionPreference = "SilentlyContinue"
$App = "netagent"
sc.exe stop $App   | Out-Null
sc.exe delete $App | Out-Null
Remove-Item "$Env:ProgramFiles\$App" -Recurse -Force
if ($Purge) { Remove-Item "$Env:ProgramData\$App" -Recurse -Force }
Write-Host "Removed service '$App'." ($(if ($Purge) {"(purged data)"} else {"(kept ProgramData)"}))
