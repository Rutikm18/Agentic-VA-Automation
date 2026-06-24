# Install netagent as a Windows service. Run as Administrator.
#   .\install-service.ps1 -Binary .\netagent-windows-x64.exe -EnrollToken "<token>"
param(
    [Parameter(Mandatory=$true)][string]$Binary,
    [string]$EnrollToken = "",
    [string]$ManagerUrl  = ""
)
$ErrorActionPreference = "Stop"
$App = "netagent"
$InstallDir = "$Env:ProgramFiles\$App"
$DataDir    = "$Env:ProgramData\$App"

New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir | Out-Null
Copy-Item $Binary "$InstallDir\$App.exe" -Force

# Config file (read by the binary on startup).
$envFile = "$DataDir\$App.env"
if (-not (Test-Path $envFile)) {
    $lines = @()
    if ($EnrollToken) { $lines += "PROBE_ENROLL_TOKEN=$EnrollToken" }
    if ($ManagerUrl)  { $lines += "PROBE_MANAGER_URL=$ManagerUrl" }
    Set-Content -Path $envFile -Value $lines -Encoding ASCII
}
# Lock the data dir down (service account + admins only).
icacls $DataDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

# Create + start the service. Runs as LocalService (least privilege; connect-scan only).
sc.exe create $App binPath= "`"$InstallDir\$App.exe`" run" start= auto obj= "NT AUTHORITY\LocalService" DisplayName= "netagent" | Out-Null
sc.exe description $App "netagent network service" | Out-Null
sc.exe failure $App reset= 86400 actions= restart/10000/restart/10000/restart/10000 | Out-Null
sc.exe start $App | Out-Null
Write-Host "Installed and started service '$App'. Config: $envFile"
