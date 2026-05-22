param([string]$FlareRoot = $PSScriptRoot, [string]$PythonExe = "python")
$ErrorActionPreference = "SilentlyContinue"

$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $scriptPath = $MyInvocation.MyCommand.Definition
    Start-Process powershell -Verb RunAs -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$scriptPath`" -FlareRoot `"$FlareRoot`" -PythonExe `"$PythonExe`""
    exit
}

function Write-Step { param($msg) Write-Host "`n  [+] $msg" -ForegroundColor Cyan }
function Write-OK   { param($msg) Write-Host "      OK  $msg" -ForegroundColor Green }

Write-Host "`n  FLARE v0.4 - Server Uninstaller (Dependencies Preserved)" -ForegroundColor White

Write-Step "Stopping running server processes"
Get-WmiObject Win32_Process -Filter "Name='python.exe' OR Name='python3.exe'" -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.CommandLine -match [regex]::Escape("flare_server.py")) {
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        Write-OK "Killed flare_server.py"
    }
}

Write-Step "Removing Machine-scope env variables"
@("FLARE_DASHBOARD_USER","FLARE_DASHBOARD_PASS_HASH","FLARE_PORT","FLARE_DB_PATH","FLARE_FL_MIN_CLIENTS","FLARE_FL_TEST_MODE","FLARE_CERT_FILE","FLARE_KEY_FILE","FLARE_CA_CERT") | ForEach-Object {
    [System.Environment]::SetEnvironmentVariable($_, $null, "Machine")
}
Write-OK "Environment variables cleared"

Write-Step "Removing firewall rules"
Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match "^FLARE-Server-Inbound-" } | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Write-OK "Firewall rules removed"

Write-Step "Deleting databases & certs"
Remove-Item -Path (Join-Path $FlareRoot "data") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $FlareRoot "certs") -Recurse -Force -ErrorAction SilentlyContinue
Write-OK "Data and certs folders deleted"

Write-Step "Removing certs from Windows Trust Store"
Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Where-Object { $_.Subject -match "CN=FLARE CA" } | Remove-Item -ErrorAction SilentlyContinue
Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue | Where-Object { $_.Issuer -match "CN=FLARE CA" } | Remove-Item -ErrorAction SilentlyContinue
@("HKLM:\SOFTWARE\Policies\Google\Chrome\AutoSelectCertificateForUrls", "HKLM:\SOFTWARE\Policies\Microsoft\Edge\AutoSelectCertificateForUrls") | ForEach-Object { Remove-Item -Path $_ -Recurse -Force -ErrorAction SilentlyContinue }
Write-OK "Certificates and policies removed"

Write-Host "`n  Server uninstallation complete." -ForegroundColor Green