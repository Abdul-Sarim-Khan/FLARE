param([string]$PythonExe = "python", [switch]$NoExit)
$ErrorActionPreference = "Stop"
$FlareRoot = Split-Path -Parent $PSScriptRoot

Write-Host "`n[+] Installing agent dependencies..." -ForegroundColor Cyan
& $PythonExe -m pip install -r (Join-Path $FlareRoot "requirements_agent.txt")

Write-Host "[+] Creating required folders..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path (Join-Path $FlareRoot "certs") -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType Directory -Path (Join-Path $FlareRoot "logs") -Force -ErrorAction SilentlyContinue | Out-Null

Write-Host "[+] Installing FLARE service..." -ForegroundColor Cyan
$svcScript = Join-Path $FlareRoot "flare_service.py"
if (Test-Path $svcScript) { & $PythonExe $svcScript install }

Write-Host "`nAgent setup complete!" -ForegroundColor Green