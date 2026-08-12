<#
.SYNOPSIS
    FLARE - Step 2b: Install the FLARE server.
#>

param(
    [string]$FlareRoot   = (Split-Path -Parent $PSScriptRoot),
    [string]$DataDir     = "",
    [int]   $ServerPort  = 7331,
    [string]$PythonExe   = "python",
    [switch]$OpenFirewall,
    [switch]$NoExit
)

$ErrorActionPreference = "Stop"

if (-not $DataDir) { $DataDir = Join-Path $FlareRoot "data" }

$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
$isAdmin   = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

if ($OpenFirewall -and -not $isAdmin) {
    Write-Host "Not running as Administrator - relaunching elevated for firewall rule..." -ForegroundColor Yellow
    $scriptPath = $MyInvocation.MyCommand.Definition
    Start-Process powershell -Verb RunAs -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$scriptPath`" -FlareRoot `"$FlareRoot`" -DataDir `"$DataDir`" -ServerPort $ServerPort -PythonExe `"$PythonExe`" -OpenFirewall"
    exit
}

function Write-Step { param($msg) Write-Host "`n  [+] $msg" -ForegroundColor Cyan }
function Write-OK   { param($msg) Write-Host "      OK  $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "      !!  $msg" -ForegroundColor Yellow }
function Write-Fail {
    param($msg)
    Write-Host "      ERR $msg" -ForegroundColor Red
    if (-not $NoExit) { Read-Host "`n  Press Enter to exit" }
    exit 1
}

Write-Host ""
Write-Host "  FLARE - Server Setup" -ForegroundColor White
Write-Host "  Repo root : $FlareRoot"
Write-Host "  Data dir  : $DataDir"
Write-Host "  Port      : $ServerPort"
Write-Host "  Python    : $PythonExe"

Write-Step "Checking Python version"
try {
    $pyCmd = "import sys; print(str(sys.version_info[0]) + '.' + str(sys.version_info[1]))"
    $verStr = & $PythonExe -c $pyCmd 2>&1
    $verStr = ($verStr -split "`n")[0].Trim()
    $parts  = $verStr -split '\.'
    $major  = [int]$parts[0]
    $minor  = [int]$parts[1]
    if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 10)) {
        Write-Fail "Python 3.10+ required - found $verStr"
    }
    Write-OK "Python $verStr"
} catch {
    Write-Fail "Python not found at '$PythonExe'. Install from https://python.org"
}

Write-Step "Installing server dependencies"
$reqFile = Join-Path $FlareRoot "requirements_server.txt"
if (-not (Test-Path $reqFile)) { Write-Fail "requirements_server.txt not found at $reqFile" }

Write-Host " (Installing packages - this may take a few minutes)" -ForegroundColor Gray
& $PythonExe -m pip install --no-input -r $reqFile
if ($LASTEXITCODE -ne 0) { Write-Fail "pip install failed" }
Write-OK "All packages installed"

Write-Step "Verifying proto module"
$protoCheck = & $PythonExe -c @"
import sys
sys.path.insert(0, r'$FlareRoot')
from proto import log_schema_pb2 as pb
hb = pb.Heartbeat()
hb.client_id = 'test'
print('OK proto: ' + str(len(hb.SerializeToString())) + ' bytes')
"@ 2>&1
if ($LASTEXITCODE -ne 0) { Write-Fail "Proto import failed: $protoCheck" }
Write-OK $protoCheck

Write-Step "Verifying FastAPI app imports"
$appCheck = & $PythonExe -c @"
import sys, os
sys.path.insert(0, r'$FlareRoot')
os.chdir(r'$FlareRoot')
import flare_server
print('OK app loaded')
"@ 2>&1
if ($LASTEXITCODE -ne 0) { Write-Fail "Server import failed: $appCheck" }
Write-OK $appCheck

Write-Step "Creating data directory: $DataDir"
if (-not (Test-Path $DataDir)) {
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    Write-OK "Created $DataDir"
} else {
    Write-Warn "$DataDir already exists"
}

$envFile = Join-Path $DataDir "server.env"
Write-Step "Writing skeleton config: $envFile"
if (Test-Path $envFile) {
    Write-Warn "$envFile already exists - not overwriting"
} else {
    $envContent = @(
        "# FLARE Server Configuration",
        "# Apply with: setup\2_configure.ps1 -Mode server",
        "",
        "FLARE_PORT=$ServerPort",
        "FLARE_DB_PATH=C:\Program Files\Flare-data\server\flare.db",
        "FLARE_FL_TEST_MODE=0"
    )
    $envContent | Set-Content $envFile -Encoding UTF8
    Write-OK "Wrote $envFile"
}

Write-Step "Generating mTLS PKI (CA + server certificate)"
$pkiScript = Join-Path $FlareRoot "generate_pki.py"
if (Test-Path $pkiScript) {
    $pkiOutput = & $PythonExe $pkiScript 2>&1
    $pkiOutput | ForEach-Object { Write-Host "      $_" }
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "PKI generation returned exit code $LASTEXITCODE - check output above."
    } else {
        Write-OK "PKI generation complete"
    }
} else {
    Write-Fail "generate_pki.py not found at $pkiScript"
}

Write-Step "Installing CA cert into Windows Trusted Root CA store"
$caCertFile = Join-Path $FlareRoot "certs\ca.crt"
if (Test-Path $caCertFile) {
    try {
        Get-ChildItem Cert:\LocalMachine\Root |
            Where-Object { $_.Subject -match "CN=FLARE CA" } |
            ForEach-Object { Remove-Item "Cert:\LocalMachine\Root\$($_.Thumbprint)" -ErrorAction SilentlyContinue }

        Import-Certificate -FilePath $caCertFile -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
        Write-OK "CA cert installed - browsers on this machine will trust the server"
    } catch {
        Write-Warn "Could not install CA cert automatically: $_"
    }
} else {
    Write-Warn "CA cert not found at $caCertFile - skipping trust installation"
}

Write-Host ""
Write-Host "  ================================================================" -ForegroundColor Yellow
Write-Host "  mTLS PKI ready.  To provision a new agent machine:" -ForegroundColor Yellow
Write-Host ""
Write-Host "    python generate_pki.py --client [AGENT-HOSTNAME]" -ForegroundColor Cyan
Write-Host ""
Write-Host "  ================================================================" -ForegroundColor Yellow
Write-Host ""

if ($OpenFirewall) {
    Write-Step "Opening inbound firewall rule for port $ServerPort"
    $ruleName = "FLARE-Server-Inbound-$ServerPort"
    if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
        Write-Warn "Rule '$ruleName' already exists"
    } else {
        New-NetFirewallRule `
            -DisplayName $ruleName `
            -Direction   Inbound `
            -Protocol    TCP `
            -LocalPort   $ServerPort `
            -Action      Allow `
            -Profile     Any `
            -Description "Allow FLARE agents to reach the FLARE server" |
            Out-Null
        Write-OK "Inbound firewall rule created (TCP port $ServerPort)"
    }
}

Write-Host ""
Write-Host "  Server setup complete." -ForegroundColor Green
Write-Host ""
if (-not $NoExit) { Read-Host "  Press Enter to exit" }