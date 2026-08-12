<#
.SYNOPSIS
    FLARE - Server Uninstaller

.DESCRIPTION
    Reverses the server install AND wipes all runtime state, while leaving
    everything needed to re-run setup and reinstall:

      System changes:
        - Stops & deletes the FLAREServerAgent Windows service (if installed)
        - Kills any running flare_server.py process
        - Removes Machine-scope environment variables set during configuration
        - Removes FLARE-Server-Inbound-* firewall rules
        - Removes the FLARE CA certificate from the Windows trust stores
          and any browser auto-select-certificate policies

      Runtime / generated state:
        - Deletes C:\Program Files\Flare-data\server\ (all server logs)
        - Deletes certs\ (CA, server cert/key, all issued client certs)
        - Deletes the SQLite database (flare.db, -wal, -shm)
        - Deletes data\ folder if present (legacy location)
        - Deletes net_flows_*.csv / *.flare_offset files and the archive\
          folder under the server directory (server-side network capture)
        - Deletes __pycache__ folders under the server directory

      NOT deleted (kept so the server can be reinstalled / re-run):
        - All .py source files, proto/, host/, ioc/, network/, ui/
        - Trained model files under network\models\ (network_mlp.pkl,
          network_scaler.pkl, feature_names.json, network_mlp_weights.json)
        - setup\ scripts, generate_cert.py, generate_pki.py,
          requirements_server.txt, HOW_TO_RUN.md, CHANGES.md
        - Installed Python packages (left untouched)

    Must run as Administrator.

.PARAMETER FlareRoot
    Root of the server project (where certs\, the database, and net_flows
    CSVs live). Defaults to the folder containing this script.

.EXAMPLE
    .\uninstall_server.ps1
#>

param(
    [string]$FlareRoot = $PSScriptRoot,
    [string]$PythonExe = "python"
)

$ErrorActionPreference = "SilentlyContinue"

# ---------------------------------------------------------------------------
# 0. Self-elevate
# ---------------------------------------------------------------------------
$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Not running as Administrator - relaunching elevated..." -ForegroundColor Yellow
    $scriptPath = $MyInvocation.MyCommand.Definition
    Start-Process powershell -Verb RunAs -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$scriptPath`" -FlareRoot `"$FlareRoot`" -PythonExe `"$PythonExe`""
    exit
}

function Write-Step { param($msg) Write-Host "`n  [+] $msg" -ForegroundColor Cyan }
function Write-OK   { param($msg) Write-Host "      OK  $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "      !!  $msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "  FLARE - Server Uninstaller (dependencies preserved)" -ForegroundColor White
Write-Host "  FlareRoot : $FlareRoot"

# ---------------------------------------------------------------------------
# 1. Stop and delete the FLAREServerAgent Windows service
# ---------------------------------------------------------------------------
Write-Step "Removing FLAREServerAgent service"
$svcAgent = Get-Service -Name "FLAREServerAgent" -ErrorAction SilentlyContinue
if ($svcAgent) {
    sc.exe stop "FLAREServerAgent" 2>&1 | Out-Null
    Start-Sleep -Milliseconds 1500
    sc.exe delete "FLAREServerAgent" 2>&1 | Out-Null
    Write-OK "FLAREServerAgent service stopped and deleted"
} else {
    Write-Warn "Service 'FLAREServerAgent' not found - skipping"
}

# ---------------------------------------------------------------------------
# 2. Stop any running server processes
# ---------------------------------------------------------------------------
Write-Step "Stopping running server processes"
$killed = $false
Get-WmiObject Win32_Process -Filter "Name='python.exe' OR Name='python3.exe'" `
    -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.CommandLine -match [regex]::Escape("flare_server.py")) {
        $pid_ = $_.ProcessId
        Stop-Process -Id $pid_ -Force -ErrorAction SilentlyContinue
        Write-OK "Killed flare_server.py process (PID $pid_)"
        $killed = $true
    }
}
if (-not $killed) {
    Write-Warn "No running flare_server.py process found - skipping"
}

Start-Sleep -Milliseconds 500

# ---------------------------------------------------------------------------
# 3. Remove Machine-scope environment variables
# ---------------------------------------------------------------------------
Write-Step "Removing Machine-scope environment variables"
$envVars = @(
    "FLARE_DASHBOARD_USER",
    "FLARE_DASHBOARD_PASS_HASH",
    "FLARE_PORT",
    "FLARE_DB_PATH",
    "FLARE_FL_MIN_CLIENTS",
    "FLARE_FL_TEST_MODE",
    "FLARE_CERT_FILE",
    "FLARE_KEY_FILE",
    "FLARE_CA_CERT",
    "FLARE_LOG_LEVEL"
)
foreach ($var in $envVars) {
    $current = [System.Environment]::GetEnvironmentVariable($var, "Machine")
    if ($null -ne $current) {
        [System.Environment]::SetEnvironmentVariable($var, $null, "Machine")
        [System.Environment]::SetEnvironmentVariable($var, $null, "Process")
        Write-OK "Removed $var"
    } else {
        Write-Warn "$var was not set - skipping"
    }
}

# ---------------------------------------------------------------------------
# 4. Remove FLARE-Server-Inbound-* firewall rules
# ---------------------------------------------------------------------------
Write-Step "Removing inbound firewall rules"
$rules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match "^FLARE-Server-Inbound-" }
if ($rules) {
    $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Write-OK "Removed $($rules.Count) firewall rule(s)"
} else {
    Write-Warn "No FLARE-Server-Inbound-* firewall rules found - skipping"
}

# ---------------------------------------------------------------------------
# 5. Delete the SQLite database (flare.db, -wal, -shm)
# ---------------------------------------------------------------------------
Write-Step "Deleting SQLite database"
$dbDeleted = $false
Get-ChildItem -Path $FlareRoot -Filter "flare.db*" -File -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
    Write-OK "Deleted $($_.Name)"
    $dbDeleted = $true
}
if (-not $dbDeleted) {
    Write-Warn "No flare.db files found - skipping"
}

# ---------------------------------------------------------------------------
# 6. Delete legacy data\ folder and certs\ folder
# ---------------------------------------------------------------------------
Write-Step "Deleting data\ and certs\ folders"
$dataDir  = Join-Path $FlareRoot "data"
$certsDir = Join-Path $FlareRoot "certs"
if (Test-Path $dataDir) {
    Remove-Item -Path $dataDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-OK "Deleted $dataDir"
} else {
    Write-Warn "$dataDir not found - skipping"
}
if (Test-Path $certsDir) {
    Remove-Item -Path $certsDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-OK "Deleted $certsDir"
} else {
    Write-Warn "$certsDir not found - skipping"
}

# ---------------------------------------------------------------------------
# 7. Remove FLARE CA certs from Windows trust stores / browser policies
# ---------------------------------------------------------------------------
Write-Step "Removing certs from Windows Trust Store"
Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Where-Object { $_.Subject -match "CN=FLARE CA" } | Remove-Item -ErrorAction SilentlyContinue
Get-ChildItem Cert:\CurrentUser\My  -ErrorAction SilentlyContinue | Where-Object { $_.Issuer  -match "CN=FLARE CA" } | Remove-Item -ErrorAction SilentlyContinue
@(
    "HKLM:\SOFTWARE\Policies\Google\Chrome\AutoSelectCertificateForUrls",
    "HKLM:\SOFTWARE\Policies\Microsoft\Edge\AutoSelectCertificateForUrls"
) | ForEach-Object { Remove-Item -Path $_ -Recurse -Force -ErrorAction SilentlyContinue }
Write-OK "Certificates and policies removed"

# ---------------------------------------------------------------------------
# 8. Delete all server logs under C:\Program Files\Flare-data\server
# ---------------------------------------------------------------------------
Write-Step "Deleting server log directory"
$logDir    = "C:\Program Files\Flare-data\server"
$flareData = "C:\Program Files\Flare-data"
if (Test-Path $logDir) {
    Remove-Item -Path $logDir -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $logDir) {
        # Almost always a flare_server.py / flare_agent.py process still holding
        # flare.db or a CSV open. Give the OS a moment to release handles, retry.
        Start-Sleep -Milliseconds 1500
        Remove-Item -Path $logDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $logDir) {
        Write-Warn "Could NOT delete $logDir - a FLARE server/agent is still holding a file open. Stop it and re-run, or delete it manually."
    } else {
        Write-OK "Deleted $logDir"
    }
} else {
    Write-Warn "$logDir not found - skipping"
}
# Remove the parent C:\Program Files\Flare-data once its last subfolder is gone,
# so the uninstall doesn't leave an empty Flare-data directory behind. Kept if
# the other role's data (e.g. \client) is still present.
if ((Test-Path $flareData) -and -not (Get-ChildItem -Path $flareData -Force -ErrorAction SilentlyContinue)) {
    Remove-Item -Path $flareData -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path $flareData)) { Write-OK "Removed empty $flareData" }
}

# ---------------------------------------------------------------------------
# 9. Delete net_flows CSVs, offset trackers, and the archive folder
#  (only present if the server's own host agent captures network flows)
# ---------------------------------------------------------------------------
Write-Step "Deleting net_flows CSV data"
$csvDeleted = $false
Get-ChildItem -Path $FlareRoot -Filter "net_flows_*.csv" -File -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
    Write-OK "Deleted $($_.Name)"
    $csvDeleted = $true
}
Get-ChildItem -Path $FlareRoot -Filter "*.flare_offset" -File -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
    Write-OK "Deleted $($_.Name)"
    $csvDeleted = $true
}
$archiveDir = Join-Path $FlareRoot "archive"
if (Test-Path $archiveDir) {
    Remove-Item -Path $archiveDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-OK "Deleted $archiveDir"
    $csvDeleted = $true
}
if (-not $csvDeleted) {
    Write-Warn "No net_flows CSV / offset / archive data found - skipping"
}

# ---------------------------------------------------------------------------
# 10. Delete __pycache__ folders under the server directory
# ---------------------------------------------------------------------------
Write-Step "Deleting __pycache__ folders"
$pycacheDirs = Get-ChildItem -Path $FlareRoot -Filter "__pycache__" -Directory -Recurse -ErrorAction SilentlyContinue
if ($pycacheDirs) {
    foreach ($dir in $pycacheDirs) {
        Remove-Item -Path $dir.FullName -Recurse -Force -ErrorAction SilentlyContinue
        Write-OK "Deleted $($dir.FullName)"
    }
} else {
    Write-Warn "No __pycache__ folders found - skipping"
}

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "  Server uninstallation complete." -ForegroundColor Green
Write-Host "  Kept (needed to reinstall): source files, setup\ scripts," -ForegroundColor White
Write-Host "  generate_cert.py / generate_pki.py, trained model files under" -ForegroundColor White
Write-Host "  network\models\, requirements_server.txt, and all installed" -ForegroundColor White
Write-Host "  Python packages." -ForegroundColor White
Write-Host ""
Read-Host "  Press Enter to exit"
