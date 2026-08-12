<#
.SYNOPSIS
    FLARE - Step 3: Apply runtime configuration to this machine.
#>

param(
    [ValidateSet("agent","server")]
    [string]$Mode          = "server",
    [string]$FlareRoot     = (Split-Path -Parent $PSScriptRoot),
    [switch]$NonInteractive,
    [switch]$NoExit
)

$ErrorActionPreference = "Stop"

$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Not running as Administrator - relaunching elevated..." -ForegroundColor Yellow
    $scriptPath = $MyInvocation.MyCommand.Definition
    $argList    = "-NoExit -ExecutionPolicy Bypass -File `"$scriptPath`" -Mode $Mode -FlareRoot `"$FlareRoot`""
    if ($NonInteractive) { $argList += " -NonInteractive" }
    Start-Process powershell -Verb RunAs -ArgumentList $argList
    exit
}

. "$PSScriptRoot\config_helpers.ps1"

Write-Host ""
Write-Host "  FLARE - Configuration ($Mode mode)" -ForegroundColor White

# ---------------------------------------------------------------------------
# Create C:\Program Files\Flare-data\server and grant write access
# ---------------------------------------------------------------------------
# flare_server.py writes its log files,
# flare.db (+ -wal/-shm), net_flows_*.csv captures, .flare_offset trackers and
# the archive\ folder here. Program Files is read-only to non-admins by
# default, so grant the local Users group (and Local Service, used by
# services running under that account) Modify rights.
if ($Mode -eq "server") {
    $flareDataServer = "C:\Program Files\Flare-data\server"
    Write-Step "Preparing $flareDataServer"
    if (-not (Test-Path $flareDataServer)) {
        New-Item -ItemType Directory -Path $flareDataServer -Force | Out-Null
    }
    try {
        icacls $flareDataServer /grant "*S-1-5-32-545:(OI)(CI)M" /T /Q | Out-Null   # Users: Modify
        icacls $flareDataServer /grant "*S-1-5-19:(OI)(CI)M"     /T /Q | Out-Null   # LOCAL SERVICE: Modify
        Write-OK "Granted write access for Users / Local Service"
    } catch {
        Write-Warn "Could not set ACLs on $flareDataServer : $_"
    }
}

if ($Mode -eq "agent") {
    $envFilePath = Join-Path $FlareRoot "agent.env"
} else {
    $envFilePath = Join-Path $FlareRoot "data\server.env"
}

$envDefaults = @{}
if (Test-Path $envFilePath) {
    $envDefaults = Read-EnvFile $envFilePath
}

$dataDir = Join-Path $FlareRoot "data"

Write-Host ""

$dashUser = Prompt-Value `
    -Description "Dashboard login username" `
    -Default    (Get-Default $envDefaults "FLARE_DASHBOARD_USER" "admin")

$dashPass = Prompt-Value `
    -Description "Dashboard login password" `
    -Default     "flare" `
    -Secret      $false

if ([string]::IsNullOrWhiteSpace($dashPass)) {
    $dashPass = "flare"
}

$bytes    = [System.Text.Encoding]::UTF8.GetBytes($dashPass)
$sha256   = [System.Security.Cryptography.SHA256]::Create()
$hashBytes = $sha256.ComputeHash($bytes)
$passHash = ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""

$serverPort = Prompt-Value `
    -Description "Listen port" `
    -Default    (Get-Default $envDefaults "FLARE_PORT" "7331")

$minClients = Prompt-Value `
    -Description "Min agents before FL aggregation runs (1 = single machine OK)" `
    -Default    (Get-Default $envDefaults "FLARE_FL_MIN_CLIENTS" "1")

Write-Step "Writing Machine-scope environment variables"
Set-MachineEnv "FLARE_DASHBOARD_USER"      $dashUser
Set-MachineEnv "FLARE_DASHBOARD_PASS_HASH" $passHash
Set-MachineEnv "FLARE_PORT"                $serverPort
Set-MachineEnv "FLARE_FL_MIN_CLIENTS"      $minClients
Set-MachineEnv "FLARE_FL_TEST_MODE"       (Get-Default $envDefaults "FLARE_FL_TEST_MODE" "0")

# FIX: Hardcoding relative paths strictly to ensure complete machine portability.
# Replaces fragile `ConvertTo-RelativePath` logic which accidentally mapped to absolute user directories.
# The database lives under Program Files\Flare-data\server (alongside logs and
# net_flows captures) so it survives a project-folder reinstall and is fully
# wiped by uninstall_server.ps1.
$relDbPath   = "C:\Program Files\Flare-data\server\flare.db"
$relCert     = "certs\server.crt"
$relKey      = "certs\server.key"
$relCaCert   = "certs\ca.crt"

Set-MachineEnv "FLARE_DB_PATH"             $relDbPath
Set-MachineEnv "FLARE_CERT_FILE"           $relCert
Set-MachineEnv "FLARE_KEY_FILE"            $relKey
Set-MachineEnv "FLARE_CA_CERT"             $relCaCert

Write-Step "Updating $envFilePath"
$envContent = @(
    "# FLARE Server Configuration",
    "FLARE_DASHBOARD_USER=$dashUser",
    "FLARE_DASHBOARD_PASS_HASH=$passHash",
    "FLARE_PORT=$serverPort",
    "FLARE_DB_PATH=$relDbPath",
    "FLARE_FL_MIN_CLIENTS=$minClients",
    "FLARE_FL_TEST_MODE=0",
    "FLARE_CERT_FILE=$relCert",
    "FLARE_KEY_FILE=$relKey",
    "FLARE_CA_CERT=$relCaCert"
)
$envContent | Set-Content $envFilePath -Encoding UTF8
Write-OK "Saved $envFilePath"

Write-Step "Generating admin browser certificate"
$adminDir = Join-Path $FlareRoot "certs\clients\admin"
$adminP12 = Join-Path $adminDir "client.p12"
$pkiScript = Join-Path $FlareRoot "generate_pki.py"

if (-not (Test-Path $adminP12)) {
    if (Test-Path $pkiScript) {
        $savedEAP = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $pkiOut = & python $pkiScript --client admin --p12-pass flare 2>&1
        $ErrorActionPreference = $savedEAP
        if ($LASTEXITCODE -eq 0) { Write-OK "Admin certificate bundle created" }
    }
}

Write-Step "Installing admin cert into Windows Personal cert store"
if (Test-Path $adminP12) {
    try {
        Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Issuer -match "CN=FLARE CA" } | ForEach-Object { Remove-Item "Cert:\CurrentUser\My\$($_.Thumbprint)" -ErrorAction SilentlyContinue }
        $p12pass = ConvertTo-SecureString "flare" -AsPlainText -Force
        Import-PfxCertificate -FilePath $adminP12 -CertStoreLocation Cert:\CurrentUser\My -Password $p12pass | Out-Null
        Write-OK "Admin cert installed - Chrome and Edge will use it automatically"
    } catch {}
}

Write-Step "Configuring browser certificate auto-select policy"
$certFilter = '{"pattern":"https://localhost:' + $serverPort + '","filter":{"ISSUER":{"CN":"FLARE CA"}}}'
$browsers = @("HKLM:\SOFTWARE\Policies\Google\Chrome\AutoSelectCertificateForUrls", "HKLM:\SOFTWARE\Policies\Microsoft\Edge\AutoSelectCertificateForUrls")
foreach ($regPath in $browsers) {
    try {
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        Set-ItemProperty -Path $regPath -Name "1" -Value $certFilter -Type String
        Write-OK "Auto-select policy set"
    } catch {}
}

Write-Host ""
Write-Host "  Server configured." -ForegroundColor Green
if (-not $NoExit) { Read-Host "  Press Enter to exit" }