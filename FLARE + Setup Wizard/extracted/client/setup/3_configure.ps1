param(
    [string]$FlareRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$PythonExe = "python",
    [switch]$NoExit
)

$ErrorActionPreference = "Stop"

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -Verb RunAs -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`" -PythonExe `"$PythonExe`""
    exit
}

. "$PSScriptRoot\config_helpers.ps1"

Write-Host "`n  FLARE - Agent Configuration" -ForegroundColor White
$certsDir = Join-Path $FlareRoot "certs"
if (-not (Test-Path $certsDir)) { New-Item -ItemType Directory -Path $certsDir -Force | Out-Null }

# ---------------------------------------------------------------------------
# STEP 0: Create C:\Program Files\Flare-data\client and grant write access
# ---------------------------------------------------------------------------
# The agent normally runs as a regular user (or as the "FLAREAgent" service
# account), but Program Files is read-only to non-admins by default. Grant the
# local Users group Modify rights so the agent can write its log file,
# net_flows_*.csv captures, .flare_offset trackers and the archive\ folder
# without needing to run elevated every time.
$flareDataClient = "C:\Program Files\Flare-data\client"
Write-Host "`n  [+] Preparing $flareDataClient ..." -ForegroundColor Cyan
if (-not (Test-Path $flareDataClient)) {
    New-Item -ItemType Directory -Path $flareDataClient -Force | Out-Null
}
try {
    icacls $flareDataClient /grant "*S-1-5-32-545:(OI)(CI)M" /T /Q | Out-Null   # Users: Modify
    icacls $flareDataClient /grant "*S-1-5-19:(OI)(CI)M"     /T /Q | Out-Null   # LOCAL SERVICE: Modify
    Write-Host "      OK  Granted write access for Users / Local Service" -ForegroundColor Green
} catch {
    Write-Host "      !!  Could not set ACLs on $flareDataClient : $_" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# STEP 1: Select Network Interface & Auto-Discover Server
# ---------------------------------------------------------------------------
$ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' })
if ($ips.Count -eq 0) {
    $selectedIp = "0.0.0.0"
} else {
    Write-Host "`n  Select network interface to listen for the server beacon:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $ips.Count; $i++) {
        Write-Host "    [$($i+1)] $($ips[$i].IPAddress) ($($ips[$i].InterfaceAlias))"
    }
    $choice = Read-Host "  Choice [1]"
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = 1 }
    $selectedIp = $ips[[int]$choice - 1].IPAddress
}

Write-Host "`n  [+] Listening for server beacon (UDP 37020) on $selectedIp..." -ForegroundColor Cyan

$discoveredUrl = $null
try {
    $bindIp = if ($selectedIp -eq "0.0.0.0") { [System.Net.IPAddress]::Any } else { [System.Net.IPAddress]::Parse($selectedIp) }
    $udpEndpoint = New-Object System.Net.IPEndPoint($bindIp, 37020)
    $udpClient   = New-Object System.Net.Sockets.UdpClient
    $udpClient.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
    $udpClient.ExclusiveAddressUse = $false
    $udpClient.Client.Bind($udpEndpoint)
    $udpClient.Client.ReceiveTimeout = 5000

    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while ([DateTime]::UtcNow -lt $deadline) {
        $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $bytes = $udpClient.Receive([ref]$ep)
        $msg = [System.Text.Encoding]::UTF8.GetString($bytes)
        if ($msg -match '^FLARE_SERVER::([^:]+)::(\d+)$') {
            $discoveredUrl = "https://$($Matches[1]):$($Matches[2])"
            Write-Host "      OK  Server found: $discoveredUrl" -ForegroundColor Green
            break
        }
    }
    $udpClient.Close()
} catch {}

if (-not $discoveredUrl) {
    Write-Host "`n      !!  Beacon timeout." -ForegroundColor Yellow
    do {
        $manualUrl = Read-Host "      Enter server URL manually (e.g. https://192.168.100.190:7331)"
    } while ([string]::IsNullOrWhiteSpace($manualUrl) -or -not ($manualUrl -match "^https?://"))
    $discoveredUrl = $manualUrl.Trim()
}

# ---------------------------------------------------------------------------
# STEP 2: Securely Auto-Provision Certificates (1-Click)
# ---------------------------------------------------------------------------
Write-Host "`n  [+] Downloading mTLS certificates from server..." -ForegroundColor Cyan

$clientName = $env:COMPUTERNAME
$provisionUrl = "$discoveredUrl/api/provision?token=flare&client=$clientName"
$zipTmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "flare-certs.zip")

try {
    # FIX: PowerShell's native Invoke-WebRequest uses Windows Schannel for TLS. 
    # When a server asks for an optional client certificate (mTLS), Schannel often 
    # panics and forcibly closes the connection if it doesn't have one to provide.
    # Python's 'requests' library (backed by OpenSSL) handles this gracefully. 
    # Since Python is already installed, we use it to securely download the certificates.
    
    $pyScriptPath = Join-Path $env:TEMP "download_certs.py"
    $pyCode = @"
import requests
import urllib3
import sys
urllib3.disable_warnings()
try:
    r = requests.get('$provisionUrl', verify=False, timeout=15)
    r.raise_for_status()
    with open(r'$zipTmp', 'wb') as f:
        f.write(r.content)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
"@
    $pyCode | Set-Content $pyScriptPath -Encoding UTF8

    # Run the Python downloader and capture output
    $savedEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $pyOutput = & $PythonExe $pyScriptPath 2>&1
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedEAP

    Remove-Item $pyScriptPath -Force -ErrorAction SilentlyContinue

    if ($exitCode -ne 0) {
        throw "Python download failed: $pyOutput"
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (Test-Path $certsDir) { Remove-Item "$certsDir\*" -Force -ErrorAction SilentlyContinue }
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipTmp, $certsDir)
    Remove-Item $zipTmp -Force -ErrorAction SilentlyContinue

    Write-Host "      OK  Certificates downloaded and installed!" -ForegroundColor Green

    # Install the CA locally so the agent trusts the server going forward
    Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -match "CN=FLARE CA" } | Remove-Item -ErrorAction SilentlyContinue
    Import-Certificate -FilePath "$certsDir\ca.crt" -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
} catch {
    Write-Host "      ERR Failed to download certs: $_" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# STEP 3: Save Environment Paths
# ---------------------------------------------------------------------------
Write-Host "`n  [+] Saving Configuration..." -ForegroundColor Cyan
Set-MachineEnv "FLARE_SERVER_URL" $discoveredUrl

$envFilePath = Join-Path $FlareRoot "agent.env"
@(
    "FLARE_SERVER_URL=$discoveredUrl",
    "FLARE_CA_CERT=certs\ca.crt",
    "FLARE_CLIENT_CERT=certs\client.crt",
    "FLARE_CLIENT_KEY=certs\client.key",
    "FLARE_NET_CSV=C:\Program Files\Flare-data\client\net_flows.csv",
    "FLARE_LOG_LEVEL=INFO",
    "FLARE_FL_TEST_MODE=0"
) | Set-Content $envFilePath -Encoding UTF8

Write-Host "`n  Agent Configured Successfully!" -ForegroundColor Green
if (-not $NoExit) { Read-Host "  Press Enter to exit" }