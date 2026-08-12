<#
.SYNOPSIS
    Build FLARE_Server_Setup.exe and FLARE_Client_Setup.exe using Inno Setup.

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Target server
    .\build.ps1 -Target client
#>

param(
    [ValidateSet("both", "server", "client")]
    [string]$Target = "both"
)

$ErrorActionPreference = "Stop"

$ScriptDir = $PSScriptRoot
$OutputDir = Join-Path $ScriptDir "Output"
New-Item -ItemType Directory -Force $OutputDir | Out-Null

Write-Host ""
Write-Host "  FLARE Installer Builder" -ForegroundColor Cyan
Write-Host "  Target : $Target"
Write-Host "  Output : $OutputDir"
Write-Host ""

# --- 1. Generate branding images ---

Write-Host "  [1/3] Generating branding images..." -ForegroundColor Cyan

$CreateImages = Join-Path $ScriptDir "create_images.py"
if (-not (Test-Path $CreateImages)) {
    Write-Host "  ERROR: create_images.py not found at $CreateImages" -ForegroundColor Red
    exit 1
}

python $CreateImages
if ($LASTEXITCODE -ne 0) {
    Write-Host "  WARNING: create_images.py exited with code $LASTEXITCODE" -ForegroundColor Yellow
    Write-Host "  Continuing - Inno Setup will build without branding images." -ForegroundColor Yellow
}

$BannerOK = Test-Path (Join-Path $ScriptDir "banner.bmp")
$SmallOK  = Test-Path (Join-Path $ScriptDir "small.bmp")
if (-not $BannerOK -or -not $SmallOK) {
    Write-Host "  WARNING: BMP files not found - installer will build without FLARE branding." -ForegroundColor Yellow
}

# --- 2. Locate Inno Setup ---

Write-Host ""
Write-Host "  [2/3] Locating Inno Setup compiler..." -ForegroundColor Cyan

$CandidatePaths = @(
    "C:\Program Files\Inno Setup 7\ISCC.exe",
    "C:\Program Files (x86)\Inno Setup 7\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe",
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 5\ISCC.exe",
    "C:\Program Files (x86)\Inno Setup 5\ISCC.exe"
)

$ISCC = $null
foreach ($p in $CandidatePaths) {
    if (Test-Path $p) { $ISCC = $p; break }
}

if (-not $ISCC) {
    Write-Host ""
    Write-Host "  ERROR: Inno Setup not found." -ForegroundColor Red
    Write-Host "  Download from: https://jrsoftware.org/isdl.php" -ForegroundColor Yellow
    Write-Host "  Install it, then re-run this script." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

Write-Host "  Found : $ISCC" -ForegroundColor Green

# --- 3. Compile ---

Write-Host ""
Write-Host "  [3/3] Compiling installer(s)..." -ForegroundColor Cyan

function Build-Installer {
    param([string]$IssFile, [string]$Label)
    Write-Host ""
    Write-Host "  Building $Label ..." -ForegroundColor White
    $full = Join-Path $ScriptDir $IssFile
    if (-not (Test-Path $full)) {
        Write-Host "  ERROR: $full not found." -ForegroundColor Red
        exit 1
    }
    & $ISCC $full
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  FAILED: $Label (ISCC exit code $LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
    Write-Host "  OK: $Label" -ForegroundColor Green
}

if ($Target -eq "both" -or $Target -eq "server") {
    Build-Installer "server_setup.iss" "FLARE Server Setup"
}
if ($Target -eq "both" -or $Target -eq "client") {
    Build-Installer "client_setup.iss" "FLARE Client Setup"
}

# --- Done ---

Write-Host ""
Write-Host "  Build complete. Output files:" -ForegroundColor Green
Get-ChildItem $OutputDir -Filter "*.exe" | ForEach-Object {
    Write-Host "    $($_.FullName)" -ForegroundColor Cyan
}
Write-Host ""
