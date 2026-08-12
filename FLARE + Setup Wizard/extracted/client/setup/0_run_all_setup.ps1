<#
.SYNOPSIS
    Runs all client setup scripts sequentially with Administrator privileges.
#>

$ErrorActionPreference = "Stop"

$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$p  = New-Object System.Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Elevating to Administrator..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -NoExit -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$Root = $PSScriptRoot

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "   FLARE - Client Setup Runner" -ForegroundColor Red
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "  [0] Locating Python 3.10+" -ForegroundColor Cyan

$PythonExe = $null

foreach ($exe in @("python", "py", "python3")) {
    try {
        $pyCmd = "import sys; print(str(sys.version_info[0]) + '.' + str(sys.version_info[1]))"
        $verOut = & $exe -c $pyCmd 2>&1
        $verOut = ($verOut -split "`n")[0].Trim()
        if ($verOut -match '^\d+\.\d+$') {
            $parts = $verOut -split '\.'
            if ([int]$parts[0] -ge 3 -and [int]$parts[1] -ge 10) {
                $cmdObj = Get-Command $exe -ErrorAction SilentlyContinue
                if ($cmdObj -and $cmdObj.Source) {
                    $PythonExe = $cmdObj.Source
                } else {
                    $PythonExe = $exe
                }
                Write-Host "      OK  Python $verOut at: $PythonExe" -ForegroundColor Green
                break
            }
        }
    }
    catch { }
}

if (-not $PythonExe) {
    Write-Host "`n  ERROR: Python 3.10+ not found." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

$scripts = @(
    @{ File = "1_grant_privileges.ps1"; Args = @{ NoExit = $true } },
    @{ File = "2_setup.ps1";            Args = @{ NoExit = $true; PythonExe = $PythonExe } },
    @{ File = "3_configure.ps1";        Args = @{ NoExit = $true; PythonExe = $PythonExe } }
)

foreach ($script in $scripts) {
    $scriptPath = Join-Path $Root $script.File
    if (Test-Path $scriptPath) {
        Write-Host "`n--- Running: $($script.File) ---" -ForegroundColor Magenta
        try {
            if ($script.Args) {
                $splat = $script.Args
                & $scriptPath @splat
            } else {
                & $scriptPath
            }
            Write-Host "--- Done: $($script.File) ---" -ForegroundColor Green
        } catch {
            Write-Host "--- Error in: $($script.File) ---" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            Read-Host "Press Enter to exit"
            exit
        }
    }
}

Write-Host "`n===============================================" -ForegroundColor Cyan
Write-Host "  ALL SETUP SCRIPTS COMPLETED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Cyan
Read-Host "Press Enter to exit"