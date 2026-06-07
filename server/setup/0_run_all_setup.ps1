<#
.SYNOPSIS
    Runs all server setup scripts sequentially with Administrator privileges.
#>

$ErrorActionPreference = "Stop"

# Ensure script is running as Administrator
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$p  = New-Object System.Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Elevating to Administrator..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$Root = $PSScriptRoot

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "   FLARE v0.6 - Server Setup Runner" -ForegroundColor Red
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
    @{ File = "1_setup.ps1";     Args = @{ NoExit = $true; PythonExe = $PythonExe } },
    @{ File = "2_configure.ps1"; Args = @{ Mode = "server"; NoExit = $true; PythonExe = $PythonExe } }
)

foreach ($entry in $scripts) {
    $scriptPath = Join-Path $Root $entry.File
    if (Test-Path $scriptPath) {
        Write-Host "`n>>> Running: $($entry.File) <<<" -ForegroundColor Magenta
        try {
            if ($entry.Args) {
                $splat = $entry.Args
                & $scriptPath @splat
            } else {
                & $scriptPath
            }
            Write-Host ">>> Done: $($entry.File) <<<" -ForegroundColor Green
        } catch {
            Write-Host ">>> Error executing $($entry.File) <<<" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            Read-Host "Press Enter to exit"
            exit
        }
    } else {
        Write-Host "`n>>> WARNING: $($entry.File) not found. Skipping... <<<" -ForegroundColor Yellow
    }
}

Write-Host "`n===============================================" -ForegroundColor Cyan
Write-Host "  ALL SETUP SCRIPTS COMPLETED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Cyan

Read-Host "Press Enter to exit"
