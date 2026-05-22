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
Write-Host "   FLARE v0.4 - Server Setup Runner" -ForegroundColor Red
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

$scripts = @(
    @{ File = "1_setup.ps1";     Args = @{ NoExit = $true } },
    @{ File = "2_configure.ps1"; Args = @{ Mode = "server"; NoExit = $true } }
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
