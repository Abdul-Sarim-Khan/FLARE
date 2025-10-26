# ========================================================
# FLARE Agent Installation Script
# Installs and configures the log collection agent as a Scheduled Task.
# Requires: Running as Administrator.
# ========================================================

#Requires -RunAsAdministrator

param(
    [string]$InstallPath = "C:\Program Files\FLARE\Agent",
    [switch]$Uninstall
)

$ServiceName = "FLARELogCollectorAgent"
$ServiceDisplayName = "FLARE Log Collection Agent"
$ServiceDescription = "Collects and displays Windows Event Logs"

Write-Host "`n=== FLARE Agent Installation ===" -ForegroundColor Cyan

if ($Uninstall) {
    Write-Host "`nUninstalling agent..." -ForegroundColor Yellow
    
    # Remove scheduled task
    if (Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue) {
        Write-Host "Removing scheduled task..." -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false
    }
    
    # Remove installation directory
    if (Test-Path $InstallPath) {
        Write-Host "Removing installation directory..." -ForegroundColor Yellow
        Remove-Item -Path $InstallPath -Recurse -Force
    }
    
    # Remove data directories
    if (Test-Path "C:\FLARE-data") {
        Write-Host "Removing FLARE data directory (C:\FLARE-data)..." -ForegroundColor Yellow
        Remove-Item -Path "C:\FLARE-data" -Recurse -Force
    }
    
    Write-Host "`n✓ Agent uninstalled successfully!" -ForegroundColor Green
    exit 0
}

# Check if already installed
$existingTask = Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Host "`nAgent is already installed (Scheduled Task exists)!" -ForegroundColor Yellow
    Write-Host "To reinstall, first uninstall: .\install.ps1 -Uninstall" -ForegroundColor Yellow
    exit 1
}

# Create installation directory
Write-Host "`n[1/5] Creating installation directory..." -ForegroundColor Cyan
if (-not (Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    Write-Host "  ✓ Created: $InstallPath" -ForegroundColor Green
} else {
    Write-Host "  ✓ Directory already exists" -ForegroundColor Green
}

# Copy agent files
$currentDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "`n[2/5] Copying agent files..." -ForegroundColor Cyan
Copy-Item -Path "$currentDir\LogCollectionAgent.ps1" -Destination "$InstallPath\" -Force
Write-Host "  ✓ Agent files copied" -ForegroundColor Green

# Create data directories
Write-Host "`n[3/5] Creating data directories..." -ForegroundColor Cyan
$dataDirs = @("C:\FLARE-data\Data", "C:\FLARE-data\Logs")
foreach ($dir in $dataDirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "  ✓ Created: $dir" -ForegroundColor Green
    }
}

# Enable required audit policies
Write-Host "`n[4/5] Enabling audit policies..." -ForegroundColor Cyan
try {
    & auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>&1 | Out-Null
    & auditpol /set /subcategory:"Logoff" /success:enable /failure:enable 2>&1 | Out-Null
    & auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable 2>&1 | Out-Null
    Write-Host "  ✓ Audit policies configured" -ForegroundColor Green
} catch {
    Write-Host "  ℹ Skipping audit policy configuration" -ForegroundColor Yellow
}

# Create Windows Scheduled Task
Write-Host "`n[5/5] Creating Windows Scheduled Task ($ServiceName)..." -ForegroundColor Cyan
$taskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstallPath\LogCollectionAgent.ps1`" -Start"

# Run every 1 minute - using a daily trigger with 1-minute repetition
$taskTrigger = New-ScheduledTaskTrigger -Daily -At "12:00AM"
$taskTrigger.Repetition = (New-ScheduledTaskTrigger -Once -At "12:00AM" -RepetitionInterval (New-TimeSpan -Minutes 1)).Repetition

$taskSettings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable

# Run as SYSTEM for elevated privileges
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $ServiceName -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $principal -Description $ServiceDescription -Force | Out-Null

Write-Host "`n✓ Agent installed successfully!" -ForegroundColor Green
Write-Host "`nNEXT STEPS:" -ForegroundColor Yellow
Write-Host "1. Test the agent manually: " -NoNewline
Write-Host ".\LogCollectionAgent.ps1 -Start" -ForegroundColor White
Write-Host "2. The Scheduled Task will run automatically every 1 minute"
Write-Host "3. To uninstall: " -NoNewline
Write-Host ".\install.ps1 -Uninstall" -ForegroundColor White
Write-Host ""