# ========================================================
# FLARE Enterprise Auto-Installer
# 1. Sets up the Log Collector (Periodic Task)
# 2. Sets up the AI Brain (Always-Running Service)
# ========================================================
#Requires -RunAsAdministrator

param(
    [string]$InstallPath = "C:\Program Files\FLARE\Agent",
    [switch]$Uninstall
)

$CollectorTask = "FLARE_Collector"
$AITask = "FLARE_AI_Engine"

Write-Host "`n=== FLARE Deployment Wizard ===" -ForegroundColor Cyan

# --- UNINSTALL LOGIC ---
if ($Uninstall) {
    Write-Host "Uninstalling..." -ForegroundColor Yellow
    
    # 1. Remove Tasks
    Unregister-ScheduledTask -TaskName $CollectorTask -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $AITask -Confirm:$false -ErrorAction SilentlyContinue
    
    # 2. Stop Processes
    Stop-Process -Name "fl_client" -ErrorAction SilentlyContinue
    
    # 3. Delete Files
    Remove-Item -Path $InstallPath -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\FLARE-data" -Recurse -Force -ErrorAction SilentlyContinue
    
    Write-Host "✓ Cleanup Complete." -ForegroundColor Green
    exit 0
}

# --- INSTALL LOGIC ---

# 1. Create Directory Structure
New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
New-Item -ItemType Directory -Path "C:\FLARE-data\Logs" -Force | Out-Null
New-Item -ItemType Directory -Path "C:\FLARE-data\Data" -Force | Out-Null

# 2. Deploy Files
$currentDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "Deploying Agents..." -ForegroundColor Cyan

# Copy Script
Copy-Item "$currentDir\LogCollectionAgent.ps1" "$InstallPath\" -Force

# Copy EXE (Critical Check)
if (Test-Path "$currentDir\fl_client.exe") {
    Copy-Item "$currentDir\fl_client.exe" "$InstallPath\" -Force
    Write-Host "  ✓ AI Engine (fl_client.exe) Found & Deployed" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  CRITICAL WARNING: fl_client.exe is missing!" -ForegroundColor Red
    Write-Host "      You must compile the Python script before running this installer."
}

# 3. Configure Windows Audit Policy
# (We need this or Windows won't generate Event 4624/4625)
Write-Host "Configuring Audit Policies..." -ForegroundColor Cyan
& auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>&1 | Out-Null

# 4. Task 1: The Log Collector
# Runs every 1 minute to ensure fresh data
$actionCollect = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -File `"$InstallPath\LogCollectionAgent.ps1`" -Start"
$triggerCollect = New-ScheduledTaskTrigger -Once -At 12:00am -RepetitionInterval (New-TimeSpan -Minutes 1)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $CollectorTask -Action $actionCollect -Trigger $triggerCollect -Settings $settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null

# 5. Task 2: The AI Brain
# Runs at Startup and stays running (listening for file changes)
$actionAI = New-ScheduledTaskAction -Execute "$InstallPath\fl_client.exe"
$triggerAI = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName $AITask -Action $actionAI -Trigger $triggerAI -Settings $settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null

# 6. Start Everything Now
Start-ScheduledTask -TaskName $CollectorTask
Start-ScheduledTask -TaskName $AITask

Write-Host "`n✓ FLARE System Successfully Deployed." -ForegroundColor Green
Write-Host "  1. Collector is active (Interval: 1 min)"
Write-Host "  2. AI Engine is active (Mode: Watchdog)"