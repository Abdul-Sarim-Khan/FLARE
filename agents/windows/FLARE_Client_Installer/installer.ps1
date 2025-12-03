#Requires -RunAsAdministrator
param(
    [switch]$Uninstall,
    [switch]$StartOnly
)

$InstallPath = "C:\Program Files\FLARE\Agent"
$currentDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# ==========================================
# START ONLY MODE (Requested Feature)
# ==========================================
if ($StartOnly) {
    Write-Host "Starting FLARE Services..." -ForegroundColor Cyan
    Start-ScheduledTask -TaskName "FLARE_Collector" -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName "FLARE_AI_Engine" -ErrorAction SilentlyContinue
    Write-Host "[SUCCESS] Services Triggered." -ForegroundColor Green
    exit
}

# ==========================================
# UNINSTALL MODE
# ==========================================
if ($Uninstall) {
    Write-Host "Uninstalling FLARE Agent..." -ForegroundColor Yellow

    # Stop & Remove Tasks
    Unregister-ScheduledTask -TaskName "FLARE_Collector" -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "FLARE_AI_Engine" -Confirm:$false -ErrorAction SilentlyContinue
    Stop-Process -Name "fl_client" -ErrorAction SilentlyContinue

    # Remove Firewall Rules
    Remove-NetFirewallRule -DisplayName "FLARE Client In" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "FLARE Client Out" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "FLARE Beacon In" -ErrorAction SilentlyContinue

    # Remove Files
    if (Test-Path $InstallPath) { Remove-Item -Path $InstallPath -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path "C:\FLARE-data") { Remove-Item -Path "C:\FLARE-data" -Recurse -Force -ErrorAction SilentlyContinue }

    Write-Host "[SUCCESS] Uninstalled." -ForegroundColor Green
    exit
}

# ==========================================
# INSTALL MODE
# ==========================================
Write-Host "Starting Installation..." -ForegroundColor Cyan

# 1. Create Directories
if (-not (Test-Path $InstallPath)) { New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null }
if (-not (Test-Path "C:\FLARE-data\Logs")) { New-Item -ItemType Directory -Path "C:\FLARE-data\Logs" -Force | Out-Null }
if (-not (Test-Path "C:\FLARE-data\Data")) { New-Item -ItemType Directory -Path "C:\FLARE-data\Data" -Force | Out-Null }

# 2. Copy Files
Copy-Item "$currentDir\LogCollectionAgent.ps1" "$InstallPath\" -Force
if (Test-Path "$currentDir\fl_client.exe") {
    Stop-Process -Name "fl_client" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Copy-Item "$currentDir\fl_client.exe" "$InstallPath\" -Force
}

# 3. Configure Firewall (CLIENT SIDE)
Write-Host "Configuring Client Firewall..." -ForegroundColor Cyan

# Allow Inbound UDP (To hear the beacon)
New-NetFirewallRule -DisplayName "FLARE Client In" `
    -Direction Inbound -Program "$InstallPath\fl_client.exe" `
    -Protocol UDP -LocalPort 37020 -Action Allow `
    -ErrorAction SilentlyContinue | Out-Null

# Allow Outbound TCP (To send data)
New-NetFirewallRule -DisplayName "FLARE Client Out" `
    -Direction Outbound -Program "$InstallPath\fl_client.exe" `
    -Action Allow -ErrorAction SilentlyContinue | Out-Null

& auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>&1 | Out-Null

# 4. Register Scheduled Tasks
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

$arg = "-NoProfile -WindowStyle Hidden -File `"$InstallPath\LogCollectionAgent.ps1`" -Start"
$a1 = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $arg
$t1 = New-ScheduledTaskTrigger -Once -At 12:00am -RepetitionInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "FLARE_Collector" -Action $a1 -Trigger $t1 -Settings $settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null

$a2 = New-ScheduledTaskAction -Execute "$InstallPath\fl_client.exe"
$t2 = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "FLARE_AI_Engine" -Action $a2 -Trigger $t2 -Settings $settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null

# 5. Start
Start-ScheduledTask -TaskName "FLARE_Collector"
Start-ScheduledTask -TaskName "FLARE_AI_Engine"

Write-Host "[SUCCESS] Installed. Agent is scanning for Master Node..." -ForegroundColor Green