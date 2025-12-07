#Requires -RunAsAdministrator
param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$StartOnly
)

$InstallPath = "C:\Program Files\FLARE\Agent"
$currentDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# === START SERVICES ONLY ===
if ($StartOnly) {
    Start-ScheduledTask -TaskName "FLARE_Collector" -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName "FLARE_AI_Engine" -ErrorAction SilentlyContinue
    Write-Host "[SUCCESS] Services Started." -ForegroundColor Green
    exit
}

# === UNINSTALL MODE ===
if ($Uninstall) {
    Write-Host "Uninstalling FLARE Agent..." -ForegroundColor Yellow
    
    # 1. Remove Tasks
    Unregister-ScheduledTask -TaskName "FLARE_Collector" -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "FLARE_AI_Engine" -Confirm:$false -ErrorAction SilentlyContinue
    
    # 2. Stop Process
    Stop-Process -Name "fl_client" -ErrorAction SilentlyContinue
    
    # 3. Remove Firewall Rules
    Remove-NetFirewallRule -DisplayName "FLARE Client In" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "FLARE Client Out" -ErrorAction SilentlyContinue
    
    # 4. Remove Files
    if (Test-Path $InstallPath) { Remove-Item $InstallPath -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path "C:\FLARE-data") { Remove-Item "C:\FLARE-data" -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path "C:\Program Files\FLARE") { Remove-Item "C:\Program Files\FLARE" -Recurse -Force -ErrorAction SilentlyContinue }
    
    Write-Host "[SUCCESS] Uninstalled." -ForegroundColor Green
    exit
}

# === INSTALL MODE ===
if ($Install) {
    Write-Host "Installing FLARE Agent..." -ForegroundColor Cyan

    # 1. Create Directories
    if (-not (Test-Path $InstallPath)) { New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null }
    if (-not (Test-Path "C:\FLARE-data\Logs")) { New-Item -ItemType Directory -Path "C:\FLARE-data\Logs" -Force | Out-Null }
    if (-not (Test-Path "C:\FLARE-data\Data")) { New-Item -ItemType Directory -Path "C:\FLARE-data\Data" -Force | Out-Null }

    # 2. Copy Files
    Copy-Item "$currentDir\LogCollectionAgent.ps1" "$InstallPath\" -Force

    # Copy Python/Exe if exists
    if (Test-Path "$currentDir\fl_client.exe") {
        Stop-Process -Name "fl_client" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        Copy-Item "$currentDir\fl_client.exe" "$InstallPath\" -Force
    }

    # 3. Configure Firewall
    New-NetFirewallRule -DisplayName "FLARE Client In" -Direction Inbound -Protocol UDP -LocalPort 37020 -Action Allow -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "FLARE Client Out" -Direction Outbound -Program "$InstallPath\fl_client.exe" -Action Allow -ErrorAction SilentlyContinue | Out-Null

    # Enable Auditing
    & auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>&1 | Out-Null

    # 4. Register Tasks
    $arg = "-NoProfile -WindowStyle Hidden -File `"$InstallPath\LogCollectionAgent.ps1`" -Start"
    $a1 = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $arg
    $t1 = New-ScheduledTaskTrigger -Once -At 12:00am -RepetitionInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName "FLARE_Collector" -Action $a1 -Trigger $t1 -User "SYSTEM" -RunLevel Highest -Force | Out-Null

    $a2 = New-ScheduledTaskAction -Execute "$InstallPath\fl_client.exe"
    $t2 = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName "FLARE_AI_Engine" -Action $a2 -Trigger $t2 -User "SYSTEM" -RunLevel Highest -Force | Out-Null

    # 5. Start Services
    Start-ScheduledTask -TaskName "FLARE_Collector"
    Start-ScheduledTask -TaskName "FLARE_AI_Engine"
    
    Write-Host "[SUCCESS] Installed." -ForegroundColor Green
    exit
}

# === NO MODE SELECTED ===
Write-Host "Usage: .\install.ps1 -Install | -Uninstall | -StartOnly" -ForegroundColor Yellow