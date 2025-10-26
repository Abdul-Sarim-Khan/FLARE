# SIEM Agent Installation Script
# Installs and configures the log collection agent as a Windows service

#Requires -RunAsAdministrator

param(
    [string]$ServerEndpoint = "http://localhost:8000/api/logs/ingest",
    [string]$InstallPath = "C:\Program Files\SIEM\Agent",
    [switch]$Uninstall
)

$ServiceName = "SIEMLogAgent"
$ServiceDisplayName = "SIEM Log Collection Agent"
$ServiceDescription = "Collects security logs and sends to SIEM backend"

Write-Host "`n=== SIEM Agent Installation ===" -ForegroundColor Cyan

if ($Uninstall) {
    Write-Host "`nUninstalling agent..." -ForegroundColor Yellow
    
    # Stop service
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq 'Running') {
            Write-Host "Stopping service..." -ForegroundColor Yellow
            Stop-Service -Name $ServiceName -Force
        }
        
        Write-Host "Removing service..." -ForegroundColor Yellow
        sc.exe delete $ServiceName
    }
    
    # Remove installation directory
    if (Test-Path $InstallPath) {
        Write-Host "Removing installation directory..." -ForegroundColor Yellow
        Remove-Item -Path $InstallPath -Recurse -Force
    }
    
    # Remove data directories
    if (Test-Path "C:\SIEM") {
        Write-Host "Removing data directories..." -ForegroundColor Yellow
        Remove-Item -Path "C:\SIEM" -Recurse -Force
    }
    
    Write-Host "`n✓ Agent uninstalled successfully!" -ForegroundColor Green
    exit 0
}

# Check if already installed
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "`nAgent is already installed!" -ForegroundColor Yellow
    Write-Host "To reinstall, first uninstall: .\install.ps1 -Uninstall" -ForegroundColor Yellow
    exit 1
}

# Create installation directory
Write-Host "`n[1/6] Creating installation directory..." -ForegroundColor Cyan
if (-not (Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    Write-Host "  ✓ Created: $InstallPath" -ForegroundColor Green
} else {
    Write-Host "  ✓ Directory already exists" -ForegroundColor Green
}

# Copy agent files
Write-Host "`n[2/6] Copying agent files..." -ForegroundColor Cyan
$currentDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Copy-Item -Path "$currentDir\LogCollectionAgent.ps1" -Destination "$InstallPath\" -Force
Copy-Item -Path "$currentDir\config.json" -Destination "$InstallPath\" -Force
Write-Host "  ✓ Agent files copied" -ForegroundColor Green

# Update config with provided endpoint
Write-Host "`n[3/6] Configuring agent..." -ForegroundColor Cyan
$configPath = Join-Path $InstallPath "config.json"
$config = Get-Content $configPath -Raw | ConvertFrom-Json
$config.server.endpoint = $ServerEndpoint
$config | ConvertTo-Json -Depth 10 | Set-Content $configPath
Write-Host "  ✓ Server endpoint: $ServerEndpoint" -ForegroundColor Green

# Create data directories
Write-Host "`n[4/6] Creating data directories..." -ForegroundColor Cyan
$dataDirs = @("C:\SIEM\Queue", "C:\SIEM\Logs")
foreach ($dir in $dataDirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "  ✓ Created: $dir" -ForegroundColor Green
    }
}

# Enable required audit policies
Write-Host "`n[5/6] Enabling audit policies..." -ForegroundColor Cyan
try {
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Logoff" /success:enable | Out-Null
    auditpol /set /subcategory:"Account Lockout" /failure:enable | Out-Null
    auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Security Group Management" /success:enable | Out-Null
    Write-Host "  ✓ Audit policies enabled" -ForegroundColor Green
} catch {
    Write-Host "  ! Warning: Could not enable all audit policies" -ForegroundColor Yellow
}

# Create Windows service wrapper script
Write-Host "`n[6/6] Creating Windows service..." -ForegroundColor Cyan
$wrapperScript = @"
`$agentScript = Join-Path "$InstallPath" "LogCollectionAgent.ps1"
& `$agentScript -Start
"@
$wrapperPath = Join-Path $InstallPath "service_wrapper.ps1"
$wrapperScript | Out-File -FilePath $wrapperPath -Encoding UTF8 -Force

# Install as Windows service using NSSM (Non-Sucking Service Manager)
# Note: For production, you would install NSSM or use Task Scheduler
Write-Host "  Note: Service installation requires NSSM or Task Scheduler" -ForegroundColor Yellow
Write-Host "  For now, agent can be run manually or via Task Scheduler" -ForegroundColor Yellow

# Create a scheduled task instead
$taskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$InstallPath\LogCollectionAgent.ps1`" -Start"

$taskTrigger = New-ScheduledTaskTrigger -AtStartup

$taskSettings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoing