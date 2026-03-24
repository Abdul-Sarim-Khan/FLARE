#Requires -RunAsAdministrator
param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$StartOnly
)

$InstallPath = "C:\Program Files\FLARE\Agent"
$DataRoot    = "C:\FLARE-data"
$LogsDir     = "$DataRoot\Logs"
$DataDir     = "$DataRoot\Data"
$ModelDir    = "$DataRoot\model"
$currentDir  = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($StartOnly) {
    Start-ScheduledTask -TaskName "FLARE_Collector" -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName "FLARE_AI_Engine"  -ErrorAction SilentlyContinue
    Write-Host "Services started."
    exit
}

if ($Uninstall) {
    Write-Host "Uninstalling FLARE Agent..."
Write-Host "Disabling Windows Filtering Platform Auditing..." -ForegroundColor Yellow

# Disable success and failure auditing for network connections
auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:disable 2>$null

if ($LASTEXITCODE -eq 0) {
    Write-Host "Windows Filtering Platform Auditing Disabled Successfully."
} else {
    Write-Host "Failed to disable auditing (check for Admin privileges)." -ForegroundColor Red
}
    Unregister-ScheduledTask -TaskName "FLARE_Collector" -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "FLARE_AI_Engine"  -Confirm:$false -ErrorAction SilentlyContinue
    Stop-Process -Name "fl_client" -Force -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "FLARE Client In"  -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "FLARE Client Out" -ErrorAction SilentlyContinue
    if (Test-Path $InstallPath) { Remove-Item $InstallPath -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $DataRoot)    { Remove-Item $DataRoot    -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path "C:\Program Files\FLARE") { Remove-Item "C:\Program Files\FLARE" -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "Uninstalled."
    exit
}

if ($Install) {
    Write-Host "Installing FLARE Agent..."

    if (-not (Test-Path $InstallPath)) { New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null }
    if (-not (Test-Path $LogsDir))     { New-Item -ItemType Directory -Path $LogsDir     -Force | Out-Null }
    if (-not (Test-Path $DataDir))     { New-Item -ItemType Directory -Path $DataDir     -Force | Out-Null }
    if (-not (Test-Path $ModelDir))    { New-Item -ItemType Directory -Path $ModelDir    -Force | Out-Null }

    Write-Host "Directories created."

    if (Test-Path "$currentDir\LogCollectionAgent.ps1") {
        Copy-Item "$currentDir\LogCollectionAgent.ps1" "$InstallPath\" -Force
        Write-Host "Copied LogCollectionAgent.ps1"
    } else {
        Write-Host "WARNING: LogCollectionAgent.ps1 not found"
    }

    if (Test-Path "$currentDir\fl_client.exe") {
        Stop-Process -Name "fl_client" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        Copy-Item "$currentDir\fl_client.exe" "$InstallPath\" -Force
        Write-Host "Copied fl_client.exe"
    } else {
        Write-Host "WARNING: fl_client.exe not found"
    }

    if (Test-Path "$currentDir\global_model.pkl") {
        Copy-Item "$currentDir\global_model.pkl" "$ModelDir\" -Force
        Write-Host "Copied global_model.pkl"
    } else {
        Write-Host "INFO: global_model.pkl not found - client runs in rule-only mode"
    }


Write-Host "Enabling Windows Filtering Platform Auditing..."

auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable 2>$null

if ($LASTEXITCODE -eq 0) {
    Write-Host "Windows Filtering Platform Enabled Successfully."
} else {
    Write-Host "Failed to enable Windows Filtering Platform Auditing." -ForegroundColor Red
}


    New-NetFirewallRule -DisplayName "FLARE Client In"  -Direction Inbound  -Protocol UDP -LocalPort 37020 -Action Allow -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "FLARE Client Out" -Direction Outbound -Program "$InstallPath\fl_client.exe" -Action Allow -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Firewall rules added."

    auditpol /set /category:"Logon/Logoff"          /success:enable /failure:enable 2>$null | Out-Null
    auditpol /set /category:"Detailed Tracking"     /success:enable /failure:enable 2>$null | Out-Null
    auditpol /set /category:"Privilege Use"         /success:enable /failure:enable 2>$null | Out-Null
    auditpol /set /category:"Account Management"    /success:enable /failure:enable 2>$null | Out-Null
    Write-Host "Audit policies enabled."

    $collectorArg = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallPath\LogCollectionAgent.ps1`""
    $a1 = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $collectorArg
    $t1 = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName "FLARE_Collector" -Action $a1 -Trigger $t1 -User "SYSTEM" -RunLevel Highest -Force | Out-Null
    Write-Host "Registered FLARE_Collector task."

    $a2 = New-ScheduledTaskAction -Execute "$InstallPath\fl_client.exe"
    $t2 = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName "FLARE_AI_Engine" -Action $a2 -Trigger $t2 -User "SYSTEM" -RunLevel Highest -Force | Out-Null
    Write-Host "Registered FLARE_AI_Engine task."

    Start-ScheduledTask -TaskName "FLARE_Collector" -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName "FLARE_AI_Engine"  -ErrorAction SilentlyContinue
    Write-Host "Services started."

    Write-Host ""
    Write-Host "Install complete."
    Write-Host "Install path : $InstallPath"
    Write-Host "Logs         : $LogsDir"
    Write-Host "Model        : $ModelDir"
    Write-Host ""
    Write-Host "To check logs run:"
    Write-Host "Get-Content C:\FLARE-data\Logs\agent_debug.log -Tail 20"
    exit
}

Write-Host "Usage: .\installer.ps1 -Install | -Uninstall | -StartOnly"
