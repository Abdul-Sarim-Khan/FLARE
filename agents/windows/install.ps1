#Requires -RunAsAdministrator
$InstallPath = "C:\Program Files\FLARE\Agent"

# 1. Folders
New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
New-Item -ItemType Directory -Path "C:\FLARE-data\Logs" -Force | Out-Null
New-Item -ItemType Directory -Path "C:\FLARE-data\Data" -Force | Out-Null

# 2. Files
$currentDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Copy-Item "$currentDir\LogCollectionAgent.ps1" "$InstallPath\" -Force
if (Test-Path "$currentDir\fl_client.exe") { Copy-Item "$currentDir\fl_client.exe" "$InstallPath\" -Force }

# 3. Security
New-NetFirewallRule -DisplayName "FLARE Client" -Direction Outbound -Program "$InstallPath\fl_client.exe" -Action Allow -ErrorAction SilentlyContinue | Out-Null
& auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>&1 | Out-Null

# 4. Tasks
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$a1 = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -File `"$InstallPath\LogCollectionAgent.ps1`" -Start"
$t1 = New-ScheduledTaskTrigger -Once -At 12:00am -RepetitionInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "FLARE_Collector" -Action $a1 -Trigger $t1 -Settings $settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null

$a2 = New-ScheduledTaskAction -Execute "$InstallPath\fl_client.exe"
$t2 = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "FLARE_AI_Engine" -Action $a2 -Trigger $t2 -Settings $settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null

Start-ScheduledTask -TaskName "FLARE_Collector"
Start-ScheduledTask -TaskName "FLARE_AI_Engine"
Write-Host "✓ Installed. Agent is scanning for Master Node..." -ForegroundColor Green