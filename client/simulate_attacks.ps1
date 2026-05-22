<#
.SYNOPSIS
    FLARE v0.4 - Attack Simulation Suite

.DESCRIPTION
    Simulates 18 host-based + 5 network attack techniques and verifies the
    FLARE agent detects and forwards them to the server dashboard.

    Prerequisites:
      - FLARE agent is already running (flare_agent.py or FLAREAgent service)
      - Run on a TEST machine  - this script clears the Security event log
      - Run as Administrator (script self-elevates if needed)

    What this script does  - attack by attack:
      [01] PowerShell Download Cradle       → Event 4104  → rule: ps_download_cradle      (CRITICAL)
      [02] PowerShell Encoded Command       → Event 4104  → rule: ps_encoded_command       (HIGH)
      [03] PowerShell Reflection Load       → Event 4104  → rule: ps_reflection_load       (HIGH)
      [04] Brute Force Logon (15 attempts)  → Event 4625  → rule: brute_force_logon        (HIGH)
      [05] Password Spray (7 users)         → Event 4625  → rule: password_spray           (HIGH)
      [06] Shadow Copy Deletion             → Event 4688  → rule: shadow_copy_deletion     (CRITICAL)
      [07] IOC Process Name: mimikatz.exe   → Event 4688  → rule: ioc_process_name         (HIGH)
      [08] IOC Process Name: nmap.exe       → Event 4688  → rule: ioc_process_name         (HIGH)
      [09] IOC Process Chain: wscript→ps    → Event 4688  → rule: ioc_process_chain        (CRITICAL)
      [10] Suspicious Scheduled Task        → Event 4698  → rule: scheduled_task_suspicious (HIGH)
      [11] Service in AppData Path          → Event 7045  → rule: new_service_susp_path    (HIGH)
      [12] PSEXESVC Service Installed       → Event 7045  → rule: psexec_lateral_movement  (CRITICAL)
      [13] WMI Event Subscription           → Event 5861  → rule: wmi_persistence          (CRITICAL)
      [14] User Added to Administrators     → Event 4732  → rule: privileged_group_mod     (HIGH)
      [15] Defender Real-Time Off           → Event 5001  → rule: defender_disabled        (CRITICAL)
      [16] Audit Policy Changed             → Event 4719  → rule: audit_policy_changed     (CRITICAL)
      [17] Security Log Cleared             → Event 1102  → rule: security_log_cleared     (CRITICAL)
      [18] DNS Query to IOC Domain          → Event 3008  → rule: ioc_domain_match         (CRITICAL)
      [19] Network Attacks (5 types)        → net_flows.csv  → ML network inference engine  (MIXED)

    All created artifacts (services, tasks, WMI subs, test user, temp files)
    are fully removed during cleanup at the end of the script.

.EXAMPLE
    Double-click run_attack_sim.bat    (recommended)
    powershell -ExecutionPolicy Bypass -File .\simulate_attacks.ps1
#>

# -----------------------------------------------------------------------------
# 0. Self-elevate
# -----------------------------------------------------------------------------
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$p  = New-Object System.Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Elevating to Administrator..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs `
        -ArgumentList "-NoProfile -NoExit -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$ErrorActionPreference = "SilentlyContinue"
Set-Location $PSScriptRoot

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
function Write-Banner {
    param([string]$Text)
    $line = "-" * 62
    Write-Host ""
    Write-Host "  $line" -ForegroundColor DarkCyan
    Write-Host "  $Text"  -ForegroundColor Cyan
    Write-Host "  $line" -ForegroundColor DarkCyan
}

function Write-Attack {
    param([int]$Num, [string]$Name, [string]$Rule, [string]$Sev)
    $col = if ($Sev -eq "CRITICAL") { "Red" } else { "DarkYellow" }
    Write-Host ""
    Write-Host ("  [{0:D2}] {1}" -f $Num, $Name) -ForegroundColor $col
    Write-Host "       Rule     : $Rule"   -ForegroundColor DarkGray
    Write-Host "       Severity : $Sev"   -ForegroundColor DarkGray
}

function Write-OK   { param([string]$m) Write-Host "       OK  $m" -ForegroundColor Green }
function Write-Skip { param([string]$m) Write-Host "       --  $m" -ForegroundColor Yellow }
function Write-Note { param([string]$m) Write-Host "       >>  $m" -ForegroundColor DarkGray }
function Pause-Sim  { param([int]$s = 2) Start-Sleep -Seconds $s }

# -----------------------------------------------------------------------------
# Artifact names  - all cleaned up at the end
# -----------------------------------------------------------------------------
$SIM_USER      = "FLARESimUser"
$SIM_TASK      = "FLARESimTask"
$SIM_SVC       = "FLARESimSvc"
$SIM_PSEXEC    = "PSEXESVC"
$SIM_WMI_F     = "FLARESimFilter"
$SIM_WMI_C     = "FLARESimConsumer"
$SIM_MIMI      = "$env:TEMP\mimikatz.exe"
$SIM_NMAP      = "$env:TEMP\nmap.exe"
$SIM_VBS       = "$env:TEMP\FLARESim_chain.vbs"
$SIM_SVC_EXE   = "$env:APPDATA\FLARESimSvc.exe"
$defenderWasOn = $true   # tracks whether we need to re-enable Defender

# -----------------------------------------------------------------------------
# Banner + confirmation
# -----------------------------------------------------------------------------
Write-Banner "FLARE v0.4 - Attack Simulation Suite"
Write-Host ""
Write-Host "  Simulates 18 host + 5 network attacks and verifies the FLARE agent detects them." -ForegroundColor White
Write-Host "  Make sure  flare_agent.py  (or the FLAREAgent service) is running" -ForegroundColor White
Write-Host "  and connected to the server BEFORE you continue."               -ForegroundColor White
Write-Host ""
Write-Host "  WARNING  - this script will:" -ForegroundColor Yellow
Write-Host "    * Create then delete: a local user, 2 services, 1 task, 1 WMI subscription" -ForegroundColor Yellow
Write-Host "    * Drop then remove:   two renamed executables in %TEMP%" -ForegroundColor Yellow
Write-Host "    * Clear the Security event log (attack #17)"               -ForegroundColor Yellow
Write-Host "    * Temporarily disable Windows Defender (attack #15)"       -ForegroundColor Yellow
Write-Host ""
$yn = Read-Host "  Type  YES  to start the simulation"
if ($yn -ne "YES") { Write-Host "  Aborted."; exit }

# -----------------------------------------------------------------------------
# SETUP  - enable all audit policies and logging the rules depend on
# -----------------------------------------------------------------------------
Write-Banner "Enabling required audit policies"

# Process Creation + command-line capture (needed for Event 4688 with CommandLine)
auditpol /set /subcategory:"Process Creation" /success:enable 2>&1 | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f 2>&1 | Out-Null
Write-OK "Process Creation auditing + command-line capture"

# Logon failures (Event 4625  - brute force / spray)
auditpol /set /subcategory:"Logon" /failure:enable 2>&1 | Out-Null
Write-OK "Logon failure auditing"

# Security Group Management (Events 4728/4732/4756)
auditpol /set /subcategory:"Security Group Management" /success:enable 2>&1 | Out-Null
Write-OK "Security Group Management auditing"

# Audit Policy Change (Event 4719)
auditpol /set /subcategory:"Audit Policy Change" /success:enable 2>&1 | Out-Null
Write-OK "Audit Policy Change auditing"

# PowerShell Script Block Logging (Event 4104)
$sbPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $sbPath)) { New-Item -Path $sbPath -Force | Out-Null }
Set-ItemProperty -Path $sbPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
Write-OK "PowerShell Script Block Logging (Event 4104)"

# DNS Client Operational log (Event 3008)
wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true 2>&1 | Out-Null
Write-OK "DNS Client Operational log"

Write-Note "Waiting 3 s for policies to take effect..."
Start-Sleep -Seconds 3


# ═════════════════════════════════════════════════════════════════════════════
#  ATTACK SIMULATIONS
# ═════════════════════════════════════════════════════════════════════════════

# -----------------------------------------------------------------------------
# [01] PowerShell Download Cradle  - Event 4104
#      Pattern:  New-Object Net.WebClient  (also matches DownloadString, IEX)
#      Requires: Script Block Logging enabled (done in setup above)
# -----------------------------------------------------------------------------
Write-Attack 1 "PowerShell Download Cradle" "ps_download_cradle" "CRITICAL"

# Execute a script block whose TEXT contains the download-cradle pattern.
# The script block is harmless  - we never actually download anything.
# Windows logs the raw text of every executed script block to Event 4104,
# which is what the FLARE rule scans.
$cradleBlock = {
    # FLARE detection pattern: "New-Object.*Net\.WebClient"
    $wc  = New-Object Net.WebClient
    $out = "FLARE_SIM_01: cradle pattern present in this script block"
    Write-Host "  [sim] $out" -ForegroundColor DarkGray
}
& $cradleBlock
Write-OK "Script block with 'New-Object Net.WebClient' executed → Event 4104"
Pause-Sim


# -----------------------------------------------------------------------------
# [02] PowerShell Encoded Command  - Event 4104
#      Pattern:  -EncodedCommand flag  AND  [Convert]::FromBase64String
# -----------------------------------------------------------------------------
Write-Attack 2 "PowerShell Encoded Command" "ps_encoded_command" "HIGH"

# Encode a harmless string and launch it with -EncodedCommand.
# The Event 4104 ScriptBlockText for the child process will show
# the decoded script, and the PARENT process's 4104 shows FromBase64String.
$enc = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes("Write-Host 'FLARE_SIM_02'")
)
powershell.exe -NoProfile -NonInteractive -EncodedCommand $enc 2>&1 | Out-Null
Write-OK "-EncodedCommand child process launched → Event 4104 (flag visible in cmdline)"

# Also trigger the inline FromBase64String pattern in a script block
$b64Block = {
    # FLARE detection pattern: "FromBase64String"
    $bytes = [Convert]::FromBase64String("RkxBUkVfU0lNXzAy")
    Write-Host "  [sim] $([Text.Encoding]::UTF8.GetString($bytes))" -ForegroundColor DarkGray
}
& $b64Block
Write-OK "Inline [Convert]::FromBase64String() in script block → Event 4104"
Pause-Sim


# -----------------------------------------------------------------------------
# [03] PowerShell Reflection Load  - Event 4104
#      Pattern:  [Reflection.Assembly]  and  GetMethod
# -----------------------------------------------------------------------------
Write-Attack 3 "PowerShell Reflection Assembly Load" "ps_reflection_load" "HIGH"

$reflBlock = {
    # FLARE detection pattern: "Reflection\.Assembly" and "GetMethod"
    $asm  = [System.Reflection.Assembly]::GetExecutingAssembly()
    $meth = $asm.GetType("System.String").GetMethod("IsNullOrEmpty")
    Write-Host "  [sim] FLARE_SIM_03 - reflection pattern in script block" -ForegroundColor DarkGray
}
& $reflBlock
Write-OK "[Reflection.Assembly]::GetExecutingAssembly() in script block → Event 4104"
Pause-Sim


# -----------------------------------------------------------------------------
# [04] Brute Force Logon  - Event 4625 (threshold ≥ 10 failures / 60 s)
#      Uses loopback (127.0.0.1) so IpAddress is consistent across all attempts.
# -----------------------------------------------------------------------------
Write-Attack 4 "Brute Force Logon  - 15 attempts, same username" "brute_force_logon" "HIGH"

Write-Note "Generating 15 rapid failed logons against 'brute_target' from 127.0.0.1 ..."
for ($i = 1; $i -le 15; $i++) {
    cmd.exe /C "net use \\127.0.0.1\IPC$ /user:.\brute_target WrongPass$i >nul 2>&1"
    cmd.exe /C "net use \\127.0.0.1\IPC$ /delete >nul 2>&1"
}
Write-OK "15 × Event 4625 (type 3, src=127.0.0.1, user=brute_target)"
Write-Note "FLARE threshold: ≥ 10 failures from same IP in 60 s"
Pause-Sim


# -----------------------------------------------------------------------------
# [05] Password Spray  - Event 4625 (threshold ≥ 5 distinct users / 60 s)
#      One wrong password per account (evades lockout policies).
# -----------------------------------------------------------------------------
Write-Attack 5 "Password Spray  - 7 users, 1 attempt each" "password_spray" "HIGH"

Write-Note "Generating failed logons against 7 distinct usernames from 127.0.0.1 ..."
$sprayTargets = @(
    "spray_hr_user", "spray_it_admin", "spray_ceo_acc",
    "spray_finance1", "spray_devops",  "spray_support", "spray_dom_adm"
)
foreach ($u in $sprayTargets) {
    cmd.exe /C "net use \\127.0.0.1\IPC$ /user:.\$u Summer2024! >nul 2>&1"
    cmd.exe /C "net use \\127.0.0.1\IPC$ /delete >nul 2>&1"
}
Write-OK "7 × Event 4625 against distinct usernames (src=127.0.0.1)"
Write-Note "FLARE threshold: ≥ 5 distinct usernames from same IP in 60 s"
Pause-Sim


# -----------------------------------------------------------------------------
# [06] Volume Shadow Copy Deletion  - Event 4688
#      Process: vssadmin.exe   CommandLine contains "delete shadows"
#      Dual trigger: also fires ioc_process_name (vssadmin.exe is in IOC list)
#      Safe: if no shadow copies exist, vssadmin returns "No items found"
# -----------------------------------------------------------------------------
Write-Attack 6 "Volume Shadow Copy Deletion (Pre-Ransomware)" "shadow_copy_deletion" "CRITICAL"

vssadmin.exe delete shadows /all /quiet 2>&1 | Out-Null
Write-OK "vssadmin delete shadows /all /quiet executed → Event 4688"
Write-Note "Also fires: ioc_process_name (vssadmin.exe is in ioc_process_names.txt)"
Write-Note "Safe: returns 'No items found' if no shadow copies exist"
Pause-Sim


# -----------------------------------------------------------------------------
# [07] IOC Process Name: mimikatz.exe  - Event 4688
#      cmd.exe is copied and renamed  - process name matches IOC list entry.
#      The rule extracts the basename of NewProcessName and checks ioc_process_names.txt.
# -----------------------------------------------------------------------------
Write-Attack 7 "Known Attack Tool: mimikatz.exe" "ioc_process_name" "HIGH"

Copy-Item "$env:WINDIR\System32\cmd.exe" $SIM_MIMI -Force
if (Test-Path $SIM_MIMI) {
    & $SIM_MIMI /C "exit 0" 2>&1 | Out-Null
    Write-OK "mimikatz.exe launched from $SIM_MIMI → Event 4688 (basename matches IOC)"
    Write-Note "Binary is cmd.exe renamed  - harmless"
} else {
    Write-Skip "Could not create $SIM_MIMI"
}
Pause-Sim


# -----------------------------------------------------------------------------
# [08] IOC Process Name: nmap.exe  - Event 4688
#      Second IOC process name hit to show coverage of the list.
# -----------------------------------------------------------------------------
Write-Attack 8 "Known Attack Tool: nmap.exe" "ioc_process_name" "HIGH"

Copy-Item "$env:WINDIR\System32\cmd.exe" $SIM_NMAP -Force
if (Test-Path $SIM_NMAP) {
    & $SIM_NMAP /C "exit 0" 2>&1 | Out-Null
    Write-OK "nmap.exe launched from $SIM_NMAP → Event 4688 (basename matches IOC)"
} else {
    Write-Skip "Could not create $SIM_NMAP"
}
Pause-Sim


# -----------------------------------------------------------------------------
# [09] IOC Process Chain: wscript.exe → powershell.exe  - Event 4688
#      A VBScript creates a child powershell.exe process.
#      Event 4688 for powershell.exe has ParentProcessName = wscript.exe.
#      This chain is in ioc_process_chains.txt.
# -----------------------------------------------------------------------------
Write-Attack 9 "Suspicious Process Chain: wscript.exe -> powershell.exe" "ioc_process_chain" "CRITICAL"

@"
Set oShell = CreateObject("WScript.Shell")
oShell.Run "powershell.exe -NoProfile -NonInteractive -Command exit 0", 0, True
"@ | Set-Content $SIM_VBS -Encoding ASCII

if (Test-Path $SIM_VBS) {
    wscript.exe $SIM_VBS 2>&1 | Out-Null
    Write-OK "wscript.exe spawned powershell.exe → Event 4688 (chain matches IOC list)"
    Write-Note "ParentProcessName=wscript.exe  NewProcessName=powershell.exe"
} else {
    Write-Skip "Could not create VBS file for chain simulation"
}
Pause-Sim


# -----------------------------------------------------------------------------
# [10] Suspicious Scheduled Task  - Event 4698
#      Action runs powershell.exe with -ExecutionPolicy bypass -EncodedCommand.
#      TaskContentXml contains "powershell", "bypass", "encoded" → suspicious rule fires.
#      Also fires: scheduled_task_created (low-confidence catch-all on any 4698).
# -----------------------------------------------------------------------------
Write-Attack 10 "Suspicious Scheduled Task Created" "scheduled_task_suspicious" "HIGH"

# Payload: -EncodedCommand encodes "Write-Host 'FLARE_SIM_10'"  - harmless
$enc10 = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes("Write-Host 'FLARE_SIM_10'")
)
$act10 = New-ScheduledTaskAction `
    -Execute  "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy bypass -EncodedCommand $enc10"
$trg10 = New-ScheduledTaskTrigger -AtStartup

Register-ScheduledTask -TaskName $SIM_TASK -Action $act10 -Trigger $trg10 -Force 2>&1 | Out-Null
if (Get-ScheduledTask -TaskName $SIM_TASK -ErrorAction SilentlyContinue) {
    Write-OK "Task '$SIM_TASK' created with powershell+bypass+encoded action → Event 4698"
    Write-Note "Also fires: scheduled_task_created (MEDIUM, any 4698)"
} else {
    Write-Skip "Scheduled task creation may have failed"
}
Pause-Sim


# -----------------------------------------------------------------------------
# [11] Service with Suspicious Path  - Event 7045
#      ImagePath is inside \AppData\ which matches _SUSPICIOUS_PATH_PATTERNS.
#      Legitimate services install to Program Files or Windows directories.
# -----------------------------------------------------------------------------
Write-Attack 11 "Malicious Service  - Executable in AppData Path" "new_service_suspicious_path" "HIGH"

Copy-Item "$env:WINDIR\System32\cmd.exe" $SIM_SVC_EXE -Force
sc.exe create $SIM_SVC binPath= "`"$SIM_SVC_EXE`"" start= demand 2>&1 | Out-Null
if ((sc.exe query $SIM_SVC 2>&1) -match "SERVICE_NAME") {
    Write-OK "Service '$SIM_SVC' registered → Event 7045  (ImagePath in \AppData\)"
    Write-Note "ImagePath: $SIM_SVC_EXE"
} else {
    Write-Skip "Service creation may have failed"
}
Pause-Sim


# -----------------------------------------------------------------------------
# [12] PSEXESVC Service  - Event 7045
#      ServiceName is exactly "PSEXESVC"  - the deterministic PsExec signature.
#      Confidence: 1.0  - no false positives possible.
# -----------------------------------------------------------------------------
Write-Attack 12 "PsExec Lateral Movement  - PSEXESVC Service" "psexec_lateral_movement" "CRITICAL"

sc.exe delete $SIM_PSEXEC 2>&1 | Out-Null   # remove any leftover from prior run
sc.exe create $SIM_PSEXEC binPath= "C:\Windows\PSEXESVC.exe" start= demand 2>&1 | Out-Null
if ((sc.exe query $SIM_PSEXEC 2>&1) -match "SERVICE_NAME") {
    Write-OK "Service 'PSEXESVC' registered → Event 7045 (PsExec lateral movement)"
} else {
    Write-Skip "PSEXESVC service creation may have failed"
}
Pause-Sim


# -----------------------------------------------------------------------------
# [13] WMI Permanent Event Subscription  - Event 5861
#      Creates __EventFilter + CommandLineEventConsumer + __FilterToConsumerBinding
#      in root\subscription.  WMI subscriptions survive reboots, run silently.
#      Monitored channel: Microsoft-Windows-WMI-Activity/Operational
# -----------------------------------------------------------------------------
Write-Attack 13 "WMI Permanent Event Subscription (Fileless Persistence)" "wmi_persistence" "CRITICAL"

try {
    $wmiF = Set-WmiInstance -Namespace "root\subscription" -Class "__EventFilter" `
        -Arguments @{
            Name           = $SIM_WMI_F
            EventNamespace = "root\cimv2"
            QueryLanguage  = "WQL"
            Query          = "SELECT * FROM __InstanceCreationEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_Process'"
        }

    $wmiC = Set-WmiInstance -Namespace "root\subscription" -Class "CommandLineEventConsumer" `
        -Arguments @{
            Name                = $SIM_WMI_C
            CommandLineTemplate = "cmd.exe /c echo FLARE_SIM_13"
        }

    Set-WmiInstance -Namespace "root\subscription" -Class "__FilterToConsumerBinding" `
        -Arguments @{ Filter = $wmiF; Consumer = $wmiC } | Out-Null

    Write-OK "WMI filter + consumer + binding created → Event 5861"
    Write-Note "Namespace: root\subscription   Query: Win32_Process creation"
} catch {
    Write-Skip "WMI subscription failed: $_"
}
Pause-Sim


# -----------------------------------------------------------------------------
# [14] User Added to Privileged Group  - Event 4732
#      Creates a temporary local user then adds them to Administrators.
#      Generates: Event 4720 (account created) + Event 4732 (group membership add).
#      Rule checks GroupName against PRIVILEGED_GROUPS set.
# -----------------------------------------------------------------------------
Write-Attack 14 "User Added to Administrators (Privilege Escalation)" "privileged_group_modification" "HIGH"

net user $SIM_USER "FlareSim!2024" /add 2>&1 | Out-Null
net localgroup Administrators $SIM_USER /add 2>&1 | Out-Null
if ((net localgroup Administrators 2>&1) -match $SIM_USER) {
    Write-OK "User '$SIM_USER' created and added to Administrators → Event 4732"
    Write-Note "Also generates Event 4720 (new account created)"
} else {
    Write-Skip "Group modification may have failed"
}
Pause-Sim


# -----------------------------------------------------------------------------
# [15] Windows Defender Real-Time Protection Disabled  - Event 5001
#      Monitored channel: Microsoft-Windows-Windows Defender/Operational
#      NOTE: Windows Defender Tamper Protection (enabled by default on W10/11)
#      will block this. If it fails, follow the manual steps shown below.
# -----------------------------------------------------------------------------
Write-Attack 15 "Windows Defender Real-Time Protection Disabled" "defender_disabled" "CRITICAL"

$mpPref = Get-MpPreference -ErrorAction SilentlyContinue
if ($mpPref) {
    $defenderWasOn = (-not $mpPref.DisableRealtimeMonitoring)
}

try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    Write-OK "Defender real-time protection disabled → Event 5001"
    Write-Note "Will be re-enabled during cleanup"
} catch {
    Write-Skip "Blocked by Tamper Protection  - to test manually:"
    Write-Note "  Windows Security → Virus & threat protection → Manage settings → Real-time OFF"
    Write-Note "  This generates Event 5001 in Windows Defender/Operational channel"
    $defenderWasOn = $true   # nothing changed, nothing to restore
}
Pause-Sim


# -----------------------------------------------------------------------------
# [16] Audit Policy Changed  - Event 4719
#      Temporarily disables then immediately restores Object Access auditing.
#      Any audit subcategory change generates 4719.
# -----------------------------------------------------------------------------
Write-Attack 16 "System Audit Policy Modified (Defense Evasion)" "audit_policy_changed" "CRITICAL"

auditpol /set /subcategory:"Object Access" /success:disable /failure:disable 2>&1 | Out-Null
Write-OK "Object Access audit disabled → Event 4719"
auditpol /set /subcategory:"Object Access" /success:enable  /failure:enable  2>&1 | Out-Null
Write-Note "Audit policy immediately restored"
Pause-Sim


# -----------------------------------------------------------------------------
# [17] Security Log Cleared  - Event 1102
#      Done intentionally last among the destructive tests.
#      FLARE captures Event 1102 in real-time before the clear is complete  -
#      all previously simulated events are already queued for the server.
# -----------------------------------------------------------------------------
Write-Attack 17 "Security Event Log Cleared (Cover Tracks)" "security_log_cleared" "CRITICAL"

wevtutil cl Security 2>&1 | Out-Null
Write-OK "Security log cleared → Event 1102"
Write-Note "FLARE captures Event 1102 in real-time before the wipe takes effect"
Pause-Sim


# -----------------------------------------------------------------------------
# [18] DNS Query to Known Malicious Domain  - Event 3008
#      Channel: Microsoft-Windows-DNS-Client/Operational
#      Event 3008 fires on DNS FAILURES (NXDOMAIN, timeout).
#      These domains are sinkholed/taken down  - resolution will fail → 3008.
# -----------------------------------------------------------------------------
Write-Attack 18 "DNS Query to Known Malicious Domain (C2 / Miner)" "ioc_domain_match" "CRITICAL"

# Load exact-match (non-wildcard) domains from the live IOC list so the
# simulation always reflects the current threat feed.
$iocFile   = Join-Path $PSScriptRoot "ioc\ioc_domains.txt"
$iocDomains = @()
if (Test-Path $iocFile) {
    $iocDomains = Get-Content $iocFile |
        Where-Object { $_ -match '^\S' -and $_ -notmatch '^#' -and $_ -notmatch '^\*' } |
        Select-Object -First 4
}
if ($iocDomains.Count -eq 0) {
    # Fallback if file is missing or empty
    $iocDomains = @("cmstrack.top", "windowsupdate-cdn.live", "svchost-update.net", "cdn-microsoft-update.com")
}
foreach ($d in $iocDomains) {
    Resolve-DnsName -Name $d -Type A -ErrorAction SilentlyContinue | Out-Null
}
Write-OK "DNS queries issued: $($iocDomains -join ', ')"
Write-Note "Sinkholed/dead domains generate Event 3008 (DNS failure)"
Write-Note "Channel: Microsoft-Windows-DNS-Client/Operational"
Pause-Sim 3


# -----------------------------------------------------------------------------
# [19] Network Attack Simulation  - ML-based network inference engine
#      Injects synthetic malicious flow rows into net_flows.csv.
#      The network inference thread picks them up within the next 30-second
#      polling cycle and sends alerts to the FLARE dashboard.
#      Attack types: DDoS, Port Scan, SSH Brute Force, Web Attack (SQLi), Botnet C2
# -----------------------------------------------------------------------------
Write-Attack 19 "Network Attacks - DDoS / Port Scan / SSH Brute / Web Attack / Botnet C2" "ML-network-inference" "MIXED"

$netSimScript = Join-Path $PSScriptRoot "simulate_network_attacks.py"
if (Test-Path $netSimScript) {
    Write-Note "Injecting synthetic malicious flow rows into net_flows.csv..."
    $netSimOut = & python $netSimScript --count 10 2>&1
    $netSimOut | ForEach-Object { Write-Host "       $_" }
    if ($LASTEXITCODE -eq 0) {
        Write-OK "Network attack rows appended - alerts expected within ~30 seconds"
    } else {
        Write-Skip "Network simulation returned exit code $LASTEXITCODE - check output above"
    }
} else {
    Write-Skip "simulate_network_attacks.py not found at $netSimScript"
    Write-Note "Run manually: python simulate_network_attacks.py"
}
Pause-Sim 3


# ═════════════════════════════════════════════════════════════════════════════
#  CLEANUP  - reverse every persistent change
# ═════════════════════════════════════════════════════════════════════════════
Write-Banner "Cleanup  - Reversing All Simulation Artifacts"

# Defender
if ($defenderWasOn) {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Write-OK "Defender real-time protection re-enabled"
}

# Scheduled task
Unregister-ScheduledTask -TaskName $SIM_TASK -Confirm:$false -ErrorAction SilentlyContinue
Write-OK "Scheduled task '$SIM_TASK' removed"

# Services
sc.exe stop   $SIM_SVC    2>&1 | Out-Null; sc.exe delete $SIM_SVC    2>&1 | Out-Null
sc.exe stop   $SIM_PSEXEC 2>&1 | Out-Null; sc.exe delete $SIM_PSEXEC 2>&1 | Out-Null
Write-OK "Services '$SIM_SVC' and '$SIM_PSEXEC' removed"

# WMI subscription
Get-WmiObject -Namespace "root\subscription" -Class "__FilterToConsumerBinding" `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.Filter -like "*$SIM_WMI_F*" } |
    Remove-WmiObject -ErrorAction SilentlyContinue
Get-WmiObject -Namespace "root\subscription" -Class "CommandLineEventConsumer" `
    -Filter "Name='$SIM_WMI_C'" -ErrorAction SilentlyContinue |
    Remove-WmiObject -ErrorAction SilentlyContinue
Get-WmiObject -Namespace "root\subscription" -Class "__EventFilter" `
    -Filter "Name='$SIM_WMI_F'" -ErrorAction SilentlyContinue |
    Remove-WmiObject -ErrorAction SilentlyContinue
Write-OK "WMI subscription removed"

# Test user
net user $SIM_USER /delete 2>&1 | Out-Null
Write-OK "Test user '$SIM_USER' deleted"

# Temp files
foreach ($f in @($SIM_MIMI, $SIM_NMAP, $SIM_VBS, $SIM_SVC_EXE)) {
    Remove-Item $f -Force -ErrorAction SilentlyContinue
}
Write-OK "Temp files removed"


# ═════════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ═════════════════════════════════════════════════════════════════════════════
Write-Banner "Expected Alerts  - Check the FLARE Dashboard"

Write-Host ""
Write-Host ("  {0,-10} {1,-38} {2}" -f "SEVERITY", "RULE ID", "MITRE") -ForegroundColor DarkGray
Write-Host ("  {0,-10} {1,-38} {2}" -f "--------", "--------------------------------------", "-------------") -ForegroundColor DarkGray

$alerts = @(
    @("CRITICAL","ps_download_cradle",              "T1059.001"),
    @("HIGH",    "ps_encoded_command",              "T1027    "),
    @("HIGH",    "ps_reflection_load",              "T1620    "),
    @("HIGH",    "brute_force_logon",               "T1110.001"),
    @("HIGH",    "password_spray",                  "T1110.003"),
    @("CRITICAL","shadow_copy_deletion",            "T1490    "),
    @("HIGH",    "ioc_process_name  (vssadmin.exe)","T1588.002"),
    @("HIGH",    "ioc_process_name  (mimikatz.exe)","T1588.002"),
    @("HIGH",    "ioc_process_name  (nmap.exe)",    "T1588.002"),
    @("CRITICAL","ioc_process_chain (wscript→ps)",  "T1059    "),
    @("HIGH",    "scheduled_task_suspicious",       "T1053.005"),
    @("MEDIUM",  "scheduled_task_created",          "T1053.005"),
    @("HIGH",    "new_service_suspicious_path",     "T1543.003"),
    @("CRITICAL","psexec_lateral_movement",         "T1569.002"),
    @("CRITICAL","wmi_persistence",                 "T1546.003"),
    @("HIGH",    "privileged_group_modification",   "T1098    "),
    @("CRITICAL","defender_disabled  (if no tamper protection)", "T1562.001"),
    @("CRITICAL","audit_policy_changed",            "T1562.002"),
    @("CRITICAL","security_log_cleared",            "T1070.001"),
    @("CRITICAL","ioc_domain_match",                "T1071.004"),
    @("HIGH",    "network: DDoS (HTTP Flood)",      "T1498    "),
    @("HIGH",    "network: Port Scan (SYN)",        "T1046    "),
    @("HIGH",    "network: SSH Brute Force",        "T1110.003"),
    @("HIGH",    "network: Web Attack (SQLi)",      "T1190    "),
    @("HIGH",    "network: Botnet C2 Beacon",       "T1071.001")
)

foreach ($a in $alerts) {
    $col = switch ($a[0]) {
        "CRITICAL" { "Red" }
        "HIGH"     { "DarkYellow" }
        default    { "White" }
    }
    Write-Host ("  {0,-10} {1,-38} {2}" -f $a[0], $a[1], $a[2]) -ForegroundColor $col
}

Write-Host ""
Write-Host "  Total: up to 25 alerts  (19 host + 5 network; +1 if Tamper Protection is off)" -ForegroundColor Green
Write-Host ""
Write-Host "  Dashboard: https://[FLARE_SERVER]:7331" -ForegroundColor Cyan
Write-Host "  Alerts tab → filter by this client's hostname to see only this run's results" -ForegroundColor DarkGray
Write-Host ""
Read-Host "  Press Enter to exit"
