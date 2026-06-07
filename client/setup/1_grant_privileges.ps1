<#
.SYNOPSIS
    FLARE v0.6 - Step 1: Grant OS privileges required by the agent.

.DESCRIPTION
    Runs ONCE on each endpoint that will host flare_agent.py.
    Must be executed as Administrator.

    What this script does:
      1. Adds the target account to "Event Log Readers" so the agent
         can read Security, Sysmon, System, and PowerShell channels.
      2. Grants explicit read access on the Security channel via wevtutil
         (Security requires a separate ACL beyond Event Log Readers).
      3. Grants the target account Modify rights to the agent directory.
      4. Adds an outbound firewall rule for TCP 7331 to the FLARE server.

.PARAMETER Account
    The Windows account that will run flare_agent.py.
    Defaults to the current interactive user.
    For service installs use: -Account "NT AUTHORITY\SYSTEM"

.PARAMETER FlareDir
    Working directory for the agent. Default: Current Client Directory

.EXAMPLE
    .\1_grant_privileges.ps1
    .\1_grant_privileges.ps1 -Account "NT AUTHORITY\SYSTEM"
#>

param(
    [string]$Account    = $env:USERNAME,
    [string]$FlareDir   = (Split-Path -Parent $PSScriptRoot),
    [int]   $ServerPort = 7331,
    [switch]$NoExit
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# 0. Self-elevate if not already running as Administrator
# ---------------------------------------------------------------------------

$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

if (-not $principal.IsInRole($adminRole)) {
    Write-Host "Not running as Administrator - relaunching elevated..." -ForegroundColor Yellow
    $scriptPath = $MyInvocation.MyCommand.Definition
    $argList    = "-NoExit -ExecutionPolicy Bypass -File `"$scriptPath`" -Account `"$Account`" -FlareDir `"$FlareDir`" -ServerPort $ServerPort"
    Start-Process powershell -Verb RunAs -ArgumentList $argList
    exit
}

function Write-Step { param($msg) Write-Host "`n  [+] $msg" -ForegroundColor Cyan }
function Write-OK   { param($msg) Write-Host "      OK  $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "      !!  $msg" -ForegroundColor Yellow }
function Write-Fail { param($msg) Write-Host "      ERR $msg" -ForegroundColor Red; if (-not $NoExit) { Read-Host "`nPress Enter to exit" }; exit 1 }

Write-Host ""
Write-Host "  FLARE v0.6 - Privilege Grant" -ForegroundColor White
Write-Host "  Target account : $Account"
Write-Host "  Working dir    : $FlareDir"

# ---------------------------------------------------------------------------
# 1. Add to Event Log Readers
# ---------------------------------------------------------------------------

Write-Step "Adding '$Account' to 'Event Log Readers' group"

$shortName = ($Account -split '\\')[-1]

try {
    $group   = [ADSI]"WinNT://./Event Log Readers,group"
    $members = @(
        $group.Invoke("Members") | ForEach-Object {
            $_.GetType().InvokeMember("Name", "GetProperty", $null, $_, $null)
        }
    )

    if ($members -contains $shortName) {
        Write-Warn "Already a member of Event Log Readers - skipping"
    } else {
        # Use WinNT://./name for local accounts; domain accounts keep their DOMAIN\name prefix
        $adsiPath = if ($Account -match '\\') { "WinNT://$Account" } else { "WinNT://./$Account" }
        $group.Add($adsiPath)
        Write-OK "Added to Event Log Readers"
    }
} catch {
    Write-Warn "ADSI method failed: $_ - trying net localgroup fallback"
    try {
        $result = net localgroup "Event Log Readers" "$Account" /add 2>&1
        Write-OK "Added via net localgroup"
    } catch {
        Write-Warn "net localgroup also failed (account may already be a member): $_"
    }
}

# ---------------------------------------------------------------------------
# 2. Grant Security event log read access via wevtutil SDDL
# ---------------------------------------------------------------------------

Write-Step "Granting Security event log read access"

try {
    $rawOutput   = wevtutil gl Security
    $sddlLine    = $rawOutput | Where-Object { $_ -match "channelAccess" }
    $currentSddl = $sddlLine -replace ".*channelAccess:\s*", ""

    $acctObj = New-Object System.Security.Principal.NTAccount($Account)
    $sid     = $acctObj.Translate([System.Security.Principal.SecurityIdentifier]).Value
    $newAce  = "(A;;0x1;;;$sid)"

    if ($currentSddl -match [regex]::Escape($sid)) {
        Write-Warn "SID already present in Security channel ACL - skipping"
    } else {
        $newSddl = $currentSddl + $newAce
        wevtutil sl Security "/ca:$newSddl"
        Write-OK "Security channel ACL updated"
    }
} catch {
    Write-Warn "Could not update Security channel SDDL: $_"
    Write-Warn "If running agent as SYSTEM or Administrator this is not needed."
}

# ---------------------------------------------------------------------------
# 3. Grant Modify rights to the working directory
# ---------------------------------------------------------------------------

Write-Step "Granting Modify rights to agent working directory: $FlareDir"

if (-not (Test-Path $FlareDir)) {
    New-Item -ItemType Directory -Path $FlareDir -Force | Out-Null
    Write-OK "Created $FlareDir"
}

try {
    $acl     = Get-Acl $FlareDir
    $acctObj = New-Object System.Security.Principal.NTAccount($Account)
    $rights  = [System.Security.AccessControl.FileSystemRights]::Modify
    $inherit = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
    $prop    = [System.Security.AccessControl.PropagationFlags]::None
    $type    = [System.Security.AccessControl.AccessControlType]::Allow
    $rule    = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $acctObj, $rights, $inherit, $prop, $type
    )
    $acl.AddAccessRule($rule)
    Set-Acl $FlareDir $acl
    Write-OK "Granted Modify on $FlareDir for $Account"
} catch {
    Write-Warn "Could not set ACL on $FlareDir : $_"
}

# ---------------------------------------------------------------------------
# 4. Outbound firewall rule for FLARE server traffic
# ---------------------------------------------------------------------------

Write-Step "Adding outbound firewall rule for FLARE server traffic"

$ruleName = "FLARE-Agent-Outbound"

if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
    Write-Warn "Firewall rule '$ruleName' already exists - skipping"
} else {
    try {
        New-NetFirewallRule `
            -DisplayName $ruleName `
            -Direction   Outbound `
            -Protocol    TCP `
            -RemotePort  $ServerPort `
            -Action      Allow `
            -Profile     Any `
            -Description "Allow FLARE agent to POST alerts and heartbeats to the FLARE server" |
            Out-Null
        Write-OK "Firewall rule created (TCP outbound port $ServerPort)"
    } catch {
        Write-Warn "Could not create firewall rule: $_"
    }
}

# ---------------------------------------------------------------------------
# 5. Enable audit policies required by the FLARE detection rules
# ---------------------------------------------------------------------------

Write-Step "Enabling required Windows audit policies"

$auditSettings = @(
    # subcategory GUID / name                       why it is needed
    @("Process Creation",               "Event 4688 - process name + command line (shadow copy, IOC process, chains)"),
    @("Logon",                          "Event 4625 - failed logons (brute force, password spray)"),
    @("Security Group Management",      "Events 4728/4732/4756 - privileged group membership changes"),
    @("Audit Policy Change",            "Event 4719 - audit policy modifications"),
    @("Filtering Platform Connection",  "Event 5156 - outbound connections to IOC IPs (check_ioc_ip rule)")
)

foreach ($entry in $auditSettings) {
    $subcat = $entry[0]
    $reason = $entry[1]
    try {
        auditpol /set /subcategory:"$subcat" /success:enable 2>&1 | Out-Null
        if ($subcat -eq "Logon") {
            auditpol /set /subcategory:"$subcat" /failure:enable 2>&1 | Out-Null
        }
        Write-OK "$subcat  ($reason)"
    } catch {
        Write-Warn "Could not set audit policy for '$subcat': $_"
    }
}

# Enable command-line capture inside Event 4688 (needed for shadow copy rule)
try {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
        /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f 2>&1 | Out-Null
    Write-OK "Process creation command-line capture enabled (registry)"
} catch {
    Write-Warn "Could not enable command-line capture: $_"
}

# Enable PowerShell Script Block Logging (Event 4104  - download cradle, encoded, reflection)
try {
    $sbPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $sbPath)) { New-Item -Path $sbPath -Force | Out-Null }
    Set-ItemProperty -Path $sbPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
    Write-OK "PowerShell Script Block Logging enabled (Event 4104)"
} catch {
    Write-Warn "Could not enable PowerShell Script Block Logging: $_"
}

# Enable DNS Client Operational log (Event 3008  - IOC domain queries)
try {
    wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true 2>&1 | Out-Null
    Write-OK "DNS Client Operational log enabled (Event 3008)"
} catch {
    Write-Warn "Could not enable DNS Client Operational log: $_"
}

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "  NOTE  Network capture requires the agent to run as Administrator" -ForegroundColor Yellow
Write-Host "        to run as Administrator or NT AUTHORITY\SYSTEM."            -ForegroundColor Yellow
Write-Host "        The Windows Service runs as SYSTEM by default."             -ForegroundColor Yellow
Write-Host ""
Write-Host "  Privilege grant complete." -ForegroundColor Green
Write-Host "  Next step: run  setup\2_setup.ps1" -ForegroundColor White
Write-Host ""
if (-not $NoExit) { Read-Host "  Press Enter to exit" }