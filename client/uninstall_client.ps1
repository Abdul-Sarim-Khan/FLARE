<#
.SYNOPSIS
    FLARE v0.6 - Client Uninstaller

.DESCRIPTION
    Reverses every system change made by the three client setup scripts:
      1_grant_privileges.ps1  -> removes Event Log Readers membership,
                                  reverts Security channel SDDL ACE,
                                  removes ACL on working directory,
                                  removes FLARE-Agent-Outbound firewall rule.
      2_setup.ps1             -> deletes agent.env.
      3_configure.ps1         -> removes Machine-scope environment variables.

    Also stops and deletes the FLAREAgent Windows service if present.
    Python packages and project files are left intact.
    Must run as Administrator.

.PARAMETER Account
    The account that was passed to 1_grant_privileges.ps1.
    Defaults to the current interactive user.

.PARAMETER FlareDir
    Working directory that was granted Modify rights.
    Defaults to the parent of this script (the client folder).

.EXAMPLE
    .\uninstall_client.ps1
    .\uninstall_client.ps1 -Account "NT AUTHORITY\SYSTEM"
#>

param(
    [string]$Account  = $env:USERNAME,
    [string]$FlareDir = $PSScriptRoot
)

$ErrorActionPreference = "SilentlyContinue"

# ---------------------------------------------------------------------------
# 0. Self-elevate, forwarding both parameters
# ---------------------------------------------------------------------------
$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Not running as Administrator - relaunching elevated..." -ForegroundColor Yellow
    $scriptPath = $MyInvocation.MyCommand.Definition
    Start-Process powershell -Verb RunAs -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$scriptPath`" -Account `"$Account`" -FlareDir `"$FlareDir`""
    exit
}

function Write-Step { param($msg) Write-Host "`n  [+] $msg" -ForegroundColor Cyan }
function Write-OK   { param($msg) Write-Host "      OK  $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "      !!  $msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "  FLARE v0.6 - Client Uninstaller" -ForegroundColor White
Write-Host "  Account  : $Account"
Write-Host "  FlareDir : $FlareDir"

# ---------------------------------------------------------------------------
# 0. Stop any running FLARE agent processes
# ---------------------------------------------------------------------------
Write-Step "Stopping any running FLARE agent processes"

$killed = $false
Get-WmiObject Win32_Process -Filter "Name='python.exe' OR Name='python3.exe'" `
    -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.CommandLine -match [regex]::Escape("flare_agent.py")) {
        $pid_ = $_.ProcessId
        Stop-Process -Id $pid_ -Force -ErrorAction SilentlyContinue
        Write-OK "Killed flare_agent.py process (PID $pid_)"
        $killed = $true
    }
}
if (-not $killed) {
    Write-Warn "No running flare_agent.py process found - skipping"
}

Start-Sleep -Milliseconds 500

# ---------------------------------------------------------------------------
# 1. Stop and delete the FLAREAgent Windows service
# ---------------------------------------------------------------------------
Write-Step "Removing FLAREAgent service"
$svc = Get-Service -Name "FLAREAgent" -ErrorAction SilentlyContinue
if ($svc) {
    # Use sc.exe stop instead of Stop-Service to avoid PowerShell printing
    # the old registered display name in its waiting-for-stop warnings.
    sc.exe stop "FLAREAgent" 2>&1 | Out-Null
    Start-Sleep -Milliseconds 1500
    sc.exe delete "FLAREAgent" 2>&1 | Out-Null
    Write-OK "FLAREAgent service stopped and deleted"
} else {
    Write-Warn "Service 'FLAREAgent' not found - skipping"
}

# ---------------------------------------------------------------------------
# 2. Remove Machine-scope environment variables (from 3_configure.ps1)
# ---------------------------------------------------------------------------
Write-Step "Removing Machine-scope environment variables"
$envVars = @(
    "FLARE_SERVER_URL",
    "FLARE_CA_CERT",
    "FLARE_CLIENT_CERT",
    "FLARE_CLIENT_KEY",
    "FLARE_NET_CSV",
    "FLARE_LOG_LEVEL",
    "FLARE_FL_TEST_MODE"
)
foreach ($var in $envVars) {
    $current = [System.Environment]::GetEnvironmentVariable($var, "Machine")
    if ($null -ne $current) {
        [System.Environment]::SetEnvironmentVariable($var, $null, "Machine")
        [System.Environment]::SetEnvironmentVariable($var, $null, "Process")
        Write-OK "Removed $var"
    } else {
        Write-Warn "$var was not set - skipping"
    }
}

# ---------------------------------------------------------------------------
# 3. Remove FLARE-Agent-Outbound firewall rule (from 1_grant_privileges.ps1)
# ---------------------------------------------------------------------------
Write-Step "Removing outbound firewall rule"
$rule = Get-NetFirewallRule -DisplayName "FLARE-Agent-Outbound" -ErrorAction SilentlyContinue
if ($rule) {
    Remove-NetFirewallRule -DisplayName "FLARE-Agent-Outbound" -ErrorAction SilentlyContinue
    Write-OK "Removed firewall rule 'FLARE-Agent-Outbound'"
} else {
    Write-Warn "Firewall rule 'FLARE-Agent-Outbound' not found - skipping"
}

# ---------------------------------------------------------------------------
# 4. Remove account from Event Log Readers group (from 1_grant_privileges.ps1)
# ---------------------------------------------------------------------------
Write-Step "Removing '$Account' from 'Event Log Readers' group"
try {
    $result = net localgroup "Event Log Readers" "$Account" /delete 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-OK "Removed from Event Log Readers"
    } else {
        Write-Warn "net localgroup delete returned: $result"
    }
} catch {
    Write-Warn "Could not remove from group: $_"
}

# ---------------------------------------------------------------------------
# 5. Revert Security event log channel SDDL (from 1_grant_privileges.ps1)
# ---------------------------------------------------------------------------
Write-Step "Reverting Security event log channel ACL for '$Account'"
try {
    $acctObj     = New-Object System.Security.Principal.NTAccount($Account)
    $sid         = $acctObj.Translate([System.Security.Principal.SecurityIdentifier]).Value
    $aceToRemove = "(A;;0x1;;;$sid)"

    $rawOutput   = wevtutil gl Security 2>&1
    $sddlLine    = $rawOutput | Where-Object { $_ -match "channelAccess" }
    $currentSddl = ($sddlLine -replace ".*channelAccess:\s*", "").Trim()

    if ($currentSddl -match [regex]::Escape($aceToRemove)) {
        $newSddl = $currentSddl -replace [regex]::Escape($aceToRemove), ""
        wevtutil sl Security "/ca:$newSddl"
        Write-OK "Security channel ACE for SID $sid removed"
    } else {
        Write-Warn "ACE for SID $sid not present in Security channel ACL - skipping"
    }
} catch {
    Write-Warn "Could not revert Security channel SDDL: $_"
}

# ---------------------------------------------------------------------------
# 6. Remove Modify ACL on agent working directory (from 1_grant_privileges.ps1)
# ---------------------------------------------------------------------------
Write-Step "Removing Modify ACL on '$FlareDir' for '$Account'"
if (Test-Path $FlareDir) {
    try {
        $acl     = Get-Acl $FlareDir
        $acctObj = New-Object System.Security.Principal.NTAccount($Account)
        $toRemove = $acl.Access | Where-Object {
            $_.IdentityReference -eq $acctObj -and
            $_.FileSystemRights  -band [System.Security.AccessControl.FileSystemRights]::Modify
        }
        if ($toRemove) {
            foreach ($rule in $toRemove) {
                $acl.RemoveAccessRule($rule) | Out-Null
            }
            Set-Acl $FlareDir $acl
            Write-OK "Removed Modify ACL on $FlareDir for $Account"
        } else {
            Write-Warn "No matching ACL entry found - skipping"
        }
    } catch {
        Write-Warn "Could not modify ACL on $FlareDir : $_"
    }
} else {
    Write-Warn "$FlareDir does not exist - skipping ACL removal"
}

# ---------------------------------------------------------------------------
# 7. Revert audit policies set by 1_grant_privileges.ps1
# ---------------------------------------------------------------------------
Write-Step "Reverting audit policies"

$auditReverts = @(
    "Filtering Platform Connection",
    "Security Group Management",
    "Audit Policy Change"
)
foreach ($subcat in $auditReverts) {
    auditpol /set /subcategory:"$subcat" /success:disable /failure:disable 2>&1 | Out-Null
    Write-OK "Reverted: $subcat"
}

# Remove command-line capture registry key
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    /v ProcessCreationIncludeCmdLine_Enabled /f 2>&1 | Out-Null
Write-OK "Removed ProcessCreationIncludeCmdLine_Enabled registry value"

# Disable PowerShell Script Block Logging
$sbPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (Test-Path $sbPath) {
    Set-ItemProperty -Path $sbPath -Name "EnableScriptBlockLogging" -Value 0 -Type DWord `
        -ErrorAction SilentlyContinue
    Write-OK "PowerShell Script Block Logging disabled"
}

# Disable DNS Client Operational log
wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:false 2>&1 | Out-Null
Write-OK "DNS Client Operational log disabled"

# ---------------------------------------------------------------------------
# 8. Delete agent.env (from 2_setup.ps1)
# ---------------------------------------------------------------------------
Write-Step "Deleting agent.env"
$envFile = Join-Path $FlareDir "agent.env"
if (Test-Path $envFile) {
    Remove-Item -Path $envFile -Force -ErrorAction SilentlyContinue
    Write-OK "Deleted $envFile"
} else {
    Write-Warn "agent.env not found at $envFile - skipping"
}

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "  Client uninstallation complete." -ForegroundColor Green
Write-Host "  Python packages and project files were left intact." -ForegroundColor White
Write-Host ""
Read-Host "  Press Enter to exit"
