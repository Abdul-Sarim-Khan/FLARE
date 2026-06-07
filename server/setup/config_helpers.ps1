# FLARE v0.6 - Shared configuration helpers
# Dot-sourced by 3_configure.ps1.
# Do NOT run this file directly.

function Write-Step { param($msg) Write-Host "`n  [+] $msg" -ForegroundColor Cyan }
function Write-OK   { param($msg) Write-Host "      OK  $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "      !!  $msg" -ForegroundColor Yellow }
function Write-Fail {
    param($msg)
    Write-Host "      ERR $msg" -ForegroundColor Red
    # When invoked by the runner ($NoExit is set in calling scope), skip the
    # prompt — the runner has its own error handler that prompts the user.
    if (-not $NoExit) { Read-Host "`n  Press Enter to exit" }
    exit 1
}

# Parse a KEY=VALUE env file into a hashtable.
function Read-EnvFile {
    param([string]$Path)
    $map = @{}
    if (-not (Test-Path $Path)) { return $map }
    foreach ($line in Get-Content $Path) {
        $line = $line.Trim()
        if ($line -match '^#' -or $line -eq '') { continue }
        $parts = $line -split '=', 2
        if ($parts.Count -eq 2) {
            $map[$parts[0].Trim()] = $parts[1].Trim()
        }
    }
    return $map
}

# Prompt the user for a value, returning $Default if they press Enter.
# Pass -Secret $true to mask input (for passwords).
# Skips the prompt entirely when $NonInteractive is set in the calling scope.
function Prompt-Value {
    param(
        [string]$Description,
        [string]$Default,
        [bool]  $Secret = $false
    )
    if ($NonInteractive) { return $Default }
    $prompt = "  $Description"
    if ($Default -and -not $Secret) { $prompt += " [$Default]" }
    $prompt += ": "
    Write-Host $prompt -NoNewline -ForegroundColor White
    if ($Secret) {
        $raw  = Read-Host -AsSecureString
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($raw)
        $val  = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    } else {
        $val = Read-Host
    }
    if ([string]::IsNullOrWhiteSpace($val)) { return $Default }
    return $val
}

# Write a Machine-scope environment variable (persists across reboots).
function Set-MachineEnv {
    param([string]$Name, [string]$Value)
    [System.Environment]::SetEnvironmentVariable($Name, $Value, "Machine")
    [System.Environment]::SetEnvironmentVariable($Name, $Value, "Process")
    if ($Name -match 'PASS|TOKEN|SECRET') {
        Write-OK "Set $Name = ***hidden***"
    } else {
        Write-OK "Set $Name = $Value"
    }
}

# Return $Map[$Key] if it exists and is not a placeholder, otherwise $Fallback.
function Get-Default {
    param([hashtable]$Map, [string]$Key, [string]$Fallback)
    if ($Map.ContainsKey($Key)) {
        $val = $Map[$Key]
        if ($val -match 'CHANGE_ME|YOUR_|PLACEHOLDER|TODO') { return $Fallback }
        return $val
    }
    return $Fallback
}
