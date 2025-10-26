<#
.SYNOPSIS
    FLARE Log Collection Agent (Display Mode)
.DESCRIPTION
    Collects system logs and displays them in PowerShell window with deduplication.
#>

param(
    [switch]$Test,
    [switch]$Start
)

# --- Configuration ---
$IntervalSeconds = 10
$BatchSize = 100
$LogName = "Application"
$StateFile = "C:\FLARE-data\Data\agent_state.json"
$LogsFile = "C:\FLARE-data\Logs\logs.json"

# Display banner
function Show-Banner {
    Clear-Host
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                FLARE Log Collection Agent                  ║" -ForegroundColor Cyan
    Write-Host "║                 (Live Log Display Mode)                    ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Configuration:" -ForegroundColor Yellow
    Write-Host "  • Log Source: $LogName" -ForegroundColor White
    Write-Host "  • Interval: $IntervalSeconds seconds" -ForegroundColor White
    Write-Host "  • Batch Size: $BatchSize events" -ForegroundColor White
    Write-Host "  • State File: $StateFile" -ForegroundColor White
    Write-Host "  • Logs Archive: $LogsFile" -ForegroundColor White
    Write-Host ""
    Write-Host "Press Ctrl+C to stop collecting logs" -ForegroundColor DarkGray
    Write-Host ("=" * 62) -ForegroundColor DarkGray
    Write-Host ""
}

# --- State Management Functions ---
function Get-AgentState {
    $defaultState = @{
        LastRecordId = 0
        LastTime = (Get-Date).AddHours(-1).ToUniversalTime()
    }

    if (Test-Path $StateFile) {
        try {
            $state = Get-Content $StateFile -Raw | ConvertFrom-Json
            $state.LastTime = [datetime]::ParseExact($state.LastTime, "o", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
            return $state
        } catch {
            Write-Host "⚠️  Invalid state file. Using default state." -ForegroundColor Yellow
            return $defaultState
        }
    }
    return $defaultState
}

function Set-AgentState($stateObject) {
    $dir = Split-Path $StateFile
    if (-not (Test-Path $dir)) { 
        New-Item -ItemType Directory -Path $dir -Force | Out-Null 
    }

    $stateToSave = @{
        LastRecordId = $stateObject.LastRecordId
        LastTime = $stateObject.LastTime.ToString("o")
    }

    $stateToSave | ConvertTo-Json -Depth 3 | Set-Content $StateFile -Force
}

# --- Log Storage Functions ---
function Save-LogsToFile($logs) {
    try {
        $dir = Split-Path $LogsFile
        if (-not (Test-Path $dir)) { 
            New-Item -ItemType Directory -Path $dir -Force | Out-Null 
        }

        # Load existing logs if file exists
        $allLogs = @()
        if (Test-Path $LogsFile) {
            $existingContent = Get-Content $LogsFile -Raw
            if ($existingContent) {
                $allLogs = $existingContent | ConvertFrom-Json
            }
        }

        # Append new logs
        $allLogs += $logs

        # Save back to file
        $allLogs | ConvertTo-Json -Depth 5 | Set-Content $LogsFile -Force
        
        Write-Host "  💾 Saved $($logs.Count) log(s) to $LogsFile" -ForegroundColor Cyan
    } catch {
        Write-Host "  ⚠️  Failed to save logs to file: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# --- Log Display Functions ---
function Get-LogLevelColor($level) {
    switch ($level) {
        "Critical" { return "Red" }
        "Error" { return "Red" }
        "Warning" { return "Yellow" }
        "Information" { return "Green" }
        default { return "White" }
    }
}

function Show-LogEntry($log, $index) {
    $color = Get-LogLevelColor $log.LevelDisplayName
    
    Write-Host ""
    Write-Host "┌─ Log #$index " -NoNewline -ForegroundColor DarkGray
    Write-Host "─────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "│ " -NoNewline -ForegroundColor DarkGray
    Write-Host "Time:     " -NoNewline -ForegroundColor Cyan
    Write-Host $log.TimeCreated -ForegroundColor White
    Write-Host "│ " -NoNewline -ForegroundColor DarkGray
    Write-Host "Level:    " -NoNewline -ForegroundColor Cyan
    Write-Host $log.LevelDisplayName -ForegroundColor $color
    Write-Host "│ " -NoNewline -ForegroundColor DarkGray
    Write-Host "Event ID: " -NoNewline -ForegroundColor Cyan
    Write-Host $log.Id -ForegroundColor White
    Write-Host "│ " -NoNewline -ForegroundColor DarkGray
    Write-Host "Record:   " -NoNewline -ForegroundColor Cyan
    Write-Host $log.RecordId -ForegroundColor White
    
    if ($log.Message) {
        $message = $log.Message
        if ($message.Length -gt 200) {
            $message = $message.Substring(0, 197) + "..."
        }
        Write-Host "│ " -NoNewline -ForegroundColor DarkGray
        Write-Host "Message:  " -NoNewline -ForegroundColor Cyan
        Write-Host $message -ForegroundColor Gray
    }
    Write-Host "└" -NoNewline -ForegroundColor DarkGray
    Write-Host ("─" * 61) -ForegroundColor DarkGray
}

# --- Main Collection Logic ---
function Start-LogCollection {
    Show-Banner
    
    $collectionCount = 0
    
    while ($true) {
        $state = Get-AgentState
        $startTime = $state.LastTime

        $filterHash = @{
            LogName = $LogName
            StartTime = $startTime
        }

        try {
            $newLogs = Get-WinEvent -FilterHashtable $filterHash -MaxEvents $BatchSize -ErrorAction SilentlyContinue |
                       Where-Object { $_.RecordId -gt $state.LastRecordId } |
                       Sort-Object -Property RecordId

            if ($newLogs) {
                $logsArray = @($newLogs)
                $collectionCount++
                
                Write-Host ""
                Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
                Write-Host "║  NEW LOGS COLLECTED - Collection #$collectionCount" -ForegroundColor Green
                Write-Host "║  Found: $($logsArray.Count) new event(s)" -ForegroundColor Green
                Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green

                for ($i = 0; $i -lt $logsArray.Count; $i++) {
                    Show-LogEntry $logsArray[$i] ($i + 1)
                }

                # Save logs to JSON file
                $logsToSave = $logsArray | Select-Object TimeCreated, RecordId, Id, LevelDisplayName, Message
                Save-LogsToFile $logsToSave

                # Update state with the last log
                $lastLog = $logsArray[-1]
                $state.LastRecordId = $lastLog.RecordId
                $state.LastTime = $lastLog.TimeCreated
                Set-AgentState $state
                
                Write-Host ""
                Write-Host "✓ State updated. Last Record ID: " -NoNewline -ForegroundColor Green
                Write-Host $lastLog.RecordId -ForegroundColor White
                
            } else {
                $timestamp = Get-Date -Format "HH:mm:ss"
                Write-Host "[$timestamp] " -NoNewline -ForegroundColor DarkGray
                Write-Host "💤 No new logs. Monitoring... (Last ID: $($state.LastRecordId))" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host "⚠️  Error collecting logs: $($_.Exception.Message)" -ForegroundColor Red
        }

        Start-Sleep -Seconds $IntervalSeconds
    }
}

# --- Test Function ---
function Test-Agent {
    Write-Host "`n=== Running Agent Diagnostics ===" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "[1] Checking Event Log Access..." -ForegroundColor Yellow
    try {
        $testLog = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop
        Write-Host "  ✓ Successfully accessed $LogName log" -ForegroundColor Green
        Write-Host "    Latest event: $($testLog.TimeCreated)" -ForegroundColor Gray
    } catch {
        Write-Host "  ✗ Cannot access $LogName log" -ForegroundColor Red
        Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "[2] Checking State File..." -ForegroundColor Yellow
    if (Test-Path $StateFile) {
        $state = Get-AgentState
        Write-Host "  ✓ State file exists" -ForegroundColor Green
        Write-Host "    Last Record ID: $($state.LastRecordId)" -ForegroundColor Gray
        Write-Host "    Last Time: $($state.LastTime)" -ForegroundColor Gray
    } else {
        Write-Host "  ℹ State file not found (will be created on first run)" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "[3] Checking Logs Archive..." -ForegroundColor Yellow
    if (Test-Path $LogsFile) {
        $logsContent = Get-Content $LogsFile -Raw
        if ($logsContent) {
            $logsArray = $logsContent | ConvertFrom-Json
            $logCount = if ($logsArray -is [Array]) { $logsArray.Count } else { 1 }
            Write-Host "  ✓ Logs file exists: $LogsFile" -ForegroundColor Green
            Write-Host "    Total logs archived: $logCount" -ForegroundColor Gray
        } else {
            Write-Host "  ℹ Logs file is empty" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  ℹ Logs file not found (will be created on first collection)" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "[4] Checking Data Directory..." -ForegroundColor Yellow
    $dataDir = Split-Path $StateFile
    if (Test-Path $dataDir) {
        Write-Host "  ✓ Data directory exists: $dataDir" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ Data directory missing (will be created)" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "=== Diagnostics Complete ===" -ForegroundColor Cyan
    Write-Host ""
}

# --- Execution Flow ---
if ($Test) {
    Test-Agent
}
elseif ($Start) {
    Start-LogCollection
}
else {
    Write-Host ""
    Write-Host "FLARE Log Collection Agent" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\LogCollectionAgent.ps1 -Test   " -NoNewline -ForegroundColor White
    Write-Host "# Run diagnostics" -ForegroundColor Gray
    Write-Host "  .\LogCollectionAgent.ps1 -Start  " -NoNewline -ForegroundColor White
    Write-Host "# Start collecting and displaying logs" -ForegroundColor Gray
    Write-Host ""
}