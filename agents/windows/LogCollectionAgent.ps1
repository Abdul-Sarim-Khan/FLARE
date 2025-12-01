<#
.SYNOPSIS
    FLARE Log Collection Agent (Security & Pattern Focus)
.DESCRIPTION
    Collects Security Event Logs (4624, 4625) and parses them into structured features 
    (User, IP, LogonType) for the AI Model.
#>

param(
    [switch]$Test,
    [switch]$Start
)

# --- Configuration ---
$IntervalSeconds = 10
$BatchSize = 100
# WE ONLY MONITOR SECURITY LOGS NOW (For Auth Patterns)
$LogName = "Security" 
# Filter for Login Success (4624) and Failure (4625)
$EventIDs = @(4624, 4625) 

$StateFile = "C:\FLARE-data\Data\agent_state.json"
$LogsFile = "C:\FLARE-data\Logs\logs.json"

# --- Helper: Parse XML Data ---
# This is the "Magic" function that extracts patterns from raw text
function Get-EventProperty {
    param($XmlContent, $PropertyName)
    $val = $XmlContent.Event.EventData.Data | Where-Object { $_.Name -eq $PropertyName }
    return $val.'#text'
}

# --- Main Collection Logic ---
function Start-LogCollection {
    Write-Host "🔥 FLARE Agent Started: Monitoring Security Patterns..." -ForegroundColor Cyan
    
    # Ensure directories exist
    New-Item -ItemType Directory -Path "C:\FLARE-data\Logs" -Force | Out-Null
    New-Item -ItemType Directory -Path "C:\FLARE-data\Data" -Force | Out-Null

    while ($true) {
        # 1. Load State (Last Record ID)
        $lastRecordId = 0
        if (Test-Path $StateFile) {
            $state = Get-Content $StateFile | ConvertFrom-Json
            $lastRecordId = $state.LastRecordId
        }

        # 2. Fetch New Events
        # We fetch raw XML because Get-WinEvent objects hide the specific IP/User details we need
        $query = "*[System[(EventID=4624 or EventID=4625) and EventRecordID > $lastRecordId]]"
        
        try {
            $events = Get-WinEvent -LogName $LogName -FilterXPath $query -MaxEvents $BatchSize -ErrorAction SilentlyContinue 
            
            if ($events) {
                $parsedLogs = @()
                
                foreach ($evt in $events) {
                    # Convert to XML for deep parsing
                    $xml = [xml]$evt.ToXml()

                    # Extract Key Features for AI
                    $user = Get-EventProperty -XmlContent $xml -PropertyName "TargetUserName"
                    $ip   = Get-EventProperty -XmlContent $xml -PropertyName "IpAddress"
                    $type = Get-EventProperty -XmlContent $xml -PropertyName "LogonType"
                    
                    # Create Structured Object
                    $logObj = @{
                        Timestamp = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                        EventID   = $evt.Id
                        User      = $user
                        IP        = $ip
                        LogonType = $type  # Critical for pattern (2=Interactive, 3=Network, 10=RDP)
                        Status    = if ($evt.Id -eq 4624) { "Authorized" } else { "Unauthorized" }
                    }
                    $parsedLogs += $logObj
                }

                # 3. Append to JSON File (Atomic Append)
                $currentContent = @()
                if (Test-Path $LogsFile) {
                    $currentContent = Get-Content $LogsFile | ConvertFrom-Json
                }
                $currentContent += $parsedLogs
                $currentContent | ConvertTo-Json -Depth 3 | Set-Content $LogsFile

                # 4. Update State
                $newState = @{ LastRecordId = $events[0].RecordId }
                $newState | ConvertTo-Json | Set-Content $StateFile

                Write-Host "  [+] Processed $($events.Count) new authentication events." -ForegroundColor Green
            }
        } catch {
            # Ignore "No events found" errors
        }
        
        Start-Sleep -Seconds $IntervalSeconds
    }
}

if ($Start) { Start-LogCollection }
elseif ($Test) { Write-Host "Test Mode: Fetching last 5 security events..." -ForegroundColor Yellow; Get-WinEvent -LogName "Security" -MaxEvents 5 | Format-Table TimeCreated, Id, Message -AutoSize }
else { Write-Host "Usage: .\LogCollectionAgent.ps1 -Start" }