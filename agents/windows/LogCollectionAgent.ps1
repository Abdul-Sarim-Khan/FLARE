# SIEM Log Collection Agent
# Collects security logs from Windows systems and sends to central server

#Requires -RunAsAdministrator

# ============================================================================
# CONFIGURATION
# ============================================================================

$config = @{
    # Agent Settings
    AgentName = $env:COMPUTERNAME
    AgentVersion = "1.0.0"
    
    # Collection Settings
    CollectionInterval = 10  # seconds between collections
    BatchSize = 100          # max events per batch
    
    # Server Settings
    ServerEndpoint = "http://localhost:8000/api/logs/ingest"  # Change to your server
    ServerTimeout = 30       # seconds
    
    # Log Sources
    EventLogs = @(
        @{
            LogName = "Security"
            EventIDs = @(4624, 4625, 4672, 4720, 4732, 4740)  # Login, privilege, account changes
            Level = @(2, 3, 4)  # Warning, Error, Critical
        },
        @{
            LogName = "System"
            EventIDs = @(7036, 7040, 1102)  # Service changes, audit log cleared
            Level = @(2, 3, 4)
        },
        @{
            LogName = "Application"
            EventIDs = @()  # Empty = all events
            Level = @(2, 3, 4)
        }
    )
    
    # Storage Settings
    LocalQueuePath = "C:\SIEM\Queue"
    LocalLogPath = "C:\SIEM\Logs"
    MaxQueueSize = 10000  # Max events in local queue
    
    # Retry Settings
    MaxRetries = 3
    RetryDelay = 5  # seconds
}

# ============================================================================
# INITIALIZATION
# ============================================================================

# Create directories
$directories = @($config.LocalQueuePath, $config.LocalLogPath)
foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Agent log file
$agentLogFile = Join-Path $config.LocalLogPath "agent_$(Get-Date -Format 'yyyyMMdd').log"

# Last collection timestamp file
$timestampFile = Join-Path $config.LocalQueuePath "last_collection.txt"

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

function Write-AgentLog {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to console with color
    $color = switch ($Level) {
        'INFO'  { 'White' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        'DEBUG' { 'Gray' }
    }
    Write-Host $logMessage -ForegroundColor $color
    
    # Write to file
    Add-Content -Path $agentLogFile -Value $logMessage
}

# ============================================================================
# EVENT COLLECTION FUNCTIONS
# ============================================================================

function Get-LastCollectionTime {
    if (Test-Path $timestampFile) {
        try {
            $content = Get-Content $timestampFile -Raw
            return [DateTime]::Parse($content)
        } catch {
            Write-AgentLog "Could not parse timestamp file, using default" -Level WARN
        }
    }
    return (Get-Date).AddMinutes(-5)  # Default: last 5 minutes
}

function Set-LastCollectionTime {
    param([DateTime]$Timestamp)
    $Timestamp.ToString("o") | Out-File $timestampFile -Force
}

function Get-SecurityEvents {
    param(
        [DateTime]$StartTime,
        [int]$MaxEvents = 100
    )
    
    $collectedEvents = @()
    
    foreach ($logConfig in $config.EventLogs) {
        try {
            Write-AgentLog "Collecting from $($logConfig.LogName)..." -Level DEBUG
            
            # Build filter hashtable
            $filterHash = @{
                LogName = $logConfig.LogName
                StartTime = $StartTime
            }
            
            # Add Level filter if specified
            if ($logConfig.Level.Count -gt 0) {
                $filterHash['Level'] = $logConfig.Level
            }
            
            # Add EventID filter if specified
            if ($logConfig.EventIDs.Count -gt 0) {
                $filterHash['ID'] = $logConfig.EventIDs
            }
            
            # Collect events
            $events = Get-WinEvent -FilterHashtable $filterHash -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
            
            if ($events) {
                Write-AgentLog "Found $($events.Count) events in $($logConfig.LogName)" -Level INFO
                $collectedEvents += $events
            }
            
        } catch {
            Write-AgentLog "Error collecting from $($logConfig.LogName): $($_.Exception.Message)" -Level ERROR
        }
    }
    
    return $collectedEvents
}

function ConvertTo-UnifiedLogFormat {
    param(
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event
    )
    
    # Extract common properties
    $unifiedLog = @{
        # Metadata
        agent_name = $config.AgentName
        agent_version = $config.AgentVersion
        collection_time = (Get-Date).ToString("o")
        
        # Event Details
        timestamp = $Event.TimeCreated.ToString("o")
        event_id = $Event.Id
        log_name = $Event.LogName
        level = $Event.LevelDisplayName
        source = $Event.ProviderName
        
        # Computer Info
        computer_name = $Event.MachineName
        user = $Event.UserId
        
        # Event Data
        message = $Event.Message
        task_category = $Event.TaskDisplayName
    }
    
    # Extract specific fields based on Event ID
    switch ($Event.Id) {
        # Successful Logon (4624)
        4624 {
            $unifiedLog['event_type'] = 'authentication_success'
            $unifiedLog['username'] = $Event.Properties[5].Value
            $unifiedLog['domain'] = $Event.Properties[6].Value
            $unifiedLog['logon_type'] = $Event.Properties[8].Value
            $unifiedLog['source_ip'] = $Event.Properties[18].Value
            $unifiedLog['logon_process'] = $Event.Properties[9].Value
        }
        
        # Failed Logon (4625)
        4625 {
            $unifiedLog['event_type'] = 'authentication_failure'
            $unifiedLog['username'] = $Event.Properties[5].Value
            $unifiedLog['domain'] = $Event.Properties[6].Value
            $unifiedLog['logon_type'] = $Event.Properties[10].Value
            $unifiedLog['source_ip'] = $Event.Properties[19].Value
            $unifiedLog['failure_reason'] = $Event.Properties[8].Value
            $unifiedLog['failure_status'] = $Event.Properties[7].Value
        }
        
        # Special Privileges Assigned (4672)
        4672 {
            $unifiedLog['event_type'] = 'privilege_escalation'
            $unifiedLog['username'] = $Event.Properties[1].Value
            $unifiedLog['domain'] = $Event.Properties[2].Value
            $unifiedLog['privileges'] = $Event.Properties[4].Value
        }
        
        # User Account Created (4720)
        4720 {
            $unifiedLog['event_type'] = 'account_created'
            $unifiedLog['target_username'] = $Event.Properties[0].Value
            $unifiedLog['target_domain'] = $Event.Properties[1].Value
            $unifiedLog['creator_username'] = $Event.Properties[4].Value
        }
        
        # User Added to Security Group (4732)
        4732 {
            $unifiedLog['event_type'] = 'group_membership_change'
            $unifiedLog['username'] = $Event.Properties[0].Value
            $unifiedLog['group_name'] = $Event.Properties[2].Value
            $unifiedLog['modifier'] = $Event.Properties[6].Value
        }
        
        # Account Locked (4740)
        4740 {
            $unifiedLog['event_type'] = 'account_locked'
            $unifiedLog['username'] = $Event.Properties[0].Value
            $unifiedLog['caller_computer'] = $Event.Properties[1].Value
        }
        
        # Default
        default {
            $unifiedLog['event_type'] = 'general'
        }
    }
    
    # Convert to JSON
    return $unifiedLog | ConvertTo-Json -Compress
}

# ============================================================================
# QUEUE MANAGEMENT
# ============================================================================

function Add-ToLocalQueue {
    param([array]$Events)
    
    if ($Events.Count -eq 0) { return }
    
    $queueFile = Join-Path $config.LocalQueuePath "queue_$(Get-Date -Format 'yyyyMMddHHmmss').json"
    
    $queueData = @{
        timestamp = (Get-Date).ToString("o")
        event_count = $Events.Count
        events = $Events
    }
    
    $queueData | ConvertTo-Json -Depth 10 | Out-File $queueFile -Force
    Write-AgentLog "Queued $($Events.Count) events to local storage" -Level INFO
}

function Get-QueuedBatches {
    Get-ChildItem -Path $config.LocalQueuePath -Filter "queue_*.json" | 
        Sort-Object LastWriteTime | 
        Select-Object -First 10
}

function Remove-QueuedBatch {
    param([string]$FilePath)
    Remove-Item $FilePath -Force
}

# ============================================================================
# DATA TRANSMISSION
# ============================================================================

function Send-ToServer {
    param([array]$Events)
    
    if ($Events.Count -eq 0) {
        Write-AgentLog "No events to send" -Level DEBUG
        return $true
    }
    
    $payload = @{
        agent = @{
            name = $config.AgentName
            version = $config.AgentVersion
        }
        timestamp = (Get-Date).ToString("o")
        event_count = $Events.Count
        events = $Events
    } | ConvertTo-Json -Depth 10
    
    $attempt = 0
    while ($attempt -lt $config.MaxRetries) {
        $attempt++
        
        try {
            Write-AgentLog "Sending $($Events.Count) events to server (attempt $attempt/$($config.MaxRetries))..." -Level INFO
            
            $response = Invoke-RestMethod -Uri $config.ServerEndpoint `
                -Method Post `
                -Body $payload `
                -ContentType "application/json" `
                -TimeoutSec $config.ServerTimeout `
                -ErrorAction Stop
            
            Write-AgentLog "Successfully sent $($Events.Count) events to server" -Level INFO
            return $true
            
        } catch {
            $errorMsg = $_.Exception.Message
            Write-AgentLog "Failed to send to server: $errorMsg" -Level ERROR
            
            if ($attempt -lt $config.MaxRetries) {
                Write-AgentLog "Retrying in $($config.RetryDelay) seconds..." -Level WARN
                Start-Sleep -Seconds $config.RetryDelay
            }
        }
    }
    
    Write-AgentLog "Failed to send after $($config.MaxRetries) attempts, queueing locally" -Level WARN
    return $false
}

# ============================================================================
# MAIN COLLECTION LOOP
# ============================================================================

function Start-LogCollection {
    Write-AgentLog "========================================" -Level INFO
    Write-AgentLog "SIEM Log Collection Agent v$($config.AgentVersion)" -Level INFO
    Write-AgentLog "Agent: $($config.AgentName)" -Level INFO
    Write-AgentLog "Server: $($config.ServerEndpoint)" -Level INFO
    Write-AgentLog "========================================" -Level INFO
    
    Write-Host "`nPress Ctrl+C to stop the agent`n" -ForegroundColor Cyan
    
    while ($true) {
        try {
            # Get last collection time
            $lastCollection = Get-LastCollectionTime
            $now = Get-Date
            
            Write-AgentLog "Starting collection cycle (since $($lastCollection.ToString('yyyy-MM-dd HH:mm:ss')))" -Level INFO
            
            # Collect events
            $rawEvents = Get-SecurityEvents -StartTime $lastCollection -MaxEvents $config.BatchSize
            
            if ($rawEvents.Count -gt 0) {
                # Convert to unified format
                Write-AgentLog "Converting $($rawEvents.Count) events to unified format..." -Level INFO
                $unifiedEvents = @()
                foreach ($event in $rawEvents) {
                    $unifiedEvents += ConvertTo-UnifiedLogFormat -Event $event
                }
                
                # Try to send to server
                $sent = Send-ToServer -Events $unifiedEvents
                
                # If failed, queue locally
                if (-not $sent) {
                    Add-ToLocalQueue -Events $unifiedEvents
                }
            } else {
                Write-AgentLog "No new events found" -Level DEBUG
            }
            
            # Process queued batches
            $queuedBatches = Get-QueuedBatches
            if ($queuedBatches.Count -gt 0) {
                Write-AgentLog "Processing $($queuedBatches.Count) queued batches..." -Level INFO
                
                foreach ($batch in $queuedBatches) {
                    try {
                        $queueData = Get-Content $batch.FullName -Raw | ConvertFrom-Json
                        $sent = Send-ToServer -Events $queueData.events
                        
                        if ($sent) {
                            Remove-QueuedBatch -FilePath $batch.FullName
                            Write-AgentLog "Sent queued batch: $($batch.Name)" -Level INFO
                        } else {
                            break  # Stop processing queue if server is still unavailable
                        }
                    } catch {
                        Write-AgentLog "Error processing queued batch: $($_.Exception.Message)" -Level ERROR
                    }
                }
            }
            
            # Update last collection time
            Set-LastCollectionTime -Timestamp $now
            
            # Wait before next collection
            Write-AgentLog "Waiting $($config.CollectionInterval) seconds until next collection...`n" -Level DEBUG
            Start-Sleep -Seconds $config.CollectionInterval
            
        } catch {
            Write-AgentLog "Error in collection loop: $($_.Exception.Message)" -Level ERROR
            Write-AgentLog "Waiting 30 seconds before retry..." -Level WARN
            Start-Sleep -Seconds 30
        }
    }
}

# ============================================================================
# TEST MODE
# ============================================================================

function Test-Agent {
    Write-Host "`n=== SIEM Agent Test Mode ===" -ForegroundColor Cyan
    
    # Test 1: Check permissions
    Write-Host "`n[TEST 1] Checking Administrator Permissions..." -ForegroundColor Yellow
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Write-Host "  ✓ Running as Administrator" -ForegroundColor Green
    } else {
        Write-Host "  ✗ NOT running as Administrator - some features may not work" -ForegroundColor Red
    }
    
    # Test 2: Check Event Log access
    Write-Host "`n[TEST 2] Testing Event Log Access..." -ForegroundColor Yellow
    foreach ($logConfig in $config.EventLogs) {
        try {
            $testEvents = Get-WinEvent -LogName $logConfig.LogName -MaxEvents 1 -ErrorAction Stop
            Write-Host "  ✓ Can access $($logConfig.LogName)" -ForegroundColor Green
        } catch {
            Write-Host "  ✗ Cannot access $($logConfig.LogName): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # Test 3: Collect sample events
    Write-Host "`n[TEST 3] Collecting Sample Events..." -ForegroundColor Yellow
    $sampleEvents = Get-SecurityEvents -StartTime (Get-Date).AddHours(-1) -MaxEvents 5
    Write-Host "  Found $($sampleEvents.Count) events in the last hour" -ForegroundColor $(if ($sampleEvents.Count -gt 0) { 'Green' } else { 'Yellow' })
    
    if ($sampleEvents.Count -gt 0) {
        Write-Host "`n  Sample Event:" -ForegroundColor Cyan
        $firstEvent = $sampleEvents[0]
        Write-Host "    Event ID: $($firstEvent.Id)"
        Write-Host "    Time: $($firstEvent.TimeCreated)"
        Write-Host "    Source: $($firstEvent.ProviderName)"
        Write-Host "    Level: $($firstEvent.LevelDisplayName)"
    }
    
    # Test 4: Test unified format conversion
    if ($sampleEvents.Count -gt 0) {
        Write-Host "`n[TEST 4] Testing Unified Format Conversion..." -ForegroundColor Yellow
        try {
            $unified = ConvertTo-UnifiedLogFormat -Event $sampleEvents[0]
            Write-Host "  ✓ Successfully converted to unified format" -ForegroundColor Green
            Write-Host "`n  Unified Log Sample:" -ForegroundColor Cyan
            $unified | ConvertFrom-Json | ConvertTo-Json | Write-Host
        } catch {
            Write-Host "  ✗ Conversion failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # Test 5: Test server connectivity
    Write-Host "`n[TEST 5] Testing Server Connectivity..." -ForegroundColor Yellow
    try {
        $testPayload = @{ test = "connection" } | ConvertTo-Json
        Invoke-RestMethod -Uri $config.ServerEndpoint -Method Post -Body $testPayload -ContentType "application/json" -TimeoutSec 5 -ErrorAction Stop | Out-Null
        Write-Host "  ✓ Server is reachable" -ForegroundColor Green
    } catch {
        Write-Host "  ✗ Server not reachable: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "    Events will be queued locally until server is available" -ForegroundColor Gray
    }
    
    # Test 6: Check directories
    Write-Host "`n[TEST 6] Checking Directories..." -ForegroundColor Yellow
    foreach ($dir in @($config.LocalQueuePath, $config.LocalLogPath)) {
        if (Test-Path $dir) {
            Write-Host "  ✓ $dir exists" -ForegroundColor Green
        } else {
            Write-Host "  ✗ $dir does not exist (will be created)" -ForegroundColor Yellow
        }
    }
    
    Write-Host "`n=== Test Complete ===" -ForegroundColor Cyan
    Write-Host "Ready to start collection? Run with -Start parameter`n" -ForegroundColor White
}

# ============================================================================
# ENTRY POINT
# ============================================================================

param(
    [switch]$Start,
    [switch]$Test
)

if ($Test) {
    Test-Agent
} elseif ($Start) {
    Start-LogCollection
} else {
    Write-Host "`nSIEM Log Collection Agent v$($config.AgentVersion)" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "`nUsage:" -ForegroundColor Yellow
    Write-Host "  .\LogCollectionAgent.ps1 -Test   # Run diagnostics"
    Write-Host "  .\LogCollectionAgent.ps1 -Start  # Start collecting logs"
    Write-Host "`nConfiguration:" -ForegroundColor Yellow
    Write-Host "  Server Endpoint: $($config.ServerEndpoint)"
    Write-Host "  Collection Interval: $($config.CollectionInterval) seconds"
    Write-Host "  Batch Size: $($config.BatchSize) events"
    Write-Host "`n"
}