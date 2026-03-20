param([switch]$Start)

# ============================================================
# FLARE Log Collection Agent
# Dataset-aligned: CICIDS2017 (network) + BOTSv3 (system)
# Strategy: collect WIDE now, prune to narrow after RF analysis
# ============================================================

$LogName     = "Security"
$IncomingFile = "C:\FLARE-data\Logs\incoming.json"
$StateFile    = "C:\FLARE-data\Data\agent_state.json"
$BatchSize    = 200   # increased - more data per cycle

function Get-EventProperty {
    param($XmlContent, $PropertyName)
    $val = ($XmlContent.Event.EventData.Data | Where-Object { $_.Name -eq $PropertyName }).'#text'
    if (-not $val) { return "N/A" }
    return $val
}

function Get-SystemProperty {
    param($XmlContent, $PropertyName)
    $val = ($XmlContent.Event.System.$PropertyName)
    if (-not $val) { return "N/A" }
    return $val
}

function Invoke-LogCollection {

    # --- Ensure directories ---
    foreach ($dir in @("C:\FLARE-data\Logs", "C:\FLARE-data\Data")) {
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    }

    # --- Load last record ID (deduplication) ---
    $lastRecordId = 0
    if (Test-Path $StateFile) {
        try {
            $state = Get-Content $StateFile | ConvertFrom-Json
            $lastRecordId = $state.LastRecordId
        } catch { $lastRecordId = 0 }
    }

    $new_logs = @()
    $maxRecordId = $lastRecordId

    # ================================================================
    # 1. SYSTEM LOGS – Wide collection aligned with BOTSv3 schema
    # ================================================================
    # EventIDs collected:
    #   4624  Successful logon
    #   4625  Failed logon
    #   4648  Explicit credential logon (pass-the-hash indicator)
    #   4672  Special privileges assigned
    #   4688  Process created
    #   4689  Process exited
    #   4698  Scheduled task created  (persistence)
    #   4700  Scheduled task enabled  (persistence)
    #   4702  Scheduled task updated  (persistence)
    #   4720  User account created    (backdoor)
    #   4726  User account deleted
    #   4732  Member added to local group (lateral movement)
    #   4776  NTLM credential validation
    #   7045  New service installed   (persistence) -- System log
    # ================================================================

    $securityEventIds = "4624 or EventID=4625 or EventID=4648 or EventID=4672 or EventID=4688 or EventID=4689 or EventID=4698 or EventID=4700 or EventID=4702 or EventID=4720 or EventID=4726 or EventID=4732 or EventID=4776"
    $securityQuery = "*[System[(EventID=$securityEventIds) and EventRecordID > $lastRecordId]]"

    try {
        $events = Get-WinEvent -LogName $LogName -FilterXPath $securityQuery -MaxEvents $BatchSize -ErrorAction SilentlyContinue
        if ($events) {
            $events = $events | Sort-Object TimeCreated
            foreach ($evt in $events) {
                $xml = [xml]$evt.ToXml()

                # --- Common fields (BOTSv3 aligned) ---
                $log = @{
                    Type                 = "System"
                    Timestamp            = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    EventID              = $evt.Id
                    ComputerName         = $evt.MachineName
                    RecordNumber         = $evt.RecordId
                    Keywords             = if ($evt.Keywords) { $evt.Keywords.ToString() } else { "N/A" }
                    TaskCategory         = $evt.TaskDisplayName
                    LogName              = $evt.LogName

                    # Subject (who did the action)
                    SubjectUserName      = Get-EventProperty -XmlContent $xml -PropertyName "SubjectUserName"
                    SubjectUserSid       = Get-EventProperty -XmlContent $xml -PropertyName "SubjectUserSid"
                    SubjectDomainName    = Get-EventProperty -XmlContent $xml -PropertyName "SubjectDomainName"
                    SubjectLogonId       = Get-EventProperty -XmlContent $xml -PropertyName "SubjectLogonId"

                    # Target (who was affected)
                    TargetUserName       = Get-EventProperty -XmlContent $xml -PropertyName "TargetUserName"
                    TargetUserSid        = Get-EventProperty -XmlContent $xml -PropertyName "TargetUserSid"
                    TargetDomainName     = Get-EventProperty -XmlContent $xml -PropertyName "TargetDomainName"
                    TargetLogonId        = Get-EventProperty -XmlContent $xml -PropertyName "TargetLogonId"

                    # Logon specifics (4624/4625/4648)
                    LogonType            = Get-EventProperty -XmlContent $xml -PropertyName "LogonType"
                    LogonProcessName     = Get-EventProperty -XmlContent $xml -PropertyName "LogonProcessName"
                    AuthPackage          = Get-EventProperty -XmlContent $xml -PropertyName "AuthenticationPackageName"
                    WorkstationName      = Get-EventProperty -XmlContent $xml -PropertyName "WorkstationName"
                    IpAddress            = Get-EventProperty -XmlContent $xml -PropertyName "IpAddress"
                    IpPort               = Get-EventProperty -XmlContent $xml -PropertyName "IpPort"
                    ImpersonationLevel   = Get-EventProperty -XmlContent $xml -PropertyName "ImpersonationLevel"
                    ElevatedToken        = Get-EventProperty -XmlContent $xml -PropertyName "ElevatedToken"
                    TokenElevationType   = Get-EventProperty -XmlContent $xml -PropertyName "TokenElevationType"

                    # Process specifics (4688/4689)
                    NewProcessId         = Get-EventProperty -XmlContent $xml -PropertyName "NewProcessId"
                    NewProcessName       = Get-EventProperty -XmlContent $xml -PropertyName "NewProcessName"
                    ParentProcessId      = Get-EventProperty -XmlContent $xml -PropertyName "ProcessId"
                    CreatorProcessName   = Get-EventProperty -XmlContent $xml -PropertyName "ParentProcessName"
                    CommandLine          = Get-EventProperty -XmlContent $xml -PropertyName "CommandLine"
                    MandatoryLabel       = Get-EventProperty -XmlContent $xml -PropertyName "MandatoryLabel"

                    # Privilege use (4672)
                    PrivilegeList        = Get-EventProperty -XmlContent $xml -PropertyName "PrivilegeList"

                    # Scheduled task (4698/4700/4702)
                    TaskName             = Get-EventProperty -XmlContent $xml -PropertyName "TaskName"
                    TaskContent          = Get-EventProperty -XmlContent $xml -PropertyName "TaskContent"

                    # Account events (4720/4726/4732)
                    SamAccountName       = Get-EventProperty -XmlContent $xml -PropertyName "SamAccountName"
                    GroupName            = Get-EventProperty -XmlContent $xml -PropertyName "GroupName"

                    # NTLM (4776)
                    PackageName          = Get-EventProperty -XmlContent $xml -PropertyName "PackageName"
                    Status               = Get-EventProperty -XmlContent $xml -PropertyName "Status"
                    FailureReason        = Get-EventProperty -XmlContent $xml -PropertyName "FailureReason"
                    SubStatus            = Get-EventProperty -XmlContent $xml -PropertyName "SubStatus"
                }

                $new_logs += $log
                if ($evt.RecordId -gt $maxRecordId) { $maxRecordId = $evt.RecordId }
            }
        }
    } catch {
        # Silent fail for background task
    }

    # --- Service installation (System log, EventID 7045) ---
    try {
        $sysQuery = "*[System[EventID=7045 and EventRecordID > $lastRecordId]]"
        $sysEvents = Get-WinEvent -LogName "System" -FilterXPath $sysQuery -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($sysEvents) {
            foreach ($evt in $sysEvents) {
                $xml = [xml]$evt.ToXml()
                $new_logs += @{
                    Type          = "System"
                    Timestamp     = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    EventID       = $evt.Id
                    TaskCategory  = "Service Installation"
                    ComputerName  = $evt.MachineName
                    RecordNumber  = $evt.RecordId
                    ServiceName   = Get-EventProperty -XmlContent $xml -PropertyName "ServiceName"
                    ImagePath     = Get-EventProperty -XmlContent $xml -PropertyName "ImagePath"
                    ServiceType   = Get-EventProperty -XmlContent $xml -PropertyName "ServiceType"
                    StartType     = Get-EventProperty -XmlContent $xml -PropertyName "StartType"
                    AccountName   = Get-EventProperty -XmlContent $xml -PropertyName "AccountName"
                }
            }
        }
    } catch { }

    # ================================================================
    # 2. NETWORK LOGS – Wide collection aligned with CICIDS2017 schema
    # ================================================================
    # CICIDS2017 key features and their PowerShell equivalents:
    #
    #   Destination Port        -> RemotePort
    #   Flow Duration           -> ConnectionDuration (seconds since create)
    #   Total Fwd Packets       -> not directly available (ETW needed for deep)
    #   Flow Bytes/s            -> approximated via OwningProcess perf counters
    #   Flow Packets/s          -> partially via Get-NetAdapterStatistics
    #   FIN/PSH/ACK Flag Count  -> TCP State transitions (proxy)
    #   Packet Length stats     -> via performance counters (proxy)
    #   Init_Win_bytes          -> not available without ETW/WFP
    #   Active/Idle Mean        -> approximated via State changes
    #   Attack Type label       -> (to be added by detection layer)
    #
    # We collect what PowerShell natively exposes, plus process context.
    # Deep packet stats require ETW (Windows Event Tracing) -- commented
    # below for future expansion.
    # ================================================================

    try {
        $now = Get-Date
        $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue

        # Get per-process network counters for bandwidth approximation
        $netStats = @{}
        try {
            $procNetData = Get-Process | Where-Object { $_.WorkingSet -gt 0 } |
                Select-Object Id, Name, CPU, WorkingSet, HandleCount
            foreach ($p in $procNetData) { $netStats[$p.Id] = $p }
        } catch { }

        foreach ($c in $conns) {
            # Skip loopback
            if ($c.RemoteAddress -match "^127\.|^::1|^0\.0\.0\.0$") { continue }

            # Resolve owning process
            $procName = "N/A"
            $procId   = $c.OwningProcess
            $procCpu  = 0.0
            $procMem  = 0
            try {
                $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
                if ($proc) {
                    $procName = $proc.Name
                    $procCpu  = [math]::Round($proc.CPU, 2)
                    $procMem  = $proc.WorkingSet
                }
            } catch { }

            # Duration proxy: CreationTime if available
            $durationSec = 0
            try {
                if ($c.CreationTime) {
                    $durationSec = [int]($now - $c.CreationTime).TotalSeconds
                }
            } catch { }

            # Map TCP state to flag approximation
            # ESTABLISHED=active data, TIME_WAIT=FIN exchange, CLOSE_WAIT=FIN received
            $finFlag = if ($c.State -in @("TIME_WAIT","CLOSE_WAIT","FIN_WAIT1","FIN_WAIT2")) { 1 } else { 0 }
            $ackFlag = if ($c.State -in @("ESTABLISHED","CLOSE_WAIT","FIN_WAIT2")) { 1 } else { 0 }

            $new_logs += @{
                Type             = "Network"
                Timestamp        = $now.ToString("yyyy-MM-dd HH:mm:ss")

                # CICIDS2017 aligned
                DestinationPort  = $c.RemotePort
                LocalPort        = $c.LocalPort
                SourceIP         = $c.LocalAddress
                DestIP           = $c.RemoteAddress
                Protocol         = "TCP"
                State            = $c.State.ToString()
                FlowDurationSec  = $durationSec

                # Flag proxies (exact counts need ETW/WFP)
                FINFlagProxy     = $finFlag
                ACKFlagProxy     = $ackFlag
                PSHFlagProxy     = if ($c.State -eq "ESTABLISHED") { 1 } else { 0 }

                # Process context (threat hunting value)
                OwningPID        = $procId
                OwningProcess    = $procName
                ProcessCPU       = $procCpu
                ProcessMemBytes  = $procMem

                # Initialisation window size (from SYN -- only in LISTEN/SYN states)
                # Accurate value requires WFP; proxy via state
                InitWinProxy     = if ($c.State -eq "ESTABLISHED" -and $durationSec -lt 5) { 1 } else { 0 }

                # Placeholder fields for ETW enrichment (filled by future agent)
                FlowBytesTotal   = 0
                FwdPackets       = 0
                BwdPackets       = 0
                PacketLenMean    = 0.0
                IATMeanMs        = 0.0
                ActiveMeanSec    = 0.0
                IdleMeanSec      = 0.0

                # Label placeholder (Detection layer fills this)
                AttackType       = "Unknown"
            }
        }
    } catch { }

    # ================================================================
    # 3. DNS QUERY LOGS – exfiltration / C2 detection
    # ================================================================
    # DNS logs require "Microsoft-Windows-DNS-Client/Operational" to be enabled.
    # Enable with: wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true
    # ================================================================
    try {
        $dnsQuery = "*[System[EventID=3008 and EventRecordID > $lastRecordId]]"
        $dnsEvents = Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" `
            -FilterXPath $dnsQuery -MaxEvents 100 -ErrorAction SilentlyContinue
        if ($dnsEvents) {
            foreach ($evt in $dnsEvents) {
                $xml = [xml]$evt.ToXml()
                $new_logs += @{
                    Type          = "DNS"
                    Timestamp     = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    EventID       = $evt.Id
                    ComputerName  = $evt.MachineName
                    RecordNumber  = $evt.RecordId
                    QueryName     = Get-EventProperty -XmlContent $xml -PropertyName "QueryName"
                    QueryType     = Get-EventProperty -XmlContent $xml -PropertyName "QueryType"
                    QueryStatus   = Get-EventProperty -XmlContent $xml -PropertyName "QueryStatus"
                    QueryResults  = Get-EventProperty -XmlContent $xml -PropertyName "QueryResults"
                    PID           = Get-SystemProperty -XmlContent $xml -PropertyName "ProcessID"
                }
            }
        }
    } catch { }

    # ================================================================
    # 4. POWERSHELL SCRIPT BLOCK LOGS – malware / LOLBaS detection
    # ================================================================
    # Requires: Set-ItemProperty HKLM:\...\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 1
    # EventID 4104 = script block executed
    # ================================================================
    try {
        $psQuery = "*[System[EventID=4104 and EventRecordID > $lastRecordId]]"
        $psEvents = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" `
            -FilterXPath $psQuery -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($psEvents) {
            foreach ($evt in $psEvents) {
                $xml = [xml]$evt.ToXml()
                # Truncate script block to 500 chars to keep JSON manageable
                $scriptText = Get-EventProperty -XmlContent $xml -PropertyName "ScriptBlockText"
                if ($scriptText -ne "N/A" -and $scriptText.Length -gt 500) {
                    $scriptText = $scriptText.Substring(0, 500) + "...[truncated]"
                }
                $new_logs += @{
                    Type           = "PowerShell"
                    Timestamp      = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    EventID        = $evt.Id
                    ComputerName   = $evt.MachineName
                    RecordNumber   = $evt.RecordId
                    ScriptBlockId  = Get-EventProperty -XmlContent $xml -PropertyName "ScriptBlockId"
                    ScriptBlockText = $scriptText
                    Path           = Get-EventProperty -XmlContent $xml -PropertyName "Path"
                    MessageNumber  = Get-EventProperty -XmlContent $xml -PropertyName "MessageNumber"
                    MessageTotal   = Get-EventProperty -XmlContent $xml -PropertyName "MessageTotal"
                }
            }
        }
    } catch { }

    # ================================================================
    # 5. APPEND TO INCOMING FILE
    # ================================================================
    if ($new_logs.Count -gt 0) {
        $currentBuffer = @()
        try {
            if (Test-Path $IncomingFile) {
                $content = Get-Content $IncomingFile -ErrorAction Stop
                if ($content) { $currentBuffer = $content | ConvertFrom-Json }
            }
        } catch { $currentBuffer = @() }

        if ($currentBuffer -isnot [System.Array]) { $currentBuffer = @($currentBuffer) }
        $currentBuffer += $new_logs

        try {
            $currentBuffer | ConvertTo-Json -Depth 5 | Set-Content $IncomingFile -Force
        } catch { }

        # Save state (only advance if we read security events)
        if ($maxRecordId -gt $lastRecordId) {
            @{ LastRecordId = $maxRecordId } | ConvertTo-Json | Set-Content $StateFile
        }
    }
}

Invoke-LogCollection
