# ============================================================
# FLARE Log Collection Agent
# Uses exact Windows XML field names verified from Event Viewer
# Must run as SYSTEM or Administrator
# ============================================================

$IncomingFile = "C:\FLARE-data\Logs\incoming.json"
$StateFile    = "C:\FLARE-data\Data\agent_state.json"
$BatchSize    = 200

foreach ($dir in @("C:\FLARE-data\Logs", "C:\FLARE-data\Data")) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

# Enable audit policies silently
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable 2>$null | Out-Null
auditpol /set /subcategory:"Process Creation"             /success:enable /failure:enable 2>$null | Out-Null
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Output /t REG_DWORD /d 1 /f 2>$null | Out-Null

# ── Exact XML field extractor ────────────────────────────────
# Windows EventData uses exact names including spaces.
# e.g. "Source Address" NOT "SourceAddress", "New Process Name" NOT "NewProcessName"
function Get-Prop {
    param($Xml, [string]$Name)
    try {
        $node = $Xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name }
        if ($node) {
            $val = $node.InnerText
            if (-not $val) { $val = $node.'#text' }
            if ($val -and $val.Trim() -ne "") { return $val.Trim() }
        }
    } catch { }
    return "N/A"
}

function Invoke-LogCollection {

    $lastId = 0
    if (Test-Path $StateFile) {
        try { $lastId = (Get-Content $StateFile | ConvertFrom-Json).LastRecordId } catch { }
    }

    $new_logs = @()
    $maxId    = $lastId

    # ============================================================
    # SECTION 1 — SECURITY LOG EVENTS
    # All EventIDs from BOTSv3 WinEventLog:Security distribution
    # ============================================================
    $secIds   = "4624 or EventID=4625 or EventID=4627 or EventID=4648 or EventID=4659 or EventID=4663 or EventID=4670 or EventID=4672 or EventID=4673 or EventID=4688 or EventID=4689 or EventID=4697 or EventID=4698 or EventID=4700 or EventID=4702 or EventID=4720 or EventID=4726 or EventID=4732 or EventID=4776 or EventID=5156 or EventID=5157"
    $secQuery = "*[System[(EventID=$secIds) and EventRecordID > $lastId]]"

    try {
        $events = Get-WinEvent -LogName "Security" -FilterXPath $secQuery -MaxEvents $BatchSize -ErrorAction SilentlyContinue
        if ($events) {
            $events = $events | Sort-Object TimeCreated
            foreach ($evt in $events) {
                $xml = [xml]$evt.ToXml()
                $eid = $evt.Id

                # ── Base fields present on every event ───────────
                $entry = [ordered]@{
                    Type         = "System"
                    EventID      = $eid
                    Timestamp    = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    ComputerName = $evt.MachineName
                    RecordNumber = $evt.RecordId
                    TaskCategory = $evt.TaskDisplayName
                    Keywords     = if ($evt.Keywords) { $evt.Keywords.ToString() } else { "N/A" }
                }

                # ── Authentication events: 4624, 4625, 4627, 4648 ─
                if ($eid -in @(4624, 4625, 4627, 4648)) {
                    # Subject (who initiated)
                    $entry["SubjectUserName"]   = Get-Prop $xml "SubjectUserName"
                    $entry["SubjectDomainName"] = Get-Prop $xml "SubjectDomainName"
                    $entry["SubjectLogonId"]    = Get-Prop $xml "SubjectLogonId"
                    # Target (who logged on)
                    $entry["TargetUserName"]    = Get-Prop $xml "TargetUserName"
                    $entry["TargetDomainName"]  = Get-Prop $xml "TargetDomainName"
                    $entry["TargetLogonId"]     = Get-Prop $xml "TargetLogonId"
                    # Logon details
                    $entry["LogonType"]         = Get-Prop $xml "LogonType"
                    $entry["LogonProcessName"]  = Get-Prop $xml "LogonProcessName"
                    $entry["AuthPackage"]       = Get-Prop $xml "AuthenticationPackageName"
                    $entry["WorkstationName"]   = Get-Prop $xml "WorkstationName"
                    $entry["IpAddress"]         = Get-Prop $xml "IpAddress"
                    $entry["IpPort"]            = Get-Prop $xml "IpPort"
                    $entry["ImpersonationLevel"]= Get-Prop $xml "ImpersonationLevel"
                    $entry["ElevatedToken"]     = Get-Prop $xml "ElevatedToken"
                    $entry["TokenElevationType"]= Get-Prop $xml "TokenElevationType"
                }

                # ── Process events: 4688, 4689 ────────────────────
                # Verified field names from Event Viewer XML:
                #   "New Process Name"    (has space)
                #   "ParentProcessName"   (no space)
                #   "CommandLine"
                #   "MandatoryLabel"
                elseif ($eid -in @(4688, 4689)) {
                    $entry["SubjectUserName"]    = Get-Prop $xml "SubjectUserName"
                    $entry["SubjectDomainName"]  = Get-Prop $xml "SubjectDomainName"
                    $entry["SubjectLogonId"]     = Get-Prop $xml "SubjectLogonId"
                    $entry["NewProcessId"]       = Get-Prop $xml "NewProcessId"
                    $entry["NewProcessName"]     = Get-Prop $xml "New Process Name"      # space required
                    $entry["TokenElevationType"] = Get-Prop $xml "TokenElevationType"
                    $entry["MandatoryLabel"]     = Get-Prop $xml "MandatoryLabel"
                    $entry["CreatorProcessId"]   = Get-Prop $xml "ProcessId"
                    $entry["CreatorProcessName"] = Get-Prop $xml "ParentProcessName"     # no space
                    $entry["CommandLine"]        = Get-Prop $xml "CommandLine"
                }

                # ── Privilege events: 4672, 4673 ──────────────────
                elseif ($eid -in @(4672, 4673)) {
                    $entry["SubjectUserName"]  = Get-Prop $xml "SubjectUserName"
                    $entry["SubjectDomainName"]= Get-Prop $xml "SubjectDomainName"
                    $entry["SubjectLogonId"]   = Get-Prop $xml "SubjectLogonId"
                    $entry["PrivilegeList"]    = Get-Prop $xml "PrivilegeList"
                    $entry["ServiceName"]      = Get-Prop $xml "ServiceName"     # 4673 only
                }

                # ── Object access: 4659, 4663, 4670 ──────────────
                elseif ($eid -in @(4659, 4663, 4670)) {
                    $entry["SubjectUserName"]  = Get-Prop $xml "SubjectUserName"
                    $entry["SubjectDomainName"]= Get-Prop $xml "SubjectDomainName"
                    $entry["ObjectServer"]     = Get-Prop $xml "ObjectServer"
                    $entry["ObjectType"]       = Get-Prop $xml "ObjectType"
                    $entry["ObjectName"]       = Get-Prop $xml "ObjectName"
                    $entry["AccessMask"]       = Get-Prop $xml "AccessMask"
                    $entry["OldSd"]            = Get-Prop $xml "OldSd"      # 4670 only
                    $entry["NewSd"]            = Get-Prop $xml "NewSd"      # 4670 only
                }

                # ── Service install: 4697 ─────────────────────────
                elseif ($eid -eq 4697) {
                    $entry["SubjectUserName"] = Get-Prop $xml "SubjectUserName"
                    $entry["ServiceName"]     = Get-Prop $xml "ServiceName"
                    $entry["ImagePath"]       = Get-Prop $xml "ServiceFileName"   # exact name in 4697
                    $entry["ServiceType"]     = Get-Prop $xml "ServiceType"
                    $entry["StartType"]       = Get-Prop $xml "ServiceStartType"  # exact name in 4697
                    $entry["AccountName"]     = Get-Prop $xml "ServiceAccount"    # exact name in 4697
                }

                # ── Scheduled task: 4698, 4700, 4702 ─────────────
                elseif ($eid -in @(4698, 4700, 4702)) {
                    $entry["SubjectUserName"] = Get-Prop $xml "SubjectUserName"
                    $entry["TaskName"]        = Get-Prop $xml "TaskName"
                    $entry["TaskContent"]     = Get-Prop $xml "TaskContent"
                }

                # ── Account events: 4720, 4726, 4732 ─────────────
                elseif ($eid -in @(4720, 4726, 4732)) {
                    $entry["SubjectUserName"] = Get-Prop $xml "SubjectUserName"
                    $entry["TargetUserName"]  = Get-Prop $xml "TargetUserName"
                    $entry["SamAccountName"]  = Get-Prop $xml "SamAccountName"
                    $entry["GroupName"]       = Get-Prop $xml "TargetUserName"   # for 4732 group name
                }

                # ── NTLM: 4776 ───────────────────────────────────
                elseif ($eid -eq 4776) {
                    $entry["PackageName"]     = Get-Prop $xml "PackageName"
                    $entry["TargetUserName"]  = Get-Prop $xml "TargetUserName"
                    $entry["Workstation"]     = Get-Prop $xml "Workstation"
                    $entry["Status"]          = Get-Prop $xml "Status"
                }

                # ── WFP Network: 5156, 5157 ───────────────────────
                # Verified field names from Event Viewer XML (Image 2):
                #   "Source Address"      (space required)
                #   "Source Port"         (space required)
                #   "Destination Address" (space required)
                #   "Destination Port"    (space required)
                #   "Protocol"
                #   "Application Name"    (space required)
                elseif ($eid -in @(5156, 5157)) {
                    $entry["Direction"]        = Get-Prop $xml "Direction"
                    $entry["SourceAddress"]    = Get-Prop $xml "Source Address"       # space required
                    $entry["SourcePort"]       = Get-Prop $xml "Source Port"          # space required
                    $entry["DestIP"]           = Get-Prop $xml "Destination Address"  # space required
                    $entry["DestPort"]         = Get-Prop $xml "Destination Port"     # space required
                    $entry["Protocol"]         = Get-Prop $xml "Protocol"
                    $entry["AppPath"]          = Get-Prop $xml "Application Name"     # space required
                    $entry["LayerName"]        = Get-Prop $xml "Layer Name"           # space required
                    $entry["FilterRTID"]       = Get-Prop $xml "Filter Run-Time ID"
                }

                $new_logs += $entry
                if ($evt.RecordId -gt $maxId) { $maxId = $evt.RecordId }
            }
        }
    } catch { }

    # ── System log: EventID 7045 (service install) ────────────
    try {
        $sysQ = "*[System[EventID=7045 and EventRecordID > $lastId]]"
        $sysEvts = Get-WinEvent -LogName "System" -FilterXPath $sysQ -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($sysEvts) {
            foreach ($evt in $sysEvts) {
                $xml = [xml]$evt.ToXml()
                $new_logs += [ordered]@{
                    Type         = "System"
                    EventID      = $evt.Id
                    Timestamp    = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    ComputerName = $evt.MachineName
                    RecordNumber = $evt.RecordId
                    TaskCategory = "Service Installation"
                    ServiceName  = Get-Prop $xml "ServiceName"
                    ImagePath    = Get-Prop $xml "ImagePath"
                    ServiceType  = Get-Prop $xml "ServiceType"
                    StartType    = Get-Prop $xml "StartType"
                    AccountName  = Get-Prop $xml "AccountName"
                }
                if ($evt.RecordId -gt $maxId) { $maxId = $evt.RecordId }
            }
        }
    } catch { }

    # ============================================================
    # SECTION 2 — NETWORK SNAPSHOT (simple 6-field format)
    # ============================================================
    try {
        $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue
        foreach ($c in $conns) {
            if ($c.RemoteAddress -match "^127\.|^::1|^0\.0\.0\.0$") { continue }
            $new_logs += [ordered]@{
                Type      = "Network"
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Source    = $c.LocalAddress
                DestIP    = $c.RemoteAddress
                DestPort  = $c.RemotePort
                FlowBytes = 0
            }
        }
    } catch { }

    # ============================================================
    # SECTION 3 — DNS QUERY LOGS
    # ============================================================
    try {
        $dnsQ  = "*[System[EventID=3008 and EventRecordID > $lastId]]"
        $dnsEvts = Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" `
            -FilterXPath $dnsQ -MaxEvents 100 -ErrorAction SilentlyContinue
        if ($dnsEvts) {
            foreach ($evt in $dnsEvts) {
                $xml = [xml]$evt.ToXml()
                $new_logs += [ordered]@{
                    Type         = "DNS"
                    EventID      = $evt.Id
                    Timestamp    = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    ComputerName = $evt.MachineName
                    RecordNumber = $evt.RecordId
                    QueryName    = Get-Prop $xml "QueryName"
                    QueryType    = Get-Prop $xml "QueryType"
                    QueryStatus  = Get-Prop $xml "QueryStatus"
                    QueryResults = Get-Prop $xml "QueryResults"
                }
            }
        }
    } catch { }

    # ============================================================
    # SECTION 4 — POWERSHELL SCRIPT BLOCK LOGS
    # ============================================================
    try {
        $psQ  = "*[System[EventID=4104 and EventRecordID > $lastId]]"
        $psEvts = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" `
            -FilterXPath $psQ -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($psEvts) {
            foreach ($evt in $psEvts) {
                $xml  = [xml]$evt.ToXml()
                $text = Get-Prop $xml "ScriptBlockText"
                if ($text -ne "N/A" -and $text.Length -gt 500) {
                    $text = $text.Substring(0, 500) + "...[truncated]"
                }
                $new_logs += [ordered]@{
                    Type            = "PowerShell"
                    EventID         = $evt.Id
                    Timestamp       = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    ComputerName    = $evt.MachineName
                    RecordNumber    = $evt.RecordId
                    ScriptBlockId   = Get-Prop $xml "ScriptBlockId"
                    ScriptBlockText = $text
                    Path            = Get-Prop $xml "Path"
                    MessageNumber   = Get-Prop $xml "MessageNumber"
                    MessageTotal    = Get-Prop $xml "MessageTotal"
                }
            }
        }
    } catch { }

    # ============================================================
    # SECTION 5 — SAVE TO INCOMING FILE
    # ============================================================
    if ($new_logs.Count -gt 0) {
        $buf = @()
        try {
            if (Test-Path $IncomingFile) {
                $raw = Get-Content $IncomingFile -ErrorAction Stop
                if ($raw) { $buf = $raw | ConvertFrom-Json }
            }
        } catch { $buf = @() }

        if ($buf -isnot [System.Array]) { $buf = @($buf) }
        $buf += $new_logs

        try { $buf | ConvertTo-Json -Depth 5 | Set-Content $IncomingFile -Force } catch { }

        if ($maxId -gt $lastId) {
            @{ LastRecordId = $maxId } | ConvertTo-Json | Set-Content $StateFile
        }
    }
}

Invoke-LogCollection