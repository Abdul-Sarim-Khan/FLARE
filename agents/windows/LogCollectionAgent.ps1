param([switch]$Start)

$LogName = "Security"
$IncomingFile = "C:\FLARE-data\Logs\incoming.json"
$StateFile = "C:\FLARE-data\Data\agent_state.json"
$BatchSize = 100

function Get-EventProperty {
    param($XmlContent, $PropertyName)
    $val = ($XmlContent.Event.EventData.Data | Where-Object { $_.Name -eq $PropertyName }).'#text'
    if (-not $val) { return "N/A" }
    return $val
}

function Invoke-LogCollection {
    # Ensure directories exist
    if (-not (Test-Path "C:\FLARE-data\Logs")) { New-Item -ItemType Directory -Path "C:\FLARE-data\Logs" -Force | Out-Null }
    if (-not (Test-Path "C:\FLARE-data\Data")) { New-Item -ItemType Directory -Path "C:\FLARE-data\Data" -Force | Out-Null }

    $lastRecordId = 0
    if (Test-Path $StateFile) { 
        try { 
            $state = Get-Content $StateFile | ConvertFrom-Json
            $lastRecordId = $state.LastRecordId 
        } catch { 
            $lastRecordId = 0 
        } 
    }

    $new_logs = @()

    # 1. System Logs Collection
    $query = "*[System[(EventID=4624 or EventID=4625 or EventID=4688 or EventID=4720 or EventID=4672) and EventRecordID > $lastRecordId]]"
    try {
        $events = Get-WinEvent -LogName $LogName -FilterXPath $query -MaxEvents $BatchSize -ErrorAction SilentlyContinue 
        if ($events) {
            $events = $events | Sort-Object TimeCreated
            foreach ($evt in $events) {
                $xml = [xml]$evt.ToXml()
                $process = "N/A"
                $logonType = "0"

                if ($evt.Id -eq 4688) { 
                    $process = Get-EventProperty -XmlContent $xml -PropertyName "NewProcessName" 
                } else {
                    $logonType = Get-EventProperty -XmlContent $xml -PropertyName "LogonType"
                }
                
                $new_logs += @{
                    Type      = "System"
                    Timestamp = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    EventID   = $evt.Id
                    User      = Get-EventProperty -XmlContent $xml -PropertyName "TargetUserName"
                    LogonType = $logonType
                    Process   = $process
                }
            }
            # Save state
            @{ LastRecordId = $events[-1].RecordId } | ConvertTo-Json | Set-Content $StateFile
        }
    } catch {
        # Silent fail intended for background tasks
    }

    # 2. Network Snapshot Collection
    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Select-Object RemoteAddress, RemotePort, LocalAddress
        foreach ($c in $conns) {
            if ($c.RemoteAddress -match "^127\.|^::1") { continue }
            
            $new_logs += @{
                Type      = "Network"
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Source    = $c.LocalAddress
                DestIP    = $c.RemoteAddress
                DestPort  = $c.RemotePort
                FlowBytes = 0
            }
        }
    } catch {
        # Silent fail intended
    }

    # 3. Append to Incoming File
    if ($new_logs.Count -gt 0) {
        $currentBuffer = @()
        try { 
            if (Test-Path $IncomingFile) { 
                $content = Get-Content $IncomingFile -ErrorAction Stop
                if ($content) {
                    $currentBuffer = $content | ConvertFrom-Json 
                }
            }
        } catch { 
            $currentBuffer = @() 
        }

        if ($currentBuffer -isnot [System.Array]) { $currentBuffer = @($currentBuffer) }
        $currentBuffer += $new_logs
        
        try { 
            $currentBuffer | ConvertTo-Json -Depth 3 | Set-Content $IncomingFile -Force 
        } catch {}
    }
}

Invoke-LogCollection