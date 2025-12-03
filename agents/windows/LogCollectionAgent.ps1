param([switch]$Start)

$LogName = "Security"
$StateFile = "C:\FLARE-data\Data\agent_state.json"
$LogsFile = "C:\FLARE-data\Logs\logs.json"
$BatchSize = 100

function Get-EventProperty {
    param($XmlContent, $PropertyName)
    return ($XmlContent.Event.EventData.Data | Where-Object { $_.Name -eq $PropertyName }).'#text'
}

function Start-Collection {
    if (-not (Test-Path "C:\FLARE-data\Logs")) { New-Item -ItemType Directory -Path "C:\FLARE-data\Logs" -Force | Out-Null }
    if (-not (Test-Path "C:\FLARE-data\Data")) { New-Item -ItemType Directory -Path "C:\FLARE-data\Data" -Force | Out-Null }

    $lastRecordId = 0
    if (Test-Path $StateFile) { try { $state = Get-Content $StateFile | ConvertFrom-Json; $lastRecordId = $state.LastRecordId } catch { $lastRecordId = 0 } }

    $query = "*[System[(EventID=4624 or EventID=4625) and EventRecordID > $lastRecordId]]"
    
    try {
        $events = Get-WinEvent -LogName $LogName -FilterXPath $query -MaxEvents $BatchSize -ErrorAction SilentlyContinue 
        if ($events) {
            $events = $events | Sort-Object TimeCreated
            $parsedLogs = @()
            foreach ($evt in $events) {
                $xml = [xml]$evt.ToXml()
                $parsedLogs += @{
                    Timestamp = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    EventID   = $evt.Id
                    User      = Get-EventProperty -XmlContent $xml -PropertyName "TargetUserName"
                    LogonType = Get-EventProperty -XmlContent $xml -PropertyName "LogonType"
                    Status    = if ($evt.Id -eq 4624) { "Authorized" } else { "Unauthorized" }
                }
            }
            $currentContent = @()
            if (Test-Path $LogsFile) { try { $currentContent = Get-Content $LogsFile | ConvertFrom-Json } catch {} }
            if ($currentContent -is [System.Array]) { $currentContent += $parsedLogs } else { $currentContent = @($currentContent) + $parsedLogs }
            
            $currentContent | ConvertTo-Json -Depth 3 | Set-Content $LogsFile
            @{ LastRecordId = $events[-1].RecordId } | ConvertTo-Json | Set-Content $StateFile
        }
    } catch {}
}
Start-Collection