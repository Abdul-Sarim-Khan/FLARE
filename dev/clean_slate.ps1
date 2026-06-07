#Requires -Version 5.1
<#
.SYNOPSIS
    FLARE - Clean Slate
    Wipes all runtime data so the next agent/server run starts completely fresh.

.DESCRIPTION
    Clears:
      - Server DB  : alerts, clients, fl_updates, sessions  (fl_models kept)
                     This is what populates the dashboard -- wiping it gives a
                     blank Alerts tab and resets the Clients list.
      - Client CSV : net_flows.csv       -- raw pktmon flow data written by the
                                           collector and read by the infer engine.
                     net_flows.flare_offset -- byte-offset bookmark so the infer
                                           engine knows where it last stopped;
                                           must be deleted with the CSV or it
                                           will seek past the new header row.

    FL model weights are intentionally preserved.

.PARAMETER SkipDB
    Skip clearing the server database.

.PARAMETER SkipClient
    Skip clearing the client CSV files.

.EXAMPLE
    .\clean_slate.ps1
    .\clean_slate.ps1 -SkipDB
    .\clean_slate.ps1 -SkipClient
#>

param(
    [switch]$SkipDB,
    [switch]$SkipClient
)

$ErrorActionPreference = "Stop"

$Root       = Split-Path -Parent $MyInvocation.MyCommand.Path
$DbPath     = Join-Path $Root "server\data\flare.db"
$CsvPath    = Join-Path $Root "client\net_flows.csv"
$OffsetPath = Join-Path $Root "client\net_flows.flare_offset"

function Write-OK   { param($m) Write-Host "  [OK]  $m" -ForegroundColor Green }
function Write-Skip { param($m) Write-Host "  [--]  $m" -ForegroundColor DarkGray }
function Write-Warn { param($m) Write-Host "  [!!]  $m" -ForegroundColor Yellow }
function Write-Step { param($m) Write-Host "  $m"       -ForegroundColor Cyan }

Write-Host ""
Write-Host "  FLARE Clean Slate" -ForegroundColor White
Write-Host "  -----------------------------------------" -ForegroundColor DarkGray
Write-Host ""

# ── Safety: warn if FLARE processes are still running ────────────────────────
$pyProcs = Get-Process -Name "python","python3","pythonw" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match "flare_agent|flare_server|flare_service" }

if ($pyProcs) {
    Write-Warn "FLARE processes still running:"
    foreach ($p in $pyProcs) {
        Write-Host "       PID $($p.Id)  $($p.CommandLine)" -ForegroundColor Yellow
    }
    Write-Host ""
    $confirm = Read-Host "  Stop them and continue? [y/N]"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "  Aborted." -ForegroundColor Red
        exit 1
    }
    $pyProcs | Stop-Process -Force
    Start-Sleep -Milliseconds 500
    Write-OK "Processes stopped"
    Write-Host ""
}

# ── Stop pktmon if still capturing ───────────────────────────────────────────
$pktmon = Get-Process -Name "pktmon" -ErrorAction SilentlyContinue
if ($pktmon) {
    Write-Step "Stopping pktmon..."
    try { & pktmon stop 2>$null | Out-Null; Write-OK "pktmon stopped" }
    catch { Write-Warn "Could not stop pktmon: $_" }
}

# ── 1. Server database ────────────────────────────────────────────────────────
if ($SkipDB) {
    Write-Skip "Server DB skipped (-SkipDB)"
} elseif (-not (Test-Path $DbPath)) {
    Write-Skip "Server DB not found: $DbPath"
} else {
    Write-Step "Clearing server database..."

    # Write Python to a temp file — avoids all multiline/quoting issues with python -c
    $tmpPy = Join-Path $env:TEMP "flare_clean_slate.py"
    Set-Content -Path $tmpPy -Encoding UTF8 -Value @"
import sqlite3
conn = sqlite3.connect(r"$($DbPath -replace '\\', '\\\\')")
before = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
conn.execute("DELETE FROM alerts")
conn.execute("DELETE FROM clients")
conn.execute("DELETE FROM fl_updates")
conn.execute("DELETE FROM sessions")
conn.commit()
conn.close()
print("alerts cleared: " + str(before) + " rows removed")
"@

    try {
        $result = python $tmpPy 2>&1
        if ($LASTEXITCODE -ne 0) { throw $result }
        Write-OK $result
    } catch {
        Write-Warn "DB clear failed: $_"
    } finally {
        Remove-Item $tmpPy -ErrorAction SilentlyContinue
    }
}

# ── 2. Client network flow files ──────────────────────────────────────────────
if ($SkipClient) {
    Write-Skip "Client files skipped (-SkipClient)"
} else {
    Write-Step "Clearing client runtime files..."

    if (Test-Path $CsvPath) {
        $rows = (Get-Content $CsvPath | Measure-Object -Line).Lines - 1
        Remove-Item -Force $CsvPath
        Write-OK "net_flows.csv removed ($rows flow rows)"
    } else {
        Write-Skip "net_flows.csv not found"
    }

    if (Test-Path $OffsetPath) {
        Remove-Item -Force $OffsetPath
        Write-OK "net_flows.flare_offset removed"
    } else {
        Write-Skip "net_flows.flare_offset not found"
    }
}

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Done. Start the server then the agent for a clean run." -ForegroundColor Green
Write-Host ""
