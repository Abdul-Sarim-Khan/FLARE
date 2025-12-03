#Requires -RunAsAdministrator
param(
    [switch]$Open,
    [switch]$Close
)

Write-Host ""
Write-Host "=== FLARE Firewall Manager ===" -ForegroundColor Cyan

# Rule Names (consistent everywhere)
$rules = @(
    "FLARE Beacon",
    "FLARE Beacon In",
    "FLARE API"
)

# ===============================
# OPEN FIREWALL FOR DEMO
# ===============================
if ($Open) {
    Write-Host "🔓 Opening FLARE Firewall Ports..." -ForegroundColor Yellow

    # Beacon (UDP Discovery)
    New-NetFirewallRule -DisplayName "FLARE Beacon"    -Direction Outbound -Protocol UDP -LocalPort 37020 -Action Allow -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "FLARE Beacon In" -Direction Inbound  -Protocol UDP -LocalPort 37020 -Action Allow -ErrorAction SilentlyContinue | Out-Null

    # API (Server Communication)
    New-NetFirewallRule -DisplayName "FLARE API"       -Direction Inbound  -Protocol TCP -LocalPort 8000  -Action Allow -ErrorAction SilentlyContinue | Out-Null

    Write-Host "✅ FLARE Firewall Rules Applied" -ForegroundColor Green
    Write-Host "   - UDP 37020 IN/OUT allowed"
    Write-Host "   - TCP 8000 IN allowed"
    exit
}

# ===============================
# CLOSE FIREWALL (RESTORE SECURITY)
# ===============================
if ($Close) {
    Write-Host "🔒 Removing FLARE Firewall Rules..." -ForegroundColor Yellow

    foreach ($rule in $rules) {
        Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
    }

    Write-Host "📌 Restoring Private Firewall Profile..." -ForegroundColor Yellow
    Set-NetFirewallProfile -Profile Private -Enabled "True"

    Write-Host "✅ Security Restored. FLARE ports are now closed." -ForegroundColor Green
    exit
}

# ===============================
# HELP MESSAGE
# ===============================
Write-Host ""
Write-Host "Usage:" -ForegroundColor Yellow
Write-Host "  ./Firewall_Manage.ps1 -Open    # Open required FLARE ports for demo"
Write-Host "  ./Firewall_Manage.ps1 -Close   # Remove ports and restore security"
Write-Host ""
