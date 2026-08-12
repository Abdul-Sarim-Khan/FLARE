param([string]$PythonExe = "python", [switch]$NoExit)
$ErrorActionPreference = "Stop"
$FlareRoot = Split-Path -Parent $PSScriptRoot

Write-Host "`n[+] Installing agent dependencies..." -ForegroundColor Cyan
& $PythonExe -m pip install -r (Join-Path $FlareRoot "requirements_agent.txt")

Write-Host "`n[+] Running pywin32 system integration..." -ForegroundColor Cyan
# Required for Windows to natively recognize Python scripts as Services.
$postInstallScript = & $PythonExe -c "import sys, os; print(os.path.join(os.path.dirname(sys.executable), 'Scripts', 'pywin32_postinstall.py'))"
if (Test-Path $postInstallScript) {
    # The post-install tries to REPLACE the pywin32 system DLLs, which fails with
    # an "Access is denied" Python traceback whenever one of those DLLs is already
    # loaded/locked (by a running agent, or by python itself). That's harmless -
    # pywin32 is already integrated. Suppress the post-install's noisy output and
    # judge success by whether pywin32 actually imports, not by its exit code.
    $eap = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    & $PythonExe $postInstallScript -install -quiet 2>$null | Out-Null
    & $PythonExe -c "import win32evtlog, pywintypes" 2>$null | Out-Null
    $pywin32Ok = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = $eap
    if ($pywin32Ok) {
        Write-Host "      OK  pywin32 already integrated (host event-log access available)." -ForegroundColor Green
    } else {
        Write-Host "      WARN pywin32 failed to import - host detection may not work." -ForegroundColor Yellow
        Write-Host "           Stop the FLARE agent, then run:  $PythonExe `"$postInstallScript`" -install" -ForegroundColor DarkGray
    }
} else {
    Write-Host "      WARN pywin32_postinstall.py not found. Service might fail if DLLs are missing." -ForegroundColor Yellow
}

Write-Host "`n[+] Enabling Windows audit policies for FLARE host detection..." -ForegroundColor Cyan
# Filtering Platform Connection: generates Event 5156 (allowed) and 5157 (blocked)
# for every inbound TCP/UDP connection attempt. Required for port scan detection.
$auditResults = @(
    @{ sub = "Filtering Platform Connection"; desc = "Port scan detection (Event 5156/5157)" },
    @{ sub = "Filtering Platform Packet Drop";  desc = "Packet-level drop visibility (Event 5152)" },
    @{ sub = "Process Creation";                desc = "Process-creation logging (Event 4688)" }
)
foreach ($a in $auditResults) {
    $result = auditpol /set /subcategory:$($a.sub) /success:enable /failure:enable 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "      OK  $($a.desc)" -ForegroundColor Green
    } else {
        Write-Host "      WARN $($a.desc) - $result" -ForegroundColor Yellow
    }
}

# Include the full command line in 4688 events. Without this, command-line
# dependent rules (shadow-copy deletion / pre-ransomware, PowerShell download
# cradle, encoded execution) cannot fire — 4688 arrives with an empty CommandLine.
$cmdLineKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
try {
    if (-not (Test-Path $cmdLineKey)) { New-Item -Path $cmdLineKey -Force | Out-Null }
    Set-ItemProperty -Path $cmdLineKey -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
    Write-Host "      OK  Command line included in process-creation events (4688)" -ForegroundColor Green
} catch {
    Write-Host "      WARN Could not enable command-line capture in 4688 - $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "           Shadow-copy and PowerShell host rules may not fire on this host." -ForegroundColor DarkGray
}

Write-Host "`n[+] Creating required folders..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path (Join-Path $FlareRoot "certs") -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType Directory -Path (Join-Path $FlareRoot "logs") -Force -ErrorAction SilentlyContinue | Out-Null

Write-Host "`n[+] Configuring FLARE Auto-Boot Service..." -ForegroundColor Cyan
$svcScript = Join-Path $FlareRoot "flare_service.py"
if (Test-Path $svcScript) { 
    
    # Clean up existing service if you are re-running the setup
    if (Get-Service -Name "FLAREAgent" -ErrorAction SilentlyContinue) {
        Stop-Service -Name "FLAREAgent" -ErrorAction SilentlyContinue
        & $PythonExe $svcScript remove 2>&1 | Out-Null
        Start-Sleep -Seconds 2
    }

    # 1. Install the service into Windows SCM
    & $PythonExe $svcScript install | Out-Null
    
    # 2. Force it to run automatically on machine boot
    Set-Service -Name "FLAREAgent" -StartupType Automatic
    
    # 3. Configure Crash Recovery (Restart the agent automatically if it crashes)
    sc.exe failure "FLAREAgent" reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
    
    # 4. Start the service right now so you don't have to reboot
    Start-Service -Name "FLAREAgent"
    
    Write-Host "      OK  FLAREAgent service is installed, set to Auto-Boot, and Running in the background." -ForegroundColor Green
}

Write-Host "`nAgent setup complete!" -ForegroundColor Green