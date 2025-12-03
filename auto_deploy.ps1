# Scans your subnet and pushes the agent
$Subnet = "192.168.1."  # <--- CHECK YOUR SUBNET
$SourcePath = ".\FLARE_Client_Installer"
$RemoteDest = "C:\Temp\FLARE_Install"
$creds = Get-Credential -UserName "Administrator" -Message "Enter Admin Creds"

1..254 | ForEach-Object {
    $ip = "$Subnet$_"
    if (Test-Connection -ComputerName $ip -Count 1 -Quiet) {
        Write-Host "Found: $ip" -ForegroundColor Green
        try {
            $s = New-PSSession -ComputerName $ip -Credential $creds -ErrorAction Stop
            Invoke-Command -Session $s -ScriptBlock { New-Item -ItemType Directory -Path $using:RemoteDest -Force }
            Copy-Item -Path "$SourcePath\*" -Destination "$RemoteDest" -ToSession $s -Recurse -Force
            Invoke-Command -Session $s -ScriptBlock { Set-Location $using:RemoteDest; .\install.ps1 }
            Remove-PSSession $s
            Write-Host "  -> Deployed!" -ForegroundColor Cyan
        } catch { Write-Host "  -> Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}