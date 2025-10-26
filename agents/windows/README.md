# Windows Log Collection Agent

## Overview
Collects Windows security, system, and application logs and sends them to the SIEM backend server.

## Features
- ✅ Real-time log collection from Windows Event Logs
- ✅ Converts logs to unified JSON format
- ✅ Offline queueing when server unavailable
- ✅ Automatic retry mechanism
- ✅ Configurable via JSON file
- ✅ Low resource usage (<5% CPU, ~50MB RAM)

## Prerequisites
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or higher
- Administrator privileges
- Network connectivity to SIEM backend

## Installation

### Quick Install
```powershell
# Run as Administrator
.\install.ps1 -ServerEndpoint "http://your-siem-server:8000/api/logs/ingest"
```

### Manual Install
```powershell
# 1. Copy files to desired location
Copy-Item .\* -Destination "C:\SIEM\Agent\" -Recurse

# 2. Edit config.json with your server details
notepad "C:\SIEM\Agent\config.json"

# 3. Test the agent
.\LogCollectionAgent.ps1 -Test

# 4. Start collecting
.\LogCollectionAgent.ps1 -Start
```

## Configuration

Edit `config.json`:
```json
{
  "server": {
    "endpoint": "http://localhost:8000/api/logs/ingest",
    "timeout": 30
  },
  "agent": {
    "collection_interval": 10,
    "batch_size": 100
  }
}
```

### Key Settings:
- **endpoint**: URL of your SIEM backend API
- **collection_interval**: Seconds between log collections (default: 10)
- **batch_size**: Maximum events per batch (default: 100)

## Usage

### Test Mode
```powershell
.\LogCollectionAgent.ps1 -Test
```
Runs diagnostics to verify:
- Administrator permissions
- Event log access
- Server connectivity
- Configuration validity

### Start Collection
```powershell
.\LogCollectionAgent.ps1 -Start
```
Begins collecting logs in foreground. Press Ctrl+C to stop.

### Run as Service (After Installation)
```powershell
# Start
Start-ScheduledTask -TaskName "SIEMLogAgent"

# Stop
Stop-ScheduledTask -TaskName "SIEMLogAgent"

# Check status
Get-ScheduledTask -TaskName "SIEMLogAgent"
```

## Event Types Collected

### Security Events
- **4624**: Successful logon
- **4625**: Failed logon (brute force indicator)
- **4672**: Special privileges assigned (privilege escalation)
- **4720**: User account created
- **4732**: User added to security group
- **4740**: Account locked out

### System Events
- **7036**: Service state changes
- **7040**: Service startup type changed
- **1102**: Audit log cleared (tampering indicator)

### Application Events
- Warnings and Errors only

## Monitoring

### View Live Logs
```powershell
Get-Content C:\SIEM\Logs\agent_$(Get-Date -Format 'yyyyMMdd').log -Tail 20 -Wait
```

### Check Queue Status
```powershell
Get-ChildItem C:\SIEM\Queue\
```

### View Statistics
```powershell
# In the agent output
# Shows events collected, sent, queued
```

## Troubleshooting

### Agent Not Collecting Logs
```powershell
# Check if running as Administrator
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Verify audit policies
auditpol /get /category:*

# Enable required auditing
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

### Cannot Connect to Server
```powershell
# Test connectivity
Test-NetConnection -ComputerName your-server -Port 8000

# Check firewall
Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*SIEM*"}
```

### High CPU/Memory Usage
- Increase `collection_interval` in config.json
- Decrease `batch_size` in config.json
- Check for event storms in Windows logs

## Uninstallation
```powershell
.\install.ps1 -Uninstall
```

This will:
- Stop the agent
- Remove scheduled task
- Delete agent files
- Remove data directories (queued logs)

## Security Considerations

### Production Deployment
- ✅ Use HTTPS for server endpoint
- ✅ Implement certificate validation
- ✅ Use service account with minimal permissions
- ✅ Encrypt queued logs at rest
- ✅ Rotate log files regularly

### Network Security
- Agent uses outbound HTTP/HTTPS only
- No inbound ports required
- Compatible with corporate firewalls
- Supports proxy configuration (add to config.json)

## Performance

### Expected Resource Usage
- **CPU**: <5% (idle), <15% (peak)
- **Memory**: 50-100 MB
- **Network**: ~1-5 KB per event
- **Disk**: ~100 MB per day per agent

### Scaling
- Supports 100-500 events/second per agent
- Minimal impact on system performance
- Automatic throttling during high load

## Support

For issues or questions:
1. Check logs: `C:\SIEM\Logs\`
2. Run diagnostics: `.\LogCollectionAgent.ps1 -Test`
3. Review configuration: `config.json`
4. Contact: [Your team contact info]

## Version History

- **v1.0.0** - Initial release
  - Basic log collection
  - Offline queueing
  - JSON configuration

## License

[Your License Here]