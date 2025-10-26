# ⚙️ FLARE Log Collection Agent  
**by IU - Beaconers**




## 🧩 Overview
The **FLARE Log Collection Agent** is a lightweight **PowerShell-based system monitor** designed to collect, deduplicate, and locally archive **Windows Event Logs** in real-time.  
It serves as the **data collection module** of the [FLARE](https://github.com/IU-Beaconers/FLARE) platform, providing **clean, structured, and privacy-preserving** log data for analysis and threat detection.

---

## 🚀 Features
- ✅ Real-time Windows Event Log collection  
- ✅ Live display in PowerShell console with color-coded severity  
- ✅ Deduplication to avoid repetitive logs  
- ✅ Local JSON archiving (no network transmission)  
- ✅ Configurable batch size & interval  
- ✅ Persistent state between restarts  
- ✅ Runs automatically via Windows Scheduled Task  
- ✅ Lightweight & low resource usage  

---

## 🧱 Prerequisites

| Requirement | Description |
|--------------|-------------|
| **OS** | Windows 10/11 or Windows Server 2016+ |
| **PowerShell** | Version 5.1 or higher |
| **Permissions** | Administrator privileges required |
| **Storage** | Minimal disk space for archives and state files |

---

## ⚡ Quick Start

### 🔹 1. Installation
```powershell
# Run as Administrator
.\install.ps1
```

### 🔹 2. Test Agent
```powershell
.\LogCollectionAgent.ps1 -Test
```

### 🔹 3. Start Live Collection
```powershell
.\LogCollectionAgent.ps1 -Start
```
---
### ⚙️ Automated Installation
The install.ps1 script performs the following:

- Creates installation directory: C:\Program Files\FLARE\Agent
- Copies all agent files
- Creates data directories:
- C:\FLARE-data\Data
- C:\FLARE-data\Logs
- Configures Windows audit policies
- Registers a Windows Scheduled Task for auto startup
---

## 💾 Data Storage
### 📂 State Management
- File: C:\FLARE-data\Data\agent_state.json
- Tracks the last collected event to ensure deduplication.

### 🗃️ Log Archive
- File: C:\FLARE-data\Logs\logs.json
- Stores all collected logs in JSON format.

## 🧮 Collection Logic
### Process	Description
- Deduplication	Filters already collected events using RecordId
- Batch Processing	Collects logs in batches of N per cycle
- State Tracking	Saves last timestamp and RecordId
- Chronological Sorting	Ensures event order consistency

## 🧩 Scheduled Task Management
```powershell
# View task status
Get-ScheduledTask -TaskName "FLARELogCollectorAgent"
```

## 🧰 Agent Health
```powershell
.\LogCollectionAgent.ps1 -Test
```

## 📈 Performance
### Metric	Value
- CPU Usage	<2%
- Memory Usage	20–50 MB
- Archive Growth	~1–5 MB per 1,000 events
- Collection Interval	10 seconds (default)
- Batch Size	100 events per cycle

### 🛡️ Security & Compliance
- Operates locally — no external network transmission
- Requires Admin or SYSTEM privileges only
- Adheres to Windows Audit Policy for:
- Logon/Logoff
- Account Management
- Privilege Use
- All logs remain stored in C:\FLARE-data under secured ACL permissions.

## 🧰 Uninstallation
### 🔹 Complete Removal
```powershell
.\install.ps1 -Uninstall
```
#### Removes:

- Scheduled Task
- Installation directory
- Data & Log directories

### 🔹 Partial Cleanup
```powershell
Unregister-ScheduledTask -TaskName "FLARELogCollectorAgent" -Confirm:$false
Remove-Item "C:\FLARE-data" -Recurse -Force
```