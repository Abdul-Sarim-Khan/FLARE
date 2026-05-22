# FLARE v0.4 — Client Agent: Setup & Operation

This folder contains everything needed to run the FLARE endpoint agent on a
Windows workstation. Copy this entire folder to the client machine and follow
the steps below.

---

## Folder contents

```
flare_agent.py          Main agent entry point
flare_service.py        Windows Service wrapper
requirements.txt        Python package list

proto/                  Protobuf schema (shared with server — do not edit)
  log_schema.proto
  log_schema_pb2.py

host/                   Host rule engine
  host_engine.py        Windows Event Log subscriptions + rule evaluation
  ioc_loader.py         Loads IOC lists from ioc/
  rules.py              19 detection rules (Kerberoasting, LSASS, etc.)

network/                Network inference engine
  flare_network_infer.py  XGBoost classifier on pktmon flow CSV
  models/
    xgboost_34f.json    Trained XGBoost model (34 features)
    scaler_34f.pkl      StandardScaler fitted to training data
    feature_names.json  Ordered list of 34 feature names

ioc/                    Threat intelligence lists (plain text, one entry per line)
  ioc_domains.txt
  ioc_ips.txt
  ioc_process_chains.txt
  ioc_process_names.txt

network/models/         Federated Learning MLP (hot-swapped by FL-Poll thread)
  network_mlp.pkl
  network_mlp_weights.json
  network_scaler.pkl

setup/
  1_grant_privileges.ps1   Adds privileges + creates C:\FLARE\  (run first)
  2_setup.ps1              Installs Python packages
  3_configure.ps1          Sets environment variables
```

---

## Prerequisites

- Windows 10 / 11 or Windows Server 2016+
- Python 3.10 or later (add to PATH during install)
- Network access to the FLARE server on port 7331

---

## First-time setup (run once per machine)

### Step 1 — Grant Windows privileges

Right-click `setup\1_grant_privileges.ps1` and choose **Run with PowerShell**.

The script self-elevates (UAC prompt will appear). It:
- Adds your account to the **Event Log Readers** group
- Grants read access on the Security event log channel
- Creates `C:\FLARE\` working directory
- Adds an outbound firewall rule for port 7331

Press Enter when it finishes.

### Step 2 — Install Python dependencies

Right-click `setup\2_setup.ps1` and choose **Run with PowerShell**.

Installs all packages from `requirements.txt` and runs the pywin32
post-install hook needed for Windows Event Log access.

Press Enter when it finishes.

### Step 3 — Configure the agent

Right-click `setup\3_configure.ps1` and choose **Run with PowerShell**.

When asked for mode, type: `agent`

You will be prompted for:

| Setting | Description | Example |
|---|---|---|
| Server URL | Full HTTP URL of the FLARE server | `http://192.168.1.100:7331` |
| Network CSV path | Where pktmon writes flow data | `C:\FLARE\net_flows.csv` (default) |
| Log level | Verbosity | `INFO` (default) |

These are saved as Machine-scope environment variables and are picked up
automatically when the agent runs as a Windows Service.

---

## Start the network flow collector

The network ML model reads a CSV of live network flows written by pktmon.
You must start this collector before the agent will produce network alerts.

Open **PowerShell as Administrator** and run:

```powershell
cd "path\to\this\folder\network"
.\flare_net_collector_full.ps1 -OutputPath C:\FLARE\net_flows.csv
```

Keep this window open. To automate it on boot, create a Scheduled Task
pointing at this script with Administrator rights.

> **Note:** if `flare_net_collector_full.ps1` is not present, the network
> inference engine will still run but will silently find no new rows until
> the CSV appears.

---

## Running the agent

### Option A — Manual (foreground, best for testing)

```powershell
cd "path\to\this\folder"
python flare_agent.py
```

Logs print to the terminal. Press `Ctrl+C` to stop.

### Option B — Windows Service (recommended for production)

Survives logouts, reboots, and session changes.

```powershell
# Run PowerShell as Administrator
cd "path\to\this\folder"
python flare_service.py install
sc start FLAREAgent
```

The service appears in `services.msc` as **FLARE v0.4 Endpoint Agent**.

Check it is running:

```powershell
sc query FLAREAgent
```

Read the live log:

```powershell
Get-Content C:\FLARE\flare_agent.log -Wait -Tail 40
```

Stop / uninstall:

```powershell
sc stop FLAREAgent
python flare_service.py remove
```

### Option C — Run at login (no service, simpler)

```powershell
$startup = [Environment]::GetFolderPath("Startup")
$wsh = New-Object -ComObject WScript.Shell
$s   = $wsh.CreateShortcut("$startup\FLARE Agent.lnk")
$s.TargetPath  = "python"
$s.Arguments   = "`"$(Resolve-Path flare_agent.py)`""
$s.WindowStyle = 7
$s.Save()
```

---

## Verifying the agent is working

1. Open the FLARE dashboard: `http://<server-ip>:7331`
2. Log in with the credentials set during server setup
3. Go to the **Clients** tab
4. Your machine should appear as **Online** within 60 seconds

If it does not appear:
- Check `C:\FLARE\flare_agent.log` (Service mode) or your terminal (manual mode)
- Confirm `FLARE_SERVER_URL` is set: `[System.Environment]::GetEnvironmentVariable("FLARE_SERVER_URL","Machine")`
- Test connectivity: `Invoke-WebRequest http://<server-ip>:7331/ -UseBasicParsing`

---

## Updating the agent

1. Stop the service: `sc stop FLAREAgent`
2. Replace the files in this folder
3. Start the service: `sc start FLAREAgent`

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Service won't start | Check `C:\FLARE\flare_agent.log` for import errors |
| "Access denied" reading Security log | Re-run `setup\1_grant_privileges.ps1` |
| No network alerts ever | Confirm the pktmon collector is running and writing to `C:\FLARE\net_flows.csv` |
| Agent connects but no alerts | Normal — no rules fired and no attack traffic detected |
| `win32api` import error | Re-run `setup\2_setup.ps1` (pywin32 postinstall needed) |
| Agent shows Offline in dashboard | Check the server URL — agent heartbeat is every 60 s; offline threshold is 180 s |
| High CPU from host engine | Check `C:\FLARE\flare_agent.log` for a looping rule hit; contact your FLARE admin |
