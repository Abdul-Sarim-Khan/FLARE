# FLARE v0.6 — Client Agent: Setup & Operation

This folder contains everything needed to run the FLARE endpoint agent on a
Windows workstation or server. Copy this entire `client\` folder to each
endpoint machine and follow the steps below.

---

## Folder contents

```
flare_agent.py          Main agent entry point (orchestrates all subsystems)
flare_service.py        Windows Service wrapper (install/start/stop/remove)
requirements_agent.txt  Python package list

proto/                  Protobuf schema v0.6 (shared with server — do not edit)
  log_schema.proto
  log_schema_pb2.py

host/                   Host rule engine
  host_engine.py        Windows Event Log subscriptions + rule evaluation
  ioc_loader.py         Loads IOC lists from ioc/
  rules.py              19 detection rules (Kerberoasting, LSASS, Pass-the-Hash, etc.)

network/                Network inference engine
  flare_network_infer.py  MLP classifier on CICFlowMeter flow CSV
  models/
    network_mlp.pkl         Trained MLP (hot-swapped by FL poll thread)
    network_mlp_weights.json  Current model weights
    network_scaler.pkl        StandardScaler for feature normalization

ioc/                    Threat intelligence lists (one entry per line)
  ioc_domains.txt
  ioc_ips.txt
  ioc_process_chains.txt
  ioc_process_names.txt

certs/                  mTLS certificate bundle (copy from server or auto-provisioned)
  ca.crt                FLARE CA certificate (copy from server/certs/ca.crt)
  client.crt            This agent's client certificate
  client.key            This agent's private key

logs/
  flare_agent.log       Rotating log (10 MB × 3 backups)

setup/
  0_run_all_setup.ps1   Runs all setup steps in one go
  1_grant_privileges.ps1  Grants OS privileges + creates working directory
  2_setup.ps1           Installs Python packages
  3_configure.ps1       Sets environment variables (server URL, cert paths, etc.)
```

---

## How it works

The agent starts the following subsystems on every endpoint:

| Subsystem | What it does |
|---|---|
| **Host rule engine** | Subscribes to Windows Event Log channels (Security, System, PowerShell). Evaluates 19 MITRE ATT&CK-mapped rules (Kerberoasting, LSASS dumping, Pass-the-Hash, PowerShell download cradles, etc.) and IOC list matching. |
| **Flow collector** | Runs CICFlowMeter in the background to capture live network traffic and write flow features to a CSV file. |
| **Network inference** | Reads new rows from the flow CSV every 30 seconds, runs the 34-feature MLP classifier, and queues alerts for any flows classified as ATTACK. |
| **Alert sender** | Batches alert events into Protobuf `AlertBatch` messages and POSTs them to the server over mTLS HTTPS. Buffers up to 500 alerts if the server is unreachable and retries with backoff. |
| **Heartbeat** | Sends a liveness ping to the server every 60 seconds including model version, alert counters, and subsystem health. |
| **FL poll** | Checks for a new global network model from the server every 6 hours. Hot-swaps the local MLP weights if a newer version is available. |

### Security model

All agent ↔ server communication uses **mutual TLS (mTLS)**:

- The agent verifies the server's certificate against the FLARE CA (`ca.crt`)
- The agent presents its own client certificate (`client.crt` + `client.key`)
- The server rejects any connection that doesn't present a valid cert

Certificates are provisioned per-machine from the server. Copy
`certs/ca.crt`, `client.crt`, and `client.key` from the server's
`certs/clients/<hostname>/` folder to this machine's `certs/` folder,
or use the auto-provisioning flow (see below).

### Auto-discovery (no hardcoded IP needed)

If `FLARE_SERVER_URL` is not set (or is still the default `localhost`), the
agent listens on UDP port 37020 for up to 5 seconds at startup. The server
broadcasts its address every 3 seconds on the LAN — the agent picks it up
and connects automatically. No configuration required on a standard LAN.

Disable: `python flare_agent.py --no-beacon`

---

## Prerequisites

- Windows 10 / 11 or Windows Server 2016+
- Python 3.10 or later (add to PATH during install)
- Network access to the FLARE server on port 7331 (TCP)
- UDP port 37020 accessible for LAN discovery (inbound — receive only)

---

## First-time setup (run once per machine)

### Step 1 — Grant Windows privileges

Right-click `setup\1_grant_privileges.ps1` → **Run with PowerShell**.

UAC prompt will appear. The script:
- Adds your account to the **Event Log Readers** group
- Grants read access to the Security event log channel
- Creates the working directory (`C:\FLARE\` by default)
- Adds an outbound firewall allow rule for port 7331

Press Enter when it finishes.

### Step 2 — Install Python dependencies

Right-click `setup\2_setup.ps1` → **Run with PowerShell**.

Installs all packages from `requirements_agent.txt` and runs the pywin32
post-install hook needed for Windows Event Log access.

### Step 3 — Configure the agent

Right-click `setup\3_configure.ps1` → **Run with PowerShell**, then type `agent`.

| Setting | Description | Example |
|---|---|---|
| Server URL | FLARE server HTTPS URL | `https://192.168.1.10:7331` |
| CA cert path | Path to `ca.crt` | `certs\ca.crt` (relative, auto-resolved) |
| Client cert path | Path to `client.crt` | `certs\client.crt` |
| Client key path | Path to `client.key` | `certs\client.key` |
| Network CSV path | Where the flow collector writes | `C:\FLARE\net_flows.csv` |
| Log level | Verbosity | `INFO` |

Saved as Machine-scope environment variables, picked up automatically by the
Windows Service.

> **Tip:** If you leave the server URL as `localhost`, the agent will attempt
> LAN beacon discovery on startup and configure itself automatically.

---

## Running the agent

### Option A — Manual (foreground, best for testing)

```powershell
cd "path\to\client"
python flare_agent.py
```

Logs print to the terminal. Press `Ctrl+C` to stop.

Additional flags:

```powershell
python flare_agent.py --server https://192.168.1.10:7331   # explicit server
python flare_agent.py --no-beacon                          # skip LAN discovery
python flare_agent.py --no-net-capture                     # host-only, skip network capture
python flare_agent.py --log-level DEBUG                    # verbose output
```

### Option B — Windows Service (recommended for production)

Survives logouts, reboots, and session changes.

```powershell
# Run PowerShell as Administrator
cd "path\to\client"
python flare_service.py install
python flare_service.py start
```

The service appears in `services.msc` as **FLARE v0.6 Endpoint Agent**.

Other service commands:

```powershell
python flare_service.py status    # show running/stopped
python flare_service.py stop
python flare_service.py restart
python flare_service.py debug     # run in foreground (Ctrl-C to stop)
python flare_service.py remove    # uninstall
```

Log file: `logs\flare_agent.log`

### Option C — Run at login (no service install)

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

## Skipping network capture (`--no-net-capture`)

On machines where packet capture is not possible (locked-down endpoints, VMs
without promiscuous mode access, or the server host itself), the flow collector
and network inference engine can be disabled entirely:

```powershell
python flare_agent.py --no-net-capture
```

Or in `agent.env`:

```
FLARE_NO_NET_CAPTURE=1
```

The host rule engine and all other subsystems continue running normally. The
heartbeat will report `net_track_ok: false` (accurate — it isn't running).

---

## Verifying the agent is working

1. Open the FLARE dashboard: `https://<server-ip>:7331`
2. Log in with the credentials set during server setup
3. Go to the **Clients** tab
4. Your machine name should appear as **Online** within 60 seconds

If it does not appear:
- Check `logs\flare_agent.log` (service mode) or your terminal (manual mode)
- Confirm `FLARE_SERVER_URL` is set correctly:
  ```powershell
  [System.Environment]::GetEnvironmentVariable("FLARE_SERVER_URL","Machine")
  ```
- Test connectivity: `Invoke-WebRequest https://<server-ip>:7331/ -UseBasicParsing`
- Check that `certs\ca.crt`, `certs\client.crt`, and `certs\client.key` exist

---

## Updating the agent

```powershell
python flare_service.py stop
# Replace files in this folder
python flare_service.py start
```

The FL poll thread handles model updates automatically — no manual action needed
when the server issues a new global model.

---

## Uninstalling

```powershell
.\uninstall_client.ps1
```

This stops and removes the `FLAREAgent` service, removes Machine-scope
environment variables, reverts audit policies and event log ACLs, and removes
the outbound firewall rule. Python packages and project files are left intact.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Service won't start | Check `logs\flare_agent.log` for import errors |
| "Access denied" reading Security log | Re-run `setup\1_grant_privileges.ps1` as Administrator |
| No network alerts | Confirm the flow collector is running and writing to the CSV path |
| mTLS error / server rejects connection | Check `certs\ca.crt`, `client.crt`, and `client.key` exist and are from the FLARE CA |
| Agent connects but no alerts | Normal — no rules fired and no attack traffic detected |
| `win32api` import error | Re-run `setup\2_setup.ps1` (pywin32 postinstall hook needed) |
| Agent shows Offline in dashboard | Heartbeat is every 60 s; offline threshold is 180 s — check server URL and network |
| Beacon discovery times out | Check UDP/37020 is not blocked by a firewall; try `--server https://<ip>:7331` instead |
| High CPU from host engine | Check `logs\flare_agent.log` for a looping rule; contact your FLARE admin |
