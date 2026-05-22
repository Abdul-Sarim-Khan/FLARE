# FLARE v0.4 — Server: Setup & Operation

This folder contains everything needed to run the FLARE server on a Windows
machine. Copy this entire folder to the server machine and follow the steps
below.

---

## Folder contents

```
flare_server.py          Server entry point (FastAPI + SQLite)
requirements_server.txt  Python package list
generate_cert.py         TLS certificate generator (called by 1_setup.ps1)
start_server.bat         One-click server start script

certs/                  TLS certificate + key (generated during setup, gitignored)
  flare_server.crt
  flare_server.key

proto/                  Protobuf schema (shared with agents -- do not edit)
  log_schema.proto
  log_schema_pb2.py

ui/
  index.html            Dashboard single-page app (served by the server)

network/models/
  network_mlp_weights.json   Initial FL model weights (seeds fl_models table)

setup/
  0_run_all_setup.ps1   Runs all setup steps in one go
  1_setup.ps1           Installs Python packages + generates TLS cert
  2_configure.ps1       Sets dashboard credentials, port, and cert paths
```

The server creates these at runtime (not included, created automatically):

```
data/
  flare.db              SQLite database (alerts, clients, FL state, log requests)
  server.env            Environment variable snapshot (written by 2_configure.ps1)
```

---

## Prerequisites

- Windows 10 / 11 or Windows Server 2016+
- Python 3.10 or later (add to PATH during install)
- Open port 7331 inbound (or whatever port you choose)

---

## First-time setup (run once)

### Step 1 — Install Python dependencies

Right-click `setup\1_setup.ps1` and choose **Run with PowerShell**.

Installs all packages from `requirements_server.txt`, creates the `data\` folder, and generates the TLS certificate.

Press Enter when it finishes.

To also open the Windows Firewall for port 7331 automatically, run:

```powershell
.\setup\1_setup.ps1 -OpenFirewall
```

### Step 2 — Set your dashboard credentials

Right-click `setup\2_configure.ps1` and choose **Run with PowerShell**.

You will be prompted for:

| Setting | Description | Default |
|---|---|---|
| Dashboard username | Login username for the web UI | `admin` |
| Dashboard password | Login password (SHA-256 hashed before storing) | *(required)* |
| Port | TCP port the server listens on | `7331` |
| Database path | Path to the SQLite file | `data\flare.db` |
| Min FL clients | Agents needed before FL round runs | `1` |
| TLS certificate path | Path to the generated cert PEM | `certs\flare_server.crt` |
| TLS key path | Path to the generated key PEM | `certs\flare_server.key` |

The password is never stored in plain text — only its SHA-256 hash is saved
as `FLARE_DASHBOARD_PASS_HASH` in Machine-scope environment variables.

Press Enter when it finishes, then **restart any open PowerShell windows**
so the new environment variables are picked up.

---

## Starting the server

### Option A — Manual (foreground, best for testing)

```powershell
cd "path\to\this\folder"
python flare_server.py
```

The server starts on port 7331 with TLS. Open `https://localhost:7331` in a browser.
Your browser will warn about the self-signed cert — this is expected. Accept it once,
or add `certs\flare_server.crt` to your Trusted Root CAs to silence the warning permanently.
Press `Ctrl+C` to stop.

### Option B — One-click start script

```bat
start_server.bat
```

### Option C — Background (persistent, no service)

```powershell
Start-Process python -ArgumentList "flare_server.py" `
    -WindowStyle Hidden `
    -RedirectStandardOutput "data\server.log" `
    -RedirectStandardError  "data\server_err.log"
```

Check the log: `Get-Content data\server.log -Wait -Tail 40`

Stop it: `Get-Process python | Stop-Process`

### Option D — Windows Scheduled Task (recommended for production)

1. Open **Task Scheduler**
2. Create Basic Task → name it **FLARE Server**
3. Trigger: **At system startup**
4. Action: **Start a program**
   - Program: `python`
   - Arguments: `flare_server.py`
   - Start in: `C:\path\to\this\folder`
5. Check **Run whether user is logged on or not**
6. Check **Run with highest privileges**

---

## Opening the firewall (if agents are on other machines)

Run this once as Administrator:

```powershell
New-NetFirewallRule -DisplayName "FLARE-Server-Inbound" `
    -Direction Inbound -Protocol TCP -LocalPort 7331 -Action Allow
```

Or pass `-OpenFirewall` to the setup script:

```powershell
.\setup\1_setup.ps1 -OpenFirewall
```

---

## Dashboard

Open `https://<server-ip>:7331` in any browser on the network. Accept the self-signed certificate warning on first visit (or install `certs\flare_server.crt` in your Trusted Root CAs).

Log in with the username and password you set during setup.

**Tabs:**

| Tab | Contents |
|---|---|
| Overview | Severity/track doughnut charts, rule histogram, recent alerts |
| Alerts | Full paginated table; click rows to expand evidence, suggested actions, and isolation commands; filter by severity/track/client; Export CSV |
| Clients | All connected agents, online/offline status, per-client alert counts |
| FL | Federated Learning round counter and model version |

**Auto-refresh** every 15 seconds (toggle in the top-right config bar).

---

## Changing your password

Re-run the configure script and restart the server:

```powershell
.\setup\2_configure.ps1 -Mode server
# Then restart the server so it picks up the new env var
```

---

## Exporting alerts

On the **Alerts** tab, click **Export CSV** to download all currently
filtered alerts as a CSV file. Useful for incident reports.

---

## Federated Learning

The server automatically aggregates model updates from agents once the minimum
client threshold (`FLARE_FL_MIN_CLIENTS`, default: 1) is reached for a given round.
The FL tab shows the current round number and which model version is active.
Agents poll for new global models every 6 hours and hot-swap their local MLP weights.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| "Dashboard password not set" on login | Run `setup\2_configure.ps1 -Mode server` then restart the server |
| Agents not appearing in Clients tab | Confirm agents have `FLARE_SERVER_URL` pointing to this machine and port 7331 |
| Port 7331 already in use | Change `FLARE_PORT` via `setup\2_configure.ps1 -Mode server` and restart |
| Login works but dashboard is blank | Open browser console — look for API errors; server may have failed to initialise the database |
| `data\flare.db` not created | Run `setup\1_setup.ps1` to create the `data\` folder, then restart |
| Server crashes with ImportError | Run `pip install -r requirements_server.txt` again in the folder |
| FL round never advances | Check `FLARE_FL_MIN_CLIENTS` — need that many agents submitting updates; check FL tab for pending update count |
| Agents can't connect (TLS error) | Ensure `FLARE_SERVER_CERT_FINGERPRINT` on agents matches the fingerprint shown by `setup\1_setup.ps1` |
