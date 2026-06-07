# FLARE v0.6 — Server: Setup & Operation

This folder contains everything needed to run the FLARE server on a Windows
machine. Copy this entire `server\` folder to the server machine and follow
the steps below.

---

## Folder contents

```
flare_server.py                 Server entry point (FastAPI + uvicorn + SQLite)
flare_server_agent_service.py   Windows Service that runs the FLARE agent on THIS machine
generate_pki.py                 CA + certificate generator (called automatically on first start)
generate_cert.py                Legacy single-cert helper (superseded by generate_pki.py)
requirements_server.txt         Python package list
start_server.bat                One-click server start (interactive NIC picker)

certs/                          PKI bundle (auto-generated on first start, gitignored)
  ca.crt                        FLARE Certificate Authority (copy to every client machine)
  ca.key                        CA private key (keep on server only)
  server.crt                    Server TLS certificate (SAN covers all local IPs)
  server.key                    Server TLS private key
  clients/                      Per-agent client cert bundles (provisioned via /api/provision)
    <hostname>/
      client.crt
      client.key
      client.p12                Browser import for the admin dashboard

data/
  flare.db                      SQLite database (alerts, clients, FL state)
  server.env                    Runtime config snapshot (written by 2_configure.ps1)

proto/                          Protobuf schema v0.6 (shared with agents — do not edit)
  log_schema.proto
  log_schema_pb2.py

ui/
  index.html                    Dashboard single-page app

network/models/
  network_mlp_weights.json      Initial FL model weights (seeds fl_models table on startup)

logs/
  flare_server_agent.log        Log for the server host agent service (auto-created)

setup/
  0_run_all_setup.ps1           Runs all setup steps in one go
  1_setup.ps1                   Installs Python packages, opens firewall
  2_configure.ps1               Sets credentials, port, cert paths as Machine env vars
```

---

## How it works

### Security model

All agent ↔ server communication uses **mutual TLS (mTLS)**:

- The server presents `certs/server.crt` signed by the FLARE CA
- Each agent presents its own `client.crt` (also signed by the FLARE CA)
- Both sides verify the other's certificate — an agent without a valid cert
  cannot connect, and an agent cannot be spoofed by a rogue server

The only unauthenticated endpoint is `GET /api/provision`, which lets a new
agent fetch its first cert bundle using a shared provisioning token.

### PKI bootstrap

On first start the server automatically:
1. Generates a self-signed FLARE CA (`certs/ca.crt` + `certs/ca.key`)
2. Issues a server certificate covering every local IPv4 address
   (so clients can connect via any of the machine's network interfaces)
3. Seeds the FL model table from `network/models/network_mlp_weights.json`

If the server's IP changes (new DHCP lease, moved networks), it detects the
mismatch and regenerates the server cert silently. The CA is unchanged, so
agents keep trusting it.

### LAN discovery beacon

The server broadcasts a UDP packet every 3 seconds to `255.255.255.255:37020`:

```
FLARE_SERVER::<advertised-ip>::<port>
```

Clients listening on that port learn the server's address automatically — no
hardcoded IP needed on the client side.

On startup you choose which network interface IP to advertise (or pass
`--host <ip>` to skip the prompt). In headless / service mode the primary
default-route IP is selected automatically.

---

## Prerequisites

- Windows 10 / 11 or Windows Server 2016+
- Python 3.10 or later (add to PATH during install)
- Inbound TCP port 7331 open (or your chosen port)
- Inbound UDP port 37020 open (for LAN beacon — clients only need to receive)

---

## First-time setup (run once)

### Step 1 — Install Python dependencies and open the firewall

Right-click `setup\1_setup.ps1` → **Run with PowerShell**.

Installs all packages from `requirements_server.txt` and creates the `data\`
folder. To also open the Windows Firewall automatically:

```powershell
.\setup\1_setup.ps1 -OpenFirewall
```

### Step 2 — Configure the server

Right-click `setup\2_configure.ps1` → **Run with PowerShell**.

You will be prompted for:

| Setting | Description | Default |
|---|---|---|
| Dashboard username | Login for the web UI | `admin` |
| Dashboard password | SHA-256 hashed before storing | *(required)* |
| Port | TCP port the server listens on | `7331` |
| Database path | Path to the SQLite file | `data\flare.db` |
| Min FL clients | Agents needed before FL round runs | `1` |
| Provision token | Token agents use to self-provision certs | `flare` |

Press Enter when it finishes, then **restart any open PowerShell windows** so
the new environment variables are picked up.

---

## Starting the server

### Option A — Manual (foreground, best for testing)

```powershell
cd "path\to\server"
python flare_server.py
```

On first run you will see the network interface picker:

```
  ┌─ Select network interface to advertise on the LAN ───────────────
  │   [1] 192.168.1.10  (primary)
  │   [2] 172.20.10.4
  │   [0] Don't broadcast a beacon (clients connect manually)
  └──────────────────────────────────────────────────────────────────
  Choice [1]:
```

Pick the interface reachable by your client machines. Press `Ctrl+C` to stop.

### Option B — One-click start

```bat
start_server.bat
```

### Option C — Skip the interface picker

```powershell
python flare_server.py --host 192.168.1.10   # advertise specific IP
python flare_server.py --no-beacon           # disable LAN discovery broadcast
```

### Option D — Windows Scheduled Task (persistent, no service install)

1. Open **Task Scheduler** → Create Basic Task → name it **FLARE Server**
2. Trigger: **At system startup**
3. Action: **Start a program** — Program: `python`, Arguments: `flare_server.py`
4. Start in: `C:\path\to\server`
5. Check **Run whether user is logged on or not** and **Run with highest privileges**

---

## Server host agent (protects THIS machine)

The server machine itself also needs a FLARE agent to monitor for threats. A
separate Windows service (`FLAREServerAgent`) handles this. It runs the same
host rule engine as client agents but **skips network capture** to avoid a
feedback loop where the agent analyses its own FLARE server traffic.

Install it (run as Administrator from `server\`):

```powershell
python flare_server_agent_service.py install
python flare_server_agent_service.py start
```

On first start it automatically provisions its own mTLS client certificate
from `/api/provision` — no manual cert copying needed.

Other commands:

```powershell
python flare_server_agent_service.py status   # show running/stopped
python flare_server_agent_service.py stop
python flare_server_agent_service.py debug    # run in foreground (Ctrl-C to stop)
python flare_server_agent_service.py remove   # uninstall
```

Logs: `server\logs\flare_server_agent.log`

---

## Provisioning client certificates

New client agents provision their own certificates automatically on first
connection using the provisioning token. If you need to provision manually:

```powershell
# On the server machine
python generate_pki.py --client <hostname>
```

This creates `certs/clients/<hostname>/client.crt`, `client.key`, and
`client.p12`. Copy `client.crt`, `client.key`, and `certs/ca.crt` to the
client machine.

The `client.p12` is for browser import — install it to access the admin
dashboard with client certificate authentication.

---

## Dashboard

Open `https://<server-ip>:7331` in a browser. The server uses a self-signed
FLARE CA — either accept the warning once, or install `certs/ca.crt` into
your Trusted Root CAs to silence it permanently.

Log in with the credentials set during setup.

**Tabs:**

| Tab | Contents |
|---|---|
| Overview | Severity/track charts, rule histogram, recent alerts |
| Alerts | Full paginated table; expandable evidence, MITRE tags, suggested actions; filter and Export CSV |
| Clients | All agents (online/offline), per-client alert counts, last-seen time |
| FL | Federated Learning round counter and global model version |

Auto-refresh every 15 seconds (toggle in the top-right config bar).

---

## Federated Learning

Agents fine-tune the network MLP locally every 24 hours and submit weight
updates to the server. Once `FLARE_FL_MIN_CLIENTS` updates arrive for a round,
the server runs FedAvg, bumps the round counter, and broadcasts the new global
model. Agents hot-swap their local model on the next 6-hour poll.

Test mode (`FLARE_FL_TEST_MODE=1`): retrain every 5 min, poll every 2 min —
useful for verifying the FL loop without waiting hours.

---

## Changing your password

```powershell
.\setup\2_configure.ps1 -Mode server
# Restart the server to pick up the new env var
```

---

## Uninstalling

```powershell
.\uninstall_server.ps1
```

This stops the server agent service, kills the server process, removes
Machine-scope environment variables, deletes `data\` and `certs\`, removes
the FLARE CA from the Windows trust store, and cleans up firewall rules.
Python packages and project files are left intact.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| "Dashboard password not set" on login | Run `setup\2_configure.ps1 -Mode server` then restart |
| Agents not appearing in Clients tab | Confirm agents have `FLARE_SERVER_URL` pointing here and port 7331 is open |
| Port 7331 already in use | Change `FLARE_PORT` via `setup\2_configure.ps1` and restart |
| TLS handshake errors from agents | Agent's `ca.crt` may be stale — re-copy `certs\ca.crt` to the agent machine |
| FL round never advances | Check `FLARE_FL_MIN_CLIENTS` — need that many agents submitting updates |
| Server cert SAN mismatch | Delete `certs\server.crt` and restart — it will regenerate with updated IPs |
| Server agent not appearing in dashboard | Check `logs\flare_server_agent.log`; ensure server is running before the agent starts |
| Provisioning fails (server agent) | Check `FLARE_PROVISION_TOKEN` matches on both server and agent env; server must be reachable on localhost:7331 |
