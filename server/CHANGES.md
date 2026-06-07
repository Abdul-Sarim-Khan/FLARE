# FLARE v0.6 — Changelog

All changes made during the v0.6 development cycle, including every session of
AI-assisted work. Entries are ordered newest-first within each category.

---

## Server Agent (New)

### `server/flare_server_agent_service.py` — NEW FILE

The server host machine now protects itself with its own FLARE agent, running
as a separate Windows service (`FLAREServerAgent`). Previously only client
machines were monitored.

Key design decisions:
- **Separate service** from the main server so it can be started, stopped, and
  debugged independently via `services.msc` or `sc.exe`
- **Network capture disabled** (`no_net_capture=True`) to prevent the agent
  from capturing FLARE's own server traffic and feeding it into the inference
  engine — this would create a feedback loop and produce false positives
- **Auto-provisioning** — on first start the service calls `/api/provision` to
  obtain its own mTLS client certificate (`certs/clients/server-agent/`).
  Retries up to 3 times with a short delay to allow the server to start first
- **Connects to `https://localhost:7331`** with `--no-beacon` — no network
  discovery needed since it is on the same machine
- Logs to `server/logs/flare_server_agent.log` (10 MB rotating, 3 backups)

Usage (run as Administrator from `server\`):
```
python flare_server_agent_service.py install
python flare_server_agent_service.py start
python flare_server_agent_service.py debug    # foreground test
python flare_server_agent_service.py status
python flare_server_agent_service.py stop
python flare_server_agent_service.py remove
```

---

## Agent (`client/flare_agent.py`)

### `--no-net-capture` flag

New CLI flag and `run()` parameter that disables both the flow collector and
the network inference engine. When set:
- The CICFlowMeter flow collector thread is not started
- The MLP/network inference thread is not started  
- Host rule engine and heartbeat still run normally
- `net_track_ok` is reported as `False` in heartbeats (accurate — it isn't running)

This was added specifically for the server host agent to prevent the feedback
loop described above, but is also useful for hosts where packet capture is not
possible (locked-down corporate endpoints, VMs without promiscuous mode).

CLI: `python flare_agent.py --no-net-capture`

Programmatic: `flare_agent.run(stop_event, no_net_capture=True)`

---

## Server (`server/flare_server.py`)

### Network adapter selection on startup

The server now shows an interactive picker to select which network interface
to advertise on the LAN:

```
  ┌─ Select network interface to advertise on the LAN ───────────────
  │   [1] 192.168.1.10  (primary)
  │   [2] 172.20.10.4
  │   [3] 10.5.0.7
  │   [0] Don't broadcast a beacon (clients connect manually)
  └──────────────────────────────────────────────────────────────────
  Choice [1]:
```

The bind address is always `0.0.0.0` — every interface accepts connections.
What you pick is the IP included in the beacon payload. When `stdin` is not a
TTY (Windows service, piped input) the server auto-picks the primary
default-route IP with no prompt.

Override: `python flare_server.py --host 192.168.1.10`

### UDP LAN beacon

The server broadcasts a discovery packet every 3 seconds:

```
FLARE_SERVER::<advertised-ip>::<port>
```

Sent to `255.255.255.255:37020` (UDP). Clients listening on that port learn
the server's address automatically — no hardcoded IP needed.

**Beacon socket binding fix**: the UDP socket is explicitly bound to the
advertised IP rather than `0.0.0.0`. On Windows hosts with Host-Only VM
adapters, binding to `0.0.0.0` causes the OS to route the broadcast out the
wrong adapter. Explicit binding forces it out the correct one.

Disable: `python flare_server.py --no-beacon`

### Real mTLS enforcement

Previous code passed `ssl_cert_reqs=ssl.CERT_NONE` to uvicorn despite claiming
mTLS in its docstring — clients without certificates were silently accepted.

Now uses `ssl.CERT_OPTIONAL` to allow the unauthenticated `/api/provision`
bootstrap endpoint (needed so new agents can fetch their first cert), while
all other endpoints reject uncertified clients at the TLS handshake layer.

### Auto-bootstrap PKI

If `certs/ca.crt`, `certs/server.crt`, or `certs/server.key` are missing when
the server starts, it calls `generate_pki.generate_ca()` and
`generate_server_cert()` to create them automatically. The server no longer
falls back to plain HTTP — it either starts with mTLS or exits with a clear
error.

### SAN regeneration on IP change

When the selected interface IP is not in the server certificate's
SubjectAlternativeName list (e.g. after a new DHCP lease or moving networks),
the server regenerates the server certificate automatically. The CA is
unchanged, so agents and admin browsers keep trusting it.

### Client provisioning endpoint

`GET /api/provision?token=<token>&client=<name>` generates a signed client
certificate bundle and returns it as a ZIP containing `ca.crt`, `client.crt`,
and `client.key`. Used by new agents (including the server agent) to
self-provision their mTLS identity without manual file copying.

---

## PKI (`server/generate_pki.py`)

### Complete SAN coverage

Old behavior: server cert SAN included only the result of
`socket.gethostbyname(hostname)` — one IP. On multi-NIC, VPN-connected, WSL,
or dual-stack machines, TLS handshakes from clients reaching the server via
any other IP would fail with a SAN mismatch.

New behavior: SAN includes every local IPv4 from `gethostbyname_ex` plus the
default-route IP from `socket.connect(("8.8.8.8", 80))`:

```
SERVER_SAN_IPS  ['10.5.0.7', '127.0.0.1', '172.20.10.4', '192.168.1.10']
```

Also adds `AuthorityKeyIdentifier` extension for Python 3.12+ / OpenSSL 3.x
compatibility.

---

## Agent (`client/flare_agent.py`)

### Server auto-discovery via UDP beacon

If no `--server` flag or `FLARE_SERVER_URL` env var is set (or the URL is
still the default `localhost`), the agent listens on UDP/37020 for up to
5 seconds on startup. The first valid `FLARE_SERVER::<ip>::<port>` beacon
received is used as the server URL — no configuration required.

Priority order:
1. `--server` CLI flag
2. `FLARE_SERVER_URL` env var (if not localhost)
3. UDP beacon auto-discovery (5 s timeout)
4. Error with instructions if still localhost

Disable discovery: `--no-beacon`

### mTLS client session

The `requests` session is configured with:
- `session.verify = CA_CERT` — verifies the server certificate against the
  FLARE CA
- `session.cert = (CLIENT_CERT, CLIENT_KEY)` — presents this agent's client
  certificate for mutual authentication

Falls back to `urllib` with a manually configured `ssl.SSLContext` when
`requests` is not installed.

On missing certs the agent logs a clear error showing exactly which files are
needed and where to copy them from, then continues running (heartbeats and
host alerts still work, server will reject them until certs are fixed).

---

## Version strings

All `v0.4` and `v0.5` version strings have been updated to `v0.6`:

| File | What changed |
|------|-------------|
| `client/flare_agent.py` | Module docstring, argparse description |
| `client/network/flare_network_infer.py` | Module docstring, argparse description, print banner |
| `client/requirements_agent.txt` | Comment header |
| `client/proto/log_schema.proto` | Schema version comment, inline field comments |
| `server/proto/log_schema.proto` | Same as client proto |

---

## Service wrapper (`client/flare_service.py`)

No functional changes. The service name `FLAREAgent` and display name
`FLARE v0.6 Endpoint Agent` were already correct in this version.

> **Note for uninstall:** if a legacy `FLARE v0.4 Endpoint Agent` service is
> still registered on a machine, uninstall it first:
> ```
> sc stop FLAREAgent
> sc delete FLAREAgent
> ```
> Then install fresh with `python flare_service.py install`.
