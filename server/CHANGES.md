# FLARE Server — Network Discovery, mTLS Hardening, Portability

This patch set updates `flare_server.py`, `generate_pki.py`, and `start_server.bat`
so that any teammate can clone the repo, run setup, and have a working
secure server — no machine-specific edits required.

## Drop-in instructions

Replace these three files in your `server/` folder:

```
server/flare_server.py        ← replace
server/generate_pki.py        ← replace
server/start_server.bat       ← replace
```

Everything else (setup scripts, proto, UI, requirements, etc.) is unchanged.

After replacing, run from the server folder:

```
setup\0_run_all_setup.ps1
```

This still works exactly as before. To clean uninstall, the existing
`run_uninstall.bat` / `uninstall_server.ps1` are untouched.

---

## What changed and why

### 1. Network adapter selection on startup (`flare_server.py`)

The server now prompts you to pick a network interface, the same way
`fl_server.py` does:

```
  ┌─ Select network interface to advertise on the LAN ───────────────
  │   [1] 192.168.1.10  (primary)
  │   [2] 172.20.10.4
  │   [3] 10.5.0.7
  │   [0] Don't broadcast a beacon (clients connect manually)
  └──────────────────────────────────────────────────────────────────
  Choice [1]:
```

The bind address is always `0.0.0.0` (so any interface can accept
connections) — what you pick is the IP that gets **advertised** in the
LAN discovery beacon below.

**Skip the prompt** (for headless / service use):

```
python flare_server.py --host 192.168.1.10     # bind + advertise that IP
python flare_server.py --host 0.0.0.0          # bind all, advertise primary
```

When `stdin` isn't a TTY (Windows service, piped input), it auto-picks
the primary default-route IP — no hang.

### 2. UDP LAN beacon (`flare_server.py`)

Once an interface is picked, the server broadcasts a UDP packet every
3 seconds to `<broadcast>:37020`:

```
FLARE_SERVER::<advertised-ip>::<port>
```

Any client listening on UDP/37020 sees the server and knows where to
connect. There's **no shared secret** in the beacon — actual auth happens
via mTLS on the HTTPS connection that follows. A spoofed beacon at most
wastes one failed TLS handshake on the client.

Disable with `--no-beacon`.

### 3. Real mTLS enforcement (`flare_server.py`)

The previous code claimed mTLS in its docstring but passed
`ssl_cert_reqs=ssl.CERT_NONE` to uvicorn — meaning **clients without a
certificate were still accepted**. That's now fixed:

```python
cert_reqs = ssl.CERT_NONE if args.no_mtls else ssl.CERT_REQUIRED
```

Browsers connecting to the dashboard need the admin client cert in
their cert store — your existing `2_configure.ps1` already installs it
and sets the Chrome/Edge auto-select policy, so this is invisible to
the operator. Agents already have their per-machine client cert from
`generate_pki.py --client <hostname>`.

Override with `--no-mtls` for debugging only.

### 4. Auto-bootstrap PKI (`flare_server.py`)

If `certs/ca.crt`, `certs/server.crt`, or `certs/server.key` are missing
when the server starts, it now calls `generate_pki.generate_ca()` and
`generate_server_cert()` directly to create them. No more silent
fallback to plain HTTP — the server either runs with mTLS or prints a
clear error and exits.

### 5. SAN regeneration on IP change (`flare_server.py`)

When you pick an interface whose IP isn't in the server cert's
SubjectAlternativeName (e.g. you moved laptops, joined a different
network, got a new DHCP lease), the server detects this and regenerates
the server cert silently. The CA stays put, so agents and admin
browser bundles keep working.

### 6. Cert covers ALL local IPs (`generate_pki.py`)

Old behavior: server cert SAN included only `socket.gethostbyname(hostname)`
— a single IP. On any multi-NIC, VPN-connected, WSL-host, or
dual-stack machine, the cert covered exactly one interface and TLS
handshakes from clients reaching the server via any other IP would
warn about a SAN mismatch.

New behavior: SAN includes every local IPv4 discovered via
`gethostbyname_ex` plus the default-route IP. Output line shows them:

```
SERVER_SAN_IPS  ['10.5.0.7', '127.0.0.1', '172.20.10.4', '192.168.1.10']
```

This is what makes the project genuinely portable — a teammate's machine
on a different subnet generates a cert valid for their interfaces, with
no manual editing.

### 7. start_server.bat no longer pins `--host`

The old `.bat` passed `--host 0.0.0.0`, which would skip the interactive
picker. New `.bat` omits it, so you get the prompt. Headless users still
have `--host` available on the command line.

---

## What did NOT change

- `setup/0_run_all_setup.ps1` and the rest of `setup/`
- `proto/`, `ui/`, `requirements_server.txt`
- `run_uninstall.bat`, `uninstall_server.ps1` (your existing uninstall flow)
- The agent / client code

The agents already trust the FLARE CA (from `1_setup.ps1` installing it
into the Windows Trusted Root store on the server, or by copying
`ca.crt` to agent machines). All the wire formats, endpoints, DB
schema, and FL aggregation logic are byte-identical.

---

## Quick sanity check after deploying

On the server machine, after `0_run_all_setup.ps1`:

```
> python generate_pki.py
... should print SERVER_SAN_IPS [<list of your local IPs>]
> start_server.bat
... interactive picker appears
... beacon line in the log:
    beacon       : udp://<broadcast>:37020  advertising 192.168.x.x:7331
... mTLS line in the log:
    tls          : mTLS enforced (client cert REQUIRED)
```

On another machine on the same LAN, agents listening on UDP/37020 will
see the beacon and connect (assuming they have their client cert + the
shared `ca.crt`).
