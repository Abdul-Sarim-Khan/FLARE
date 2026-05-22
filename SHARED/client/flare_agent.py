# -*- coding: utf-8 -*-
"""
FLARE v0.4 - Agent Orchestrator
───────────────────────────────
Main entry point for the FLARE endpoint agent. Starts and supervises:

  • Host rule engine  — real-time Windows Event Log subscriptions (19 rules + IOC)
  • Network inference — MLP classifier on pktmon flow CSV (every 30 s)
  • Alert sender      — batches AlertEvent protos -> HTTP POST with retry/buffer
  • Heartbeat         — status ping every 60 s
  • FL model poll     — checks for updated global network model from server

Configuration (all via environment variables):

  FLARE_SERVER_URL    HTTPS base URL of the FLARE server      (default: https://localhost:7331)
  FLARE_CA_CERT       Path to FLARE CA certificate (PEM)      (copy ca.crt from server)
  FLARE_CLIENT_CERT   Path to this agent's client cert (PEM)  (copy client.crt from server bundle)
  FLARE_CLIENT_KEY    Path to this agent's client key (PEM)   (copy client.key from server bundle)
  FLARE_NET_CSV       Path to pktmon flow CSV                  (default: local net_flows.csv)
  FLARE_FL_TEST_MODE  Set to "1" for fast FL timing            (default: 0)
  FLARE_LOG_LEVEL     Logging level: DEBUG/INFO/WARNING        (default: INFO)

Run:
    python flare_agent.py
    python flare_agent.py --server https://192.168.1.10:7331
"""

import argparse
import hashlib
import json
import logging
import os
import queue
import socket
import struct
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Path setup ────────────────────────────────────────────────────────────────
_AGENT_DIR = Path(__file__).parent
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))

from proto import log_schema_pb2 as pb

from host.host_engine import (
    start as _start_host_engine,
    get_counters as _get_host_counters,
)
from network.flare_network_infer import start as _start_net_infer

log = logging.getLogger("flare_agent")

# ─────────────────────────────────────────────────────────────────────────────
# Version + paths
# ─────────────────────────────────────────────────────────────────────────────

AGENT_VERSION  = "0.4.0"
_NET_MODEL_PATH = _AGENT_DIR / "network" / "models" / "network_mlp.pkl"

# ─────────────────────────────────────────────────────────────────────────────
# Load agent.env — values here override stale machine env vars.
# This ensures the agent always uses whatever was written by the last
# setup/configure run, even if the machine-scope registry value is outdated.
# Empty values in the file are intentionally skipped so they do not erase a
# machine env var that the operator may have set by hand.
# ─────────────────────────────────────────────────────────────────────────────

_ENV_FILE = _AGENT_DIR / "agent.env"
if _ENV_FILE.exists():
    for _line in _ENV_FILE.read_text(encoding="utf-8").splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            _k, _v = _k.strip(), _v.strip()
            if _k and _v:           # skip keys with empty values
                os.environ[_k] = _v

# Resolve any relative paths (from agent.env) relative to the agent directory.
# This makes the project portable: no hardcoded absolute paths are needed.
for _path_key in ("FLARE_CA_CERT", "FLARE_CLIENT_CERT", "FLARE_CLIENT_KEY", "FLARE_NET_CSV"):
    _path_val = os.environ.get(_path_key, "").strip()
    if _path_val and not os.path.isabs(_path_val):
        os.environ[_path_key] = str((_AGENT_DIR / _path_val).resolve())

# ─────────────────────────────────────────────────────────────────────────────
# Runtime configuration  (env vars -> module-level, overridable by CLI)
# ─────────────────────────────────────────────────────────────────────────────

SERVER_URL   = os.environ.get("FLARE_SERVER_URL",   "https://localhost:7331").rstrip("/")
NET_CSV      = os.environ.get("FLARE_NET_CSV",      str(_AGENT_DIR / "net_flows.csv"))
FL_TEST      = os.environ.get("FLARE_FL_TEST_MODE", "0") == "1"
CA_CERT      = os.environ.get("FLARE_CA_CERT",      "").strip()
CLIENT_CERT  = os.environ.get("FLARE_CLIENT_CERT",  "").strip()
CLIENT_KEY   = os.environ.get("FLARE_CLIENT_KEY",   "").strip()

# ── Tuning constants ──────────────────────────────────────────────────────────
HEARTBEAT_INTERVAL_SECS = 60

ALERT_BATCH_SIZE   = 20      # max alerts per HTTP POST
ALERT_FLUSH_SECS   = 5       # flush even if batch not full after this many seconds
ALERT_MAX_BUFFER   = 500     # max buffered alerts while server is down
ALERT_RETRY_BACKOFF = [2, 5, 10, 30, 60]   # seconds between retries

NET_INFER_INTERVAL_SECS = 30

# Federated learning timing
FL_POLL_SECS    = 120    if FL_TEST else 21_600   # 2 min vs 6 h
FL_RETRAIN_SECS = 300    if FL_TEST else 86_400   # 5 min vs 24 h

# ─────────────────────────────────────────────────────────────────────────────
# Shared state (written by engine threads, read by heartbeat)
# ─────────────────────────────────────────────────────────────────────────────

_counters_lock       = threading.Lock()
_host_alerts_total   = 0
_net_alerts_total    = 0
_host_track_ok       = False   # set True once host_engine starts successfully
_net_track_ok        = False   # set True once net_infer starts successfully
_agent_start_time    = time.monotonic()


def _inc_host_alerts(n: int = 1):
    global _host_alerts_total
    with _counters_lock:
        _host_alerts_total += n


def _inc_net_alerts(n: int = 1):
    global _net_alerts_total
    with _counters_lock:
        _net_alerts_total += n


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _client_id() -> str:
    return os.environ.get("COMPUTERNAME", socket.gethostname())


def _client_ip() -> str:
    try:
        server_url = os.environ.get("FLARE_SERVER_URL", "https://localhost:7331")
        from urllib.parse import urlparse
        host = urlparse(server_url).hostname or "localhost"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((host, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "0.0.0.0"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _model_hash(path: Path) -> str:
    """First 8 hex chars of SHA-256 of the model file, or empty string."""
    try:
        h = hashlib.sha256(path.read_bytes()).hexdigest()
        return h[:8]
    except OSError:
        return ""


def _frame(data: bytes) -> bytes:
    """Length-prefix framing: [4-byte big-endian uint32][N bytes payload]."""
    return struct.pack(">I", len(data)) + data


# ─────────────────────────────────────────────────────────────────────────────
# HTTP helpers  (uses requests if available, falls back to urllib)
# ─────────────────────────────────────────────────────────────────────────────

import ssl as _ssl

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False
    import urllib.request as _urllib_request
    import urllib.error  as _urllib_error


# ─────────────────────────────────────────────────────────────────────────────
# Server auto-discovery via UDP beacon
# ─────────────────────────────────────────────────────────────────────────────

BEACON_PORT = 37020


def _discover_server_via_beacon(timeout_s: float = 5.0) -> Optional[str]:
    """Listen on UDP/37020 for the FLARE_SERVER beacon broadcast.

    Returns the HTTPS server URL (e.g. 'https://192.168.1.10:7331') if a
    beacon is received within `timeout_s` seconds, otherwise None.

    The server broadcasts: FLARE_SERVER::<ip>::<port>  (every 3 s)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout_s)
        sock.bind(("", BEACON_PORT))
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                data, _addr = sock.recvfrom(1024)
                msg = data.decode("utf-8")
                if msg.startswith("FLARE_SERVER::"):
                    parts = msg.split("::")
                    if len(parts) == 3:
                        ip, port = parts[1].strip(), parts[2].strip()
                        if ip and port.isdigit():
                            return f"https://{ip}:{port}"
            except socket.timeout:
                break
            except OSError:
                break
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return None


def _get_outbound_ip() -> str:
    """Return the local IP that will be used to reach the FLARE server."""
    try:
        from urllib.parse import urlparse
        host = urlparse(SERVER_URL).hostname or "8.8.8.8"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((host, 443))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "0.0.0.0"


# ── mTLS session ──────────────────────────────────────────────────────────────
# The server requires client certificates (mTLS).  We configure the requests
# session with:
#   session.verify = CA_CERT        — verify server cert against FLARE CA
#   session.cert   = (CERT, KEY)    — present this agent's client cert
#
# If certs are missing the agent starts but logs a clear error showing
# exactly which files are needed and where to copy them from.

if _HAS_REQUESTS:
    _session = _requests.Session()

    if CA_CERT and Path(CA_CERT).exists():
        _session.verify = CA_CERT
        _TLS_MODE = "mtls" if (
            CLIENT_CERT and CLIENT_KEY and
            Path(CLIENT_CERT).exists() and Path(CLIENT_KEY).exists()
        ) else "no-client-cert"
    else:
        # CA cert missing — refuse to send to an unverified server
        _session.verify = True   # keep verify=True; will fail with a clear SSL error
        _TLS_MODE = "no-ca-cert"

    if CLIENT_CERT and CLIENT_KEY and Path(CLIENT_CERT).exists() and Path(CLIENT_KEY).exists():
        _session.cert = (CLIENT_CERT, CLIENT_KEY)
    else:
        if _TLS_MODE == "mtls":
            _TLS_MODE = "no-client-cert"


def _post(endpoint: str, body: bytes, timeout: int = 10) -> bool:
    """
    POST framed protobuf bytes to <SERVER_URL><endpoint>.
    Returns True on 2xx, False on any error.
    """
    url     = SERVER_URL + endpoint
    headers = {"Content-Type": "application/octet-stream"}
    try:
        if _HAS_REQUESTS:
            resp = _session.post(url, data=body, headers=headers, timeout=timeout)
            if resp.status_code < 200 or resp.status_code >= 300:
                log.warning("POST %s -> HTTP %d", endpoint, resp.status_code)
                return False
            return True
        else:
            # urllib fallback — build an mTLS context manually
            ctx = _ssl.create_default_context()
            if CA_CERT and Path(CA_CERT).exists():
                ctx.load_verify_locations(CA_CERT)
            else:
                ctx.check_hostname = False
                ctx.verify_mode    = _ssl.CERT_NONE
            if CLIENT_CERT and CLIENT_KEY:
                ctx.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
            req = _urllib_request.Request(url, data=body, headers=headers, method="POST")
            with _urllib_request.urlopen(req, timeout=timeout, context=ctx):
                return True
    except Exception as exc:
        log.warning("POST %s failed: %s (URL: %s)", endpoint, exc, url)
        return False


def _get_json(endpoint: str, timeout: int = 10) -> Optional[dict]:
    """GET <SERVER_URL><endpoint>, return parsed JSON dict or None."""
    url = SERVER_URL + endpoint
    try:
        if _HAS_REQUESTS:
            resp = _session.get(url, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
        else:
            ctx = _ssl.create_default_context()
            if CA_CERT and Path(CA_CERT).exists():
                ctx.load_verify_locations(CA_CERT)
            else:
                ctx.check_hostname = False
                ctx.verify_mode    = _ssl.CERT_NONE
            if CLIENT_CERT and CLIENT_KEY:
                ctx.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
            req = _urllib_request.Request(url)
            with _urllib_request.urlopen(req, timeout=timeout, context=ctx) as r:
                if r.status == 200:
                    return json.loads(r.read().decode())
    except Exception as exc:
        log.warning("GET %s failed: %s (URL: %s)", endpoint, exc, url)
    return None


def _post_json(endpoint: str, data: dict, timeout: int = 15) -> bool:
    """POST a JSON dict to <SERVER_URL><endpoint>. Returns True on 2xx."""
    url     = SERVER_URL + endpoint
    body    = json.dumps(data).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    try:
        if _HAS_REQUESTS:
            resp = _session.post(url, data=body, headers=headers, timeout=timeout)
            return 200 <= resp.status_code < 300
        else:
            ctx = _ssl.create_default_context()
            if CA_CERT and Path(CA_CERT).exists():
                ctx.load_verify_locations(CA_CERT)
            else:
                ctx.check_hostname = False
                ctx.verify_mode    = _ssl.CERT_NONE
            if CLIENT_CERT and CLIENT_KEY:
                ctx.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
            req = _urllib_request.Request(url, data=body, headers=headers, method="POST")
            with _urllib_request.urlopen(req, timeout=timeout, context=ctx):
                return True
    except Exception as exc:
        log.debug("POST JSON %s failed: %s", endpoint, exc)
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Alert counting wrapper queue
# ─────────────────────────────────────────────────────────────────────────────

class _TrackingQueue:
    """
    Wraps a shared queue.Queue.
    Intercepts put() calls to count alerts per track for heartbeat stats.
    """
    def __init__(self, inner: queue.Queue):
        self._q = inner

    def put(self, alert: pb.AlertEvent):
        if alert.track == pb.TRACK_HOST:
            _inc_host_alerts()
        elif alert.track == pb.TRACK_NETWORK:
            _inc_net_alerts()
        self._q.put(alert)

    def put_nowait(self, alert: pb.AlertEvent):
        if alert.track == pb.TRACK_HOST:
            _inc_host_alerts()
        elif alert.track == pb.TRACK_NETWORK:
            _inc_net_alerts()
        self._q.put_nowait(alert)

    # Delegate everything else
    def get(self, *a, **kw):    return self._q.get(*a, **kw)
    def get_nowait(self):       return self._q.get_nowait()
    def empty(self):            return self._q.empty()
    def qsize(self):            return self._q.qsize()
    def task_done(self):        return self._q.task_done()


# ─────────────────────────────────────────────────────────────────────────────
# Alert Sender Thread
# ─────────────────────────────────────────────────────────────────────────────

class AlertSenderThread(threading.Thread):
    """
    Drains alert_queue, batches into AlertBatch, POSTs to /api/alerts/ingest.

    On server failure:
      - Alerts accumulate in an in-memory buffer (max ALERT_MAX_BUFFER)
      - Retries with exponential backoff (ALERT_RETRY_BACKOFF)
      - When server comes back the entire buffer is flushed first
      - Alerts beyond ALERT_MAX_BUFFER are dropped with a warning

    Wire format: _frame(AlertBatch.SerializeToString())
    """

    def __init__(self, alert_queue: queue.Queue, stop_event: threading.Event):
        super().__init__(name="AlertSender", daemon=True)
        self._q          = alert_queue
        self._stop       = stop_event
        self._buffer:    list[pb.AlertEvent] = []
        self._retry_at:  float = 0.0          # epoch time of next retry
        self._retry_idx: int   = 0            # index into ALERT_RETRY_BACKOFF
        self._server_ok: bool  = True

    def run(self):
        log.info("AlertSender: started (batch=%d flush=%ds buffer=%d)",
                 ALERT_BATCH_SIZE, ALERT_FLUSH_SECS, ALERT_MAX_BUFFER)

        last_flush = time.monotonic()

        while not self._stop.is_set():
            # Drain the queue into the buffer
            self._drain_queue()

            now = time.monotonic()
            should_send = (
                len(self._buffer) >= ALERT_BATCH_SIZE
                or (self._buffer and now - last_flush >= ALERT_FLUSH_SECS)
            )

            if self._buffer and should_send:
                if time.monotonic() >= self._retry_at:
                    sent = self._flush_buffer()
                    if sent:
                        last_flush = time.monotonic()
                    # If not sent, retry_at was bumped by _flush_buffer
            elif not self._buffer:
                last_flush = now

            time.sleep(0.25)

        # Drain and flush whatever remains on shutdown
        self._drain_queue()
        if self._buffer:
            log.info("AlertSender: flushing %d remaining alerts on shutdown",
                     len(self._buffer))
            self._flush_buffer()

    def _drain_queue(self):
        """Move all currently queued alerts into the buffer."""
        while True:
            try:
                alert = self._q.get_nowait()
            except queue.Empty:
                break
            if len(self._buffer) < ALERT_MAX_BUFFER:
                self._buffer.append(alert)
            else:
                log.warning("AlertSender: buffer full (%d) — dropping alert %s",
                            ALERT_MAX_BUFFER, alert.rule_id or alert.attack_type)

    def _flush_buffer(self) -> bool:
        """
        Send buffer in batches of ALERT_BATCH_SIZE.
        On first failure: schedule retry, return False.
        On full success: clear buffer, reset retry state, return True.
        """
        total   = len(self._buffer)
        sent    = 0
        batches = [self._buffer[i:i + ALERT_BATCH_SIZE]
                   for i in range(0, total, ALERT_BATCH_SIZE)]

        for batch in batches:
            ab = pb.AlertBatch()
            ab.alerts.extend(batch)
            body = _frame(ab.SerializeToString())
            ok   = _post("/api/alerts/ingest", body)
            if not ok:
                # Leave unsent portion in buffer
                self._buffer = self._buffer[sent:]
                self._schedule_retry()
                return False
            sent += len(batch)

        # All sent
        if not self._server_ok:
            log.info("AlertSender: server back online — flushed %d buffered alerts",
                     total)
        self._buffer     = []
        self._retry_at   = 0.0
        self._retry_idx  = 0
        self._server_ok  = True
        return True

    def _schedule_retry(self):
        backoff = ALERT_RETRY_BACKOFF[
            min(self._retry_idx, len(ALERT_RETRY_BACKOFF) - 1)
        ]
        self._retry_at  = time.monotonic() + backoff
        self._retry_idx = min(self._retry_idx + 1, len(ALERT_RETRY_BACKOFF) - 1)
        if self._server_ok:
            log.warning("AlertSender: server unreachable — buffering alerts "
                        "(retry in %ds)", backoff)
        self._server_ok = False


# ─────────────────────────────────────────────────────────────────────────────
# Heartbeat Thread
# ─────────────────────────────────────────────────────────────────────────────

class HeartbeatThread(threading.Thread):
    """
    Sends a Heartbeat proto to /api/heartbeat every HEARTBEAT_INTERVAL_SECS.
    Carries agent version, uptime, track health, and rule-engine counters.
    """

    def __init__(self, stop_event: threading.Event):
        super().__init__(name="Heartbeat", daemon=True)
        self._stop  = stop_event
        self._cid   = _client_id()
        self._cip   = _client_ip()

    def run(self):
        log.info("Heartbeat: started (interval=%ds)", HEARTBEAT_INTERVAL_SECS)
        # Send one immediately on startup so the server sees the agent right away
        self._send()
        while not self._stop.is_set():
            # Sleep in small ticks so stop_event is checked promptly
            for _ in range(HEARTBEAT_INTERVAL_SECS * 4):
                if self._stop.is_set():
                    return
                time.sleep(0.25)
            self._send()

    def _send(self):
        hc = _get_host_counters()

        with _counters_lock:
            hat  = _host_alerts_total
            nat  = _net_alerts_total
            htok = _host_track_ok
            # Fix 7: net_track_ok reflects both a successful worker start AND
            # that the CSV feed is currently present on disk.  A True startup
            # flag with a missing CSV gives a misleading "healthy" status.
            ntok = _net_track_ok and Path(NET_CSV).exists()

        hb = pb.Heartbeat()
        hb.client_id          = self._cid
        hb.timestamp          = _now_iso()
        hb.client_ip          = self._cip
        hb.agent_version      = AGENT_VERSION
        hb.host_model_hash    = ""   # no host ML model in Flare-Final-V2
        hb.net_model_hash     = _model_hash(_NET_MODEL_PATH)
        hb.uptime_seconds     = int(time.monotonic() - _agent_start_time)
        hb.host_track_ok      = htok
        hb.net_track_ok       = ntok
        hb.host_alerts_total  = hat
        hb.net_alerts_total   = nat
        hb.ioc_matches_total  = hc.get("ioc_matches", 0)
        hb.rule_hits_total    = hc.get("rule_hits",   0)

        ok = _post("/api/heartbeat", _frame(hb.SerializeToString()))
        if ok:
            log.debug("Heartbeat: sent (uptime=%ds host_alerts=%d net_alerts=%d)",
                      hb.uptime_seconds, hat, nat)
        else:
            log.warning("Heartbeat: delivery failed")


# ─────────────────────────────────────────────────────────────────────────────
# FL Poll Thread  (network model only)
# ─────────────────────────────────────────────────────────────────────────────

class FLPollThread(threading.Thread):
    """
    Polls /api/fl/model/network for a newer global model.
    When a ModelUpdate arrives with a round newer than the current one,
    the local network MLP weights are hot-swapped.

    TODO: FL local fine-tuning + FLUpdate submission is not yet implemented.
          That will be added once the server-side FL aggregator is built.
    """

    def __init__(self, stop_event: threading.Event, reload_event: Optional[threading.Event] = None):
        super().__init__(name="FL-Poll", daemon=True)
        self._stop          = stop_event
        self._reload_event  = reload_event
        self._current_round = -1

    def run(self):
        log.info("FL-Poll: started (interval=%ds, test_mode=%s)",
                 FL_POLL_SECS, FL_TEST)
        while not self._stop.is_set():
            # Sleep first — no need to poll immediately on startup
            for _ in range(FL_POLL_SECS * 4):
                if self._stop.is_set():
                    return
                time.sleep(0.25)
            self._poll()

    def _poll(self):
        try:
            if _HAS_REQUESTS:
                # Use the mTLS session (not bare _requests) so the CA cert and
                # client cert are presented — required by the FLARE server.
                resp = _session.get(
                    SERVER_URL + "/api/fl/model/network",
                    timeout=15,
                )
                if resp.status_code == 204:
                    log.debug("FL-Poll: no update available")
                    return
                if resp.status_code != 200:
                    log.debug("FL-Poll: server returned %d", resp.status_code)
                    return
                raw = resp.content
            else:
                req = _urllib_request.Request(
                    SERVER_URL + "/api/fl/model/network"
                )
                with _urllib_request.urlopen(req, timeout=15) as r:
                    if r.status == 204:
                        return
                    raw = r.read()

            # Unframe and parse ModelUpdate
            if len(raw) < 4:
                return
            length = struct.unpack(">I", raw[:4])[0]
            body   = raw[4: 4 + length]
            mu     = pb.ModelUpdate()
            mu.ParseFromString(body)

            if mu.round <= self._current_round:
                log.debug("FL-Poll: already on round %d", self._current_round)
                return

            log.info("FL-Poll: new global model — round %d -> %d (%d clients)",
                     self._current_round, mu.round, mu.client_count)
            self._apply_model(mu)
            self._current_round = mu.round

        except Exception as exc:
            log.debug("FL-Poll: error: %s", exc)

    def _apply_model(self, mu: pb.ModelUpdate):
        """
        Hot-swap the network MLP weights from a ModelUpdate message.
        Loads the local sklearn MLP pkl, replaces coefs_ and intercepts_,
        then saves it back so the inference engine picks it up on the next cycle.

        TODO: signal the running _NetInferWorker to reload its model in-memory
              rather than relying on the pkl file being re-read.
        """
        import numpy as np
        import joblib

        mlp_path = _AGENT_DIR / "network" / "models" / "network_mlp.pkl"
        if not mlp_path.exists():
            log.warning("FL-Poll: MLP pkl not found at %s — cannot apply update",
                        mlp_path)
            return

        try:
            mlp = joblib.load(mlp_path)

            new_coefs = []
            for lw in mu.coefs:
                arr = np.array(lw.values, dtype=np.float32)
                if lw.cols > 0:
                    arr = arr.reshape(lw.rows, lw.cols)
                new_coefs.append(arr)

            new_intercepts = []
            for lw in mu.intercepts:
                arr = np.array(lw.values, dtype=np.float32)
                new_intercepts.append(arr)

            if new_coefs:
                mlp.coefs_      = new_coefs
            if new_intercepts:
                mlp.intercepts_ = new_intercepts

            joblib.dump(mlp, mlp_path)

            # Apply scaler updates if provided.
            # The scaler is a SEPARATE StandardScaler object stored in
            # network_scaler.pkl — it is NOT an attribute on the MLP itself.
            if mu.scaler_mean or mu.scaler_scale:
                scaler_path = _AGENT_DIR / "network" / "models" / "network_scaler.pkl"
                if scaler_path.exists():
                    try:
                        scaler = joblib.load(scaler_path)
                        if mu.scaler_mean:
                            scaler.mean_  = np.array(mu.scaler_mean,  dtype=np.float64)
                        if mu.scaler_scale:
                            scaler.scale_ = np.array(mu.scaler_scale, dtype=np.float64)
                        joblib.dump(scaler, scaler_path)
                        log.info("FL-Poll: scaler updated to round %d", mu.round)
                    except Exception as exc:
                        log.error("FL-Poll: failed to update scaler: %s", exc)
            log.info("FL-Poll: network MLP updated to round %d and saved",
                     mu.round)
            
            if self._reload_event:
                self._reload_event.set()

        except Exception as exc:
            log.error("FL-Poll: failed to apply model update: %s", exc,
                      exc_info=True)


# ─────────────────────────────────────────────────────────────────────────────
# Log-fetch worker
# ─────────────────────────────────────────────────────────────────────────────

def _parse_log_event_xml(xml_str: str) -> dict:
    """
    Lightweight parser for Windows Event Log XML — for display only.
    Extracts SystemTime, EventID, Channel, Computer, Provider, and all
    EventData named values.  Returns a plain dict safe to JSON-serialise.
    """
    import xml.etree.ElementTree as ET

    _NS = "http://schemas.microsoft.com/win/2004/08/events/event"

    def _sys(tag: str) -> str:
        el = system.find(f"{{{_NS}}}{tag}") if system is not None else None
        return (el.text or "").strip() if el is not None else ""

    def _sysattr(tag: str, attr: str) -> str:
        el = system.find(f"{{{_NS}}}{tag}") if system is not None else None
        return (el.get(attr) or "").strip() if el is not None else ""

    try:
        root   = ET.fromstring(xml_str)
        system = root.find(f"{{{_NS}}}System")

        eid_el   = system.find(f"{{{_NS}}}EventID") if system is not None else None
        event_id = int(eid_el.text) if (eid_el is not None and eid_el.text) else 0

        data: dict = {}
        event_data = root.find(f"{{{_NS}}}EventData")
        if event_data is not None:
            for item in event_data:
                name = item.get("Name", "")
                if name:
                    data[name] = (item.text or "").strip()

        return {
            "event_id":  event_id,
            "timestamp": _sysattr("TimeCreated", "SystemTime"),
            "channel":   _sys("Channel"),
            "computer":  _sys("Computer"),
            "provider":  _sysattr("Provider", "Name"),
            "level":     _sys("Level"),
            "data":      data,
        }
    except Exception as exc:
        return {"event_id": 0, "timestamp": "", "channel": "", "computer": "",
                "provider": "", "level": "", "data": {}, "parse_error": str(exc)}





# ─────────────────────────────────────────────────────────────────────────────
# Main run loop
# ─────────────────────────────────────────────────────────────────────────────

def run(stop_event: Optional[threading.Event] = None) -> None:
    """
    Start all agent subsystems and block until stop_event is set
    (or KeyboardInterrupt if running interactively).

    Args:
        stop_event: External stop signal. If None, one is created internally.
    """
    global _host_track_ok, _net_track_ok, _agent_start_time

    if stop_event is None:
        stop_event = threading.Event()

    reload_event = threading.Event()

    _agent_start_time = time.monotonic()
    cid = _client_id()
    cip = _client_ip()

    log.info("=" * 60)
    log.info("FLARE v%s  —  agent starting", AGENT_VERSION)
    log.info("  client_id : %s", cid)
    log.info("  client_ip : %s", cip)
    log.info("  server    : %s", SERVER_URL)
    log.info("  fl_test   : %s", FL_TEST)
    log.info("=" * 60)

    # ── Shared alert queue ────────────────────────────────────────────────────
    _raw_queue    = queue.Queue(maxsize=2000)
    tracking_q    = _TrackingQueue(_raw_queue)

    # ── Start host rule engine ────────────────────────────────────────────────
    try:
        _start_host_engine(tracking_q, stop_event)
        _host_track_ok = True
        log.info("Host engine: started")
    except Exception as exc:
        log.error("Host engine: failed to start: %s", exc)
        _host_track_ok = False

    # ── Start network inference ───────────────────────────────────────────────
    try:
        _start_net_infer(
            tracking_q,
            stop_event,
            csv_path=NET_CSV,
            interval_secs=NET_INFER_INTERVAL_SECS,
            reload_event=reload_event,
        )
        _net_track_ok = True
        log.info("Network inference: started (csv=%s)", NET_CSV)
    except Exception as exc:
        log.error("Network inference: failed to start: %s", exc)
        _net_track_ok = False

    # ── Start supporting threads ──────────────────────────────────────────────
    AlertSenderThread(_raw_queue, stop_event).start()
    HeartbeatThread(stop_event).start()
    FLPollThread(stop_event, reload_event).start()

    log.info("All subsystems running — waiting for stop signal")

    # ── Block until stop ──────────────────────────────────────────────────────
    try:
        stop_event.wait()
    except KeyboardInterrupt:
        log.info("KeyboardInterrupt — shutting down")
        stop_event.set()

    log.info("FLARE agent stopped.")


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def _setup_logging(level: str):
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s  %(levelname)-8s  %(name)-20s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main():
    global SERVER_URL, NET_CSV, FL_TEST, CA_CERT, CLIENT_CERT, CLIENT_KEY, _TLS_MODE

    parser = argparse.ArgumentParser(
        description="FLARE v0.4 — Federated Log Analysis and Response Engine (Agent)"
    )
    parser.add_argument("--server",  default=None,
                        help="Server URL (default: FLARE_SERVER_URL env or auto-discover via beacon)")
    parser.add_argument("--net-csv", default=None,
                        help="Path to pktmon CSV (default: local directory net_flows.csv)")
    parser.add_argument("--test-fl", action="store_true",
                        help="Enable FL test mode (5 min intervals)")
    parser.add_argument("--log-level", default=os.environ.get("FLARE_LOG_LEVEL","INFO"),
                        help="Log level DEBUG/INFO/WARNING (default: INFO)")
    parser.add_argument("--no-beacon", action="store_true",
                        help="Skip server auto-discovery via UDP beacon")
    args = parser.parse_args()

    _setup_logging(args.log_level)

    if args.net_csv:
        NET_CSV = args.net_csv
    if args.test_fl:
        FL_TEST = True

    # ── Server URL resolution ─────────────────────────────────────────────────
    # Priority: --server CLI > env var > beacon discovery > fail
    if args.server:
        SERVER_URL = args.server.rstrip("/")
        log.info("server URL : %s  (from --server)", SERVER_URL)
    elif SERVER_URL and "localhost" not in SERVER_URL and "127.0.0.1" not in SERVER_URL:
        log.info("server URL : %s  (from config)", SERVER_URL)
    else:
        # URL not configured (or still default localhost) — try beacon
        if not args.no_beacon:
            log.info("server URL not configured — listening for UDP beacon on port %d (5 s)…", BEACON_PORT)
            discovered = _discover_server_via_beacon(timeout_s=5.0)
            if discovered:
                SERVER_URL = discovered
                log.info("server URL : %s  (auto-discovered via beacon)", SERVER_URL)

                # Rebuild the requests session now that we know the server URL
                if _HAS_REQUESTS:
                    _session.verify = CA_CERT if (CA_CERT and Path(CA_CERT).exists()) else True

            else:
                log.warning("No server beacon received.")
                if "localhost" in SERVER_URL:
                    log.error(
                        "Server URL is still localhost (%s) and no beacon was found.\n"
                        "  Fix: run  setup\\3_configure.ps1  and set the correct server URL, OR\n"
                        "       pass  --server https://<SERVER-IP>:7331  on the command line.",
                        SERVER_URL
                    )
        else:
            log.info("server URL : %s  (beacon disabled)", SERVER_URL)

    # Rebuild outbound IP now that SERVER_URL is final
    outbound_ip = _get_outbound_ip()

    # ── Log TLS / mTLS status ─────────────────────────────────────────────────
    cert_dir = _AGENT_DIR / "certs"
    if _TLS_MODE == "mtls":
        log.info("mTLS       : ACTIVE — CA=%s  cert=%s", CA_CERT, CLIENT_CERT)
    elif _TLS_MODE == "no-client-cert":
        log.error(
            "mTLS       : CLIENT CERT MISSING — the server will reject this agent!\n"
            "  Expected : %s\n"
            "             %s\n"
            "  Fix      : On the server run:  python generate_pki.py --client %s\n"
            "             Then copy  certs\\clients\\%s\\client.crt  -->  %s\n"
            "                        certs\\clients\\%s\\client.key  -->  %s",
            CLIENT_CERT or str(cert_dir / "client.crt"),
            CLIENT_KEY  or str(cert_dir / "client.key"),
            os.environ.get("COMPUTERNAME", "HOSTNAME"),
            os.environ.get("COMPUTERNAME", "HOSTNAME"), CLIENT_CERT or str(cert_dir / "client.crt"),
            os.environ.get("COMPUTERNAME", "HOSTNAME"), CLIENT_KEY  or str(cert_dir / "client.key"),
        )
    elif _TLS_MODE == "no-ca-cert":
        log.error(
            "mTLS       : CA CERT MISSING — cannot verify server identity!\n"
            "  Expected : %s\n"
            "  Fix      : Copy  server\\certs\\ca.crt  -->  %s",
            CA_CERT or str(cert_dir / "ca.crt"),
            CA_CERT or str(cert_dir / "ca.crt"),
        )
    else:
        log.warning("TLS        : 'requests' library not available — using urllib fallback")

    log.info("network    : local IP %s  ->  server %s", outbound_ip, SERVER_URL)

    run()


if __name__ == "__main__":
    main()