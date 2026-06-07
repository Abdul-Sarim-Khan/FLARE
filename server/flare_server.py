# -*- coding: utf-8 -*-
"""
FLARE v0.6 — Server
"""

import hashlib
import ipaddress
import json
import logging
import os
import secrets
import socket
import sqlite3
import struct
import sys
import threading
import time
import uuid
import zipfile
import io
import ssl
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import numpy as np
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT      = Path(__file__).parent
UI_DIR    = ROOT / "ui"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from proto import log_schema_pb2 as pb

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

def _load_env_file():
    env_file = ROOT / "data" / "server.env"
    vals = {}
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                vals[k.strip()] = v.strip()

    for _path_key in ("FLARE_DB_PATH", "FLARE_CERT_FILE", "FLARE_KEY_FILE", "FLARE_CA_CERT"):
        _path_val = vals.get(_path_key, "").strip()
        if _path_val and not os.path.isabs(_path_val):
            vals[_path_key] = str((ROOT / _path_val).resolve())

    return vals

_env_file_vals = _load_env_file()

def _cfg(key: str, default: str = "") -> str:
    return _env_file_vals.get(key) or os.environ.get(key) or default

SERVER_PORT         = int(_cfg("FLARE_PORT",              "7331"))
DB_PATH             = _cfg("FLARE_DB_PATH",              str(ROOT / "flare.db"))
FL_TEST             = _cfg("FLARE_FL_TEST_MODE",         "0") == "1"
DASHBOARD_USER      = _cfg("FLARE_DASHBOARD_USER",       "admin")
DASHBOARD_PASS_HASH = _cfg("FLARE_DASHBOARD_PASS_HASH",  "")
TLS_CERT            = _cfg("FLARE_CERT_FILE",            str(ROOT / "certs" / "server.crt"))
TLS_KEY             = _cfg("FLARE_KEY_FILE",             str(ROOT / "certs" / "server.key"))
TLS_CA              = _cfg("FLARE_CA_CERT",              str(ROOT / "certs" / "ca.crt"))
PROVISION_TOKEN     = _cfg("FLARE_PROVISION_TOKEN",      "flare") 

MIN_FL_CLIENTS     = int(_cfg("FLARE_FL_MIN_CLIENTS", "1"))
OFFLINE_AFTER_SECS = 180   # agents heartbeat every 60 s; allow 3 missed before offline
MAX_STALE_ROUNDS   = 1            

# ─────────────────────────────────────────────────────────────────────────────
# Logging & Utilities
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logging.getLogger("asyncio").setLevel(logging.CRITICAL)
log = logging.getLogger("flare_server")

def read_frames(body: bytes) -> list[bytes]:
    frames = []
    offset = 0
    while offset < len(body):
        if offset + 4 > len(body): raise ValueError("Truncated frame header")
        (length,) = struct.unpack_from(">I", body, offset)
        offset += 4
        if offset + length > len(body): raise ValueError(f"Frame claims {length} bytes but only {len(body) - offset} remain")
        frames.append(body[offset: offset + length])
        offset += length
    return frames

def write_frame(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data

# ─────────────────────────────────────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS alerts (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id       TEXT    UNIQUE,
            received_at    REAL,
            client_id      TEXT,
            client_ip      TEXT,
            timestamp      TEXT,
            track          INTEGER,
            attack_type    TEXT,
            severity       INTEGER,
            confidence     REAL,
            window_start   TEXT,
            window_end     TEXT,
            event_count    INTEGER,
            evidence       TEXT,
            rule_id        TEXT,
            mitre_id       TEXT,
            mitre_tactic   TEXT,
            suggestion     TEXT,
            risk_note      TEXT,
            raw_log        TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_client ON alerts(client_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_track ON alerts(track);
        CREATE INDEX IF NOT EXISTS idx_alerts_received ON alerts(received_at DESC);
        CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);
        CREATE TABLE IF NOT EXISTS clients (
            client_id          TEXT PRIMARY KEY,
            client_ip          TEXT,
            last_seen          REAL,
            agent_version      TEXT,
            host_model_hash    TEXT,
            net_model_hash     TEXT,
            uptime_seconds     INTEGER,
            host_track_ok      INTEGER,
            net_track_ok       INTEGER,
            host_alerts_total  INTEGER,
            net_alerts_total   INTEGER,
            ioc_matches_total  INTEGER DEFAULT 0,
            rule_hits_total    INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS fl_updates (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            received_at   REAL,
            client_id     TEXT,
            track         INTEGER,
            sample_count  INTEGER,
            base_round    INTEGER,
            local_loss    REAL,
            weights_json  TEXT
        );
        CREATE TABLE IF NOT EXISTS fl_models (
            track         INTEGER PRIMARY KEY,
            round         INTEGER  DEFAULT 0,
            version       TEXT     DEFAULT '3.0.0',
            client_count  INTEGER  DEFAULT 0,
            updated_at    REAL,
            weights_json  TEXT
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT PRIMARY KEY,
            expires_at REAL
        );
    """)
    conn.commit()
    try:
        conn.execute("ALTER TABLE alerts ADD COLUMN status TEXT DEFAULT 'open'")
        conn.commit()
    except Exception:
        pass
    conn.close()
    log.info("Database ready: %s", DB_PATH)

def _load_initial_weights() -> Optional[dict]:
    candidates = [ROOT / "network" / "models" / "network_mlp_weights.json"]
    for p in candidates:
        if p.exists():
            with open(p, encoding="utf-8") as f:
                return json.load(f)
    return None

def bootstrap_fl_model():
    conn = _get_conn()
    row = conn.execute("SELECT weights_json FROM fl_models WHERE track=?", (pb.TRACK_NETWORK,)).fetchone()
    if row and row["weights_json"]:
        conn.close()
        return
    weights = _load_initial_weights()
    if weights is None:
        conn.close()
        return
    now = time.time()
    conn.execute(
        """INSERT INTO fl_models (track, round, version, client_count, updated_at, weights_json)
           VALUES (?,0,?,0,?,?)
           ON CONFLICT(track) DO UPDATE SET
             weights_json=excluded.weights_json, updated_at=excluded.updated_at""",
        (pb.TRACK_NETWORK, weights.get("version", "0.4.0"), now, json.dumps(weights)),
    )
    conn.commit()
    conn.close()
    log.info("Seeded initial FL model for TRACK_NETWORK")

def get_fl_model_proto(track: int) -> Optional[pb.ModelUpdate]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM fl_models WHERE track=?", (track,)).fetchone()
    conn.close()
    if not row or not row["weights_json"]: return None
    w  = json.loads(row["weights_json"])
    mu = pb.ModelUpdate()
    mu.timestamp    = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    mu.track        = track
    mu.version      = row["version"]
    mu.round        = row["round"]
    mu.client_count = row["client_count"]

    for coef_matrix in w.get("coefs", []):
        arr = np.array(coef_matrix, dtype=np.float32)
        lw  = mu.coefs.add()
        lw.values.extend(arr.flatten().tolist())
        lw.rows = arr.shape[0]
        lw.cols = arr.shape[1] if arr.ndim > 1 else 0

    for bias_vec in w.get("intercepts", []):
        arr = np.array(bias_vec, dtype=np.float32).flatten()
        lw  = mu.intercepts.add()
        lw.values.extend(arr.tolist())
        lw.rows = len(arr)
        lw.cols = 0

    mu.scaler_mean.extend(w.get("scaler_mean",  []))
    mu.scaler_scale.extend(w.get("scaler_scale", []))
    return mu

_fedavg_lock = threading.Lock()
def _maybe_run_fedavg(track: int):
    with _fedavg_lock:
        conn = _get_conn()
        row  = conn.execute("SELECT round, version FROM fl_models WHERE track=?", (track,)).fetchone()
        current_round = row["round"] if row else 0
        updates = conn.execute(
            "SELECT weights_json, sample_count FROM fl_updates WHERE track=? AND base_round >= ? ORDER BY received_at",
            (track, current_round - 1),
        ).fetchall()
        if len(updates) < MIN_FL_CLIENTS:
            conn.close()
            return

        total_samples = sum(u["sample_count"] for u in updates)
        avg: Optional[dict] = None

        for upd in updates:
            w    = json.loads(upd["weights_json"])
            frac = upd["sample_count"] / total_samples
            if avg is None:
                avg = {
                    "coefs":       [np.array(c, dtype=np.float64) * frac for c in w["coefs"]],
                    "intercepts":  [np.array(b, dtype=np.float64) * frac for b in w["intercepts"]],
                }
                if w.get("scaler_mean"): avg["scaler_mean"] = np.array(w["scaler_mean"], dtype=np.float64) * frac
                if w.get("scaler_scale"): avg["scaler_scale"] = np.array(w["scaler_scale"], dtype=np.float64) * frac
            else:
                for i, c in enumerate(w["coefs"]): avg["coefs"][i] += np.array(c, dtype=np.float64) * frac
                for i, b in enumerate(w["intercepts"]): avg["intercepts"][i] += np.array(b, dtype=np.float64) * frac
                if w.get("scaler_mean"): avg["scaler_mean"] += np.array(w["scaler_mean"], dtype=np.float64) * frac
                if w.get("scaler_scale"): avg["scaler_scale"] += np.array(w["scaler_scale"], dtype=np.float64) * frac

        new_round   = current_round + 1
        ver_parts   = (row["version"] if row else "0.4.0").split(".")
        new_version = f"{ver_parts[0]}.{ver_parts[1]}.{new_round}"
        serializable = {
            "coefs":       [c.tolist() for c in avg["coefs"]],
            "intercepts":  [b.tolist() for b in avg["intercepts"]],
            "scaler_mean":  avg["scaler_mean"].tolist() if "scaler_mean" in avg else [],
            "scaler_scale": avg["scaler_scale"].tolist() if "scaler_scale" in avg else [],
            "version": new_version,
        }
        now = time.time()
        conn.execute(
            """INSERT INTO fl_models (track, round, version, client_count, updated_at, weights_json)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(track) DO UPDATE SET round=excluded.round, version=excluded.version,
               client_count=excluded.client_count, updated_at=excluded.updated_at, weights_json=excluded.weights_json""",
            (track, new_round, new_version, len(updates), now, json.dumps(serializable)),
        )
        conn.execute("DELETE FROM fl_updates WHERE track=? AND base_round < ?", (track, new_round))
        conn.commit()
        conn.close()

# ─────────────────────────────────────────────────────────────────────────────
# Session-based dashboard auth
# ─────────────────────────────────────────────────────────────────────────────
_SESSION_TTL   = 28_800
def _hash_pw(pw: str) -> str: return hashlib.sha256(pw.encode("utf-8")).hexdigest()
def _create_session() -> str:
    token = secrets.token_hex(32)
    conn = _get_conn()
    conn.execute("INSERT INTO sessions (token, expires_at) VALUES (?,?)", (token, time.time() + _SESSION_TTL))
    conn.commit(); conn.close()
    return token

def _valid_session(token: str) -> bool:
    if not token: return False
    conn = _get_conn()
    row = conn.execute("SELECT expires_at FROM sessions WHERE token=?", (token,)).fetchone()
    conn.close()
    return bool(row and time.time() < row["expires_at"])

def _require_session(request: Request):
    if not _valid_session(request.cookies.get("flare_session", "")):
        raise HTTPException(status_code=401, detail="Not logged in")

@asynccontextmanager
async def _lifespan(app: FastAPI):
    init_db()
    bootstrap_fl_model()
    yield

app = FastAPI(title="FLARE v0.6", version="0.6.0", lifespan=_lifespan)

# ─────────────────────────────────────────────────────────────────────────────
# PROVISIONING APIS
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/provision/health")
async def provision_health():
    return {"ok": True}

@app.get("/api/provision")
async def provision_cert(token: str, client: str):
    if token != PROVISION_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")
    try:
        import generate_pki
        ca_key_path = ROOT / "certs" / "ca.key"
        ca_cert_path = ROOT / "certs" / "ca.crt"
        if not ca_key_path.exists() or not ca_cert_path.exists():
            raise HTTPException(status_code=500, detail="Server CA not found")

        ca_key_obj, ca_cert_obj = generate_pki.generate_ca(ca_cert_path, ca_key_path)
        client_dir = ROOT / "certs" / "clients" / client
        generate_pki.generate_client_bundle(client, ca_key_obj, ca_cert_obj, client_dir)

        mem_zip = io.BytesIO()
        with zipfile.ZipFile(mem_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(ca_cert_path, arcname="ca.crt")
            zf.write(client_dir / "client.crt", arcname="client.crt")
            zf.write(client_dir / "client.key", arcname="client.key")
        
        mem_zip.seek(0)
        return Response(mem_zip.read(), media_type="application/zip")
    except Exception as e:
        log.error(f"Provisioning failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ─────────────────────────────────────────────────────────────────────────────
# API Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/alerts/ingest")
async def ingest_alerts(request: Request):
    body = await request.body()
    frames = read_frames(body)
    inserted = 0
    now = time.time()
    conn = _get_conn()

    # Server-side burst deduplication window (seconds).
    # If the same client already has an alert with the same attack_type
    # received within this window, merge the new one in (update event_count
    # and confidence) rather than inserting a duplicate row.
    # This handles the case where the agent still sends per-flow alerts during
    # an attack burst — the server collapses them into one running tally.
    _DEDUP_WINDOW = 60  # seconds

    for frame in frames:
        batch = pb.AlertBatch()
        batch.ParseFromString(frame)
        for ev in batch.alerts:
            try:
                # Check for a recent alert from the same client with same type
                existing = conn.execute(
                    """SELECT id, event_count, confidence, rule_id
                       FROM alerts
                       WHERE client_id   = ?
                         AND attack_type = ?
                         AND track       = ?
                         AND received_at >= ?
                       ORDER BY received_at DESC
                       LIMIT 1""",
                    (ev.client_id, ev.attack_type, ev.track, now - _DEDUP_WINDOW)
                ).fetchone()

                if existing:
                    # Merge: bump event_count, keep highest confidence.
                    # Also backfill rule metadata if the stored row has it empty
                    # (happens when earlier alerts arrived before the agent fix).
                    new_count = existing[1] + max(ev.event_count, 1)
                    new_conf  = max(existing[2], ev.confidence)
                    conn.execute(
                        """UPDATE alerts SET
                               event_count  = ?,
                               confidence   = ?,
                               received_at  = ?,
                               rule_id      = CASE WHEN (rule_id IS NULL OR rule_id = '') AND ? != '' THEN ? ELSE rule_id END,
                               mitre_id     = CASE WHEN (mitre_id IS NULL OR mitre_id = '') AND ? != '' THEN ? ELSE mitre_id END,
                               mitre_tactic = CASE WHEN (mitre_tactic IS NULL OR mitre_tactic = '') AND ? != '' THEN ? ELSE mitre_tactic END,
                               suggestion   = CASE WHEN (suggestion IS NULL OR suggestion = '') AND ? != '' THEN ? ELSE suggestion END,
                               risk_note    = CASE WHEN (risk_note IS NULL OR risk_note = '') AND ? != '' THEN ? ELSE risk_note END
                           WHERE id = ?""",
                        (new_count, new_conf, now,
                         ev.rule_id,      ev.rule_id,
                         ev.mitre_id,     ev.mitre_id,
                         ev.mitre_tactic, ev.mitre_tactic,
                         ev.suggestion,   ev.suggestion,
                         ev.risk_note,    ev.risk_note,
                         existing[0])
                    )
                    # don't increment inserted — this is a merge not a new row
                else:
                    conn.execute(
                        """INSERT OR IGNORE INTO alerts
                           (alert_id, received_at, client_id, client_ip, timestamp,
                            track, attack_type, severity, confidence,
                            window_start, window_end, event_count, evidence,
                            rule_id, mitre_id, mitre_tactic, suggestion, risk_note, raw_log)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (ev.alert_id or str(uuid.uuid4()), now,
                         ev.client_id, ev.client_ip, ev.timestamp,
                         ev.track, ev.attack_type, ev.severity, ev.confidence,
                         ev.window_start, ev.window_end, max(ev.event_count, 1),
                         ev.evidence, ev.rule_id, ev.mitre_id, ev.mitre_tactic,
                         ev.suggestion, ev.risk_note, ev.raw_log)
                    )
                    if conn.total_changes > 0: inserted += 1
            except Exception:
                pass

    conn.commit(); conn.close()
    return {"inserted": inserted}

@app.post("/api/heartbeat")
async def heartbeat(request: Request):
    body = await request.body()
    frames = read_frames(body)
    for frame in frames:
        hb = pb.Heartbeat()
        hb.ParseFromString(frame)
        conn = _get_conn()
        conn.execute(
            """INSERT INTO clients (client_id, client_ip, last_seen, agent_version, host_model_hash, net_model_hash, uptime_seconds, host_track_ok, net_track_ok, host_alerts_total, net_alerts_total, ioc_matches_total, rule_hits_total) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(client_id) DO UPDATE SET client_ip=excluded.client_ip, last_seen=excluded.last_seen, agent_version=excluded.agent_version, host_model_hash=excluded.host_model_hash, net_model_hash=excluded.net_model_hash, uptime_seconds=excluded.uptime_seconds, host_track_ok=excluded.host_track_ok, net_track_ok=excluded.net_track_ok, host_alerts_total=excluded.host_alerts_total, net_alerts_total=excluded.net_alerts_total, ioc_matches_total=excluded.ioc_matches_total, rule_hits_total=excluded.rule_hits_total""",
            (hb.client_id, hb.client_ip, time.time(), hb.agent_version, hb.host_model_hash, hb.net_model_hash, hb.uptime_seconds, int(hb.host_track_ok), int(hb.net_track_ok), hb.host_alerts_total, hb.net_alerts_total, hb.ioc_matches_total, hb.rule_hits_total)
        )
        conn.commit(); conn.close()
    return {"ok": True}

@app.post("/api/fl/update")
async def fl_update(request: Request):
    body = await request.body()
    frames = read_frames(body)
    for frame in frames:
        flu = pb.FLUpdate()
        flu.ParseFromString(frame)
        conn = _get_conn()
        row  = conn.execute("SELECT round FROM fl_models WHERE track=?", (flu.track,)).fetchone()
        conn.close()
        current_round = row["round"] if row else 0
        if flu.base_round < current_round - MAX_STALE_ROUNDS: continue
        if flu.sample_count <= 0 or flu.sample_count > 100000: continue
            
        coefs = [np.array(list(lw.values), dtype=np.float32).reshape(lw.rows, lw.cols if lw.cols > 0 else 1).tolist() for lw in flu.coefs]
        intercepts = [list(lw.values) for lw in flu.intercepts]
        conn = _get_conn()
        conn.execute("INSERT INTO fl_updates (received_at, client_id, track, sample_count, base_round, local_loss, weights_json) VALUES (?,?,?,?,?,?,?)",
            (time.time(), flu.client_id, flu.track, flu.sample_count, flu.base_round, flu.local_loss, json.dumps({"coefs": coefs, "intercepts": intercepts})))
        conn.commit(); conn.close()
        _maybe_run_fedavg(flu.track)
    return {"ok": True}

@app.get("/api/fl/model/{track_name}")
async def get_fl_model(track_name: str):
    track_map = {"host": pb.TRACK_HOST, "network": pb.TRACK_NETWORK}
    mu = get_fl_model_proto(track_map[track_name])
    if mu is None: return Response(status_code=204)
    return Response(content=write_frame(mu.SerializeToString()), media_type="application/octet-stream")

@app.get("/api/alerts")
async def list_alerts(request: Request, limit: int = 100, offset: int = 0):
    _require_session(request)
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM alerts ORDER BY received_at DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.close()
    return {"total": total, "offset": offset, "limit": limit, "alerts": [dict(r) for r in rows]}

@app.patch("/api/alerts/{alert_id}/status")
async def update_alert_status(alert_id: str, request: Request):
    """Update the status of a single alert.

    Body (JSON): { "status": "resolved" | "false_positive" | "open" }

    Returns 200 with the updated alert row on success.
    """
    _require_session(request)
    body = await request.json()
    status = body.get("status", "").strip()
    if status not in ("open", "resolved", "false_positive"):
        raise HTTPException(status_code=400, detail="status must be 'open', 'resolved', or 'false_positive'")
    conn = _get_conn()
    conn.execute(
        "UPDATE alerts SET status = ? WHERE alert_id = ?",
        (status, alert_id)
    )
    conn.commit()
    row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return dict(row)


@app.get("/api/alerts/stats")
async def alert_stats(request: Request, hours: int = 24):
    _require_session(request)
    conn   = _get_conn()
    cutoff = time.time() - (hours * 3600)

    # Severity breakdown  {4: N, 3: N, 2: N, 1: N, 0: N}
    sev_rows = conn.execute(
        "SELECT severity, COUNT(*) as count FROM alerts WHERE received_at >= ? GROUP BY severity",
        (cutoff,)
    ).fetchall()
    by_severity = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
    for r in sev_rows:
        k = int(r["severity"] or 0)
        by_severity[k] = by_severity.get(k, 0) + r["count"]

    # Track breakdown  {1: N, 2: N, 0: N}
    trk_rows = conn.execute(
        "SELECT track, COUNT(*) as count FROM alerts WHERE received_at >= ? GROUP BY track",
        (cutoff,)
    ).fetchall()
    by_track = {0: 0, 1: 0, 2: 0}
    for r in trk_rows:
        k = int(r["track"] or 0)
        by_track[k] = by_track.get(k, 0) + r["count"]

    # Top attack types (shown in bar chart as "rules")
    type_rows = conn.execute(
        """SELECT attack_type as rule_id, COUNT(*) as count
           FROM alerts WHERE received_at >= ? AND attack_type IS NOT NULL AND attack_type != ''
           GROUP BY attack_type ORDER BY count DESC LIMIT 15""",
        (cutoff,)
    ).fetchall()
    by_rule_id = [{"rule_id": r["rule_id"], "count": r["count"]} for r in type_rows]

    conn.close()
    return {
        "hours":       hours,
        "by_severity": by_severity,
        "by_track":    by_track,
        "by_rule_id":  by_rule_id,
    }

@app.get("/api/clients")
async def list_clients(request: Request):
    _require_session(request)
    now  = time.time()
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM clients ORDER BY last_seen DESC").fetchall()
    conn.close()
    clients = []
    for row in rows:
        d = dict(row)
        d["online"] = (now - row["last_seen"]) < OFFLINE_AFTER_SECS
        d["last_seen_ago"] = int(now - row["last_seen"])
        clients.append(d)
    return {"clients": clients}

@app.get("/api/status")
async def status(request: Request):
    _require_session(request)
    now  = time.time()
    conn = _get_conn()

    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    all_clients  = conn.execute("SELECT last_seen FROM clients").fetchall()
    online_count = sum(1 for c in all_clients if (now - c["last_seen"]) < OFFLINE_AFTER_SECS)

    # FL model info
    fl_row = conn.execute(
        "SELECT round, version, client_count, updated_at FROM fl_models WHERE track=2 ORDER BY round DESC LIMIT 1"
    ).fetchone()
    fl_model = dict(fl_row) if fl_row else None

    # Pending FL updates (submitted but not yet aggregated)
    fl_pending = conn.execute(
        "SELECT COUNT(*) FROM fl_updates WHERE base_round >= (SELECT COALESCE(MAX(round),0) FROM fl_models WHERE track=2)"
    ).fetchone()[0]

    conn.close()
    return {
        "server_time":        now,
        "total_alerts":       total_alerts,
        "online_clients":     online_count,
        "total_clients":      len(all_clients),
        "fl_model":           fl_model,
        "fl_pending_updates": fl_pending,
        "fl_min_clients":     MIN_FL_CLIENTS,
    }

@app.post("/login")
async def login(request: Request):
    body = await request.json()
    if body.get("username") != DASHBOARD_USER or _hash_pw(body.get("password")) != DASHBOARD_PASS_HASH:
        raise HTTPException(status_code=401, detail="Invalid")
    token = _create_session()
    response = JSONResponse({"ok": True})
    response.set_cookie("flare_session", token, httponly=True, samesite="strict", max_age=_SESSION_TTL)
    return response

@app.get("/")
async def dashboard():
    index = UI_DIR / "index.html"
    if index.exists(): return FileResponse(str(index))
    return JSONResponse({"status": "FLARE v0.6 server running"})

# ─────────────────────────────────────────────────────────────────────────────
# Network interface discovery + LAN beacon
# ─────────────────────────────────────────────────────────────────────────────

BEACON_PORT       = 37020
BEACON_INTERVAL_S = 3.0
_beacon_stop      = threading.Event()

def _get_local_ipv4_addresses() -> list[str]:
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        primary = s.getsockname()[0]
        s.close()
        if primary and not primary.startswith("127."): ips.append(primary)
    except Exception: pass
    try:
        _, _, addrs = socket.gethostbyname_ex(socket.gethostname())
        for ip in addrs:
            if "." in ip and not ip.startswith("127.") and ip not in ips: ips.append(ip)
    except Exception: pass
    return ips

def _select_advertised_ip(cli_host: Optional[str]) -> tuple[str, str]:
    ips = _get_local_ipv4_addresses()
    if cli_host and cli_host not in ("0.0.0.0", "ASK"): return cli_host, cli_host
    if not ips: return "0.0.0.0", "127.0.0.1"
    if not sys.stdin.isatty(): return "0.0.0.0", ips[0]
    print("\n  ┌─ Select network interface to advertise on the LAN ───────────────")
    for i, ip in enumerate(ips): print(f"  │   [{i+1}] {ip}{'  (primary)' if i == 0 else ''}")
    print("  └──────────────────────────────────────────────────────────────────")
    try:
        choice = input("  Choice [1]: ").strip() or "1"
        idx = int(choice)
        if 1 <= idx <= len(ips): return "0.0.0.0", ips[idx - 1]
    except Exception: pass
    return "0.0.0.0", ips[0]

def _broadcast_presence(advertised_ip: str, port: int, stop_event: threading.Event):
    if not advertised_ip or advertised_ip == "0.0.0.0": return
    try:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # CRITICAL FIX: Explicitly bind to the advertised IP. 
        # This forces Windows to route the beacon OUT of the specific adapter (e.g., VM Host-Only).
        udp.bind((advertised_ip, 0))
    except Exception as e:
        log.error(f"Beacon broadcast failed to bind: {e}")
        return
        
    payload = f"FLARE_SERVER::{advertised_ip}::{port}".encode("utf-8")
    log.info(f"beacon       : udp://<broadcast>:{BEACON_PORT}  advertising {advertised_ip}:{port}")
    while not stop_event.is_set():
        try: udp.sendto(payload, ("255.255.255.255", BEACON_PORT))
        except Exception: pass
        stop_event.wait(BEACON_INTERVAL_S)

def _cert_covers_ip(cert_path: Path, ip: str) -> bool:
    """Return True if the server cert's SAN already includes the given IP."""
    try:
        import ipaddress as _ip
        from cryptography import x509 as _x509
        cert = _x509.load_pem_x509_certificate(cert_path.read_bytes())
        san  = cert.extensions.get_extension_for_class(_x509.SubjectAlternativeName)
        target = _ip.IPv4Address(ip)
        return any(
            isinstance(n, _x509.IPAddress) and n.value == target
            for n in san.value
        )
    except Exception:
        return True  # don't regenerate if we can't parse

def _ensure_pki(advertised_ip: str) -> bool:
    cert_path = Path(TLS_CERT)
    key_path  = Path(TLS_KEY)
    ca_path   = Path(TLS_CA)
    ca_key    = ca_path.with_suffix(".key")

    needs_regen = (
        not cert_path.exists() or not key_path.exists() or not ca_path.exists()
        or (advertised_ip and not _cert_covers_ip(cert_path, advertised_ip))
    )

    if needs_regen:
        if cert_path.exists() and advertised_ip and not _cert_covers_ip(cert_path, advertised_ip):
            log.warning("Server IP %s not in cert SAN — regenerating server cert", advertised_ip)
            cert_path.unlink(missing_ok=True)
            key_path.unlink(missing_ok=True)
        try:
            sys.path.insert(0, str(ROOT))
            import generate_pki
            ca_key_obj, ca_cert_obj = generate_pki.generate_ca(ca_path, ca_key)
            generate_pki.generate_server_cert(cert_path, key_path, ca_key_obj, ca_cert_obj)
        except Exception as e:
            log.error("PKI generation failed: %s", e)
    return cert_path.exists() and key_path.exists() and ca_path.exists()

if __name__ == "__main__":
    import argparse
    import uvicorn
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=SERVER_PORT)
    args, _ = parser.parse_known_args()

    bind_host, advertised_ip = _select_advertised_ip(None)
    _ensure_pki(advertised_ip)

    if advertised_ip:
        _beacon_stop.clear()
        threading.Thread(target=_broadcast_presence, args=(advertised_ip, args.port, _beacon_stop), daemon=True).start()

    print(f"\n  FLARE v0.6 Server\n    advertised : https://{advertised_ip}:{args.port}\n")
    try:
        # CRITICAL FIX: Changed ssl_cert_reqs from CERT_REQUIRED (2) to CERT_OPTIONAL (1).
        # This prevents the mTLS chicken-and-egg lock out where the client can't hit /api/provision to get a cert.
        uvicorn.run("flare_server:app", host=bind_host, port=args.port, log_level="info", 
                    ssl_certfile=TLS_CERT, ssl_keyfile=TLS_KEY, ssl_ca_certs=TLS_CA, 
                    ssl_cert_reqs=ssl.CERT_OPTIONAL if 'ssl' in sys.modules else 1)
    except Exception as e:
        log.error(f"Failed to start server: {e}")
    finally:
        _beacon_stop.set()