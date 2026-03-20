import uvicorn
from fastapi import FastAPI, Header, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import logging, datetime, pickle, os, socket, threading, time, hmac, hashlib, struct, json
import sys

# ============================================================
# FLARE Master Node  –  Alert-Only Mode
#
# What changed from original fl_server.py:
#   - /api/logs/upload  kept for backward compat but marked legacy
#   - /api/alerts/ingest  is the new primary endpoint
#     Parses AlertEvent protos (or JSON fallback), logs them,
#     stores in alerts.json for the dashboard, prints to console
#   - /api/alerts/recent  returns last N alerts as JSON (dashboard)
#   - /api/fl/update  unchanged – receives 18-dim weight vectors
#   - FedAvg aggregation runs in background, updates global model
#   - /api/model/latest  lets clients download updated global model
# ============================================================

HAS_SCHEMA = False
if getattr(sys, 'frozen', False):
    sys.path.append(sys._MEIPASS)

try:
    import log_schema_pb2
    HAS_SCHEMA = True
    print("\n✅ [SUCCESS] Schema loaded on Server.")
except ImportError:
    print("\n⚠️  [WARNING] log_schema_pb2.py not found – JSON alert fallback active.")

SECRET_KEY       = b"FLARE_ENTERPRISE_SECRET_KEY_2025"
SELECTED_HOST_IP = "0.0.0.0"
BEACON_stop_event = threading.Event()
ALERTS_FILE      = "alerts.json"
MODEL_FILE       = "backend/global_model.pkl"

# Auto-create backend folder so model saving never fails
os.makedirs("backend", exist_ok=True)

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
logger = logging.getLogger("FLARE_Server")
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

app = FastAPI(title="FLARE Master Node")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"]
)

# In-memory alert store (also persisted to alerts.json)
_alert_store: list[dict] = []
_alert_lock = threading.Lock()

# In-memory FL aggregation state
_fl_updates: dict[str, dict] = {}   # client_id -> {weights, sample_count}
_fl_lock = threading.Lock()


# ============================================================
# UTILITIES
# ============================================================
def get_local_ip_choices():
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except: pass
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None):
            ip = item[4][0]
            if "." in ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except: pass
    return ips

def sign_message(message: bytes) -> bytes:
    return hmac.new(SECRET_KEY, message, hashlib.sha256).digest()

async def verify_token(x_auth_token: str = Header(None)):
    if x_auth_token != SECRET_KEY.decode():
        raise HTTPException(status_code=401, detail="Invalid Auth Token")

SEVERITY_LABELS = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
SEVERITY_COLORS = {0: "blue",  1: "green", 2: "yellow", 3: "orange", 4: "red"}

def _store_alert(alert_dict: dict):
    with _alert_lock:
        _alert_store.append(alert_dict)
        # Keep last 1000 in memory
        if len(_alert_store) > 1000:
            _alert_store.pop(0)
    # Persist to disk
    try:
        with open(ALERTS_FILE, 'w') as f:
            json.dump(_alert_store[-500:], f, indent=2, default=str)
    except Exception as e:
        logger.warning(f"Alert persist failed: {e}")

def _load_persisted_alerts():
    if os.path.exists(ALERTS_FILE):
        try:
            with open(ALERTS_FILE) as f:
                data = json.load(f)
            with _alert_lock:
                _alert_store.extend(data)
            logger.info(f"[STORE] Loaded {len(data)} persisted alerts")
        except Exception as e:
            logger.warning(f"Alert load failed: {e}")


# ============================================================
# BEACON
# ============================================================
def broadcast_presence(stop_event):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        udp.bind((SELECTED_HOST_IP, 0))
        print(f"\n[BEACON] Started on {SELECTED_HOST_IP}:37020")
    except Exception as e:
        print(f"[ERROR] Beacon Bind Failed: {e}")
        return
    while not stop_event.is_set():
        try:
            payload   = b"FLARE_MASTER"
            signature = sign_message(payload).hex().encode()
            udp.sendto(payload + b"::" + signature, ('<broadcast>', 37020))
            time.sleep(3)
        except: time.sleep(5)
    udp.close()
    print("[BEACON] Stopped.")


# ============================================================
# FEDERATED AVERAGING BACKGROUND TASK
# ============================================================
def _fedavg_loop():
    """Runs in background. Every 60s aggregates client weight updates."""
    import numpy as np
    while True:
        time.sleep(60)
        with _fl_lock:
            updates = dict(_fl_updates)
        if len(updates) < 1:
            continue
        try:
            total   = sum(u['sample_count'] for u in updates.values())
            weights = np.zeros(18, dtype=np.float64)
            for u in updates.values():
                w = np.array(u['weights'], dtype=np.float64)
                if len(w) == 18:
                    weights += w * (u['sample_count'] / total)

            # Load existing bundle, update fl_weights, save back
            bundle = {}
            if os.path.exists(MODEL_FILE):
                with open(MODEL_FILE, 'rb') as f:
                    bundle = pickle.load(f)
            bundle['fl_weights']      = weights.tolist()
            bundle['fl_last_update']  = datetime.datetime.now().isoformat()
            bundle['fl_client_count'] = len(updates)
            os.makedirs(os.path.dirname(MODEL_FILE), exist_ok=True)
            with open(MODEL_FILE, 'wb') as f:
                pickle.dump(bundle, f)
            logger.info(f"[FedAvg] Updated global model from {len(updates)} clients")
        except Exception as e:
            logger.error(f"[FedAvg] Error: {e}")


# ============================================================
# API ROUTES
# ============================================================

# ── FL update (unchanged from original) ──────────────────────
class ModelUpdate(BaseModel):
    client_id:    str
    weights:      List[float]
    sample_count: int
    vector_dim:   Optional[int] = 18
    type_counts:  Optional[dict] = {}

@app.post("/api/fl/update", dependencies=[Depends(verify_token)])
async def receive_fl_update(update: ModelUpdate):
    with _fl_lock:
        _fl_updates[update.client_id] = {
            'weights':      update.weights,
            'sample_count': update.sample_count,
            'last_seen':    datetime.datetime.now().isoformat()
        }
    logger.info(f"[FL] Weights from {update.client_id}  samples={update.sample_count}")
    return {"status": "accepted"}


# ── NEW: Alert ingest ─────────────────────────────────────────
@app.post("/api/alerts/ingest", dependencies=[Depends(verify_token)])
async def ingest_alerts(request: Request):
    """
    Receives length-delimited AlertEvent protos (or JSON fallback).
    Parses, stores, and logs each alert.
    """
    data    = await request.body()
    offset  = 0
    count   = 0
    alerts  = []

    while offset < len(data):
        try:
            if offset + 4 > len(data): break
            size = struct.unpack(">I", data[offset:offset+4])[0]
            offset += 4
            if offset + size > len(data): break
            msg = data[offset:offset+size]
            offset += size

            alert_dict = _parse_alert(msg)
            if alert_dict:
                alerts.append(alert_dict)
                count += 1
        except: break

    for a in alerts:
        _store_alert(a)
        _print_alert(a)

    logger.info(f"[ALERTS] Received and stored {count} alert(s)")
    return {"received": count}


def _parse_alert(msg: bytes) -> dict | None:
    """Try proto first, fall back to JSON."""
    # Proto path
    if HAS_SCHEMA and hasattr(log_schema_pb2, 'AlertEvent'):
        try:
            alert = log_schema_pb2.AlertEvent()
            alert.ParseFromString(msg)
            return {
                "alert_id":    alert.alert_id,
                "timestamp":   alert.timestamp,
                "client_id":   alert.client_id,
                "client_ip":   alert.client_ip,
                "severity":    alert.severity,
                "severity_label": SEVERITY_LABELS.get(alert.severity, "Unknown"),
                "threat_type": alert.threat_type,
                "reason":      alert.reason,
                "ae_score":    round(alert.ae_score, 5),
                "ae_threshold":round(alert.ae_threshold, 5),
                "rule_matched":alert.rule_matched,
                "rule_name":   alert.rule_name,
                "source_log_type": _get_log_type(alert.source_log),
            }
        except: pass

    # JSON fallback (client sends JSON if AlertEvent not in schema)
    try:
        return json.loads(msg.decode('utf-8'))
    except: pass

    return None


def _get_log_type(log) -> str:
    try:
        if log.HasField("system"):  return "System"
        if log.HasField("network"): return "Network"
        if log.HasField("dns"):     return "DNS"
        if log.HasField("powershell"): return "PowerShell"
    except: pass
    return "Unknown"


def _print_alert(a: dict):
    sev   = a.get('severity', 0)
    label = a.get('severity_label', 'Unknown')
    ttype = a.get('threat_type', 'Unknown')
    reason = a.get('reason', '')
    client = a.get('client_id', '?')
    ts    = a.get('timestamp', '')

    prefix = {4: "[!!! CRITICAL !!!]", 3: "[!!! HIGH !!!]",
               2: "[!! MEDIUM !!]",    1: "[ LOW ]", 0: "[ INFO ]"}.get(sev, "[???]")

    logger.warning(f"{prefix} {ttype} from {client} @ {ts} | {reason}")

    # Mirror original server detection log style for existing demo
    if ttype == "RDP_Anomaly":
        logger.critical(f"[!!! RDP ALERT !!!] Unauthorized Remote Access! {reason}")
    elif ttype == "Brute_Force":
        logger.warning(f"[!!! AUTH ALERT !!!] Failed Login detected: {reason}")
    elif ttype == "Privilege_Escalation":
        logger.critical(f"[!!! PRIVILEGE ALERT !!!] {reason}")
    elif ttype == "Backdoor_NewUser":
        logger.critical(f"[!!! BACKDOOR ALERT !!!] {reason}")
    elif ttype == "Malware_Execution":
        logger.critical(f"[!!! MALWARE ALERT !!!] {reason}")
    elif ttype == "DDoS_HighVolume":
        logger.critical(f"[!!! DDoS ALERT !!!] {reason}")
    elif ttype == "Exfiltration_C2":
        logger.critical(f"[!!! EXFIL ALERT !!!] {reason}")
    elif ttype == "Port_Scan":
        logger.warning(f"[!!! SCAN ALERT !!!] {reason}")


# ── NEW: Recent alerts for dashboard ─────────────────────────
@app.get("/api/alerts/recent")
async def get_recent_alerts(limit: int = 50):
    """Returns last N alerts as JSON for the dashboard to poll."""
    with _alert_lock:
        recent = list(reversed(_alert_store[-limit:]))
    return {"alerts": recent, "total": len(_alert_store)}


# ── NEW: Client downloads updated global model ───────────────
@app.get("/api/model/latest", dependencies=[Depends(verify_token)])
async def get_latest_model():
    """
    Clients call this on startup to get the current global model.
    Returns the pickled bundle as binary.
    """
    if not os.path.exists(MODEL_FILE):
        raise HTTPException(status_code=404, detail="No model available yet")
    from fastapi.responses import FileResponse
    return FileResponse(MODEL_FILE, media_type="application/octet-stream",
                        filename="global_model.pkl")


# ── LEGACY: raw log upload (kept for backward compatibility) ──
@app.post("/api/logs/upload", dependencies=[Depends(verify_token)])
async def upload_logs_legacy(request: Request):
    """
    LEGACY endpoint from original fl_server.py.
    Still works for old clients / testing with simulation attack JSONs.
    Runs same rule-based detection as before.
    """
    data   = await request.body()
    offset = 0
    count  = 0

    while offset < len(data):
        try:
            if offset + 4 > len(data): break
            size = struct.unpack(">I", data[offset:offset+4])[0]
            offset += 4
            if offset + size > len(data): break
            msg = data[offset:offset+size]
            offset += size

            if HAS_SCHEMA:
                log = log_schema_pb2.UnifiedLog()
                log.ParseFromString(msg)
                _legacy_detect(log)
            count += 1
        except: break

    logger.info(f"[LEGACY] Received {count} raw log events")
    return {"count": count}


def _legacy_detect(log):
    """Original detection logic – kept intact for demo continuity."""
    if not HAS_SCHEMA: return
    if log.HasField("system"):
        s = log.system
        if s.event_id == 4625:
            logger.warning(f"[!!! AUTH ALERT !!!] Failed Login: {s.target_user}")
        if s.event_id == 4624 and s.logon_type == 10:
            logger.critical(f"[!!! RDP ALERT !!!] Remote Access! User: {s.target_user}")
        if s.event_id == 4672:
            logger.critical(f"[!!! PRIVILEGE ALERT !!!] Admin Rights: {s.target_user}")
        if s.event_id == 4720:
            logger.critical(f"[!!! BACKDOOR ALERT !!!] New User: {s.target_user}")
        if s.event_id == 4688:
            bad = ["mimikatz","powershell","ncat","metasploit"]
            if any(b in s.new_process_name.lower() for b in bad):
                logger.critical(f"[!!! MALWARE ALERT !!!] Process: {s.new_process_name}")
    if log.HasField("network"):
        n = log.network
        if n.flow_bytes_s > 10000:
            logger.critical(f"[!!! DDoS ALERT !!!] {n.flow_bytes_s} bytes/s → port {n.dest_port}")
        if n.dest_port == 4444:
            logger.critical(f"[!!! EXFIL ALERT !!!] Suspicious Port 4444!")
        if n.dest_port in (21,22,23) and n.flow_bytes_s < 1000:
            logger.warning(f"[!!! SCAN ALERT !!!] Port scan on port {n.dest_port}")


# ── Stats endpoint for dashboard ────────────────────────────
@app.get("/api/stats")
async def get_stats():
    with _alert_lock:
        total = len(_alert_store)
        by_severity = {}
        by_type     = {}
        for a in _alert_store:
            s = a.get('severity_label', 'Unknown')
            t = a.get('threat_type', 'Unknown')
            by_severity[s] = by_severity.get(s, 0) + 1
            by_type[t]     = by_type.get(t, 0) + 1
    with _fl_lock:
        clients = list(_fl_updates.keys())

    return {
        "total_alerts":    total,
        "by_severity":     by_severity,
        "by_threat_type":  by_type,
        "active_clients":  clients,
        "client_count":    len(clients),
    }


# ============================================================
# SERVER MANAGEMENT
# ============================================================
def start_beacon_thread():
    global BEACON_stop_event
    BEACON_stop_event.clear()
    t = threading.Thread(target=broadcast_presence, args=(BEACON_stop_event,), daemon=True)
    t.start()

def restart_beacon():
    global BEACON_stop_event, SELECTED_HOST_IP
    print("\n[INFO] Restarting Beacon...")
    BEACON_stop_event.set()
    time.sleep(1)
    ips = get_local_ip_choices()
    if ips:
        print("\nAvailable Interfaces:")
        for i, ip in enumerate(ips): print(f" [{i+1}] {ip}")
        try:
            choice = input("Choice: ")
            if choice.strip(): SELECTED_HOST_IP = ips[int(choice) - 1]
        except: pass
    start_beacon_thread()

def run_api_server():
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="critical")

def main():
    global SELECTED_HOST_IP

    print("\n[START] FLARE SERVER MASTER NODE  –  Alert-Only Mode")
    _load_persisted_alerts()

    ips = get_local_ip_choices()
    if ips:
        print("Select Interface:")
        for i, ip in enumerate(ips): print(f" [{i+1}] {ip}")
        try:
            choice = input("Choice: ")
            if choice.strip(): SELECTED_HOST_IP = ips[int(choice) - 1]
            else:              SELECTED_HOST_IP = ips[0]
        except: SELECTED_HOST_IP = ips[0]

    threading.Thread(target=run_api_server, daemon=True).start()
    threading.Thread(target=_fedavg_loop, daemon=True).start()
    start_beacon_thread()

    print("\n[SUCCESS] Server is RUNNING.")
    print("   Listening for alerts on  POST /api/alerts/ingest")
    print("   Dashboard feed           GET  /api/alerts/recent")
    print("   Stats                    GET  /api/stats")
    print("   Model download           GET  /api/model/latest")
    print("   [COMMANDS] 'b' -> Broadcast Again, 'q' -> Quit\n")

    while True:
        try:
            cmd = input("flare-master> ").strip().lower()
            if cmd == 'b': restart_beacon()
            elif cmd == 'q':
                BEACON_stop_event.set()
                sys.exit(0)
            elif cmd == 'alerts':
                with _alert_lock:
                    for a in _alert_store[-10:]:
                        print(f"  {a.get('timestamp','')} | {a.get('severity_label','')} | {a.get('threat_type','')} | {a.get('reason','')}")
            elif cmd == 'clients':
                with _fl_lock:
                    for cid, u in _fl_updates.items():
                        print(f"  {cid}  samples={u['sample_count']}  last_seen={u['last_seen']}")
        except KeyboardInterrupt:
            sys.exit(0)

if __name__ == "__main__":
    main()
