import uvicorn
from fastapi import FastAPI, Header, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import logging, datetime, pickle, os, socket, threading, time, hmac, hashlib, struct, json
import sys

HAS_SCHEMA = False
if getattr(sys, 'frozen', False):
    sys.path.append(sys._MEIPASS)

try:
    import log_schema_pb2
    HAS_SCHEMA = True
    print("\n[SUCCESS] Schema loaded.")
except ImportError:
    print("\n[WARNING] log_schema_pb2.py not found – JSON fallback active.")

SECRET_KEY        = b"FLARE_ENTERPRISE_SECRET_KEY_2025"
SELECTED_HOST_IP  = "0.0.0.0"
BEACON_stop_event = threading.Event()
ALERTS_FILE       = "alerts.json"
MODEL_FILE        = "backend/global_model.pkl"

os.makedirs("backend", exist_ok=True)

# Only show WARNING and above in console – suppresses FL noise
logging.basicConfig(level=logging.WARNING, format='%(asctime)s | %(levelname)s | %(message)s')
logger = logging.getLogger("FLARE")
logging.getLogger("uvicorn.access").setLevel(logging.ERROR)
logging.getLogger("uvicorn").setLevel(logging.ERROR)

app = FastAPI(title="FLARE Master Node")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

_alert_store = []
_alert_lock  = threading.Lock()
_fl_updates  = {}
_fl_lock     = threading.Lock()

SEVERITY_LABELS = {0:"Info", 1:"Low", 2:"Medium", 3:"High", 4:"Critical"}


def get_local_ip_choices():
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ips.append(s.getsockname()[0]); s.close()
    except: pass
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None):
            ip = item[4][0]
            if "." in ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except: pass
    return ips

def sign_message(message):
    return hmac.new(SECRET_KEY, message, hashlib.sha256).digest()

async def verify_token(x_auth_token: str = Header(None)):
    if x_auth_token != SECRET_KEY.decode():
        raise HTTPException(status_code=401, detail="Unauthorized")

def _store_alert(a):
    with _alert_lock:
        _alert_store.append(a)
        if len(_alert_store) > 1000:
            _alert_store.pop(0)
    try:
        with open(ALERTS_FILE, 'w') as f:
            json.dump(_alert_store[-500:], f, indent=2, default=str)
    except: pass

def _load_persisted_alerts():
    if os.path.exists(ALERTS_FILE):
        try:
            with open(ALERTS_FILE) as f: data = json.load(f)
            with _alert_lock: _alert_store.extend(data)
            print(f"[INFO] Loaded {len(data)} persisted alerts")
        except: pass


def broadcast_presence(stop_event):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        udp.bind((SELECTED_HOST_IP, 0))
        print(f"[BEACON] Started on {SELECTED_HOST_IP}:37020")
    except Exception as e:
        print(f"[ERROR] Beacon failed: {e}"); return
    while not stop_event.is_set():
        try:
            payload = b"FLARE_MASTER"
            sig     = sign_message(payload).hex().encode()
            udp.sendto(payload + b"::" + sig, ('<broadcast>', 37020))
            time.sleep(3)
        except: time.sleep(5)
    udp.close()


def _fedavg_loop():
    import numpy as np
    while True:
        time.sleep(60)
        with _fl_lock: updates = dict(_fl_updates)
        if not updates: continue
        try:
            total   = sum(u['sample_count'] for u in updates.values())
            weights = np.zeros(18, dtype=np.float64)
            for u in updates.values():
                w = np.array(u['weights'], dtype=np.float64)
                if len(w) == 18:
                    weights += w * (u['sample_count'] / total)
            bundle = {}
            if os.path.exists(MODEL_FILE):
                with open(MODEL_FILE, 'rb') as f: bundle = pickle.load(f)
            bundle['fl_weights']     = weights.tolist()
            bundle['fl_last_update'] = datetime.datetime.now().isoformat()
            bundle['fl_clients']     = len(updates)
            with open(MODEL_FILE, 'wb') as f: pickle.dump(bundle, f)
            # Silent – no console spam for routine FL aggregation
        except Exception as e:
            logger.error(f"[FedAvg] {e}")


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
    # Debug only – won't show unless logging level is DEBUG
    logger.debug(f"[FL] Weights from {update.client_id}")
    return {"status": "accepted"}


@app.post("/api/alerts/ingest", dependencies=[Depends(verify_token)])
async def ingest_alerts(request: Request):
    data = await request.body()
    offset, count, alerts = 0, 0, []
    while offset < len(data):
        try:
            if offset + 4 > len(data): break
            size = struct.unpack(">I", data[offset:offset+4])[0]; offset += 4
            if offset + size > len(data): break
            msg = data[offset:offset+size]; offset += size
            a = _parse_alert(msg)
            if a: alerts.append(a); count += 1
        except: break
    for a in alerts:
        _store_alert(a)
        _print_alert(a)
    return {"received": count}


def _parse_alert(msg):
    if HAS_SCHEMA and hasattr(log_schema_pb2, 'AlertEvent'):
        try:
            a = log_schema_pb2.AlertEvent()
            a.ParseFromString(msg)
            return {
                "alert_id":     a.alert_id,
                "timestamp":    a.timestamp,
                "client_id":    a.client_id,
                "client_ip":    a.client_ip,
                "severity":     a.severity,
                "severity_label": SEVERITY_LABELS.get(a.severity, "Unknown"),
                "threat_type":  a.threat_type,
                "reason":       a.reason,
                "ae_score":     round(a.ae_score, 5),
                "ae_threshold": round(a.ae_threshold, 5),
                "rule_matched": a.rule_matched,
                "rule_name":    a.rule_name,
            }
        except: pass
    try:
        return json.loads(msg.decode('utf-8'))
    except: pass
    return None


def _print_alert(a):
    sev    = a.get('severity', 0)
    ttype  = a.get('threat_type', 'Unknown')
    reason = a.get('reason', '')
    client = a.get('client_id', '?')
    ts     = a.get('timestamp', '')

    prefix = {4:"[!!! CRITICAL !!!]", 3:"[!!! HIGH !!!]",
               2:"[!! MEDIUM !!]",    1:"[ LOW ]", 0:"[ INFO ]"}.get(sev, "[???]")

    print(f"{prefix} {ttype} | {client} | {ts} | {reason}")

    alert_map = {
        "RDP_Anomaly":        "[!!! RDP ALERT !!!] Unauthorized Remote Access!",
        "Brute_Force":        "[!!! AUTH ALERT !!!] Failed Login detected",
        "Privilege_Escalation": "[!!! PRIVILEGE ALERT !!!] Special privileges assigned",
        "Backdoor_NewUser":   "[!!! BACKDOOR ALERT !!!] New user account created",
        "Malware_Execution":  "[!!! MALWARE ALERT !!!] Malicious process detected",
        "DDoS_HighVolume":    "[!!! DDoS ALERT !!!] High traffic volume detected",
        "Exfiltration_C2":    "[!!! EXFIL ALERT !!!] Data exfiltration detected",
        "Port_Scan":          "[!!! SCAN ALERT !!!] Port scanning activity",
        "Persistence_SchedTask": "[!!! PERSISTENCE ALERT !!!] Scheduled task created",
        "Persistence_Service":   "[!!! PERSISTENCE ALERT !!!] New service installed",
        "LOLBaS_Execution":   "[!! LOLBAS ALERT !!] Living-off-the-land binary",
        "PS_Obfuscation":     "[!! POWERSHELL ALERT !!] Encoded command detected",
        "PS_Download":        "[!! POWERSHELL ALERT !!] Download cradle detected",
    }
    if ttype in alert_map:
        print(f"{alert_map[ttype]}: {reason}")
    print()


@app.get("/api/alerts/recent")
async def get_recent_alerts(limit: int = 50):
    with _alert_lock:
        recent = list(reversed(_alert_store[-limit:]))
    return {"alerts": recent, "total": len(_alert_store)}


@app.get("/api/model/latest", dependencies=[Depends(verify_token)])
async def get_latest_model():
    if not os.path.exists(MODEL_FILE):
        raise HTTPException(status_code=404, detail="No model available")
    from fastapi.responses import FileResponse
    return FileResponse(MODEL_FILE, media_type="application/octet-stream", filename="global_model.pkl")


@app.post("/api/logs/upload", dependencies=[Depends(verify_token)])
async def upload_logs_legacy(request: Request):
    """Legacy endpoint – kept for backward compat with old clients."""
    data = await request.body()
    offset, count = 0, 0
    while offset < len(data):
        try:
            if offset + 4 > len(data): break
            size = struct.unpack(">I", data[offset:offset+4])[0]; offset += 4
            if offset + size > len(data): break
            msg = data[offset:offset+size]; offset += size
            if HAS_SCHEMA:
                log = log_schema_pb2.UnifiedLog()
                log.ParseFromString(msg)
                _legacy_detect(log)
            count += 1
        except: break
    return {"count": count}


def _legacy_detect(log):
    if not HAS_SCHEMA: return
    if log.HasField("system"):
        s = log.system
        if s.event_id == 4625: print(f"[!!! AUTH ALERT !!!] Failed Login: {s.target_user}")
        if s.event_id == 4624 and s.logon_type == 10: print(f"[!!! RDP ALERT !!!] Remote Access: {s.target_user}")
        if s.event_id == 4672: print(f"[!!! PRIVILEGE ALERT !!!] Admin rights: {s.target_user}")
        if s.event_id == 4720: print(f"[!!! BACKDOOR ALERT !!!] New user: {s.target_user}")
        if s.event_id == 4688:
            if any(b in s.new_process_name.lower() for b in ["mimikatz","powershell","ncat","metasploit"]):
                print(f"[!!! MALWARE ALERT !!!] Process: {s.new_process_name}")
    if log.HasField("network"):
        n = log.network
        if n.flow_bytes_s > 10000: print(f"[!!! DDoS ALERT !!!] {n.flow_bytes_s:.0f} B/s to port {n.dest_port}")
        if n.dest_port == 4444:    print(f"[!!! EXFIL ALERT !!!] Suspicious port 4444")
        if n.dest_port in (21,22,23) and n.flow_bytes_s < 1000: print(f"[!!! SCAN ALERT !!!] Port {n.dest_port}")


@app.get("/api/stats")
async def get_stats():
    with _alert_lock:
        total = len(_alert_store)
        by_sev, by_type = {}, {}
        for a in _alert_store:
            s = a.get('severity_label','Unknown'); by_sev[s] = by_sev.get(s,0)+1
            t = a.get('threat_type','Unknown');    by_type[t] = by_type.get(t,0)+1
    with _fl_lock: clients = list(_fl_updates.keys())
    return {"total_alerts": total, "by_severity": by_sev, "by_threat_type": by_type,
            "active_clients": clients, "client_count": len(clients)}


def start_beacon_thread():
    global BEACON_stop_event
    BEACON_stop_event.clear()
    threading.Thread(target=broadcast_presence, args=(BEACON_stop_event,), daemon=True).start()

def restart_beacon():
    global BEACON_stop_event, SELECTED_HOST_IP
    print("\n[INFO] Restarting Beacon...")
    BEACON_stop_event.set(); time.sleep(1)
    ips = get_local_ip_choices()
    if ips:
        for i, ip in enumerate(ips): print(f" [{i+1}] {ip}")
        try:
            c = input("Choice: ")
            if c.strip(): SELECTED_HOST_IP = ips[int(c)-1]
        except: pass
    start_beacon_thread()

def main():
    global SELECTED_HOST_IP
    print("\n[START] FLARE SERVER MASTER NODE")
    _load_persisted_alerts()
    ips = get_local_ip_choices()
    if ips:
        print("Select Interface:")
        for i, ip in enumerate(ips): print(f" [{i+1}] {ip}")
        try:
            c = input("Choice: ")
            SELECTED_HOST_IP = ips[int(c)-1] if c.strip() else ips[0]
        except: SELECTED_HOST_IP = ips[0]

    threading.Thread(target=lambda: uvicorn.run(app, host="0.0.0.0", port=8000, log_level="error"), daemon=True).start()
    threading.Thread(target=_fedavg_loop, daemon=True).start()
    start_beacon_thread()

    print("\n[SUCCESS] Server RUNNING")
    print("  Alerts  : POST /api/alerts/ingest")
    print("  Feed    : GET  /api/alerts/recent")
    print("  Stats   : GET  /api/stats")
    print("\nCommands: 'b' Restart beacon | 'alerts' Show last 10 | 'clients' Show clients | 'q' Quit\n")

    while True:
        try:
            cmd = input("flare> ").strip().lower()
            if cmd == 'b':
                restart_beacon()
            elif cmd == 'q':
                BEACON_stop_event.set(); sys.exit(0)
            elif cmd == 'alerts':
                with _alert_lock:
                    for a in _alert_store[-10:]:
                        print(f"  {a.get('timestamp','')} | {a.get('severity_label','')} | {a.get('threat_type','')} | {a.get('reason','')}")
            elif cmd == 'clients':
                with _fl_lock:
                    if not _fl_updates: print("  No clients connected yet.")
                    for cid, u in _fl_updates.items():
                        print(f"  {cid}  samples={u['sample_count']}  last={u['last_seen']}")
        except KeyboardInterrupt:
            sys.exit(0)

if __name__ == "__main__":
    main()
