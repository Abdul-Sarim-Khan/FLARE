import uvicorn
from fastapi import FastAPI, Header, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import logging, datetime, pickle, os, socket, threading, time, hmac, hashlib, struct
import sys

# === SCHEMA IMPORT (HARDENED) ===
HAS_SCHEMA = False
# Force path for PyInstaller bundled files
if getattr(sys, 'frozen', False):
    base_path = sys._MEIPASS
    sys.path.append(base_path)

try:
    import log_schema_pb2
    HAS_SCHEMA = True
    print("\n✅ [SUCCESS] Schema loaded on Server.")
except ImportError:
    print("\n❌ [CRITICAL WARNING] log_schema_pb2.py NOT FOUND.")
    print("   The server acts as a 'Blind Mailbox' (Stores logs but cannot read/alert).")

# === CONFIGURATION ===
SECRET_KEY = b"FLARE_ENTERPRISE_SECRET_KEY_2025"
SELECTED_HOST_IP = "0.0.0.0"
BEACON_stop_event = threading.Event()

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
logger = logging.getLogger("FLARE_Server")
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

app = FastAPI(title="FLARE Master Node")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# === UTILITIES ===
def get_local_ip_choices():
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except: pass
    try:
        hostname = socket.gethostname()
        for item in socket.getaddrinfo(hostname, None):
            ip = item[4][0]
            if "." in ip and not ip.startswith("127.") and ip not in ips: ips.append(ip)
    except: pass
    return ips

def sign_message(message: bytes) -> bytes:
    return hmac.new(SECRET_KEY, message, hashlib.sha256).digest()

async def verify_token(x_auth_token: str = Header(None)):
    if x_auth_token != SECRET_KEY.decode():
        raise HTTPException(status_code=401, detail="Invalid Auth Token")

# === BEACON LOGIC ===
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
            payload = b"FLARE_MASTER"
            signature = sign_message(payload).hex().encode()
            udp.sendto(payload + b"::" + signature, ('<broadcast>', 37020))
            time.sleep(3)
        except: time.sleep(5)
    udp.close()
    print("[BEACON] Stopped.")

# === API ROUTES ===
class ModelUpdate(BaseModel):
    client_id: str
    weights: List[float]
    sample_count: int

@app.post("/api/fl/update", dependencies=[Depends(verify_token)])
async def receive_update(update: ModelUpdate):
    logger.info(f"[FL] Weights received from {update.client_id}")
    return {"status": "accepted"}

@app.post("/api/logs/upload", dependencies=[Depends(verify_token)])
async def upload_logs(request: Request):
    """Receives Binary Protobuf Stream and Detects Attacks"""
    data = await request.body()
    offset = 0
    count = 0
    
    while offset < len(data):
        try:
            # Parse Length-Delimited Protobuf
            if offset + 4 > len(data): break
            size = struct.unpack(">I", data[offset:offset+4])[0]
            offset += 4
            if offset + size > len(data): break
            msg = data[offset:offset+size]
            offset += size
            
            if HAS_SCHEMA:
                log = log_schema_pb2.UnifiedLog()
                log.ParseFromString(msg)
                
                # === 🛡️ DEMO DETECTION LOGIC 🛡️ ===
                
                if log.HasField("system"):
                    # 1. Brute Force
                    if log.system.event_id == 4625:
                         logger.warning(f"[!!! AUTH ALERT !!!] Failed Login detected: {log.system.user}")

                    # 2. RDP at Night (Poke: Type 10)
                    if log.system.event_id == 4624 and log.system.logon_type == 10:
                        logger.critical(f"[!!! RDP ALERT !!!] Unauthorized Remote Access! User: {log.system.user}")

                    # 3. Privilege Escalation
                    if log.system.event_id == 4672:
                        logger.critical(f"[!!! PRIVILEGE ALERT !!!] Special Admin Rights Assigned: {log.system.user}")
                    
                    # 4. Persistence (Backdoor)
                    if log.system.event_id == 4720:
                         logger.critical(f"[!!! BACKDOOR ALERT !!!] New User Account Created: {log.system.user}")

                    # 7. Malware Execution (NEW)
                    if log.system.event_id == 4688:
                        bad_procs = ["mimikatz", "powershell", "ncat", "metasploit"]
                        proc_name = log.system.process_name.lower()
                        if any(bad in proc_name for bad in bad_procs):
                            logger.critical(f"[!!! MALWARE ALERT !!!] Malicious Process Detected: {log.system.process_name}")

                if log.HasField("network"):
                    # 5. DDoS / High Volume
                    if log.network.flow_bytes > 10000:
                        logger.critical(f"[!!! DDoS ALERT !!!] High Traffic Volume! {log.network.flow_bytes} bytes -> Port {log.network.dest_port}")

                    # 6. Data Exfiltration
                    if log.network.dest_port == 4444:
                        logger.critical(f"[!!! EXFIL ALERT !!!] Suspicious Data Upload to Port 4444!")

                    # 8. Port Scanning (NEW)
                    if log.network.dest_port in [21, 22, 23] and log.network.flow_bytes < 1000:
                        logger.warning(f"[!!! SCAN ALERT !!!] Port Scanning Activity on Port {log.network.dest_port}")

            count += 1
        except: break
        
    logger.info(f"[LOGS] Received {count} Protobuf events")
    return {"count": count}

# === SERVER MANAGEMENT ===
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
    print("\n[START] FLARE SERVER MASTER NODE")
    ips = get_local_ip_choices()
    if ips:
        print("Select Interface:")
        for i, ip in enumerate(ips): print(f" [{i+1}] {ip}")
        try: 
            choice = input("Choice: ")
            if choice.strip(): SELECTED_HOST_IP = ips[int(choice) - 1]
            else: SELECTED_HOST_IP = ips[0]
        except: SELECTED_HOST_IP = ips[0]
    
    threading.Thread(target=run_api_server, daemon=True).start()
    start_beacon_thread()
    
    print("\n[SUCCESS] Server is RUNNING.")
    print("   [COMMANDS] 'b' -> Broadcast Again, 'q' -> Quit")
    
    while True:
        try:
            cmd = input("\nflare-master> ").strip().lower()
            if cmd == 'b': restart_beacon()
            elif cmd == 'q': 
                BEACON_stop_event.set()
                sys.exit(0)
        except KeyboardInterrupt:
            sys.exit(0)

if __name__ == "__main__":
    main()