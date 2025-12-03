import uvicorn
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import logging
import datetime
import pickle
import os
import socket
import threading
import time
import hmac
import hashlib

# === SECURITY CONFIG ===
SECRET_KEY = b"FLARE_ENTERPRISE_SECRET_KEY_2025"

# Logging Setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
logger = logging.getLogger("FLARE_Server")

app = FastAPI(title="FLARE Master Node (Secure)")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === NETWORK SELECTION UTILS ===
def get_local_ip_choices():
    """Finds all valid network interfaces"""
    interfaces = []
    try:
        # Get all addresses
        hostname = socket.gethostname()
        # This is a bit tricky in Python, so we iterate common interfaces
        # A robust way is to connect to a dummy external IP to see which interface is used,
        # but here we want to list ALL choices.
        info = socket.getaddrinfo(hostname, None)
        seen = set()
        for item in info:
            ip = item[4][0]
            # Filter for IPv4 and skip localhost
            if "." in ip and ip != "127.0.0.1" and ip not in seen:
                interfaces.append(ip)
                seen.add(ip)
    except:
        pass
    
    # Fallback if detection fails
    if not interfaces:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            interfaces.append(ip)
        except:
            pass
        finally:
            s.close()
            
    return interfaces

# GLOBAL VARIABLE FOR SELECTED HOST
SELECTED_HOST_IP = "0.0.0.0"

# === SECURITY UTILS ===
def sign_message(message: bytes) -> bytes:
    return hmac.new(SECRET_KEY, message, hashlib.sha256).digest()

async def verify_token(x_auth_token: str = Header(None)):
    if x_auth_token != SECRET_KEY.decode():
        logger.warning("⛔ Unauthorized access attempt blocked!")
        raise HTTPException(status_code=401, detail="Invalid Auth Token")

# === SECURE BEACON ===
def broadcast_presence():
    """Broadcasts on the SPECIFIC interface selected by the user"""
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    # Bind to the user-selected IP
    try:
        udp.bind((SELECTED_HOST_IP, 0))
        logger.info(f"📡 [BEACON] Broadcasting on interface: {SELECTED_HOST_IP}")
    except Exception as e:
        logger.error(f"Failed to bind beacon to {SELECTED_HOST_IP}: {e}")
        return

    while True:
        try:
            payload = b"FLARE_MASTER"
            signature = sign_message(payload).hex().encode()
            packet = payload + b"::" + signature
            udp.sendto(packet, ('<broadcast>', 37020))
            time.sleep(3)
        except Exception as e:
            logger.error(f"Beacon error: {e}")
            time.sleep(5)

# === STANDARD API LOGIC ===
MODEL_PATH = "global_model.pkl"
global_model = []
if os.path.exists(MODEL_PATH):
    with open(MODEL_PATH, "rb") as f: global_model = pickle.load(f)
else: print("⚠️ No brain found.")

client_updates = []
alerts = []

class ModelUpdate(BaseModel):
    client_id: str
    weights: List[float]
    sample_count: int

class Alert(BaseModel):
    client_id: str
    severity: str
    message: str
    timestamp: Optional[str] = None

@app.post("/api/fl/update", dependencies=[Depends(verify_token)])
async def receive_update(update: ModelUpdate):
    logger.info(f"📥 [FL] Verified Update from {update.client_id}")
    client_updates.append(update)
    global global_model
    global_model = update.weights 
    return {"status": "accepted"}

@app.post("/api/alerts", dependencies=[Depends(verify_token)])
async def receive_alert(alert: Alert):
    alert.timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    logger.warning(f"🚨 [ALERT] {alert.message}")
    alerts.append(alert)
    return {"status": "logged"}

@app.get("/api/dashboard/stats")
def get_stats():
    return {
        "threats": len(alerts),
        "incidents": sum(1 for a in alerts if a.severity == 'critical'),
        "monitored": len(set(u.client_id for u in client_updates)),
        "eps": 120 + len(client_updates) * 10,
        "recent_alerts": alerts[-10:]
    }

def main():
    global SELECTED_HOST_IP
    
    print("\n🔥 FLARE MASTER NODE INITIALIZATION 🔥")
    print("---------------------------------------")
    print("Please select the Network Interface to broadcast on:")
    
    ips = get_local_ip_choices()
    if not ips:
        print("❌ No network interfaces found! Check your connection.")
        return

    for i, ip in enumerate(ips):
        print(f" [{i+1}] {ip}")
    
    print("---------------------------------------")
    
    choice = input("Enter number (default 1): ")
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(ips):
            SELECTED_HOST_IP = ips[idx]
        else:
            SELECTED_HOST_IP = ips[0]
    except:
        SELECTED_HOST_IP = ips[0]

    print(f"\n✅ Selected Interface: {SELECTED_HOST_IP}")
    print("🚀 Starting Server & Beacon...")
    
    # Start Beacon in background AFTER selection
    threading.Thread(target=broadcast_presence, daemon=True).start()
    
    # Start API Server on ALL interfaces (0.0.0.0) so it's reachable
    uvicorn.run(app, host="0.0.0.0", port=8000)

if __name__ == "__main__":
    main()