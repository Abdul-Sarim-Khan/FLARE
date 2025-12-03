import uvicorn
from fastapi import FastAPI
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

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
logger = logging.getLogger("FLARE_Server")

app = FastAPI(title="FLARE Master Node")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def broadcast_presence():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp.bind(("", 0))
    logger.info("📡 [BEACON] Broadcasting presence on Port 37020...")
    while True:
        try:
            udp.sendto(b"FLARE_MASTER_PRESENCE", ('<broadcast>', 37020))
            time.sleep(3)
        except Exception as e:
            logger.error(f"Beacon error: {e}")
            time.sleep(5)

threading.Thread(target=broadcast_presence, daemon=True).start()

MODEL_PATH = "global_model.pkl"
global_model = []
if os.path.exists(MODEL_PATH):
    with open(MODEL_PATH, "rb") as f:
        global_model = pickle.load(f)
    print(f"✅ Loaded Brain: {global_model}")
else:
    print("⚠️ No brain found. Run train_initial_model.py first!")

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

@app.post("/api/fl/update")
async def receive_update(update: ModelUpdate):
    logger.info(f"📥 [FL] Update from {update.client_id}")
    client_updates.append(update)
    global global_model
    global_model = update.weights 
    return {"status": "accepted"}

@app.post("/api/alerts")
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

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)