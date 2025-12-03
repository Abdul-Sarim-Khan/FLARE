import time, json, os, requests, logging, socket
import numpy as np
from datetime import datetime

CLIENT_ID = os.environ.get('COMPUTERNAME', 'Unknown-Node')
LOGS_PATH = r"C:\FLARE-data\Logs\logs.json"
LOG_FILE = r"C:\FLARE-data\Logs\agent_debug.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

def find_server():
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    client.bind(("", 37020))
    logging.info("📡 Scanning for FLARE Master Node...")
    
    while True:
        try:
            data, addr = client.recvfrom(1024)
            if data == b"FLARE_MASTER_PRESENCE":
                server_url = f"http://{addr[0]}:8000"
                logging.info(f"✅ Found Master at: {server_url}")
                return server_url
        except: time.sleep(1)

def load_logs():
    for _ in range(3):
        try:
            if not os.path.exists(LOGS_PATH): return []
            with open(LOGS_PATH, 'r') as f:
                data = json.load(f)
                return data if isinstance(data, list) else [data]
        except: time.sleep(0.5)
    return []

def main_watchdog():
    logging.info(f"🔥 FLARE Agent Started on {CLIENT_ID}")
    SERVER_URL = find_server()
    last_mtime = 0
    
    while True:
        try:
            try: curr_mtime = os.path.getmtime(LOGS_PATH)
            except: curr_mtime = 0
            
            if curr_mtime == last_mtime:
                time.sleep(5)
                continue
            
            last_mtime = curr_mtime
            logs = load_logs()
            if not logs: continue
            
            features = []
            for log in logs[-50:]:
                try:
                    ts = datetime.strptime(log['Timestamp'], "%Y-%m-%d %H:%M:%S")
                    features.append([int(log.get('LogonType', 0)), ts.hour])
                except: continue
            
            if not features: continue
            X_train = np.array(features)
            
            weights = np.mean(X_train, axis=0).tolist()
            try:
                requests.post(f"{SERVER_URL}/api/fl/update", json={'client_id': CLIENT_ID, 'weights': weights, 'sample_count': len(X_train)}, timeout=5)
            except: 
                logging.warning("Lost connection. Re-scanning...")
                SERVER_URL = find_server()

            last = X_train[-1]
            if last[0] in [10, 8] and (0 <= last[1] <= 5):
                msg = f"CRITICAL: Suspicious Access (Type {last[0]}) at {last[1]}:00"
                try: requests.post(f"{SERVER_URL}/api/alerts", json={"client_id": CLIENT_ID, "severity": "critical", "message": msg}, timeout=5)
                except: pass

        except Exception as e:
            logging.error(f"Loop Error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main_watchdog()