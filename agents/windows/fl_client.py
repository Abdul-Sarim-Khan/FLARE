import time, json, os, requests, logging, socket
import struct
import numpy as np
import hmac
import hashlib
from datetime import datetime

# === CONFIG ===
SECRET_KEY = b"FLARE_ENTERPRISE_SECRET_KEY_2025"
CLIENT_ID = os.environ.get('COMPUTERNAME', 'Unknown-Node')

INCOMING_PATH = r"C:\FLARE-data\Logs\incoming.json"
PROCESSING_PATH = r"C:\FLARE-data\Logs\processing.json"
STORAGE_PATH = r"C:\FLARE-data\Logs\unified.bin" 
LOG_FILE = r"C:\FLARE-data\Logs\agent_debug.log"

# === INITIALIZE LOGGING ===
logging.basicConfig(
    filename=LOG_FILE, 
    level=logging.INFO, 
    format='%(asctime)s - %(message)s',
    force=True
)

# === IMPORT SCHEMA ===
try:
    import log_schema_pb2
    if not hasattr(log_schema_pb2, 'UnifiedLog'):
        raise ImportError("UnifiedLog class missing!")
except ImportError as e:
    logging.critical(f"Schema Error: {e}")
    exit(1)

def verify_signature(message: bytes, signature_hex: bytes) -> bool:
    expected = hmac.new(SECRET_KEY, message, hashlib.sha256).digest().hex().encode()
    return hmac.compare_digest(expected, signature_hex)

def find_server():
    """Auto-Discovery"""
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    client.bind(("", 37020))
    logging.info("[INFO] Scanning for Master Node...")
    while True:
        try:
            data, addr = client.recvfrom(1024)
            if b"::" in data:
                payload, sig = data.split(b"::")
                if payload == b"FLARE_MASTER" and verify_signature(payload, sig):
                    server_url = f"http://{addr[0]}:8000"
                    logging.info(f"[SUCCESS] Connected to Master at {server_url}")
                    return server_url
        except Exception as e:
            if "timed out" not in str(e):
                logging.debug(f"Discovery packet error: {e}")
            time.sleep(1)

def ingest_logs():
    if os.path.exists(INCOMING_PATH):
        try:
            if os.path.exists(PROCESSING_PATH): os.remove(PROCESSING_PATH)
            os.rename(INCOMING_PATH, PROCESSING_PATH)
        except OSError: return []

    if not os.path.exists(PROCESSING_PATH): return []
    
    try:
        with open(PROCESSING_PATH, 'r') as f: raw_data = json.load(f)
    except Exception as e:
        logging.error(f"JSON Parse Error: {e}")
        raw_data = []

    # === BUG FIX: Handle Single Log Entry (Dict vs List) ===
    if isinstance(raw_data, dict):
        raw_data = [raw_data]

    # === SAFE CONVERSION HELPERS ===
    def safe_int(val):
        try:
            if str(val).upper() == "N/A": return 0
            return int(val)
        except: return 0

    def safe_float(val):
        try:
            if str(val).upper() == "N/A": return 0.0
            return float(val)
        except: return 0.0

    proto_logs = []
    for item in raw_data:
        try:
            # Double check item is a dict (robustness)
            if not isinstance(item, dict): continue

            log = log_schema_pb2.UnifiedLog()
            log.timestamp = item.get('Timestamp', datetime.now().isoformat())
            log.host_id = CLIENT_ID
            
            if item.get('Type') == "System":
                log.system.event_id = safe_int(item.get('EventID'))
                log.system.user = item.get('User', "N/A")
                log.system.logon_type = safe_int(item.get('LogonType'))
                log.system.process_name = item.get('Process', "N/A")
                log.system.status = "Info"
            elif item.get('Type') == "Network":
                log.network.source_ip = item.get('Source', "0.0.0.0")
                log.network.dest_ip = item.get('DestIP', "0.0.0.0")
                log.network.dest_port = safe_int(item.get('DestPort'))
                log.network.flow_bytes = safe_float(item.get('FlowBytes'))
            
            proto_logs.append(log)
        except Exception as e:
            logging.error(f"Proto Conversion Error: {e}")

    if proto_logs:
        try:
            with open(STORAGE_PATH, 'ab') as f:
                for pl in proto_logs:
                    data = pl.SerializeToString()
                    f.write(struct.pack(">I", len(data)))
                    f.write(data)
            logging.info(f"Archived {len(proto_logs)} logs to binary.")
        except Exception as e:
            logging.error(f"Write Error: {e}")

    try: os.remove(PROCESSING_PATH)
    except: pass
    return proto_logs

def load_history_for_training():
    if not os.path.exists(STORAGE_PATH): return []
    
    vectors = []
    try:
        file_size = os.path.getsize(STORAGE_PATH)
        with open(STORAGE_PATH, 'rb') as f:
            if file_size > 1000000: f.seek(file_size - 1000000)
            
            while True:
                size_bytes = f.read(4)
                if len(size_bytes) < 4: break
                size = struct.unpack(">I", size_bytes)[0]
                data = f.read(size)
                if len(data) < size: break
                
                log = log_schema_pb2.UnifiedLog()
                log.ParseFromString(data)
                
                try:
                    h = 0
                    try: h = datetime.strptime(log.timestamp, "%Y-%m-%d %H:%M:%S").hour
                    except: pass
                    
                    if log.HasField("system"):
                        t = log.system.logon_type
                        if log.system.event_id == 4688: t = 0
                        if log.system.event_id in [4672, 4720]: t = 99
                        vectors.append([1, t, h, 0])
                    elif log.HasField("network"):
                        vectors.append([2, log.network.dest_port, h, log.network.flow_bytes])
                except: pass
    except Exception as e:
        logging.error(f"History Load Error: {e}")

    return vectors[-100:]

def main_watchdog():
    logging.info("[START] FLARE Protobuf Agent Started")
    SERVER_URL = find_server()
    HEADERS = {"X-Auth-Token": SECRET_KEY.decode()}
    
    while True:
        try:
            # 1. Ingest
            new_logs = ingest_logs()
            
            # 2. Upload Raw (Only if new logs exist)
            if new_logs:
                batch_data = b"".join([struct.pack(">I", len(l.SerializeToString())) + l.SerializeToString() for l in new_logs])
                try: 
                    requests.post(f"{SERVER_URL}/api/logs/upload", data=batch_data, headers=HEADERS, timeout=2)
                except Exception as e:
                    logging.warning(f"Log Upload Failed: {e}")

            # 3. Train
            vectors = load_history_for_training()
            if not vectors:
                time.sleep(5)
                continue
                
            X_train = np.array(vectors)
            weights = np.mean(X_train, axis=0).tolist()
            
            # 4. Send Update
            try:
                requests.post(
                    f"{SERVER_URL}/api/fl/update", 
                    json={'client_id': CLIENT_ID, 'weights': weights, 'sample_count': len(X_train)}, 
                    headers=HEADERS,
                    timeout=5
                )
            except Exception as e:
                logging.warning(f"Update Failed: {e}")

            time.sleep(10)

        except Exception as e:
            logging.error(f"Loop Error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main_watchdog()