import time, json, os, requests, logging, socket, pickle, uuid
import struct
import numpy as np
import hmac
import hashlib
from datetime import datetime

SECRET_KEY  = b"FLARE_ENTERPRISE_SECRET_KEY_2025"
CLIENT_ID   = os.environ.get('COMPUTERNAME', 'Unknown-Node')

INCOMING_PATH   = r"C:\FLARE-data\Logs\incoming.json"
PROCESSING_PATH = r"C:\FLARE-data\Logs\processing.json"
STORAGE_PATH    = r"C:\FLARE-data\Logs\unified.bin"
LOG_FILE        = r"C:\FLARE-data\Logs\agent_debug.log"
MODEL_PATH      = r"C:\FLARE-data\model\global_model.pkl"
DEDUP_FILE      = r"C:\FLARE-data\Data\dedup_cache.json"

VECTOR_DIM = 18

for _d in [r"C:\FLARE-data\Logs", r"C:\FLARE-data\Data", r"C:\FLARE-data\model"]:
    os.makedirs(_d, exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    force=True
)

try:
    import log_schema_pb2
    if not hasattr(log_schema_pb2, 'UnifiedLog'):
        raise ImportError("UnifiedLog class missing!")
except ImportError as e:
    logging.critical(f"Schema Error: {e}")
    exit(1)


class LocalDetector:
    def __init__(self, model_path):
        self.ae_threshold = 0.5
        self.scaler_min   = None
        self.scaler_max   = None
        self.ready        = False
        self._load(model_path)

    def _load(self, path):
        if not os.path.exists(path):
            logging.warning(f"[MODEL] {path} not found – rule-only mode active")
            return
        try:
            with open(path, 'rb') as f:
                bundle = pickle.load(f)
            ae = bundle.get("autoencoder", {})
            self.ae_W1        = np.array(ae["W1"])
            self.ae_b1        = np.array(ae["b1"])
            self.ae_W2        = np.array(ae["W2"])
            self.ae_b2        = np.array(ae["b2"])
            self.ae_threshold = float(ae.get("threshold", 0.5))
            sc = bundle.get("scaler", {})
            if sc:
                self.scaler_min = np.array(sc["min"])
                self.scaler_max = np.array(sc["max"])
            self.ready = True
            logging.info(f"[MODEL] Loaded. AE threshold={self.ae_threshold:.4f}")
        except Exception as e:
            logging.error(f"[MODEL] Load failed: {e}")

    def _normalise(self, v):
        if self.scaler_min is None:
            return v
        rng = self.scaler_max - self.scaler_min
        rng[rng == 0] = 1
        return (v - self.scaler_min) / rng

    @staticmethod
    def _relu(x):    return np.maximum(0, x)
    @staticmethod
    def _sigmoid(x): return 1 / (1 + np.exp(-np.clip(x, -500, 500)))

    def ae_score(self, vector):
        if not self.ready:
            return 0.0
        x   = self._normalise(np.array(vector, dtype=np.float32))
        h   = self._relu(x @ self.ae_W1 + self.ae_b1)
        out = self._sigmoid(h @ self.ae_W2 + self.ae_b2)
        return float(np.mean((x - out) ** 2))

    def is_anomaly(self, vector):
        score = self.ae_score(vector)
        return (score > self.ae_threshold), score


def run_rules(log):
    try:
        if log.HasField("system"):
            s   = log.system
            eid = s.event_id
            user = s.target_user or s.subject_user
            if eid == 4625:
                return 2, "Brute_Force", f"Failed login: user={user}"
            if eid == 4624 and s.logon_type == 10:
                return 4, "RDP_Anomaly", f"RDP login: user={user} at {log.timestamp}"
            if eid == 4672:
                return 3, "Privilege_Escalation", f"Special privileges: user={user}"
            if eid == 4720:
                return 4, "Backdoor_NewUser", f"New user created: {s.sam_account_name}"
            if eid in (4698, 4700):
                return 3, "Persistence_SchedTask", f"Scheduled task: {s.task_name}"
            if eid == 7045:
                return 3, "Persistence_Service", f"New service: {s.service_name}"
            if eid == 4688:
                pn = (s.new_process_name + " " + s.creator_process).lower()
                if any(b in pn for b in ["mimikatz","meterpreter","cobaltstrike","ncat","nc.exe","metasploit"]):
                    return 4, "Malware_Execution", f"Malicious process: {s.new_process_name}"
                if any(l in pn for l in ["certutil","bitsadmin","mshta","wscript","cscript","regsvr32","rundll32","installutil","cmstp","msbuild"]):
                    return 2, "LOLBaS_Execution", f"LOLBaS process: {s.new_process_name}"
        elif log.HasField("network"):
            n = log.network
            if n.flow_bytes_s > 10000:
                return 3, "DDoS_HighVolume", f"High traffic: {n.flow_bytes_s:.0f} B/s to port {n.dest_port}"
            if n.dest_port == 4444:
                return 4, "Exfiltration_C2", f"C2 port 4444: src={n.source_ip}"
            if n.dest_port in (21, 22, 23) and n.flow_bytes_s < 1000:
                return 2, "Port_Scan", f"Port scan: port {n.dest_port} src={n.source_ip}"
        elif log.HasField("dns"):
            d = log.dns
            if len(d.query_name) > 50:
                return 2, "DNS_DGA", f"Long DNS query: {d.query_name[:60]}"
        elif log.HasField("powershell"):
            txt = log.powershell.script_block_text.lower()
            if any(k in txt for k in ["-encodedcommand","frombase64string","-enc "]):
                return 3, "PS_Obfuscation", "Encoded PowerShell detected"
            if any(k in txt for k in ["invoke-webrequest","downloadstring","webclient"]):
                return 3, "PS_Download", "PowerShell download cradle detected"
    except Exception:
        pass
    return None


def verify_signature(message, signature_hex):
    expected = hmac.new(SECRET_KEY, message, hashlib.sha256).digest().hex().encode()
    return hmac.compare_digest(expected, signature_hex)

def safe_int(val, default=0):
    try:
        s = str(val).strip().upper()
        if s in ("N/A","NULL","","NONE"): return default
        if s.startswith("0X"): return int(s, 16)
        return int(float(s))
    except: return default

def safe_float(val, default=0.0):
    try:
        s = str(val).strip().upper()
        if s in ("N/A","NULL","","NONE"): return default
        if s.startswith("0X"): return float(int(s, 16))
        return float(s)
    except: return default

def hour_of_day(ts):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try: return datetime.strptime(ts[:19], fmt).hour
        except: pass
    return datetime.now().hour

def is_suspicious_port(p):
    if p in {4444,1337,31337,6666,6667,8888,9999,12345}: return 2
    if p in {21,22,23,25,110,135,139,143,445,3389}:      return 1
    return 0

def is_suspicious_process(name):
    if name in ("N/A",""): return 0
    n = name.lower()
    if any(m in n for m in ["mimikatz","meterpreter","metasploit","cobaltstrike","ncat","nc.exe"]): return 3
    if any(l in n for l in ["certutil","bitsadmin","mshta","wscript","cscript","regsvr32",
                             "rundll32","powershell","cmd","wmic","msiexec","installutil",
                             "cmstp","msbuild","msconfig","netsh","schtasks","sc.exe"]): return 1
    return 0

def is_rare_logon_type(lt):
    return {10:3,9:2,3:1,2:0,11:2,4:1}.get(lt, 0)

TCP_STATE_MAP = {"ESTABLISHED":1,"SYN_SENT":2,"SYN_RECEIVED":3,"FIN_WAIT1":4,
                 "FIN_WAIT2":5,"TIME_WAIT":6,"CLOSED":7,"CLOSE_WAIT":8,"LAST_ACK":9,"LISTEN":10,"CLOSING":11}
DNS_TYPE_MAP  = {"A":1,"AAAA":2,"MX":3,"TXT":4,"NS":5,"CNAME":6,"PTR":7,"SOA":8}

def extract_vector(log):
    v = [0.0] * VECTOR_DIM
    h = hour_of_day(log.timestamp)
    try:
        if log.HasField("system"):
            s=log.system; eid=s.event_id; lt=s.logon_type
            pn=(s.new_process_name+" "+s.creator_process).lower()
            v[0]=1.0;v[1]=float(eid);v[2]=float(lt)
            v[3]=float(is_rare_logon_type(lt));v[4]=float(h)
            v[5]=float(is_suspicious_process(pn))
            v[6]=1.0 if ("%%1937" in s.token_elevation or "full" in s.token_elevation.lower()) else 0.0
            v[7]=1.0 if s.command_line not in ("N/A","") else 0.0
            v[8]=1.0 if eid==4720 else 0.0
            v[9]=1.0 if eid in (4698,4700,4702) else 0.0
            v[10]=1.0 if eid==7045 else 0.0
            v[11]=1.0 if eid in (4625,4776) else 0.0
        elif log.HasField("network"):
            n=log.network; fb=n.flow_bytes_s; fp=max(n.fwd_packets+n.bwd_packets,1)
            v[0]=2.0;v[1]=float(n.dest_port);v[2]=float(is_suspicious_port(n.dest_port))
            v[3]=float(h);v[4]=float(np.log1p(fb));v[5]=float(n.flow_duration_sec)
            v[6]=float(n.fwd_packets);v[7]=float(n.bwd_packets);v[8]=float(n.pkt_len_mean)
            v[9]=float(n.fin_flag_count);v[10]=float(n.psh_flag_count);v[11]=float(n.ack_flag_count)
            v[12]=float(is_suspicious_process(n.owning_process));v[13]=float(n.local_port)
            v[14]=1.0 if n.dest_port==4444 else 0.0
            v[15]=float(n.fwd_packets)/max(float(n.bwd_packets),1)
            v[16]=float(fb)/max(float(fp),1);v[17]=float(TCP_STATE_MAP.get(n.state,0))
        elif log.HasField("dns"):
            d=log.dns; qn=d.query_name
            v[0]=3.0;v[1]=float(DNS_TYPE_MAP.get(d.query_type.upper(),9))
            v[2]=0.0 if "success" in d.query_status.lower() else 1.0
            v[3]=float(h);v[4]=float(len(qn));v[5]=float(qn.count('.'))
        elif log.HasField("powershell"):
            p=log.powershell; txt=p.script_block_text.lower()
            v[0]=4.0;v[1]=float(h);v[2]=float(np.log1p(len(txt)))
            v[3]=1.0 if any(k in txt for k in ["-enc","-encodedcommand","frombase64"]) else 0.0
            v[4]=1.0 if any(k in txt for k in ["invoke-webrequest","downloadstring","webclient"]) else 0.0
    except Exception as e:
        logging.warning(f"Vector error: {e}")
    return v


def find_server():
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
                    url = f"http://{addr[0]}:8000"
                    logging.info(f"[SUCCESS] Connected to Master at {url}")
                    return url
        except Exception as e:
            if "timed out" not in str(e): logging.debug(f"Discovery: {e}")
            time.sleep(1)

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except: return "0.0.0.0"


def ingest_logs():
    if os.path.exists(INCOMING_PATH):
        try:
            if os.path.exists(PROCESSING_PATH): os.remove(PROCESSING_PATH)
            os.rename(INCOMING_PATH, PROCESSING_PATH)
        except OSError: return []
    if not os.path.exists(PROCESSING_PATH): return []
    try:
        with open(PROCESSING_PATH, 'r') as f: raw = json.load(f)
    except Exception as e:
        logging.error(f"JSON parse: {e}"); raw = []
    if isinstance(raw, dict): raw = [raw]

    proto_logs = []
    for item in raw:
        if not isinstance(item, dict): continue
        try:
            log = log_schema_pb2.UnifiedLog()
            log.timestamp = item.get('Timestamp', datetime.now().isoformat())
            log.host_id   = CLIENT_ID
            t = item.get('Type', '')

            if t == "System":
                s = log.system
                s.event_id=safe_int(item.get('EventID'))
                s.task_category=item.get('TaskCategory','N/A')
                s.computer_name=item.get('ComputerName',CLIENT_ID)
                s.record_number=safe_int(item.get('RecordNumber'))
                s.keywords=item.get('Keywords','N/A')
                s.subject_user=item.get('SubjectUserName','N/A')
                s.subject_sid=item.get('SubjectUserSid','N/A')
                s.subject_domain=item.get('SubjectDomainName','N/A')
                s.subject_logon_id=item.get('SubjectLogonId','N/A')
                s.target_user=item.get('TargetUserName','N/A')
                s.target_sid=item.get('TargetUserSid','N/A')
                s.target_domain=item.get('TargetDomainName','N/A')
                s.target_logon_id=item.get('TargetLogonId','N/A')
                s.logon_type=safe_int(item.get('LogonType'))
                s.logon_process=item.get('LogonProcessName','N/A')
                s.auth_package=item.get('AuthPackage','N/A')
                s.workstation=item.get('WorkstationName','N/A')
                s.source_ip=item.get('IpAddress','0.0.0.0')
                s.source_port=item.get('IpPort','0')
                s.impersonation_lvl=item.get('ImpersonationLevel','N/A')
                s.elevated_token=item.get('ElevatedToken','N/A')
                s.token_elevation=item.get('TokenElevationType','N/A')
                s.new_process_id=item.get('NewProcessId','N/A')
                s.new_process_name=item.get('NewProcessName','N/A')
                s.parent_process_id=item.get('ParentProcessId','N/A')
                s.creator_process=item.get('CreatorProcessName','N/A')
                s.command_line=item.get('CommandLine','N/A')
                s.mandatory_label=item.get('MandatoryLabel','N/A')
                s.privilege_list=item.get('PrivilegeList','N/A')
                s.task_name=item.get('TaskName','N/A')
                s.service_name=item.get('ServiceName','N/A')
                s.image_path=item.get('ImagePath','N/A')
                s.sam_account_name=item.get('SamAccountName','N/A')
                s.group_name=item.get('GroupName','N/A')
                s.status=item.get('Status','N/A')
                s.failure_reason=item.get('FailureReason','N/A')
                s.sub_status=item.get('SubStatus','N/A')
            elif t == "Network":
                n = log.network
                n.source_ip=item.get('SourceIP','0.0.0.0')
                n.dest_ip=item.get('DestIP','0.0.0.0')
                n.dest_port=safe_int(item.get('DestinationPort',item.get('DestPort')))
                n.local_port=safe_int(item.get('LocalPort'))
                n.protocol=item.get('Protocol','TCP')
                n.state=item.get('State','N/A')
                n.flow_duration_sec=safe_int(item.get('FlowDurationSec'))
                n.flow_bytes_s=safe_float(item.get('FlowBytesTotal',item.get('FlowBytes',0)))
                n.fwd_packets=safe_int(item.get('FwdPackets'))
                n.bwd_packets=safe_int(item.get('BwdPackets'))
                n.pkt_len_mean=safe_float(item.get('PacketLenMean'))
                n.fin_flag_count=safe_int(item.get('FINFlagProxy'))
                n.psh_flag_count=safe_int(item.get('PSHFlagProxy'))
                n.ack_flag_count=safe_int(item.get('ACKFlagProxy'))
                n.owning_pid=safe_int(item.get('OwningPID'))
                n.owning_process=item.get('OwningProcess','N/A')
                n.attack_type=item.get('AttackType','Unknown')
            elif t == "DNS":
                d=log.dns
                d.event_id=safe_int(item.get('EventID'))
                d.computer_name=item.get('ComputerName',CLIENT_ID)
                d.record_number=safe_int(item.get('RecordNumber'))
                d.query_name=item.get('QueryName','N/A')
                d.query_type=item.get('QueryType','N/A')
                d.query_status=item.get('QueryStatus','N/A')
                d.query_results=item.get('QueryResults','N/A')
                d.pid=item.get('PID','N/A')
            elif t == "PowerShell":
                p=log.powershell
                p.event_id=safe_int(item.get('EventID'))
                p.computer_name=item.get('ComputerName',CLIENT_ID)
                p.record_number=safe_int(item.get('RecordNumber'))
                p.script_block_id=item.get('ScriptBlockId','N/A')
                p.script_block_text=item.get('ScriptBlockText','')
                p.path=item.get('Path','N/A')
                p.message_number=safe_int(item.get('MessageNumber'))
                p.message_total=safe_int(item.get('MessageTotal'))
            else:
                continue
            proto_logs.append(log)
        except Exception as e:
            logging.error(f"Proto error [{item.get('Type','?')}]: {e}")

    if proto_logs:
        try:
            with open(STORAGE_PATH, 'ab') as f:
                for pl in proto_logs:
                    data = pl.SerializeToString()
                    f.write(struct.pack(">I", len(data)))
                    f.write(data)
        except Exception as e:
            logging.error(f"Archive write: {e}")

    try: os.remove(PROCESSING_PATH)
    except: pass
    return proto_logs


def build_alert(log, vector, ae_score, ae_threshold, severity, threat_type, reason, rule_matched=False, rule_name=""):
    try:
        alert = log_schema_pb2.AlertEvent()
        alert.alert_id      = str(uuid.uuid4())
        alert.timestamp     = log.timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert.client_id     = CLIENT_ID
        alert.client_ip     = get_local_ip()
        alert.severity      = severity
        alert.threat_type   = threat_type
        alert.reason        = reason
        alert.ae_score      = float(ae_score)
        alert.ae_threshold  = float(ae_threshold)
        alert.rule_matched  = rule_matched
        alert.rule_name     = rule_name
        alert.source_log.CopyFrom(log)
        data = alert.SerializeToString()
        return struct.pack(">I", len(data)) + data
    except AttributeError:
        payload = json.dumps({
            "alert_id": str(uuid.uuid4()), "timestamp": log.timestamp,
            "client_id": CLIENT_ID, "client_ip": get_local_ip(),
            "severity": severity, "threat_type": threat_type,
            "reason": reason, "ae_score": float(ae_score),
            "rule_matched": rule_matched, "rule_name": rule_name,
        }).encode()
        return struct.pack(">I", len(payload)) + payload


def load_history_for_training():
    if not os.path.exists(STORAGE_PATH): return []
    vectors = []
    try:
        sz = os.path.getsize(STORAGE_PATH)
        with open(STORAGE_PATH, 'rb') as f:
            if sz > 2_000_000: f.seek(sz - 2_000_000)
            while True:
                sb = f.read(4)
                if len(sb) < 4: break
                size = struct.unpack(">I", sb)[0]
                data = f.read(size)
                if len(data) < size: break
                log = log_schema_pb2.UnifiedLog()
                log.ParseFromString(data)
                vectors.append(extract_vector(log))
    except Exception as e:
        logging.error(f"History load: {e}")
    return vectors[-200:]


def main_watchdog():
    logging.info("[START] FLARE Agent Started")
    detector   = LocalDetector(MODEL_PATH)
    SERVER_URL = find_server()
    HEADERS    = {"X-Auth-Token": SECRET_KEY.decode()}
    alert_queue = []

    # Dedup cache: persisted to disk so restarts don't re-fire old alerts
    COOLDOWN = 300
    _seen = {}
    try:
        if os.path.exists(DEDUP_FILE):
            raw = json.load(open(DEDUP_FILE))
            now = time.time()
            # Only load entries that are still within cooldown window
            _seen = {k: v for k, v in raw.items() if now - v < COOLDOWN}
            logging.info(f"[DEDUP] Loaded {len(_seen)} cached entries")
    except Exception as e:
        logging.warning(f"[DEDUP] Cache load failed: {e}")
        _seen = {}

    def _key(threat_type, log):
        try:
            if log.HasField("system"):
                return f"{threat_type}|{log.system.event_id}|{log.system.target_user}|{log.system.logon_type}"
            elif log.HasField("network"):
                return f"{threat_type}|{log.network.dest_port}|{log.network.source_ip}|{log.network.dest_ip}"
            elif log.HasField("dns"):
                return f"{threat_type}|{log.dns.query_name}"
            elif log.HasField("powershell"):
                return f"{threat_type}|{log.powershell.script_block_text[:80]}"
        except Exception: pass
        return f"{threat_type}|unknown"

    def _is_dup(threat_type, log):
        k = _key(threat_type, log)
        now = time.time()
        if now - _seen.get(k, 0) < COOLDOWN:
            return True
        _seen[k] = now
        # Prune expired entries
        for old_k in [x for x, t in list(_seen.items()) if now - t > COOLDOWN * 2]:
            del _seen[old_k]
        # Persist to disk so restarts don't re-send old alerts
        try:
            os.makedirs(os.path.dirname(DEDUP_FILE), exist_ok=True)
            json.dump(_seen, open(DEDUP_FILE, 'w'))
        except Exception:
            pass
        return False

    fl_tick = 0

    while True:
        try:
            new_logs = ingest_logs()

            for log in new_logs:
                vector = extract_vector(log)
                is_anom, ae_sc = detector.is_anomaly(vector)
                rule = run_rules(log)

                if is_anom or rule:
                    if rule:
                        sev, ttype, reason = rule
                        matched, rname = True, f"Rule_{ttype}"
                    else:
                        sev, ttype = 2, "ML_Anomaly"
                        reason = f"AE score {ae_sc:.4f} > threshold {detector.ae_threshold:.4f}"
                        matched, rname = False, ""

                    if _is_dup(ttype, log):
                        continue

                    alert_queue.append(build_alert(log, vector, ae_sc, detector.ae_threshold,
                                                   sev, ttype, reason, matched, rname))
                    logging.warning(f"[ALERT] {ttype} | {reason}")

            if alert_queue:
                try:
                    requests.post(f"{SERVER_URL}/api/alerts/ingest",
                                  data=b"".join(alert_queue), headers=HEADERS, timeout=5)
                    logging.info(f"[ALERT] Sent {len(alert_queue)} alert(s)")
                    alert_queue.clear()
                except Exception as e:
                    logging.warning(f"Alert send failed (retry next): {e}")

            # FL update every 60s (not every 10s) to reduce server noise
            fl_tick += 1
            if fl_tick >= 6:
                fl_tick = 0
                vectors = load_history_for_training()
                if vectors:
                    X = np.array(vectors, dtype=np.float32)
                    weights = np.mean(X, axis=0).tolist()
                    try:
                        requests.post(f"{SERVER_URL}/api/fl/update",
                            json={'client_id': CLIENT_ID, 'weights': weights,
                                  'sample_count': len(X), 'vector_dim': VECTOR_DIM,
                                  'type_counts': {
                                      'system':     int(sum(1 for v in vectors if v[0]==1)),
                                      'network':    int(sum(1 for v in vectors if v[0]==2)),
                                      'dns':        int(sum(1 for v in vectors if v[0]==3)),
                                      'powershell': int(sum(1 for v in vectors if v[0]==4)),
                                  }},
                            headers=HEADERS, timeout=5)
                    except Exception as e:
                        logging.warning(f"FL update failed: {e}")

            time.sleep(10)

        except Exception as e:
            logging.error(f"Loop error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main_watchdog()
