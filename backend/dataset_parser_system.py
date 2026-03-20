"""
FLARE Dataset Parser – BOTSv3 Windows Event Log
=================================================
Reads the BOTSv3 Splunk export CSV and produces:
  1. list[UnifiedLog] – same format as live agent output
  2. feature vectors via fl_client_v2.extract_vector()
  3. labels derived from EventCode + TaskCategory

BOTSv3 column → SystemEvent proto field mapping (all 47 cols):
  Account_Domain      → subject_domain
  Account_Name        → subject_user  (Splunk's merged field)
  ComputerName        → computer_name
  Creator_Process_ID  → parent_process_id
  Creator_Process_Name → creator_process
  EventCode           → event_id
  EventType           → (used for label derivation only)
  Exit_Status         → status
  Handle_ID           → (metadata, not in proto)
  Keywords            → keywords
  LogName             → log_name
  Logon_ID            → subject_logon_id
  Mandatory_Label     → mandatory_label
  Message             → (not stored – too large)
  New_Process_ID      → new_process_id
  New_Process_Name    → new_process_name
  Privileges          → privilege_list
  Process_Command_Line → command_line
  Process_ID          → parent_process_id (creator PID)
  Process_Name        → creator_process   (current process)
  RecordNumber        → record_number
  Security_ID         → subject_sid
  Service_Name        → service_name
  TaskCategory        → task_category
  Token_Elevation_Type → token_elevation
  Type                → keywords (supplementary)
  _time               → timestamp
  host                → computer_name (fallback)
"""

import csv, os, re, sys, struct
from datetime import datetime

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

try:
    import log_schema_pb2
except ImportError:
    print("ERROR: log_schema_pb2.py not found.")
    sys.exit(1)

try:
    import importlib.util
    _spec = importlib.util.spec_from_file_location(
        "fl_client_v2", os.path.join(_HERE, "fl_client_v2.py"))
    _fc = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_fc)
    extract_vector = _fc.extract_vector
except Exception as e:
    print(f"WARNING: could not import fl_client_v2 ({e}). Vectors will be empty.")
    extract_vector = lambda log: [0.0] * 18


# ── helpers ───────────────────────────────────────────────────────────────────
def _s(row, col, default="N/A"):
    v = row.get(col, "").strip()
    return v if v else default

def _i(row, col, default=0):
    try:
        v = str(row.get(col, "")).strip()
        if not v: return default
        if v.upper().startswith("0X"): return int(v, 16)
        return int(float(v))
    except:
        return default


# Normalise _time from BOTSv3 format: "2018-08-20T20:18:00.000+0500"
def _parse_time(raw: str) -> str:
    if not raw: return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # strip timezone suffix, keep up to seconds
    raw = re.sub(r'\.\d+.*$', '', raw)   # remove .000+0500
    raw = raw.replace("T", " ")[:19]
    return raw


# ── EventCode → threat label ──────────────────────────────────────────────────
# Based on BOTSv3 scenario mapping + MITRE ATT&CK tactic
_ECODE_LABEL = {
    4624:  "Logon_Success",
    4625:  "Logon_Failure",          # Brute Force
    4648:  "Explicit_Credential",    # Pass-the-Hash / Lateral Movement
    4672:  "Privilege_Escalation",
    4688:  "Process_Creation",
    4689:  "Process_Termination",
    4698:  "Persistence_SchedTask",
    4700:  "Persistence_SchedTask",
    4702:  "Persistence_SchedTask",
    4720:  "Backdoor_NewUser",
    4726:  "Account_Deleted",
    4732:  "Group_Membership_Change",
    4776:  "NTLM_Auth",
    7045:  "Persistence_Service",
    4657:  "Registry_Modified",
    4663:  "File_Access",
    4673:  "Sensitive_Privilege_Use",
}

def derive_label(event_code: int, process_name: str, task_category: str) -> str:
    """Produce a threat label from available BOTSv3 fields."""
    base = _ECODE_LABEL.get(event_code, f"EventID_{event_code}")

    # Enrich process-creation events with LOLBaS/malware flag
    if event_code == 4688 and process_name not in ("", "N/A"):
        pn = process_name.lower()
        if any(m in pn for m in ["mimikatz", "meterpreter", "cobaltstrike", "ncat"]):
            return "Malware_Execution"
        if any(l in pn for l in ["powershell", "wscript", "cscript", "certutil",
                                  "mshta", "regsvr32", "rundll32", "bitsadmin"]):
            return "LOLBaS_Execution"

    return base


# ── main loader ───────────────────────────────────────────────────────────────
def load_botsv3(csv_path: str, max_rows: int = None):
    """
    Returns
    -------
    proto_logs : list[UnifiedLog]
    vectors    : list[list[float]]
    labels     : list[str]
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"BOTSv3 CSV not found: {csv_path}")

    proto_logs, vectors, labels = [], [], []

    with open(csv_path, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if max_rows and i >= max_rows:
                break

            # ── proto construction ──────────────────────────────────────────
            log = log_schema_pb2.UnifiedLog()
            log.timestamp = _parse_time(_s(row, "_time"))
            log.host_id   = _s(row, "host", _s(row, "ComputerName", "BOTSV3_DATASET"))

            s = log.system
            eid               = _i(row, "EventCode")
            s.event_id        = eid
            s.task_category   = _s(row, "TaskCategory")
            s.log_name        = _s(row, "LogName", "Security")
            s.computer_name   = _s(row, "ComputerName", log.host_id)
            s.record_number   = _i(row, "RecordNumber")
            s.keywords        = _s(row, "Keywords")

            # Subject / actor
            # BOTSv3 merges subject+target into Account_Name in some rows
            s.subject_user    = _s(row, "Account_Name")
            s.subject_sid     = _s(row, "Security_ID")
            s.subject_domain  = _s(row, "Account_Domain")
            s.subject_logon_id = _s(row, "Logon_ID")

            # Logon fields
            s.logon_type      = _i(row, "LogonType") if "LogonType" in row else 0
            s.token_elevation = _s(row, "Token_Elevation_Type")
            s.mandatory_label = _s(row, "Mandatory_Label")
            s.status          = _s(row, "Exit_Status")

            # Process fields
            s.new_process_id   = _s(row, "New_Process_ID")
            s.new_process_name = _s(row, "New_Process_Name")
            s.parent_process_id = _s(row, "Process_ID")
            # Creator_Process_Name is the parent; Process_Name is the subject process
            s.creator_process  = _s(row, "Creator_Process_Name",
                                    _s(row, "Process_Name"))
            s.command_line     = _s(row, "Process_Command_Line")
            s.privilege_list   = _s(row, "Privileges")

            # Service (7045)
            s.service_name     = _s(row, "Service_Name")

            # ── label ───────────────────────────────────────────────────────
            proc_name = s.new_process_name if s.new_process_name != "N/A" else s.creator_process
            label = derive_label(eid, proc_name, s.task_category)

            proto_logs.append(log)
            vectors.append(extract_vector(log))
            labels.append(label)

    print(f"[BOTSv3] Loaded {len(proto_logs)} rows from {os.path.basename(csv_path)}")
    _print_label_dist(labels)
    return proto_logs, vectors, labels


def _print_label_dist(labels):
    from collections import Counter
    counts = Counter(labels)
    total  = len(labels)
    print(f"  Label distribution ({total} total):")
    for lbl, cnt in counts.most_common():
        print(f"    {lbl:<30} {cnt:>6}  ({100*cnt/total:.1f}%)")


def save_to_binary(proto_logs, out_path: str):
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, 'ab') as f:
        for log in proto_logs:
            data = log.SerializeToString()
            f.write(struct.pack(">I", len(data)))
            f.write(data)
    print(f"[BOTSv3] Saved {len(proto_logs)} protos to {out_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("csv", help="Path to BOTSv3 WinEventLog CSV file")
    p.add_argument("--max", type=int, default=None)
    p.add_argument("--save-bin", default=None)
    args = p.parse_args()

    logs, vecs, lbls = load_botsv3(args.csv, max_rows=args.max)
    print(f"\nVector shape: {len(vecs)} × {len(vecs[0]) if vecs else 0}")

    if args.save_bin:
        save_to_binary(logs, args.save_bin)
