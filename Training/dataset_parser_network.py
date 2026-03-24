"""
FLARE Dataset Parser – CICIDS2017 (Network)
=============================================
Reads the full CICIDS2017 CSV (or the head-10 sample) and produces:
  1. A list of log_schema_pb2.UnifiedLog objects (same format as live agent)
  2. Feature vectors via fl_client.extract_vector()
  3. Attack-type labels for supervised evaluation

This makes the training pipeline identical whether data comes from
the live PowerShell collector or the research dataset.

Usage:
  rows, vectors, labels = load_cicids("cicids2017_cleaned.csv")

Column → Proto field mapping (all 52 CICIDS columns preserved):
  Destination Port          → network.dest_port
  Flow Duration             → network.flow_duration_sec  (µs → sec)
  Total Fwd Packets         → network.fwd_packets
  Total Length of Fwd Packets → network.fwd_bytes_total
  Fwd Packet Length Max/Min/Mean/Std → stored in pkt_len_max/min/mean/std
  Bwd Packet Length Max/Min/Mean/Std → (mean used as bwd proxy)
  Flow Bytes/s              → network.flow_bytes_s
  Flow Packets/s            → network.flow_packets_s
  Flow IAT Mean             → network.iat_mean_ms        (µs → ms)
  FIN/PSH/ACK Flag Count    → network.fin/psh/ack_flag_count
  Init_Win_bytes_forward    → network.init_win_fwd
  Init_Win_bytes_backward   → network.init_win_bwd
  Active Mean               → network.active_mean
  Idle Mean                 → network.idle_mean
  Attack Type               → network.attack_type        (label)
"""

import csv, os, struct, sys
from datetime import datetime

# ── resolve imports whether run standalone or from project root ──────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

try:
    import log_schema_pb2
except ImportError:
    print("ERROR: log_schema_pb2.py not found. Place this script next to it.")
    sys.exit(1)

try:
    # reuse extract_vector from the live client
    import importlib.util
    _spec = importlib.util.spec_from_file_location(
        "fl_client", os.path.join(_HERE, "fl_client.py"))
    _fc = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_fc)
    extract_vector = _fc.extract_vector
except Exception as e:
    print(f"WARNING: could not import fl_client ({e}). Vectors will be empty.")
    extract_vector = lambda log: [0.0] * 18


# ── helpers ──────────────────────────────────────────────────────────────────
def _f(row, col, default=0.0):
    try:
        v = str(row.get(col, "")).strip()
        if v in ("", "Infinity", "inf", "nan", "-1"):
            return default
        return float(v)
    except:
        return default

def _i(row, col, default=0):
    try:
        v = str(row.get(col, "")).strip()
        if v in ("", "Infinity", "inf", "nan", "-1"): return default
        if v.upper().startswith("0X"): return int(v, 16)
        return int(float(v))
    except:
        return default


# Attack type normalisation – CICIDS labels → shorter canonical form
_LABEL_MAP = {
    "Normal Traffic":         "Normal",
    "BENIGN":                 "Normal",
    "DoS Hulk":               "DoS",
    "DoS GoldenEye":          "DoS",
    "DoS slowloris":          "DoS",
    "DoS Slowhttptest":       "DoS",
    "DDoS":                   "DDoS",
    "PortScan":               "PortScan",
    "FTP-Patator":            "BruteForce",
    "SSH-Patator":            "BruteForce",
    "Brute Force":            "BruteForce",
    "Web Attack – Brute Force": "BruteForce",
    "Web Attack – XSS":       "WebAttack",
    "Web Attack – Sql Injection": "SQLInjection",
    "Infiltration":           "Infiltration",
    "Heartbleed":             "Heartbleed",
    "Bot":                    "Bot",
}

def normalise_label(raw: str) -> str:
    raw = raw.strip()
    for k, v in _LABEL_MAP.items():
        if k.lower() == raw.lower():
            return v
    return raw  # keep unknown labels as-is


# ── main loader ──────────────────────────────────────────────────────────────
def load_cicids(csv_path: str, max_rows: int = None):
    """
    Returns
    -------
    proto_logs : list[UnifiedLog]
    vectors    : list[list[float]]   – 18-dim, from extract_vector()
    labels     : list[str]           – normalised attack type
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CICIDS CSV not found: {csv_path}")

    proto_logs, vectors, labels = [], [], []
    ts_base = "2017-07-03 08:00:00"   # CICIDS2017 collection start date

    with open(csv_path, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if max_rows and i >= max_rows:
                break

            label = normalise_label(row.get("Attack Type", row.get("Label", "Unknown")))

            log = log_schema_pb2.UnifiedLog()
            log.timestamp = ts_base    # dataset has no per-row timestamp
            log.host_id   = "CICIDS2017_DATASET"

            n = log.network
            n.dest_port        = _i(row, "Destination Port")
            n.local_port       = 0                          # not in dataset
            n.protocol         = "TCP"
            n.state            = "ESTABLISHED"

            # Flow timing – CICIDS stores duration in microseconds
            dur_us             = _f(row, "Flow Duration")
            n.flow_duration_sec = max(0, int(dur_us / 1_000_000))
            n.flow_bytes_s     = max(0.0, _f(row, "Flow Bytes/s"))
            n.flow_packets_s   = _f(row, "Flow Packets/s")
            n.iat_mean_ms      = _f(row, "Flow IAT Mean") / 1000.0   # µs → ms

            # Packet counts
            n.fwd_packets      = _i(row, "Total Fwd Packets")
            n.bwd_packets      = _i(row, "Total Bwd Packets") if "Total Bwd Packets" in row else 0
            n.fwd_bytes_total  = _f(row, "Total Length of Fwd Packets")

            # Packet length stats (use Fwd mean/max as primary)
            n.pkt_len_min      = _f(row, "Min Packet Length")
            n.pkt_len_max      = _f(row, "Max Packet Length")
            n.pkt_len_mean     = _f(row, "Packet Length Mean")
            n.pkt_len_std      = _f(row, "Packet Length Std")

            # TCP flags
            n.fin_flag_count   = _i(row, "FIN Flag Count")
            n.psh_flag_count   = _i(row, "PSH Flag Count")
            n.ack_flag_count   = _i(row, "ACK Flag Count")

            # Window sizes
            n.init_win_fwd     = _i(row, "Init_Win_bytes_forward")
            n.init_win_bwd     = _i(row, "Init_Win_bytes_backward")

            # Activity timing (CICIDS stores in µs)
            n.active_mean      = _f(row, "Active Mean") / 1_000_000.0
            n.idle_mean        = _f(row, "Idle Mean")   / 1_000_000.0

            # No process info in CICIDS
            n.owning_pid       = 0
            n.owning_process   = "N/A"
            n.attack_type      = label

            proto_logs.append(log)
            vectors.append(extract_vector(log))
            labels.append(label)

    print(f"[CICIDS] Loaded {len(proto_logs)} rows from {os.path.basename(csv_path)}")
    _print_label_dist(labels)
    return proto_logs, vectors, labels


def _print_label_dist(labels):
    from collections import Counter
    counts = Counter(labels)
    total  = len(labels)
    print(f"  Label distribution ({total} total):")
    for lbl, cnt in counts.most_common():
        print(f"    {lbl:<20} {cnt:>6}  ({100*cnt/total:.1f}%)")


# ── optional: write to binary archive (same format as live agent) ─────────────
def save_to_binary(proto_logs, out_path: str):
    """Write proto logs to the same length-delimited binary the live agent uses."""
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, 'ab') as f:
        for log in proto_logs:
            data = log.SerializeToString()
            f.write(struct.pack(">I", len(data)))
            f.write(data)
    print(f"[CICIDS] Saved {len(proto_logs)} protos to {out_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("csv", help="Path to CICIDS2017 CSV file")
    p.add_argument("--max", type=int, default=None, help="Max rows to load")
    p.add_argument("--save-bin", default=None, help="Also save to binary archive at this path")
    args = p.parse_args()

    logs, vecs, lbls = load_cicids(args.csv, max_rows=args.max)
    print(f"\nVector shape: {len(vecs)} × {len(vecs[0]) if vecs else 0}")

    if args.save_bin:
        save_to_binary(logs, args.save_bin)
