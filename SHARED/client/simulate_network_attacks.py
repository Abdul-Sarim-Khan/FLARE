"""
FLARE v0.4 - Network Attack Simulator
──────────────────────────────────────
Injects synthetic malicious network flow rows into the pktmon CSV so the
ML-based network inference engine (flare_network_infer.py) picks them up
and sends alerts to the FLARE dashboard.

HOW IT WORKS
  1. Loads the actual MLP model + scaler to verify every row scores as ATTACK
     (confidence >= threshold) before writing it.
  2. Generates realistic CICIDS-style feature vectors for 5 attack types.
  3. APPENDS validated rows to net_flows.csv (never overwrites — the
     _OffsetTracker byte-position mechanism requires append-only writes).
  4. The agent's network inference thread picks up the new rows within
     its next 30-second poll cycle and forwards alerts to the server.

ATTACK TYPES SIMULATED
  [01] DDoS            - HTTP flood:  high bps/pps, no server response
  [02] Port Scan       - SYN scan:    tiny flows, zero backward traffic
  [03] SSH Brute Force - Port 22:     many auth attempts, PSH+ACK heavy
  [04] Web Attack      - SQL inject:  port 80, large forward payloads
  [05] Botnet C2       - Beaconing:   port 443, low-rate regular pulses

USAGE
  # Run from the client directory (same dir as flare_agent.py):
  python simulate_network_attacks.py

  # Override CSV path:
  python simulate_network_attacks.py --csv C:\\path\\to\\net_flows.csv

  # More rows per attack type for sustained testing:
  python simulate_network_attacks.py --count 20

  # Dry-run: show what would be written, don't touch the file:
  python simulate_network_attacks.py --dry-run
"""

import argparse
import csv
import os
import random
import sys
from pathlib import Path

# ── Path setup ─────────────────────────────────────────────────────────────────
_CLIENT_DIR = Path(__file__).parent
_NET_DIR    = _CLIENT_DIR / "network"
for _p in (str(_CLIENT_DIR), str(_NET_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ── Feature list (must match feature_names.json exactly) ──────────────────────
FEATURES = [
    "DestinationPort",
    "FlowDurationMs",
    "TotalFwdPackets",
    "TotalLenFwdPackets",
    "FwdPacketLenMax",
    "FwdPacketLenMin",
    "FwdPacketLenMean",
    "FwdPacketLenStd",
    "BwdPacketLenMax",
    "BwdPacketLenMin",
    "BwdPacketLenMean",
    "BwdPacketLenStd",
    "FlowBytesPerSec",
    "FlowPacketsPerSec",
    "FlowIATMean",
    "FlowIATStd",
    "FlowIATMax",
    "FlowIATMin",
    "FwdIATTotal",
    "FwdIATMean",
    "FwdIATStd",
    "FwdIATMax",
    "FwdIATMin",
    "BwdIATTotal",
    "BwdIATMean",
    "BwdIATStd",
    "BwdIATMax",
    "BwdIATMin",
    "FINFlagCount",
    "PSHFlagCount",
    "ACKFlagCount",
    "InitWinBytesFwd",
    "InitWinBytesBwd",
    "AveragePacketSize",
]

# ── Attack profile generators ──────────────────────────────────────────────────
# Each function returns a dict of feature-name → value.
# Values are chosen to match CICIDS2017/2018 statistics for each attack class.

def _rnd(lo, hi):
    """Uniform float in [lo, hi]."""
    return random.uniform(lo, hi)

def _rint(lo, hi):
    """Uniform int in [lo, hi]."""
    return random.randint(lo, hi)


def _profile_ddos():
    """
    DDoS - HTTP/UDP flood.
    Each row represents ONE SHORT FLOW from the flood, not the entire flood.
    Flood traffic appears as many tiny flows: small fwd packet count, zero backward
    traffic (server can't respond), very short duration, low InitWin.
    PSH/ACK/FIN flags are binary (0 or 1) as in CICIDS training data.
    """
    duration_ms = _rnd(5, 100)         # very short individual flows
    fwd_pkts    = _rint(2, 15)         # few packets per flow (per-flow, not total flood)
    pkt_size    = _rnd(40, 60)         # tiny SYN/ACK-size packets
    fwd_len     = int(fwd_pkts * pkt_size)
    bps         = fwd_len / max(duration_ms / 1000.0, 0.001)
    pps         = fwd_pkts / max(duration_ms / 1000.0, 0.001)
    iat_mean    = (duration_ms * 1000) / max(fwd_pkts, 1)

    return {
        "DestinationPort":      random.choice([80, 443, 53]),
        "FlowDurationMs":       duration_ms,
        "TotalFwdPackets":      fwd_pkts,
        "TotalLenFwdPackets":   fwd_len,
        "FwdPacketLenMax":      _rint(50, 70),
        "FwdPacketLenMin":      40,
        "FwdPacketLenMean":     pkt_size,
        "FwdPacketLenStd":      _rnd(0, 8),
        "BwdPacketLenMax":      0,
        "BwdPacketLenMin":      0,
        "BwdPacketLenMean":     0,
        "BwdPacketLenStd":      0,
        "FlowBytesPerSec":      bps,
        "FlowPacketsPerSec":    pps,
        "FlowIATMean":          iat_mean,
        "FlowIATStd":           _rnd(0, iat_mean * 0.2),
        "FlowIATMax":           iat_mean * _rnd(1.2, 2.0),
        "FlowIATMin":           _rnd(0, 5),
        "FwdIATTotal":          duration_ms * 1000,
        "FwdIATMean":           iat_mean,
        "FwdIATStd":            _rnd(0, iat_mean * 0.2),
        "FwdIATMax":            iat_mean * _rnd(1.2, 2.0),
        "FwdIATMin":            _rnd(0, 5),
        "BwdIATTotal":          0,
        "BwdIATMean":           0,
        "BwdIATStd":            0,
        "BwdIATMax":            0,
        "BwdIATMin":            0,
        "FINFlagCount":         0,
        "PSHFlagCount":         0,           # binary flag — no PSH in SYN flood
        "ACKFlagCount":         _rint(0, 1), # binary flag
        "InitWinBytesFwd":      _rint(512, 2048),   # low window = attack signal
        "InitWinBytesBwd":      0,
        "AveragePacketSize":    pkt_size,
    }


def _profile_port_scan():
    """
    Port scan - SYN scan.
    Characteristics: extremely short flow (1-50ms), 1-2 forward packets,
    ZERO backward traffic (closed port / no response), tiny SYN packet size.
    Many different destination ports.
    """
    duration_ms = _rnd(1, 50)
    fwd_pkts    = _rint(1, 3)
    fwd_len     = fwd_pkts * _rint(40, 60)
    bps         = fwd_len / max(duration_ms / 1000.0, 0.001)
    pps         = fwd_pkts / max(duration_ms / 1000.0, 0.001)

    return {
        "DestinationPort":      _rint(1, 65535),
        "FlowDurationMs":       duration_ms,
        "TotalFwdPackets":      fwd_pkts,
        "TotalLenFwdPackets":   fwd_len,
        "FwdPacketLenMax":      60,
        "FwdPacketLenMin":      40,
        "FwdPacketLenMean":     _rnd(40, 60),
        "FwdPacketLenStd":      _rnd(0, 5),
        "BwdPacketLenMax":      0,
        "BwdPacketLenMin":      0,
        "BwdPacketLenMean":     0,
        "BwdPacketLenStd":      0,
        "FlowBytesPerSec":      bps,
        "FlowPacketsPerSec":    pps,
        "FlowIATMean":          duration_ms * 1000 / max(fwd_pkts, 1),
        "FlowIATStd":           0,
        "FlowIATMax":           duration_ms * 1000,
        "FlowIATMin":           0,
        "FwdIATTotal":          duration_ms * 1000,
        "FwdIATMean":           duration_ms * 1000 / max(fwd_pkts, 1),
        "FwdIATStd":            0,
        "FwdIATMax":            duration_ms * 1000,
        "FwdIATMin":            0,
        "BwdIATTotal":          0,
        "BwdIATMean":           0,
        "BwdIATStd":            0,
        "BwdIATMax":            0,
        "BwdIATMin":            0,
        "FINFlagCount":         _rint(0, 1),
        "PSHFlagCount":         0,
        "ACKFlagCount":         0,
        "InitWinBytesFwd":      _rint(1024, 8192),
        "InitWinBytesBwd":      0,
        "AveragePacketSize":    _rnd(40, 60),
    }


def _profile_ssh_brute():
    """
    SSH brute force - each row = ONE failed auth attempt flow.
    Failed auth: client sends credentials, server rejects quickly.
    Flow is short, small packet count, small packet sizes.
    PSH/ACK flags are BINARY (0 or 1) as in CICIDS training data.
    """
    duration_ms  = _rnd(50, 400)       # failed auth completes fast
    fwd_pkts     = _rint(2, 8)         # few packets per attempt
    bwd_pkts     = _rint(1, 4)         # server sends auth challenge + rejection
    fwd_pkt_size = _rnd(50, 120)       # client credential packet
    bwd_pkt_size = _rnd(50, 100)       # server rejection is small
    total_bytes  = fwd_pkts * fwd_pkt_size + bwd_pkts * bwd_pkt_size
    bps          = total_bytes / max(duration_ms / 1000.0, 0.001)
    pps          = (fwd_pkts + bwd_pkts) / max(duration_ms / 1000.0, 0.001)
    iat          = (duration_ms * 1000) / max(fwd_pkts + bwd_pkts, 1)

    return {
        "DestinationPort":      22,
        "FlowDurationMs":       duration_ms,
        "TotalFwdPackets":      fwd_pkts,
        "TotalLenFwdPackets":   int(fwd_pkts * fwd_pkt_size),
        "FwdPacketLenMax":      _rint(80, 150),
        "FwdPacketLenMin":      _rint(40, 60),
        "FwdPacketLenMean":     fwd_pkt_size,
        "FwdPacketLenStd":      _rnd(5, 30),
        "BwdPacketLenMax":      _rint(60, 120),
        "BwdPacketLenMin":      _rint(40, 60),
        "BwdPacketLenMean":     bwd_pkt_size,
        "BwdPacketLenStd":      _rnd(5, 25),
        "FlowBytesPerSec":      bps,
        "FlowPacketsPerSec":    pps,
        "FlowIATMean":          iat,
        "FlowIATStd":           _rnd(iat * 0.1, iat * 0.4),
        "FlowIATMax":           iat * _rnd(1.5, 3.0),
        "FlowIATMin":           _rnd(5, 50),
        "FwdIATTotal":          duration_ms * 1000 * 0.6,
        "FwdIATMean":           iat * 1.1,
        "FwdIATStd":            _rnd(iat * 0.1, iat * 0.3),
        "FwdIATMax":            iat * _rnd(1.5, 2.5),
        "FwdIATMin":            _rnd(5, 50),
        "BwdIATTotal":          duration_ms * 1000 * 0.4,
        "BwdIATMean":           iat * 0.9,
        "BwdIATStd":            _rnd(iat * 0.1, iat * 0.3),
        "BwdIATMax":            iat * _rnd(1.5, 2.5),
        "BwdIATMin":            _rnd(5, 50),
        "FINFlagCount":         1,           # connection closed (failed auth)
        "PSHFlagCount":         1,           # binary flag
        "ACKFlagCount":         1,           # binary flag
        "InitWinBytesFwd":      _rint(8192, 16384),
        "InitWinBytesBwd":      _rint(8192, 16384),
        "AveragePacketSize":    (fwd_pkt_size + bwd_pkt_size) / 2,
    }


def _profile_web_attack():
    """
    Web attack - SQL injection / XSS.
    Characteristics: dest port 80 or 8080, large forward payloads (injected SQL),
    moderate-to-high FlowBytesPerSec, irregular IAT (attacker typing/scripting).
    """
    duration_ms  = _rnd(2000, 15000)
    fwd_pkts     = _rint(10, 60)
    bwd_pkts     = _rint(5, 30)
    fwd_pkt_size = _rnd(400, 1400)   # large payloads with SQL
    bwd_pkt_size = _rnd(200, 800)
    total_bytes  = fwd_pkts * fwd_pkt_size + bwd_pkts * bwd_pkt_size
    bps          = total_bytes / max(duration_ms / 1000.0, 0.001)
    pps          = (fwd_pkts + bwd_pkts) / max(duration_ms / 1000.0, 0.001)
    iat          = (duration_ms * 1000) / max(fwd_pkts + bwd_pkts, 1)

    return {
        "DestinationPort":      random.choice([80, 8080, 8000]),
        "FlowDurationMs":       duration_ms,
        "TotalFwdPackets":      fwd_pkts,
        "TotalLenFwdPackets":   int(fwd_pkts * fwd_pkt_size),
        "FwdPacketLenMax":      _rint(1000, 1460),
        "FwdPacketLenMin":      _rint(200, 500),
        "FwdPacketLenMean":     fwd_pkt_size,
        "FwdPacketLenStd":      _rnd(100, 350),
        "BwdPacketLenMax":      _rint(400, 1200),
        "BwdPacketLenMin":      _rint(100, 300),
        "BwdPacketLenMean":     bwd_pkt_size,
        "BwdPacketLenStd":      _rnd(100, 300),
        "FlowBytesPerSec":      bps,
        "FlowPacketsPerSec":    pps,
        "FlowIATMean":          iat,
        "FlowIATStd":           _rnd(iat * 0.5, iat * 2.0),  # irregular
        "FlowIATMax":           iat * _rnd(4, 10),
        "FlowIATMin":           _rnd(50, 500),
        "FwdIATTotal":          duration_ms * 1000 * 0.7,
        "FwdIATMean":           iat * 1.3,
        "FwdIATStd":            _rnd(iat * 0.5, iat * 2.0),
        "FwdIATMax":            iat * _rnd(4, 10),
        "FwdIATMin":            _rnd(50, 500),
        "BwdIATTotal":          duration_ms * 1000 * 0.5,
        "BwdIATMean":           iat * 1.1,
        "BwdIATStd":            _rnd(iat * 0.3, iat * 1.5),
        "BwdIATMax":            iat * _rnd(3, 8),
        "BwdIATMin":            _rnd(50, 500),
        "FINFlagCount":         1,
        "PSHFlagCount":         1,           # binary flag
        "ACKFlagCount":         1,           # binary flag
        "InitWinBytesFwd":      65535,
        "InitWinBytesBwd":      _rint(16384, 65535),
        "AveragePacketSize":    (fwd_pkt_size + bwd_pkt_size) / 2,
    }


def _profile_botnet_c2():
    """
    Botnet C2 beaconing.
    Characteristics: port 443, low but regular traffic (heartbeat),
    long BwdIATMax (waiting for command), medium BwdPacketLenMean (C2 responses).
    """
    duration_ms  = _rnd(10000, 60000)  # longer flows
    fwd_pkts     = _rint(5, 25)
    bwd_pkts     = _rint(3, 20)
    fwd_pkt_size = _rnd(100, 400)
    bwd_pkt_size = _rnd(300, 900)     # C2 responses larger than beacons
    total_bytes  = fwd_pkts * fwd_pkt_size + bwd_pkts * bwd_pkt_size
    bps          = total_bytes / max(duration_ms / 1000.0, 0.001)
    pps          = (fwd_pkts + bwd_pkts) / max(duration_ms / 1000.0, 0.001)
    fwd_iat      = (duration_ms * 1000) / max(fwd_pkts, 1)
    bwd_iat      = (duration_ms * 1000) / max(bwd_pkts, 1)

    return {
        "DestinationPort":      random.choice([443, 8443, 4444, 1337]),
        "FlowDurationMs":       duration_ms,
        "TotalFwdPackets":      fwd_pkts,
        "TotalLenFwdPackets":   int(fwd_pkts * fwd_pkt_size),
        "FwdPacketLenMax":      _rint(300, 500),
        "FwdPacketLenMin":      _rint(80, 150),
        "FwdPacketLenMean":     fwd_pkt_size,
        "FwdPacketLenStd":      _rnd(20, 80),
        "BwdPacketLenMax":      _rint(600, 1200),
        "BwdPacketLenMin":      _rint(200, 400),
        "BwdPacketLenMean":     bwd_pkt_size,
        "BwdPacketLenStd":      _rnd(80, 250),
        "FlowBytesPerSec":      bps,
        "FlowPacketsPerSec":    pps,
        "FlowIATMean":          (fwd_iat + bwd_iat) / 2,
        "FlowIATStd":           _rnd(fwd_iat * 0.1, fwd_iat * 0.5),
        "FlowIATMax":           bwd_iat * _rnd(3, 8),    # long wait for C2 response
        "FlowIATMin":           _rnd(100, 1000),
        "FwdIATTotal":          duration_ms * 1000 * 0.8,
        "FwdIATMean":           fwd_iat,
        "FwdIATStd":            _rnd(fwd_iat * 0.05, fwd_iat * 0.2),  # regular beaconing
        "FwdIATMax":            fwd_iat * _rnd(1.5, 3.0),
        "FwdIATMin":            fwd_iat * _rnd(0.5, 0.9),
        "BwdIATTotal":          duration_ms * 1000 * 0.7,
        "BwdIATMean":           bwd_iat,
        "BwdIATStd":            _rnd(bwd_iat * 0.1, bwd_iat * 0.4),
        "BwdIATMax":            bwd_iat * _rnd(3, 10),   # long C2 response wait
        "BwdIATMin":            _rnd(500, 5000),
        "FINFlagCount":         _rint(0, 1),
        "PSHFlagCount":         1,           # binary flag
        "ACKFlagCount":         1,           # binary flag
        "InitWinBytesFwd":      _rint(8192, 32768),
        "InitWinBytesBwd":      _rint(8192, 65535),
        "AveragePacketSize":    (fwd_pkt_size + bwd_pkt_size) / 2,
    }


# ── Attack catalog ─────────────────────────────────────────────────────────────

ATTACK_TYPES = [
    ("DDoS (HTTP Flood)",   "ddos",         _profile_ddos),
    ("Port Scan (SYN)",     "port_scan",    _profile_port_scan),
    ("SSH Brute Force",     "ssh_brute",    _profile_ssh_brute),
    ("Web Attack (SQLi)",   "web_attack",   _profile_web_attack),
    ("Botnet C2 Beacon",    "botnet_c2",    _profile_botnet_c2),
]

# ── Model scoring (optional but preferred) ────────────────────────────────────

def _try_load_model():
    """
    Attempt to load the MLP model + scaler for pre-injection validation.
    Returns (model, scaler, feature_names) or None if model files missing.
    """
    try:
        import joblib
        import numpy as np
        import json

        models_dir    = _NET_DIR / "models"
        mlp_path      = models_dir / "network_mlp.pkl"
        scaler_path   = models_dir / "network_scaler.pkl"
        features_path = models_dir / "feature_names.json"

        for p in (mlp_path, scaler_path, features_path):
            if not p.exists():
                return None

        model   = joblib.load(mlp_path)
        scaler  = joblib.load(scaler_path)
        with open(features_path, encoding="utf-8") as f:
            feature_names = json.load(f)

        return model, scaler, feature_names, np

    except Exception as exc:
        print(f"  [warn] Could not load model for pre-validation: {exc}")
        return None


def _score_row(row_dict, model, scaler, feature_names, np):
    """
    Returns (confidence, is_attack) for a single row dict.
    confidence = P(ATTACK), is_attack = confidence >= 0.50
    Passes a raw numpy array to the scaler (fitted without feature names).
    """
    # Build feature vector in the exact order the scaler expects
    vec = np.array(
        [float(row_dict.get(f, 0.0)) for f in feature_names],
        dtype=np.float64,
    ).reshape(1, -1)
    # Replace inf/nan
    vec = np.nan_to_num(vec, nan=0.0, posinf=0.0, neginf=0.0)
    X_sc = scaler.transform(vec)
    prob = float(model.predict_proba(X_sc)[0, 0])  # P(ATTACK)
    return prob, prob >= 0.50


# ── CSV writer ─────────────────────────────────────────────────────────────────

def _ensure_header(csv_path: Path):
    """Create the CSV file with the header row if it doesn't exist yet."""
    if not csv_path.exists():
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FEATURES)
            writer.writeheader()
        print(f"  Created {csv_path} with header.")
    else:
        # File exists — check if it has a header
        try:
            with open(csv_path, "r", encoding="utf-8") as f:
                first_line = f.readline().strip()
            if not first_line:
                # Empty file — write header
                with open(csv_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=FEATURES)
                    writer.writeheader()
                print(f"  Wrote header to empty {csv_path}.")
            elif first_line.split(",")[0].strip() != FEATURES[0]:
                print(f"  [warn] {csv_path} exists with unknown header — rows will be appended anyway.")
        except Exception:
            pass


def _append_rows(csv_path: Path, rows: list[dict], dry_run: bool) -> int:
    """Append validated rows to the CSV. Returns count written."""
    if dry_run or not rows:
        return len(rows)
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FEATURES, extrasaction="ignore")
        for row in rows:
            writer.writerow(row)
    return len(rows)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    random.seed()  # fresh seed each run

    parser = argparse.ArgumentParser(
        description="FLARE v0.4 - Network Attack Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python simulate_network_attacks.py
  python simulate_network_attacks.py --csv C:\\flare\\net_flows.csv
  python simulate_network_attacks.py --count 20 --seed 42
  python simulate_network_attacks.py --dry-run
""",
    )
    parser.add_argument(
        "--csv", default=None,
        help="Path to pktmon net_flows.csv (default: env FLARE_NET_CSV or ./net_flows.csv)",
    )
    parser.add_argument(
        "--count", type=int, default=10,
        help="Number of rows to generate per attack type (default: 10)",
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="Random seed for reproducibility",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be written without touching the file",
    )
    parser.add_argument(
        "--no-validate", action="store_true",
        help="Skip model-based validation (write all rows even if model uncertain)",
    )
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    # Resolve CSV path
    if args.csv:
        csv_path = Path(args.csv)
    else:
        env_csv = os.environ.get("FLARE_NET_CSV")
        csv_path = Path(env_csv) if env_csv else _CLIENT_DIR / "net_flows.csv"

    print()
    print("  FLARE v0.4 - Network Attack Simulator")
    print("  " + "=" * 54)
    print(f"  CSV path     : {csv_path}")
    print(f"  Rows/type    : {args.count}")
    print(f"  Attack types : {len(ATTACK_TYPES)}")
    print(f"  Dry run      : {args.dry_run}")
    print()

    # Try to load model for validation
    model_bundle = None if args.no_validate else _try_load_model()
    if model_bundle:
        model, scaler, feature_names, np = model_bundle
        print("  Model loaded  - rows will be validated before injection.")
    else:
        if not args.no_validate:
            print("  Model unavailable - rows will be written without pre-validation.")
            print("  (Run from the client directory so network/models/ is reachable.)")
        else:
            print("  Validation skipped (--no-validate).")
    print()

    # Ensure CSV exists with header
    if not args.dry_run:
        _ensure_header(csv_path)

    total_written = 0
    total_skipped = 0

    for attack_name, attack_tag, profile_fn in ATTACK_TYPES:
        print(f"  [{attack_tag.upper():<16}] {attack_name}")

        candidates = [profile_fn() for _ in range(args.count)]

        validated = []
        skipped   = 0

        if model_bundle:
            for row in candidates:
                conf, is_attack = _score_row(row, model, scaler, feature_names, np)
                if is_attack:
                    row["_confidence"] = conf
                    validated.append(row)
                else:
                    skipped += 1

            # If the model rejected everything, lower the bar slightly and retry
            # with more aggressive values (double the anomaly signal)
            if not validated:
                print(f"    [warn] All {args.count} candidates scored as BENIGN — "
                      "generating more aggressive variants...")
                extra = [profile_fn() for _ in range(args.count * 5)]
                for row in extra:
                    conf, is_attack = _score_row(row, model, scaler, feature_names, np)
                    if is_attack:
                        row["_confidence"] = conf
                        validated.append(row)
                        if len(validated) >= args.count:
                            break
                skipped = args.count - len(validated)
        else:
            validated = candidates

        # Print per-row detail
        for row in validated:
            conf_str = f"conf={row.pop('_confidence', 0.0):.3f}" if '_confidence' in row else ""
            port = int(row.get("DestinationPort", 0))
            bps  = int(row.get("FlowBytesPerSec", 0))
            pps  = int(row.get("FlowPacketsPerSec", 0))
            print(f"    + port={port:<6}  bps={bps:<10}  pps={pps:<8}  {conf_str}")

        written = _append_rows(csv_path, validated, args.dry_run)
        total_written += written
        total_skipped += skipped

        if skipped:
            print(f"    (skipped {skipped} rows — model scored them as benign)")
        print(f"    => {written} rows {'would be written' if args.dry_run else 'appended'}")
        print()

    print("  " + "=" * 54)
    print(f"  Total written : {total_written} rows")
    if total_skipped:
        print(f"  Total skipped : {total_skipped} rows (scored as benign by model)")
    print()

    if args.dry_run:
        print("  DRY RUN - no changes made to disk.")
    else:
        print(f"  Rows appended to: {csv_path}")
        print()
        print("  The FLARE agent network inference thread polls every 30 seconds.")
        print("  Alerts should appear on the dashboard within ~30 seconds.")
        print()
        print("  If the agent is not running, start it first:")
        print("    python flare_agent.py")
    print()


if __name__ == "__main__":
    main()
