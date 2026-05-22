# -*- coding: utf-8 -*-
"""
FLARE v0.4 - Network Inference Engine
─────────────────────────────────────
Reads new rows from the pktmon flow CSV (append-only), runs the 34-feature
XGBoost classifier, and queues AlertEvent proto messages for ATTACK detections.

Byte-offset tracking means only newly appended rows are processed each cycle —
the full CSV is never re-read after startup regardless of how large it grows.

Usage (from flare_agent.py):

    import queue, threading
    from network.flare_network_infer import start as start_net_infer

    alert_q  = queue.Queue()
    stop_evt = threading.Event()
    start_net_infer(alert_q, stop_evt, csv_path="net_flows.csv")

Usage (standalone CLI — for testing):

    python flare_network_infer.py --csv net_flows.csv
    python flare_network_infer.py --csv net_flows.csv --once    # single pass, then exit
    python flare_network_infer.py --csv net_flows.csv --interval 15
"""

import argparse
import json
import logging
import os
import queue
import socket
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd

# ── Path setup ────────────────────────────────────────────────────────────────
_NET_DIR     = Path(__file__).parent
_PROJECT_DIR = _NET_DIR.parent
for _p in (str(_PROJECT_DIR), str(_NET_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from proto import log_schema_pb2 as pb # noqa: E402

log = logging.getLogger("net_infer")

# ─────────────────────────────────────────────────────────────────────────────
# Defaults
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_MODEL_DIR  = _NET_DIR / "models"
DEFAULT_MLP        = DEFAULT_MODEL_DIR / "network_mlp.pkl"
DEFAULT_SCALER     = DEFAULT_MODEL_DIR / "network_scaler.pkl"
DEFAULT_FEATURES   = DEFAULT_MODEL_DIR / "feature_names.json"

# How often (seconds) to poll the CSV for new rows when running as a service
DEFAULT_INTERVAL_SECS = 30

# Minimum attack probability to raise an alert (0.0 – 1.0)
ALERT_THRESHOLD = 0.50

# Confidence → severity breakpoints (mirror host_engine.py)
SEVERITY_CRITICAL = 0.95
SEVERITY_HIGH     = 0.85
SEVERITY_MEDIUM   = 0.75

# ─────────────────────────────────────────────────────────────────────────────
# Model loading
# ─────────────────────────────────────────────────────────────────────────────

def load_model(
    mlp_path:      Path = DEFAULT_MLP,
    scaler_path:   Path = DEFAULT_SCALER,
    features_path: Path = DEFAULT_FEATURES,
):
    """
    Load and return (model, scaler, feature_names).
    Raises FileNotFoundError if any artefact is missing.
    """
    for p, label in [
        (mlp_path,      "MLP model"),
        (scaler_path,   "scaler"),
        (features_path, "feature_names.json"),
    ]:
        if not Path(p).exists():
            raise FileNotFoundError(f"[net_infer] {label} not found: {p}")

    model = joblib.load(mlp_path)

    # Verify class label order — code assumes classes_[0]=ATTACK (0), classes_[1]=BENIGN (1).
    # If the model was trained with a different label encoding, predictions would be inverted.
    if hasattr(model, "classes_"):
        if list(model.classes_) != [0, 1]:
            raise ValueError(
                f"[net_infer] Unexpected model.classes_ order: {list(model.classes_)}. "
                "Expected [0, 1] where 0=ATTACK and 1=BENIGN. "
                "Retrain the model with integer labels 0=attack, 1=benign."
            )

    scaler = joblib.load(scaler_path)

    with open(features_path, encoding="utf-8") as f:
        feature_names = json.load(f)

    log.info(
        "net_infer: model loaded — %d features, classes=%s, scaler=%s",
        len(feature_names), list(model.classes_) if hasattr(model, "classes_") else "N/A",
        type(scaler).__name__,
    )
    return model, scaler, feature_names

# ─────────────────────────────────────────────────────────────────────────────
# CSV byte-offset tracker
# ─────────────────────────────────────────────────────────────────────────────

class _OffsetTracker:
    """
    Persists the last-read byte position of a CSV file to disk.
    State file lives alongside the CSV as  <csv_name>.flare_offset

    On every call to read_new_rows():
      1. Open the CSV at the stored offset.
      2. Read all lines appended since then.
      3. Store the new offset.
      4. Return a DataFrame of the new rows (may be empty).
    """

    def __init__(self, csv_path: Path):
        self._csv    = csv_path
        self._state  = csv_path.with_suffix(".flare_offset")
        self._header: Optional[list] = None  # column names from header line

    def _load_offset(self) -> int:
        if self._state.exists():
            try:
                return int(self._state.read_text().strip())
            except (ValueError, OSError):
                pass
        return 0

    def _save_offset(self, offset: int):
        try:
            self._state.write_text(str(offset))
        except OSError as exc:
            log.warning("net_infer: could not save offset: %s", exc)

    def read_new_rows(self) -> pd.DataFrame:
        """
        Returns a DataFrame of rows appended since the last call.
        Returns an empty DataFrame if the file doesn't exist or has no new rows.
        """
        if not self._csv.exists():
            return pd.DataFrame()

        last_offset = self._load_offset()

        # Safety: if file was truncated/rotated reset to 0
        file_size = self._csv.stat().st_size
        if last_offset > file_size:
            log.warning(
                "net_infer: CSV shrank (%d → %d bytes) — resetting offset",
                last_offset, file_size,
            )
            last_offset = 0
            self._header = None

        with open(self._csv, "r", encoding="utf-8", errors="replace") as f:
            # Populate header cache when not already set.
            # This covers two cases:
            #   (a) First-ever read (last_offset==0, self._header==None):
            #       read header and advance last_offset to just past it.
            #   (b) Agent restarted (last_offset>0 from disk, self._header==None):
            #       read header for parsing but keep the saved last_offset intact
            #       so we don't re-process already-seen rows.
            if self._header is None:
                f.seek(0)
                header_line = f.readline()
                if not header_line.strip():
                    return pd.DataFrame()
                self._header = [c.strip() for c in header_line.split(",")]
                if last_offset == 0:
                    # True first read — start right after the header line.
                    last_offset = f.tell()
                # else: last_offset retains its saved value; header was only
                # needed to re-populate the in-memory cache after restart.

            f.seek(last_offset)
            new_lines = f.readlines()
            new_offset = f.tell()

        if not new_lines:
            return pd.DataFrame()

        # Parse the new lines using the stored header
        from io import StringIO
        raw_text = "".join(new_lines)
        try:
            df = pd.read_csv(
                StringIO(raw_text),
                header=None,
                names=self._header,
                low_memory=False,
            )
        except Exception as exc:
            log.warning("net_infer: CSV parse error on new rows: %s", exc)
            # Still advance the offset so we don't re-try the same bad data
            self._save_offset(new_offset)
            return pd.DataFrame()

        self._save_offset(new_offset)
        return df

# ─────────────────────────────────────────────────────────────────────────────
# Feature preparation (mirrors flare_network_evaluate.py)
# ─────────────────────────────────────────────────────────────────────────────

_PROTOCOL_MAP = {"tcp": 6, "udp": 17}


def _prepare_features(df: pd.DataFrame, feature_names: list) -> np.ndarray:
    """
    Align columns to the model's expected 34 features, encode Protocol,
    replace inf/NaN with 0, and return a numpy array ready for the scaler.
    """
    df = df.copy()
    df.columns = df.columns.str.strip()

    # Encode Protocol string → int if present
    if "Protocol" in df.columns:
        df["Protocol"] = (
            df["Protocol"].astype(str).str.lower()
            .map(_PROTOCOL_MAP).fillna(0).astype(int)
        )

    # Add any missing model features as 0
    for col in feature_names:
        if col not in df.columns:
            df[col] = 0

    X = df[feature_names].copy()
    # Coerce any non-numeric values (e.g. "CORRUPT" in a malformed CSV row)
    # to NaN before they reach the scaler — prevents ValueError from sklearn.
    X = X.apply(pd.to_numeric, errors='coerce')
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)
    return X

# ─────────────────────────────────────────────────────────────────────────────
# Alert builder
# ─────────────────────────────────────────────────────────────────────────────

_TOP_FEATURES = [
    "BwdPacketLenStd", "AveragePacketSize", "BwdPacketLenMean",
    "FlowBytesPerSec", "BwdIATMax", "DestinationPort",
]

# ─────────────────────────────────────────────────────────────────────────────
# Fix 8: Rule-based attack_type classifier
# Operates on raw (pre-scaled) flow features to give human-readable labels.
# Priority order: most specific / highest confidence first.
# ─────────────────────────────────────────────────────────────────────────────

def _classify_attack_type(row: pd.Series) -> str:
    """
    Heuristically assign a human-readable attack category to a flagged flow.
    Returns a concise label used as AlertEvent.attack_type.
    """
    try:
        dport         = float(row.get("DestinationPort", row.get("Destination Port", 0)) or 0)
        fwd_pkts      = float(row.get("TotalFwdPackets",   row.get("Total Fwd Packets",   0)) or 0)
        bwd_pkts      = float(row.get("TotalBwdPackets",   row.get("Total Bwd Packets",   0)) or 0)
        flow_bps      = float(row.get("FlowBytesPerSec",   row.get("Flow Bytes/s",         0)) or 0)
        fwd_pkt_len   = float(row.get("FwdPacketLengthMean", row.get("Fwd Packet Length Mean", 0)) or 0)
        flow_dur      = float(row.get("FlowDuration",      row.get("Flow Duration",        0)) or 0)
        init_win_fwd  = float(row.get("InitWinBytesFwd",   row.get("Init_Win_bytes_forward", 0)) or 0)
        fwd_iat_std   = float(row.get("FwdIATStd",         row.get("Fwd IAT Std",           0)) or 0)
        bwd_iat_max   = float(row.get("BwdIATMax",         row.get("Bwd IAT Max",            0)) or 0)
        avg_pkt_size  = float(row.get("AveragePacketSize", row.get("Average Packet Size",   0)) or 0)
    except (TypeError, ValueError):
        return "Network Attack Detected"

    # ── DDoS: very high packet rate, tiny packets, mostly forward-only ─────
    # Characteristics: FlowBytesPerSec > 500k, small avg packet, high fwd count
    if flow_bps > 500_000 and avg_pkt_size < 100 and fwd_pkts > 100:
        return "DDoS / Volumetric Flood"

    # ── Port Scan: short duration, single packet per flow, many distinct ports
    # Characteristics: very short flows (< 500ms), exactly 1 fwd packet, no bwd
    if (flow_dur < 500_000 and fwd_pkts <= 2 and bwd_pkts == 0
            and fwd_pkt_len < 200):
        return "Port Scan"

    # ── SSH Brute Force: dport 22, many short flows, no large payload ──────
    if dport == 22 and avg_pkt_size < 300 and fwd_pkts < 20:
        return "SSH Brute Force"

    # ── Web Attack: dport 80/443/8080/8443, large forward payload ──────────
    if dport in (80, 443, 8080, 8443, 8000) and init_win_fwd == 65535:
        return "Web Attack"

    # ── Botnet C2 / Beaconing: regular inter-arrival, long-lived, small pkts
    # Characteristics: low bandwidth, consistent IAT, longer duration
    if (flow_dur > 1_000_000 and avg_pkt_size < 200
            and fwd_iat_std < 50_000 and bwd_iat_max < 2_000_000):
        return "Botnet C2 Beaconing"

    # ── Generic fallback ───────────────────────────────────────────────────
    return "Network Attack Detected"


def _client_id() -> str:
    return os.environ.get("COMPUTERNAME", socket.gethostname())


def _client_ip() -> str:
    try:
        server_url = os.environ.get("FLARE_SERVER_URL", "https://localhost:7331")
        from urllib.parse import urlparse
        host = urlparse(server_url).hostname or "localhost"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((host, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "0.0.0.0"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _severity(confidence: float) -> pb.Severity:
    if confidence >= SEVERITY_CRITICAL:
        return pb.SEVERITY_CRITICAL
    if confidence >= SEVERITY_HIGH:
        return pb.SEVERITY_HIGH
    if confidence >= SEVERITY_MEDIUM:
        return pb.SEVERITY_MEDIUM
    return pb.SEVERITY_LOW


def _build_alert(
    row: pd.Series,
    confidence: float,
    cid: str,
    cip: str,
    ts: str,
) -> pb.AlertEvent:
    """Build one AlertEvent proto for a single flagged flow row."""
    # Evidence: top contributing features + DestinationPort
    evidence = {}
    for feat in _TOP_FEATURES:
        if feat in row.index:
            val = row[feat]
            try:
                evidence[feat] = round(float(val), 4)
            except (TypeError, ValueError):
                evidence[feat] = str(val)

    alert               = pb.AlertEvent()
    alert.alert_id      = str(uuid.uuid4())
    alert.timestamp     = ts
    alert.client_id     = cid
    alert.client_ip     = cip
    alert.severity      = _severity(confidence)
    alert.track         = pb.TRACK_NETWORK
    alert.attack_type   = _classify_attack_type(row)  # Fix 8: per-flow label
    alert.confidence    = float(confidence)
    alert.window_start  = ts
    alert.window_end    = ts
    alert.event_count   = 1
    alert.evidence      = json.dumps(evidence, ensure_ascii=False)

    # rule_id / mitre_id left empty — server enrichment layer (future)
    return alert

# ─────────────────────────────────────────────────────────────────────────────
# Core inference function
# ─────────────────────────────────────────────────────────────────────────────

def run_once(
    tracker:       "_OffsetTracker",
    model,
    scaler,
    feature_names: list,
    alert_queue:   queue.Queue,
    cid:           str,
    cip:           str,
) -> dict:
    """
    Single inference pass — reads new rows, scores them, queues alerts.

    Returns a stats dict:
        {"rows_read": int, "attacks": int, "benign": int}
    """
    df = tracker.read_new_rows()

    if df.empty:
        return {"rows_read": 0, "attacks": 0, "benign": 0}

    rows_read = len(df)
    log.debug("net_infer: %d new rows to score", rows_read)

    # Prepare features
    X_raw = _prepare_features(df, feature_names)

    # Fix 9: Drop rows where every modelled feature is zero — these are almost
    # certainly corrupt/padding rows (pktmon sometimes emits empty records).
    # The MLP has a systematic bias toward ATTACK for all-zeros inputs because
    # legitimate flows always have at least some non-zero packet-length features.
    nonzero_mask = (X_raw.values != 0).any(axis=1)
    n_zero_rows  = int((~nonzero_mask).sum())
    if n_zero_rows:
        log.debug("net_infer: dropping %d all-zero rows (likely corrupt)", n_zero_rows)
        X_raw = X_raw[nonzero_mask]
        df    = df[nonzero_mask]
        rows_read -= n_zero_rows
        if X_raw.empty:
            return {"rows_read": 0, "attacks": 0, "benign": 0}

    X_sc  = scaler.transform(X_raw)

    # Score
    probs = model.predict_proba(X_sc)[:, 0]   # P(ATTACK) — model.classes_=[0=ATTACK, 1=BENIGN]
    preds = (probs >= ALERT_THRESHOLD).astype(bool)

    n_attacks = int(preds.sum())
    n_benign  = rows_read - n_attacks

    if n_attacks == 0:
        log.debug("net_infer: %d rows — all benign", rows_read)
        return {"rows_read": rows_read, "attacks": 0, "benign": n_benign}

    ts = _now_iso()

    # Emit one alert per flagged row
    # (flare_agent.py batches these into AlertBatch before sending)
    attack_rows  = df[preds]
    attack_probs = probs[preds]

    dropped = 0
    for i, (_, row) in enumerate(attack_rows.iterrows()):
        alert = _build_alert(row, float(attack_probs[i]), cid, cip, ts)
        try:
            alert_queue.put_nowait(alert)
        except queue.Full:
            dropped += 1

    if dropped:
        log.warning("net_infer: alert queue full — dropped %d alerts", dropped)

    log.info(
        "net_infer: %d rows scored — %d ATTACK, %d BENIGN (dropped=%d)",
        rows_read, n_attacks, n_benign, dropped,
    )
    return {"rows_read": rows_read, "attacks": n_attacks, "benign": n_benign}

# ─────────────────────────────────────────────────────────────────────────────
# Background worker thread
# ─────────────────────────────────────────────────────────────────────────────

class _NetInferWorker(threading.Thread):

    def __init__(
        self,
        csv_path:    Path,
        alert_queue: queue.Queue,
        stop_event:  threading.Event,
        model,
        scaler,
        feature_names: list,
        interval:    int,
    ):
        super().__init__(name="NetInfer-Worker", daemon=True)
        self._tracker       = _OffsetTracker(csv_path)
        self._alert_q       = alert_queue
        self._stop          = stop_event
        self._model         = model
        self._scaler        = scaler
        self._feature_names = feature_names
        self._interval      = interval
        self._reload_event  = None
        self._mlp_path      = None
        self._scaler_path   = None
        self._features_path = None
        self._cid           = _client_id()
        self._cip           = _client_ip()

    def run(self):
        log.info(
            "net_infer: worker started — polling every %ds, threshold=%.2f",
            self._interval, ALERT_THRESHOLD,
        )
        while not self._stop.is_set():
            if self._reload_event and self._reload_event.is_set():
                log.info("net_infer: reloading model from disk...")
                try:
                    self._model, self._scaler, self._feature_names = load_model(
                        self._mlp_path, self._scaler_path, self._features_path
                    )
                except Exception as exc:
                    log.error("net_infer: failed to reload model: %s", exc)
                self._reload_event.clear()

            try:
                run_once(
                    self._tracker,
                    self._model,
                    self._scaler,
                    self._feature_names,
                    self._alert_q,
                    self._cid,
                    self._cip,
                )
            except Exception as exc:
                log.error("net_infer: inference error: %s", exc, exc_info=True)

            # Sleep in small increments so stop_event is checked promptly
            for _ in range(self._interval * 2):
                if self._stop.is_set():
                    break
                time.sleep(0.5)

        log.info("net_infer: worker stopped.")

# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def start(
    alert_queue:   queue.Queue,
    stop_event:    threading.Event,
    csv_path:      Optional[str]  = None,
    interval_secs: int            = DEFAULT_INTERVAL_SECS,
    mlp_path:      Optional[str]  = None,
    scaler_path:   Optional[str]  = None,
    features_path: Optional[str]  = None,
    reload_event:  Optional[threading.Event] = None,
) -> None:
    """
    Start the network inference engine in a background thread.

    Args:
        alert_queue:   Shared queue — AlertEvent protos placed here on ATTACK.
        stop_event:    Set to request clean shutdown.
        csv_path:      Path to the pktmon output CSV.
                       Falls back to FLARE_NET_CSV env var, then local net_flows.csv.
        interval_secs: How often (seconds) to poll the CSV (default 30).
        mlp_path:      Override MLP model path.
        scaler_path:   Override scaler path.
        features_path: Override feature_names.json path.
        reload_event:  If set, the worker will reload the model when this event is set.

    Returns immediately. Thread is daemon — will not block interpreter exit.
    """
    if csv_path is None:
        csv_path = os.environ.get("FLARE_NET_CSV", str(_PROJECT_DIR / "net_flows.csv"))

    csv_p = Path(csv_path)

    mlp_p      = Path(mlp_path)      if mlp_path      else DEFAULT_MLP
    scaler_p   = Path(scaler_path)   if scaler_path   else DEFAULT_SCALER
    features_p = Path(features_path) if features_path else DEFAULT_FEATURES

    try:
        model, scaler, feature_names = load_model(mlp_p, scaler_p, features_p)
    except FileNotFoundError as exc:
        log.error("net_infer: cannot start — %s", exc)
        return

    worker = _NetInferWorker(
        csv_path=csv_p,
        alert_queue=alert_queue,
        stop_event=stop_event,
        model=model,
        scaler=scaler,
        feature_names=feature_names,
        interval=interval_secs,
    )
    worker._reload_event = reload_event
    worker._mlp_path = mlp_p
    worker._scaler_path = scaler_p
    worker._features_path = features_p
    worker.start()

    log.info(
        "net_infer: started — csv=%s  interval=%ds  model=%s",
        csv_p, interval_secs, mlp_p.name,
    )

# ─────────────────────────────────────────────────────────────────────────────
# Standalone CLI (for testing / manual runs)
# ─────────────────────────────────────────────────────────────────────────────

def _cli():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = argparse.ArgumentParser(
        description="FLARE v0.4 — Network Inference Engine"
    )
    parser.add_argument("--csv",       required=True,
                        help="Path to pktmon flow CSV")
    parser.add_argument("--mlp",       default=str(DEFAULT_MLP),
                        help=f"MLP model      (default: {DEFAULT_MLP})")
    parser.add_argument("--scaler",    default=str(DEFAULT_SCALER),
                        help=f"Scaler pkl     (default: {DEFAULT_SCALER})")
    parser.add_argument("--features",  default=str(DEFAULT_FEATURES),
                        help=f"feature_names.json  (default: {DEFAULT_FEATURES})")
    parser.add_argument("--interval",  type=int, default=DEFAULT_INTERVAL_SECS,
                        help=f"Poll interval seconds (default: {DEFAULT_INTERVAL_SECS})")
    parser.add_argument("--threshold", type=float, default=ALERT_THRESHOLD,
                        help=f"Attack probability threshold (default: {ALERT_THRESHOLD})")
    parser.add_argument("--once",      action="store_true",
                        help="Run a single pass then exit (no loop)")
    args = parser.parse_args()

    # Allow CLI to override threshold
    globals()["ALERT_THRESHOLD"] = args.threshold

    csv_p      = Path(args.csv)
    mlp_p      = Path(args.mlp)
    scaler_p   = Path(args.scaler)
    features_p = Path(args.features)

    print(f"\n── FLARE v0.4  Network Inference ──────────────────")
    print(f"  CSV      : {csv_p}")
    print(f"  Model    : {mlp_p.name}")
    print(f"  Interval : {args.interval}s")
    print(f"  Threshold: {ALERT_THRESHOLD}")
    print(f"  Mode     : {'single pass' if args.once else 'continuous'}")
    print()

    model, scaler, feature_names = load_model(mlp_p, scaler_p, features_p)
    tracker  = _OffsetTracker(csv_p)
    alert_q  = queue.Queue()
    cid      = _client_id()
    cip      = _client_ip()

    total_rows    = 0
    total_attacks = 0
    pass_num      = 0

    def _drain_and_print():
        nonlocal total_rows, total_attacks, pass_num
        pass_num += 1
        stats = run_once(tracker, model, scaler, feature_names, alert_q, cid, cip)
        total_rows    += stats["rows_read"]
        total_attacks += stats["attacks"]

        if stats["rows_read"] == 0:
            print(f"  [pass {pass_num:>4}]  no new rows")
        else:
            print(
                f"  [pass {pass_num:>4}]  "
                f"rows={stats['rows_read']:>6}  "
                f"ATTACK={stats['attacks']:>5}  "
                f"BENIGN={stats['benign']:>5}"
            )

        # Print any queued alerts
        while not alert_q.empty():
            try:
                alert = alert_q.get_nowait()
                ev    = json.loads(alert.evidence) if alert.evidence else {}
                sev   = pb.Severity.Name(alert.severity)
                port  = ev.get("DestinationPort", "?")
                conf  = f"{alert.confidence:.3f}"
                print(
                    f"    └─ ALERT  sev={sev:<12}  conf={conf}  "
                    f"port={port}  id={alert.alert_id[:8]}"
                )
            except queue.Empty:
                break

    if args.once:
        _drain_and_print()
        print(f"\n  Total rows={total_rows}  attacks={total_attacks}")
        return

    print("  Press Ctrl+C to stop.\n")
    try:
        while True:
            _drain_and_print()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\n\n  Stopped.  Total rows={total_rows}  attacks={total_attacks}")


if __name__ == "__main__":
    _cli()