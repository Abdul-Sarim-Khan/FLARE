# -*- coding: utf-8 -*-
"""
FLARE v0.6 - Network Inference Engine
─────────────────────────────────────
Reads new rows from the flow CSV (append-only), runs the 34-feature
MLP classifier, and queues AlertEvent proto messages for ATTACK detections.

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
# Raised from 0.50 to 0.65: cuts false positives on benign HTTPS/download
# traffic with negligible impact on attack detection (99.7% → 99.6% TP rate).
ALERT_THRESHOLD = 0.65

# Confidence → severity breakpoints (mirror host_engine.py)
SEVERITY_CRITICAL = 0.95
SEVERITY_HIGH     = 0.85
SEVERITY_MEDIUM   = 0.75

# Rule-based batch detection thresholds
# Raised from 20 to reduce false positives from normal browsing / game launchers.
# A real scan or flood generates hundreds of matching flows per 30-second window;
# legitimate traffic rarely exceeds 50 qualifying flows in the same window.
_PORTSCAN_MIN_FLOWS  = 50   # minimum matching flows before raising port-scan alert
_PORTSCAN_MIN_PORTS  = 30   # minimum unique destination ports (browsing hits <10)
_FLOOD_MIN_FLOWS     = 50   # minimum matching flows before raising flood alert

# UDP ports to exclude from the flood rule — these carry legitimate one-way UDP:
#   443 / 80  : QUIC (HTTP/3) used by YouTube, Chrome, etc.
#   5353      : mDNS (Bonjour / multicast DNS)
#   1900      : SSDP (UPnP discovery)
#   123       : NTP
_UDP_FLOOD_EXCLUDE_PORTS = {443, 80, 5353, 1900, 123, 37020}

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

    # Verify that the MLP input layer width matches the feature list length.
    # A mismatch means the .pkl and feature_names.json are from different training
    # runs (e.g. an FL global model trained on a different feature set was pushed).
    # Raising here keeps the old working model in place rather than crashing on
    # every inference cycle.
    if hasattr(model, "coefs_") and model.coefs_:
        model_n_features = model.coefs_[0].shape[0]
        if model_n_features != len(feature_names):
            raise ValueError(
                f"[net_infer] Feature count mismatch: model expects {model_n_features} "
                f"input features but feature_names.json has {len(feature_names)}. "
                "The pushed FL model was trained on a different feature set — "
                "keeping the previous model until a compatible update arrives."
            )

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
    Uses only the 34 FLARE features that are actually present in the CSV.
    Note: TotalBwdPackets is NOT one of the 34 features — backward traffic is
    inferred from BwdPacketLenMean and BwdIATTotal instead.
    """
    try:
        dport        = float(row.get("DestinationPort",   0) or 0)
        fwd_pkts     = float(row.get("TotalFwdPackets",   0) or 0)
        flow_bps     = float(row.get("FlowBytesPerSec",   0) or 0)
        flow_pps     = float(row.get("FlowPacketsPerSec", 0) or 0)
        bwd_pps      = float(row.get("BwdPacketsPerSec",  0) or 0)
        flow_dur     = float(row.get("FlowDurationMs",    0) or 0)
        avg_pkt_size = float(row.get("AveragePacketSize", 0) or 0)
        min_pkt_len  = float(row.get("MinPacketLength",   0) or 0)
        max_pkt_len  = float(row.get("MaxPacketLength",   0) or 0)
        bwd_iat_max  = float(row.get("BwdIATMax",         0) or 0)
        fwd_iat_std  = float(row.get("FwdIATStd",         0) or 0)
        init_win_fwd = float(row.get("InitWinBytesFwd",   0) or 0)
    except (TypeError, ValueError):
        return "Network Attack Detected"

    # BwdPacketsPerSec is now a direct feature — no proxy needed
    has_bwd = bwd_pps > 0

    # ── DDoS / Volumetric flood ────────────────────────────────────────────
    # High byte rate + small packets — direction irrelevant
    if flow_bps > 500_000 and avg_pkt_size < 100:
        return "DDoS / Volumetric Flood"

    # ── UDP Flood ──────────────────────────────────────────────────────────
    # Extreme packet rate, no server response, tiny datagrams
    if flow_pps > 1_000 and not has_bwd and avg_pkt_size < 100:
        return "UDP Flood"

    # ── Port Scan ──────────────────────────────────────────────────────────
    # Short flow, very few forward packets, no backward traffic, tiny min packet
    if flow_dur < 500_000 and fwd_pkts <= 3 and not has_bwd and min_pkt_len < 100:
        return "Port Scan"

    # ── SSH Brute Force ────────────────────────────────────────────────────
    if dport == 22 and avg_pkt_size < 300 and fwd_pkts < 20:
        return "SSH Brute Force"

    # ── FTP Brute Force ────────────────────────────────────────────────────
    if dport == 21 and avg_pkt_size < 300 and fwd_pkts < 20:
        return "FTP Brute Force"

    # ── DoS – HTTP Flood (Hulk-style) ─────────────────────────────────────
    # Web port, sustained extreme throughput, server is responding.
    # Threshold raised from 50 KB/s to 2 MB/s: 4K video streaming peaks at
    # ~5 Mbps but is spread across many flows; a single flood flow sustains
    # much higher rates. Game downloads can hit 50–100 MB/s but distribute
    # across dozens of parallel TCP streams, so per-flow rates are lower.
    if dport in (80, 443, 8080, 8443, 8000) and flow_bps > 2_000_000 and has_bwd:
        return "DoS – HTTP Flood"

    # ── Web Attack (injection / exploit attempt) ───────────────────────────
    # Port 80/8080 only (not 443): HTTP-only connections with a large initial
    # window AND multiple forward packets carrying payload. Excluded port 443
    # because init_win_fwd=65535 is the default for virtually every TLS
    # client stack, causing massive FPs on normal HTTPS traffic.
    # Also require flow_bps > 10 KB/s to exclude idle connections.
    if (dport in (80, 8080, 8000) and init_win_fwd >= 65535
            and fwd_pkts > 3 and flow_bps > 10_000):
        return "Web Attack"

    # ── Botnet C2 Beaconing ────────────────────────────────────────────────
    # Long-lived, low bandwidth, very consistent IAT, bidirectional
    if (flow_dur > 1_000_000 and avg_pkt_size < 200
            and fwd_iat_std < 50_000 and bwd_iat_max < 2_000_000 and has_bwd):
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


# ── Attack-type metadata: rule_id, MITRE, suggestion, risk_note ───────────────
# Populated into every alert so the dashboard can show actionable context
# and the RULE_ACTIONS lookup in the UI can render the response playbook.
_ATTACK_META = {
    "Port Scan": {
        "rule_id":   "net_portscan",
        "mitre_id":  "T1046",
        "mitre_tac": "Discovery",
        "suggest":   "Block the source IP at the perimeter firewall. Check whether any open ports were found and harden exposed services.",
        "risk":      "Systematic probing of destination ports — consistent with pre-attack reconnaissance. A scanner is mapping which services are reachable on this host.",
    },
    "UDP Flood": {
        "rule_id":   "net_dos",
        "mitre_id":  "T1498",
        "mitre_tac": "Impact",
        "suggest":   "Rate-limit or null-route the source IP at the upstream router. Enable SYN cookies / connection rate limiting on the firewall.",
        "risk":      "High-volume one-directional UDP traffic with no server response — consistent with a UDP flood DoS attack aimed at exhausting bandwidth or network buffers.",
    },
    "DDoS / Volumetric Flood": {
        "rule_id":   "net_dos",
        "mitre_id":  "T1498",
        "mitre_tac": "Impact",
        "suggest":   "Engage upstream ISP DDoS scrubbing. Rate-limit the source at the router. Monitor target service for degradation.",
        "risk":      "Extremely high byte rate with small packets — consistent with a volumetric DDoS flood designed to saturate the network link.",
    },
    "DoS – HTTP Flood": {
        "rule_id":   "net_dos",
        "mitre_id":  "T1499",
        "mitre_tac": "Impact",
        "suggest":   "Enable rate limiting on the web server. Deploy a WAF rule to block the flood source IP. Consider CDN / scrubbing service.",
        "risk":      "High-throughput bidirectional flows to web ports — consistent with an HTTP flood (Hulk/GoldenEye style) targeting the web server.",
    },
    "SSH Brute Force": {
        "rule_id":   "net_bruteforce_ssh",
        "mitre_id":  "T1110",
        "mitre_tac": "Credential Access",
        "suggest":   "Enable account lockout after 5 failed attempts. Switch to key-based SSH auth and disable password auth. Block the source IP.",
        "risk":      "Repeated short flows to SSH port 22 — consistent with automated credential brute-forcing attempting to gain shell access.",
    },
    "FTP Brute Force": {
        "rule_id":   "net_bruteforce_ssh",
        "mitre_id":  "T1110",
        "mitre_tac": "Credential Access",
        "suggest":   "Disable FTP if not required — use SFTP instead. Enable account lockout. Block the source IP at the firewall.",
        "risk":      "Repeated short flows to FTP port 21 — consistent with automated credential brute-forcing of the FTP service.",
    },
    "Web Attack": {
        "rule_id":   "net_web_attack",
        "mitre_id":  "T1190",
        "mitre_tac": "Initial Access",
        "suggest":   "Review web server logs for the source IP. Apply WAF rules to block SQLi/XSS patterns. Patch the affected application.",
        "risk":      "Large forward payloads to web ports with an abnormally large initial window — consistent with injection attacks (SQL, XSS) or exploit attempts against the web application.",
    },
    "Botnet C2 Beaconing": {
        "rule_id":   "net_infiltration",
        "mitre_id":  "T1071",
        "mitre_tac": "Command and Control",
        "suggest":   "Inspect the destination IP reputation. If confirmed malicious, isolate the host and scan for malware. Check recently installed software.",
        "risk":      "Long-lived low-bandwidth flows with highly regular inter-arrival times — consistent with malware beaconing to a command-and-control server on a fixed schedule.",
    },
    "Network Attack Detected": {
        "rule_id":   "net_mlp_detection",
        "mitre_id":  "",
        "mitre_tac": "",
        "suggest":   "Review the evidence fields (destination port, flow bytes/s, packet sizes). Cross-reference with expected traffic at this time. If this is recurring and unexplained, escalate for manual packet capture.",
        "risk":      "The MLP classifier assigned a high attack probability to this flow based on its statistical features. The pattern deviates significantly from the benign traffic baseline the model was trained on.",
    },
}
_DEFAULT_META = _ATTACK_META["Network Attack Detected"]


def _meta(attack_type: str) -> dict:
    return _ATTACK_META.get(attack_type, _DEFAULT_META)


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

    attack_type = _classify_attack_type(row)
    m = _meta(attack_type)

    alert               = pb.AlertEvent()
    alert.alert_id      = str(uuid.uuid4())
    alert.timestamp     = ts
    alert.client_id     = cid
    alert.client_ip     = cip
    alert.severity      = _severity(confidence)
    alert.track         = pb.TRACK_NETWORK
    alert.attack_type   = attack_type
    alert.confidence    = float(confidence)
    alert.window_start  = ts
    alert.window_end    = ts
    alert.event_count   = 1
    alert.evidence      = json.dumps(evidence, ensure_ascii=False)
    alert.rule_id       = m["rule_id"]
    alert.mitre_id      = m["mitre_id"]
    alert.mitre_tactic  = m["mitre_tac"]
    alert.suggestion    = m["suggest"]
    alert.risk_note     = m["risk"]
    return alert

# ─────────────────────────────────────────────────────────────────────────────
# Rule-based batch detection  (catches what MLP misses)
# ─────────────────────────────────────────────────────────────────────────────

def _rule_based_detect(df: pd.DataFrame) -> list:
    """
    Apply deterministic rules to a scored batch.

    The MLP is trained on CICIDS2017 and may not generalise to synthetic or
    tool-specific attacks whose feature distributions differ.  Rule-based
    detection uses coarse but reliable signatures that hold regardless of the
    exact tool used.

    Each rule requires at least N matching flows per batch — this prevents a
    single legitimately-failed TCP connection from being flagged as a scan.

    Returns: list of (attack_type: str, count: int, evidence_str: str)
    """
    alerts = []

    # ── Port Scan ──────────────────────────────────────────────────────────
    # Signature: many short TCP flows with zero payload and a fast RST response.
    # Guard against FP from game launchers / browsers that make many failed
    # connections: require both a high flow count AND many unique destination
    # ports (legitimate browsing hits a handful of ports, a scan hits dozens).
    try:
        # FlowBytesPerSec and MinPacketLength are NOT required to be exactly 0 —
        # our CICFlowMeter fork counts TCP headers in packet length, so SYN and
        # RST-ACK flows always have a small non-zero byte count.  Use loose
        # thresholds instead: very few forward packets, tiny average packet size,
        # no application payload (AveragePacketSize < 100 bytes covers header-only).
        # Port scan flows to closed/filtered ports.
        # Key conditions: very few forward packets, no application payload,
        # no FIN (connection was reset or unanswered, not gracefully closed),
        # no PSH (no application data pushed).
        #
        # BwdPacketsPerSec is intentionally NOT required:
        #  - Closed ports → RST-ACK arrives in sub-millisecond; CICFlowMeter
        #    computes BwdPacketsPerSec = 1/0ms = 0 (division by near-zero),
        #    so the condition would silently drop all fast RST flows.
        #  - Filtered ports → no backward traffic at all.
        # The unique-port threshold (>= 30) is the primary FP guard.
        ps_mask = (
            (df["TotalFwdPackets"] <= 2) &
            (df["AveragePacketSize"] < 100) &
            (df["FINFlagCount"] == 0) &
            (df["PSHFlagCount"] == 0)
        )
        n_ps = int(ps_mask.sum())
        if n_ps >= _PORTSCAN_MIN_FLOWS:
            ports    = df.loc[ps_mask, "DestinationPort"].dropna()
            n_unique = int(ports.nunique())
            if n_unique >= _PORTSCAN_MIN_PORTS:
                alerts.append((
                    "Port Scan",
                    n_ps,
                    f"{n_ps} zero-payload RST flows across {n_unique} distinct ports",
                ))
            else:
                log.debug(
                    "net_infer: port-scan candidate suppressed — only %d unique ports "
                    "(need >= %d); likely browser/launcher connection failures",
                    n_unique, _PORTSCAN_MIN_PORTS,
                )
    except Exception as exc:
        log.debug("net_infer: port-scan rule error: %s", exc)

    # ── UDP Flood ──────────────────────────────────────────────────────────
    # Signature: many one-directional flows with payload but no TCP flags set.
    # Exclude well-known legitimate UDP ports (QUIC/HTTP3 on 443/80, mDNS,
    # SSDP, NTP) to avoid false positives from YouTube and other QUIC traffic.
    try:
        base_mask = (
            (df["ACKFlagCount"] == 0) &
            (df["FINFlagCount"] == 0) &
            (df["PSHFlagCount"] == 0) &
            (df["FlowBytesPerSec"] > 0) &
            (df["BwdPacketsPerSec"] == 0) &
            (df["TotalFwdPackets"] > 2)
        )
        # Exclude legitimate one-way UDP ports
        excl_mask = df["DestinationPort"].isin(_UDP_FLOOD_EXCLUDE_PORTS)
        uf_mask = base_mask & ~excl_mask
        n_uf = int(uf_mask.sum())
        if n_uf >= _FLOOD_MIN_FLOWS:
            alerts.append((
                "UDP Flood",
                n_uf,
                f"{n_uf} one-directional no-TCP-flag flows (UDP flood signature)",
            ))
        elif int(base_mask.sum()) >= _FLOOD_MIN_FLOWS:
            log.debug(
                "net_infer: UDP-flood candidate suppressed — %d matching flows but "
                "all on excluded ports (QUIC/mDNS/NTP); likely normal traffic",
                int(base_mask.sum()),
            )
    except Exception as exc:
        log.debug("net_infer: UDP-flood rule error: %s", exc)

    return alerts


def _build_rule_alert(
    attack_type: str,
    count:       int,
    evidence_str: str,
    cid:         str,
    cip:         str,
    ts:          str,
) -> pb.AlertEvent:
    """Build a summary AlertEvent for a batch-level rule detection."""
    m = _meta(attack_type)
    alert               = pb.AlertEvent()
    alert.alert_id      = str(uuid.uuid4())
    alert.timestamp     = ts
    alert.client_id     = cid
    alert.client_ip     = cip
    alert.severity      = pb.SEVERITY_HIGH
    alert.track         = pb.TRACK_NETWORK
    alert.attack_type   = attack_type
    alert.confidence    = 0.90
    alert.window_start  = ts
    alert.window_end    = ts
    alert.event_count   = count
    alert.evidence      = json.dumps(
        {"summary": evidence_str, "method": "rule-based", "flow_count": count},
        ensure_ascii=False,
    )
    alert.rule_id      = m["rule_id"]
    alert.mitre_id     = m["mitre_id"]
    alert.mitre_tactic = m["mitre_tac"]
    alert.suggestion   = m["suggest"]
    alert.risk_note    = m["risk"]
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

    # Drop flows on ports that are definitively benign by protocol.
    # Scoring these produces reliable false positives because their traffic
    # patterns (broadcast, tiny payloads, one-directional) superficially
    # resemble attack signatures but are entirely normal system behaviour.
    _SKIP_PORTS = {
        37020,          # FLARE server beacon (our own control plane)
        53,             # DNS — always UDP query/response, never an attack source
        67, 68,         # DHCP — broadcast, 1 packet, no response expected
        137, 138, 139,  # NetBIOS name/datagram/session — LAN broadcast noise
        5353,           # mDNS — local multicast, one-directional by design
        5355,           # LLMNR — Windows link-local name resolution
        1900,           # SSDP / UPnP discovery
        123,            # NTP — tiny one-directional datagrams
    }
    if "DestinationPort" in df.columns:
        skip_mask = df["DestinationPort"].isin(_SKIP_PORTS)
        n_skip = int(skip_mask.sum())
        if n_skip:
            log.debug("net_infer: dropping %d flows on benign-protocol ports", n_skip)
            df = df[~skip_mask]
            rows_read -= n_skip
            if df.empty:
                return {"rows_read": 0, "attacks": 0, "benign": 0}

    # Prepare features
    X_raw = _prepare_features(df, feature_names)

    # Fix 9: Drop rows where every modelled feature is zero — these are almost
    # certainly corrupt/padding rows (collector sometimes emits empty records).
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

    X_sc  = scaler.transform(X_raw.values)

    # MLP scoring
    probs = model.predict_proba(X_sc)[:, 0]   # P(ATTACK) — model.classes_=[0=ATTACK, 1=BENIGN]
    preds = (probs >= ALERT_THRESHOLD).astype(bool)

    n_mlp_attacks = int(preds.sum())
    n_benign      = rows_read - n_mlp_attacks
    ts            = _now_iso()
    dropped       = 0

    # Emit MLP alerts — individual alerts for small detections, one batch
    # summary alert when many flows are flagged simultaneously (attack burst).
    # Sending thousands of individual alerts during a flood clogs the buffer,
    # drops most of them, and floods the dashboard with near-identical entries.
    _BURST_THRESHOLD = 20   # flows in one batch before switching to summary mode
    if n_mlp_attacks > 0:
        attack_rows  = df[preds]
        attack_probs = probs[preds]

        if n_mlp_attacks <= _BURST_THRESHOLD:
            # Normal mode: one alert per flagged flow
            for i, (_, row) in enumerate(attack_rows.iterrows()):
                alert = _build_alert(row, float(attack_probs[i]), cid, cip, ts)
                try:
                    alert_queue.put_nowait(alert)
                except queue.Full:
                    dropped += 1
            if dropped:
                log.warning("net_infer: alert queue full — dropped %d MLP alerts", dropped)
        else:
            # Burst mode: collapse into one summary alert
            mean_conf  = float(attack_probs.mean())
            max_conf   = float(attack_probs.max())
            top_ports  = (
                attack_rows["DestinationPort"].dropna()
                .astype(int).value_counts().head(5).to_dict()
                if "DestinationPort" in attack_rows.columns else {}
            )
            # Pick the most common heuristic attack type across flagged rows
            type_counts: dict = {}
            for _, row in attack_rows.head(200).iterrows():  # sample for speed
                t = _classify_attack_type(row)
                type_counts[t] = type_counts.get(t, 0) + 1
            dominant_type = max(type_counts, key=type_counts.get)

            summary_evidence = json.dumps({
                "flow_count":    n_mlp_attacks,
                "mean_conf":     round(mean_conf, 4),
                "max_conf":      round(max_conf, 4),
                "top_ports":     top_ports,
                "method":        "MLP-burst",
            }, ensure_ascii=False)

            m = _meta(dominant_type)
            alert               = pb.AlertEvent()
            alert.alert_id      = str(uuid.uuid4())
            alert.timestamp     = ts
            alert.client_id     = cid
            alert.client_ip     = cip
            alert.severity      = _severity(mean_conf)
            alert.track         = pb.TRACK_NETWORK
            alert.attack_type   = dominant_type
            alert.confidence    = mean_conf
            alert.window_start  = ts
            alert.window_end    = ts
            alert.event_count   = n_mlp_attacks
            alert.evidence      = summary_evidence
            alert.rule_id       = m["rule_id"]
            alert.mitre_id      = m["mitre_id"]
            alert.mitre_tactic  = m["mitre_tac"]
            alert.suggestion    = m["suggest"]
            alert.risk_note     = m["risk"]
            try:
                alert_queue.put_nowait(alert)
                log.info(
                    "net_infer: MLP BURST — %d flows flagged  mean_conf=%.3f  type=%s",
                    n_mlp_attacks, mean_conf, dominant_type,
                )
            except queue.Full:
                log.warning("net_infer: alert queue full — dropped MLP burst summary")

    # Rule-based batch detection — catches port scans / floods the MLP misses
    # because its CICIDS2017 training distribution differs from synthetic attacks.
    rule_detections = _rule_based_detect(df)
    n_rule_alerts   = 0
    for attack_type, count, evidence in rule_detections:
        rule_alert = _build_rule_alert(attack_type, count, evidence, cid, cip, ts)
        try:
            alert_queue.put_nowait(rule_alert)
            n_rule_alerts += 1
            log.info("net_infer: RULE ALERT — %s  (%s)", attack_type, evidence)
        except queue.Full:
            log.warning("net_infer: alert queue full — dropped rule alert %s", attack_type)

    n_total = n_mlp_attacks + n_rule_alerts
    if n_total == 0:
        log.info("net_infer: %d rows scored — 0 ATTACK, %d BENIGN", rows_read, n_benign)
    else:
        log.info(
            "net_infer: %d rows scored — %d ATTACK (%d MLP + %d rule), %d BENIGN",
            rows_read, n_total, n_mlp_attacks, n_rule_alerts, n_benign,
        )
    return {"rows_read": rows_read, "attacks": n_total, "benign": n_benign}

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
        csv_path:      Path to the collector output CSV.
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
        description="FLARE v0.6 — Network Inference Engine"
    )
    parser.add_argument("--csv",       required=True,
                        help="Path to flow CSV")
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

    print(f"\n-- FLARE v0.6  Network Inference ------------------")
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
                    f"    +- ALERT  sev={sev:<12}  conf={conf}  "
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