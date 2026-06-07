"""
FLARE Live Collector
=====================
Captures live network traffic using the Python CICFlowMeter fork and writes
completed flows to CSV with the 34 FLARE-compatible camelCase feature names.

Usage (run as Administrator on Windows):
    python collector.py --list-interfaces
    python collector.py -i "Wi-Fi" -o flows.csv
    python collector.py -i "Ethernet" -o flows.csv --label BENIGN

Press Ctrl-C to stop and flush remaining open flows.

Requires:
    pip install scapy
    Npcap installed (https://npcap.com)
"""

import argparse
import csv
import logging
import math
import os
import sys
import threading
from pathlib import Path

# Add CICFlowMeter fork to path — lives at Flare v0.6\CICFlowMeter
CICFLOW_DIR = Path(__file__).parent.parent.parent / "CICFlowMeter"
sys.path.insert(0, str(CICFLOW_DIR))

try:
    from cicflowmeter_py.flow import Flow
    from cicflowmeter_py.flow_generator import FlowGenerator
    from cicflowmeter_py.reader import sniff_live, list_interfaces
except ImportError as e:
    print(f"[ERROR] Cannot import cicflowmeter_py from {CICFLOW_DIR}: {e}")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(message)s")
logger = logging.getLogger(__name__)

# Column mapping: CICFlowMeter fork header name -> FLARE feature name (38 features)
CIC_TO_FLARE = {
    "Dst Port":          "DestinationPort",
    "Flow Duration":     "FlowDurationMs",
    "Tot Fwd Pkts":      "TotalFwdPackets",
    "TotLen Fwd Pkts":   "TotalLenFwdPackets",
    "Fwd Pkt Len Max":   "FwdPacketLenMax",
    "Fwd Pkt Len Min":   "FwdPacketLenMin",
    "Fwd Pkt Len Mean":  "FwdPacketLenMean",
    "Fwd Pkt Len Std":   "FwdPacketLenStd",
    "Bwd Pkt Len Max":   "BwdPacketLenMax",
    "Bwd Pkt Len Min":   "BwdPacketLenMin",
    "Bwd Pkt Len Mean":  "BwdPacketLenMean",
    "Bwd Pkt Len Std":   "BwdPacketLenStd",
    "Flow Byts/s":       "FlowBytesPerSec",
    "Flow Pkts/s":       "FlowPacketsPerSec",
    "Fwd Pkts/s":        "FwdPacketsPerSec",
    "Bwd Pkts/s":        "BwdPacketsPerSec",
    "Flow IAT Mean":     "FlowIATMean",
    "Flow IAT Std":      "FlowIATStd",
    "Flow IAT Max":      "FlowIATMax",
    "Flow IAT Min":      "FlowIATMin",
    "Fwd IAT Tot":       "FwdIATTotal",
    "Fwd IAT Mean":      "FwdIATMean",
    "Fwd IAT Std":       "FwdIATStd",
    "Fwd IAT Max":       "FwdIATMax",
    "Fwd IAT Min":       "FwdIATMin",
    "Bwd IAT Tot":       "BwdIATTotal",
    "Bwd IAT Mean":      "BwdIATMean",
    "Bwd IAT Std":       "BwdIATStd",
    "Bwd IAT Max":       "BwdIATMax",
    "Bwd IAT Min":       "BwdIATMin",
    "Pkt Len Min":       "MinPacketLength",
    "Pkt Len Max":       "MaxPacketLength",
    "FIN Flag Cnt":      "FINFlagCount",
    "PSH Flag Cnt":      "PSHFlagCount",
    "ACK Flag Cnt":      "ACKFlagCount",
    "Init Fwd Win Byts": "InitWinBytesFwd",
    "Init Bwd Win Byts": "InitWinBytesBwd",
    "Pkt Size Avg":      "AveragePacketSize",
}
FLARE_FEATURES = list(CIC_TO_FLARE.values())

# Build column-index map from the fork's header string
_FORK_HEADER = Flow.get_header().split(",")
_COL_IDX = {name: i for i, name in enumerate(_FORK_HEADER)}

for _col in CIC_TO_FLARE:
    if _col not in _COL_IDX:
        raise RuntimeError(f"Column '{_col}' not found in CICFlowMeter header — check fork version")


def _flow_to_flare_row(flow: Flow, label: str) -> dict:
    """Parse a completed Flow's CSV string and return a FLARE feature dict."""
    vals = flow.dump_flow_features(label=label).split(",")
    row = {}
    for cic_col, flare_col in CIC_TO_FLARE.items():
        raw = vals[_COL_IDX[cic_col]]
        try:
            v = float(raw)
            if not math.isfinite(v):
                v = 0.0
        except ValueError:
            v = 0.0
        row[flare_col] = v
    return row


class FlareCollector:
    """Wraps the CICFlowMeter FlowGenerator and writes FLARE-format CSV rows."""

    def __init__(self, output_path: str, label: str):
        self._label = label
        self._output_path = output_path
        self._lock = threading.Lock()
        self._total = 0

        write_header = not os.path.exists(output_path)
        self._fh = open(output_path, "a", newline="", encoding="utf-8")
        fieldnames = FLARE_FEATURES + ["Label"]
        self._writer = csv.DictWriter(self._fh, fieldnames=fieldnames)
        if write_header:
            self._writer.writeheader()

        self._gen = FlowGenerator(on_flow_complete=self._on_flow)
        logger.info("Writing flows to %s  (label=%s)", output_path, label)

    def _on_flow(self, flow: Flow):
        if flow.packet_count() <= 1:
            return
        row = _flow_to_flare_row(flow, self._label)
        row["Label"] = self._label
        with self._lock:
            self._writer.writerow(row)
            self._fh.flush()
            self._total += 1
        if self._total % 100 == 0:
            logger.info("Flows written: %d", self._total)

    def add_packet(self, pkt):
        self._gen.add_packet(pkt)

    def flush_timed_out(self):
        self._gen.flush_timed_out()

    def stop(self):
        self._gen.flush()
        self._fh.close()
        logger.info("Done. %d flows written to %s", self._total, self._output_path)


def main():
    parser = argparse.ArgumentParser(
        description="Live FLARE flow collector using Python CICFlowMeter fork",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("-i", "--interface", metavar="IFACE", help="Network interface to sniff")
    source.add_argument("--list-interfaces", action="store_true", help="Print available interfaces and exit")

    parser.add_argument("-o", "--output",       metavar="CSV", help="Output CSV file (appends if exists)")
    parser.add_argument("--label",              default="No Label", help="Label for all flows (default: 'No Label')")
    parser.add_argument("--flush-interval",     type=float, default=5.0, metavar="SEC",
                        help="Seconds between timeout checks (default: 5)")
    args = parser.parse_args()

    if args.list_interfaces:
        ifaces = list_interfaces()
        if ifaces:
            print("Available interfaces:")
            for iface in ifaces:
                print(f"  {iface}")
        else:
            print("Could not enumerate interfaces (try running as Administrator).")
        return

    if not args.interface:
        parser.error("Specify an interface: -i <interface>  or --list-interfaces")
    if not args.output:
        parser.error("-o / --output is required")

    collector = FlareCollector(args.output, args.label)
    stop_event = threading.Event()

    logger.info("Capturing on '%s'  (Ctrl+C to stop)", args.interface)
    try:
        sniff_live(
            interface=args.interface,
            on_packet=collector.add_packet,
            stop_event=stop_event,
            flush_callback=collector.flush_timed_out,
            flush_interval=args.flush_interval,
        )
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        logger.info("Flushing remaining flows...")
        collector.stop()


if __name__ == "__main__":
    main()
