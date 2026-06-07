"""
FLARE CICFlowMeter Processor
=============================
Processes a PCAP file through the Python CICFlowMeter fork and outputs
a CSV with the 34 FLARE-compatible camelCase feature names.

Usage:
    python processor.py -f traffic.pcap -o output.csv
    python processor.py -f traffic.pcap -o output.csv --label BENIGN

Requires:
    pip install scapy
    Npcap installed (Windows)
"""

import argparse
import csv
import logging
import math
import os
import sys
from pathlib import Path

# Add CICFlowMeter fork to path
CICFLOW_DIR = Path(__file__).parent.parent / "CICFlowMeter"
sys.path.insert(0, str(CICFLOW_DIR))

try:
    from cicflowmeter_py.flow import Flow
    from cicflowmeter_py.flow_generator import FlowGenerator
    from cicflowmeter_py.reader import read_pcap
except ImportError as e:
    print(f"[ERROR] Cannot import cicflowmeter_py from {CICFLOW_DIR}: {e}")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(message)s")
logger = logging.getLogger(__name__)

# Column mapping: CICFlowMeter fork header name -> FLARE feature name (34 features)
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


def process_pcap(pcap_path: str, output_path: str, label: str = "No Label") -> int:
    """Process a PCAP file and write a FLARE-compatible flow CSV."""
    total = 0

    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FLARE_FEATURES)
        writer.writeheader()

        def on_flow(flow: Flow):
            nonlocal total
            if flow.packet_count() <= 1:
                return
            writer.writerow(_flow_to_flare_row(flow, label))
            total += 1
            if total % 10_000 == 0:
                logger.info("Flows written: %d", total)

        gen = FlowGenerator(on_flow_complete=on_flow)
        pkt_count = 0
        for pkt in read_pcap(pcap_path):
            gen.add_packet(pkt)
            pkt_count += 1
            if pkt_count % 100_000 == 0:
                logger.info("Packets: %d  Flows: %d", pkt_count, total)

        gen.flush()

    logger.info("Done: %d packets -> %d flows -> %s", pkt_count, total, output_path)
    return total


def main():
    parser = argparse.ArgumentParser(
        description="Process a PCAP through Python CICFlowMeter fork, output FLARE-compatible CSV",
    )
    parser.add_argument("-f", "--file",   required=True, metavar="PCAP", help="Input PCAP file")
    parser.add_argument("-o", "--output", required=True, metavar="CSV",  help="Output CSV file")
    parser.add_argument("--label", default="No Label", help="Label value for all flows (default: 'No Label')")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    count = process_pcap(args.file, args.output, label=args.label)
    print(f"Wrote {count} flows to {args.output}")


if __name__ == "__main__":
    main()
