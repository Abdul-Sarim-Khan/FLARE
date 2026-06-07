"""
CICFlowMeter Python — CICIDS2017-compatible flow feature extractor.

Offline (PCAP file):
    python -m cicflowmeter_py -f traffic.pcap -o results\

Online (live interface):
    python -m cicflowmeter_py -i "Wi-Fi" -o results\
    python -m cicflowmeter_py -i eth0   -o flows.csv

List available interfaces:
    python -m cicflowmeter_py --list-interfaces
"""

from __future__ import annotations

import argparse
import os
import sys
import logging
import threading

from .flow import Flow
from .flow_generator import FlowGenerator
from .reader import read_pcap, sniff_live, list_interfaces

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared writer
# ---------------------------------------------------------------------------

class CsvWriter:
    """Thread-safe CSV writer with lazy header on first row."""

    def __init__(self, path: str, label: str):
        self.path = path
        self.label = label
        self._header_written = False
        self._lock = threading.Lock()

        # Start clean
        if os.path.exists(path):
            os.remove(path)

    def write_flow(self, flow: Flow):
        if flow.packet_count() <= 1:
            return
        row = flow.dump_flow_features(label=self.label)
        with self._lock:
            with open(self.path, "a", newline="", encoding="utf-8") as fh:
                if not self._header_written:
                    fh.write(Flow.get_header() + "\n")
                    self._header_written = True
                fh.write(row + "\n")


# ---------------------------------------------------------------------------
# Offline: PCAP file
# ---------------------------------------------------------------------------

def process_pcap(
    input_file: str,
    output_path: str,
    bidirectional: bool = True,
    label: str = "No Label",
    flush_on_end: bool = True,
) -> int:
    """Read a PCAP file and write flow features to CSV."""
    if os.path.isdir(output_path):
        base = os.path.splitext(os.path.basename(input_file))[0]
        output_path = os.path.join(output_path, base + "_flows.csv")

    writer = CsvWriter(output_path, label)
    total = 0

    def on_flow(flow: Flow):
        nonlocal total
        writer.write_flow(flow)
        total += 1

    gen = FlowGenerator(bidirectional=bidirectional, on_flow_complete=on_flow)

    pkt_count = 0
    for pkt in read_pcap(input_file):
        gen.add_packet(pkt)
        pkt_count += 1
        if pkt_count % 10_000 == 0:
            logger.info("Processed %d packets, %d flows emitted", pkt_count, total)

    if flush_on_end:
        gen.flush()

    logger.info("Done: %d packets, %d flows -> %s", pkt_count, total, output_path)
    return total


# ---------------------------------------------------------------------------
# Online: live interface
# ---------------------------------------------------------------------------

def capture_live(
    interface: str,
    output_path: str,
    bidirectional: bool = True,
    label: str = "No Label",
    flush_interval: float = 5.0,
):
    """
    Sniff packets from a live interface and write completed flows to CSV.
    Runs until Ctrl+C.
    """
    if os.path.isdir(output_path):
        output_path = os.path.join(output_path, f"{interface}_flows.csv")

    writer = CsvWriter(output_path, label)
    total = 0

    def on_flow(flow: Flow):
        nonlocal total
        writer.write_flow(flow)
        total += 1
        logger.info("Flow #%d completed -> %s", total, output_path)

    gen = FlowGenerator(bidirectional=bidirectional, on_flow_complete=on_flow)

    stop_event = threading.Event()

    def periodic_flush():
        """Flush flows that have exceeded their timeout."""
        gen.flush_timed_out()

    logger.info("Capturing on interface '%s' -> %s  (Ctrl+C to stop)", interface, output_path)
    try:
        sniff_live(
            interface=interface,
            on_packet=gen.add_packet,
            stop_event=stop_event,
            flush_callback=periodic_flush,
            flush_interval=flush_interval,
        )
    except KeyboardInterrupt:
        logger.info("Stopping capture...")
    finally:
        stop_event.set()
        gen.flush()   # emit remaining active flows
        logger.info("Done: %d flows written to %s", total, output_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="CICFlowMeter Python — CICIDS2017-compatible flow feature extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    source = parser.add_mutually_exclusive_group()
    source.add_argument("-f", "--file",      metavar="PCAP",      help="Input PCAP file (offline mode)")
    source.add_argument("-i", "--interface", metavar="IFACE",     help="Network interface to sniff (live mode)")
    source.add_argument("--list-interfaces", action="store_true", help="Print available interfaces and exit")

    parser.add_argument("-o", "--output",  metavar="PATH",  help="Output CSV file or directory")
    parser.add_argument("--label",         default="No Label", help="Label column value (default: 'No Label')")
    parser.add_argument("--unidirectional", action="store_true", help="Unidirectional flows (default: bidirectional)")
    parser.add_argument("--no-flush", dest="flush", action="store_false",
                        help="(Offline) Do not emit active flows at end of file")
    parser.add_argument("--flush-interval", type=float, default=5.0, metavar="SEC",
                        help="(Live) Seconds between timeout checks (default: 5)")
    parser.set_defaults(flush=True)

    args = parser.parse_args()

    # ---- list interfaces ----
    if args.list_interfaces:
        ifaces = list_interfaces()
        if ifaces:
            print("Available interfaces:")
            for iface in ifaces:
                print(f"  {iface}")
        else:
            print("Could not enumerate interfaces (try running as Administrator).")
        return

    # ---- validate ----
    if not args.file and not args.interface:
        parser.error("Specify an input: -f <pcap file>  or  -i <interface>")

    if not args.output:
        parser.error("-o / --output is required")

    bidirectional = not args.unidirectional

    # ---- offline ----
    if args.file:
        if not os.path.isfile(args.file):
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        count = process_pcap(
            input_file=args.file,
            output_path=args.output,
            bidirectional=bidirectional,
            label=args.label,
            flush_on_end=args.flush,
        )
        print(f"Wrote {count} flows.")

    # ---- live ----
    else:
        capture_live(
            interface=args.interface,
            output_path=args.output,
            bidirectional=bidirectional,
            label=args.label,
            flush_interval=args.flush_interval,
        )
