"""
Packet reading — offline (PCAP file) and online (live interface) modes.

Header-byte extraction matches CICFlowMeter PacketReader.java:
  - TCP: data-offset field x 4 (TCP header only, no IP header)
  - UDP: always 8
  - Payload: IP.len - IP header - transport header
"""

from __future__ import annotations

import logging
import time
from typing import Callable, Iterator, Optional

from .packet_info import PacketInfo

logger = logging.getLogger(__name__)


def _extract_packet(scapy_pkt) -> Optional[PacketInfo]:
    """Parse a Scapy packet into PacketInfo. Returns None for non-IP/unsupported."""
    try:
        from scapy.layers.inet import IP, TCP, UDP

        if not scapy_pkt.haslayer(IP):
            return None

        ip = scapy_pkt[IP]
        ts_us = int(float(scapy_pkt.time) * 1_000_000)

        pkt = PacketInfo()
        pkt.src_ip = ip.src
        pkt.dst_ip = ip.dst
        pkt.timestamp = ts_us

        if scapy_pkt.haslayer(TCP):
            tcp = scapy_pkt[TCP]
            pkt.src_port  = tcp.sport
            pkt.dst_port  = tcp.dport
            pkt.protocol  = 6
            pkt.tcp_window = tcp.window
            pkt.header_bytes = tcp.dataofs * 4
            payload = ip.len - (ip.ihl * 4) - (tcp.dataofs * 4)
            pkt.payload_bytes = max(0, payload)

            flags = int(tcp.flags)
            pkt.flag_fin = bool(flags & 0x01)
            pkt.flag_syn = bool(flags & 0x02)
            pkt.flag_rst = bool(flags & 0x04)
            pkt.flag_psh = bool(flags & 0x08)
            pkt.flag_ack = bool(flags & 0x10)
            pkt.flag_urg = bool(flags & 0x20)
            pkt.flag_ece = bool(flags & 0x40)
            pkt.flag_cwe = bool(flags & 0x80)

        elif scapy_pkt.haslayer(UDP):
            udp = scapy_pkt[UDP]
            pkt.src_port  = udp.sport
            pkt.dst_port  = udp.dport
            pkt.protocol  = 17
            pkt.header_bytes  = 8
            pkt.payload_bytes = max(0, udp.len - 8)
        else:
            return None

        return pkt

    except Exception as exc:
        logger.debug("Packet parse error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Offline mode
# ---------------------------------------------------------------------------

def read_pcap(filename: str) -> Iterator[PacketInfo]:
    """Yield PacketInfo from a PCAP / PCAPNG file."""
    from scapy.utils import PcapReader as ScapyPcapReader

    with ScapyPcapReader(filename) as reader:
        for raw_pkt in reader:
            pkt = _extract_packet(raw_pkt)
            if pkt is not None:
                yield pkt


# ---------------------------------------------------------------------------
# Online (live) mode
# ---------------------------------------------------------------------------

def list_interfaces() -> list[str]:
    """Return a list of available network interface names."""
    try:
        from scapy.arch import get_if_list
        return get_if_list()
    except Exception:
        return []


def sniff_live(
    interface: str,
    on_packet: Callable[[PacketInfo], None],
    stop_event=None,
    flush_callback: Optional[Callable[[], None]] = None,
    flush_interval: float = 5.0,
):
    """
    Capture packets from a live interface and call on_packet() for each one.

    Args:
        interface:      Network interface name (e.g. "eth0", "Wi-Fi").
        on_packet:      Called with each parsed PacketInfo (on the capture thread).
        stop_event:     threading.Event; sniffing stops when set. If None,
                        runs until KeyboardInterrupt.
        flush_callback: Called every flush_interval seconds so the caller can
                        flush timed-out flows from the FlowGenerator.
        flush_interval: Seconds between flush_callback calls (default 5 s).
    """
    from scapy.all import sniff as scapy_sniff

    last_flush = time.monotonic()

    def _prn(raw_pkt):
        nonlocal last_flush
        pkt = _extract_packet(raw_pkt)
        if pkt is not None:
            on_packet(pkt)

        # Periodic flush of timed-out flows
        if flush_callback is not None:
            now = time.monotonic()
            if now - last_flush >= flush_interval:
                flush_callback()
                last_flush = now

    def _stop_filter(_):
        return stop_event is not None and stop_event.is_set()

    scapy_sniff(
        iface=interface,
        prn=_prn,
        store=False,
        stop_filter=_stop_filter if stop_event is not None else None,
    )
