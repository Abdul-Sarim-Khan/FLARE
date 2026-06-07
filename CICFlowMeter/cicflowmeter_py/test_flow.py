"""
Smoke-test: build a two-packet flow manually and print its CSV row.
Run with:  python -m pytest cicflowmeter_py/test_flow.py -v
       or:  python cicflowmeter_py/test_flow.py
"""

from .packet_info import PacketInfo
from .flow import Flow
from .flow_generator import FlowGenerator


def make_pkt(src, dst, sport, dport, proto, ts_us, payload, header,
             window=0, fin=False, syn=False, ack=False, psh=False):
    p = PacketInfo()
    p.src_ip = src; p.dst_ip = dst
    p.src_port = sport; p.dst_port = dport
    p.protocol = proto
    p.timestamp = ts_us
    p.payload_bytes = payload
    p.header_bytes = header
    p.tcp_window = window
    p.flag_fin = fin; p.flag_syn = syn
    p.flag_ack = ack; p.flag_psh = psh
    return p


def test_two_packet_tcp_flow():
    """A minimal two-packet TCP flow must produce a single CSV row."""
    flows_seen = []
    gen = FlowGenerator(on_flow_complete=flows_seen.append)

    base_ts = 1_494_000_000_000_000  # ~2017-05-05 in µs

    p1 = make_pkt("192.168.1.10", "10.0.0.1", 54321, 80, 6,
                  base_ts, payload=100, header=20, window=65535, syn=True)
    p2 = make_pkt("10.0.0.1", "192.168.1.10", 80, 54321, 6,
                  base_ts + 500_000, payload=200, header=20, window=8192, ack=True)
    p3 = make_pkt("192.168.1.10", "10.0.0.1", 54321, 80, 6,
                  base_ts + 1_000_000, payload=0, header=20, fin=True, ack=True)

    for p in [p1, p2, p3]:
        gen.add_packet(p)

    assert len(flows_seen) == 1, f"Expected 1 flow, got {len(flows_seen)}"
    row = flows_seen[0].dump_flow_features()
    cols = row.split(",")
    assert len(cols) == 84, f"Expected 84 columns, got {len(cols)}"
    print("PASS: two-packet flow -> 84 columns")
    print("Header:", Flow.get_header())
    print("Row:   ", row)


def test_header_column_count():
    header = Flow.get_header()
    count = len(header.split(","))
    assert count == 84, f"Header has {count} columns, expected 84"
    print(f"PASS: header has {count} columns")


def test_summary_statistics():
    from .utils import SummaryStatistics
    import math

    s = SummaryStatistics()
    assert math.isnan(s.get_mean())

    s.add_value(10.0)
    assert s.get_mean() == 10.0
    assert math.isnan(s.get_std())   # N=1 → sample std = NaN

    s.add_value(20.0)
    assert s.get_mean() == 15.0
    assert abs(s.get_std() - 7.0710678) < 1e-5
    print("PASS: SummaryStatistics")


def test_down_up_ratio_integer_division():
    """BUG-5: Down/Up ratio uses integer division (matching Java int/int)."""
    flows_seen = []
    gen = FlowGenerator(on_flow_complete=flows_seen.append)
    base = 1_494_000_000_000_000

    # 1 fwd + 3 bwd → ratio should be 3//1 = 3 (not 3.0)
    pkts = [
        make_pkt("192.168.1.1", "10.0.0.1", 1000, 80, 6, base, 100, 20, syn=True),
        make_pkt("10.0.0.1", "192.168.1.1", 80, 1000, 6, base+100_000, 50, 20, ack=True),
        make_pkt("10.0.0.1", "192.168.1.1", 80, 1000, 6, base+200_000, 50, 20, ack=True),
        make_pkt("10.0.0.1", "192.168.1.1", 80, 1000, 6, base+300_000, 0, 20, fin=True),
    ]
    for p in pkts:
        gen.add_packet(p)

    assert len(flows_seen) == 1
    flow = flows_seen[0]
    ratio = flow._get_down_up_ratio()
    assert ratio == 3.0, f"Expected 3.0 (integer division), got {ratio}"
    print(f"PASS: Down/Up ratio = {ratio}")


if __name__ == "__main__":
    test_summary_statistics()
    test_header_column_count()
    test_two_packet_tcp_flow()
    test_down_up_ratio_integer_division()
    print("\nAll tests passed.")
