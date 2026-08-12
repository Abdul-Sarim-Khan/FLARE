from dataclasses import dataclass, field
from typing import Optional


def _ip_signed_bytes(ip: str):
    """
    Convert dotted-decimal IP string to list of signed bytes (-128..127).
    Replicates Java's signed byte comparison used in generateFlowId().
    In Java, byte is signed: values > 127 wrap to negative.
    """
    parts = [int(x) for x in ip.split('.')]
    return [p - 256 if p > 127 else p for p in parts]


def generate_flow_id(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int) -> str:
    """
    Generate canonical flow ID matching CICFlowMeter Java behaviour.
    Uses signed byte comparison (Java byte semantics) to decide direction.
    Lower-signed-byte IP goes first (forward direction).
    """
    src_signed = _ip_signed_bytes(src_ip)
    dst_signed = _ip_signed_bytes(dst_ip)
    forward = True
    for s, d in zip(src_signed, dst_signed):
        if s != d:
            if s > d:
                forward = False
            break
    if forward:
        return f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}"
    else:
        return f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{protocol}"


@dataclass
class PacketInfo:
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    timestamp: int = 0          # microseconds since epoch
    payload_bytes: int = 0
    header_bytes: int = 0       # TCP/UDP header length only (not IP header)
    tcp_window: int = 0

    flag_fin: bool = False
    flag_syn: bool = False
    flag_rst: bool = False
    flag_psh: bool = False
    flag_ack: bool = False
    flag_urg: bool = False
    flag_cwe: bool = False      # CWR in Java source (named CWE in FlowFeature)
    flag_ece: bool = False

    _flow_id: Optional[str] = field(default=None, repr=False)

    def get_flow_id(self) -> str:
        if self._flow_id is None:
            self._flow_id = generate_flow_id(
                self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol
            )
        return self._flow_id

    def fwd_flow_id(self) -> str:
        return f"{self.src_ip}-{self.dst_ip}-{self.src_port}-{self.dst_port}-{self.protocol}"

    def bwd_flow_id(self) -> str:
        return f"{self.dst_ip}-{self.src_ip}-{self.dst_port}-{self.src_port}-{self.protocol}"

    def is_forward_packet(self, flow_src_ip: str) -> bool:
        return self.src_ip == flow_src_ip

    def get_payload_packet(self) -> int:
        """Replicates BasicPacketInfo.getPayloadPacket() side-effect increment."""
        return 1
