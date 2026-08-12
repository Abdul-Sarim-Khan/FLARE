"""
BasicFlow equivalent — replicates CICFlowMeter Java logic exactly,
including all known bugs present in the CICIDS2017 dataset generation:

  BUG-1  firstPacket() adds the first packet's payload to flowLengthStats TWICE.
  BUG-2  updateFlowBulk() uses reference equality (==) for byte arrays, which is
         always False in Java because getSrc() returns Arrays.copyOf(). So every
         packet (including forward packets) goes through updateBackwardBulk().
         Forward bulk stats are always zero.
  BUG-3  dumpFlowBasedFeaturesEx() outputs fAvgBytesPerBulk() for BOTH
         "Fwd Byts/b Avg" (#63) AND "Bwd Byts/b Avg" (#66). The latter should
         be bAvgBytesPerBulk(), but is a copy-paste error.
  BUG-4  detectUpdateSubflows() condition is
             packet.ts - sfLastPacketTS / 1_000_000 > 1.0
         due to operator precedence, not
            (packet.ts - sfLastPacketTS) / 1_000_000 > 1.0
         The first form is always True for real Unix timestamps in microseconds.
  BUG-5  getDownUpRatio() uses integer division (Java int/int), so the ratio is
         always a whole number (0, 1, 2 …).
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from .packet_info import PacketInfo
from .utils import SummaryStatistics


FLOW_TIMEOUT = 15_000_000       # 15 seconds in microseconds (reduced from 120 for live IDS)
ACTIVITY_TIMEOUT = 5_000_000    # 5 seconds in microseconds


class Flow:

    def __init__(self, packet: PacketInfo,
                 flow_src_ip: Optional[str] = None,
                 flow_dst_ip: Optional[str] = None,
                 flow_src_port: Optional[int] = None,
                 flow_dst_port: Optional[int] = None,
                 bidirectional: bool = True):

        self.bidirectional = bidirectional

        # Flow identity — set after firstPacket so direction is established
        self.src_ip: str = flow_src_ip or ""
        self.dst_ip: str = flow_dst_ip or ""
        self.src_port: int = flow_src_port or 0
        self.dst_port: int = flow_dst_port or 0
        self.protocol: int = 0
        self.flow_id: str = ""

        # Timing
        self.flow_start_time: int = 0
        self.flow_last_seen: int = 0
        self.start_active_time: int = 0
        self.end_active_time: int = 0
        self.forward_last_seen: int = 0
        self.backward_last_seen: int = 0

        # Packet lists (kept for .size() equivalence)
        self.forward: list[PacketInfo] = []
        self.backward: list[PacketInfo] = []

        # Byte totals
        self.forward_bytes: int = 0
        self.backward_bytes: int = 0
        self.f_header_bytes: int = 0
        self.b_header_bytes: int = 0

        # Packet-length statistics (payload only)
        self.fwd_pkt_stats = SummaryStatistics()
        self.bwd_pkt_stats = SummaryStatistics()
        self.flow_length_stats = SummaryStatistics()     # BUG-1: first packet double-counted

        # IAT statistics
        self.flow_iat = SummaryStatistics()
        self.forward_iat = SummaryStatistics()
        self.backward_iat = SummaryStatistics()

        # Active / idle statistics
        self.flow_active = SummaryStatistics()
        self.flow_idle = SummaryStatistics()

        # Directional PSH/URG counts
        self.f_psh_cnt: int = 0
        self.b_psh_cnt: int = 0
        self.f_urg_cnt: int = 0
        self.b_urg_cnt: int = 0

        # TCP flag counts (all packets, both directions)
        self.flag_counts: dict[str, int] = {
            "FIN": 0, "SYN": 0, "RST": 0, "PSH": 0,
            "ACK": 0, "URG": 0, "CWR": 0, "ECE": 0,
        }

        # TCP window & segment metrics
        self.init_win_bytes_forward: int = 0
        self.init_win_bytes_backward: int = 0
        self.act_data_pkt_forward: int = 0
        self.min_seg_size_forward: int = 0

        # Subflow tracking (BUG-4 condition makes sfCount == packet_count)
        self._sf_last_packet_ts: int = -1
        self._sf_ac_helper: int = -1
        self._sf_count: int = 0

        # Bulk tracking — forward bulk is always zero (BUG-2)
        self._f_bulk_duration: int = 0
        self._f_bulk_packet_count: int = 0
        self._f_bulk_size_total: int = 0
        self._f_bulk_state_count: int = 0
        self._f_bulk_packet_count_helper: int = 0
        self._f_bulk_start_helper: int = 0
        self._f_bulk_size_helper: int = 0
        self._f_last_bulk_ts: int = 0

        self._b_bulk_duration: int = 0
        self._b_bulk_packet_count: int = 0
        self._b_bulk_size_total: int = 0
        self._b_bulk_state_count: int = 0
        self._b_bulk_packet_count_helper: int = 0
        self._b_bulk_start_helper: int = 0
        self._b_bulk_size_helper: int = 0
        self._b_last_bulk_ts: int = 0

        self._first_packet(packet)

        # Override src/dst if caller supplied explicit flow endpoints (timeout restart)
        if flow_src_ip is not None:
            self.src_ip = flow_src_ip
            self.dst_ip = flow_dst_ip
            self.src_port = flow_src_port
            self.dst_port = flow_dst_port

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_flags(self, pkt: PacketInfo):
        if pkt.flag_fin: self.flag_counts["FIN"] += 1
        if pkt.flag_syn: self.flag_counts["SYN"] += 1
        if pkt.flag_rst: self.flag_counts["RST"] += 1
        if pkt.flag_psh: self.flag_counts["PSH"] += 1
        if pkt.flag_ack: self.flag_counts["ACK"] += 1
        if pkt.flag_urg: self.flag_counts["URG"] += 1
        if pkt.flag_cwe: self.flag_counts["CWR"] += 1
        if pkt.flag_ece: self.flag_counts["ECE"] += 1

    def _update_flow_bulk(self, pkt: PacketInfo):
        """
        BUG-2: Java uses reference equality (this.src == packet.getSrc()).
        getSrc() always returns a new array, so the condition is always False.
        Every packet goes to _update_backward_bulk(), even forward packets.
        """
        # Always backward (BUG-2 replication)
        self._update_backward_bulk(pkt, self._f_last_bulk_ts)

    def _update_forward_bulk(self, pkt: PacketInfo, ts_of_last_bulk_in_other: int):
        size = pkt.payload_bytes
        if ts_of_last_bulk_in_other > self._f_bulk_start_helper:
            self._f_bulk_start_helper = 0
        if size <= 0:
            return
        if self._f_bulk_start_helper == 0:
            self._f_bulk_start_helper = pkt.timestamp
            self._f_bulk_packet_count_helper = 1
            self._f_bulk_size_helper = size
            self._f_last_bulk_ts = pkt.timestamp
        else:
            if (pkt.timestamp - self._f_last_bulk_ts) / 1_000_000.0 > 1.0:
                self._f_bulk_start_helper = pkt.timestamp
                self._f_last_bulk_ts = pkt.timestamp
                self._f_bulk_packet_count_helper = 1
                self._f_bulk_size_helper = size
            else:
                self._f_bulk_packet_count_helper += 1
                self._f_bulk_size_helper += size
                if self._f_bulk_packet_count_helper == 4:
                    self._f_bulk_state_count += 1
                    self._f_bulk_packet_count += self._f_bulk_packet_count_helper
                    self._f_bulk_size_total += self._f_bulk_size_helper
                    self._f_bulk_duration += pkt.timestamp - self._f_bulk_start_helper
                elif self._f_bulk_packet_count_helper > 4:
                    self._f_bulk_packet_count += 1
                    self._f_bulk_size_total += size
                    self._f_bulk_duration += pkt.timestamp - self._f_last_bulk_ts
                self._f_last_bulk_ts = pkt.timestamp

    def _update_backward_bulk(self, pkt: PacketInfo, ts_of_last_bulk_in_other: int):
        size = pkt.payload_bytes
        if ts_of_last_bulk_in_other > self._b_bulk_start_helper:
            self._b_bulk_start_helper = 0
        if size <= 0:
            return
        if self._b_bulk_start_helper == 0:
            self._b_bulk_start_helper = pkt.timestamp
            self._b_bulk_packet_count_helper = 1
            self._b_bulk_size_helper = size
            self._b_last_bulk_ts = pkt.timestamp
        else:
            if (pkt.timestamp - self._b_last_bulk_ts) / 1_000_000.0 > 1.0:
                self._b_bulk_start_helper = pkt.timestamp
                self._b_last_bulk_ts = pkt.timestamp
                self._b_bulk_packet_count_helper = 1
                self._b_bulk_size_helper = size
            else:
                self._b_bulk_packet_count_helper += 1
                self._b_bulk_size_helper += size
                if self._b_bulk_packet_count_helper == 4:
                    self._b_bulk_state_count += 1
                    self._b_bulk_packet_count += self._b_bulk_packet_count_helper
                    self._b_bulk_size_total += self._b_bulk_size_helper
                    self._b_bulk_duration += pkt.timestamp - self._b_bulk_start_helper
                elif self._b_bulk_packet_count_helper > 4:
                    self._b_bulk_packet_count += 1
                    self._b_bulk_size_total += size
                    self._b_bulk_duration += pkt.timestamp - self._b_last_bulk_ts
                self._b_last_bulk_ts = pkt.timestamp

    def _detect_update_subflows(self, pkt: PacketInfo):
        """
        BUG-4: condition is (ts - sfLastPacketTS/1e6) > 1.0 instead of
       (ts - sfLastPacketTS)/1e6 > 1.0. For real Unix timestamps in µs
        the former is always True, so sfCount increments every packet.
        """
        if self._sf_last_packet_ts == -1:
            self._sf_last_packet_ts = pkt.timestamp
            self._sf_ac_helper = pkt.timestamp

        # BUG-4: sfLastPacketTS divided by 1e6 first (operator precedence)
        if (pkt.timestamp - self._sf_last_packet_ts / 1_000_000.0) > 1.0:
            self._sf_count += 1
            self.update_active_idle_time(
                pkt.timestamp - self._sf_last_packet_ts, ACTIVITY_TIMEOUT
            )
            self._sf_ac_helper = pkt.timestamp

        self._sf_last_packet_ts = pkt.timestamp

    def update_active_idle_time(self, current_time: int, threshold: int):
        if (current_time - self.end_active_time) > threshold:
            if (self.end_active_time - self.start_active_time) > 0:
                self.flow_active.add_value(self.end_active_time - self.start_active_time)
            self.flow_idle.add_value(current_time - self.end_active_time)
            self.start_active_time = current_time
            self.end_active_time = current_time
        else:
            self.end_active_time = current_time

    def _first_packet(self, pkt: PacketInfo):
        self._update_flow_bulk(pkt)
        self._detect_update_subflows(pkt)
        self._check_flags(pkt)

        self.flow_start_time = pkt.timestamp
        self.flow_last_seen = pkt.timestamp

        # BUG-1: first payload add (duplicate — second add happens below)
        self.flow_length_stats.add_value(pkt.payload_bytes)

        # Set flow endpoints from first packet if not pre-supplied
        if not self.src_ip:
            self.src_ip = pkt.src_ip
            self.src_port = pkt.src_port
        if not self.dst_ip:
            self.dst_ip = pkt.dst_ip
            self.dst_port = pkt.dst_port

        self.protocol = pkt.protocol
        self.flow_id = pkt.get_flow_id()

        if pkt.src_ip == self.src_ip:
            self.min_seg_size_forward = pkt.header_bytes
            self.init_win_bytes_forward = pkt.tcp_window
            self.flow_length_stats.add_value(pkt.payload_bytes)   # BUG-1: second add
            self.fwd_pkt_stats.add_value(pkt.payload_bytes)
            self.f_header_bytes = pkt.header_bytes
            self.forward_last_seen = pkt.timestamp
            self.forward_bytes += pkt.payload_bytes
            self.forward.append(pkt)
            if pkt.flag_psh: self.f_psh_cnt += 1
            if pkt.flag_urg: self.f_urg_cnt += 1
        else:
            self.init_win_bytes_backward = pkt.tcp_window
            self.flow_length_stats.add_value(pkt.payload_bytes)   # BUG-1: second add
            self.bwd_pkt_stats.add_value(pkt.payload_bytes)
            self.b_header_bytes = pkt.header_bytes
            self.backward_last_seen = pkt.timestamp
            self.backward_bytes += pkt.payload_bytes
            self.backward.append(pkt)
            if pkt.flag_psh: self.b_psh_cnt += 1
            if pkt.flag_urg: self.b_urg_cnt += 1

    # ------------------------------------------------------------------
    # Public API — called by FlowGenerator
    # ------------------------------------------------------------------

    def add_packet(self, pkt: PacketInfo):
        self._update_flow_bulk(pkt)
        self._detect_update_subflows(pkt)
        self._check_flags(pkt)

        ts = pkt.timestamp

        if self.bidirectional:
            self.flow_length_stats.add_value(pkt.payload_bytes)

            if pkt.src_ip == self.src_ip:
                if pkt.payload_bytes >= 1:
                    self.act_data_pkt_forward += 1
                self.fwd_pkt_stats.add_value(pkt.payload_bytes)
                self.f_header_bytes += pkt.header_bytes
                self.forward.append(pkt)
                self.forward_bytes += pkt.payload_bytes
                if len(self.forward) > 1:
                    self.forward_iat.add_value(ts - self.forward_last_seen)
                self.forward_last_seen = ts
                self.min_seg_size_forward = min(pkt.header_bytes, self.min_seg_size_forward)
            else:
                self.bwd_pkt_stats.add_value(pkt.payload_bytes)
                self.init_win_bytes_backward = pkt.tcp_window
                self.b_header_bytes += pkt.header_bytes
                self.backward.append(pkt)
                self.backward_bytes += pkt.payload_bytes
                if len(self.backward) > 1:
                    self.backward_iat.add_value(ts - self.backward_last_seen)
                self.backward_last_seen = ts
        else:
            if pkt.payload_bytes >= 1:
                self.act_data_pkt_forward += 1
            self.fwd_pkt_stats.add_value(pkt.payload_bytes)
            self.flow_length_stats.add_value(pkt.payload_bytes)
            self.f_header_bytes += pkt.header_bytes
            self.forward.append(pkt)
            self.forward_bytes += pkt.payload_bytes
            self.forward_iat.add_value(ts - self.forward_last_seen)
            self.forward_last_seen = ts
            self.min_seg_size_forward = min(pkt.header_bytes, self.min_seg_size_forward)

        self.flow_iat.add_value(ts - self.flow_last_seen)
        self.flow_last_seen = ts

    def packet_count(self) -> int:
        if self.bidirectional:
            return len(self.forward) + len(self.backward)
        return len(self.forward)

    # ------------------------------------------------------------------
    # Feature computations
    # ------------------------------------------------------------------

    def _flow_duration(self) -> int:
        return self.flow_last_seen - self.flow_start_time

    def _get_fpkts_per_second(self) -> float:
        dur = self._flow_duration()
        if dur > 0:
            return len(self.forward) / (dur / 1_000_000.0)
        return 0.0

    def _get_bpkts_per_second(self) -> float:
        dur = self._flow_duration()
        if dur > 0:
            return len(self.backward) / (dur / 1_000_000.0)
        return 0.0

    def _get_down_up_ratio(self) -> float:
        if len(self.forward) > 0:
            # BUG-5: integer division in Java (int / int), cast to double after
            return float(len(self.backward) // len(self.forward))
        return 0.0

    def _get_avg_packet_size(self) -> float:
        if self.packet_count() > 0:
            return self.flow_length_stats.get_sum() / self.packet_count()
        return 0.0

    def _f_avg_segment_size(self) -> float:
        if len(self.forward) > 0:
            return self.fwd_pkt_stats.get_sum() / len(self.forward)
        return 0.0

    def _b_avg_segment_size(self) -> float:
        if len(self.backward) > 0:
            return self.bwd_pkt_stats.get_sum() / len(self.backward)
        return 0.0

    # Bulk getters
    def _f_avg_bytes_per_bulk(self) -> int:
        if self._f_bulk_state_count != 0:
            return self._f_bulk_size_total // self._f_bulk_state_count
        return 0

    def _f_avg_packets_per_bulk(self) -> int:
        if self._f_bulk_state_count != 0:
            return self._f_bulk_packet_count // self._f_bulk_state_count
        return 0

    def _f_avg_bulk_rate(self) -> int:
        if self._f_bulk_duration != 0:
            return int(self._f_bulk_size_total / (self._f_bulk_duration / 1_000_000.0))
        return 0

    def _b_avg_bytes_per_bulk(self) -> int:
        if self._b_bulk_state_count != 0:
            return self._b_bulk_size_total // self._b_bulk_state_count
        return 0

    def _b_avg_packets_per_bulk(self) -> int:
        if self._b_bulk_state_count != 0:
            return self._b_bulk_packet_count // self._b_bulk_state_count
        return 0

    def _b_avg_bulk_rate(self) -> int:
        if self._b_bulk_duration != 0:
            return int(self._b_bulk_size_total / (self._b_bulk_duration / 1_000_000.0))
        return 0

    # Subflow getters (sfCount == packet_count due to BUG-4)
    def _get_sflow_fpackets(self) -> int:
        if self._sf_count <= 0:
            return 0
        return len(self.forward) // self._sf_count

    def _get_sflow_fbytes(self) -> int:
        if self._sf_count <= 0:
            return 0
        return self.forward_bytes // self._sf_count

    def _get_sflow_bpackets(self) -> int:
        if self._sf_count <= 0:
            return 0
        return len(self.backward) // self._sf_count

    def _get_sflow_bbytes(self) -> int:
        if self._sf_count <= 0:
            return 0
        return self.backward_bytes // self._sf_count

    # ------------------------------------------------------------------
    # CSV dump — matches dumpFlowBasedFeaturesEx() exactly (84 columns)
    # ------------------------------------------------------------------

    def dump_flow_features(self, label: str = "No Label") -> str:
        dur = self._flow_duration()

        # Timestamp: dd/MM/yyyy hh:mm:ss a (12-hour with AM/PM, matching Java)
        ts_str = datetime.fromtimestamp(self.flow_start_time / 1_000_000.0).strftime(
            "%d/%m/%Y %I:%M:%S %p"
        )

        fwd_n = self.fwd_pkt_stats.get_n()
        bwd_n = self.bwd_pkt_stats.get_n()

        fields = [
            self.flow_id,                           # 1
            self.src_ip,                            # 2
            self.src_port,                          # 3
            self.dst_ip,                            # 4
            self.dst_port,                          # 5
            self.protocol,                          # 6
            ts_str,                                 # 7
            dur,                                    # 8
            fwd_n,                                  # 9
            bwd_n,                                  # 10
            self.fwd_pkt_stats.get_sum(),           # 11
            self.bwd_pkt_stats.get_sum(),           # 12
        ]

        # 13-16 fwd pkt length stats
        if fwd_n > 0:
            fields += [
                self.fwd_pkt_stats.get_max(),
                self.fwd_pkt_stats.get_min(),
                self.fwd_pkt_stats.get_mean(),
                self.fwd_pkt_stats.get_std(),
            ]
        else:
            fields += [0, 0, 0, 0]

        # 17-20 bwd pkt length stats
        if bwd_n > 0:
            fields += [
                self.bwd_pkt_stats.get_max(),
                self.bwd_pkt_stats.get_min(),
                self.bwd_pkt_stats.get_mean(),
                self.bwd_pkt_stats.get_std(),
            ]
        else:
            fields += [0, 0, 0, 0]

        # 21-22 flow rates
        if dur > 0:
            fields.append((self.forward_bytes + self.backward_bytes) / (dur / 1_000_000.0))  # 21
            fields.append(self.packet_count() / (dur / 1_000_000.0))                          # 22
        else:
            fields += [float('inf'), float('inf')]

        # 23-26 flow IAT
        fields += [
            self.flow_iat.get_mean(),   # 23
            self.flow_iat.get_std(),    # 24
            self.flow_iat.get_max(),    # 25
            self.flow_iat.get_min(),    # 26
        ]

        # 27-31 fwd IAT
        if len(self.forward) > 1:
            fields += [
                self.forward_iat.get_sum(),  # 27
                self.forward_iat.get_mean(), # 28
                self.forward_iat.get_std(),  # 29
                self.forward_iat.get_max(),  # 30
                self.forward_iat.get_min(),  # 31
            ]
        else:
            fields += [0, 0, 0, 0, 0]

        # 32-36 bwd IAT
        if len(self.backward) > 1:
            fields += [
                self.backward_iat.get_sum(),  # 32
                self.backward_iat.get_mean(), # 33
                self.backward_iat.get_std(),  # 34
                self.backward_iat.get_max(),  # 35
                self.backward_iat.get_min(),  # 36
            ]
        else:
            fields += [0, 0, 0, 0, 0]

        # 37-40 PSH/URG flags
        fields += [self.f_psh_cnt, self.b_psh_cnt, self.f_urg_cnt, self.b_urg_cnt]

        # 41-44 header lengths and packet rates
        fields += [
            self.f_header_bytes,            # 41
            self.b_header_bytes,            # 42
            self._get_fpkts_per_second(),   # 43
            self._get_bpkts_per_second(),   # 44
        ]

        # 45-49 overall packet length stats
        if len(self.forward) > 0 or len(self.backward) > 0:
            fields += [
                self.flow_length_stats.get_min(),      # 45
                self.flow_length_stats.get_max(),      # 46
                self.flow_length_stats.get_mean(),     # 47
                self.flow_length_stats.get_std(),      # 48
                self.flow_length_stats.get_variance(), # 49
            ]
        else:
            fields += [0, 0, 0, 0, 0]

        # 50-57 TCP flag counts (explicit order from dumpFlowBasedFeaturesEx)
        fields += [
            self.flag_counts["FIN"],  # 50
            self.flag_counts["SYN"],  # 51
            self.flag_counts["RST"],  # 52
            self.flag_counts["PSH"],  # 53
            self.flag_counts["ACK"],  # 54
            self.flag_counts["URG"],  # 55
            self.flag_counts["CWR"],  # 56
            self.flag_counts["ECE"],  # 57
        ]

        # 58-61 ratios and segment sizes
        fields += [
            self._get_down_up_ratio(),    # 58
            self._get_avg_packet_size(),  # 59
            self._f_avg_segment_size(),   # 60
            self._b_avg_segment_size(),   # 61
        ]
        # Column 62 is deleted (was duplicate of col 41 fwd header length)

        # 62-67 bulk stats (BUG-2: f_avg* always 0; BUG-3: col 65 is fAvg not bAvg)
        fields += [
            self._f_avg_bytes_per_bulk(),    # 62 → "Fwd Byts/b Avg"  (always 0 due to BUG-2)
            self._f_avg_packets_per_bulk(),  # 63 → "Fwd Pkts/b Avg"  (always 0 due to BUG-2)
            self._f_avg_bulk_rate(),         # 64 → "Fwd Blk Rate Avg" (always 0 due to BUG-2)
            self._f_avg_bytes_per_bulk(),    # 65 → "Bwd Byts/b Avg"  (BUG-3: should be b_avg)
            self._b_avg_packets_per_bulk(),  # 66 → "Bwd Pkts/b Avg"
            self._b_avg_bulk_rate(),         # 67 → "Bwd Blk Rate Avg"
        ]

        # 68-71 subflow stats
        fields += [
            self._get_sflow_fpackets(),  # 68
            self._get_sflow_fbytes(),    # 69
            self._get_sflow_bpackets(),  # 70
            self._get_sflow_bbytes(),    # 71
        ]

        # 72-75 window / segment info
        fields += [
            self.init_win_bytes_forward,   # 72
            self.init_win_bytes_backward,  # 73
            self.act_data_pkt_forward,     # 74
            self.min_seg_size_forward,     # 75
        ]

        # 76-79 active time stats
        if self.flow_active.get_n() > 0:
            fields += [
                self.flow_active.get_mean(),  # 76
                self.flow_active.get_std(),   # 77
                self.flow_active.get_max(),   # 78
                self.flow_active.get_min(),   # 79
            ]
        else:
            fields += [0, 0, 0, 0]

        # 80-83 idle time stats
        if self.flow_idle.get_n() > 0:
            fields += [
                self.flow_idle.get_mean(),  # 80
                self.flow_idle.get_std(),   # 81
                self.flow_idle.get_max(),   # 82
                self.flow_idle.get_min(),   # 83
            ]
        else:
            fields += [0, 0, 0, 0]

        # 84 label
        fields.append(label)

        return ",".join(str(f) for f in fields)

    @staticmethod
    def get_header() -> str:
        return (
            "Flow ID,Src IP,Src Port,Dst IP,Dst Port,Protocol,Timestamp,"
            "Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,"
            "TotLen Fwd Pkts,TotLen Bwd Pkts,"
            "Fwd Pkt Len Max,Fwd Pkt Len Min,Fwd Pkt Len Mean,Fwd Pkt Len Std,"
            "Bwd Pkt Len Max,Bwd Pkt Len Min,Bwd Pkt Len Mean,Bwd Pkt Len Std,"
            "Flow Byts/s,Flow Pkts/s,"
            "Flow IAT Mean,Flow IAT Std,Flow IAT Max,Flow IAT Min,"
            "Fwd IAT Tot,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,Fwd IAT Min,"
            "Bwd IAT Tot,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,"
            "Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,Bwd URG Flags,"
            "Fwd Header Len,Bwd Header Len,Fwd Pkts/s,Bwd Pkts/s,"
            "Pkt Len Min,Pkt Len Max,Pkt Len Mean,Pkt Len Std,Pkt Len Var,"
            "FIN Flag Cnt,SYN Flag Cnt,RST Flag Cnt,PSH Flag Cnt,"
            "ACK Flag Cnt,URG Flag Cnt,CWE Flag Count,ECE Flag Cnt,"
            "Down/Up Ratio,Pkt Size Avg,Fwd Seg Size Avg,Bwd Seg Size Avg,"
            "Fwd Byts/b Avg,Fwd Pkts/b Avg,Fwd Blk Rate Avg,"
            "Bwd Byts/b Avg,Bwd Pkts/b Avg,Bwd Blk Rate Avg,"
            "Subflow Fwd Pkts,Subflow Fwd Byts,Subflow Bwd Pkts,Subflow Bwd Byts,"
            "Init Fwd Win Byts,Init Bwd Win Byts,Fwd Act Data Pkts,Fwd Seg Size Min,"
            "Active Mean,Active Std,Active Max,Active Min,"
            "Idle Mean,Idle Std,Idle Max,Idle Min,Label"
        )
