"""
FlowGenerator — manages active flows and emits completed ones.
Matches CICFlowMeter FlowGenerator.java behaviour exactly.
"""

from __future__ import annotations

from typing import Callable, Optional

from .flow import Flow, FLOW_TIMEOUT, ACTIVITY_TIMEOUT
from .packet_info import PacketInfo


class FlowGenerator:

    def __init__(
        self,
        bidirectional: bool = True,
        flow_timeout: int = FLOW_TIMEOUT,
        activity_timeout: int = ACTIVITY_TIMEOUT,
        on_flow_complete: Optional[Callable[[Flow], None]] = None,
    ):
        self.bidirectional = bidirectional
        self.flow_timeout = flow_timeout
        self.activity_timeout = activity_timeout
        self.on_flow_complete = on_flow_complete

        self._current_flows: dict[str, Flow] = {}
        self._finished_flows: list[Flow] = []

    def add_packet(self, pkt: Optional[PacketInfo]):
        if pkt is None:
            return

        ts = pkt.timestamp
        fwd_id = pkt.fwd_flow_id()
        bwd_id = pkt.bwd_flow_id()

        if fwd_id in self._current_flows or bwd_id in self._current_flows:
            flow_id = fwd_id if fwd_id in self._current_flows else bwd_id
            flow = self._current_flows[flow_id]

            if (ts - flow.flow_start_time) > self.flow_timeout:
                # Flow timed out → emit if it has more than 1 packet, start fresh
                if flow.packet_count() > 1:
                    self._emit(flow)
                del self._current_flows[flow_id]
                self._current_flows[fwd_id] = Flow(
                    pkt,
                    flow_src_ip=flow.src_ip,
                    flow_dst_ip=flow.dst_ip,
                    flow_src_port=flow.src_port,
                    flow_dst_port=flow.dst_port,
                    bidirectional=self.bidirectional,
                )

            elif pkt.flag_fin:
                # TCP FIN — connection closing cleanly, emit immediately
                flow.add_packet(pkt)
                if flow.packet_count() > 1:
                    self._emit(flow)
                del self._current_flows[flow_id]

            elif pkt.flag_rst:
                # TCP RST — connection rejected/reset, emit immediately.
                # Port scan flows end with RST; without this they would sit in
                # the buffer for the full FLOW_TIMEOUT before appearing in the CSV.
                flow.add_packet(pkt)
                if flow.packet_count() > 1:
                    self._emit(flow)
                del self._current_flows[flow_id]

            else:
                flow.add_packet(pkt)

        else:
            self._current_flows[fwd_id] = Flow(pkt, bidirectional=self.bidirectional)

    def flush_timed_out(self):
        """
        Emit and remove flows that have exceeded flow_timeout without a new packet.
        Called periodically during live capture so stale flows are not held forever.
        Uses wall-clock time (time.time()) converted to microseconds.
        """
        import time
        now_us = int(time.time() * 1_000_000)
        expired = [
            flow_id for flow_id, flow in self._current_flows.items()
            if (now_us - flow.flow_last_seen) > self.flow_timeout
        ]
        for flow_id in expired:
            flow = self._current_flows.pop(flow_id)
            if flow.packet_count() > 1:
                self._emit(flow)

    def flush(self):
        """Emit all remaining active flows (call after the last packet)."""
        for flow in list(self._current_flows.values()):
            if flow.packet_count() > 1:
                self._emit(flow)
        self._current_flows.clear()

    def _emit(self, flow: Flow):
        if self.on_flow_complete is not None:
            self.on_flow_complete(flow)
        else:
            self._finished_flows.append(flow)

    @property
    def finished_flows(self) -> list[Flow]:
        return self._finished_flows
