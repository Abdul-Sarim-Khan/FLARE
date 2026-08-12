"""
cicflowmeter_py — Python port of CICFlowMeter.

Produces CICIDS2017-compatible flow features (84 columns) from PCAP files.
Replicates the exact Java behaviour, including all known bugs that are present
in the published CICIDS2017 dataset, so feature values are numerically identical.
"""

from .flow import Flow
from .flow_generator import FlowGenerator
from .packet_info import PacketInfo
from .reader import read_pcap

__all__ = ["Flow", "FlowGenerator", "PacketInfo", "read_pcap"]
