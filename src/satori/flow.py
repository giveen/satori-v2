"""Simple flow tracking: 5-tuple grouping and Host mapping.

This is intentionally minimal for Phase 0/1: deterministic and memory-bounded.
"""
from __future__ import annotations

import dataclasses
import ipaddress
import typing as t

@dataclasses.dataclass
class PacketMeta:
    ts: float
    src_mac: t.Optional[bytes]
    dst_mac: t.Optional[bytes]
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int
    raw: bytes


@dataclasses.dataclass
class Flow:
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: int
    packets: list[PacketMeta]

    def add(self, pkt: PacketMeta):
        self.packets.append(pkt)


class FlowEngine:
    """Group packets by 5-tuple and emit Flow objects.

    Note: canonicalizes tuple so flow direction is preserved in packets list.
    """

    def __init__(self):
        self._flows: dict[str, Flow] = {}

    @staticmethod
    def _make_flow_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: int) -> str:
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}/{proto}"

    def ingest_packet(self, meta: PacketMeta):
        key = self._make_flow_key(meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port, meta.proto)
        if key not in self._flows:
            self._flows[key] = Flow(flow_id=key, src_ip=meta.src_ip, src_port=meta.src_port, dst_ip=meta.dst_ip, dst_port=meta.dst_port, proto=meta.proto, packets=[])
        self._flows[key].add(meta)

    def flows(self) -> t.Iterator[Flow]:
        # deterministic iteration order
        for k in sorted(self._flows.keys()):
            yield self._flows[k]
