from __future__ import annotations

import dataclasses
import hashlib
import typing as t
from collections import defaultdict

from . import evidence as evmod


@dataclasses.dataclass
class Host:
    host_id: str
    ips: set
    macs: set
    first_seen: float | None
    last_seen: float | None
    evidence: list
    flows: set
    ambiguity: dict
    tcp_fingerprint: dict | None = None
    ssh_fingerprint: dict | None = None
    ssh_os_hint: list | None = None

    def add_ip(self, ip: str, ts: float | None):
        if ip:
            self.ips.add(ip)
            if self.first_seen is None:
                self.first_seen = ts
            self.last_seen = ts

    def add_mac(self, mac: str):
        if mac:
            self.macs.add(mac)

    def add_flow_ref(self, flow_id: str):
        if flow_id:
            self.flows.add(flow_id)

    def add_evidence(self, evidence_item: dict):
        # preserve ordering
        self.evidence.append(evidence_item)
        # update ambiguity heuristics based on attribute
        attr = evidence_item.get("attribute")
        val = evidence_item.get("value")
        if attr in ("ip.ttl", "tcp.window_size", "tcp.mss"):
            # maintain value sets
            s = self.ambiguity.setdefault("_vals", defaultdict(set))
            s[attr].add(str(val))
            # simple rule: if more than one distinct ttl/mss/window => nat_suspected
            ttl_set = s.get("ip.ttl", set())
            mss_set = s.get("tcp.mss", set())
            win_set = s.get("tcp.window_size", set())
            if len(ttl_set) > 1 or len(mss_set) > 1 or len(win_set) > 1:
                self.ambiguity["nat_suspected"] = True
        if attr == "dhcp.vendor_class_id":
            ids = self.ambiguity.setdefault("dhcp_client_ids", set())
            ids.add(str(val))
            if len(ids) > 1:
                self.ambiguity["shared_ip"] = True
        if attr == "host.mac":
            macs = self.ambiguity.setdefault("seen_macs", set())
            macs.add(str(val))
            if len(macs) > 1:
                self.ambiguity["shared_ip"] = True


class HostRegistry:
    def __init__(self, window_seconds: int = 300):
        self._by_ip: dict[str, Host] = {}
        self.window_seconds = window_seconds

    @staticmethod
    def _make_host_id(primary: str, secondary: str | None = None) -> str:
        # deterministic short hash based on primary (IP) and optional secondary (MAC)
        base = primary if primary else ""
        if secondary:
            base = base + "|" + secondary
        h = hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]
        return f"host:{h}"

    def get_or_create(self, ip: str, mac: str | None = None, ts: float | None = None) -> Host:
        if ip in self._by_ip:
            host = self._by_ip[ip]
            host.add_ip(ip, ts)
            if mac:
                host.add_mac(mac)
            return host

        hid = self._make_host_id(ip, mac)
        host = Host(host_id=hid, ips=set(), macs=set(), first_seen=ts, last_seen=ts, evidence=[], flows=set(), ambiguity={})
        host.add_ip(ip, ts)
        if mac:
            host.add_mac(mac)
        self._by_ip[ip] = host
        return host

    def all_hosts(self) -> list[Host]:
        return list(self._by_ip.values())
