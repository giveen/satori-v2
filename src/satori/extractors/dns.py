"""DNS extractor: parse DNS packets from UDP flows and emit evidence items."""
from __future__ import annotations

import typing as t
import dpkt
import socket

from satori.flow import Flow
from satori import evidence as ev


def extract_from_flow(flow: Flow) -> list[dict]:
    evidence: list[dict] = []
    for idx, pkt in enumerate(flow.packets):
        if pkt.proto != 17:
            continue
        try:
            eth = dpkt.ethernet.Ethernet(pkt.raw)
            ip = eth.data
            udp = ip.data
        except Exception:
            continue

        if not (udp.sport == 53 or udp.dport == 53):
            continue

        try:
            dns = dpkt.dns.DNS(udp.data)
        except Exception:
            continue

        queries = []
        for q in getattr(dns, "qd", []) or []:
            try:
                queries.append({"name": q.name, "type": q.type})
            except Exception:
                continue

        answers = []
        for a in getattr(dns, "an", []) or []:
            try:
                answers.append({"name": a.name, "type": a.type, "rdata": getattr(a, "rdata", None)})
            except Exception:
                continue

        client_ip = None
        try:
            client_ip = socket.inet_ntoa(ip.src) if isinstance(ip, dpkt.ip.IP) else None
        except Exception:
            client_ip = None

        evidence.append({
            "host_ip": client_ip,
            "type": "dns",
            "dns": {"id": getattr(dns, "id", None), "qdcount": getattr(dns, "qdcount", None), "ancount": getattr(dns, "ancount", None), "queries": queries, "answers": answers},
            "provenance": {"flow_id": flow.flow_id, "pkt_index": idx, "ts": pkt.ts},
            "score_hint": 0.6,
        })
        # normalized evidence: EDNS present and UDP payload size
        norm = []
        try:
            # EDNS OPT RR presence approximated by any AR record with type 41
            edns_present = any(getattr(a, "type", None) == 41 for a in getattr(dns, "ar", []) or [])
        except Exception:
            edns_present = False
        norm.append(ev.make_evidence("dns_extractor", "udp", "dns.edns_present", bool(edns_present), 0.2, None, flow.flow_id, pkt.ts, {"pkt_index": idx}))
        # udp payload size
        norm.append(ev.make_evidence("dns_extractor", "udp", "dns.udp_payload_size", len(udp.data), 0.2, None, flow.flow_id, pkt.ts, {"pkt_index": idx}))
        evidence[-1]["evidence_norm"] = norm

    return evidence
