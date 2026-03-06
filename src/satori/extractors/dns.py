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
        # normalized evidence: EDNS presence and EDNS advertised buffer size
        norm = []
        edns_present = False
        edns_buf_size = None
        try:
            for ar_rec in getattr(dns, "ar", []) or []:
                if getattr(ar_rec, "type", None) == 41:  # OPT record
                    edns_present = True
                    # CLASS field of OPT record = advertised UDP payload size
                    buf = getattr(ar_rec, "cls", None)
                    if buf is not None:
                        try:
                            edns_buf_size = int(buf)
                        except Exception:
                            pass
                    break
        except Exception:
            pass
        norm.append(ev.make_evidence("dns_extractor", "udp", "dns.edns_present", edns_present, 0.2, None, flow.flow_id, pkt.ts, {"pkt_index": idx}))
        if edns_buf_size is not None:
            norm.append(ev.make_evidence("dns_extractor", "udp", "dns.edns_buf_size", edns_buf_size, 0.3, None, flow.flow_id, pkt.ts, {"pkt_index": idx}))
        evidence[-1]["evidence_norm"] = norm

    return evidence
