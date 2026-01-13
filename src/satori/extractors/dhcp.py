"""DHCP extractor: parse DHCP packets from UDP flows and emit evidence items.

Evidence format (dict):
  - host_ip: observed client IP (if any)
  - type: 'dhcp'
  - dhcp: {op, xid, chaddr, options}
  - provenance: {flow_id, pkt_index, ts}
  - score_hint: float (0..1)
"""
from __future__ import annotations

import typing as t
import dpkt
import socket

from satori.flow import Flow
from satori import evidence as ev


def _parse_dhcp_from_udp(raw_udp_payload: bytes) -> t.Optional[dpkt.dhcp.DHCP]:
    try:
        dhcp = dpkt.dhcp.DHCP(raw_udp_payload)
        return dhcp
    except Exception:
        return None


def extract_from_flow(flow: Flow) -> list[dict]:
    evidence: list[dict] = []
    # Inspect UDP packets in the flow for DHCP payloads.
    for idx, pkt in enumerate(flow.packets):
        # UDP proto number is 17
        if pkt.proto != 17:
            continue
        # dpkt parsing: raw contains ethernet header; reparse
        try:
            eth = dpkt.ethernet.Ethernet(pkt.raw)
            ip = eth.data
            udp = ip.data
        except Exception:
            continue

        # DHCP uses ports 67 (server) and 68 (client)
        if not (udp.sport in (67, 68) or udp.dport in (67, 68)):
            continue

        dhcp = _parse_dhcp_from_udp(udp.data)
        if dhcp is None:
            continue

        # Build options mapping
        opts = {}
        try:
            for opt in dhcp.opts:
                if isinstance(opt, tuple) and len(opt) >= 2:
                    key = opt[0]
                    val = opt[1]
                    opts[key] = val
        except Exception:
            pass

        chaddr = None
        try:
            # chaddr is bytes
            chaddr = dhcp.chaddr.hex() if hasattr(dhcp, "chaddr") and dhcp.chaddr else None
        except Exception:
            chaddr = None

        client_ip = None
        try:
            if isinstance(ip, dpkt.ip.IP):
                client_ip = socket.inet_ntoa(ip.src)
            else:
                client_ip = None
        except Exception:
            client_ip = None

        evidence.append({
            "host_ip": client_ip,
            "type": "dhcp",
            "dhcp": {"op": getattr(dhcp, "op", None), "xid": getattr(dhcp, "xid", None), "chaddr": chaddr, "options": opts},
            "provenance": {"flow_id": flow.flow_id, "pkt_index": idx, "ts": pkt.ts},
            "score_hint": 0.8,
        })
        # normalized evidence for OS-relevant fields
        norm = []
        # vendor-class-identifier often option 60
        vci = opts.get(60) or opts.get("vendor-class-identifier") or opts.get(b"vendor-class-identifier")
        if vci:
            norm.append(ev.make_evidence("dhcp_extractor", "udp", "dhcp.vendor_class_id", vci, 0.4, None, flow.flow_id, pkt.ts, {"pkt_index": idx}))
        prl = opts.get(55) or opts.get("parameter-request-list")
        if prl:
            norm.append(ev.make_evidence("dhcp_extractor", "udp", "dhcp.param_request_list", prl, 0.3, None, flow.flow_id, pkt.ts, {"pkt_index": idx}))
        if norm:
            evidence[-1]["evidence_norm"] = norm

    return evidence
