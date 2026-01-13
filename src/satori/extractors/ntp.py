"""NTP extractor: parse NTP packets from UDP flows and emit evidence items.

This module implements a minimal NTP header parser (RFC 5905 fields of interest).
"""
from __future__ import annotations

import typing as t
import struct
import socket
import dpkt

from satori.flow import Flow
from satori import evidence as ev


def _parse_ntp(payload: bytes) -> t.Optional[dict]:
    # Minimal check: NTP header is 48 bytes
    if len(payload) < 48:
        return None
    try:
        # First byte: LI (2 bits), VN (3 bits), Mode (3 bits)
        b = payload[0]
        li = (b >> 6) & 0x3
        vn = (b >> 3) & 0x7
        mode = b & 0x7
        stratum = payload[1]
        poll = payload[2]
        precision = payload[3]
        ref_id = payload[12:16]
        try:
            ref_id_text = socket.inet_ntoa(ref_id)
        except Exception:
            ref_id_text = ref_id.hex()

        # timestamps: reference(16-23), originate(24-31), receive(32-39), transmit(40-47)
        def _read_ts(off: int) -> float:
            if len(payload) >= off + 8:
                secs = int.from_bytes(payload[off:off+4], "big")
                frac = int.from_bytes(payload[off+4:off+8], "big")
                # convert to float seconds (approx)
                return secs + frac / (1 << 32)
            return 0.0

        ref_ts = _read_ts(16)
        orig_ts = _read_ts(24)
        recv_ts = _read_ts(32)
        xmit_ts = _read_ts(40)

        # Interpret leap indicator
        li_map = {
            0: "no_warning",
            1: "last_minute_has_61_seconds",
            2: "last_minute_has_59_seconds",
            3: "alarm_condition",
        }

        # Detect simple MD5 auth presence: last 16 bytes non-zero and length >= 64
        auth_md5_present = False
        auth_md5_hex = None
        if len(payload) >= 48 + 16:
            tail = payload[-16:]
            if any(b != 0 for b in tail):
                auth_md5_present = True
                auth_md5_hex = tail.hex()

        return {
            "li": li,
            "li_desc": li_map.get(li, "unknown"),
            "vn": vn,
            "mode": mode,
            "stratum": stratum,
            "poll": poll,
            "precision": precision,
            "ref_id": ref_id_text,
            "ref_ts": ref_ts,
            "orig_ts": orig_ts,
            "recv_ts": recv_ts,
            "xmit_ts": xmit_ts,
            "auth_md5_present": auth_md5_present,
            "auth_md5": auth_md5_hex,
        }
    except Exception:
        return None


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

        # NTP uses port 123
        if not (udp.sport == 123 or udp.dport == 123):
            continue

        ntp = _parse_ntp(udp.data)
        if ntp is None:
            continue

        client_ip = None
        try:
            client_ip = socket.inet_ntoa(ip.src) if isinstance(ip, dpkt.ip.IP) else None
        except Exception:
            client_ip = None

        evidence.append({
            "host_ip": client_ip,
            "type": "ntp",
            "ntp": ntp,
            "provenance": {"flow_id": flow.flow_id, "pkt_index": idx, "ts": pkt.ts},
            "score_hint": 0.5,
        })
        # normalized evidence for OS-relevant NTP fields
        norm = []
        norm.append(ev.make_evidence("ntp_extractor", "udp", "ntp.version", ntp.get("vn"), 0.3, None, flow.flow_id, pkt.ts, {"pkt_index": idx}))
        norm.append(ev.make_evidence("ntp_extractor", "udp", "ntp.stratum", ntp.get("stratum"), 0.3, None, flow.flow_id, pkt.ts, {"pkt_index": idx}))
        norm.append(ev.make_evidence("ntp_extractor", "udp", "ntp.ref_id", ntp.get("ref_id"), 0.3, None, flow.flow_id, pkt.ts, {"pkt_index": idx}))
        evidence[-1]["evidence_norm"] = norm

    return evidence
