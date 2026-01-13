from typing import List, Dict, Any
import dpkt
from satori import evidence as ev


def _parse_options_bytes(data: bytes) -> List[dict]:
    opts = []
    i = 0
    while i < len(data):
        kind = data[i]
        if kind == 0:
            opts.append({"kind": 0})
            break
        if kind == 1:
            opts.append({"kind": 1})
            i += 1
            continue
        if i + 1 >= len(data):
            break
        length = data[i + 1]
        if length < 2:
            break
        val = data[i + 2 : i + length]
        opts.append({"kind": kind, "length": length, "value": val})
        i += length
    return opts


def extract_from_flow(flow) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = []

    for idx, pkt in enumerate(flow.packets):
        if pkt.proto != 6:
            continue
        try:
            eth = dpkt.ethernet.Ethernet(pkt.raw)
            ip = eth.data
            tcp = ip.data
        except Exception:
            continue

        # Look for SYN-only packets (initial SYN)
        flags = getattr(tcp, "flags", 0)
        if not (flags & dpkt.tcp.TH_SYN):
            continue

        # Determine options bytes.
        opts_raw = b""
        # dpkt may expose tcp.opts, otherwise slice from raw tcp bytes
        if hasattr(tcp, "opts") and tcp.opts:
            opts_raw = tcp.opts
        else:
            try:
                raw_tcp = bytes(tcp)
                hdr_len = (getattr(tcp, "off", 5) * 4)
                if len(raw_tcp) >= hdr_len:
                    opts_raw = raw_tcp[20:hdr_len]
            except Exception:
                opts_raw = b""

        opts = _parse_options_bytes(opts_raw)
        opt_kinds = [o.get("kind") for o in opts]

        provenance = {"flow_id": getattr(flow, "flow_id", None), "pkt_index": idx, "ts": pkt.ts}

        # legacy payload for compatibility (maintain previous API)
        legacy: Dict[str, Any] = {
            "type": "tcp",
            "provenance": provenance,
            "tcp": {
                "sport": getattr(tcp, "sport", None),
                "dport": getattr(tcp, "dport", None),
                "flags": flags,
                "win": getattr(tcp, "win", None),
                "opts_order": opt_kinds,
            },
            "ip": {"ttl": getattr(ip, "ttl", None)},
            "score_hint": 0.7,
        }

        try:
            legacy["tcp"]["isn"] = int(getattr(tcp, "seq", None))
        except Exception:
            legacy["tcp"]["isn"] = None

        try:
            ece = bool(flags & dpkt.tcp.TH_ECE)
            cwr = bool(flags & dpkt.tcp.TH_CWR)
            legacy["tcp"]["ecn"] = {"ece": ece, "cwr": cwr}
        except Exception:
            legacy["tcp"]["ecn"] = {"ece": False, "cwr": False}

        for o in opts:
            k = o.get("kind")
            if k == 2:
                val = o.get("value", b"")
                if len(val) >= 2:
                    legacy["tcp"]["mss"] = int.from_bytes(val[:2], "big")
            if k == 3:
                val = o.get("value", b"")
                if len(val) >= 1:
                    legacy["tcp"]["wscale"] = val[0]
            if k == 8:
                legacy["tcp"]["ts_present"] = True

        # build normalized evidence list
        ev_items = []
        ev_items.append(ev.make_evidence("tcp_extractor", "tcp", "tcp.opts_order", opt_kinds, 0.6, None, getattr(flow, "flow_id", None), pkt.ts, provenance))
        ev_items.append(ev.make_evidence("tcp_extractor", "ip", "ip.ttl", getattr(ip, "ttl", None), 0.5, None, getattr(flow, "flow_id", None), pkt.ts, provenance))
        ev_items.append(ev.make_evidence("tcp_extractor", "tcp", "tcp.window_size", getattr(tcp, "win", None), 0.5, None, getattr(flow, "flow_id", None), pkt.ts, provenance))

        ev_items.append(ev.make_evidence("tcp_extractor", "tcp", "tcp.isn", legacy["tcp"].get("isn"), 0.6, None, getattr(flow, "flow_id", None), pkt.ts, provenance))
        ev_items.append(ev.make_evidence("tcp_extractor", "tcp", "tcp.ecn", legacy["tcp"].get("ecn"), 0.5, None, getattr(flow, "flow_id", None), pkt.ts, provenance))

        for o in opts:
            k = o.get("kind")
            if k == 2:
                val = o.get("value", b"")
                if len(val) >= 2:
                    ev_items.append(ev.make_evidence("tcp_extractor", "tcp", "tcp.mss", int.from_bytes(val[:2], "big"), 0.7, None, getattr(flow, "flow_id", None), pkt.ts, provenance))
            if k == 3:
                val = o.get("value", b"")
                if len(val) >= 1:
                    ev_items.append(ev.make_evidence("tcp_extractor", "tcp", "tcp.wscale", val[0], 0.7, None, getattr(flow, "flow_id", None), pkt.ts, provenance))
            if k == 8:
                ev_items.append(ev.make_evidence("tcp_extractor", "tcp", "tcp.ts_present", True, 0.7, None, getattr(flow, "flow_id", None), pkt.ts, provenance))

        legacy["evidence_norm"] = ev_items
        evidence.append(legacy)

    return evidence
