"""SSH extractor: extract SSH identification banner and initial KEX info when present.

This extractor looks for TCP packets on port 22 and extracts the ASCII
SSH identification string (RFC 4253) if present in the payload. It emits
evidence items with `banner` and basic provenance.
"""
from __future__ import annotations

import typing as t
import dpkt
import socket
from satori import evidence as ev


def _extract_banner_from_payload(payload: bytes) -> t.Optional[str]:
    try:
        # SSH identification string is ASCII and ends with CRLF or LF
        idx = payload.find(b"SSH-")
        if idx == -1:
            return None
        tail = payload[idx:idx + 255]
        # read until newline
        nl = tail.find(b"\n")
        if nl == -1:
            line = tail
        else:
            line = tail[: nl + 1]
        # decode safely
        try:
            s = line.decode("ascii", errors="ignore").strip()
            return s
        except Exception:
            return None
    except Exception:
        return None


def _parse_kexinit(payload: bytes) -> t.Optional[dict]:
    """Parse a minimal SSH KEXINIT from payload bytes and return kex lists.

    This is a heuristic parser: it searches for the SSH_MSG_KEXINIT (20)
    byte and then parses subsequent name-lists per RFC 4253. It returns
    the full set of name-lists (kex, hostkey, encryption, mac, compression,
    languages) if present.
    """
    try:
        # find message byte 20
        i = payload.find(b"\x14")
        if i == -1:
            return None
        off = i + 1
        # cookie (16 bytes)
        if off + 16 > len(payload):
            return None
        cookie = payload[off:off + 16]
        off += 16

        def read_namelist(buf, o):
            if o + 4 > len(buf):
                return None, o
            n = int.from_bytes(buf[o:o+4], "big")
            o += 4
            if o + n > len(buf):
                return None, o
            s = buf[o:o+n].decode("ascii", errors="ignore")
            o += n
            return s, o

        # RFC 4253 lists 10 name-lists in order. Parse them all safely.
        names = []
        for _ in range(10):
            nl, off = read_namelist(payload, off)
            if nl is None:
                return None
            names.append(nl.split(",") if nl else [])

        # after name-lists: first_kex_packet_follows (1 byte) and reserved (4 bytes)
        if off + 5 <= len(payload):
            first_kex_packet_follows = payload[off]
            off += 1
            # reserved 4 bytes
            off += 4
        else:
            first_kex_packet_follows = None

        (kex_algos, server_host_key_algos, enc_c2s, enc_s2c, mac_c2s, mac_s2c, comp_c2s, comp_s2c, lang_c2s, lang_s2c) = names

        return {
            "cookie": cookie.hex(),
            "kex_algorithms": kex_algos,
            "server_host_key_algorithms": server_host_key_algos,
            "encryption_algorithms_client_to_server": enc_c2s,
            "encryption_algorithms_server_to_client": enc_s2c,
            "mac_algorithms_client_to_server": mac_c2s,
            "mac_algorithms_server_to_client": mac_s2c,
            "compression_algorithms_client_to_server": comp_c2s,
            "compression_algorithms_server_to_client": comp_s2c,
            "languages_client_to_server": lang_c2s,
            "languages_server_to_client": lang_s2c,
            "first_kex_packet_follows": first_kex_packet_follows,
        }
    except Exception:
        return None


def extract_from_flow(flow) -> list[dict]:
    evidence: list[dict] = []
    for idx, pkt in enumerate(flow.packets):
        if pkt.proto != 6:
            continue
        try:
            eth = dpkt.ethernet.Ethernet(pkt.raw)
            ip = eth.data
            tcp = ip.data
        except Exception:
            continue

        # check for SSH port
        if not (getattr(tcp, "sport", 0) == 22 or getattr(tcp, "dport", 0) == 22):
            continue

        payload = getattr(tcp, "data", b"") or b""
        if not payload:
            continue

        # extract banner if present
        banner = _extract_banner_from_payload(payload)
        src_ip = None
        try:
            src_ip = socket.inet_ntoa(ip.src) if isinstance(ip, dpkt.ip.IP) else None
        except Exception:
            src_ip = None

        provenance = {"flow_id": getattr(flow, "flow_id", None), "pkt_index": idx, "ts": pkt.ts}
        ev_items: list[dict] = []

        # legacy payload for compatibility
        legacy = {"host_ip": src_ip, "type": "ssh", "provenance": provenance, "score_hint": 0.5}
        if banner:
            legacy["ssh"] = {"banner": banner}

        if banner:
            ev_items.append(ev.make_evidence("ssh_extractor", "tcp", "ssh.banner", banner, 0.3, src_ip, getattr(flow, "flow_id", None), pkt.ts, provenance))
            # attempt lightweight software_family inference from banner (heuristic)
            try:
                family = None
                if "OpenSSH" in banner:
                    family = "openssh"
                elif "Dropbear" in banner:
                    family = "dropbear"
                if family:
                    ev_items.append(ev.make_evidence("ssh_extractor", "tcp", "ssh.software_family", family, 0.2, src_ip, getattr(flow, "flow_id", None), pkt.ts, provenance))
            except Exception:
                pass

        # try parsing KEXINIT if present in payload
        kex = _parse_kexinit(payload)
        if kex:
            legacy.setdefault("ssh", {})
            legacy["ssh"]["kexinit"] = kex
            # add core kex lists as individual evidence items
            ev_items.append(ev.make_evidence("ssh_extractor", "tcp", "ssh.kex_algorithms", kex.get("kex_algorithms"), 0.4, src_ip, getattr(flow, "flow_id", None), pkt.ts, provenance))
            ev_items.append(ev.make_evidence("ssh_extractor", "tcp", "ssh.hostkey_algorithms", kex.get("server_host_key_algorithms"), 0.4, src_ip, getattr(flow, "flow_id", None), pkt.ts, provenance))
            ev_items.append(ev.make_evidence("ssh_extractor", "tcp", "ssh.encryption_algorithms_c2s", kex.get("encryption_algorithms_client_to_server"), 0.4, src_ip, getattr(flow, "flow_id", None), pkt.ts, provenance))
            ev_items.append(ev.make_evidence("ssh_extractor", "tcp", "ssh.encryption_algorithms_s2c", kex.get("encryption_algorithms_server_to_client"), 0.4, src_ip, getattr(flow, "flow_id", None), pkt.ts, provenance))
            ev_items.append(ev.make_evidence("ssh_extractor", "tcp", "ssh.mac_algorithms_c2s", kex.get("mac_algorithms_client_to_server"), 0.4, src_ip, getattr(flow, "flow_id", None), pkt.ts, provenance))
            ev_items.append(ev.make_evidence("ssh_extractor", "tcp", "ssh.mac_algorithms_s2c", kex.get("mac_algorithms_server_to_client"), 0.4, src_ip, getattr(flow, "flow_id", None), pkt.ts, provenance))
            ev_items.append(ev.make_evidence("ssh_extractor", "tcp", "ssh.comp_algorithms_c2s", kex.get("compression_algorithms_client_to_server"), 0.4, src_ip, getattr(flow, "flow_id", None), pkt.ts, provenance))
            ev_items.append(ev.make_evidence("ssh_extractor", "tcp", "ssh.comp_algorithms_s2c", kex.get("compression_algorithms_server_to_client"), 0.4, src_ip, getattr(flow, "flow_id", None), pkt.ts, provenance))

        legacy["evidence_norm"] = ev_items
        if "ssh" in legacy:
            evidence.append(legacy)

    return evidence
