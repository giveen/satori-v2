"""Packet parsing helpers: convert raw bytes into PacketMeta."""
from __future__ import annotations

import typing as t
import dpkt
import socket

from .flow import PacketMeta


def parse_raw(ts: float, raw: bytes) -> t.Optional[PacketMeta]:
    """Parse raw packet bytes and return a PacketMeta or None if unsupported.

    Supports Ethernet->IP->TCP/UDP. Returns None for non-IP or malformed packets.
    """
    try:
        eth = dpkt.ethernet.Ethernet(raw)
    except Exception:
        return None

    src_mac = getattr(eth, "src", None)
    dst_mac = getattr(eth, "dst", None)

    if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
        return None

    ip = eth.data
    # dpkt's IPv4 uses `p` for protocol, IPv6 implementations may use `nh` or `nxt`.
    # Use getattr fallbacks so we don't crash on different dpkt variants.
    proto = getattr(ip, "p", getattr(ip, "nh", getattr(ip, "nxt", None)))

    try:
        if proto == dpkt.ip.IP_PROTO_TCP:
            tcp = ip.data
            src_port = getattr(tcp, "sport", 0)
            dst_port = getattr(tcp, "dport", 0)
        elif proto == dpkt.ip.IP_PROTO_UDP:
            udp = ip.data
            src_port = getattr(udp, "sport", 0)
            dst_port = getattr(udp, "dport", 0)
        else:
            src_port = 0
            dst_port = 0
    except Exception:
        src_port = 0
        dst_port = 0

    # IPv4 vs IPv6 address extraction
    if isinstance(ip, dpkt.ip.IP):
        try:
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
        except Exception:
            return None
    else:
        # basic IPv6 textual formatting
        try:
            src_ip = socket.inet_ntop(socket.AF_INET6, ip.src)
            dst_ip = socket.inet_ntop(socket.AF_INET6, ip.dst)
        except Exception:
            return None

    return PacketMeta(ts=ts, src_mac=src_mac, dst_mac=dst_mac, src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, proto=proto, raw=raw)
