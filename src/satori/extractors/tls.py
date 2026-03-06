"""TLS extractor: parse TLS ClientHello from TCP flows and emit JA3 fingerprints.

JA3 algorithm (https://github.com/salesforce/ja3):
  1. Parse TLS record layer for a ClientHello (content_type=22, handshake_type=1)
  2. Extract: SSLVersion, Ciphers, Extensions, EllipticCurves, EcPointFormats
  3. Filter GREASE values (RFC 8701) from all list fields
  4. Concatenate as: "{ver},{ciphers}-{exts}-{curves}-{formats}"
  5. MD5 the string → the JA3 hash

The extractor looks at the first data-bearing packet on any TCP flow that
appears to be TLS (starts with 0x16 0x03) for src or dst port in TLS_PORTS.
"""
from __future__ import annotations

import hashlib
import socket
import struct
import typing as t

import dpkt

from satori.flow import Flow
from satori import evidence as ev


# Ports to inspect for TLS traffic
TLS_PORTS = {443, 8443, 465, 636, 993, 995, 3389, 5061}

# GREASE values per RFC 8701 — these appear in cipher, extension and group lists
# and must be filtered before computing JA3
_GREASE = frozenset(
    0x0A0A + (i << 12) for i in range(16)
) | frozenset(
    # Standard GREASE set: 0x0a0a, 0x1a1a, ..., 0xfafa
    v
    for v in (
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A,
        0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A,
        0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    )
)


def _is_grease(v: int) -> bool:
    return v in _GREASE


def _read_u8(buf: bytes, off: int) -> t.Tuple[int, int]:
    return buf[off], off + 1


def _read_u16(buf: bytes, off: int) -> t.Tuple[int, int]:
    return struct.unpack_from(">H", buf, off)[0], off + 2


def _read_u24(buf: bytes, off: int) -> t.Tuple[int, int]:
    hi, lo = struct.unpack_from(">BH", buf, off)
    return (hi << 16) | lo, off + 3


def _read_bytes(buf: bytes, off: int, n: int) -> t.Tuple[bytes, int]:
    return buf[off:off + n], off + n


def parse_client_hello(payload: bytes) -> t.Optional[dict]:
    """Parse a TLS ClientHello and return the JA3 component fields.

    Returns None if the payload does not contain a valid ClientHello.
    Handles the common case where the entire ClientHello fits in a single
    TCP segment (the vast majority of real-world traffic).
    """
    try:
        if len(payload) < 9:
            return None

        # TLS record layer
        content_type = payload[0]
        if content_type != 0x16:  # handshake
            return None

        # Record-layer version (0x0301 for TLS 1.0+, may be 0x0300 for SSL3)
        record_version = struct.unpack_from(">H", payload, 1)[0]
        record_len = struct.unpack_from(">H", payload, 3)[0]

        # Handshake header starts at offset 5
        if len(payload) < 5 + record_len:
            # Truncated — try to parse what we have (best-effort)
            pass

        handshake_type = payload[5]
        if handshake_type != 0x01:  # ClientHello
            return None

        # 3-byte handshake length
        hs_len, _ = _read_u24(payload, 6)
        off = 9

        if off + 2 > len(payload):
            return None

        # Client version
        client_version, off = _read_u16(payload, off)

        # Random (32 bytes)
        if off + 32 > len(payload):
            return None
        off += 32  # skip random

        # Session ID
        if off + 1 > len(payload):
            return None
        sid_len, off = _read_u8(payload, off)
        off += sid_len  # skip session ID

        # --- Cipher Suites ---
        if off + 2 > len(payload):
            return None
        cs_len, off = _read_u16(payload, off)
        ciphers = []
        cs_end = off + cs_len
        while off + 2 <= min(cs_end, len(payload)):
            cs, off = _read_u16(payload, off)
            if not _is_grease(cs):
                ciphers.append(cs)
        off = cs_end  # ensure we're past the cipher suites block

        # --- Compression Methods ---
        if off + 1 > len(payload):
            return None
        cm_len, off = _read_u8(payload, off)
        off += cm_len  # skip compression methods

        # --- Extensions ---
        if off + 2 > len(payload):
            # No extensions present — rare but valid for old clients
            return {
                "client_version": client_version,
                "ciphers": ciphers,
                "extensions": [],
                "curves": [],
                "point_formats": [],
            }

        ext_total_len, off = _read_u16(payload, off)
        ext_end = off + ext_total_len
        extensions: list[int] = []
        curves: list[int] = []
        point_formats: list[int] = []

        while off + 4 <= min(ext_end, len(payload)):
            ext_type, off = _read_u16(payload, off)
            ext_len, off = _read_u16(payload, off)
            ext_data_end = off + ext_len

            if not _is_grease(ext_type):
                extensions.append(ext_type)

            # supported_groups (elliptic curves) — extension type 10
            if ext_type == 0x000A and off + 2 <= len(payload):
                gl_len, goff = _read_u16(payload, off)
                goff_end = goff + gl_len
                while goff + 2 <= min(goff_end, len(payload)):
                    g, goff = _read_u16(payload, goff)
                    if not _is_grease(g):
                        curves.append(g)

            # ec_point_formats — extension type 11
            elif ext_type == 0x000B and off + 1 <= len(payload):
                pf_len = payload[off]
                poff = off + 1
                poff_end = poff + pf_len
                while poff < min(poff_end, len(payload)):
                    point_formats.append(payload[poff])
                    poff += 1

            off = ext_data_end  # advance past extension data

        return {
            "client_version": client_version,
            "ciphers": ciphers,
            "extensions": extensions,
            "curves": curves,
            "point_formats": point_formats,
        }
    except Exception:
        return None


def compute_ja3(ch: dict) -> t.Tuple[str, str]:
    """Compute the JA3 string and MD5 hash from a parsed ClientHello dict."""
    ver = str(ch["client_version"])
    ciphers = "-".join(str(c) for c in ch["ciphers"])
    exts = "-".join(str(e) for e in ch["extensions"])
    curves = "-".join(str(g) for g in ch["curves"])
    fmts = "-".join(str(f) for f in ch["point_formats"])
    ja3_str = f"{ver},{ciphers},{exts},{curves},{fmts}"
    ja3_hash = hashlib.md5(ja3_str.encode("ascii")).hexdigest()
    return ja3_str, ja3_hash


def _find_tls_payload(flow: Flow) -> t.Optional[t.Tuple[bytes, str, int]]:
    """Scan flow packets for the first TLS ClientHello. Returns (payload, src_ip, ts)."""
    for pkt in flow.packets:
        if pkt.proto != 6:  # TCP only
            continue
        try:
            eth = dpkt.ethernet.Ethernet(pkt.raw)
            ip = eth.data
            tcp = ip.data
        except Exception:
            continue

        # Check if either endpoint is a TLS port
        sport = getattr(tcp, "sport", 0)
        dport = getattr(tcp, "dport", 0)
        if not (dport in TLS_PORTS or sport in TLS_PORTS):
            continue

        payload = bytes(getattr(tcp, "data", b"") or b"")
        if not payload:
            continue

        # TLS record must begin with 0x16 0x03 (handshake, TLS/SSL 3+)
        if len(payload) < 2 or payload[0] != 0x16 or payload[1] != 0x03:
            continue

        try:
            src_ip = socket.inet_ntoa(ip.src) if isinstance(ip, dpkt.ip.IP) else None
        except Exception:
            src_ip = None

        return payload, src_ip, pkt.ts

    return None


def extract_from_flow(flow: Flow) -> list[dict]:
    """Extract JA3 TLS fingerprint from a TCP flow containing a ClientHello.

    Returns a list of evidence dicts (may be empty if no ClientHello found).
    """
    result = _find_tls_payload(flow)
    if result is None:
        return []

    payload, src_ip, ts = result
    ch = parse_client_hello(payload)
    if ch is None:
        return []

    ja3_str, ja3_hash = compute_ja3(ch)

    norm = [
        ev.make_evidence(
            source="tls_extractor",
            protocol="tcp",
            attribute="tls.ja3",
            value=ja3_hash,
            confidence_hint=0.75,
            host_id=None,
            flow_id=flow.flow_id,
            timestamp=ts,
            provenance={"ja3_string": ja3_str, "client_version": ch["client_version"]},
        ),
        ev.make_evidence(
            source="tls_extractor",
            protocol="tcp",
            attribute="tls.ja3_string",
            value=ja3_str,
            confidence_hint=0.3,
            host_id=None,
            flow_id=flow.flow_id,
            timestamp=ts,
            provenance=None,
        ),
    ]

    return [{
        "host_ip": src_ip,
        "type": "tls",
        "tls": {
            "ja3": ja3_hash,
            "ja3_string": ja3_str,
            "client_version": ch["client_version"],
            "cipher_count": len(ch["ciphers"]),
            "extension_count": len(ch["extensions"]),
        },
        "provenance": {"flow_id": flow.flow_id, "ts": ts},
        "score_hint": 0.75,
        "evidence_norm": norm,
    }]
