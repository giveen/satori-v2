"""PCAP and PCAPNG streaming ingestion utilities.

Provides a simple streaming iterator that yields timestamp and raw packet bytes.
Attempts to use dpkt for pcap, and pcapng for pcapng files.
"""
from __future__ import annotations

import os
import typing as t
import dpkt

try:
    from pcapng import FileScanner
    _PCAPNG_FILESCANNER = True
except Exception:
    _PCAPNG_FILESCANNER = False

# fallback: dpkt may provide pcapng support (dpkt.pcapng.Reader)
try:
    import dpkt.pcapng as dpkt_pcapng
    _HAS_DPKT_PCAPNG = True
except Exception:
    _HAS_DPKT_PCAPNG = False


def iter_packets(path: str):
    """Yield (ts, raw_bytes) for packets in a pcap or pcapng file.

    This is streaming and does not load entire file in memory.
    """
    _, ext = os.path.splitext(path)
    ext = ext.lower()

    def _iter_pcap(path):
        with open(path, "rb") as fh:
            pcap = dpkt.pcap.Reader(fh)
            for ts, buf in pcap:
                yield ts, buf

    def _iter_pcapng_with_dpkt(path):
        with open(path, "rb") as fh:
            rdr = dpkt_pcapng.Reader(fh)
            for blk in rdr:
                try:
                    ts, buf = blk
                    yield ts, buf
                except Exception:
                    continue

    def _iter_pcapng_with_scanner(path):
        with open(path, "rb") as fh:
            for block in FileScanner(fh):
                if hasattr(block, "packet_data"):
                    ts = float(block.packet_header.tv_sec) + float(block.packet_header.tv_usec) / 1_000_000
                    yield ts, bytes(block.packet_data)

    # If extension explicitly indicates pcap or cap, prefer pcap Reader
    if ext in (".pcap", ".cap"):
        try:
            for pkt in _iter_pcap(path):
                yield pkt
            return
        except Exception:
            # fallthrough to pcapng attempts
            pass

    # If extension explicitly indicates pcapng, prefer pcapng
    if ext == ".pcapng":
        if _PCAPNG_FILESCANNER:
            for pkt in _iter_pcapng_with_scanner(path):
                yield pkt
            return
        if _HAS_DPKT_PCAPNG:
            for pkt in _iter_pcapng_with_dpkt(path):
                yield pkt
            return

    # Unknown extension: try pcap first, then pcapng variants
    try:
        for pkt in _iter_pcap(path):
            yield pkt
        return
    except Exception:
        # try pcapng scanner first
        if _PCAPNG_FILESCANNER:
            for pkt in _iter_pcapng_with_scanner(path):
                yield pkt
            return
        if _HAS_DPKT_PCAPNG:
            for pkt in _iter_pcapng_with_dpkt(path):
                yield pkt
            return
        raise RuntimeError("no suitable reader for pcap/pcapng files")
