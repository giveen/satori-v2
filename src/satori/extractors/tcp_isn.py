"""ISN sequence analysis utilities.

Collect SYN ISNs per host and compute delta statistics and low-order-bit entropy.
"""
from __future__ import annotations

import math
import statistics
import collections
from typing import Iterable, Dict, Any

import dpkt


def analyze_isn_sequences(flows: Iterable) -> Dict[str, Dict[str, Any]]:
    """Analyze initial sequence numbers (ISNs) from SYN packets across flows.

    Returns a mapping host_ip -> {count, seqs, mean_delta, delta_std, lsb_entropy}.
    """
    per_host: dict[str, list[tuple[float, int]]] = {}

    for flow in flows:
        for pkt in getattr(flow, "packets", []):
            if pkt.proto != 6:
                continue
            try:
                eth = dpkt.ethernet.Ethernet(pkt.raw)
                ip = eth.data
                tcp = ip.data
            except Exception:
                continue

            flags = getattr(tcp, "flags", 0)
            if not (flags & dpkt.tcp.TH_SYN):
                continue

            src = getattr(pkt, "src_ip", None) or getattr(pkt, "src", None)
            seq = int(getattr(tcp, "seq", 0))
            ts = getattr(pkt, "ts", 0.0)
            per_host.setdefault(src, []).append((ts, seq))

    results: dict[str, dict[str, Any]] = {}
    for host, arr in per_host.items():
        arr.sort(key=lambda x: x[0])
        seqs = [s for _, s in arr]
        deltas = []
        for a, b in zip(seqs, seqs[1:]):
            # compute unsigned delta modulo 2^32
            delta = (b - a) & 0xFFFFFFFF
            deltas.append(delta)

        mean_delta = float(statistics.mean(deltas)) if deltas else 0.0
        delta_std = float(statistics.pstdev(deltas)) if len(deltas) > 1 else 0.0

        # LSB entropy over 8 low-order bits
        lsb_vals = [s & 0xFF for s in seqs]
        ent = 0.0
        if lsb_vals:
            cnt = collections.Counter(lsb_vals)
            total = len(lsb_vals)
            for c in cnt.values():
                p = c / total
                ent -= p * math.log2(p)

        results[host] = {
            "count": len(seqs),
            "seqs": seqs,
            "mean_delta": mean_delta,
            "delta_std": delta_std,
            "lsb_entropy": ent,
        }

    return results
