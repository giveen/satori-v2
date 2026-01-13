"""Convert ISN analysis into simple heuristics for OS fingerprinting.

This module consumes the output of `tcp_isn.analyze_isn_sequences` and
produces heuristic evidence items suitable for the extractor pipeline.
"""
from __future__ import annotations

from typing import Iterable, List, Dict, Any
from .tcp_isn import analyze_isn_sequences


def derive_isn_heuristics(flows: Iterable) -> List[Dict[str, Any]]:
    """Derive heuristic flags from ISN analysis.

    Heuristics (simple defaults):
    - low_lsb_entropy: True if LSB entropy < 2 bits (predictable low-order bits)
    - isn_incremental: True if delta_std < mean_delta * 0.5 (regular increment)
    """
    stats = analyze_isn_sequences(flows)
    evidence = []
    for host, info in stats.items():
        lsb_entropy = info.get("lsb_entropy", 0.0)
        mean_delta = info.get("mean_delta", 0.0)
        delta_std = info.get("delta_std", 0.0)

        low_lsb = lsb_entropy < 2.0
        incremental = False
        if mean_delta > 0:
            incremental = delta_std < (mean_delta * 0.5)

        evidence.append({
            "host_ip": host,
            "type": "tcp_isn_heuristic",
            "heuristics": {
                "low_lsb_entropy": low_lsb,
                "isn_incremental": incremental,
                "mean_delta": mean_delta,
                "delta_std": delta_std,
                "lsb_entropy": lsb_entropy,
                "count": info.get("count", 0),
            },
            "provenance": {"host": host},
            "score_hint": 0.5,
        })

    return evidence
