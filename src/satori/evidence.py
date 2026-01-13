from __future__ import annotations

import typing as t
import dataclasses


def _sanitize_value(v):
    # Convert bytes to hex, dataclasses to dicts, and ensure JSON-safe primitives
    if v is None:
        return None
    if isinstance(v, bytes):
        return v.hex()
    if dataclasses.is_dataclass(v):
        return dataclasses.asdict(v)
    if isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, (list, tuple)):
        out = []
        for e in v:
            out.append(_sanitize_value(e))
        return out
    if isinstance(v, dict):
        # sort keys for determinism
        return {k: _sanitize_value(v[k]) for k in sorted(v.keys())}
    # fallback to string
    try:
        return str(v)
    except Exception:
        return None


def make_evidence(
    source: str,
    protocol: str,
    attribute: str,
    value,
    confidence_hint: float = 0.5,
    host_id: t.Optional[str] = None,
    flow_id: t.Optional[str] = None,
    timestamp: t.Optional[float] = None,
    provenance: t.Optional[dict] = None,
):
    """Create a normalized evidence dict.

    Fields:
      - schema_version: versioned schema id
      - source: extractor name (e.g., "ssh", "tcp")
      - protocol: transport/protocol (e.g., "tcp", "udp")
      - attribute: canonical attribute name (e.g., "tcp.mss")
      - value: JSON-safe sanitized value
      - confidence_hint: float 0.0-1.0
      - host_id, flow_id, timestamp
      - provenance: arbitrary provenance details (pkt indexes, offsets)
    """
    return {
        "schema_version": "evidence/v1",
        "source": source,
        "protocol": protocol,
        "attribute": attribute,
        "value": _sanitize_value(value),
        "confidence_hint": float(confidence_hint) if confidence_hint is not None else None,
        "host_id": host_id,
        "flow_id": flow_id,
        "timestamp": timestamp,
        "provenance": _sanitize_value(provenance) if provenance is not None else None,
    }
