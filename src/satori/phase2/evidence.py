"""Deterministic evidence canonicalization and hashing utilities.

These functions operate only on Phase 1 normalized evidence dictionaries
and produce reproducible, canonical JSON and SHA1 IDs for provenance.
"""
from __future__ import annotations

import json
import hashlib
from typing import Any


def _canonical(obj: Any) -> Any:
    """Return an object suitable for canonical JSON serialization.

    - dicts are emitted with sorted keys
    - lists are preserved (order matters for evidence lists)
    - primitive types passed through
    """
    if isinstance(obj, dict):
        return {k: _canonical(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [_canonical(v) for v in obj]
    # bytes should not appear in Phase 1 evidence; if they do, hex-encode
    if isinstance(obj, (bytes, bytearray)):
        return obj.hex()
    return obj


def canonicalize_evidence(ev: dict) -> str:
    """Return a canonical JSON string for `ev` with stable key ordering.

    Uses compact separators to ensure stable byte representation.
    """
    can = _canonical(ev)
    return json.dumps(can, separators=(",", ":"), ensure_ascii=False)


def evidence_sha1(ev: dict) -> str:
    """Return a deterministic SHA1 hex string for the given evidence dict."""
    cj = canonicalize_evidence(ev)
    h = hashlib.sha1()
    h.update(cj.encode("utf-8"))
    return h.hexdigest()
