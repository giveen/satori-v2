"""Helper utilities for Phase2 tests: canonical serialization and hashing.

Assumptions documented here:
- Input objects may contain floats that need consistent rounding for deterministic
  snapshot hashing; we round all floats to 3 decimals.
- Lists that must be sorted according to spec are expected to already be sorted by
  the production code; helpers do not reorder semantic lists beyond ensuring
  deterministic JSON key ordering.
"""
from typing import Any
import json
import hashlib


_FLOAT_PREC = 3


def _round_floats(obj: Any) -> Any:
    """Recursively round floats to fixed precision and return a new object."""
    if isinstance(obj, float):
        return round(obj, _FLOAT_PREC)
    if isinstance(obj, dict):
        return {k: _round_floats(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_round_floats(v) for v in obj]
    return obj


def canonical_json_bytes(obj: Any) -> bytes:
    """Return canonical JSON bytes for stable hashing/storage.

    Uses sorted keys and compact separators. Prior to dumping, round floats
    recursively to ensure stable numeric representation.
    """
    rounded = _round_floats(obj)
    return json.dumps(rounded, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode("utf-8")


def sha1_of_obj(obj: Any) -> str:
    b = canonical_json_bytes(obj)
    return hashlib.sha1(b).hexdigest()
