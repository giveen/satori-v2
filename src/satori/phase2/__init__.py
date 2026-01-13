"""Phase 2: OS inference helpers.

This package contains deterministic utilities and scaffolding for Phase 2.
"""

from .evidence import canonicalize_evidence, evidence_sha1
from .schema import build_os_inference_skeleton, SCHEMA_VERSION, SIGNATURE_TABLE_VERSION

__all__ = [
    "canonicalize_evidence",
    "evidence_sha1",
    "build_os_inference_skeleton",
    "SCHEMA_VERSION",
    "SIGNATURE_TABLE_VERSION",
]
