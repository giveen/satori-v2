"""Integration helpers to attach Phase 3 aggregated inference and correlation notes
to per-host outputs produced by the CLI pipeline.
"""
from __future__ import annotations

from typing import List, Dict, Any
from .aggregate import aggregate_hosts
from ..phase2.os_inference import build_os_inference


def _trait_set_from_host(host: Dict[str, Any]) -> set:
    # union of traits from all phase2 candidates
    oi = host.get('os_inference') or {}
    s = set()
    for c in oi.get('candidates', []):
        for t in c.get('traits_matched', []):
            s.add(t)
    return s


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union > 0 else 0.0


def integrate_phase3(hosts: List[Dict[str, Any]], trait_similarity_threshold: float = 0.5, nmap_db_path: str = None) -> List[Dict[str, Any]]:
    """Attach `os_inference` and `aggregated_os_inference` to each host and add correlation notes.

    Returns new list of host dicts (does not mutate inputs).
    """
    # ensure each host has Phase 2 os_inference
    enriched = []
    for h in hosts:
        hh = dict(h)
        if 'os_inference' not in hh:
            hh['os_inference'] = build_os_inference(hh, nmap_db_path=nmap_db_path)
        enriched.append(hh)

    # aggregate across hosts
    aggs = aggregate_hosts(enriched)

    # map aggregation_id to aggregated block
    # Also build trait sets per host for correlation
    trait_sets = { (h.get('host_id') or h.get('id')): _trait_set_from_host(h) for h in enriched }

    # attach aggregated_os_inference and correlation_notes
    out = []
    for h in enriched:
        hh = dict(h)
        aid = None
        # determine aggregation id same way as aggregate module
        # rely on aggregate to find matching group by regenerating groups: find which agg contains this host id
        hid = hh.get('host_id') or hh.get('id')
        agg_block = None
        for aid_k, block in aggs.items():
            if hid in (block.get('members') or []):
                agg_block = block
                aid = aid_k
                break

        hh['aggregated_os_inference'] = agg_block or None

        # correlation notes: compute trait similarity with other hosts deterministically
        notes = []
        my_traits = _trait_set_from_host(hh)
        for other in enriched:
            other_id = other.get('host_id') or other.get('id')
            if other_id == hid:
                continue
            j = _jaccard(my_traits, _trait_set_from_host(other))
            if j >= trait_similarity_threshold:
                notes.append({'other_host_id': other_id, 'trait_similarity': round(j, 3)})

        # deterministic sort of notes
        hh['correlation_notes'] = sorted(notes, key=lambda n: (-n['trait_similarity'], n['other_host_id']))

        out.append(hh)

    return out
