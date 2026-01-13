"""Phase 3 aggregation engine: deterministic aggregation of Phase 2 os_inference
across multiple captures and basic host-level correlation.

This module provides functions to group source hosts into aggregation ids and
produce aggregated_os_inference blocks while preserving provenance.
"""
from __future__ import annotations

from typing import Any, Dict, List, Iterable
import copy
import hashlib

from ..phase2.evidence import evidence_sha1
from ..phase2.os_inference import build_os_inference
from ..phase2.traits import extract_traits
from tests.utils_phase2 import sha1_of_obj


EPS = 1e-9
FLOAT_PREC = 3


def _round(f: float) -> float:
    return round(float(f or 0.0), FLOAT_PREC)


def _aggregation_id_for_host(host: Dict[str, Any]) -> str:
    # deterministic id from stable attributes
    mac = (host.get('mac') or host.get('mac_address') or '')
    if mac:
        norm = ''.join(c.lower() for c in mac if c.isalnum())
        return f'mac:{norm}'
    hid = host.get('host_id') or host.get('id') or ''
    if hid:
        return f'hostid:{hid}'
    # fallback: hash of evidence ids
    evs = host.get('evidence') or []
    ids = sorted([evidence_sha1(ev) for ev in evs if isinstance(ev, dict)])
    if ids:
        h = hashlib.sha1(''.join(ids).encode('utf-8')).hexdigest()
        return f'evidencehash:{h}'
    # last resort: deterministic hash of host json-ish fields
    s = str(sorted(list(host.keys())))
    return f'fallback:{hashlib.sha1(s.encode("utf-8")).hexdigest()}'


def _source_weight(host: Dict[str, Any]) -> float:
    # deterministic weight based on evidence_density (0..1)
    ed = float(host.get('evidence_density') or 0.0)
    return min(1.0, 0.5 + 0.5 * ed)


def aggregate_hosts(sources: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Aggregate Phase 2 `os_inference` across provided source host dicts.

    Returns mapping aggregation_id -> aggregated_os_inference block.
    """
    groups: Dict[str, List[Dict[str, Any]]] = {}
    # group hosts
    for h in sources:
        aid = _aggregation_id_for_host(h)
        groups.setdefault(aid, []).append(copy.deepcopy(h))

    aggs: Dict[str, Dict[str, Any]] = {}

    for aid in sorted(groups.keys()):
        members = groups[aid]
        # collect per-OS aggregated raw sums and evidence
        os_raw: Dict[str, float] = {}
        os_evidence: Dict[str, List[Dict[str, Any]]] = {}
        os_traits: Dict[str, set] = {}
        total_w = 0.0

        for m in sorted(members, key=lambda x: str(x.get('host_id') or x.get('id') or '')):
            # source-level os_inference may exist under 'os_inference' or produce one
            src_oi = m.get('os_inference') or build_os_inference(m)
            w = _source_weight(m)
            total_w += w
            for cand in sorted(src_oi.get('candidates', []), key=lambda c: c['name']):
                name = cand.get('name')
                contrib = float(cand.get('score') or 0.0) * w
                os_raw[name] = os_raw.get(name, 0.0) + contrib
                os_traits.setdefault(name, set()).update(cand.get('traits_matched') or [])
                # preserve evidence refs with provenance
                for ref in cand.get('evidence_refs') or []:
                    r = dict(ref)
                    r['source_host_id'] = m.get('host_id') or m.get('id')
                    r['capture_id'] = m.get('capture_id') or m.get('pcap_id')
                    # ensure contribution numeric placeholder updated below
                    os_evidence.setdefault(name, []).append(r)

        # normalize per OS
        ag_candidates: List[Dict[str, Any]] = []
        for name in sorted(os_raw.keys()):
            raw = os_raw[name]
            max_possible = total_w if total_w > 0 else 1.0
            normalized = raw / (max_possible + EPS)
            normalized = max(0.0, min(1.0, normalized))
            # assign contributions to evidence_refs proportionally
            refs = os_evidence.get(name, [])
            if refs:
                per_ref = raw / len(refs)
                for r in refs:
                    r['contribution'] = _round(per_ref)
            # build candidate
            cand = {
                'name': name,
                'score': _round(normalized),
                'traits_matched': sorted(os_traits.get(name, [])),
                'evidence_refs': sorted(refs, key=lambda r: (-r.get('contribution', 0.0), r.get('evidence_id'))),
                'sources': [],
                'conflicts': [],
            }
            ag_candidates.append(cand)

        # sort candidates by required deterministic ordering
        ag_candidates = sorted(ag_candidates, key=lambda c: (-c['score'], -len(c['evidence_refs']), c['name']))

        # metadata aggregation
        protocols = sorted({p for m in members for p in (m.get('protocols_seen') or [])})
        protocol_count = int(sum(len(m.get('protocols_seen') or []) for m in members))
        evidence_count = sum(len(m.get('evidence') or []) for m in members)

        ambiguity = {
            'likely_shared_device': False,
            'multi_host_conflict': False,
        }

        aggregated = {
            'aggregation_id': aid,
            'aggregated_os_inference_schema_version': 'phase3/os_inference/v1',
            'generated_by': 'phase3-v0.1',
            'candidates': ag_candidates,
            'metadata': {
                'protocols_seen': protocols,
                'protocol_count': protocol_count,
                'evidence_count': evidence_count,
            },
            'ambiguity_flags': ambiguity,
            'members': [m.get('host_id') or m.get('id') for m in members],
        }

        aggs[aid] = aggregated

    return aggs
