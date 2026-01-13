"""Deterministic temporal aggregation for Phase 4.

Provides `aggregate_temporal_os(hosts, decay_params)` that returns a new list
of host dicts with an added `temporal_os_inference` block. Does not mutate
inputs. Designed for deterministic, explainable outputs suitable for
snapshot testing.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
import copy
import math
import time
from datetime import datetime, timezone

from ..phase2.evidence import evidence_sha1
from tests.utils_phase2 import canonical_json_bytes


DEFAULT_PARAMS = {
    'half_life_hours': 72.0,
    'reference_time': None,  # epoch seconds; if None, use host.last_seen or now
    'corr_weight': 0.0,
    'conflict_threshold': 0.4,
    'primary_margin': 0.15,
}


def _parse_time(ts: Any) -> Optional[float]:
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str):
        # accept ISO8601; handle trailing Z
        s = ts
        if s.endswith('Z'):
            s = s[:-1] + '+00:00'
        try:
            dt = datetime.fromisoformat(s)
            return dt.timestamp()
        except Exception:
            return None
    return None


def decay_factor(timestamp: Optional[float], reference_ts: float, half_life_hours: float) -> float:
    if timestamp is None:
        return 1.0
    # delta in hours
    delta_h = max(0.0, (reference_ts - float(timestamp)) / 3600.0)
    if half_life_hours <= 0:
        return 1.0
    # exponential decay: exp(-ln(2) * delta / half_life)
    return math.exp(-math.log(2.0) * (delta_h / float(half_life_hours)))


def _evidence_ts_for_id(host: Dict[str, Any], evidence_id: str) -> Optional[float]:
    # attempt to locate evidence dict in host['evidence'] by matching canonical SHA1 or id fields
    for ev in host.get('evidence', []) or []:
        # if evidence has explicit id field
        if isinstance(ev, dict) and ev.get('evidence_id') == evidence_id:
            # check timestamp fields
            for k in ('ts', 'timestamp', 'first_seen', 'last_seen'):
                if k in ev:
                    t = _parse_time(ev.get(k))
                    if t is not None:
                        return t
            return None
        # compute sha1 of ev if possible and compare
        if isinstance(ev, dict):
            try:
                sid = evidence_sha1(ev)
            except Exception:
                sid = None
            if sid == evidence_id:
                for k in ('ts', 'timestamp', 'first_seen', 'last_seen'):
                    if k in ev:
                        t = _parse_time(ev.get(k))
                        if t is not None:
                            return t
                return None
    return None


def _round3(f: float) -> float:
    return round(float(f or 0.0), 3)


def aggregate_temporal_os(hosts: List[Dict[str, Any]], decay_params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    params = dict(DEFAULT_PARAMS)
    if decay_params:
        params.update(decay_params)

    out_hosts: List[Dict[str, Any]] = []
    for h in sorted((hosts or []), key=lambda x: x.get('host_id') or x.get('id') or ''):
        host = copy.deepcopy(h)
        # determine reference time
        ref = params.get('reference_time')
        if ref is None:
            ref = host.get('last_seen') or host.get('first_seen') or time.time()
        ref = float(ref)

        # find candidates: prefer aggregated_os_inference then os_inference
        agg = host.get('aggregated_os_inference') or {}
        candidates = agg.get('candidates') or host.get('os_inference', {}).get('candidates', []) or []

        temporal_candidates = []
        raw_scores = []

        # compute raw temporally-weighted scores
        for c in candidates:
            base = float(c.get('score') or 0.0)
            # gather evidence ids
            ev_refs = []
            for r in c.get('evidence_refs') or []:
                if isinstance(r, dict):
                    eid = r.get('evidence_id') or r.get('evidence_id')
                else:
                    eid = r
                if eid:
                    ev_refs.append(str(eid))

            if ev_refs:
                decays = []
                for eid in sorted(ev_refs):
                    ts = _evidence_ts_for_id(host, eid)
                    d = decay_factor(ts, ref, float(params.get('half_life_hours')))
                    decays.append(d)
                # evidence multiplier: mean decay
                evidence_multiplier = sum(decays) / len(decays)
            else:
                evidence_multiplier = 1.0

            # correlation boost from correlation_notes
            corr_boost = 1.0
            notes = host.get('correlation_notes') or []
            if notes and params.get('corr_weight', 0.0) > 0.0:
                # use max trait_similarity if present
                max_sim = 0.0
                for n in notes:
                    try:
                        s = float(n.get('trait_similarity') or 0.0)
                    except Exception:
                        s = 0.0
                    if s > max_sim:
                        max_sim = s
                corr_boost = 1.0 + float(params.get('corr_weight')) * max_sim

            raw = base * evidence_multiplier * corr_boost

            temporal_candidates.append({
                'name': c.get('name'),
                'temporal_score_raw': raw,
                'evidence_refs': sorted(ev_refs),
                'traits_matched': sorted(c.get('traits_matched') or []),
                'decay_factor': _round3(evidence_multiplier),
                'explanation': f"base={_round3(base)},evidence_mult={_round3(evidence_multiplier)},corr_boost={_round3(corr_boost)}",
            })
            raw_scores.append(raw)

        # normalize raw scores into [0,1]
        max_raw = max(raw_scores) if raw_scores else 0.0
        if max_raw > 0.0:
            for tc in temporal_candidates:
                tc['temporal_score'] = _round3(tc.pop('temporal_score_raw') / max_raw)
        else:
            for tc in temporal_candidates:
                tc['temporal_score'] = _round3(tc.pop('temporal_score_raw'))

        # detect conflicts: candidates above threshold with low evidence overlap
        conflicts = []
        thresh = float(params.get('conflict_threshold') or 0.4)
        primary_margin = float(params.get('primary_margin') or 0.15)
        # sort for deterministic tie handling
        temporal_candidates = sorted(temporal_candidates, key=lambda x: (-x['temporal_score'], x['name']))

        # build evidence sets mapping
        ev_sets = [set(tc.get('evidence_refs') or []) for tc in temporal_candidates]
        for i, tc in enumerate(temporal_candidates):
            # check rivals
            rivals = []
            for j, other in enumerate(temporal_candidates):
                if i == j:
                    continue
                if other['temporal_score'] >= thresh:
                    # compute overlap
                    s1 = ev_sets[i]
                    s2 = ev_sets[j]
                    overlap = 0.0
                    if s1 or s2:
                        overlap = float(len(s1 & s2)) / float(len(s1 | s2)) if (len(s1 | s2) > 0) else 0.0
                    # if scores within margin and low overlap, mark conflict
                    if abs(tc['temporal_score'] - other['temporal_score']) <= primary_margin and overlap < 0.25:
                        rivals.append({'name': other['name'], 'shared_evidence_overlap': _round3(overlap), 'evidence_refs': sorted(list(s2))})
            if rivals:
                tc['conflicts'] = sorted(rivals, key=lambda r: ( -r['shared_evidence_overlap'], r['name']))

        metadata = {
            'temporal_coverage': {'first_seen': host.get('first_seen'), 'last_seen': host.get('last_seen')},
            'contributing_events': sum(len(tc.get('evidence_refs') or []) for tc in temporal_candidates),
            'ambiguity_flags': agg.get('ambiguity_flags') or host.get('ambiguity') or {},
        }

        host['temporal_os_inference'] = {
            'temporal_inference_schema_version': 'temporal_os_inference/v1',
            'generated_by': 'phase4-t1-v0.1',
            'temporal_candidates': temporal_candidates,
            'metadata': metadata,
        }

        out_hosts.append(host)

    return out_hosts
