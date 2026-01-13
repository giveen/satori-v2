"""Deterministic correlation engine for Phase 4.

Provides `correlate_hosts_temporal(hosts, correlation_params)` which is
side-effect free and returns a new list of hosts with `correlated_os_inference`
and appended `correlation_notes`.
"""
from __future__ import annotations

from typing import Any, Dict, List
import copy
import math

from tests.utils_phase2 import sha1_of_obj


DEFAULT_PARAMS = {
    'trait_similarity_threshold': 0.5,
    'protocol_weights': {},
    'conflict_penalty': 0.2,
    'time_window_hours': 6.0,
    'alpha': 0.6,  # trait
    'beta': 0.3,   # evidence
    'gamma': 0.1,  # mac/temporal proximity
}


def _round3(f: float) -> float:
    return round(float(f or 0.0), 3)


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    inter = len(a & b)
    uni = len(a | b)
    return float(inter) / float(uni) if uni > 0 else 0.0


def _protocol_weight_for_host(host: Dict[str, Any], protocol_weights: Dict[str, float]) -> float:
    # collect protocols from aggregated_os_inference.metadata.protocols_seen or host['protocols_seen']
    prots = []
    agg = host.get('aggregated_os_inference') or {}
    meta = agg.get('metadata') or {}
    if meta.get('protocols_seen'):
        prots = list(meta.get('protocols_seen'))
    else:
        prots = list(host.get('protocols_seen') or [])
    if not prots:
        return 1.0
    weights = []
    for p in sorted(prots):
        weights.append(float(protocol_weights.get(p, 1.0)))
    return float(sum(weights) / len(weights)) if weights else 1.0


def correlate_hosts_temporal(hosts: List[Dict[str, Any]], correlation_params: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    params = dict(DEFAULT_PARAMS)
    if correlation_params:
        params.update(correlation_params)

    out = []
    # precompute trait sets and evidence sets per host
    host_index = {}
    for h in hosts:
        hid = h.get('host_id') or h.get('id') or ''
        # collect traits across temporal candidates
        tcs = (h.get('temporal_os_inference') or {}).get('temporal_candidates') or []
        trait_set = set()
        evidence_set = set()
        for tc in tcs:
            for t in tc.get('traits_matched') or []:
                trait_set.add(t)
            for eid in tc.get('evidence_refs') or []:
                evidence_set.add(eid)
        macs = set([m.lower() for m in (h.get('macs') or [])])
        host_index[hid] = {'host': h, 'traits': trait_set, 'evidence': evidence_set, 'macs': macs}

    # pairwise compute similarities
    ids = sorted(host_index.keys())
    sim_cache = {i: {} for i in ids}
    for i in ids:
        for j in ids:
            if i == j:
                continue
            a = host_index[i]
            b = host_index[j]
            trait_sim = _jaccard(a['traits'], b['traits'])
            evidence_j = _jaccard(a['evidence'], b['evidence'])
            mac_overlap = _jaccard(a['macs'], b['macs'])
            # combined similarity
            alpha = float(params.get('alpha', 0.6))
            beta = float(params.get('beta', 0.3))
            gamma = float(params.get('gamma', 0.1))
            sim = alpha * trait_sim + beta * evidence_j + gamma * mac_overlap
            sim_cache[i][j] = _round3(sim)

    # produce correlated outputs
    for hid in ids:
        h = host_index[hid]['host']
        host_copy = copy.deepcopy(h)
        tcs = (h.get('temporal_os_inference') or {}).get('temporal_candidates') or []

        # compute updated candidate scores by accumulating contributions from correlated peers
        contributions = {}
        for tc in tcs:
            name = tc.get('name')
            base_score = float(tc.get('temporal_score') or 0.0)
            contributions.setdefault(name, 0.0)
            # self-contribution
            proto_w = _protocol_weight_for_host(h, params.get('protocol_weights') or {})
            contributions[name] += base_score * proto_w

        # contributions from peers
        for peer_id, sim_map in sim_cache.items():
            if peer_id == hid:
                continue
            sim = sim_map.get(hid) if sim_map is not None else 0.0
            if sim is None:
                sim = 0.0
            # skip weak similarities
            if sim < float(params.get('trait_similarity_threshold', 0.5)):
                continue
            peer = host_index.get(peer_id)
            peer_tcs = (peer['host'].get('temporal_os_inference') or {}).get('temporal_candidates') or []
            peer_proto_w = _protocol_weight_for_host(peer['host'], params.get('protocol_weights') or {})
            for ptc in peer_tcs:
                pname = ptc.get('name')
                pscore = float(ptc.get('temporal_score') or 0.0)
                # weighted contribution from peer
                contributions.setdefault(pname, 0.0)
                contributions[pname] += pscore * sim * peer_proto_w

        # apply conflict penalty: if host has conflicts, reduce each contribution
        conflict_penalty = float(params.get('conflict_penalty', 0.2))
        has_conflict = any('conflicts' in tc for tc in tcs)
        if has_conflict and conflict_penalty > 0.0:
            for k in list(contributions.keys()):
                contributions[k] = contributions[k] * (1.0 - conflict_penalty)

        # normalize
        maxc = max(contributions.values()) if contributions else 0.0
        correlated_candidates = []
        for name in sorted(contributions.keys()):
            raw = contributions[name]
            score = _round3((raw / maxc) if maxc > 0.0 else raw)
            correlated_candidates.append({'name': name, 'score': score, 'raw_contribution': _round3(raw)})

        # sort deterministic: score desc, name asc
        correlated_candidates = sorted(correlated_candidates, key=lambda x: (-x['score'], x['name']))

        # build correlation_notes
        notes = []
        for peer in ids:
            if peer == hid:
                continue
            s = sim_cache.get(hid, {}).get(peer, 0.0)
            if s and s >= float(params.get('trait_similarity_threshold', 0.5)):
                shared_ev = sorted(list(host_index[hid]['evidence'] & host_index[peer]['evidence']))
                shared_traits = sorted(list(host_index[hid]['traits'] & host_index[peer]['traits']))
                notes.append({'other_host_id': peer, 'similarity': _round3(s), 'shared_traits': shared_traits, 'shared_evidence_refs': shared_ev})

        notes = sorted(notes, key=lambda n: (-n['similarity'], n['other_host_id']))

        host_copy['correlated_os_inference'] = {
            'correlated_inference_schema_version': 'phase4/correlated_os_inference/v1',
            'generated_by': 'phase4-corr-v0.1',
            'candidates': correlated_candidates,
        }
        host_copy['correlation_notes'] = notes
        out.append(host_copy)

    return out
