"""Reporting utilities for Phase 3 aggregated OS inference summaries.

Produce deterministic, compact JSON summaries for CI inspection.
"""
from __future__ import annotations

from typing import Any, Dict, List
import copy

"""Lightweight report builder; intentionally avoids importing test helpers."""


FLOAT_PREC = 3


def _round(f: float) -> float:
    return round(float(f or 0.0), FLOAT_PREC)


def _top_n_candidates(agg_block: Dict[str, Any], n: int = 3) -> List[Dict[str, Any]]:
    out = []
    for c in sorted(agg_block.get('candidates', []), key=lambda x: (-float(x.get('score') or 0.0), x.get('name'))):
        out.append({'name': c.get('name'), 'score': _round(c.get('score') or 0.0)})
        if len(out) >= n:
            break
    return out


def build_phase3_summary(hosts: List[Dict[str, Any]], top_n: int = 3) -> Dict[str, Any]:
    """Build a deterministic summary for a list of Phase 3-enriched host dicts.

    The function does not mutate input hosts.
    """
    hs = [copy.deepcopy(h) for h in hosts]

    per_host = []
    top_os_counts: Dict[str, int] = {}
    sum_scores: Dict[str, float] = {}
    count_scores: Dict[str, int] = {}
    hosts_with_os = 0
    hosts_conflicts = 0

    for h in sorted(hs, key=lambda x: x.get('host_id') or x.get('id') or ''):
        hid = h.get('host_id') or h.get('id') or ''
        agg = h.get('aggregated_os_inference') or {}

        if agg:
            hosts_with_os += 1

        candidates = agg.get('candidates') or []
        # top N
        top_candidates = _top_n_candidates(agg, n=top_n) if agg else []

        highest = ''
        if candidates:
            highest = sorted(candidates, key=lambda x: (-float(x.get('score') or 0.0), x.get('name')))[0].get('name')
            # update distribution
            top_os_counts[highest] = top_os_counts.get(highest, 0) + 1

        # accumulate avg per OS (for all candidates present in this host)
        for c in candidates:
            name = c.get('name')
            s = float(c.get('score') or 0.0)
            sum_scores[name] = sum_scores.get(name, 0.0) + s
            count_scores[name] = count_scores.get(name, 0) + 1

        # conflicts
        conflict_present = any((c.get('conflicts') for c in candidates))
        if conflict_present:
            hosts_conflicts += 1

        notes = sorted(h.get('correlation_notes') or [], key=lambda n: (-float(n.get('trait_similarity') or 0.0), n.get('other_host_id')))

        per_host.append({
            'host_id': hid,
            'top_candidates': top_candidates,
            'highest_score_os': highest or None,
            'correlation_notes': notes,
        })

    avg_confidence_per_os = {name: _round((sum_scores[name] / count_scores[name]) if count_scores.get(name) else 0.0) for name in sorted(sum_scores.keys())}

    summary = {
        'hosts': per_host,
        'metrics': {
            'num_hosts': len(hs),
            'num_hosts_with_os_inference': hosts_with_os,
            'top_os_distribution': {k: top_os_counts[k] for k in sorted(top_os_counts.keys())},
            'avg_confidence_per_os': avg_confidence_per_os,
            'hosts_with_conflicting_evidence': hosts_conflicts,
        }
    }

    return summary
