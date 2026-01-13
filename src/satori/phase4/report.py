"""Phase 4 summary reporting: build deterministic per-host and aggregate summaries
from Phase 4 correlated outputs.
"""
from __future__ import annotations

from typing import Any, Dict, List
import copy


FLOAT_PREC = 3


def _round(f: float) -> float:
    return round(float(f or 0.0), FLOAT_PREC)


def _top_n(candidates: List[Dict[str, Any]], n: int = 3) -> List[Dict[str, Any]]:
    out = []
    for c in sorted(candidates, key=lambda x: (-float(x.get('score') or 0.0), x.get('name'))):
        out.append({'name': c.get('name'), 'score': _round(c.get('score') or 0.0)})
        if len(out) >= n:
            break
    return out


def build_phase4_summary(hosts: List[Dict[str, Any]], top_n: int = 3) -> Dict[str, Any]:
    hs = [copy.deepcopy(h) for h in (hosts or [])]

    per_host = []
    top_os_counts: Dict[str, int] = {}
    sum_scores: Dict[str, float] = {}
    count_scores: Dict[str, int] = {}
    hosts_with_phase4 = 0
    hosts_conflicts = 0
    # evidence density per host and decay summaries
    evidence_counts_per_host: List[int] = []
    decay_means_per_host: List[float] = []

    for h in sorted(hs, key=lambda x: x.get('host_id') or x.get('id') or ''):
        hid = h.get('host_id') or h.get('id') or ''
        corr = h.get('correlated_os_inference') or {}
        candidates = corr.get('candidates') or []

        if candidates:
            hosts_with_phase4 += 1

        top_candidates = []
        if candidates:
            # enrich top candidates with evidence_count and confidence_avg
            for c in sorted(candidates, key=lambda x: (-float(x.get('score') or 0.0), x.get('name')))[:top_n]:
                evs = sorted(c.get('evidence_refs') or [])
                evidence_count = len(evs)
                raw = float(c.get('raw_contribution') or 0.0)
                confidence_avg = (raw / evidence_count) if evidence_count > 0 else float(c.get('score') or 0.0)
                top_candidates.append({'name': c.get('name'), 'score': _round(float(c.get('score') or 0.0)), 'evidence_count': evidence_count, 'confidence_avg': _round(confidence_avg)})

        highest = None
        if candidates:
            highest = sorted(candidates, key=lambda x: (-float(x.get('score') or 0.0), x.get('name')))[0].get('name')
            top_os_counts[highest] = top_os_counts.get(highest, 0) + 1

        for c in candidates:
            name = c.get('name')
            s = float(c.get('score') or 0.0)
            sum_scores[name] = sum_scores.get(name, 0.0) + s
            count_scores[name] = count_scores.get(name, 0) + 1

        if any('conflicts' in c for c in candidates):
            hosts_conflicts += 1

        # evidence count and decay mean from temporal_os_inference if present
        temporal = h.get('temporal_os_inference') or {}
        tcs = temporal.get('temporal_candidates') or []
        ev_count = 0
        decay_vals = []
        for tc in tcs:
            ev_count += len(tc.get('evidence_refs') or [])
            try:
                decay_vals.append(float(tc.get('decay_factor') or 1.0))
            except Exception:
                decay_vals.append(1.0)
        evidence_counts_per_host.append(int(ev_count))
        if decay_vals:
            decay_means_per_host.append(sum(decay_vals) / len(decay_vals))
        else:
            decay_means_per_host.append(1.0)

        notes = sorted(h.get('correlation_notes') or [], key=lambda n: (-float(n.get('similarity') or 0.0), n.get('other_host_id')))

        per_host.append({
            'host_id': hid,
            'top_os_candidates': top_candidates,
            'highest_score_os': highest,
            'correlation_notes': notes,
        })

    avg_confidence_per_os = {name: _round((sum_scores[name] / count_scores[name]) if count_scores.get(name) else 0.0) for name in sorted(sum_scores.keys())}
    summary = {
        'hosts': per_host,
        'metrics': {
            'num_hosts': len(hs),
            'num_hosts_with_phase4_inference': hosts_with_phase4,
            'top_os_distribution': {k: top_os_counts[k] for k in sorted(top_os_counts.keys())},
            'avg_confidence_per_os': avg_confidence_per_os,
            'hosts_with_conflicting_evidence': hosts_conflicts,
            'evidence_density': {
                'mean_per_host': _round(sum(evidence_counts_per_host) / len(evidence_counts_per_host)) if evidence_counts_per_host else 0,
                'max_per_host': int(max(evidence_counts_per_host)) if evidence_counts_per_host else 0,
            },
            'decay_summary': {
                'mean_decay_per_host': _round(sum(decay_means_per_host) / len(decay_means_per_host)) if decay_means_per_host else 1.0,
                'max_decay_per_host': _round(max(decay_means_per_host)) if decay_means_per_host else 1.0,
            },
        }
    }

    return summary
