from typing import List, Dict, Any, Optional
import copy
import json
import hashlib

from .historical import aggregate_historical_hosts, _sha1_of_evidence


def _canonical_bytes(obj: Any) -> bytes:
    def _round(o):
        if isinstance(o, float):
            return round(o, 3)
        if isinstance(o, dict):
            return {k: _round(o[k]) for k in sorted(o.keys())}
        if isinstance(o, list):
            return [_round(x) for x in o]
        return o

    fixed = _round(obj)
    return json.dumps(fixed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha1_of_obj(obj: Any) -> str:
    return hashlib.sha1(_canonical_bytes(obj)).hexdigest()


def build_phase5_summary(captures: List[List[dict]], decay_params: Optional[Dict[str, Any]] = None, top_n: int = 3) -> Dict[str, Any]:
    """
    Builds a deterministic Phase 5 summary from captures (list of host lists).

    Returns a dict with per-host summaries and aggregate metrics suitable for snapshot regression.
    """
    # do not mutate input
    captures_copy = copy.deepcopy(captures)

    hist = aggregate_historical_hosts(captures_copy, decay_params=decay_params or {})

    per_host = []
    os_counter = {}
    hosts_with_conflicts = 0
    # accumulate scores per OS for avg confidence per OS
    scores_per_os = {}
    evidence_counts = []
    top_scores = []

    for h in sorted(hist, key=lambda x: x.get("host_id") or ""):
        host_id = h.get("host_id")
        candidates = h.get("historical_os_inference", [])
        # ensure candidate scores rounded and deterministic ordering
        cand_copy = []
        for c in candidates:
            cand_copy.append({"name": c["name"], "score": round(float(c.get("score", 0.0)), 3)})
        # candidates should already be sorted by score desc then name asc
        top_candidates = cand_copy[:top_n]
        highest = top_candidates[0]["name"] if top_candidates else None
        evidence_count = int(h.get("metrics_summary", {}).get("total_evidence", 0))
        confidence_avg = None
        if cand_copy:
            vals = [c.get("score", 0.0) for c in cand_copy]
            confidence_avg = round(sum(vals) / len(vals), 3)

        # accumulate per-OS score lists for aggregate metrics
        for c in cand_copy:
            scores_per_os.setdefault(c["name"], []).append(c["score"])
        evidence_counts.append(evidence_count)
        if cand_copy:
            top_scores.append(cand_copy[0]["score"])

        if h.get("conflict"):
            hosts_with_conflicts += 1

        if highest:
            os_counter[highest] = os_counter.get(highest, 0) + 1

        # SHA1 provenance block for regression
        prov_block = {
            "host_id": host_id,
            "provenance_refs": h.get("provenance_refs", []),
        }
        prov_sha = _sha1_of_obj(prov_block)

        per_host.append({
            "host_id": host_id,
            "top_candidates": top_candidates,
            "highest_score_os": highest,
            "evidence_count": evidence_count,
            "confidence_avg": confidence_avg,
            "conflict": h.get("conflict", False),
            "conflicting_candidates": sorted(h.get("conflicting_candidates", [])),
            "provenance_sha1": prov_sha,
        })

    # aggregate metrics
    num_hosts = len(per_host)
    num_with_hist = sum(1 for p in per_host if p.get("top_candidates"))

    # top OS distribution sorted deterministically
    top_os_distribution = sorted([{"os": k, "count": v} for k, v in os_counter.items()], key=lambda x: (-x["count"], x["os"]))

    # avg confidence per OS
    avg_confidence_per_os = {k: round(sum(v) / len(v), 3) for k, v in sorted(scores_per_os.items(), key=lambda x: x[0])}

    # evidence density summaries
    total_evidence = sum(evidence_counts) if evidence_counts else 0
    avg_evidence_per_host = round((total_evidence / num_hosts) if num_hosts else 0.0, 3)

    # decay-adjusted metrics: average top score across hosts
    avg_top_score = round((sum(top_scores) / len(top_scores)) if top_scores else 0.0, 3)

    summary = {
        "num_hosts": num_hosts,
        "num_hosts_with_historical_os_inference": num_with_hist,
        "top_os_distribution": top_os_distribution,
        "avg_confidence_per_os": avg_confidence_per_os,
        "evidence_density": {"total_evidence": total_evidence, "avg_evidence_per_host": avg_evidence_per_host},
        "decay_adjusted": {"avg_top_score": avg_top_score},
        "hosts_with_conflicts": hosts_with_conflicts,
    }

    return {"hosts": per_host, "metrics": summary}
