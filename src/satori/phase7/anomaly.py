from __future__ import annotations

import copy
import hashlib
import json
from typing import List, Dict, Any, Tuple

def _round_floats(obj):
    if isinstance(obj, float):
        return round(obj, 3)
    if isinstance(obj, dict):
        return {k: _round_floats(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_round_floats(v) for v in obj]
    return obj


def _canonical_bytes(obj: Any) -> bytes:
    fixed = _round_floats(obj)
    return json.dumps(fixed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha1_bytes(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()


def _safe_host_copy(host: Dict[str, Any]) -> Dict[str, Any]:
    return copy.deepcopy(host)


def detect_anomalies(hosts: List[Dict[str, Any]], config: Dict[str, Any] | None = None) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Analyze Phase2-6 enriched host dicts and return (per_host_reports, aggregated_metrics).

    Simple rule-based anomaly detector with deterministic outputs suitable for
    regression snapshotting. Does not mutate input hosts.
    """
    cfg = config or {}
    reports: List[Dict[str, Any]] = []

    # parameters
    flow_threshold = float(cfg.get("flow_threshold", 10))
    nat_score = float(cfg.get("nat_score", 0.7))
    conflict_score = float(cfg.get("conflict_score", 0.9))
    suspicious_score = float(cfg.get("suspicious_score", 0.6))

    # collect aggregated metrics counters
    metrics = {"num_hosts_with_anomalies": 0, "anomaly_counts": {}, "avg_score_by_type": {}}
    sums_by_type: Dict[str, float] = {}

    # Build quick map of aggregation groups if present
    agg_map: Dict[str, List[str]] = {}
    for h in hosts:
        ag = h.get("aggregated_os_inference")
        if isinstance(ag, dict):
            aid = ag.get("aggregation_id")
            if aid:
                agg_map.setdefault(aid, []).append(h.get("host_id"))

    for host in hosts:
        h = _safe_host_copy(host)
        hid = h.get("host_id")
        anomalies: List[Dict[str, Any]] = []

        # 1) OS conflict: host-level os_inference vs aggregated top candidate
        top_host = None
        try:
            hcands = h.get("os_inference", {}).get("candidates") or []
            if hcands:
                top_host = hcands[0].get("name")
        except Exception:
            top_host = None

        top_agg = None
        try:
            acands = h.get("aggregated_os_inference", {}).get("candidates") or []
            if acands:
                top_agg = acands[0].get("name")
        except Exception:
            top_agg = None

        if top_host and top_agg and top_host != top_agg:
            evs = []
            for ev in h.get("evidence", []):
                # evidence provenance id best-effort
                pid = ev.get("provenance") or {}
                evs.append(str(pid))
            evs = sorted(set(evs))
            anomalies.append({
                "type": "os_conflict",
                "score": round(conflict_score, 3),
                "contributing_evidence": evs,
                "description": f"Host-level OS '{top_host}' conflicts with aggregated OS '{top_agg}'.",
            })

        # 2) NAT/shared IP suspicion based on ambiguity flags
        amb = h.get("ambiguity") or {}
        if amb.get("nat_suspected") or amb.get("shared_ip"):
            evs = sorted({str(ev.get("provenance") or {}) for ev in h.get("evidence", [])})
            anomalies.append({
                "type": "baseline_deviation",
                "score": round(nat_score, 3),
                "contributing_evidence": evs,
                "description": "Host shows ambiguity indicators (nat_suspected/shared_ip).",
            })

        # 3) Suspicious traffic: high number of flows
        flows = h.get("flows") or []
        if isinstance(flows, (list, set)) and len(flows) > flow_threshold:
            evs = sorted({str(ev.get("provenance") or {}) for ev in h.get("evidence", [])})
            anomalies.append({
                "type": "suspicious_traffic",
                "score": round(suspicious_score, 3),
                "contributing_evidence": evs,
                "description": f"Host has high flow count ({len(flows)} > {flow_threshold}).",
            })

        # 4) Cross-host correlation: if host is in an aggregation with >1 host and
        #    the aggregation members have differing top OS candidates, report correlation note
        corr_notes = None
        a = h.get("aggregated_os_inference")
        if a and isinstance(a, dict):
            members = a.get("members") or []
            if len(members) > 1:
                # gather top candidates for each member from input hosts
                tops = {}
                for m in members:
                    for hh in hosts:
                        if hh.get("host_id") == m:
                            try:
                                mcands = hh.get("os_inference", {}).get("candidates") or []
                                tops[m] = mcands[0].get("name") if mcands else None
                            except Exception:
                                tops[m] = None
                uniq = sorted({v for v in tops.values() if v is not None})
                if len(uniq) > 1:
                    corr_notes = {"aggregation_id": a.get("aggregation_id"), "conflicting_members": tops}

        overall = 0.0
        if anomalies:
            metrics["num_hosts_with_anomalies"] += 1
            for an in anomalies:
                t = an.get("type")
                s = float(an.get("score") or 0.0)
                metrics["anomaly_counts"][t] = metrics["anomaly_counts"].get(t, 0) + 1
                sums_by_type[t] = sums_by_type.get(t, 0.0) + s
                overall = max(overall, s)

        report = {
            "host_id": hid,
            "anomalies": sorted(anomalies, key=lambda x: x.get("type")),
            "overall_score": round(overall, 3),
        }
        if corr_notes:
            report["correlation_notes"] = corr_notes

        reports.append(report)

    # finalize avg scores
    for t, sm in sums_by_type.items():
        cnt = metrics["anomaly_counts"].get(t, 1)
        metrics["avg_score_by_type"][t] = round(sm / float(cnt), 3)

    # deterministic ordering of reports by host_id
    reports = sorted(reports, key=lambda x: x.get("host_id") or "")

    return reports, metrics
