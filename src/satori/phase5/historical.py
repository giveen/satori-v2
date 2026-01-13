from typing import List, Dict, Any
from collections import defaultdict
import copy
import json
import hashlib
import math
from datetime import datetime


def _parse_ts(ts):
    if not ts:
        return None
    if isinstance(ts, (int, float)):
        # assume epoch seconds
        return datetime.utcfromtimestamp(float(ts))
    try:
        # expect format like 2025-01-01T00:00:00Z
        if ts.endswith("Z"):
            return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def _decay_factor(delta_hours: float, half_life_hours: float) -> float:
    if half_life_hours is None or half_life_hours <= 0:
        return 1.0
    return math.exp(-math.log(2) * (delta_hours / half_life_hours))


def _sha1_of_evidence(ev: Dict[str, Any]) -> str:
    def _round(o):
        if isinstance(o, float):
            return round(o, 3)
        if isinstance(o, dict):
            return {k: _round(o[k]) for k in sorted(o.keys())}
        if isinstance(o, list):
            return [_round(x) for x in o]
        return o

    fixed = _round(ev)
    b = json.dumps(fixed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha1(b).hexdigest()


def _round_floats(o, ndigits=3):
    if isinstance(o, float):
        return round(o, ndigits)
    if isinstance(o, dict):
        return {k: _round_floats(o[k], ndigits) for k in o}
    if isinstance(o, list):
        return [_round_floats(x, ndigits) for x in o]
    return o


def aggregate_historical_hosts(hosts_list: List[List[dict]], decay_params: Dict[str, Any] = None) -> List[dict]:
    """
    hosts_list: List of captures; each capture is a list of host dicts
    decay_params: dict like {"half_life_hours": 168}

    Returns: list of aggregated per-host dicts
    """
    decay_params = decay_params or {}
    half_life = decay_params.get("half_life_hours")

    # flatten captures if user provided flat list
    flattened = []
    for entry in hosts_list:
        if isinstance(entry, list):
            flattened.extend(entry)
        elif isinstance(entry, dict):
            flattened.append(entry)

    # work on deep copies to guarantee immutability
    items = [copy.deepcopy(h) for h in flattened]

    # group by host_id initial
    groups = defaultdict(list)
    for h in items:
        hid = h.get("host_id")
        if not hid:
            macs = tuple(sorted(h.get("macs", [])))
            hid = f"host-macs:{','.join(macs)}"
            h["host_id"] = hid
        groups[hid].append(h)

    # deterministic merge by MAC overlaps
    mac_map = {}
    for hid in sorted(list(groups.keys())):
        members = groups.get(hid, [])
        macs = set()
        for m in members:
            macs.update(m.get("macs", []))
        for mac in sorted(macs):
            if mac not in mac_map:
                mac_map[mac] = hid
            else:
                other = mac_map[mac]
                if other == hid:
                    continue
                canonical = min(other, hid)
                non_canonical = max(other, hid)
                if canonical != non_canonical:
                    groups[canonical].extend(groups.pop(non_canonical, []))

    out = []

    for hid in sorted(groups.keys()):
        members = groups[hid]
        # find most recent timestamp for decay baseline
        ts_list = [_parse_ts(m.get("capture_timestamp") or m.get("timestamp") or m.get("seen_ts")) for m in members]
        ts_list = [t for t in ts_list if t is not None]
        if ts_list:
            latest = max(ts_list)
        else:
            latest = None

        # accumulate candidates
        candidates = {}
        provenance_hashes = set()
        metrics_acc = {"count": 0, "evidence_count": 0}

        # collect top candidates per capture to detect conflicts
        top_candidates_seen = []

        for m in members:
            ts = _parse_ts(m.get("capture_timestamp") or m.get("timestamp") or m.get("seen_ts"))
            delta_hours = 0.0
            if latest and ts:
                delta = latest - ts
                delta_hours = delta.total_seconds() / 3600.0
            decay = _decay_factor(delta_hours, half_life) if half_life else 1.0

            # metrics summarization
            metrics = m.get("temporal_metrics") or m.get("phase4_metrics") or {}
            if metrics:
                metrics_acc["count"] += 1
                # evidence density if present
                metrics_acc["evidence_count"] += len(m.get("evidence", []))

            # candidates
            oi = m.get("os_inference") or {}
            cand_list = oi.get("candidates", [])
            if cand_list:
                top_candidates_seen.append(cand_list[0].get("name"))
            for c in cand_list:
                name = c.get("name")
                score = float(c.get("score", 0.0)) * decay
                traits = c.get("traits") or {}

                if name not in candidates:
                    candidates[name] = {"score_sum": 0.0, "evidence_refs": set(), "traits": {}, "occurrences": 0}
                candidates[name]["score_sum"] += score
                candidates[name]["occurrences"] += 1
                # collect traits shallow merge deterministically
                for tk in sorted(traits.keys()):
                    if tk not in candidates[name]["traits"]:
                        candidates[name]["traits"][tk] = traits[tk]

            # evidence provenance
            for ev in m.get("evidence", []):
                sha = _sha1_of_evidence(ev)
                provenance_hashes.add(sha)

        # build candidate list sorted
        cand_out = []
        for name, info in candidates.items():
            cand_out.append({
                "name": name,
                "score": round(info["score_sum"], 3),
                "occurrences": info.get("occurrences", 0),
                "traits": _round_floats(info["traits"]),
                "evidence_refs": sorted(list(info["evidence_refs"])),
            })

        # determine conflicts: multiple distinct top candidates seen across captures
        conflict = False
        conflicting_candidates = []
        distinct_tops = sorted(set([t for t in top_candidates_seen if t]))
        if len(distinct_tops) > 1:
            conflict = True
            conflicting_candidates = distinct_tops

        # sort candidates by score desc then name asc
        cand_out.sort(key=lambda x: (-x["score"], x["name"]))

        metrics_summary = {
            "captures": metrics_acc["count"],
            "total_evidence": metrics_acc["evidence_count"],
        }

        aggregated = {
            "host_id": hid,
            "historical_os_inference": cand_out,
            "metrics_summary": metrics_summary,
            "provenance_refs": sorted(list(provenance_hashes)),
            "conflict": conflict,
            "conflicting_candidates": conflicting_candidates,
        }

        out.append(aggregated)

    return out
