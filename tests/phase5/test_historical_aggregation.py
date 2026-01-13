import copy
import hashlib
import json

from src.satori.phase5.historical import aggregate_historical_hosts, _sha1_of_evidence


def canonical_json_bytes(obj):
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


def sha1_of_obj(obj):
    return hashlib.sha1(canonical_json_bytes(obj)).hexdigest()


def test_historical_aggregation_deterministic_and_immutable():
    # capture1 contains host-1
    host_a_cap1 = {
        "host_id": "host-1",
        "macs": ["aa:aa:aa:aa:aa:aa"],
        "evidence": [{"evidence_id": "e1", "attr": 1.23456}],
        "os_inference": {"candidates": [{"name": "Linux", "score": 0.91234}]},
        "temporal_metrics": {"uptime": 12.3456},
        "capture_timestamp": "2025-01-01T00:00:00Z",
        "source": "cap1",
    }

    # capture2 contains host-1 and host-B
    host_a_cap2 = {
        "host_id": "host-1",
        "macs": ["aa:aa:aa:aa:aa:aa"],
        "evidence": [{"evidence_id": "e1", "attr": 1.23456}, {"evidence_id": "e2", "attr": 2.71828}],
        "os_inference": {"candidates": [{"name": "Linux", "score": 0.83}]},
        "phase4_metrics": {"confidence": 0.75},
        "capture_timestamp": "2025-01-02T00:00:00Z",
        "source": "cap2",
    }

    # different host_id but shares MAC with host-1; should be merged
    host_b = {
        "host_id": "host-B",
        "macs": ["aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"],
        "evidence": [{"evidence_id": "e3", "attr": 9.999}],
        "os_inference": {"candidates": [{"name": "Windows", "score": 0.65}]},
        "capture_timestamp": "2025-01-03T00:00:00Z",
        "source": "cap3",
    }

    # build captures as lists
    captures = [[host_a_cap1], [host_a_cap2, host_b]]
    orig_copy = copy.deepcopy(captures)

    agg1 = aggregate_historical_hosts(captures, decay_params={"half_life_hours": 168})
    agg2 = aggregate_historical_hosts(captures, decay_params={"half_life_hours": 168})

    # deterministic: two runs equal sha1
    def canonical_bytes(o):
        def _round(o):
            if isinstance(o, float):
                return round(o, 3)
            if isinstance(o, dict):
                return {k: _round(o[k]) for k in sorted(o.keys())}
            if isinstance(o, list):
                return [_round(x) for x in o]
            return o

        fixed = _round(o)
        return json.dumps(fixed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    h1 = hashlib.sha1(canonical_bytes(agg1)).hexdigest()
    h2 = hashlib.sha1(canonical_bytes(agg2)).hexdigest()
    assert h1 == h2

    # immutability: original inputs unchanged
    assert captures == orig_copy

    # find aggregated host-1
    matched = [r for r in agg1 if r.get("host_id") == "host-1"]
    assert matched, "host-1 should be present"
    merged = matched[0]

    # provenance hashes include e1,e2,e3
    # compute ev sha1s
    sha_e1 = _sha1_of_evidence({"evidence_id": "e1", "attr": 1.23456})
    sha_e2 = _sha1_of_evidence({"evidence_id": "e2", "attr": 2.71828})
    sha_e3 = _sha1_of_evidence({"evidence_id": "e3", "attr": 9.999})
    prov = set(merged.get("provenance_refs", []))
    assert {sha_e1, sha_e2, sha_e3}.issubset(prov)

    # candidates include Linux and Windows due to MAC merge
    cand_names = [c["name"] for c in merged["historical_os_inference"]]
    assert "Linux" in cand_names
    assert "Windows" in cand_names

    # conflict should be true since both Linux and Windows top candidates observed
    assert merged.get("conflict") is True

    # metrics summary has captures count
    assert merged.get("metrics_summary", {}).get("captures", 0) >= 1
