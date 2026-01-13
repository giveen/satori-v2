import copy
import hashlib
import json

from src.satori.phase5.report import build_phase5_summary


def canonical_bytes(o):
    def _round(x):
        if isinstance(x, float):
            return round(x, 3)
        if isinstance(x, dict):
            return {k: _round(x[k]) for k in sorted(x.keys())}
        if isinstance(x, list):
            return [_round(xx) for xx in x]
        return x

    fixed = _round(o)
    return json.dumps(fixed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha1_of_obj(o):
    return hashlib.sha1(canonical_bytes(o)).hexdigest()


def test_phase5_report_deterministic_and_metrics():
    host1 = {
        "host_id": "h1",
        "macs": ["aa:aa:aa:aa:aa:aa"],
        "evidence": [{"evidence_id": "e1", "attr": 1.0}],
        "os_inference": {"candidates": [{"name": "Linux", "score": 0.9}]},
        "capture_timestamp": "2025-02-01T00:00:00Z",
    }

    host2 = {
        "host_id": "h2",
        "macs": ["bb:bb:bb:bb:bb:bb"],
        "evidence": [{"evidence_id": "e2", "attr": 2.0}],
        "os_inference": {"candidates": [{"name": "Windows", "score": 0.7}]},
        "capture_timestamp": "2025-02-02T00:00:00Z",
    }

    captures = [[host1, host2]]

    s1 = build_phase5_summary(copy.deepcopy(captures), decay_params={"half_life_hours": 168})
    s2 = build_phase5_summary(copy.deepcopy(captures), decay_params={"half_life_hours": 168})

    assert sha1_of_obj(s1) == sha1_of_obj(s2)

    # basic metrics presence
    assert s1.get("metrics", {}).get("num_hosts") == 2
    hosts = s1.get("hosts", [])
    assert any(h.get("host_id") == "h1" for h in hosts)
    assert any(h.get("host_id") == "h2" for h in hosts)
