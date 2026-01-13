import json
import hashlib
from satori.phase7.anomaly import detect_anomalies


def _sha1_of_obj(obj):
    b = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha1(b).hexdigest()


def test_basic_os_conflict():
    # host with differing top candidates between host and aggregated
    host = {
        "host_id": "host:a",
        "os_inference": {"candidates": [{"name": "Linux"}]},
        "aggregated_os_inference": {"candidates": [{"name": "Windows"}], "aggregation_id": "agg:1", "members": ["host:a"]},
        "evidence": [{"provenance": {"id": 1}}],
        "ambiguity": {},
        "flows": [],
    }
    reports, metrics = detect_anomalies([host])
    assert len(reports) == 1
    rep = reports[0]
    assert rep["host_id"] == "host:a"
    assert any(a["type"] == "os_conflict" for a in rep["anomalies"]) 
    assert metrics["num_hosts_with_anomalies"] == 1
