import json
import hashlib
from satori.phase7.anomaly import detect_anomalies


def canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def test_deterministic_output():
    h = {
        "host_id": "host:z",
        "os_inference": {"candidates": [{"name": "Linux"}]},
        "aggregated_os_inference": {"candidates": [{"name": "Linux"}], "aggregation_id": "aggZ", "members": ["host:z"]},
        "evidence": [{"provenance": {"id": 1}}],
        "ambiguity": {"nat_suspected": True},
        "flows": [],
    }
    r1, m1 = detect_anomalies([h])
    r2, m2 = detect_anomalies([h])
    b1 = canonical_bytes({"reports": r1, "metrics": m1})
    b2 = canonical_bytes({"reports": r2, "metrics": m2})
    assert hashlib.sha1(b1).hexdigest() == hashlib.sha1(b2).hexdigest()
