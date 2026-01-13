import copy
from satori.phase9.alerts import generate_alerts


def test_generate_alerts_deterministic():
    hosts = [
        {
            "host_id": "host-A",
            "phase7_anomaly_score": 0.9,
            "evidence_refs": ["sha1:aaa111"],
        },
        {
            "host_id": "host-B",
            "phase7_anomaly_score": 0.4,
            "phase8_candidates": [
                {"name": "Linux", "score": 0.5, "evidence_refs": ["sha1:bbb222"]},
                {"name": "Android", "score": 0.5, "evidence_refs": ["sha1:bbb222"]},
            ],
            "evidence_refs": ["sha1:bbb222"],
        },
    ]

    lm = {"now": "2026-01-12T00:00:00Z"}

    a1 = generate_alerts(hosts, live_metrics=lm, threshold=0.5)
    a2 = generate_alerts(copy.deepcopy(hosts), live_metrics=lm, threshold=0.5)

    assert a1 == a2
    # ordering: host-B should have higher severity (entropy) than host-A
    assert len(a1) == 2
    assert a1[0]["host_id"] == "host-B"
    assert a1[1]["host_id"] == "host-A"
    # severities rounded to 3 decimals
    for a in a1:
        assert isinstance(a["severity"], float)
        assert round(a["severity"], 3) == a["severity"]
