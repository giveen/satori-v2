from satori.phase7.anomaly import detect_anomalies


def test_multi_host_correlation():
    # two hosts in same aggregation with different inferred OS -> correlation note
    h1 = {
        "host_id": "host:1",
        "os_inference": {"candidates": [{"name": "Linux"}]},
        "aggregated_os_inference": {"aggregation_id": "aggX", "members": ["host:1", "host:2"], "candidates": [{"name": "Linux"}]},
        "evidence": [{"provenance": {"pkt": 1}}],
        "ambiguity": {},
        "flows": [],
    }
    h2 = {
        "host_id": "host:2",
        "os_inference": {"candidates": [{"name": "Windows"}]},
        "aggregated_os_inference": {"aggregation_id": "aggX", "members": ["host:1", "host:2"], "candidates": [{"name": "Linux"}]},
        "evidence": [{"provenance": {"pkt": 2}}],
        "ambiguity": {},
        "flows": [],
    }
    reports, metrics = detect_anomalies([h1, h2])
    # both should have reports; at least one should have correlation_notes
    assert any(r.get("correlation_notes") for r in reports)
