import json
from pathlib import Path
from satori.phase9.alerts import feed_live_alerts


def test_feed_live_alerts_snapshot_and_ndjson(tmp_path):
    hosts = [
        {"host_id": "h1", "phase7_anomaly_score": 0.9, "evidence_refs": ["sha1:x"]},
        {"host_id": "h2", "phase7_anomaly_score": 0.2, "evidence_refs": ["sha1:y"]},
    ]
    snap_dir = tmp_path / "alerts"
    res = feed_live_alerts(hosts, live_metrics={"now": "2026-01-12T00:00:00Z", "prefix": "testcap"}, alert_threshold=0.5, snapshot_dir=str(snap_dir), snapshot_interval=0.0, snapshot_batch_size=1, ndjson=False)
    assert res["did_snapshot"] is True
    # per-host json files exist
    assert (snap_dir / "testcap__alerts__h1.json").exists()
    # metrics file exists
    assert (snap_dir / "testcap__alerts_metrics.json").exists()

    # now test NDJSON append
    res2 = feed_live_alerts(hosts, live_metrics={"now": "2026-01-12T00:01:00Z", "prefix": "testcap"}, alert_threshold=0.5, snapshot_dir=str(snap_dir), snapshot_interval=0.0, snapshot_batch_size=1, ndjson=True)
    assert (snap_dir / "testcap__alerts__h1.ndjson").exists()
    # ensure NDJSON file has at least one line
    lines = (snap_dir / "testcap__alerts__h1.ndjson").read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 1
