import hashlib
import json
from pathlib import Path
import pytest
from satori.phase7.anomaly import detect_anomalies


def canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def test_phase7_regression(update_snapshots, tmp_path):
    # construct two hosts with known anomalies
    h1 = {
        "host_id": "host:reg1",
        "os_inference": {"candidates": [{"name": "Linux"}]},
        "aggregated_os_inference": {"candidates": [{"name": "Windows"}], "aggregation_id": "areg", "members": ["host:reg1"]},
        "evidence": [{"provenance": {"pkt": 1}}],
        "ambiguity": {},
        "flows": [],
    }
    h2 = {
        "host_id": "host:reg2",
        "os_inference": {"candidates": [{"name": "Linux"}]},
        "aggregated_os_inference": {"candidates": [{"name": "Linux"}], "aggregation_id": "areg", "members": ["host:reg1", "host:reg2"]},
        "evidence": [{"provenance": {"pkt": 2}}],
        "ambiguity": {"nat_suspected": True},
        "flows": [],
    }
    reports, metrics = detect_anomalies([h1, h2])
    out = {"reports": reports, "metrics": metrics}
    b = canonical_bytes(out)
    expected_dir = Path("tests/expected_phase7")
    expected_dir.mkdir(exist_ok=True)
    out_path = expected_dir / "phase7_regression.json"
    if update_snapshots:
        out_path.write_bytes(b)
        pytest.skip("snapshots updated")
    if not out_path.exists():
        pytest.skip("missing snapshot; run with --update-snapshots to create")
    exp = out_path.read_bytes()
    assert hashlib.sha1(b).hexdigest() == hashlib.sha1(exp).hexdigest()
