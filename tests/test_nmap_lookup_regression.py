import hashlib
import json
from pathlib import Path
import pytest
from satori.nmap_lookup import lookup_os_from_nmap


def canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def test_nmap_lookup_regression(update_snapshots, tmp_path):
    db_path = str(Path("tests/data/nmap_test_db.json").resolve())
    fp = {
        "tcp_fingerprint": {
            "options": ["mss:1460", "timestamp", "wscale:7"],
            "ttl": 64,
            "window": 64240,
        }
    }
    candidates = lookup_os_from_nmap(fp, db_path=db_path)
    out = {"candidates": candidates}
    b = canonical_bytes(out)
    expected_dir = Path("tests/expected_nmap_lookup")
    expected_dir.mkdir(exist_ok=True)
    out_path = expected_dir / "nmap_lookup_regression.json"
    if update_snapshots:
        out_path.write_bytes(b)
        pytest.skip("snapshots updated")
    if not out_path.exists():
        pytest.skip("missing snapshot; run with --update-snapshots to create")
    exp = out_path.read_bytes()
    assert hashlib.sha1(b).hexdigest() == hashlib.sha1(exp).hexdigest()
