import os
from pathlib import Path
from satori.nmap_lookup import lookup_os_from_nmap


def test_basic_match():
    db_path = str(Path("tests/data/nmap_test_db.json").resolve())
    # fingerprint meant to match Linux 4.x strongly
    fp = {
        "tcp_fingerprint": {
            "options": ["mss:1460", "timestamp", "wscale:7"],
            "ttl": 64,
            "window": 64240,
        }
    }
    c = lookup_os_from_nmap(fp, db_path=db_path)
    assert isinstance(c, list)
    assert len(c) >= 1
    assert c[0]["name"] == "Linux 4.x"
    assert c[0]["score"] > 0.8
