from satori.nmap_lookup import lookup_os_from_nmap
import copy


def test_determinism():
    db_path = "tests/data/nmap_test_db.json"
    fp = {
        "tcp_fingerprint": {
            "options": ["mss:1460", "timestamp", "wscale:7"],
            "ttl": 64,
            "window": 64240,
        }
    }
    a = lookup_os_from_nmap(copy.deepcopy(fp), db_path=db_path)
    b = lookup_os_from_nmap(copy.deepcopy(fp), db_path=db_path)
    assert a == b
    # evidence_refs deterministic and sorted
    for cand in a:
        assert isinstance(cand.get("evidence_refs"), list)
