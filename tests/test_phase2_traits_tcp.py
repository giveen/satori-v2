from satori.phase2.traits import extract_traits


def test_tcp_traits_deterministic_and_sorted():
    host = {
        "tcp_fingerprint": {
            "ttl": {"observed_values": [64], "inferred_initial": 64},
            "window_size": {"values": [65535]},
            "mss": {"values": [1460]},
            "wscale": {"values": [7]},
            "tcp_options_order": ["mss", "sack", "ts", "wscale"],
            "ts_present": "present",
            "confidence": 0.5,
        },
        "evidence": [],
    }

    t1 = extract_traits(host)
    t2 = extract_traits(host)
    assert t1 == t2
    # expected keys
    assert "tcp:ttl:64" in t1
    assert "tcp:window:65535" in t1
    assert "tcp:mss:1460" in t1
    assert "tcp:wscale:7" in t1
    # opts are sorted alphabetically for determinism
    assert "tcp:opts:mss,sack,ts,wscale" in t1
    assert "tcp:ts:present" in t1
