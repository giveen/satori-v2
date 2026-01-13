import dataclasses
import json
from satori.tcp_fingerprint import build_tcp_fingerprint
from satori.host import Host
from satori.evidence import make_evidence


def make_host(evidence_list, ambiguity=None):
    if ambiguity is None:
        ambiguity = {}
    return Host(host_id="host:test", ips=set(), macs=set(), first_seen=None, last_seen=None, evidence=evidence_list, flows=set(), ambiguity=ambiguity, tcp_fingerprint=None)


def test_determinism_and_json_stability():
    # same evidence different order -> identical fingerprint
    ev1 = make_evidence("tcp_extractor", "ip", "ip.ttl", 64, 0.5, None, None, 1.0, {"flow_id": "f1"})
    ev2 = make_evidence("tcp_extractor", "tcp", "tcp.mss", 1460, 0.7, None, None, 1.0, {"flow_id": "f1"})
    ev3 = make_evidence("tcp_extractor", "tcp", "tcp.isn", 1000, 0.6, None, None, 1.0, {"flow_id": "f1"})

    h_a = make_host([ev1, ev2, ev3])
    h_b = make_host([ev3, ev1, ev2])

    f_a = build_tcp_fingerprint(h_a)
    f_b = build_tcp_fingerprint(h_b)

    da = dataclasses.asdict(f_a)
    db = dataclasses.asdict(f_b)
    assert da == db

    # JSON stability (sorted keys)
    s1 = json.dumps(da, sort_keys=True)
    s2 = json.dumps(db, sort_keys=True)
    assert s1 == s2


def test_ttl_inference_and_preservation():
    # TTLs 60 and 61 -> inferred_initial should bin to 64
    evs = [make_evidence("tcp_extractor", "ip", "ip.ttl", 60, 0.5, None, None, 1.0, {"flow_id": "f1"}),
           make_evidence("tcp_extractor", "ip", "ip.ttl", 61, 0.5, None, None, 1.0, {"flow_id": "f1"})]
    h = make_host(evs)
    f = build_tcp_fingerprint(h)
    assert 64 == f.ttl["inferred_initial"]
    assert set(f.ttl["observed_values"]) == {60, 61}

    # TTLs 127 and 128 -> inferred_initial 128
    evs2 = [make_evidence("tcp_extractor", "ip", "ip.ttl", 127, 0.5, None, None, 1.0, {"flow_id": "f1"}),
            make_evidence("tcp_extractor", "ip", "ip.ttl", 128, 0.5, None, None, 1.0, {"flow_id": "f1"})]
    h2 = make_host(evs2)
    f2 = build_tcp_fingerprint(h2)
    assert 128 == f2.ttl["inferred_initial"]
    assert set(f2.ttl["observed_values"]) == {127, 128}


def test_isn_classification_incremental_lowentropy_random():
    # Incremental: same flow, sequential ISNs
    evs_inc = [make_evidence("tcp_extractor", "tcp", "tcp.isn", v, 0.6, None, None, 1.0, {"flow_id": "flow_inc"}) for v in (1000, 2000, 3000, 4000, 5000)]
    h_inc = make_host(evs_inc)
    f_inc = build_tcp_fingerprint(h_inc)
    assert f_inc.isn_behavior == "incremental"

    # Low-entropy: many ISNs with identical low 8 bits (entropy low)
    base = [0x100, 0x200, 0x300, 0x400]
    evs_low = [make_evidence("tcp_extractor", "tcp", "tcp.isn", v, 0.6, None, None, 1.0, {"flow_id": f"f{i}"}) for i, v in enumerate(base)]
    h_low = make_host(evs_low)
    f_low = build_tcp_fingerprint(h_low)
    assert f_low.isn_behavior == "low_entropy"

    # Random: single ISN per unique flow (no diffs) -> classified as random
    rnd_vals = [100 + i for i in range(8)]
    evs_rnd = [make_evidence("tcp_extractor", "tcp", "tcp.isn", v, 0.6, None, None, 1.0, {"flow_id": f"flow_{i}"}) for i, v in enumerate(rnd_vals)]
    h_rnd = make_host(evs_rnd)
    f_rnd = build_tcp_fingerprint(h_rnd)
    assert f_rnd.isn_behavior == "random"


def test_ambiguity_reduces_confidence_but_keeps_values():
    evs = [make_evidence("tcp_extractor", "ip", "ip.ttl", 64, 0.5, None, None, 1.0, {"flow_id": "f1"}),
           make_evidence("tcp_extractor", "tcp", "tcp.mss", 1460, 0.7, None, None, 1.0, {"flow_id": "f1"})]
    h_clean = make_host(list(evs), ambiguity={})
    h_amb = make_host(list(evs), ambiguity={"nat_suspected": True})
    f_clean = build_tcp_fingerprint(h_clean)
    f_amb = build_tcp_fingerprint(h_amb)
    # values unchanged
    assert set(f_clean.mss["values"]) == set(f_amb.mss["values"]) == {1460}
    # confidence reduced when ambiguity present
    assert f_amb.confidence < f_clean.confidence


def test_missing_data_yields_valid_fingerprint_and_lower_confidence():
    # only TTL evidence
    h_partial = make_host([make_evidence("tcp_extractor", "ip", "ip.ttl", 64, 0.5, None, None, 1.0, {"flow_id": "f1"})])
    f_partial = build_tcp_fingerprint(h_partial)
    assert isinstance(f_partial.confidence, float)
    # partial should have lower confidence than a more complete example
    h_full = make_host([
        make_evidence("tcp_extractor", "ip", "ip.ttl", 64, 0.5, None, None, 1.0, {"flow_id": "f1"}),
        make_evidence("tcp_extractor", "tcp", "tcp.mss", 1460, 0.7, None, None, 1.0, {"flow_id": "f1"}),
    ])
    f_full = build_tcp_fingerprint(h_full)
    assert f_partial.confidence < f_full.confidence
