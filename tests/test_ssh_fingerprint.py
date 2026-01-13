import dataclasses
import json
from satori.ssh_fingerprint import build_ssh_fingerprint
from satori.host import Host
from satori.evidence import make_evidence


def make_host(evidence_list, ambiguity=None):
    if ambiguity is None:
        ambiguity = {}
    return Host(host_id="host:test", ips=set(), macs=set(), first_seen=None, last_seen=None, evidence=evidence_list, flows=set(), ambiguity=ambiguity, tcp_fingerprint=None, ssh_fingerprint=None)


def test_determinism_and_aggregation():
    ev_banner = make_evidence("ssh_extractor", "tcp", "ssh.banner", "SSH-2.0-OpenSSH_8.2p1", 0.3, None, None, 1.0, {"flow_id": "f1"})
    ev_fam = make_evidence("ssh_extractor", "tcp", "ssh.software_family", "openssh", 0.2, None, None, 1.0, {"flow_id": "f1"})
    ev_kex = make_evidence("ssh_extractor", "tcp", "ssh.kex_algorithms", ["curve25519-sha256","diffie-hellman-group14-sha1"], 0.4, None, None, 1.0, {"flow_id": "f1"})
    ev_kex2 = make_evidence("ssh_extractor", "tcp", "ssh.kex_algorithms", ["diffie-hellman-group14-sha1"], 0.4, None, None, 2.0, {"flow_id": "f2"})
    ev_hostkey = make_evidence("ssh_extractor", "tcp", "ssh.hostkey_algorithms", ["rsa-sha2-512"], 0.4, None, None, 1.5, {"flow_id": "f1"})

    h_a = make_host([ev_banner, ev_fam, ev_kex, ev_kex2, ev_hostkey])
    h_b = make_host([ev_kex2, ev_hostkey, ev_fam, ev_kex, ev_banner])

    f_a = build_ssh_fingerprint(h_a)
    f_b = build_ssh_fingerprint(h_b)

    da = dataclasses.asdict(f_a)
    db = dataclasses.asdict(f_b)
    assert da == db

    s1 = json.dumps(da, sort_keys=True)
    s2 = json.dumps(db, sort_keys=True)
    assert s1 == s2

    # aggregated lists should include items from both kex entries
    assert "curve25519-sha256" in f_a.kex_algorithms
    assert "diffie-hellman-group14-sha1" in f_a.kex_algorithms
    assert "rsa-sha2-512" in f_a.hostkey_algorithms


def test_ambiguity_penalizes_confidence_but_preserves_values():
    ev_banner = make_evidence("ssh_extractor", "tcp", "ssh.banner", "SSH-2.0-OpenSSH_8.2p1", 0.3, None, None, 1.0, {"flow_id": "f1"})
    ev_kex = make_evidence("ssh_extractor", "tcp", "ssh.kex_algorithms", ["a","b"], 0.4, None, None, 1.0, {"flow_id": "f1"})
    h_clean = make_host([ev_banner, ev_kex], ambiguity={})
    h_amb = make_host([ev_banner, ev_kex], ambiguity={"nat_suspected": True})
    f_clean = build_ssh_fingerprint(h_clean)
    f_amb = build_ssh_fingerprint(h_amb)
    assert set(f_clean.kex_algorithms) == set(f_amb.kex_algorithms)
    assert f_amb.confidence < f_clean.confidence


def test_missing_fields_reduce_confidence_but_valid():
    ev_banner = make_evidence("ssh_extractor", "tcp", "ssh.banner", "SSH-2.0-OpenSSH_8.2p1", 0.3, None, None, 1.0, {"flow_id": "f1"})
    h_partial = make_host([ev_banner])
    f_partial = build_ssh_fingerprint(h_partial)
    assert isinstance(f_partial.confidence, float)
    # more complete increases confidence
    ev_kex = make_evidence("ssh_extractor", "tcp", "ssh.kex_algorithms", ["a"], 0.4, None, None, 2.0, {"flow_id": "f2"})
    h_full = make_host([ev_banner, ev_kex])
    f_full = build_ssh_fingerprint(h_full)
    assert f_partial.confidence < f_full.confidence
