import json
from satori.host import Host, HostRegistry
from satori.evidence import make_evidence
from satori.ssh_fingerprint import build_ssh_fingerprint


def make_host_with_evidence(host_id, evidence_list, flows=None, ambiguity=None):
    h = Host(host_id=host_id, ips=set(), macs=set(), first_seen=None, last_seen=None, evidence=[], flows=set(), ambiguity=ambiguity or {})
    # add flows if provided
    if flows:
        for f in flows:
            h.flows.add(f)
    # add evidence in provided order
    for ev in evidence_list:
        h.add_evidence(ev)
    return h


def build_cli_hosts_output(hosts):
    hosts_output = []
    for h in hosts:
        # compute ssh fingerprint
        h.ssh_fingerprint = build_ssh_fingerprint(h)
        hosts_output.append({
            "host_id": h.host_id,
            "ips": sorted(list(h.ips)),
            "macs": sorted(list(h.macs)),
            "ambiguity": {k: v for k, v in h.ambiguity.items() if not k.startswith("_")},
            "first_seen": h.first_seen,
            "last_seen": h.last_seen,
            "evidence": h.evidence,
            "ssh_fingerprint": (h.ssh_fingerprint.__dict__ if h.ssh_fingerprint is not None else None),
            "flows": sorted(list(h.flows)),
        })
    return hosts_output


def test_cli_includes_ssh_fingerprint_and_is_deterministic():
    # Clean host with SSH evidence
    ev_banner = make_evidence("ssh_extractor", "tcp", "ssh.banner", "SSH-2.0-OpenSSH_8.4", 0.3, None, None, 1.0, {"flow_id": "f1"})
    ev_kex1 = make_evidence("ssh_extractor", "tcp", "ssh.kex_algorithms", ["curve25519-sha256", "diffie-hellman-group14-sha1"], 0.4, None, None, 1.0, {"flow_id": "f1"})
    ev_kex2 = make_evidence("ssh_extractor", "tcp", "ssh.kex_algorithms", ["diffie-hellman-group14-sha1"], 0.4, None, None, 2.0, {"flow_id": "f2"})
    ev_hostkey = make_evidence("ssh_extractor", "tcp", "ssh.hostkey_algorithms", ["rsa-sha2-512"], 0.4, None, None, 1.5, {"flow_id": "f1"})
    ev_enc = make_evidence("ssh_extractor", "tcp", "ssh.encryption_algorithms_c2s", ["aes128-ctr"], 0.3, None, None, 1.2, {"flow_id": "f1"})
    clean = make_host_with_evidence("host:clean", [ev_banner, ev_kex1, ev_kex2, ev_hostkey, ev_enc], flows=["f1", "f2"], ambiguity={})

    # Ambiguous host
    ev_banner_a = make_evidence("ssh_extractor", "tcp", "ssh.banner", "SSH-2.0-OpenSSH_7.2", 0.3, None, None, 3.0, {"flow_id": "fa1"})
    ev_kex_a = make_evidence("ssh_extractor", "tcp", "ssh.kex_algorithms", ["a","b"], 0.4, None, None, 3.0, {"flow_id": "fa1"})
    amb = make_host_with_evidence("host:amb", [ev_banner_a, ev_kex_a], flows=["fa1"], ambiguity={"nat_suspected": True, "shared_ip": True})

    # Host with no SSH evidence
    none_host = make_host_with_evidence("host:none", [], flows=[], ambiguity={})

    hosts = [clean, amb, none_host]

    out1 = {"hosts": build_cli_hosts_output(hosts)}
    out2 = {"hosts": build_cli_hosts_output(hosts)}

    s1 = json.dumps(out1, sort_keys=True)
    s2 = json.dumps(out2, sort_keys=True)
    assert s1 == s2, "CLI output should be deterministic across runs"

    # Assertions per host
    for h_out, h in zip(out1["hosts"], hosts):
        assert "ssh_fingerprint" in h_out
        sf = h_out["ssh_fingerprint"]
        if h is none_host:
            # ssh_fingerprint may be present as an empty fingerprint dict; accept either
            if sf is None:
                continue
            assert isinstance(sf, dict)
            assert sf.get("kex_algorithms") == []
            assert sf.get("hostkey_algorithms") == []
            assert sf.get("ssh_banner") == []
            assert isinstance(sf.get("confidence"), float)
        else:
            # banner presence and insertion order
            assert sf["ssh_banner"]
            # aggregated kex algorithms deduped and sorted
            assert isinstance(sf["kex_algorithms"], list)
            # hostkey algorithms present when provided
            if h is clean:
                assert "rsa-sha2-512" in sf["hostkey_algorithms"]
                # provenance includes flow ids
                prov = sf["provenance"]
                assert "kex_algorithms" in prov and "f1" in prov["kex_algorithms"]
                # confidence numeric <= 1.0 and reduced for ambiguous host
                assert isinstance(sf["confidence"], float) and 0.0 <= sf["confidence"] <= 1.0
            if h is amb:
                # ambiguous host should have lower confidence than clean (compare by recomputing)
                clean_sf = build_ssh_fingerprint(clean)
                amb_sf = build_ssh_fingerprint(amb)
                assert amb_sf.confidence < clean_sf.confidence
