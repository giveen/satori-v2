from satori.phase2.evidence import canonicalize_evidence, evidence_sha1
import json
from pathlib import Path


def test_evidence_hash_deterministic():
    p = Path('tests/output/dhcp.pcap.summary.json')
    assert p.exists()
    j = json.loads(p.read_text())
    hosts = j.get('hosts', [])
    assert hosts
    # pick first host with evidence
    target = None
    for h in hosts:
        if h.get('evidence'):
            target = h
            break
    assert target is not None
    ev = target['evidence'][0]
    # canonicalize twice and compare
    c1 = canonicalize_evidence(ev)
    c2 = canonicalize_evidence(ev)
    assert c1 == c2
    # hash twice and compare
    h1 = evidence_sha1(ev)
    h2 = evidence_sha1(ev)
    assert h1 == h2
