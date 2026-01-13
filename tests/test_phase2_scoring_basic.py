from satori.phase2.scoring import score_host
from satori.phase2.traits import extract_traits
import json


def test_single_trait_single_os_score():
    # build host with single tcp ttl trait via tcp_fingerprint
    host = {
        'tcp_fingerprint': {'ttl': {'inferred_initial': 64}, 'confidence': 0.5},
        'ssh_fingerprint': {'confidence': 0.0},
        'evidence': [],
        'protocols_seen': ['tcp'],
        'protocol_count': 1,
        'evidence_density': 0.0,
        'ambiguity': {}
    }
    traits = extract_traits(host)
    res = score_host(traits, host)
    # Ubuntu and Debian present in signature table for tcp:ttl:64
    assert 'Ubuntu' in res and 'Debian' in res
    # raw scores should be > 0
    assert res['Ubuntu']['raw_score'] > 0
    assert 0.0 <= res['Ubuntu']['final_score'] <= 1.0
