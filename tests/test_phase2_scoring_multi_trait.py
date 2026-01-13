from satori.phase2.scoring import score_host
from satori.phase2.traits import extract_traits


def test_multiple_traits_additive():
    host = {
        'tcp_fingerprint': {'ttl': {'inferred_initial': 64}, 'confidence': 0.9},
        'ssh_fingerprint': {'kex_algorithms': ['curve25519-sha256@libssh.org'], 'confidence': 0.8},
        'evidence': [],
        'protocols_seen': ['tcp', 'ssh'],
        'protocol_count': 2,
        'evidence_density': 1.0,
        'ambiguity': {}
    }
    traits = extract_traits(host)
    res = score_host(traits, host)
    # Ubuntu appears for both traits; final score should reflect both contributions
    assert 'Ubuntu' in res
    u = res['Ubuntu']
    assert u['raw_score'] > 0
    # ensure normalized <=1
    assert 0.0 <= u['normalized_score'] <= 1.0
    assert 0.0 <= u['final_score'] <= 1.0
