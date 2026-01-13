from satori.phase2.scoring import score_host
from satori.phase2.traits import extract_traits


def test_scoring_deterministic_on_repeated_runs():
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
    r1 = score_host(traits, host)
    r2 = score_host(traits, host)
    assert r1 == r2
