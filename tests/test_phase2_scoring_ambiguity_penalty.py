from satori.phase2.scoring import score_host
from satori.phase2.traits import extract_traits


def test_ambiguity_penalty_reduces_score():
    host_clean = {
        'tcp_fingerprint': {'ttl': {'inferred_initial': 64}, 'confidence': 0.9},
        'ssh_fingerprint': {'confidence': 0.0},
        'evidence': [],
        'protocols_seen': ['tcp'],
        'protocol_count': 1,
        'evidence_density': 0.0,
        'ambiguity': {}
    }
    host_amb = dict(host_clean)
    host_amb['ambiguity'] = {'nat_suspected': True}

    traits = extract_traits(host_clean)
    r_clean = score_host(traits, host_clean)
    r_amb = score_host(traits, host_amb)
    # pick an OS present
    osn = 'Ubuntu'
    assert osn in r_clean and osn in r_amb
    assert r_amb[osn]['final_score'] <= r_clean[osn]['final_score']
