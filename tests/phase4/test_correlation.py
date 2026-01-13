from satori.phase4.correlation import correlate_hosts_temporal
from tests.utils_phase2 import sha1_of_obj


def _make_host(hid, macs, candidates, evidence=None, protocols=None):
    return {
        'host_id': hid,
        'macs': macs,
        'aggregated_os_inference': {'candidates': candidates, 'metadata': {'protocols_seen': protocols or []}},
        'temporal_os_inference': {'temporal_candidates': candidates},
        'evidence': evidence or [],
    }


def test_correlation_basic_and_determinism():
    # two hosts with overlapping trait/evidence to produce correlation
    h1 = _make_host('h1', ['aa:bb:cc:11:22:33'], [
        {'name': 'Linux', 'temporal_score': 0.8, 'traits_matched': ['t1'], 'evidence_refs': ['e1']}
    ], evidence=[{'evidence_id': 'e1'}], protocols=['tcp'])

    h2 = _make_host('h2', ['aa:bb:cc:11:22:33'], [
        {'name': 'Linux', 'temporal_score': 0.6, 'traits_matched': ['t1'], 'evidence_refs': ['e1']}
    ], evidence=[{'evidence_id': 'e1'}], protocols=['tcp'])

    params = {'trait_similarity_threshold': 0.1, 'protocol_weights': {'tcp': 1.0}, 'conflict_penalty': 0.0}
    out1 = correlate_hosts_temporal([h1, h2], params)
    out2 = correlate_hosts_temporal([h1, h2], params)
    # determinism via SHA1
    assert sha1_of_obj(out1) == sha1_of_obj(out2)

    # ensure correlated candidates present and sorted
    c1 = out1[0]['correlated_os_inference']['candidates']
    assert c1[0]['name'] == 'Linux'
    assert isinstance(out1[0]['correlation_notes'], list)


def test_conflict_penalty_applied():
    h1 = _make_host('h1', [], [
        {'name': 'A', 'temporal_score': 0.7, 'traits_matched': ['t1'], 'evidence_refs': ['e1']},
        {'name': 'B', 'temporal_score': 0.6, 'traits_matched': ['t2'], 'evidence_refs': ['e2'], 'conflicts': [{'name': 'A'}]}
    ], evidence=[{'evidence_id': 'e1'},{'evidence_id': 'e2'}])

    h2 = _make_host('h2', [], [
        {'name': 'A', 'temporal_score': 0.6, 'traits_matched': ['t1'], 'evidence_refs': ['e1']},
    ], evidence=[{'evidence_id': 'e1'}])

    params = {'trait_similarity_threshold': 0.0, 'conflict_penalty': 0.2}
    out = correlate_hosts_temporal([h1, h2], params)
    # host with conflicts should have reduced raw contribution
    cands = {c['name']: c for c in out[0]['correlated_os_inference']['candidates']}
    assert cands['A']['raw_contribution'] >= cands['B']['raw_contribution']
