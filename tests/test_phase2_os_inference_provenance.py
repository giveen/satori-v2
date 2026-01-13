from satori.phase2.os_inference import build_os_inference


def _host_fixture():
    return {
        'tcp_fingerprint': {'ttl': {'inferred_initial': 64}, 'confidence': 0.9},
        'ssh_fingerprint': {'kex_algorithms': ['curve25519-sha256@libssh.org'], 'confidence': 0.8},
        'evidence': [
            {
                'source': 'tcp_extractor',
                'attribute': 'tcp.ttl',
                'value': 64,
                'confidence_hint': 0.9,
                'protocol': 'tcp',
                'flow_id': 'f1',
            },
            {
                'source': 'ssh_extractor',
                'attribute': 'ssh.kex_algorithms',
                'value': ['curve25519-sha256@libssh.org'],
                'confidence_hint': 0.8,
                'protocol': 'ssh',
                'flow_id': 'f2',
            }
        ],
        'protocols_seen': ['tcp', 'ssh'],
        'protocol_count': 2,
        'evidence_density': 0.5,
        'ambiguity': {},
    }


def test_provenance_refs_point_to_evidence():
    host = _host_fixture()
    oi = build_os_inference(host)
    # every evidence_ref.evidence_id must correspond to an evidence in host
    ev_ids = set()
    for ev in host['evidence']:
        # compute sha1 via same utility
        from satori.phase2.evidence import evidence_sha1

        ev_ids.add(evidence_sha1(ev))

    for cand in oi['candidates']:
        for ref in cand['evidence_refs']:
            assert ref['evidence_id'] in ev_ids
            assert 'pointer' in ref and isinstance(ref['pointer'], list)
            assert 'trait' in ref
            assert 'contribution' in ref
