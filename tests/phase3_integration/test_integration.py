from satori.phase3.integration import integrate_phase3


def test_integrate_phase3_attaches_blocks_and_notes():
    hosts = [
        {
            'host_id': 'h1',
            'capture_id': 'pcap-1',
            'mac': 'aa:bb:cc:11:22:33',
            'evidence': [{'attribute': 'tcp.ttl', 'value': 64}],
            'protocols_seen': ['tcp'],
            'evidence_density': 0.5,
            'os_inference': {'candidates': [{'name': 'Ubuntu', 'score': 0.9, 'traits_matched': ['tcp:ttl:64'], 'evidence_refs': [{'evidence_id': 'e1'}]}]},
        },
        {
            'host_id': 'h2',
            'capture_id': 'pcap-2',
            'mac': 'aa:bb:cc:44:55:66',
            'evidence': [{'attribute': 'ssh.kex', 'value': 'curve25519'}],
            'protocols_seen': ['ssh'],
            'evidence_density': 0.5,
            'os_inference': {'candidates': [{'name': 'Ubuntu', 'score': 0.8, 'traits_matched': ['ssh:kex:curve25519'], 'evidence_refs': [{'evidence_id': 'e2'}]}]},
        }
    ]

    out = integrate_phase3(hosts, trait_similarity_threshold=0.0)
    # both hosts should have aggregated_os_inference attached
    for h in out:
        assert 'os_inference' in h
        assert 'aggregated_os_inference' in h
        assert 'correlation_notes' in h
    # with threshold 0.0 they should be correlated (since jaccard >=0)
    assert any(h['correlation_notes'] for h in out)
