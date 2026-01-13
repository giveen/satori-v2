from satori.phase3.aggregate import aggregate_hosts


def test_aggregation_basic():
    # two source hosts from different captures representing same host_id
    host_a = {
        'host_id': 'a1',
        'capture_id': 'pcap-1',
        'mac': 'AA:BB:CC:11:22:33',
        'evidence': [{'attribute': 'tcp.ttl', 'value': 64}],
        'protocols_seen': ['tcp'],
        'evidence_density': 0.5,
        'os_inference': {
            'candidates': [
                {'name': 'Ubuntu', 'score': 0.8, 'traits_matched': ['tcp:ttl:64'], 'evidence_refs': [{'evidence_id': 'e1'}]},
            ]
        }
    }

    host_b = {
        'host_id': 'a1',
        'capture_id': 'pcap-2',
        'mac': 'aa:bb:cc:11:22:33',
        'evidence': [{'attribute': 'ssh.kex', 'value': 'curve25519'}],
        'protocols_seen': ['ssh'],
        'evidence_density': 0.8,
        'os_inference': {
            'candidates': [
                {'name': 'Ubuntu', 'score': 0.6, 'traits_matched': ['ssh:kex:curve25519'], 'evidence_refs': [{'evidence_id': 'e2'}]},
            ]
        }
    }

    aggs = aggregate_hosts([host_a, host_b])
    # aggregation id should be mac: aabbcc112233
    aid = 'mac:aabbcc112233'
    assert aid in aggs
    agg = aggs[aid]
    assert 'candidates' in agg
    assert len(agg['candidates']) >= 1
    # Ubuntu candidate present
    names = [c['name'] for c in agg['candidates']]
    assert 'Ubuntu' in names
    # evidence_refs preserved and annotated
    for c in agg['candidates']:
        for r in c.get('evidence_refs', []):
            assert 'source_host_id' in r and 'capture_id' in r
