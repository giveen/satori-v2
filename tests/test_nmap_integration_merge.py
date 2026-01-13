from satori.phase2.os_inference import build_os_inference


def test_nmap_merge_candidates():
    host = {
        'host_id': 'host:test',
        'tcp_fingerprint': {
            'ttl': {'inferred_initial': 64},
            'window_size': {'values': [64240]},
            'mss': {'values': [1460]},
            'wscale': {'values': [7]},
            'tcp_options_order': ['mss:1460', 'timestamp', 'wscale:7'],
            'ts_present': True,
        },
        'evidence': [],
    }
    # use test DB shipped in tests/data
    nmap_db = 'tests/data/nmap_test_db.json'
    oi = build_os_inference(host, nmap_db_path=nmap_db)
    assert 'candidates' in oi
    names = [c.get('name') for c in oi.get('candidates', [])]
    assert 'Linux 4.x' in names
