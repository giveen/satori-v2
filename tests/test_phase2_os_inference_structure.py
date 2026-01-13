from satori.phase2.os_inference import build_os_inference
from satori.phase2.traits import extract_traits
from satori.phase2.scoring import score_host


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


def test_structure_and_schema_present():
    host = _host_fixture()
    oi = build_os_inference(host)
    assert oi['os_inference_schema_version'] == 'os_inference/v1'
    assert 'signature_table_version' in oi
    assert oi['generated_by'] == 'phase2-v0.1'
    assert isinstance(oi['candidates'], list)
    assert isinstance(oi['explanation'], dict)
    assert isinstance(oi['metadata'], dict)
