from satori.phase2.os_inference import build_os_inference
import json
import hashlib


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


def _sha1_of_obj(obj):
    b = json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha1(b).hexdigest()


def test_regression_same_output_on_repeated_runs():
    host = _host_fixture()
    oi1 = build_os_inference(host)
    oi2 = build_os_inference(host)
    s1 = _sha1_of_obj(oi1)
    s2 = _sha1_of_obj(oi2)
    assert s1 == s2
