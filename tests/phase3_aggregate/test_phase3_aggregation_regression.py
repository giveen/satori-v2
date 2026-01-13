import json
import hashlib
from satori.phase3.aggregate import aggregate_hosts
from tests.utils_phase2 import canonical_json_bytes, sha1_of_obj


def _fixture_hosts():
    return [
        {
            'host_id': 'h1',
            'mac': '00:11:22:33:44:55',
            'capture_id': 'pcap-A',
            'protocols_seen': ['tcp'],
            'evidence': [{'attribute': 'tcp.ttl', 'value': 64}],
            'evidence_density': 0.5,
            'os_inference': {'candidates': [{'name': 'Debian', 'score': 0.7, 'traits_matched': ['tcp:ttl:64'], 'evidence_refs': [{'evidence_id': 'e1'}]}]},
        },
        {
            'host_id': 'h1',
            'mac': '00:11:22:33:44:55',
            'capture_id': 'pcap-B',
            'protocols_seen': ['ssh'],
            'evidence': [{'attribute': 'ssh.kex', 'value': 'curve25519'}],
            'evidence_density': 0.2,
            'os_inference': {'candidates': [{'name': 'Debian', 'score': 0.4, 'traits_matched': ['ssh:kex:curve25519'], 'evidence_refs': [{'evidence_id': 'e2'}]}]},
        }
    ]


def test_phase3_regression_hash_stable():
    hosts = _fixture_hosts()
    aggs = aggregate_hosts(hosts)
    # compute sha1 of canonical serialization of the aggregated mapping
    b = canonical_json_bytes(aggs)
    s = hashlib.sha1(b).hexdigest()
    # running twice should produce same hash
    aggs2 = aggregate_hosts(hosts)
    b2 = canonical_json_bytes(aggs2)
    s2 = hashlib.sha1(b2).hexdigest()
    assert s == s2
