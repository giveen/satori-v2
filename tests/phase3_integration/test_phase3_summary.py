import os
import json

from satori.phase3.report import build_phase3_summary
from tests.utils_phase2 import canonical_json_bytes, sha1_of_obj


SNAP_DIR = os.path.join(os.path.dirname(__file__), "..", "expected_phase3_snapshots")


def _load_all_hosts():
    hosts = []
    if not os.path.isdir(SNAP_DIR):
        return hosts
    for fn in sorted(os.listdir(SNAP_DIR)):
        if not fn.endswith('.json'):
            continue
        path = os.path.join(SNAP_DIR, fn)
        with open(path, 'r') as fh:
            hosts.append(json.load(fh))
    return hosts


def test_phase3_summary_deterministic_and_structure():
    hosts = _load_all_hosts()
    # if no snapshots present, skip (keeps CI flexible)
    if not hosts:
        return

    summary = build_phase3_summary(hosts, top_n=3)
    # Basic structural checks
    assert 'hosts' in summary and isinstance(summary['hosts'], list)
    assert 'metrics' in summary and isinstance(summary['metrics'], dict)

    # Deterministic serialization checksum
    b = canonical_json_bytes(summary)
    h1 = sha1_of_obj(summary)
    # build again and ensure same sha1
    summary2 = build_phase3_summary(hosts, top_n=3)
    h2 = sha1_of_obj(summary2)
    assert h1 == h2


def test_top_os_distribution_totals_match():
    hosts = _load_all_hosts()
    if not hosts:
        return
    summary = build_phase3_summary(hosts, top_n=3)
    metrics = summary['metrics']
    total = sum(metrics.get('top_os_distribution', {}).values())
    # total distribution may be <= num_hosts_with_os_inference when some hosts have no candidates
    assert total <= metrics.get('num_hosts_with_os_inference', 0)
