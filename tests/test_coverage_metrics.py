import json
from pathlib import Path


def test_compact_summaries_include_coverage_metrics():
    # regenerate compact summaries to ensure coverage_metrics present
    import subprocess, sys, os

    py = os.path.join('.venv', 'bin', 'python') if Path('.venv/bin/python').exists() else sys.executable
    rc = subprocess.run([py, 'scripts/pcap_summary.py'], capture_output=True, text=True).returncode
    assert rc == 0
    files = sorted(Path('tests/output').glob('*.compact.json'))
    assert files, 'No compact JSON files found; run scripts/pcap_summary.py first'
    for p in files:
        j = json.loads(p.read_text())
        # top-level coverage_metrics must exist
        assert 'coverage_metrics' in j, f'coverage_metrics missing in {p}'
        cov = j['coverage_metrics']
        # ensure host_coverage and protocol_coverage_ratios exist
        assert 'host_coverage' in cov
        assert 'protocol_coverage_ratios' in cov
        # per-host fields
        for h in j.get('hosts', []):
            assert 'protocols_seen' in h
            assert 'protocol_count' in h
            assert 'evidence_density' in h


def test_dhcp_pcap_has_dhcp_hosts():
    # ensure summaries regenerated
    import subprocess, sys, os

    py = os.path.join('.venv', 'bin', 'python') if Path('.venv/bin/python').exists() else sys.executable
    rc = subprocess.run([py, 'scripts/pcap_summary.py'], capture_output=True, text=True).returncode
    assert rc == 0

    p = Path('tests/output/dhcp.pcap.compact.json')
    assert p.exists()
    j = json.loads(p.read_text())
    cov = j['coverage_metrics']
    hc = cov['host_coverage']
    assert hc['num_hosts'] == 4
    assert hc['hosts_with_dhcp_evidence'] >= 1
