import json
import os
import subprocess
import sys
from pathlib import Path


def find_python():
    venv_py = os.path.join('.venv', 'bin', 'python')
    if os.path.exists(venv_py):
        return venv_py
    return sys.executable


def _run_summary(py):
    cmd = [py, 'scripts/pcap_summary.py']
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def _sha1_for_compacts():
    import hashlib

    out = []
    for p in sorted(Path('tests/output').glob('*.compact.json')):
        h = hashlib.sha1(p.read_bytes()).hexdigest()
        out.append((str(p), h))
    return out


def test_pcap_summary_deterministic_and_schema(tmp_path):
    py = find_python()
    # run twice
    rc1, _, err1 = _run_summary(py)
    assert rc1 == 0, err1
    sha1_a = _sha1_for_compacts()
    rc2, _, err2 = _run_summary(py)
    assert rc2 == 0, err2
    sha1_b = _sha1_for_compacts()
    assert sha1_a == sha1_b, 'compact JSON outputs changed between runs'

    # Basic schema checks: each compact json must include pcap_file and hosts with required fields
    for p, _ in sha1_a:
        j = json.loads(Path(p).read_text())
        assert 'pcap_file' in j
        assert 'num_hosts' in j
        assert 'hosts' in j and isinstance(j['hosts'], list)
        for h in j['hosts']:
            assert 'host_id' in h
            assert 'ips' in h
            assert 'macs' in h
            assert 'tcp_fingerprint' in h
            assert 'ssh_fingerprint' in h
            # confidence fields should be present (may be None or numeric)
            assert 'evidence_count' in h
