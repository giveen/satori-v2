import json
import os
import subprocess
import sys


def find_python():
    venv_py = os.path.join('.venv', 'bin', 'python')
    if os.path.exists(venv_py):
        return venv_py
    return sys.executable


def test_cli_emits_valid_json_and_provenance(tmp_path):
    py = find_python()
    out_path = tmp_path / 'out.json'
    cmd = [py, '-m', 'satori.cli', 'analyze', 'tests/data/dhcp.pcap', '--out', str(out_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    # stdout must be valid JSON
    payload = json.loads(proc.stdout)
    # ensure provenance present
    assert 'pcap_file' in payload
    # file path should match requested input (or be present)
    assert payload['pcap_file'] is not None
    # written file must exist and be valid JSON
    assert out_path.exists()
    written = json.load(open(out_path))
    assert isinstance(written, dict)
