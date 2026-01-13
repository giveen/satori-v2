import subprocess
import json
import sys
from pathlib import Path


def test_cli_analyze_dhcp(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    pcap = repo / "tests" / "data" / "dhcp.pcap"
    assert pcap.exists(), f"Expected sample pcap at {pcap}"

    cmd = [sys.executable, "-m", "satori.cli", "analyze", str(pcap)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr

    # CLI prints a JSON-like dict to stdout; parse the last line
    out = proc.stdout.strip().splitlines()[-1]
    data = json.loads(out.replace("'", '"'))
    assert data.get("parsed", 0) > 0
    assert data.get("flows", 0) >= 0
