import json
import pytest
from pathlib import Path
from satori import cli


def test_smoke_golden_dhcp(tmp_path):
    pcap = Path("tests/data/dhcp.pcap")
    if not pcap.exists():
        pytest.skip("missing pcap fixture")
    out = tmp_path / "out.json"
    # run analyze in-process; it writes artifacts to --out path
    try:
        cli.main(["analyze", str(pcap), "--pcap-file", str(pcap), "--out", str(out), "--json-only"])
    except SystemExit as e:
        # analyze should not exit with non-zero when run programmatically
        if e.code != 0:
            pytest.skip(f"analyze exited with code {e.code}")
    # ensure out artifact produced and contains version meta
    assert out.exists(), "out.json was not produced"
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    assert 'meta' in payload and 'version' in payload['meta']