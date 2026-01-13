import hashlib
import json
import shutil
from pathlib import Path
import pytest


@pytest.mark.parametrize("pcap", [Path("tests/data/dhcp.pcap")])
def test_cli_nmap_phase2_regression(pcap, tmp_path, update_snapshots):
    from satori import cli

    if not pcap.exists():
        pytest.skip("missing pcap fixture")

    out_path = tmp_path / f"{pcap.stem}__nmap_out.json"

    # Run CLI with Nmap lookup enabled and point it to the offline test DB
    cli.main([
        "analyze",
        str(pcap),
        "--pcap-file",
        str(pcap),
        "--use-nmap-db",
        "--nmap-db-path",
        "tests/data/nmap_test_db.json",
        "--out",
        str(out_path),
    ])

    expected_dir = Path("tests/expected_phase8_snapshots")
    expected_dir.mkdir(exist_ok=True)

    a_name = f"{pcap.stem}__phase2_nmap.json"

    produced = out_path.read_text(encoding="utf-8")

    def _canonical_bytes_from_text(text: str) -> bytes:
        obj = json.loads(text)

        def _round(o):
            if isinstance(o, float):
                return round(o, 3)
            if isinstance(o, dict):
                return {k: _round(o[k]) for k in sorted(o.keys())}
            if isinstance(o, list):
                return [_round(x) for x in o]
            return o

        return json.dumps(_round(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    b = _canonical_bytes_from_text(produced)

    if update_snapshots:
        (expected_dir / a_name).write_bytes(b)
        pytest.skip("snapshots updated")

    if not (expected_dir / a_name).exists():
        pytest.skip("Missing expected Phase8 snapshot; run with --update-snapshots to create")

    exp = (expected_dir / a_name).read_bytes()
    assert hashlib.sha1(b).hexdigest() == hashlib.sha1(exp).hexdigest()
