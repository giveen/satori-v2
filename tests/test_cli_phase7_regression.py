import hashlib
import json
import shutil
from pathlib import Path
import pytest


def _canonical_bytes_from_text(text: str) -> bytes:
    # assume text is JSON content; ensure canonical formatting
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


@pytest.mark.parametrize("pcap", sorted(Path("tests/data").glob("*.pcap*")))
def test_phase7_replay_snapshots(pcap, tmp_path, update_snapshots):
    from satori import cli
    if not pcap.exists():
        pytest.skip("missing pcap fixture")

    outdir = tmp_path / "phase7_out"
    outdir.mkdir()

    cli.main(["analyze", str(pcap), "--pcap-file", str(pcap), "--live-snapshot-dir", str(outdir), "--snapshot-batch-size", "1", "--phase7-anomalies"])

    expected_dir = Path("tests/expected_phase7_snapshots")
    expected_dir.mkdir(exist_ok=True)

    a_name = f"{pcap.stem}__anomalies.json"
    m_name = f"{pcap.stem}__anomalies_metrics.json"

    produced_a = outdir / a_name
    produced_m = outdir / m_name

    if update_snapshots:
        shutil.copy(produced_a, expected_dir / a_name)
        shutil.copy(produced_m, expected_dir / m_name)
        pytest.skip("snapshots updated")

    if not (expected_dir / a_name).exists() or not (expected_dir / m_name).exists():
        pytest.skip(f"Missing expected Phase7 snapshots for {pcap.name}; run with --update-snapshots to create")

    exp_a = (expected_dir / a_name).read_text(encoding="utf-8")
    exp_m = (expected_dir / m_name).read_text(encoding="utf-8")

    prod_a = produced_a.read_text(encoding="utf-8")
    prod_m = produced_m.read_text(encoding="utf-8")

    assert hashlib.sha1(_canonical_bytes_from_text(prod_a)).hexdigest() == hashlib.sha1(_canonical_bytes_from_text(exp_a)).hexdigest()
    assert hashlib.sha1(_canonical_bytes_from_text(prod_m)).hexdigest() == hashlib.sha1(_canonical_bytes_from_text(exp_m)).hexdigest()
