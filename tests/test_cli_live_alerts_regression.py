import hashlib
import json
from pathlib import Path
import pytest


@pytest.mark.parametrize("pcap", [Path("tests/data/dhcp.pcap")])
def test_cli_live_alerts_regression(pcap, tmp_path, update_snapshots):
    from satori import cli

    if not pcap.exists():
        pytest.skip("missing pcap fixture")

    snap_dir = tmp_path / "alerts"

    # Run CLI in replay/live mode with live alerts enabled
    cli.main([
        "analyze",
        str(pcap),
        "--pcap-file",
        str(pcap),
        "--live-alerts",
        "--alert-snapshot-dir",
        str(snap_dir),
        "--alert-ndjson",
        "--out",
        str(tmp_path / "out.json"),
    ])

    # Collect produced artifacts
    files = []
    if snap_dir.exists():
        for p in sorted(snap_dir.iterdir()):
            if p.name.startswith(pcap.stem + "__alerts"):
                files.append(p)

    bundle = {}
    for f in files:
        if f.suffix == ".json":
            try:
                obj = json.loads(f.read_text(encoding="utf-8"))
            except Exception:
                # maybe binary canonical bytes
                obj = f.read_bytes().decode("utf-8", errors="ignore")
            bundle[f.name] = obj
        elif f.suffix == ".ndjson":
            lines = [json.loads(l) for l in f.read_text(encoding="utf-8").splitlines() if l.strip()]
            bundle[f.name] = lines
        else:
            bundle[f.name] = f.read_text(encoding="utf-8")

    # canonicalize bundle
    def _round(o):
        if isinstance(o, float):
            return round(o, 3)
        if isinstance(o, dict):
            return {k: _round(o[k]) for k in sorted(o.keys())}
        if isinstance(o, list):
            return [_round(x) for x in o]
        return o

    canon = json.dumps(_round(bundle), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    expected_dir = Path("tests/expected_phase9_snapshots")
    expected_dir.mkdir(exist_ok=True)
    out_name = f"{pcap.stem}__alerts_bundle.json"

    if update_snapshots:
        (expected_dir / out_name).write_bytes(canon)
        pytest.skip("snapshots updated")

    if not (expected_dir / out_name).exists():
        pytest.skip("Missing expected Phase9 snapshot; run with --update-snapshots to create")

    exp = (expected_dir / out_name).read_bytes()
    assert hashlib.sha1(canon).hexdigest() == hashlib.sha1(exp).hexdigest()
