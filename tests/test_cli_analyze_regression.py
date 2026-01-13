import json
from pathlib import Path
import pytest


def _canonical(obj):
    def _round(o):
        if isinstance(o, float):
            return round(o, 3)
        if isinstance(o, dict):
            return {k: _round(o[k]) for k in sorted(o.keys())}
        if isinstance(o, list):
            return [_round(x) for x in o]
        return o

    return json.dumps(_round(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@pytest.mark.parametrize("pcap", [Path("tests/data/dhcp.pcap")])
def test_cli_analyze_regression(pcap, tmp_path, monkeypatch, capsys, update_snapshots):
    from satori import cli

    if not pcap.exists():
        pytest.skip("missing pcap fixture")

    # change cwd so default ./satori-output writes into tmp_path
    monkeypatch.chdir(tmp_path)

    # Run CLI with default analyze (uses default profile)
    cli.main(["analyze", str(pcap.resolve()), "--pcap-file", str(pcap.resolve())])

    captured = capsys.readouterr()
    stdout = captured.out

    out_dir = tmp_path / "satori-output"
    bundle = {"stdout": stdout, "files": {}}
    if out_dir.exists():
        for f in sorted(out_dir.rglob("*")):
            rel = f.relative_to(out_dir)
            try:
                if f.suffix in (".json",):
                    bundle["files"][str(rel)] = json.loads(f.read_text(encoding="utf-8"))
                else:
                    bundle["files"][str(rel)] = f.read_text(encoding="utf-8")
            except Exception:
                bundle["files"][str(rel)] = f.read_bytes().decode("utf-8", errors="ignore")

    # Normalize any absolute pcap paths for determinism across tempdirs
    pcap_abs = str(pcap.resolve())
    def _sanitize(o):
        if isinstance(o, dict):
            return {k: _sanitize(v) for k, v in o.items()}
        if isinstance(o, list):
            return [_sanitize(x) for x in o]
        if isinstance(o, str):
            return o.replace(pcap_abs, "<PCAP_PATH>")
        return o

    bundle = _sanitize(bundle)
    canon = _canonical(bundle)

    expected_dir = Path(__file__).resolve().parent.parent / "tests/expected_phase9_snapshots"
    expected_dir.mkdir(parents=True, exist_ok=True)
    out_name = f"{pcap.stem}__analyze_bundle.json"

    if update_snapshots:
        (expected_dir / out_name).write_bytes(canon)
        pytest.skip("snapshots updated")

    if not (expected_dir / out_name).exists():
        pytest.skip("Missing expected analyze snapshot; run with --update-snapshots to create")

    exp = (expected_dir / out_name).read_bytes()
    assert json.loads(canon.decode("utf-8")) == json.loads(exp.decode("utf-8"))
