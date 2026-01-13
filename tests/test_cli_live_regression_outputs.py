import hashlib
import json
from pathlib import Path
import pytest


def _round_floats(obj):
    if isinstance(obj, float):
        return round(obj, 3)
    if isinstance(obj, dict):
        return {k: _round_floats(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_round_floats(v) for v in obj]
    return obj


def _canonical_line_bytes(line: str) -> bytes:
    """If line is JSON, canonicalize it; otherwise normalize whitespace."""
    try:
        obj = json.loads(line)
    except Exception:
        return (line.rstrip() + "\n").encode("utf-8")
    obj = _round_floats(obj)
    s = json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    return (s + "\n").encode("utf-8")


def _canonical_stdout_bytes(raw: str) -> bytes:
    parts = []
    for ln in raw.splitlines():
        parts.append(_canonical_line_bytes(ln))
    return b"".join(parts)


def _sha1_of_bytes(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()


@pytest.mark.parametrize("pcap", sorted(Path("tests/data").glob("*.pcap*")))
def test_cli_replay_stdout_regression(pcap, update_snapshots, capsys):
    from satori import cli

    # run replay once and capture stdout
    argv = ["analyze", str(pcap), "--pcap-file", str(pcap), "--live-stdout"]
    cli.main(argv)
    captured = capsys.readouterr().out

    # canonicalize and compute sha1
    canon = _canonical_stdout_bytes(captured)
    sha = _sha1_of_bytes(canon)

    # snapshot paths
    outdir = Path("tests/expected_live_stdout")
    outdir.mkdir(exist_ok=True)
    json_path = outdir / f"{pcap.stem}__stdout.json"
    txt_path = outdir / f"{pcap.stem}__stdout.txt"

    if update_snapshots:
        # write canonical bytes as canonical json-lines file
        with json_path.open("wb") as fh:
            fh.write(canon)
        pytest.skip("Snapshots updated")

    # If no snapshot exists, skip and instruct how to create it
    if not json_path.exists() and not txt_path.exists():
        pytest.skip(f"Missing snapshot for {pcap.name}; run tests with --update-snapshots to create")

    # prefer json snapshot if present
    use_path = json_path if json_path.exists() else txt_path
    existing = use_path.read_bytes()
    existing_sha = _sha1_of_bytes(existing)

    assert sha == existing_sha, (
        f"Stdout SHA1 mismatch for {pcap.name}: got {sha}, expected {existing_sha}.\n"
        "Run pytest --update-snapshots tests/test_cli_live_regression_outputs.py -q to refresh."
    )
