import hashlib
import json
from pathlib import Path
import shutil
import pytest


def _round_floats(obj):
    if isinstance(obj, float):
        return round(obj, 3)
    if isinstance(obj, dict):
        return {k: _round_floats(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_round_floats(v) for v in obj]
    return obj


def canonical_json_bytes(obj) -> bytes:
    obj = _round_floats(obj)
    s = json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    return (s + "\n").encode("utf-8")


def canonicalize_file_bytes(path: Path) -> bytes:
    # if file contains NDJSON or JSON-lines, canonicalize per line
    raw = path.read_text(encoding="utf-8")
    parts = []
    for ln in raw.splitlines():
        try:
            obj = json.loads(ln)
        except Exception:
            parts.append((ln.rstrip() + "\n").encode("utf-8"))
            continue
        parts.append(canonical_json_bytes(obj))
    return b"".join(parts)


def sha1_bytes(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()


@pytest.mark.parametrize("pcap", sorted(Path("tests/data").glob("*.pcap*")))
def test_replay_live_regression(pcap: Path, tmp_path: Path, update_snapshots, capsys):
    """Run CLI replay for each PCAP and verify deterministic live outputs against snapshots.

    Produces per-host JSON snapshots and metrics in `tmp_path` and compares their
    canonicalized SHA1s to stored expected files in `tests/expected_live_snapshots`.
    Also compares canonicalized stdout against `tests/expected_live_stdout`.
    """
    from satori import cli

    if not pcap.exists():
        pytest.skip(f"Missing fixture {pcap}; skipping")

    outdir = tmp_path / "live_out"
    outdir.mkdir()

    argv = [
        "analyze",
        str(pcap),
        "--pcap-file",
        str(pcap),
        "--live-metrics",
        "--live-snapshot-dir",
        str(outdir),
        "--live-ndjson",
        "--live-stdout",
    ]

    # Run CLI and capture stdout
    cli.main(argv)
    captured = capsys.readouterr().out

    # Prepare expected dirs
    expected_snap = Path("tests/expected_live_snapshots")
    expected_stdout = Path("tests/expected_live_stdout")
    expected_snap.mkdir(exist_ok=True)
    expected_stdout.mkdir(exist_ok=True)

    # Collect produced files
    produced = sorted(outdir.glob("*"))

    # If update_snapshots, copy canonicalized produced files into expected dirs
    if update_snapshots:
        for f in produced:
            # canonicalize and write into expected dir preserving name
            data = canonicalize_file_bytes(f)
            (expected_snap / f.name).write_bytes(data)
        # also write stdout
        stdout_bytes = b"".join([
            canonicalize_file_bytes(Path(line)) if False else b""
            for line in []
        ])
        # canonicalize captured stdout lines
        parts = []
        for ln in captured.splitlines():
            try:
                parts.append(canonical_json_bytes(json.loads(ln)))
            except Exception:
                parts.append((ln.rstrip() + "\n").encode("utf-8"))
        stdout_bytes = b"".join(parts)
        (expected_stdout / f"{pcap.stem}__stdout.json").write_bytes(stdout_bytes)
        pytest.skip("Updated snapshots")

    # Otherwise, verify produced files match expected
    # For each expected file that matches this fixture stem, compare SHA1
    expected_files = sorted([p for p in expected_snap.glob(f"{pcap.stem}__*")])
    if not expected_files:
        pytest.skip(f"Missing expected snapshots for {pcap.name}; run with --update-snapshots to create")

    # Map produced names to their canonical bytes
    prod_map = {p.name: canonicalize_file_bytes(p) for p in produced}

    mismatches = []
    for ef in expected_files:
        name = ef.name
        expected_bytes = canonicalize_file_bytes(ef)
        prod_bytes = prod_map.get(name)
        if prod_bytes is None:
            mismatches.append((name, "missing-produced", None, None))
            continue
        if sha1_bytes(expected_bytes) != sha1_bytes(prod_bytes):
            mismatches.append((name, "sha-mismatch", sha1_bytes(prod_bytes), sha1_bytes(expected_bytes)))

    # Stdout comparison
    stdout_expected = expected_stdout / f"{pcap.stem}__stdout.json"
    if not stdout_expected.exists():
        pytest.skip(f"Missing expected stdout for {pcap.name}; run with --update-snapshots to create")
    # canonicalize captured stdout
    parts = []
    for ln in captured.splitlines():
        try:
            parts.append(canonical_json_bytes(json.loads(ln)))
        except Exception:
            parts.append((ln.rstrip() + "\n").encode("utf-8"))
    stdout_bytes = b"".join(parts)
    expected_stdout_bytes = canonicalize_file_bytes(stdout_expected)
    if sha1_bytes(stdout_bytes) != sha1_bytes(expected_stdout_bytes):
        mismatches.append((stdout_expected.name, "stdout-sha-mismatch", sha1_bytes(stdout_bytes), sha1_bytes(expected_stdout_bytes)))

    if mismatches:
        msg_lines = [f"Mismatches for fixture {pcap.name}:"]
        for name, reason, got, exp in mismatches:
            if reason == "missing-produced":
                msg_lines.append(f" - {name}: produced file missing")
            else:
                msg_lines.append(f" - {name}: {reason}: got {got} expected {exp}")
        pytest.fail("\n".join(msg_lines))
