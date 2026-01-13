import os
import json
from pathlib import Path
import pytest

from satori.phase2.os_inference import build_os_inference
from tests.utils_phase2 import canonical_json_bytes, sha1_of_obj


FIXTURES_DIR = Path(__file__).parent / 'data' / 'phase1_fixtures'
SNAP_DIR = Path(__file__).parent / 'expected_os_snapshots'


def _iter_fixture_files():
    if not FIXTURES_DIR.exists():
        return []
    return sorted(FIXTURES_DIR.glob('*.json'))


def _safe_name(s: str) -> str:
    return ''.join(c if c.isalnum() or c in ('-', '_') else '_' for c in s)


def _load_fixture(path: Path):
    with path.open('r', encoding='utf-8') as fh:
        data = json.load(fh)
    # Accept list of hosts or dict mapping
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # common shapes: {'hosts': [...]} or mapping of id->host
        if 'hosts' in data and isinstance(data['hosts'], list):
            return data['hosts']
        # fallback: treat values that are dicts as hosts
        hosts = [v for v in data.values() if isinstance(v, dict)]
        if hosts:
            return hosts
    raise RuntimeError(f"Unrecognized fixture shape in {path}")


def test_snapshot_regression(update_snapshots: bool):
    fixture_paths = _iter_fixture_files()
    if not fixture_paths:
        pytest.skip(f"No fixtures found in {FIXTURES_DIR}")

    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    failures = []

    for fixture_path in fixture_paths:
        hosts = _load_fixture(fixture_path)

        for idx, host in enumerate(hosts):
            host_id = host.get('host_id') or host.get('id') or f'host_{idx}'
            fname = f"{_safe_name(fixture_path.stem)}__{_safe_name(str(host_id))}.json"
            snap_path = SNAP_DIR / fname

            os_inference = build_os_inference(host)
            # verify required schema/version fields
            assert 'os_inference_schema_version' in os_inference
            assert 'signature_table_version' in os_inference

            cur_bytes = canonical_json_bytes(os_inference)
            cur_sha = sha1_of_obj(os_inference)

            if not snap_path.exists():
                if update_snapshots:
                    with snap_path.open('wb') as fh:
                        fh.write(cur_bytes)
                    continue
                else:
                    pytest.fail(f"Missing snapshot for host {host_id}: {snap_path}\nRun with --update-snapshots to create it.")

            # load stored snapshot and compare SHA1
            with snap_path.open('rb') as fh:
                stored_bytes = fh.read()
            try:
                stored_obj = json.loads(stored_bytes.decode('utf-8'))
            except Exception:
                pytest.fail(f"Stored snapshot {snap_path} is not valid JSON")

            stored_sha = sha1_of_obj(stored_obj)
            if stored_sha != cur_sha:
                # build readable diff info
                def _summaries(o):
                    return {c['name']: c.get('score') for c in (o.get('candidates') or [])}

                cur_s = _summaries(os_inference)
                stored_s = _summaries(stored_obj)

                msg = (
                    f"Snapshot mismatch for host {host_id} (fixture {fixture_path.name})\n"
                    f"Stored SHA1: {stored_sha}\n"
                    f"Current SHA1: {cur_sha}\n"
                    f"Stored candidates and scores: {stored_s}\n"
                    f"Current candidates and scores: {cur_s}\n"
                    f"To update snapshots run: pytest --update-snapshots tests/test_phase2_snapshot_regression.py -q"
                )
                failures.append(msg)

    if failures:
        pytest.fail('\n\n'.join(failures))
