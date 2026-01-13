import json
import hashlib
from pathlib import Path
import pytest

from satori.phase3.integration import integrate_phase3
from tests.utils_phase2 import canonical_json_bytes, sha1_of_obj


FIXTURES_DIR = Path(__file__).parent.parent / 'data' / 'phase1_fixtures'
SNAP_DIR = Path(__file__).parent.parent / 'expected_phase3_snapshots'


def _iter_fixture_files():
    if not FIXTURES_DIR.exists():
        return []
    return sorted(FIXTURES_DIR.glob('*.json'))


def _load_fixture(path: Path):
    with path.open('r', encoding='utf-8') as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if 'hosts' in data and isinstance(data['hosts'], list):
            return data['hosts']
        hosts = [v for v in data.values() if isinstance(v, dict)]
        if hosts:
            return hosts
    raise RuntimeError(f"Unrecognized fixture shape in {path}")


def _safe_name(s: str) -> str:
    return ''.join(c if c.isalnum() or c in ('-', '_') else '_' for c in s)


@pytest.mark.parametrize('fixture_path', list(_iter_fixture_files()))
def test_phase3_cli_regression(fixture_path: Path, update_snapshots: bool):
    hosts = _load_fixture(fixture_path)
    if not hosts:
        pytest.skip(f"No hosts in fixture {fixture_path}")

    SNAP_DIR.mkdir(parents=True, exist_ok=True)

    # run integrate_phase3 twice and compare per-host aggregated blocks
    out1 = integrate_phase3(hosts)
    out2 = integrate_phase3(hosts)

    # map by host_id for deterministic checks
    by_id_1 = {h.get('host_id') or h.get('id') or f'host_{i}': h for i, h in enumerate(out1)}
    by_id_2 = {h.get('host_id') or h.get('id') or f'host_{i}': h for i, h in enumerate(out2)}

    failures = []

    for hid, h1 in sorted(by_id_1.items()):
        h2 = by_id_2.get(hid)
        assert h2 is not None

        block1 = {'aggregated_os_inference': h1.get('aggregated_os_inference'), 'correlation_notes': h1.get('correlation_notes')}
        block2 = {'aggregated_os_inference': h2.get('aggregated_os_inference'), 'correlation_notes': h2.get('correlation_notes')}

        sha1_1 = sha1_of_obj(block1)
        sha1_2 = sha1_of_obj(block2)

        snap_path = SNAP_DIR / f"{_safe_name(fixture_path.stem)}__{_safe_name(hid)}.json"

        if not snap_path.exists():
            if update_snapshots:
                with snap_path.open('wb') as fh:
                    fh.write(canonical_json_bytes(block1))
            else:
                pytest.fail(f"Missing snapshot for aggregated host {hid}: {snap_path}\nRun with --update-snapshots to create it.")
        else:
            with snap_path.open('rb') as fh:
                stored = json.loads(fh.read().decode('utf-8'))
            if sha1_of_obj(stored) != sha1_1:
                failures.append(f"Mismatch for {hid}: stored {sha1_of_obj(stored)} vs current {sha1_1}")

    if failures:
        pytest.fail('\n'.join(failures))
