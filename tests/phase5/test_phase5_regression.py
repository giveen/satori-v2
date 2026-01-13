import json
from pathlib import Path
import pytest

from satori.phase3.integration import integrate_phase3
from satori.phase4.temporal_aggregation import aggregate_temporal_os
from satori.phase4.correlation import correlate_hosts_temporal
from satori.phase5.report import build_phase5_summary
from tests.utils_phase2 import canonical_json_bytes, sha1_of_obj


FIXTURES_DIR = Path(__file__).parent.parent / 'data' / 'phase1_fixtures'
SNAP_DIR = Path(__file__).parent.parent / 'expected_phase5_snapshots'


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
def test_phase5_regression(fixture_path: Path, update_snapshots: bool):
    hosts = _load_fixture(fixture_path)
    if not hosts:
        pytest.skip(f"No hosts in fixture {fixture_path}")

    SNAP_DIR.mkdir(parents=True, exist_ok=True)

    # Run Phase3 integration
    out_phase3 = integrate_phase3(hosts)

    # Run Phase4 temporal aggregation
    out_temporal = aggregate_temporal_os(out_phase3)

    # Run correlation
    out_corr = correlate_hosts_temporal(out_temporal)

    # Phase5 summary builder expects captures list
    summary = build_phase5_summary([out_corr])

    by_id = {h.get('host_id') or f'host_{i}': h for i, h in enumerate(summary.get('hosts', []))}

    failures = []

    for hid, h in sorted(by_id.items()):
        # snapshot the full per-host summary object for regression
        block = h
        sha_current = sha1_of_obj(block)

        snap_path = SNAP_DIR / f"{_safe_name(fixture_path.stem)}__{_safe_name(hid)}.json"

        if update_snapshots:
            # overwrite existing snapshot when requested
            with snap_path.open('wb') as fh:
                fh.write(canonical_json_bytes(block))
        else:
            if not snap_path.exists():
                pytest.fail(f"Missing Phase5 snapshot for host {hid}: {snap_path}\nRun with --update-snapshots to create it.")
            with snap_path.open('rb') as fh:
                stored = json.loads(fh.read().decode('utf-8'))
            if sha1_of_obj(stored) != sha_current:
                failures.append(f"Mismatch for {hid}: stored={sha1_of_obj(stored)} current={sha_current}")

    # fixture-level metrics snapshot
    metrics_block = {'summary_metrics': summary.get('metrics', {})}
    metrics_snap = SNAP_DIR / f"{_safe_name(fixture_path.stem)}__metrics.json"
    if update_snapshots:
        with metrics_snap.open('wb') as fh:
            fh.write(canonical_json_bytes(metrics_block))
    else:
        if not metrics_snap.exists():
            pytest.fail(f"Missing Phase5 metrics snapshot for fixture {fixture_path.stem}: {metrics_snap}\nRun with --update-snapshots to create it.")
        with metrics_snap.open('rb') as fh:
            stored = json.loads(fh.read().decode('utf-8'))
        if sha1_of_obj(stored) != sha1_of_obj(metrics_block):
            failures.append(f"Metrics mismatch for fixture {fixture_path.stem}: stored={sha1_of_obj(stored)} current={sha1_of_obj(metrics_block)}")

    if failures:
        pytest.fail('\n'.join(failures))
