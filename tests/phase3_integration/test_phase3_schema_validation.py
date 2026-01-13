import json
from pathlib import Path
import pytest

from satori.phase3.integration import integrate_phase3

from src.satori.phase2 import __name__ as _unused


FIXTURES_DIR = Path(__file__).parent.parent / 'data' / 'phase1_fixtures'


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


@pytest.mark.parametrize('fixture_path', list(_iter_fixture_files()))
def test_phase3_schema_validation(fixture_path: Path):
    hosts = _load_fixture(fixture_path)
    if not hosts:
        pytest.skip(f"No hosts in fixture {fixture_path}")

    out = integrate_phase3(hosts)

    for h in out:
        assert 'os_inference' in h
        assert 'aggregated_os_inference' in h
        assert isinstance(h.get('correlation_notes'), list)

        agg = h['aggregated_os_inference']
        for c in agg.get('candidates', []):
            s = c.get('score')
            assert isinstance(s, float) or isinstance(s, int)
            assert 0.0 <= float(s) <= 1.0
            if float(s) > 0.1:
                # higher-than-baseline candidates should have traits
                assert c.get('traits_matched')
            # evidence refs exist
            for r in c.get('evidence_refs', []):
                assert 'evidence_id' in r
