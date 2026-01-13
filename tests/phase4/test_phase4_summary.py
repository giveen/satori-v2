import json
from pathlib import Path
from satori.phase3.integration import integrate_phase3
from satori.phase4.temporal_aggregation import aggregate_temporal_os
from satori.phase4.correlation import correlate_hosts_temporal
from satori.phase4.report import build_phase4_summary
from tests.utils_phase2 import canonical_json_bytes, sha1_of_obj


FIXTURES_DIR = Path(__file__).parent.parent / 'data' / 'phase1_fixtures'


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


def test_phase4_summary_structure_and_determinism():
    fixtures = sorted(FIXTURES_DIR.glob('*.json'))
    if not fixtures:
        return
    hosts = _load_fixture(fixtures[0])

    out3 = integrate_phase3(hosts)
    temporal = aggregate_temporal_os(out3)
    correlated = correlate_hosts_temporal(temporal)
    summary = build_phase4_summary(correlated)

    # structural checks
    assert 'hosts' in summary and isinstance(summary['hosts'], list)
    assert 'metrics' in summary and isinstance(summary['metrics'], dict)

    # determinism: build again and compare sha1
    summary2 = build_phase4_summary(correlated)
    assert sha1_of_obj(summary) == sha1_of_obj(summary2)
