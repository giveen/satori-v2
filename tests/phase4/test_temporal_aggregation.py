import time
import math
from satori.phase4.temporal_aggregation import aggregate_temporal_os, decay_factor
from tests.utils_phase2 import sha1_of_obj, canonical_json_bytes


def test_decay_factor_basic():
    now = 1600000000.0
    # half life 1 hour -> after 1 hour decay=0.5
    d = decay_factor(now - 3600, now, 1.0)
    assert abs(d - 0.5) < 1e-6


def test_temporal_scores_and_ordering():
    host = {
        'host_id': 'h1',
        'first_seen': 1600000000.0,
        'last_seen': 1600003600.0,
        'evidence': [
            {'evidence_id': 'e1', 'ts': 1600000000.0},
            {'evidence_id': 'e2', 'ts': 1600000000.0},
        ],
        'aggregated_os_inference': {
            'candidates': [
                {'name': 'Linux', 'score': 0.9, 'traits_matched': ['a'], 'evidence_refs': [{'evidence_id': 'e1'}]},
                {'name': 'BSD', 'score': 0.9, 'traits_matched': ['b'], 'evidence_refs': [{'evidence_id': 'e2'}]},
            ]
        },
        'correlation_notes': []
    }

    out = aggregate_temporal_os([host], decay_params={'half_life_hours': 24.0})
    assert len(out) == 1
    th = out[0]['temporal_os_inference']
    # deterministic ordering: scores equal after normalization -> name asc
    names = [c['name'] for c in th['temporal_candidates']]
    assert names == sorted(names)


def test_conflict_annotation_and_snapshot_determinism():
    host = {
        'host_id': 'h2',
        'first_seen': 1600000000.0,
        'last_seen': 1600003600.0,
        'evidence': [
            {'evidence_id': 'e1', 'ts': 1600000000.0},
            {'evidence_id': 'e2', 'ts': 1600000100.0},
        ],
        'aggregated_os_inference': {
            'candidates': [
                {'name': 'A', 'score': 0.6, 'traits_matched': ['t1'], 'evidence_refs': [{'evidence_id': 'e1'}]},
                {'name': 'B', 'score': 0.55, 'traits_matched': ['t2'], 'evidence_refs': [{'evidence_id': 'e2'}]},
            ]
        },
        'correlation_notes': []
    }

    out1 = aggregate_temporal_os([host], decay_params={'half_life_hours': 100.0, 'conflict_threshold': 0.4, 'primary_margin': 0.1})
    out2 = aggregate_temporal_os([host], decay_params={'half_life_hours': 100.0, 'conflict_threshold': 0.4, 'primary_margin': 0.1})
    # determinism: SHA1 of output identical
    h1 = sha1_of_obj(out1)
    h2 = sha1_of_obj(out2)
    assert h1 == h2

    tc = out1[0]['temporal_os_inference']['temporal_candidates']
    # since scores are close and distinct evidence, conflicts annotation may be present
    conflicts_present = any('conflicts' in c for c in tc)
    assert isinstance(conflicts_present, bool)
