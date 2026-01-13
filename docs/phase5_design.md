# Phase 5 Design: Historical Trends, Anomaly Detection & Provenance-first Alerts

Status: proposed / ready for implementation

Scope
-----
Phase 5 builds on Phase 1–4 outputs and produces actionable, provenance-preserving, deterministic metrics and alerts:
- Multi-host temporal trends (OS and protocol prevalence over time windows)
- Per-host and per-fleet anomaly flags with evidence_refs explaining the reasons
- Historical correlation maps showing evolving relationships between hosts
- Compact CI-ready `phase5_summary` JSON for regression and human inspection

Design Principles
-----------------
- Additive: never mutate Phase 1–4 artifacts; Phase 5 emits new objects.
- Provenance-first: every metric/flag must include `evidence_refs` (SHA1) pointing back to Phase 1 canonical evidence.
- Deterministic: sorted lists, floats rounded to 3 decimals, no RNG or external I/O.
- Snapshot-friendly: compact JSON with canonical serialization for SHA1 regression tests.

High-level pipeline (T1→T5)
- T1 Historical aggregation: assemble a time-ordered store per host of Phase 1–4 observations (candidates, evidence_refs, timestamps).
- T2 Trend computation: windowed aggregation (sliding windows), decay-weighted scoring, per-window prevalence for OS/protocols.
- T3 Anomaly detection: run heuristics on windows and deltas to flag anomalies with evidence_refs and explanations.
- T4 Phase5 report builder: produce per-host and aggregate `phase5_summary` JSON with trends, anomalies, and SHA1 checks.
- T5 Tests & CI: unit tests for math & heuristics, regression snapshot tests with `--update-snapshots`, CI precheck for Phase5 snapshots.

Data models & schemas
---------------------
Key inputs (read-only): Phase 3/4 host objects with fields such as:
- `host_id`, `macs`, `os_inference`, `aggregated_os_inference`, `temporal_os_inference`, `correlated_os_inference`, `correlation_notes`, `evidence` (Phase 1 canonical dicts with timestamps).

Primary outputs (Phase 5): `phase5_summary` (per-fixture) and per-host `phase5_metrics` blocks.

Example per-host `phase5_metrics` snippet:

```json
{
  "host_id": "host-A",
  "temporal_trend_metrics": [
    {"window": {"start": "2025-12-01T00:00:00Z","end":"2025-12-01T06:00:00Z"},
     "os_prevalence": [{"name":"Linux","score":0.842,"evidence_refs":["sha1...","sha1..."]}],
     "protocol_coverage": {"tcp":10,"ssh":2},
     "evidence_density": 12
    }
  ],
  "anomaly_flags": [
    {"name":"conflicting_os_signals","severity":"medium","evidence_refs":["sha1..."],"explanation":"Two high-confidence candidates with disjoint evidence in same window"}
  ],
  "historical_correlation": [
    {"peer_id":"host-B","time_window":{"start":"...","end":"..."},"similarity":0.78,"shared_evidence_refs":["sha1..."]}
  ]
}
```

Aggregate `phase5_summary` (fixture-level):
- `num_hosts`, `hosts_with_anomalies`, `os_adoption_over_time` (series of counts or normalized scores), `protocol_trends`, `evidence_density_stats` (mean/max), `sha1` checksum of report.

Algorithms & formulas
---------------------
Canonical choices (deterministic, tunable):

1) Windowing & decay
- Windows: fixed-size sliding windows parameterized by `window_size_hours` and `stride_hours`.
- For evidence with timestamp t, reference to window W ending at T_end, compute age a=(T_end - t)/3600.
- Decay: exponential decay as used previously: decay(a) = exp(-ln(2) * a / half_life_hours).

2) OS / protocol prevalence per window
- For each OS label c in window W, compute raw support:

  raw_support_c = sum_{e in evidence_for_c_in_W} (e.confidence * protocol_weight(p_e) * decay(age_e))

- Window prevalence normalized to [0,1] by dividing by max raw_support across labels in the same window.

3) Time-series aggregation
- For each host or fleet, emit a time-ordered series of prevalence vectors sampled per-window.
- For fleet-wide OS adoption, sum host-level prevalence weights (or count hosts where label score > threshold).

4) Anomaly heuristics (deterministic rules)
- Conflicting OS signals: in a single window, if two candidates both have normalized score >= conflict_threshold (e.g., 0.4) and evidence overlap (Jaccard on evidence_refs) < overlap_threshold (e.g., 0.25), flag `conflicting_os_signals` with evidence_refs = union of both candidates' evidence_refs.
- Sudden evidence density spike: if evidence_count_in_window >= mean_recent*spike_factor (e.g., 3× mean over past N windows) and >= min_count, flag `evidence_spike`.
- Protocol anomaly: if a protocol's per-host rate (e.g., SSH flows) increases > threshold relative to baseline, flag `protocol_spike` with evidence_refs of most recent flows.
- Suspicious trait deviation: if trait value deviates from correlated peers' consensus (e.g., SSH banner differs while peers share same banner), flag `trait_deviation`.

Each flag includes severity (low/medium/high), deterministic explanation text, and `evidence_refs` (sorted SHA1 list).

Determinism & canonicalization
-------------------------------
- Prior to any hashing/serializing, round floats to 3 decimals.
- Sort lists deterministically:
  - candidates: (score DESC, evidence_count DESC, name ASC)
  - evidence_refs: SHA1 ascending
  - time-series windows: chronological
- When emitting the `phase5_summary`, include a `sha1` field computed from canonical JSON bytes (sorted keys, compact separators) to enable regression checks.

Testing & CI
------------
Unit tests
- Tests for decay function, windowing, prevalence math, and each anomaly heuristic with small deterministic inputs.

Regression tests
- Produce canonical Phase 5 snapshots under `tests/expected_phase5_snapshots/` named `<fixture>__<host_id>.json` and fixture-level `__metrics.json` files.
- Regression harness supports `--update-snapshots` for local snapshot generation.

CI integration
- Add a pre-test CI job to verify presence of Phase 5 snapshots (fail-fast with missing list).
- Run Phase 5 regression tests as part of the test matrix after Phase 1–4 checks.

Implementation plan (T1→T6 deliverables)
---------------------------------------
- T1: `src/satori/phase5/historical.py` — collect time-ordered observations per host, normalizing timestamps and mapping evidence_refs to canonical SHA1.
- T2: `src/satori/phase5/trends.py` — windowing & prevalence math, protocol coverage counts.
- T3: `src/satori/phase5/anomalies.py` — deterministic heuristics returning flags with evidence_refs.
- T4: `src/satori/phase5/report.py` — compose `phase5_summary` per-host and aggregate outputs; provide `build_phase5_summary(hosts)` API and small CLI hook.
- T5: `tests/phase5/` — unit tests for functions and regression harness mirroring Phase 4 structure.
- T6: `docs/phase5_design.md` (this file) plus governance notes for snapshot updates and parameter tuning.

Configuration & parameters
--------------------------
Place defaults in `src/satori/phase5/phase5_config.json` with keys:
- `window_size_hours`, `stride_hours`, `half_life_hours`, `conflict_threshold`, `overlap_threshold`, `spike_factor`, `baseline_window_count`.

Operational notes
-----------------
- All Phase 5 outputs are additive; CLI flags like `--phase5-summary` and `--out-summary-5` will produce reports without changing prior data.
- Avoid heavy memory growth: implement windowed on-disk or streaming aggregation when processing many hosts (out-of-scope for initial implementation but documented in T4 notes).

Next steps (actionable)
-----------------------
1. Add `phase5_config.json` and minimal `src/satori/phase5/__init__.py`.
2. Implement `historical.py` and `trends.py` with unit tests for windowing & decay.
3. Implement `anomalies.py` heuristics and unit tests for each flag.
4. Implement `report.py` with canonical JSON serialization and SHA1 snapshot generation helper.
5. Add regression harness under `tests/phase5/test_phase5_regression.py` and update CI to check snapshots.

Acceptance criteria
-------------------
- All Phase 5 outputs deterministic and additive.
- Unit tests for math and heuristics pass.
- Regression tests produce stable SHA1s and CI verifies snapshot presence.
