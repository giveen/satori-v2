# Phase 4 Design: Temporal Aggregation & Weighted Correlation

Status: in-progress

Purpose
-------
Phase 4 extends Phase 3 by adding time-awareness and stronger, weighted correlation across hosts and observations. The goal is to produce time-aware aggregated OS inferences that: (1) combine evidence across captures and time windows, (2) compute robust correlation/confidence scores between hosts, and (3) preserve deterministic provenance back to Phase 1–3 evidence.

High-level goals
- Add temporal aggregation (sliding windows / observation intervals) and evidence decay
- Compute weighted host-to-host correlation using trait overlap, evidence confidence and protocol weighting
- Detect conflicts and ambiguous inferences and annotate aggregated outputs
- Preserve deterministic, explainable outputs with full provenance mapping

Inputs & Outputs
------------------
Inputs (from Phase 3)
- Per-host output objects produced by Phase 3: each host includes `os_inference` (Phase 2 per-capture), `aggregated_os_inference` (Phase 3 per-aggregation_id), and `correlation_notes`.
- Each candidate and evidence entry must include `evidence_refs` (SHA1 IDs) linking back to Phase 1 evidence.

Outputs (Phase 4)
- `time_aware_aggregations`: list of aggregated blocks keyed by `aggregation_id` and time window.
- `correlated_hosts`: per-host list of correlated peers with `correlation_score`, `shared_traits`, `shared_evidence_refs` and `time_window`.
- `temporal_candidates`: for each host/time window, candidates with weighted time-decayed scores and `provenance` linking to evidence_refs.
- `conflict_annotations`: per-host/per-window flags with explanatory `conflict_reasons`.

Data Models (examples)
----------------------
Example: time-aware aggregation block

```json
{
  "aggregation_id": "mac:aabbcc001122",
  "time_window": {"start": "2025-12-01T00:00:00Z","end": "2025-12-01T06:00:00Z"},
  "temporal_candidates": [
    {"name": "Linux 5.x","score": 0.842,"support_count": 5,
     "provenance": {"evidence_refs": ["sha1...","sha1..."], "protocols_seen": ["ssh","tcp"]}},
    {"name": "OpenBSD","score": 0.123,"support_count": 1,"provenance": {"evidence_refs": ["sha1..."],"protocols_seen": ["tcp"]}}
  ],
  "members": ["host-A","host-B"],
  "metadata": {"generation_time": "2026-01-10T12:00:00Z","evidence_count": 6}
}
```

Example: correlated host entry

```json
{
  "host_id": "host-A",
  "peer_id": "host-B",
  "time_window": {"start": "2025-12-01T00:00:00Z","end": "2025-12-01T06:00:00Z"},
  "correlation_score": 0.78,
  "shared_traits": ["tcp_isn_behavior","ssh_banner_fingerprint"],
  "shared_evidence_refs": ["sha1...","sha1..."],
  "explanation": "High trait overlap weighted by evidence confidence and protocol weights"
}
```

Algorithms
----------
All formulas and algorithms must be deterministic and reproducible given the same inputs and parameters.

1) Temporal aggregation
- Approach: partition observations by fixed-size windows or event-driven intervals (configurable). Windows may be overlapping (sliding) or disjoint.
- Window parameters: `window_size` (e.g., 6h), `stride` (e.g., 1h), `min_evidence_threshold`.
- Evidence decay: each evidence item is weighted by an exponential decay function as a function of age relative to window end:

  decay(t) = exp(-ln(2) * t / half_life)

  where `t` is time difference in hours and `half_life` is a configurable parameter (e.g., 72 hours). This creates continuous, deterministic attenuation for older evidence.

- Per-window candidate score aggregation: for each candidate name c, compute

  score_c = normalize( sum_{e in evidence_for_c} (e.confidence * protocol_weight(p_e) * decay(t_e)) )

  where `e.confidence` is the evidence-level confidence (from Phase 2), `protocol_weight(p_e)` comes from signature table (existing `src/signatures/v1.json`), and `decay(t_e)` is as above. Normalization divides by sum of weighted supports or by max across candidates — choose a stable deterministic strategy (we recommend dividing by max_raw_score so scores in [0,1]).

2) Weighted correlation
- Trait overlap: compute a weighted Jaccard-like similarity where trait contributions are weighted by trait importance (e.g., signature match weight) and by evidence confidences:

  weighted_intersection = sum_{trait in intersection} w_trait * min(sum_conf_trait_hostA, sum_conf_trait_hostB)
  weighted_union = sum_{trait in union} w_trait * max(sum_conf_trait_hostA, sum_conf_trait_hostB)
  trait_similarity = weighted_intersection / weighted_union

- Evidence overlap: compute Jaccard on evidence_refs (SHA1), optionally weighted by per-evidence confidence.
- Combined correlation score: convex combination

  correlation_score = alpha * trait_similarity + beta * evidence_jaccard + gamma * temporal_proximity_score

  with alpha+beta+gamma = 1.0 (configurable). `temporal_proximity_score` favors hosts with overlapping windows and more recently shared evidence (also computed deterministically via decay weights).

3) Conflict detection & resolution
- A host-window is marked `conflicting` if two (or more) candidates exceed `conflict_threshold` (e.g., both > 0.4) and their proof sets have disjoint strong evidence (low evidence overlap) and differing high-confidence traits.
- Resolution rules (deterministic):
  - If one candidate has >= primary_margin (e.g., 0.15) higher score than the next, mark winner and annotate loser(s).
  - If scores are within margin and evidence sets overlap < overlap_threshold, mark `multi_host_conflict` and preserve both candidates with `conflict_reasons` listing evidence_refs and traits.

Determinism & Provenance
------------------------
- No randomness: all operations are pure functions of inputs and configuration parameters.
- Canonical ordering: sort lists deterministically before serialization. Use orders such as:
  - candidates: (score DESC, support_count DESC, name ASC)
  - evidence_refs: sort by SHA1 ascending
  - correlation lists: (correlation_score DESC, peer_id ASC)
- Rounding: round floats to 3 decimal places before final serialization for snapshot stability.
- Evidence IDs: use SHA1 of canonical JSON of evidence (already present from Phase 2). Include these `evidence_refs` verbatim in outputs for traceability.
- Provenance mapping: each aggregated candidate must include `provenance.evidence_refs`, `provenance.members` (list of host IDs contributing), and optionally `provenance.protocols_seen`.

Schemas (summary)
------------------
- `TimeAwareAggregation` (JSON Schema sketch)

```json
{
  "type": "object",
  "properties": {
    "aggregation_id": {"type": "string"},
    "time_window": {"type": "object"},
    "temporal_candidates": {"type": "array"},
    "members": {"type": "array"}
  },
  "required": ["aggregation_id","time_window","temporal_candidates"]
}
```

Testing Strategy
----------------
Unit tests
- Test decay function correctness and boundary cases.
- Test per-window scoring using synthetic phase3 fixture inputs with known evidence confidence and protocol weights.
- Test weighted correlation math (trait_similarity, evidence_jaccard) with small, deterministic examples.

Regression tests & snapshots
- Build canonical Phase 4 fixtures derived from canonical Phase 3 snapshots. Provide `--update-snapshots` flag for local snapshot generation.
- For each fixture, produce deterministic JSON summary and assert SHA1 matches stored snapshot (same strategy used in Phase 2/3).

Schema validation
- Add JSON Schema tests to assert output shape and required provenance fields.

CI Considerations
-----------------
- Add pre-test check to ensure Phase 4 fixture snapshots exist (fail-fast), similar to Phase 3.
- Add pipeline stage for Phase 4 tests; ensure reproducible Python environment.
- Keep `--update-snapshots` local-only; CI must not auto-update snapshots.

Operational Parameters & Tuning
-------------------------------
Configurable parameters (defaults recommended):
- `window_size_hours`: 6
- `window_stride_hours`: 1
- `evidence_half_life_hours`: 72
- `protocol_weights`: reuse `src/signatures/v1.json`
- `alpha,beta,gamma` for correlation score: default (0.6, 0.3, 0.1)
- `conflict_threshold`: 0.4
- `primary_margin`: 0.15

Add a `phase4_config.json` to place defaults and allow reproducible runs.

Implementation notes
--------------------
- Add a new package `src/satori/phase4/` with modules:
  - `temporal.py` — windowing, decay functions, per-window candidate aggregation
  - `correlation.py` — trait & evidence similarity, combined correlation score
  - `schema.py` — JSON Schema definitions and validators
  - `integration.py` — orchestration, CLI hooks and `--phase4-summary` flag
- Reuse Phase 2/3 utilities: canonical JSON, SHA1 helpers, protocol weights.
- Keep outputs additive: do not modify Phase 1/2/3 artifacts — produce new `phase4` objects.

Next steps (actionable)
-----------------------
1. Create `docs/phase4_design.md` (this document) — complete.
2. Add `phase4_config.json` with defaults and parameter validation.
3. Implement core `temporal.py` and unit tests for decay and windowing.
4. Implement `correlation.py` with deterministic weighted similarity tests.
5. Add integration CLI flags and regression snapshot tests.
6. Wire CI pre-test snapshot checks and run Phase 4 tests under the same matrix.

References
----------
- Phase 2/3 modules and helpers: `src/satori/phase2/`, `src/satori/phase3/`
- Existing signature table: `src/signatures/v1.json`

Appendix: formulas recap
- decay(t) = exp(-ln(2) * t / half_life)
- score_c = normalize( sum_e (e.confidence * protocol_weight * decay(t_e)) )
- trait_similarity = weighted_intersection / weighted_union
- correlation_score = alpha*trait_similarity + beta*evidence_jaccard + gamma*temporal_proximity
