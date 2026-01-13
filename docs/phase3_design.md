# Phase 3 Design — Aggregation & Cross-Host Correlation

Status: draft

Purpose
-------
Phase 3 expands Phase 2 OS inference by deterministically aggregating per-host OS hypotheses across multiple PCAPs/flows and correlating hosts that likely represent the same physical device. Phase 3 must use only Phase 1 and Phase 2 outputs (no active probing, no ML), preserve determinism and provenance, and produce explainable, audit-ready JSON.

Inputs
------
- Phase 1 compact host JSONs (`*.compact.json`) containing `evidence` lists and `protocols_seen` metadata.
- Phase 2 `os_inference` blocks produced per-host containing `candidates`, `evidence_refs`, `traits_matched`, `metadata`, and `explanation`.

High-level outputs
------------------
- Per-host aggregated `os_inference` (multi-PCAP-aware) that consolidates evidence across captures.
- Cross-host correlation annotations marking likely same-device groups and ambiguity flags.
- Extended provenance that preserves pointers into the original Phase 1 evidence objects.

Design goals & constraints
-------------------------
- Deterministic: same inputs → byte-identical outputs.
- Explainable: every aggregated candidate decomposes into contributing Phase 2 candidates and their evidence_refs.
- Non-destructive: do not modify Phase 1 or Phase 2 original files; produce new aggregated artifacts.
- No external network calls or probabilistic models.

Core concepts
-------------
- Source host: a host object produced for a capture (Phase 1 compact host).
- Source `os_inference`: the Phase 2 inference block attached to a source host.
- Aggregated host: a grouping keyed by a deterministic `aggregation_id` (see below) representing either a single logical host aggregated across captures or a cluster of correlated source hosts.

Aggregation identifiers
-----------------------
- `aggregation_id` is deterministic and constructed from available stable host attributes in this order (first available):
  1. MAC address (canonicalized lowercase, punctuation removed): `mac:<value>`
  2. Persistent host id from Phase 1 if present: `hostid:<value>`
  3. IP + observed network (fall-back): `ip:<addr>` + capture-id
  4. If none present, a deterministic hash of sorted evidence_ids: `evidencehash:<sha1>`

Multi-PCAP Aggregation rules
---------------------------
1. Group source hosts by `aggregation_id`.
2. For each group, collect all source `os_inference.candidates` and all `evidence_refs` (preserve the original `pointer` plus `source_host_id` and `capture_id`).
3. For each unique OS name across group members compute an aggregated raw contribution:

   aggregated_raw(OS) = sum_{s in sources} sum_{c in s.candidates where c.name==OS} (c.score * coverage_factor_s * w_source)

   - `c.score` is Phase 2 candidate `score` (already normalized/final). 
   - `coverage_factor_s` is copied from source `metadata.protocol_coverage` & protocol_count influence (use Phase 2 coverage factor if available). 
   - `w_source` is a deterministic source weight reflecting the evidence volume and quality: w_source = min(1.0, 0.5 + 0.5 * evidence_density_s)

4. Compute aggregated_max_possible(OS) = sum over sources of 1.0 (because `c.score` ∈ [0,1]), used for normalization.
5. Normalize: aggregated_normalized(OS) = aggregated_raw(OS) / (aggregated_max_possible(OS) + EPS), clamp to [0,1].
6. Apply cross-host ambiguity penalties: if group contains conflicting high-scoring OS candidates across different hardware fingerprints (e.g., divergent `traits_matched` with disjoint evidence sets), reduce normalized score by penalty P_conflict (deterministic formula below).
7. Final aggregated score = aggregated_normalized × group_coverage_factor × (1 - total_group_ambiguity_penalty).

Group coverage factor
---------------------
- Compute group protocol coverage as sorted union of all `protocols_seen` across sources.
- group_coverage_factor = min(1.0, 0.25 + 0.75 * min(total_unique_protocols / 3.0, 1.0)) × (0.9 + 0.1 * min(avg_evidence_density, 1.0))

Cross-host correlation (same-device detection)
----------------------------------------------
Deterministic heuristics to mark source hosts as likely same physical device (do NOT merge host IDs; only annotate):

- Rule A (MAC exact): identical MAC -> strongly linked.
- Rule B (Evidence overlap): Jaccard similarity of evidence_id sets ≥ 0.6 -> linked.
- Rule C (Trait fingerprint similarity): cosine-like overlap of trait sets where weighted trait matches align (score-weighted intersection) ≥ 0.7 -> linked.

Link strength is numeric in [0,1], deterministic, and computed as a weighted average of Rule A/B/C contributions. Pairs above threshold (e.g., ≥ 0.75) assigned to same `aggregation_id` group.

Ambiguity detection & flags
---------------------------
- For each aggregated group compute:
  - `multi_host_conflict`: true if multiple sources offer different top OS names with final scores ≥ 0.6 and evidence sets are disjoint.
  - `likely_shared_device`: true if link strength suggests NAT/shared IP or device clustering.

Extended provenance & explainability
-----------------------------------
- Aggregated candidates include:
  - `name`: OS name
  - `score`: aggregated final score (rounded)
  - `sources`: list of source host references contributing to this candidate with per-source contribution
  - `evidence_refs`: flattened list of evidence refs, each annotated with `source_host_id`, `capture_id`, original `pointer`, and `contribution`
  - `traits_matched`: union of trait strings across contributing sources
  - `conflicts`: list of conflicting OS names and deterministic conflict reasons

Example aggregated candidate (schema excerpt)

```
{
  "name": "Ubuntu",
  "score": 0.732,
  "traits_matched": ["ssh:kex:curve255...","tcp:ttl:64"],
  "sources": [
    {"source_host_id":"a1","capture_id":"pcap-2025-01","contribution":0.42},
    {"source_host_id":"b2","capture_id":"pcap-2025-02","contribution":0.31}
  ],
  "evidence_refs": [
    {"evidence_id":"<sha1>","source_host_id":"a1","capture_id":"pcap-2025-01","trait":"tcp:ttl:64","contribution":0.21,"pointer":[...]} 
  ],
  "conflicts": []
}
```

Deterministic ordering rules
----------------------------
- Candidates sorted by (score DESC, number_of_evidence_refs DESC, name ASC).
- Evidence_refs sorted by (contribution DESC, evidence_id ASC).
- Source lists sorted by (contribution DESC, source_host_id ASC).

Conflict reduction / penalty formula
-----------------------------------
- For each OS candidate, compute pairwise trait-disagreement between contributing sources; if average disagreement > D_thresh, set P_conflict = min(0.9, 0.2 + 0.8 * disagreement).
- Final score reduced multiplicatively: final = normalized × (1 - P_conflict).

Regression & determinism strategy
---------------------------------
- Canonical serialization: round floats to 3 decimals, sort keys, compact separators (reuse Phase 2 helpers).
- Compute SHA1 of aggregated `os_inference` blocks and store snapshots under `tests/expected_phase3_snapshots/` named `{aggregation_id}.json`.
- Add tests:
  - Unit: `test_phase3_aggregation_basic.py` — aggregate multiple host fixtures and assert expected numeric result (deterministic example vectors).
  - Unit: `test_phase3_correlation.py` — verify link detection heuristics and flags.
  - Regression: `test_phase3_snapshot_regression.py` — analogous to Phase 2 regression harness with `--update-snapshots`.
- CI: include Phase 3 unit and regression tests in `ci.yml` (they will skip if fixtures absent).

Example workflows for running tests & generating snapshots
--------------------------------------------------------
1. Add canonical Phase 1 compact host fixtures into `tests/data/phase1_fixtures_phase3/` grouped by capture.
2. Run:

```bash
PYTHONPATH=src .venv/bin/python -m pytest tests/test_phase3_snapshot_regression.py -q --update-snapshots
```

3. Review generated snapshots under `tests/expected_phase3_snapshots/` and commit.

Documentation & governance
-------------------------
- Add `docs/phase3_design.md` (this file is the draft) and link from `docs/README` and main `README.md` when finalized.
- Signature table changes: Phase 3 uses Phase 2 signatures; any changes must include snapshot updates and an entry in CHANGELOG documenting behavioral impacts.

Open considerations
-------------------
- Weighting choices (w_source, coverage factors) are policy parameters — we recommend maintaining them in a small config file (versioned) that is tracked with signature changes.
- Merge policy: Phase 3 annotates linkages but does not collapse host IDs; a future Phase 4 may optionally coalesce hosts for reporting.

Deliverables
------------
- `docs/phase3_design.md` (this file)
- Test plan and example parameter vectors
- Proposed schema for aggregated os_inference blocks (see examples above)

Next steps I can take
--------------------
- Implement aggregation code in `src/satori/phase3/aggregate.py` with deterministic outputs and tests.
- Add unit-test skeletons and CI workflow update to include Phase 3 tests.
