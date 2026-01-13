Phase 7 — Anomaly Detection (T1)
================================

Overview
--------
Phase 7 runs deterministic, explainable anomaly detection on enriched per-host
outputs produced by Phases 2–6. Its outputs are suitable for CI regression
testing: canonical JSON with sorted keys and floats rounded to 3 decimals.

API
---
- Module: `src/satori/phase7/anomaly.py`
- Function: `detect_anomalies(hosts: list[dict], config: dict | None) -> (reports, metrics)`

Input expectations
------------------
- `hosts` is a list of host dicts (each host a dict) produced by Phase2–5
  pipelines. Required keys (best-effort): `host_id`, `os_inference`,
  `aggregated_os_inference`, `temporal_os_inference` (Phase4), `flows`, `evidence`.
- Module treats missing optional data gracefully — rules that require missing
  inputs are not applied.

Anomaly rules (default)
------------------------
- `os_conflict`: Host-level top OS candidate differs from aggregated top.
  - Score: configurable; default 0.9
  - Contributing evidence: provenance objects from host `evidence` list.
- `baseline_deviation`: Ambiguity flags such as `nat_suspected` or `shared_ip`.
  - Score: configurable; default 0.7
- `suspicious_traffic`: Excessive number of flows vs `flow_threshold`.
  - Score: configurable; default 0.6
- Cross-host correlation notes are attached when aggregation members have
  conflicting top candidates.

Outputs / Schema
----------------
Per-host report (dict):

- `host_id`: string
- `anomalies`: list of anomaly dicts, each with:
  - `type`: string
  - `score`: float (0–1, rounded to 3 decimals)
  - `contributing_evidence`: list of provenance identifiers (strings)
  - `description`: human-readable explanation
- `overall_score`: float (max of anomaly scores, rounded 3 decimals)
- `correlation_notes` (optional): details about multi-host correlation conflicts

Aggregated metrics (dict):

- `num_hosts_with_anomalies`: int
- `anomaly_counts`: dict mapping type -> count
- `avg_score_by_type`: dict mapping type -> avg score (rounded to 3 decimals)

Determinism guarantees
----------------------
- Inputs are not mutated; the detector operates on deep copies.
- Canonical JSON serialization uses sorted keys, compact separators, and
  rounds floats to 3 decimals for stable SHA1 hashing.
- Lists in outputs are deterministically ordered: reports sorted by
  `host_id`; anomalies sorted by type (and can be re-ordered by score in
  later revisions, but tests expect consistent ordering).

Testing and CI
--------------
- Unit tests included: basic rule checks, multi-host correlation, determinism.
- Regression snapshot test writes canonicalized output to
  `tests/expected_phase7/phase7_regression.json` when run with
  `--update-snapshots` and compares SHA1 otherwise.
- CI should run the Phase7 regression test (after snapshot files are
  committed) and fail fast if expected Phase7 snapshot is missing.

Next steps
----------
T2: Add CLI flags `--phase7-anomalies` and `--out-anomalies` to emit
     Phase7 reports from the CLI and allow snapshotting.
T3: Add Phase7 snapshots to CI pre-checks and include them in the
     `tests/expected_phase7/` directory (commit updated snapshots).

CLI usage & snapshot naming
---------------------------

- CLI flags: `--phase7-anomalies` to run detection, `--out-anomalies <path>` to write output.
- If running in replay mode with snapshot prefixing enabled, anomalies are written as:
  - `{pcap_stem}__anomalies.json`
  - `{pcap_stem}__anomalies_metrics.json`

Determinism & snapshots
------------------------
- Outputs are canonicalized (sorted keys, floats rounded to 3 decimals) before writing.
- Use the test harness `tests/test_phase7_anomaly_regression.py` with `--update-snapshots` to generate
  and refresh snapshot files locally; commit them to enable CI regression testing.

Notes
-----
This design is intentionally conservative: rule-based detectors provide
explainable outputs suitable for initial CI regression. Future work can add
statistical baselines, ML-based anomaly scoring, and streaming incremental
anomaly updates.
