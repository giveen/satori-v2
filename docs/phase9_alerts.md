Phase 9 — Alerts & Notification Layer (T1)

Purpose
- Capture and emit alerts derived from Phase6 live/replay ingestion and Phase7/Phase8 analyses.
- Support per-host and per-network alerts with deterministic, canonical outputs suitable for regression snapshots and CI verification.

Design Objectives
- Inputs: Phase6 snapshots (live/replay), Phase7 anomaly outputs, Phase8 Nmap-enhanced OS inferences (optional enrichment).
- Outputs: Alert objects (JSON) per host or network segment and optional NDJSON stream for live mode.
- Determinism: Canonical JSON and stable sorting for snapshot/regression testing.
- Provenance: Each alert must trace back to evidence SHA1s and inference candidates.

Alert Schema (canonical JSON sample)
Host-level alert example:
{
  "alert_id": "alrt-0001",
  "host_id": "host-192.0.2.5",
  "scope": "host",
  "alert_type": "OS_CONFLICT",
  "severity": 0.820,
  "severity_label": "high",
  "timestamp": "2026-01-12T15:04:05Z",
  "evidence_refs": ["sha1:abc123...", "sha1:def456..."],
  "metrics": {
    "anomaly_score": 0.83,
    "conflicting_os_candidates": [
      {"name": "Linux 5.x", "score": 0.61},
      {"name": "Android 9", "score": 0.42}
    ]
  },
  "provenance": {
    "phases": [
      {"phase": "phase6", "snapshot_id": "snap-20260112-1500", "evidence_sha1s": ["sha1:abc123..."]},
      {"phase": "phase8", "nmap_db": "tests/data/nmap_test_db.json", "candidates_sha1": ["sha1:def456..."]}
    ]
  }
}

Network-level (aggregated) alert example:
{
  "alert_id": "alrt-1001",
  "scope": "network",
  "network": "192.0.2.0/24",
  "alert_type": "WIDE_OS_ANOMALY",
  "severity": 0.650,
  "timestamp": "2026-01-12T15:05:00Z",
  "metrics": {"hosts_affected": 8, "os_conflict_fraction": 0.35},
  "evidence_refs": ["sha1:..."],
  "provenance": {"phases": [{"phase": "phase7", "detector": "dhcp-os-conflict-v1"}]}
}

Canonical output rules (determinism)
- Canonical JSON: use JSON with sort_keys=true, separators=(",",":"), ensure_ascii=false.
- Float rounding: round all floating severity/metric values to 3 decimal places before serialization (e.g., 0.820).
- Timestamp canonicalization: use UTC ISO8601 with `Z` suffix. For regression snapshots, freeze or replace timestamps with a `snapshot_time` metadata file; tests should support `--update-snapshots` to regenerate.
- Alert ordering for snapshots: sort alerts by tuple `(scope, host_id_or_network, -severity, alert_type)`.
- Evidence SHA1s: compute SHA1 over canonical bytes of the original evidence block (same canonicalization rules used elsewhere).

Alert Types (initial list)
- OS_CONFLICT: conflicting OS inferences between internal scoring and Nmap or between multiple fingerprints.
- FINGERPRINT_CHANGE: a host's fingerprint changed significantly since last snapshot.
- TTL_ANOMALY: TTL or window size deviates from historical baseline.
- DHCP_MISMATCH: DHCP-derived attributes conflict with other signals (e.g., vendor/class vs fingerprint).
- PORT_SCAN: detected port scanning behavior (burst scans across ports/hosts).
- SERVICE_ANOMALY: services changed unexpectedly or suspicious service banners.
- HIGH_ANOMALY_SCORE: Phase7 anomaly score above threshold.
- NEW_HOST: previously unseen host appears in network.
- COMPROMISE_SUSPECT: composite detector indicating likely compromise (high-confidence rule).
- NETWORK_WIDE_EVENT: correlated event affecting many hosts (e.g., worm-like behavior).

Scoring formula (deterministic, composable)
- Overview: severity ∈ [0,1] computed by weighted combination of normalized components.
- Components:
  - E = Phase7 anomaly_score in [0,1] (0 none → 1 extreme).
  - C = Conflict score from OS candidates (use normalized entropy):
      Let candidate probabilities p_i = score_i / sum(score_i). Entropy H = -sum(p_i*log(p_i)). Normalize H_norm = H / log(n) when n>1 else 0.
      C = H_norm (higher when many similarly-scored candidates).
  - N = Nmap confidence contribution ∈ [0,1] (if available; else 0).
  - I = Impact factor based on host importance (0-1) or default 0.5.
  - R = recency modifier (1.0 for fresh evidence, 0.75 for older evidence; record in provenance).
- Concrete formula (example weights):
  severity_raw = clip( wE*E + wC*C + wN*N + wI*I, 0, 1 )
  with wE=0.45, wC=0.30, wN=0.15, wI=0.10
- Final severity: severity = round(severity_raw * R, 3)
- Severity labels: map ranges {0-0.249: low, 0.25-0.499: medium, 0.5-0.749: high, 0.75-1.0: critical}

Provenance & Evidence
- `evidence_refs`: array of SHA1s (format `sha1:...`) referencing canonical evidence blocks produced by Phase6/7/8.
- `provenance.phases`: ordered list of objects describing which phase contributed (phase name, snapshot id, detector name, db path for enrichment, candidate sha1s).
- Keep evidence small: include only the SHA1 in alerts; retain mapping from SHA1 -> canonical evidence in the snapshot bundle for auditors.

NDJSON streaming (live mode)
- Each alert emitted as one JSON line.
- Example (two-line NDJSON):
{"alert_id":"alrt-0002","host_id":"host-198.51.100.6","alert_type":"FINGERPRINT_CHANGE","severity":0.420,"timestamp":"2026-01-12T15:10:05Z","evidence_refs":["sha1:..."]}
{"alert_id":"alrt-0003","scope":"network","network":"198.51.100.0/24","alert_type":"WIDE_OS_ANOMALY","severity":0.713,"timestamp":"2026-01-12T15:10:07Z","evidence_refs":["sha1:..."]}

Live/incremental mechanics
- State store: per-run ephemeral store (or pluggable persistent DB) tracking last alert time, last fingerprint, and suppression windows per host.
- Suppression & aggregation:
  - `suppress_window` (configurable) to avoid alert storms; low-severity repeated alerts suppressed unless severity increases by a configured delta.
  - Escalation: if repeated anomalies occur within time window, escalate severity.
- Generation modes:
  - One-shot (replay): run detectors → emit complete alert set → write canonical JSON array (deterministic sort) for snapshot.
  - Live incremental: stream NDJSON lines as alerts are raised; also write periodic checkpoint snapshot files for CI-like verification.
- API hooks: allow external sinks (webhook, syslog, Elastic, Kafka) via pluggable emitter interface.

CLI flags (proposal)
- `--alerts` : enable alert generation.
- `--out-alerts <path|->` : write alerts to file (`-` for stdout) or NDJSON streaming socket.
- `--alert-threshold <float>` : global threshold to emit alerts (default 0.5).
- `--alert-suppress-window <seconds>` : suppression window for repeated alerts (default 300).
- `--alert-live` : run in continuous/live mode (requires state store path or will use ephemeral memory store).
- `--alerts-format {ndjson, json}` : output format.

Testing strategy
- Unit tests:
  - Score component tests: verify component math (entropy normalization, rounding, recency modifier).
  - Determinism tests: same inputs produce identical canonical JSON and identical evidence SHA1s across runs.
  - Conflict resolution tests: when duplicate alerts or overlapping alerts exist, deterministic dedupe keeps highest severity and stable tie-breakers (alphabetical by alert_type).
  - Edge cases: missing evidence_refs, partial host data, single candidate only (entropy=0), Nmap DB not available.
- Regression tests:
  - Snapshot directory: `tests/expected_phase9_snapshots/`.
  - Regression test runner uses `--update-snapshots` to refresh expected outputs.
  - CI runs smoke test: compare produced alerts to snapshots; fail-fast if missing expected snapshot file.
- Integration tests:
  - Small pcap/replay fixtures that exercise fingerprints, state changes, and Nmap enrichment using `tests/data/nmap_test_db.json`.

CI considerations
- Do not download live Nmap DB in CI. Use `tests/data/nmap_test_db.json` or add a cached artifact to runners.
- Add a dedicated job `phase9-alerts` that runs alert generation on a small fixture and compares to `tests/expected_phase9_snapshots/`.
- Fail-fast: if snapshots missing or mismatched, fail the job and instruct developer to run tests with `--update-snapshots` locally.

Edge cases & recommendations
- Missing evidence_refs: emit alert with `severity` lowered (multiply by 0.5) and include `provenance.missing_evidence:true`.
- Conflicting alerts: deduplicate deterministically; keep the alert with higher severity, or if equal, use lexicographic `alert_type` tie-breaker.
- Partial host data: emit lower severity and include `metrics.partial_data:true`.
- Large-scale events: emit network-level aggregated alerts rather than per-host duplicate alerts to reduce noise.

Data retention & snapshots
- For snapshot artifacts, include both `alerts.json` (canonical array) and `evidence_map.json` mapping `sha1 -> canonical_evidence` for auditing.
- Recommended snapshot path: `tests/expected_phase9_snapshots/<fixture>__phase9_alerts.json` and `...__phase9_evidence_map.json`.

Implementation notes (next steps)
- Create `src/satori/phase9/alerts.py` with:
  - `generate_alerts(phase6_snapshot, phase7_anomalies, phase8_inferences=None, config=None) -> List[alert_obj]`.
  - `serialize_alerts_canonical(alerts: List[dict]) -> bytes` (applies canonical JSON rules).
  - `stream_alerts_ndjson(out, alerts_iterable)` for live mode.
- Add CLI wiring in `src/satori/cli.py` to accept flags and call `generate_alerts()`.
- Add unit tests for scoring and determinism; add small integration fixtures and snapshot expectations.

Incremental / Live alerting
- Added `feed_live_alerts(hosts, live_metrics=None, alert_threshold=0.5, snapshot_dir=None, snapshot_interval=10.0, snapshot_batch_size=10, ndjson=False, callback=None)`:
  - Works with per-host updates from the live ingestion callback.
  - Writes per-host snapshot files named `{prefix}__alerts__{host_id}.json` (or `.ndjson` when `ndjson=True`).
  - Writes aggregate metrics `{prefix}__alerts_metrics.json` and maintains a small state file `.alerts_state.json` in the snapshot dir to implement interval and batch snapshotting.
  - `live_metrics` may carry `now` and `prefix` (useful for deterministic replay).
  - Callback receives `(alert, metrics)` and is executed safely (exceptions caught and logged).

CLI flags added for live mode:
- `--live-alerts`: enable incremental alert generation during capture.
- `--alert-snapshot-dir`: directory to write alert snapshots.
- `--alert-ndjson`: write per-host alerts in NDJSON append mode.

CI note: avoid downloading external data during live runs in CI. Use deterministic fixtures and `--update-snapshots` locally to refresh expected outputs.

Next actionable items (Phase9 T1)
1. Add design doc (this file).
2. Create alert module skeleton: `src/satori/phase9/alerts.py` (stubs only).
3. Add unit test stubs and one deterministic snapshot for a small fixture (e.g., `tests/data/dhcp.pcap`) under `tests/expected_phase9_snapshots/`.
4. Wire CLI flags and a dry-run that emits alerts to stdout (design-first; implement next iteration).

Phase 9 completion
- Baseline snapshots: generate with the regression harness:

```bash
PYTHONPATH=src .venv/bin/python -m pytest tests/test_cli_live_alerts_regression.py --update-snapshots
```

- CI enforcement: the repository CI now checks for `tests/expected_phase9_snapshots/*` and will fail fast if missing. Developers should run the `--update-snapshots` flow locally to create or refresh baselines.

- Determinism guarantees: alerts serialization uses canonical JSON (sorted keys, separators=(',', ':'), floats rounded to 3 decimals). Filenames follow `{pcap_stem}__alerts*` conventions used by the regression harness.

Phase 9 is complete for T1 when:
- Baseline snapshots exist in `tests/expected_phase9_snapshots/`.
- CI enforces their presence and fails fast on missing snapshots.
- Regression tests pass without skips.

If you'd like, I can now add a small README entry or update project tracker items marking Phase 9 complete.

Questions for you
- Preferred default `--alert-threshold` (I used 0.5 in examples)?
- Should snapshots freeze timestamps (replace with snapshot_time metadata) automatically, or prefer embedding real timestamps and a separate test hook to normalize them?

References
- Determinism conventions follow existing project rules: canonical JSON + 3-decimal rounding + evidence SHA1s.
- Plan to reuse Phase7 anomaly scores and Phase8 evidence_refs for provenance.
