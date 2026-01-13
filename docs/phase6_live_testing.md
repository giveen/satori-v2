Phase 6 — Live / Replay Testing and Snapshot Regression
=====================================================

This document describes how to run end-to-end live/replay regression tests
and manage deterministic snapshots used by CI.

Running tests locally
---------------------

Generate or update snapshots from deterministic PCAP fixtures:

```bash
PYTHONPATH=src .venv/bin/python -m pytest tests/test_cli_live_end_to_end.py -q --update-snapshots
```

This writes canonical JSON snapshots to `tests/expected_live_snapshots/` per-fixture.

Run regression checks (no snapshot write):

```bash
PYTHONPATH=src .venv/bin/python -m pytest tests/test_cli_live_end_to_end.py -q
```

CI behavior
-----------

- CI pre-checks fail fast if expected snapshots under `tests/expected_live_snapshots/` are missing.
- The replay-mode regression tests run in CI using pcap fixtures and do not require scapy.
- Live-mode sniffing tests should be guarded or skipped when scapy or interfaces are unavailable.

Incremental snapshotting and NDJSON
----------------------------------

The live ingestion supports incremental snapshotting and live metrics. Use the CLI flags:

- `--live-metrics`: compute Phase4/Phase5 metrics on-the-fly and write metrics snapshots.
- `--live-snapshot-dir`: directory to write incremental per-host snapshots (or NDJSON records).
- `--snapshot-interval`: seconds between automatic snapshots.
- `--snapshot-batch-size`: number of events between snapshots.
- `--live-ndjson`: append newline-delimited JSON records instead of overwriting.

Examples:

```bash
# Replay and write per-host JSON snapshots every event
PYTHONPATH=src .venv/bin/python -m satori.cli analyze tests/data/dhcp.pcap --pcap-file tests/data/dhcp.pcap --live-snapshot-dir /tmp/snapshots --snapshot-batch-size 1 --live-metrics
```

NDJSON mode (append-only):

```bash
PYTHONPATH=src .venv/bin/python -m satori.cli analyze tests/data/dhcp.pcap --pcap-file tests/data/dhcp.pcap --live-snapshot-dir /tmp/snapshots --live-ndjson
```

Snapshots are canonicalized (sorted keys, floats rounded to 3 decimals) and include SHA1 provenance where applicable.

Snapshot governance
-------------------

- Update snapshots intentionally when changes alter deterministic outputs by running tests with `--update-snapshots` and committing the updated files.
- Prefer small, focused PCAP fixtures to keep snapshots reviewable.

Stdout / Tabular snapshot naming
--------------------------------

- CLI stdout captures for replay are stored under `tests/expected_live_stdout/`.
- Naming convention: `{fixture_stem}__stdout.json` for canonical JSON-lines output, or `{fixture_stem}__stdout.txt` for raw text/tabular output.
- The regression test `tests/test_cli_live_regression_outputs.py` will compare SHA1 of canonicalized stdout against these files. Use `--update-snapshots` to refresh them locally.

CI Pre-check and Fail-fast
--------------------------

- The GitHub Actions CI workflow includes a pre-check step that validates expected
	live/replay snapshots and stdout captures are present under `tests/expected_live_snapshots/`
	and `tests/expected_live_stdout/` respectively. If any expected file is missing the CI job
	will fail fast and list the missing files.
- To add or refresh snapshots locally run the regression test with `--update-snapshots` and commit
	the generated files; do not run `--update-snapshots` in CI.
