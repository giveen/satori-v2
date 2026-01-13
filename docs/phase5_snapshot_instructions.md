Phase 5 snapshot regression

To generate or update Phase 5 snapshots locally run the regression test with the `--update-snapshots` flag:

```bash
PYTHONPATH=src .venv/bin/python -m pytest tests/phase5/test_phase5_regression.py --maxfail=1 -q --update-snapshots
```

This will write per-host snapshots to `tests/expected_phase5_snapshots/` and a fixture-level metrics file `*___metrics.json`.

CI behavior

The CI workflow validates that snapshots exist before running tests. If snapshots are missing the job will fail with a clear message indicating which files are absent.

Details & guidance

- Determinism guarantees:
	- All candidate numeric scores are rounded to 3 decimals.
	- Candidate ordering is `score` (desc) then `name` (asc).
	- `provenance_refs` and `conflicting_candidates` are sorted deterministically.
	- Inputs from Phase 1–4 are not mutated; Phase 5 runs work on deep copies.

- Local snapshot workflow:
	1. Run the regression test with `--update-snapshots` to create/update snapshots.
	2. Review the files under `tests/expected_phase5_snapshots/`. Commit them when they are correct.
	3. Run the regression test without `--update-snapshots` to verify SHA1s match.

- Running the full Phase 5 test suite locally:
```bash
PYTHONPATH=src .venv/bin/python -m pytest tests/phase5 -q
```

- CI behavior (fail-fast):
	- The CI job runs a pre-check that enumerates fixtures in `tests/data/phase1_fixtures/` and confirms per-host and metrics snapshots exist in `tests/expected_phase5_snapshots/`.
	- If any snapshot is missing the job exits early and prints a list of missing files so the developer can run the update flow locally.

Troubleshooting mismatches

- If a regression test fails because of a SHA1 mismatch (and you expect the change), run the update command above and inspect the newly written JSON files.
- If a mismatch is unexpected, verify:
	- You used the canonical environment (`PYTHONPATH=src` and the same Python version as CI).
	- There are no non-deterministic fields in Phase 1–4 fixtures (timestamps, random seeds).
	- Run the unit tests for Phase 5 components to locate the divergence.

