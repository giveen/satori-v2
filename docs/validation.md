# Validation and Determinism

This document describes what "deterministic" means for this project, the guarantees provided by the validation suite, and limitations of the current fingerprint outputs.

Determinism
- The project treats determinism as byte-for-byte stability of the compact per-pcap summaries located at `tests/output/*.compact.json` when the same inputs and environment are used.
- The regression test `tests/test_regression_deterministic.py` runs `scripts/pcap_summary.py` twice and asserts that SHA1 checksums of all `*.compact.json` files are identical.

Provenance
- Each CLI output and compact summary now includes a `pcap_file` field that holds the original input path used to produce the summary.
- The compact summary also includes `file_size` and `capture_duration` (if available) to aid downstream auditing.

Strict JSON
- The CLI guarantees that stdout is always valid JSON (no Python `repr()`), and tests assert this via `json.loads`.

What fingerprints mean
- Fingerprints are advisory signals. Confidence values are relative and intended to convey the strength of evidence from the parsed traffic; they are not ground-truth.
- Do not treat the OS hints as definitive — use them as part of a broader analysis pipeline.

Limitations
- This phase is focused on stability and provenance. No changes to scoring heuristics, fingerprint features, or external DB integrations were made.
- Capture duration is estimated from host first/last seen timestamps when available; it is a lightweight heuristic, not a source-synchronized duration.

Validation criteria enforced by tests
- CLI stdout must be valid JSON.
- Each compact summary must contain `pcap_file`, `num_hosts`, and `hosts` with per-host `host_id`, `ips`, `macs`, `tcp_fingerprint`, `ssh_fingerprint`, and `evidence_count`.
- `tests/test_regression_deterministic.py` ensures deterministic compact outputs.

If you need stricter provenance (absolute input canonicalization, capture metadata from pcap headers, original capture timestamps), we can add that in a follow-up change.
