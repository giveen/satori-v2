# Phase 2 Design (OS Inference)

Status: implemented (T1–T4)

Overview
--------
Phase 2 consumes Phase 1 compact host JSON objects and performs deterministic OS inference in stages:

- T1 — evidence canonicalization & hashing
- T2 — trait extraction (TCP, SSH, DHCP, DNS, NTP)
- T3 — deterministic scoring using an embedded signature table
- T4 — assembly of explainable `os_inference` blocks with evidence-level provenance

Goals
-----
- Determinism: same input → byte-identical `os_inference` JSON output.
- Explainability: every candidate must list the traits and per-trait evidence contributing to the score.
- Non-destructive: Phase 1 data is never mutated.

Signature Table
---------------
Location: `src/signatures/v1.json` (versioned)

Schema (example):

{
  "version": "v1",
  "protocol_weights": { "tcp": 1.0, "ssh": 1.2 },
  "baseline_threshold": 0.1,
  "ambiguity_penalties": { "nat_suspected": 0.3 },
  "traits": {
    "tcp:ttl:64": { "matches": { "Ubuntu": 1.0, "Debian": 0.9 } },
    "ssh:kex:curve25519-sha256@libssh.org": { "matches": { "Ubuntu": 0.8 } }
  }
}

Versioning & Governance
-----------------------
- The `version` string acts as the signature table version.
- Changes to signatures should increment the version and include a short rationale and test updates.

Evidence hashing & canonicalization (T1)
----------------------------------------
- Evidence objects from Phase 1 are canonicalized to deterministic JSON (sorted keys, compact separators) and hashed using SHA1.
- Utility: `satori.phase2.evidence.canonicalize_evidence` and `evidence_sha1`.
- The canonical JSON uses stable float handling and standard ordering to guarantee identical hashes across runs.

Trait extraction (T2)
---------------------
- Implemented in `satori.phase2.traits.extract_traits(host)`.
- Produces a deterministic sorted list of trait strings like `tcp:ttl:64`, `ssh:kex:curve25519-sha256@libssh.org`.

Scoring (T3)
------------
- Implemented in `satori.phase2.scoring.score_host(traits, host)`.
- Per-trait contribution = signature_strength × evidence_confidence × protocol_weight × baseline_multiplier.
- Baseline multiplier downweights low-confidence protocol-only traits (configurable via `baseline_threshold`).
- Normalization: per-OS raw score divided by max_possible (precomputed from signature table), clamped to [0,1].
- Coverage factor: scales final score by observed protocol coverage and evidence density (bounded). 
- Ambiguity penalties (e.g., NAT, shared IP) reduce the final score multiplicatively.

OS Inference Schema (T4)
-------------------------
- Implemented in `satori.phase2.os_inference.build_os_inference(host)`.
- Output block attached per-host as `host['os_inference']` (callers should set it externally to avoid mutating Phase 1 host if desired).

Shape (summary):

{
  "os_inference_schema_version": "os_inference/v1",
  "signature_table_version": "sigs/v1",
  "generated_by": "phase2-v0.1",
  "candidates": [
    {
      "name": "Ubuntu",
      "score": 0.624,
      "traits_matched": ["ssh:kex:...","tcp:ttl:64"],
      "evidence_refs": [
        { "evidence_id": "<sha1>", "trait": "ssh:...", "contribution": 0.08, "pointer": ["ssh_extractor","ssh.kex_algorithms","flow_id"] }
      ],
      "conflicts": []
    }
  ],
  "explanation": { "summary": "Ubuntu ranked highest due to ...", "by_trait": { ... } },
  "metadata": { "protocol_coverage": ["tcp","ssh"], "protocol_count": 2, "evidence_density": 0.013, "ambiguity_flags": {...} }
}

Determinism guarantees
----------------------
- All lists are sorted deterministically: candidates by (score DESC, evidence_refs count DESC, name ASC), trait lists alphabetically, pointers in a fixed key order.
- Floating values in snapshots are rounded to 3 decimal places before hashing/serialization.
- No randomness or external network lookups are performed.

Regression testing and snapshots
--------------------------------
- Tests live in `tests/test_phase2_snapshot_regression.py`.
- Fixtures expected under `tests/data/phase1_fixtures/*.json`.
- Snapshots stored under `tests/expected_os_snapshots/` as canonical JSON files named `{fixture_stem}__{host_id}.json`.
- Use the pytest flag `--update-snapshots` to create/update snapshots when intentionally changing signatures or expected behaviour.

How to update snapshots safely
-----------------------------
1. Audit changes to `src/signatures/v1.json` and bump `version` when making non-backwards-compatible edits.
2. Run the regression locally and verify changes:

```bash
PYTHONPATH=src python -m pytest tests/test_phase2_snapshot_regression.py -q --update-snapshots
```

3. Inspect snapshots in `tests/expected_os_snapshots/` and commit them alongside signature changes.

Adding new signatures / OS candidates
------------------------------------
- Add trait keys and `matches` entries to `src/signatures/v1.json`.
- Add unit tests that exercise the new traits and validate numeric contributions and ordering.
- Update snapshots only after reviewing the deterministic outputs.

Examples
--------
- See `tests/test_phase2_os_inference_structure.py` and `tests/test_phase2_os_inference_provenance.py` for example host fixtures and expected fields.

Documentation link
------------------
- This document is linked from the project `README.md` under Phase 2.
