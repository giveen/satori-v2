Phase 8 — Nmap OS DB lookup
===========================

Enable optional Nmap OS fingerprint lookups to augment Phase2 OS candidates.

CLI
---
- `--use-nmap-db`: enable Nmap lookups during the CLI `analyze` run.
- `--nmap-db-path PATH`: path to a local Nmap DB file (text `nmap-os-db` or JSON export).

Behavior
--------
- If `--use-nmap-db` is specified and `--nmap-db-path` is omitted, the CLI attempts to download
  `https://svn.nmap.org/nmap/nmap-os-db` into `~/.cache/satori/nmap-os-db` and uses it. If the
  network is unavailable the CLI falls back to an offline test DB if supplied explicitly.
- Lookups are deterministic: fingerprint normalization, canonical JSON hashing, float rounding to
  3 decimals, and deterministic sorting are applied so outputs are stable across runs.

Testing
-------
- Use `--update-snapshots` to generate regression snapshots for Phase2 outputs that include Nmap
  candidates. Example:

```bash
PYTHONPATH=src .venv/bin/python -m pytest tests/test_cli_nmap_regression.py --update-snapshots -q
```

CI
--
- CI should run in offline mode using the committed `tests/data/nmap_test_db.json` or a pre-cached
  `nmap-os-db` to ensure deterministic regression results.

Notes
-----
- The shipped `parse_nmap_os_db_text` is conservative. For full coverage, pre-convert `nmap-os-db`
  to a JSON representation and supply it via `--nmap-db-path`.
