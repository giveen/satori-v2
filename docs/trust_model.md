# Satori Trust & Threat Model

This document describes Satori's high-level trust and threat model, determinism guarantees, and safe default behaviors.

Determinism guarantees
- Deterministic serialization: JSON artifacts use canonical serialization (sorted keys, separators=(',', ':'), ensure_ascii=False).
- Float rounding: floating scores are rounded to 3 decimal places when included in canonical artifacts used for hashing or regression snapshots.
- Filenames: regression and live snapshot filenames follow deterministic `{pcap_stem}__{artifact}` conventions.

No network exfiltration
- Satori does not phone home or send analysis data to remote services by default.
- Optional behavior: when `--use-nmap-db` is enabled and no local cache exists, Satori may attempt to download an Nmap OS DB into `~/.cache/satori/` to improve OS inference. This download is optional and can be disabled by passing `--use-nmap-db False` or by pre-populating the cache.
- Satori never uploads captured packets or derived artifacts to third-party services.

Optional Nmap DB behavior
- If enabled and no local DB is found, Satori will attempt to download the DB into `~/.cache/satori/nmap-os-db`.
- The operation is best-effort; failures are non-fatal and Satori continues without Nmap enrichment.

What Satori does NOT do
- Satori is not a network monitoring daemon; it performs offline analysis and optional short-lived live captures.
- Satori does not execute arbitrary code from packets.
- Satori does not exfiltrate data unless explicitly configured to do so via user-provided callbacks or scripts.

Privacy & Security notes
- Users should avoid running Satori on sensitive environments without auditing capture sources.
- Artifacts written to disk (default `./satori-output/`) may contain IPs and metadata; treat them as sensitive.

Appendix: suggestions for safe use
- Run `satori doctor` before large-scale runs to validate environment and permissions.
- Pin dependencies and run inside virtual environments for reproducible execution.

