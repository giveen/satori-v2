# Satori

## Usage
Live and replay capture
-----------------------

You can run Satori in live or replay mode. Replay mode is deterministic and suitable
for regression testing. Example usage:

```bash
# Replay a PCAP deterministically and write incremental host snapshots
python -m satori.cli analyze tests/data/dhcp.pcap \
	--pcap-file tests/data/dhcp.pcap --live-snapshot-dir /tmp/snapshots --live-metrics \
	--live-ndjson --live-stdout --out /tmp/out.json
```

Phase 7 anomaly detection (CLI)
--------------------------------

Run Phase 7 after Phase 2–6 processing and write anomalies to a file or stdout:

```bash
python -m satori.cli analyze tests/data/dhcp.pcap --pcap-file tests/data/dhcp.pcap \
# Satori

Intro
-----

Satori is a lightweight, deterministic passive OS fingerprinting prototype. It can
replay PCAP/PCAPNG files deterministically for testing or capture live from an
interface. Outputs are JSON-friendly and suitable for streaming to `jq`.

Installation
------------

Create a Python virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Optional (Poetry):

```bash
poetry install
```

Usage
-----

Show CLI help:

```bash
# Satori

## Intro

Satori is a lightweight, deterministic **passive OS fingerprinting** prototype.

It supports:

- **Deterministic replay** of PCAP/PCAPNG files (ideal for testing & CI)
- **True live capture** from a network interface
- **Streaming JSON / NDJSON output** suitable for piping into `jq`

Satori focuses on *observability and reproducibility*: the same PCAP always
produces the same results, while live mode emits incremental updates as
traffic is observed.

---

## Installation

Create a Python virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Optional (Poetry):

```bash
poetry install
```

Note: live capture requires elevated privileges and optional dependencies such
as `scapy`.

## Usage

Show CLI help:

```bash
python -m satori.cli --help
```

### Replay Capture (Deterministic)

Replay mode reads a PCAP file and processes it deterministically. This is
ideal for regression testing, CI, and snapshot comparison.

Replay and stream per-host JSON:

```bash
python -m satori.cli analyze tests/data/http.cap \
	--use-nmap-db \
	--nmap-db-path tests/data/nmap_test_db.json \
	--live-stdout \
	--live-ndjson
```

Each host update is emitted as a single JSON object on stdout (NDJSON).

Replay and write incremental snapshots:

```bash
python -m satori.cli analyze tests/data/dhcp.pcap \
	--live-snapshot-dir /tmp/snapshots \
	--live-metrics \
	--live-ndjson \
	--out /tmp/out.json
```

This writes:

- Incremental per-host snapshots to `/tmp/snapshots`
- A final aggregate result to `/tmp/out.json`

### Live Capture (Rolling Output)

Live mode captures packets directly from an interface and streams results as
they are observed.

True live capture with rolling JSON:

```bash
python -m satori.cli analyze \
	--live \
	--interface eth0 \
	--live-stdout \
	--live-ndjson
```

Each line written to stdout is a complete JSON object representing a host
update, making it suitable for real-time pipelines.

Example output line:

```json
{"host_id":"host:abc123","ips":["192.168.0.10"],"flows":["192.168.0.1:67-192.168.0.10:68"],"os_candidates":[]}
```

Pipe live output into `jq`:

```bash
python -m satori.cli analyze \
	--live \
	--interface eth0 \
	--live-stdout \
	--live-ndjson \
| jq -c '{host_id, ips, flows, os_candidates}'
```

## Output model

Satori emits incremental host updates rather than monolithic reports during
live operation.

User-facing JSON focuses on the minimal fields useful for downstream
processing:

- `host_id`
- `ips`
- `flows`
- `os_candidates`

Internal processing metadata is intentionally excluded from the live output.

## Common options

- `--out FILE` — Final aggregated JSON output (default: `./satori-output/out.json`)
- `--live-stdout` — Stream incremental host updates to stdout
- `--live-ndjson` — Emit one JSON object per line (NDJSON)
- `--live-snapshot-dir DIR` — Write rolling per-host snapshots to disk
- `--use-nmap-db` / `--nmap-db-path` — Enable OS enrichment using an Nmap OS database
- `--profile {default,ci,soc,forensics}` — Tune output and behavior for different use cases

---

If you want help with examples, testing PCAPs, or using the Nmap OS DB for
enrichment, open an issue or ask in the repository and I'll add targeted
examples.
