# Satori - Version 2

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

```bash
python -m satori.cli analyze \
  --live \
  --interface eth0 \
  --live-stdout \
  --live-ndjson \
```

User-facing JSON focuses on the minimal fields useful for downstream
processing:

- `flows`
- `os_candidates`

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

## Inspired by

- https://github.com/NikolaiT/zardaxt
- https://github.com/xnih/satori

## Testing done on

- https://weberblog.net/the-ultimate-pcap/
- https://wiki.wireshark.org/samplecaptures


---

## VIBE CODED

This project was *vibe-coded into existence*.  
I am not a traditional programmer — and I’m unapologetic about it.

- **Planning Agent:** qwen2.5:7b-instruct  
- **Coding Agent:** GPT-5-mini  

### Human-in-the-Loop Vibe Coding Process

I use a deliberate **Human-in-the-Loop (HITL)** workflow to keep control of design,
security assumptions, and intent while letting agents handle implementation details.

1. **Ideation & Discovery**  
   I start with the Planning Agent using a prompt like:  
   > *“I’m thinking of making an XYZ project. Ask me questions to help plan and design this out.”*  
   This forces clarity before any code is written.

2. **Architecture & Breakdown**  
   I ask the Planning Agent to produce a **reviewable architecture and development plan**, broken down into:
   - Major development phases
   - Sub-tasks per phase  
   I explicitly remind the agent:  
   > *“I’m a security engineer, not a programmer — explain this in terms I can understand.”*

3. **Human Approval Gate**  
   I review, question, and approve the plan **before** any implementation begins.

4. **Execution by Coding Agent**  
   The approved planning prompt is passed to the Coding Agent, with instructions to:
   - Implement only the approved phase or sub-task
   - Return a **completion summary** explaining:
     - What was done
     - Which phase/sub-task was completed

5. **Review & Refinement**  
   Results are sent back to the Planning Agent for:
   - Review
   - Design feedback
   - Security considerations
   - Follow-up questions or suggested changes

6. **Iterative Loop**  
   Steps 4–5 repeat until the project converges.

This loop keeps the system **intent-driven, explainable, and auditable**, while still
moving fast — and without pretending I suddenly became a full-time software engineer.

