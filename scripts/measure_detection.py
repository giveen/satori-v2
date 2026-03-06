#!/usr/bin/env python3
"""Measure detection rate against the Ultimate PCAP."""
import sys
import io
import json
import os

os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, "src")

from satori import cli

old_stdout = sys.stdout
sys.stdout = buf = io.StringIO()
try:
    pcap = "tests/data/The Ultimate PCAP v20251206.pcapng"
    # Use offline analyze path (no --pcap-file which goes through live ingest)
    cli.main(["analyze", pcap])
    output = buf.getvalue()
finally:
    sys.stdout = old_stdout

# Handle both single JSON and JSONL-style output
output = output.strip()
if not output:
    print("ERROR: no output from CLI", file=sys.stderr)
    sys.exit(1)
try:
    data = json.loads(output)
except json.JSONDecodeError:
    # Try JSONL (one object per line)
    lines = [l for l in output.splitlines() if l.strip()]
    data = json.loads(lines[-1]) if lines else {}
hosts = data if isinstance(data, list) else data.get("hosts", [])
total = len(hosts)
detected = 0
os_counter = {}
tls_hosts = 0
for h in hosts:
    has_tls = any(
        e.get("attribute") == "tls.ja3" for e in (h.get("evidence") or [])
    )
    if has_tls:
        tls_hosts += 1
    oi = h.get("os_inference") or {}
    cands = oi.get("candidates") or []
    if cands and cands[0].get("score", 0) > 0:
        detected += 1
        os_name = cands[0].get("os_family", "unknown")
        os_counter[os_name] = os_counter.get(os_name, 0) + 1

print(f"Total hosts: {total}")
print(f"Hosts with TLS/JA3 evidence: {tls_hosts}")
print(f"Detected (before TLS): 247/490 (50.4%)")
print(f"Detected (now): {detected}/{total} ({detected/total*100:.1f}%)")
print()
print("OS breakdown:")
for os_name, cnt in sorted(os_counter.items(), key=lambda x: -x[1]):
    print(f"  {os_name}: {cnt}")
