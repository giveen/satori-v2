#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from glob import glob


def sanitize_filename(name: str) -> str:
    """Return a filesystem-safe filename by replacing control chars with '_'."""
    # Remove/control newlines and exotic chars that may break paths
    return "".join(c if (c.isalnum() or c in " ._-()") else "_" for c in name).strip()


def find_python():
    venv_py = os.path.join('.venv', 'bin', 'python')
    if os.path.exists(venv_py):
        return venv_py
    return sys.executable


def run_cli_on(pcap_path, out_path):
    py = find_python()
    cmd = [py, '-m', 'satori.cli', 'analyze', pcap_path, '--out', out_path]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def summarize_report(report):
    hosts = report.get('hosts', [])
    # summary includes per-host compact info and coverage metrics
    summary = {'num_hosts': len(hosts), 'hosts': []}

    # helpers
    def _gather_protocols(h):
        prots = set()
        for ev in h.get('evidence', []):
            # normalized evidence may be in 'evidence_norm' list
            if isinstance(ev, dict) and 'evidence_norm' in ev and isinstance(ev['evidence_norm'], list):
                for n in ev['evidence_norm']:
                    if not isinstance(n, dict):
                        continue
                    # protocol field may be transport-level (tcp/udp); 'source' indicates extractor
                    p = n.get('protocol')
                    s = n.get('source')
                    if p:
                        prots.add(p)
                    if s:
                        # normalize extractor source like 'dhcp_extractor' -> 'dhcp'
                        if isinstance(s, str) and s.endswith('_extractor'):
                            prots.add(s[:-10])
                        else:
                            prots.add(s)
            else:
                # fallback: top-level keys
                if isinstance(ev, dict):
                    if 'protocol' in ev and ev.get('protocol'):
                        prots.add(ev.get('protocol'))
                    if 'type' in ev and ev.get('type'):
                        prots.add(ev.get('type'))
                    if 'source' in ev and ev.get('source'):
                        s = ev.get('source')
                        if isinstance(s, str) and s.endswith('_extractor'):
                            prots.add(s[:-10])
                        else:
                            prots.add(s)
        return sorted(prots)

    for h in hosts:
        evidence_list = h.get('evidence') or []
        protocols = _gather_protocols(h)
        # observation window
        first = h.get('first_seen')
        last = h.get('last_seen')
        duration = None
        try:
            if first is not None and last is not None:
                duration = last - first if last >= first else None
        except Exception:
            duration = None

        ev_count = len(evidence_list)
        evidence_density = None
        if duration and duration > 0:
            evidence_density = ev_count / duration

        hf = {
            'host_id': h.get('host_id'),
            'ips': h.get('ips'),
            'macs': h.get('macs'),
            'ambiguity': h.get('ambiguity'),
            'tcp_fingerprint': h.get('tcp_fingerprint'),
            'ssh_fingerprint': h.get('ssh_fingerprint'),
            'evidence_count': ev_count,
            'protocols_seen': protocols,
            'protocol_count': len(protocols),
            'evidence_density': evidence_density,
        }
        summary['hosts'].append(hf)

    # Compute coverage metrics at PCAP level
    pc = summary
    num_hosts = pc['num_hosts']
    hosts_with_any_evidence = sum(1 for h in pc['hosts'] if h.get('evidence_count', 0) > 0)
    hosts_with_tcp_evidence = sum(1 for h in pc['hosts'] if 'tcp' in (h.get('protocols_seen') or []))
    hosts_with_ssh_evidence = sum(1 for h in pc['hosts'] if 'ssh' in (h.get('protocols_seen') or []))
    hosts_with_dhcp_evidence = sum(1 for h in pc['hosts'] if 'dhcp' in (h.get('protocols_seen') or []))
    hosts_with_dns_evidence = sum(1 for h in pc['hosts'] if 'dns' in (h.get('protocols_seen') or []))
    hosts_with_ntp_evidence = sum(1 for h in pc['hosts'] if 'ntp' in (h.get('protocols_seen') or []))
    hosts_with_2plus = sum(1 for h in pc['hosts'] if (h.get('protocol_count') or 0) >= 2)

    # confidence histograms
    def _bucket_confidences(key):
        buckets = {'0-0.25': 0, '0.25-0.5': 0, '0.5-0.75': 0, '0.75-1.0': 0}
        vals = [ (h.get(key) or {}).get('confidence') if isinstance(h.get(key), dict) else None for h in pc['hosts'] ]
        for v in vals:
            if isinstance(v, (int, float)):
                if 0.0 <= v < 0.25:
                    buckets['0-0.25'] += 1
                elif 0.25 <= v < 0.5:
                    buckets['0.25-0.5'] += 1
                elif 0.5 <= v < 0.75:
                    buckets['0.5-0.75'] += 1
                elif 0.75 <= v <= 1.0:
                    buckets['0.75-1.0'] += 1
        return buckets

    tcp_buckets = _bucket_confidences('tcp_fingerprint')
    ssh_buckets = _bucket_confidences('ssh_fingerprint')

    # ambiguity metrics
    hosts_with_ambiguity = sum(1 for h in pc['hosts'] if h.get('ambiguity'))
    hosts_nat_suspected = sum(1 for h in pc['hosts'] if h.get('macs') and len(h.get('macs')) > 1)
    # shared IP: build ip->count map
    ip_map = {}
    for h in pc['hosts']:
        for ip in (h.get('ips') or []):
            ip_map.setdefault(ip, 0)
            ip_map[ip] += 1
    hosts_shared_ip = sum(1 for h in pc['hosts'] if any(ip_map.get(ip,0) > 1 for ip in (h.get('ips') or [])))

    coverage = {
        'host_coverage': {
            'num_hosts': num_hosts,
            'hosts_with_any_evidence': hosts_with_any_evidence,
            'hosts_with_tcp_evidence': hosts_with_tcp_evidence,
            'hosts_with_ssh_evidence': hosts_with_ssh_evidence,
            'hosts_with_dhcp_evidence': hosts_with_dhcp_evidence,
            'hosts_with_dns_evidence': hosts_with_dns_evidence,
            'hosts_with_ntp_evidence': hosts_with_ntp_evidence,
        },
        'protocol_coverage_ratios': {
            'pct_hosts_with_tcp_evidence': (hosts_with_tcp_evidence / num_hosts) if num_hosts else 0.0,
            'pct_hosts_with_ssh_evidence': (hosts_with_ssh_evidence / num_hosts) if num_hosts else 0.0,
            'pct_hosts_with_dhcp_evidence': (hosts_with_dhcp_evidence / num_hosts) if num_hosts else 0.0,
            'pct_hosts_with_2plus_protocols': (hosts_with_2plus / num_hosts) if num_hosts else 0.0,
        },
        'confidence_histograms': {
            'tcp': tcp_buckets,
            'ssh': ssh_buckets,
        },
        'ambiguity_metrics': {
            'hosts_with_ambiguity': hosts_with_ambiguity,
            'hosts_nat_suspected': hosts_nat_suspected,
            'hosts_shared_ip': hosts_shared_ip,
            'ratio_ambiguous_to_total': (hosts_with_ambiguity / num_hosts) if num_hosts else 0.0,
        }
    }

    summary['coverage_metrics'] = coverage
    return summary


def main():
    base = os.path.join('tests', 'data')
    patterns = [os.path.join(base, '*.pcap'), os.path.join(base, '*.pcapng')]
    files = []
    for p in patterns:
        files.extend(glob(p))

    if not files:
        print('No pcap files found under tests/data')
        return 0

    results = []
    for f in sorted(files):
        base_name = sanitize_filename(os.path.basename(f))
        out_json = os.path.join('tests', 'output', base_name + '.summary.json')
        os.makedirs(os.path.dirname(out_json), exist_ok=True)
        rc, out, err = run_cli_on(f, out_json)
        # include original path and file size for provenance
        size = None
        try:
            size = os.path.getsize(f)
        except Exception:
            pass
        entry = {'pcap_file': f, 'rc': rc, 'file_size': size}
        if rc != 0:
            entry['error'] = err or out
            results.append(entry)
            continue
        try:
            # CLI wrote full structured JSON to out_json (args.out)
            if os.path.exists(out_json):
                with open(out_json, 'r') as fh:
                    rep = json.load(fh)
            else:
                # CLI should always emit strict JSON to stdout now; parse it
                rep = json.loads(out)
                # persist the structured JSON so subsequent checks can read it
                os.makedirs(os.path.dirname(out_json), exist_ok=True)
                with open(out_json, 'w') as fh:
                    json.dump(rep, fh, indent=2)
        except Exception as e:
            entry['error'] = f'failed to read output: {e}'
            results.append(entry)
            continue

        # augment compact summary with provenance (pcap_file, size, capture duration)
        compact = summarize_report(rep)
        compact['pcap_file'] = f
        compact['file_size'] = size
        # attempt to compute capture duration from hosts' first_seen/last_seen
        try:
            times = []
            for h in rep.get('hosts', []):
                fs = h.get('first_seen')
                ls = h.get('last_seen')
                if fs is not None:
                    times.append(fs)
                if ls is not None:
                    times.append(ls)
            if times:
                compact['capture_duration'] = max(times) - min(times)
            else:
                compact['capture_duration'] = None
        except Exception:
            compact['capture_duration'] = None

        entry['summary'] = compact
        # persist compact per-pcap summary for regression checks
        compact_path = os.path.join('tests', 'output', base_name + '.compact.json')
        with open(compact_path, 'w') as ch:
            json.dump(entry['summary'], ch, indent=2)
        results.append(entry)

    print(json.dumps(results, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
