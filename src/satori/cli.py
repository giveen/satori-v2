"""CLI skeleton for satori-offline."""
from __future__ import annotations

import argparse
import logging
import dataclasses
import os
import json
from .logging_config import setup_logging
from . import __version__


def _doctor_checks():
    """Run environment checks and return (exit_code, report_dict)."""
    import sys
    import os
    from pathlib import Path

    report = {"python": sys.version.splitlines()[0], "checks": []}
    # Python version check
    py_ok = sys.version_info >= (3, 10)
    report["checks"].append({"name": "python_version", "ok": py_ok, "detail": sys.version})

    # live capture permission (simple check: can open a raw socket?)
    live_ok = True
    live_detail = "ok"
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.close()
    except PermissionError:
        live_ok = False
        live_detail = "permission denied for raw socket"
    except Exception as e:
        # non-fatal (may run on systems without raw sockets)
        live_ok = False
        live_detail = f"raw socket check failed: {e}"
    report["checks"].append({"name": "live_capture_permission", "ok": live_ok, "detail": live_detail})

    # nmap db availability (optional)
    nmap_ok = False
    nmap_detail = "not checked"
    try:
        cache = os.path.expanduser(os.path.join('~', '.cache', 'satori', 'nmap-os-db'))
        if Path(cache).exists():
            nmap_ok = True
            nmap_detail = str(cache)
        else:
            nmap_ok = False
            nmap_detail = f"missing: {cache}"
    except Exception as e:
        nmap_ok = False
        nmap_detail = str(e)
    report["checks"].append({"name": "nmap_db", "ok": nmap_ok, "detail": nmap_detail})

    # writable output dir
    out_dir = Path('.') / 'satori-output'
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        testf = out_dir / '.satori_doctor_test'
        testf.write_text('ok')
        testf.unlink()
        out_ok = True
        out_detail = str(out_dir)
    except Exception as e:
        out_ok = False
        out_detail = str(e)
    report["checks"].append({"name": "writable_output_dir", "ok": out_ok, "detail": out_detail})

    # Determine exit code: 0 success, 2 partial analysis, 3 live permission failure, 10 internal
    if not py_ok:
        code = 10
    elif not out_ok:
        code = 10
    elif not live_ok:
        code = 3
    else:
        code = 0

    return code, report


def build_parser():
    p = argparse.ArgumentParser(prog="satori", description="Satori offline analysis CLI")
    sub = p.add_subparsers(dest="cmd")
    # Make the positional `pcap` argument optional so `--live` can be used
    # without providing a PCAP file. When `--live` is set we capture from
    # the interface directly and avoid opening any PCAP file.
    a = sub.add_parser("analyze", help="Analyze a pcap file")
    a.add_argument("pcap", nargs='?', default=None, help="Path to pcap/pcapng (optional when --live is used)")
    a.add_argument("--live", action="store_true", help="Enable live capture mode (use --interface or --pcap-file)")
    a.add_argument("--interface", help="Network interface to capture from when using --live")
    a.add_argument("--pcap-file", help="Alternate path to pcap/pcapng for deterministic replay")
    a.add_argument("--out", help="Path to write the main JSON artifact (defaults to ./satori-output/out.json)", default=None, metavar="FILE")
    a.add_argument("--out-live-json", help="Write a single live JSON snapshot file for the capture", metavar="FILE")
    a.add_argument("--live-metrics", action="store_true", help="Compute and emit temporal and historical metrics during live capture")
    a.add_argument("--live-snapshot-dir", help="Directory to write incremental live snapshots")
    a.add_argument("--snapshot-interval", type=float, help="Seconds between periodic live snapshots")
    a.add_argument("--snapshot-batch-size", type=int, help="Number of host updates per batch snapshot")
    a.add_argument("--live-ndjson", action="store_true", help="Append live snapshots as newline-delimited JSON")
    a.add_argument("--live-stdout", action="store_true", help="Stream minimal per-host JSON lines to stdout")
    a.add_argument("--live-tabular", action="store_true", help="Print compact tabular host updates to stdout")
    a.add_argument("--out-summary", help=argparse.SUPPRESS, metavar="FILE")
    a.add_argument("--host-summary", action="store_true", dest="phase3_summary", help="Produce per-host summary output")
    a.add_argument("--use-nmap-db", action="store_true", help="Enable Nmap OS DB lookup if available")
    a.add_argument("--nmap-db-path", help="Path to Nmap OS fingerprint DB for enrichment (optional)")
    a.add_argument("--out-temporal-summary", help=argparse.SUPPRESS, dest="out_summary_4", metavar="FILE")
    a.add_argument("--temporal-summary", action="store_true", dest="phase4_summary", help=argparse.SUPPRESS)
    a.add_argument("--out-temporal-metrics", help=argparse.SUPPRESS, dest="out_metrics_4", metavar="FILE")
    a.add_argument("--temporal-metrics", action="store_true", dest="phase4_metrics", help=argparse.SUPPRESS)
    a.add_argument("--out-historical-summary", help=argparse.SUPPRESS, dest="out_summary_5", metavar="FILE")
    a.add_argument("--historical", action="store_true", dest="phase5_historical", help="Produce historical summaries")
    a.add_argument("--out-historical-metrics", help=argparse.SUPPRESS, dest="out_metrics_5", metavar="FILE")
    a.add_argument("--anomalies", action="store_true", dest="phase7_anomalies", help="Run anomaly detection on hosts")
    a.add_argument("--out-anomalies", help=argparse.SUPPRESS, metavar="FILE")
    a.add_argument("--alerts", action="store_true", help="Enable alert generation")
    a.add_argument("--out-alerts", help="Path to write alerts JSON (defaults to stdout)", metavar="FILE")
    a.add_argument("--alert-threshold", type=float, help="Minimum severity (0-1) to emit alerts (default: 0.5)")
    a.add_argument("--live-alerts", action="store_true", help="Enable live alerting callbacks during capture")
    a.add_argument("--alert-snapshot-dir", help="Directory to write alert snapshots")
    a.add_argument("--alert-ndjson", action="store_true", help="Write alerts as newline-delimited JSON")
    a.add_argument("--profile", choices=["default", "ci", "soc", "forensics"], default="default", help="Preset profile (default,ci,soc,forensics)")
    a.add_argument("--json-only", action="store_true", help="Emit only machine JSON outputs (suitable for CI)")
    # legacy/ergonomic alias: accept `--json` as a shorthand for `--json-only`
    a.add_argument("--json", action="store_true", help="Legacy alias for --json-only")
    a.add_argument("--pipe-jq", nargs='?', const='.', help="Pipe live JSON through `jq -c <filter>` (default '.')")
    a.add_argument("--quiet", action="store_true", help="Suppress human-readable stdout summary")
    a.add_argument("--advanced", action="store_true", help="Enable advanced/experimental CLI options")
    d = sub.add_parser("doctor", help="Run environment checks and exit with a machine-friendly code")
    d.add_argument("--json", action="store_true", help="Emit canonical JSON report instead of human summary")
    p.add_argument("--log", default="INFO", help="Log level")
    return p, {"analyze": a, "doctor": d}


def main(argv=None):
    parser, subparsers = build_parser()
    import sys as _sys
    argv_list = argv if argv is not None else _sys.argv[1:]
    # If user requested help without specifying a subcommand, show full help
    if ("-h" in argv_list or "--help" in argv_list) and not any(cmd in argv_list for cmd in ("analyze", "doctor")):
        parser.print_help()
        print()
        print("analyze subcommand options:")
        subparsers["analyze"].print_help()
        print()
        print("doctor subcommand options:")
        subparsers["doctor"].print_help()
        return
    args = parser.parse_args(argv)
    setup_logging(args.log)
    log = logging.getLogger("satori.cli")
    # apply profile presets (simple, deterministic mappings)
    profile_presets = {
        "default": {"phase7_anomalies": True, "alerts": True, "use_nmap_db": True},
        "ci": {"phase7_anomalies": True, "alerts": True, "use_nmap_db": False, "json_only": True, "quiet": True},
        "soc": {"phase7_anomalies": True, "alerts": True, "use_nmap_db": True, "live": True, "live_alerts": True},
        "forensics": {"phase7_anomalies": True, "alerts": False, "use_nmap_db": True},
    }
    preset = getattr(args, 'profile', None)
    if preset in profile_presets:
        for k, v in profile_presets[preset].items():
            try:
                # only set if not explicitly provided (conservative)
                if getattr(args, k, None) in (None, False):
                    setattr(args, k, v)
            except Exception:
                pass

    # deprecation warnings for internal phase flags usage in argv
    try:
        import sys
        for a in sys.argv[1:]:
            if a.startswith("--phase"):
                log.warning("Deprecated flag %s used; phase internals are hidden in user mode", a)
                break
    except Exception:
        pass
    # When running live captures, stream JSON updates to stdout by default
    # so users see rolling JSON without needing to pass --live-stdout.
    try:
        if getattr(args, 'live', False):
            setattr(args, 'live_stdout', True)
    except Exception:
        pass
    if args.cmd == "analyze":
        # determine a human-friendly target for the initial log (pcap path or live:interface)
        _target = getattr(args, 'pcap_file', None) or args.pcap
        if not _target and getattr(args, 'live', False):
            _target = f"live:{(getattr(args, 'interface', None) or 'any')}"
        log.info("Analyze requested for: %s", _target)
        # legacy alias: if user passed --json, treat as --json-only
        if getattr(args, 'json', False):
            try:
                setattr(args, 'json_only', True)
            except Exception:
                pass
        # ensure hosts_output exists even if live/offline branches fail
        hosts_output = []
        # capture prefix used for snapshot/filenames (pcap stem or live-<iface>)
        capture_prefix = None
        try:
            if getattr(args, 'pcap_file', None) or args.pcap:
                from pathlib import Path as _P
                capture_prefix = _P(getattr(args, 'pcap_file', None) or args.pcap).stem
            elif getattr(args, 'live', False):
                capture_prefix = f"live_{(getattr(args, 'interface', None) or 'capture')}"
        except Exception:
            capture_prefix = None
        live_mode_used = False
        pkt_count = 0
        parsed_count = 0
        flows = []
        heuristics = []
        evidence = {"tcp": {"isn_heuristics": []}, "dhcp": [], "dns": [], "ntp": [], "ssh": []}
        # If live or pcap-file mode requested, reuse capture_live + feed_live_evidence
        live_requested = bool(getattr(args, 'live', False) or getattr(args, 'pcap_file', None))
        if live_requested:
            try:
                from .live_capture import capture_live
                from .live_ingest import feed_live_evidence
                

                pcap_file = getattr(args, 'pcap_file', None) or args.pcap

                # resolve nmap DB path for live mode if requested
                nmap_db_path = None
                if getattr(args, 'use_nmap_db', False):
                    nmap_db_path = getattr(args, 'nmap_db_path', None)
                    if not nmap_db_path:
                        try:
                            from .nmap_lookup import download_nmap_os_db

                            cache_dir = os.path.expanduser(os.path.join('~', '.cache', 'satori'))
                            os.makedirs(cache_dir, exist_ok=True)
                            candidate = os.path.join(cache_dir, 'nmap-os-db')
                            res = download_nmap_os_db(candidate)
                            if res:
                                nmap_db_path = res
                        except Exception:
                            nmap_db_path = None

                # determine snapshot prefix early so callbacks can reference it
                snap_prefix = capture_prefix

                # callback to write incremental JSON snapshots if requested
                def _make_callback(path):
                    def cb(host_dict, stage_results):
                        try:
                            # snapshot current registry state from host_dict's perspective
                            # here we write per-host snapshot file containing host and latest phase outputs
                            out_obj = {'host': host_dict, 'stages': stage_results}
                            out_dir = os.path.dirname(path)
                            if out_dir:
                                os.makedirs(out_dir, exist_ok=True)
                            with open(path, 'w') as fh:
                                fh.write(json.dumps(out_obj, separators=(",", ":"), sort_keys=True))
                        except Exception:
                            log.exception('failed to write live JSON snapshot to %s', path)
                    return cb

                cb = None
                if getattr(args, 'out_live_json', None):
                    cb = _make_callback(args.out_live_json)

                # Optionally pipe live JSON through `jq -c` if requested.
                jq_proc = None
                if getattr(args, 'pipe_jq', None):
                    try:
                        import shutil, subprocess, sys
                        jq_bin = shutil.which('jq')
                        if jq_bin:
                            jq_filter = getattr(args, 'pipe_jq') or '.'
                            # spawn jq with stdout inherited so filtered output appears
                            jq_proc = subprocess.Popen([jq_bin, '-c', jq_filter], stdin=subprocess.PIPE)

                            def _jq_writer(host_dict, stages):
                                try:
                                    oi = host_dict.get('os_inference') or {}
                                    cands = oi.get('candidates') or []
                                    record = {
                                        'host_id': host_dict.get('host_id'),
                                        'ips': host_dict.get('ips') or [],
                                        'flows': host_dict.get('flows') or [],
                                        'os_candidates': [c.get('name') for c in cands],
                                    }
                                    line = json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n"
                                    jq_proc.stdin.write(line.encode('utf-8'))
                                    jq_proc.stdin.flush()
                                except Exception:
                                    log.exception('jq writer failed')

                            if cb is None:
                                cb = _jq_writer
                            else:
                                prev_cb = cb
                                def _chained_jq(host_dict, stages):
                                    try:
                                        prev_cb(host_dict, stages)
                                    except Exception:
                                        log.exception('live file callback failed')
                                    _jq_writer(host_dict, stages)
                                cb = _chained_jq
                        else:
                            log.warning('jq not found in PATH; --pipe-jq ignored')
                    except Exception:
                        log.exception('failed to spawn jq for --pipe-jq')

                # optional stdout/tabular printing via callback
                def _print_callback(host_dict, stages):
                    try:
                        # Stream minimal JSON for live updates when requested. If
                        # `--json-only` is set for live runs, treat it as live stdout.
                        if getattr(args, 'live_stdout', False) or (getattr(args, 'json_only', False) and getattr(args, 'live', False)):
                            # Emit minimal host update with only desired keys
                            oi = host_dict.get('os_inference') or {}
                            cands = oi.get('candidates') or []
                            record = {
                                'host_id': host_dict.get('host_id'),
                                'ips': host_dict.get('ips') or [],
                                'flows': host_dict.get('flows') or [],
                                'os_candidates': [c.get('name') for c in cands],
                            }
                            # one JSON object per line, flushed immediately for jq
                            print(json.dumps(record, separators=(",", ":"), sort_keys=True), flush=True)
                        if getattr(args, 'live_tabular', False):
                            # print a compact tabular line: timestamp, host_id, top candidate, score
                            hid = host_dict.get('host_id')
                            top = None
                            score = None
                            oi = host_dict.get('os_inference') or {}
                            cands = oi.get('candidates') or []
                            if cands:
                                top = cands[0].get('name')
                                score = cands[0].get('score')
                            ts = host_dict.get('last_seen') or ''
                            print(f"{ts}\t{hid}\t{top}\t{score}")
                    except Exception:
                        log.exception('live print callback failed')

                # chain callbacks: write file callback then print callback
                if cb is None and (getattr(args, 'live_stdout', False) or getattr(args, 'live_tabular', False)):
                    cb = _print_callback
                elif cb is not None and (getattr(args, 'live_stdout', False) or getattr(args, 'live_tabular', False)):
                    orig_cb = cb
                    def _chained(host_dict, stages):
                        try:
                            orig_cb(host_dict, stages)
                        except Exception:
                            log.exception('live file callback failed')
                        _print_callback(host_dict, stages)
                    cb = _chained

                # add alerts callback for live mode if requested
                if getattr(args, 'live_alerts', False):
                    try:
                        from .phase9.alerts import feed_live_alerts

                        def _alerts_callback(host_dict, stages):
                            try:
                                # non-blocking best-effort: call feed_live_alerts for this single host
                                snap_dir = getattr(args, 'alert_snapshot_dir', None) or getattr(args, 'live_snapshot_dir', None) or getattr(args, 'out_live_json', None)
                                lm = {"now": host_dict.get('last_seen'), "prefix": snap_prefix or 'capture'}
                                # call with single-host list; exceptions are contained within feed_live_alerts
                                feed_live_alerts([host_dict], live_metrics=lm, alert_threshold=(getattr(args, 'alert_threshold', None) or 0.5), snapshot_dir=snap_dir, snapshot_interval=(getattr(args, 'snapshot_interval', 10.0) or 10.0), snapshot_batch_size=(getattr(args, 'snapshot_batch_size', 10) or 10), ndjson=getattr(args, 'alert_ndjson', False), callback=None)
                            except Exception:
                                log.exception('live alerts callback failed')

                        if cb is None:
                            cb = _alerts_callback
                        else:
                            prev_cb = cb
                            def _chained_alerts(host_dict, stages):
                                try:
                                    prev_cb(host_dict, stages)
                                except Exception:
                                    log.exception('live callback failed')
                                _alerts_callback(host_dict, stages)
                            cb = _chained_alerts
                    except Exception:
                        log.exception('failed to enable live alerts')

                gen = capture_live(interface=getattr(args, 'interface', None), pcap_file=pcap_file, callback=None)
                final_hosts = {}
                # feed into ingest; pass snapshot and metrics options
                # ensure snap_prefix is available for callbacks
                if snap_prefix is None:
                    try:
                        from pathlib import Path as _P
                        snap_prefix = _P(pcap_file).stem if pcap_file else None
                    except Exception:
                        snap_prefix = None

                for host in feed_live_evidence(
                    gen,
                    callback=cb,
                    apply_phases=(2, 3, 4, 5),
                    decay_params=None,
                    snapshot_dir=getattr(args, 'live_snapshot_dir', None) or getattr(args, 'out_live_json', None),
                    snapshot_prefix=snap_prefix,
                    snapshot_interval=getattr(args, 'snapshot_interval', None),
                    snapshot_batch_size=getattr(args, 'snapshot_batch_size', None),
                    ndjson=getattr(args, 'live_ndjson', False),
                    live_metrics=getattr(args, 'live_metrics', False),
                    nmap_db_path=nmap_db_path,
                    # live stdout/tabular
                    
                ):
                    final_hosts[host.get('host_id')] = host

                # after capture finishes, optionally dump final summaries similar to offline path
                hosts_output = list(final_hosts.values())
                live_mode_used = True
                # reuse Phase3/4/5 CLI branches below by setting hosts_output in locals
            except Exception:
                log.exception('live/capture mode failed')
                # If user explicitly requested live capture and did not provide
                # a pcap to fall back to, abort rather than attempting offline.
                try:
                    import sys as _sys
                    if getattr(args, 'live', False) and not (getattr(args, 'pcap_file', None) or args.pcap):
                        _sys.exit(2)
                except SystemExit:
                    raise
                except Exception:
                    pass
                # otherwise fall through to offline processing if pcap provided
        
            # Minimal pipeline: ingest -> parse -> flow engine -> report counts
            if not live_mode_used:
            
                from .ingest import iter_packets
                from .packet import parse_raw
                from .flow import FlowEngine

                fe = FlowEngine()
                pkt_count = 0
                parsed_count = 0
                for ts, raw in iter_packets(args.pcap):
                    pkt_count += 1
                    meta = parse_raw(ts, raw)
                    if meta is None:
                        continue
                    parsed_count += 1
                    fe.ingest_packet(meta)

                flows = list(fe.flows())
                log.info("Read %d packets, parsed %d, flows %d", pkt_count, parsed_count, len(flows))

                # Derive ISN heuristics and include in structured output
                try:
                    from .extractors.tcp_heuristics import derive_isn_heuristics

                    heuristics = derive_isn_heuristics(flows)
                except Exception:
                    heuristics = []

                # Build HostRegistry from observed packets
                from .host import HostRegistry

                registry = HostRegistry()
                # register packets (ips/mac)
                for f in flows:
                    for pkt in f.packets:
                        # pkt is PacketMeta with src_ip/src_mac/dst_ip/dst_mac
                        try:
                            registry.get_or_create(pkt.src_ip, pkt.src_mac.hex() if pkt.src_mac else None, pkt.ts)
                        except Exception:
                            pass
                        try:
                            registry.get_or_create(pkt.dst_ip, pkt.dst_mac.hex() if pkt.dst_mac else None, pkt.ts)
                        except Exception:
                            pass

                # Collect extractor outputs into evidence buckets (legacy) while routing normalized evidence to hosts
                evidence = {"tcp": {"isn_heuristics": heuristics}, "dhcp": [], "dns": [], "ntp": [], "ssh": []}
                hosts_output = [] if not live_mode_used else hosts_output

                try:
                    from .extractors.dhcp import extract_from_flow as dhcp_extract
                except Exception:
                    dhcp_extract = None

                try:
                    from .extractors.dns import extract_from_flow as dns_extract
                except Exception:
                    dns_extract = None

                try:
                    from .extractors.ntp import extract_from_flow as ntp_extract
                except Exception:
                    ntp_extract = None

                try:
                    from .extractors.ssh import extract_from_flow as ssh_extract
                except Exception:
                    ssh_extract = None

                # helper to route normalized evidence into hosts
                def route_norm_list(norm_list, fallback_ip, flow_id):
                    for ne in norm_list:
                        # determine host by host_id or fallback ip
                        hid = ne.get("host_id")
                        target = None
                        if hid:
                            # search host by id
                            for h in registry.all_hosts():
                                if h.host_id == hid:
                                    target = h
                                    break
                        if target is None:
                            h = registry.get_or_create(fallback_ip)
                            target = h
                        target.add_evidence(ne)

                for f in flows:
                    if dhcp_extract:
                        try:
                            out = dhcp_extract(f) or []
                            evidence["dhcp"].extend(out)
                            for it in out:
                                norm = it.get("evidence_norm")
                                host_ip = it.get("host_ip") or f.src_ip
                                if norm:
                                    route_norm_list(norm, host_ip, f.flow_id)
                        except Exception:
                            pass
                    if dns_extract:
                        try:
                            out = dns_extract(f) or []
                            evidence["dns"].extend(out)
                            for it in out:
                                norm = it.get("evidence_norm")
                                host_ip = it.get("host_ip") or f.src_ip
                                if norm:
                                    route_norm_list(norm, host_ip, f.flow_id)
                        except Exception:
                            pass
                    if ntp_extract:
                        try:
                            out = ntp_extract(f) or []
                            evidence["ntp"].extend(out)
                            for it in out:
                                norm = it.get("evidence_norm")
                                host_ip = it.get("host_ip") or f.src_ip
                                if norm:
                                    route_norm_list(norm, host_ip, f.flow_id)
                        except Exception:
                            pass
                    if ssh_extract:
                        try:
                            out = ssh_extract(f) or []
                            evidence["ssh"].extend(out)
                            for it in out:
                                norm = it.get("evidence_norm")
                                # legacy ssh uses host_ip field at top-level
                                host_ip = it.get("host_ip") or f.src_ip
                                if norm:
                                    route_norm_list(norm, host_ip, f.flow_id)
                        except Exception:
                            pass

                # build hosts output
                for h in registry.all_hosts():
                    try:
                        from .tcp_fingerprint import build_tcp_fingerprint

                        h.tcp_fingerprint = build_tcp_fingerprint(h)
                    except Exception:
                        h.tcp_fingerprint = None
                    try:
                        from .ssh_fingerprint import build_ssh_fingerprint

                        h.ssh_fingerprint = build_ssh_fingerprint(h)
                    except Exception:
                        h.ssh_fingerprint = None
                    try:
                        from .ssh_os_hint import build_ssh_os_hint

                        h.ssh_os_hint = build_ssh_os_hint(h)
                    except Exception:
                        h.ssh_os_hint = None
                    hosts_output.append({
                        "host_id": h.host_id,
                        "ips": sorted(list(h.ips)),
                        "macs": sorted(list(h.macs)),
                        "ambiguity": {k: v for k, v in h.ambiguity.items() if not k.startswith("_")},
                        "first_seen": h.first_seen,
                        "last_seen": h.last_seen,
                        "evidence": h.evidence,
                        "tcp_fingerprint": (h.tcp_fingerprint.__dict__ if h.tcp_fingerprint is not None else None),
                        "ssh_fingerprint": (h.ssh_fingerprint.__dict__ if h.ssh_fingerprint is not None else None),
                        "ssh_os_hint": ([dataclasses.asdict(x) for x in h.ssh_os_hint] if h.ssh_os_hint is not None else None),
                        "flows": sorted(list(h.flows)),
                    })

        # Phase 2: produce os_inference for each host and Phase 3: aggregate and correlate
        try:
            from .phase3.integration import integrate_phase3

            nmap_db_path = None
            if getattr(args, 'use_nmap_db', False):
                nmap_db_path = getattr(args, 'nmap_db_path', None)
                if not nmap_db_path:
                    # try to download into a local cache
                    try:
                        from .nmap_lookup import download_nmap_os_db

                        cache_dir = os.path.expanduser(os.path.join('~', '.cache', 'satori'))
                        os.makedirs(cache_dir, exist_ok=True)
                        candidate = os.path.join(cache_dir, 'nmap-os-db')
                        res = download_nmap_os_db(candidate)
                        if res:
                            nmap_db_path = res
                    except Exception:
                        nmap_db_path = None

            hosts_output = integrate_phase3(hosts_output, nmap_db_path=nmap_db_path)
        except Exception:
            # if Phase 3 integration fails, continue without aggregated data
            hosts_output = hosts_output

        # Optionally produce Phase 3 summary
        if getattr(args, 'phase3_summary', False):
            try:
                from .phase3.report import build_phase3_summary
                

                summary = build_phase3_summary(hosts_output)
                # compact deterministic JSON
                s = json.dumps(summary, separators=(",", ":"), sort_keys=True)
                if args.out_summary:
                    out_dir = os.path.dirname(args.out_summary)
                    if out_dir:
                        os.makedirs(out_dir, exist_ok=True)
                    with open(args.out_summary, "w") as fh:
                        fh.write(s)
                else:
                    print(s)
            except Exception:
                log.exception("Phase 3 summary generation failed")
            # Optionally produce Phase 4 summary (temporal + correlation)
            if getattr(args, 'phase4_summary', False):
                try:
                    from .phase4.temporal_aggregation import aggregate_temporal_os
                    from .phase4.correlation import correlate_hosts_temporal
                    from .phase4.report import build_phase4_summary
                    

                    # do not mutate hosts_output
                    temporal = aggregate_temporal_os(hosts_output)
                    correlated = correlate_hosts_temporal(temporal)
                    summary = build_phase4_summary(correlated)
                    s = json.dumps(summary, separators=(",", ":"), sort_keys=True)
                    out_path = getattr(args, 'out_summary_4', None)
                    if out_path:
                        out_dir = os.path.dirname(out_path)
                        if out_dir:
                            os.makedirs(out_dir, exist_ok=True)
                        with open(out_path, "w") as fh:
                            fh.write(s)
                    else:
                        print(s)
                except Exception:
                    log.exception("Phase 4 summary generation failed")
            # Optionally write enriched Phase 4 metrics
            if getattr(args, 'phase4_metrics', False):
                try:
                    # Reuse build_phase4_summary to derive metrics
                    from .phase4.report import build_phase4_summary

                    # Ensure we don't mutate hosts_output
                    temporal = aggregate_temporal_os(hosts_output)
                    correlated = correlate_hosts_temporal(temporal)
                    full = build_phase4_summary(correlated)
                    metrics = full.get('metrics', {})
                    s = json.dumps(metrics, separators=(",", ":"), sort_keys=True)
                    out_path = getattr(args, 'out_metrics_4', None)
                    if out_path:
                        out_dir = os.path.dirname(out_path)
                        if out_dir:
                            os.makedirs(out_dir, exist_ok=True)
                        with open(out_path, "w") as fh:
                            fh.write(s)
                    else:
                        print(s)
                except Exception:
                    log.exception("Phase 4 metrics generation failed")
            # Optionally produce Phase 5 historical summaries
            if getattr(args, 'phase5_historical', False):
                try:
                    from .phase5.report import build_phase5_summary

                    # build from hosts_output captures
                    # for CLI we treat hosts_output as a single capture
                    summary5 = build_phase5_summary([hosts_output])
                    s = json.dumps(summary5, separators=(",", ":"), sort_keys=True)
                    out_path = getattr(args, 'out_summary_5', None)
                    if out_path:
                        out_dir = os.path.dirname(out_path)
                        if out_dir:
                            os.makedirs(out_dir, exist_ok=True)
                        with open(out_path, "w") as fh:
                            fh.write(s)
                    else:
                        print(s)

                    # optional metrics output
                    out_metrics_path = getattr(args, 'out_metrics_5', None)
                    if out_metrics_path:
                        m = summary5.get('metrics', {})
                        ms = json.dumps(m, separators=(",", ":"), sort_keys=True)
                        out_dir = os.path.dirname(out_metrics_path)
                        if out_dir:
                            os.makedirs(out_dir, exist_ok=True)
                        with open(out_metrics_path, "w") as fh:
                            fh.write(ms)
                except Exception:
                    log.exception("Phase 5 historical generation failed")
        # Optionally run anomaly detection
        if getattr(args, 'phase7_anomalies', False):
            try:
                from .phase7.anomaly import detect_anomalies
                from pathlib import Path as _P

                anomalies_reports, anomalies_metrics = detect_anomalies(hosts_output)

                def _round(o):
                    if isinstance(o, float):
                        return round(o, 3)
                    if isinstance(o, dict):
                        return {k: _round(o[k]) for k in sorted(o.keys())}
                    if isinstance(o, list):
                        return [_round(x) for x in o]
                    return o

                def _canonical_json(obj):
                    return json.dumps(_round(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

                anomalies_obj = {"reports": anomalies_reports, "metrics": anomalies_metrics}
                try:
                    anomalies_obj.setdefault('meta', {})
                    anomalies_obj['meta']['version'] = __version__
                except Exception:
                    pass

                out_path = getattr(args, 'out_anomalies', None)
                snapshot_dir = getattr(args, 'live_snapshot_dir', None) or getattr(args, 'out_live_json', None)
                prefix = capture_prefix

                if out_path:
                    out_dir = os.path.dirname(out_path)
                    if out_dir:
                        os.makedirs(out_dir, exist_ok=True)
                    with open(out_path, "w") as fh:
                        fh.write(_canonical_json(anomalies_obj))
                elif snapshot_dir and prefix:
                    os.makedirs(snapshot_dir, exist_ok=True)
                    a_path = _P(snapshot_dir) / f"{prefix}__anomalies.json"
                    m_path = _P(snapshot_dir) / f"{prefix}__anomalies_metrics.json"
                    a_path.write_text(_canonical_json(anomalies_obj), encoding="utf-8")
                    m_path.write_text(json.dumps(_round(anomalies_metrics), sort_keys=True, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
                else:
                    print(_canonical_json(anomalies_obj))
            except Exception:
                log.exception("Phase 7 anomaly detection failed")
        

        # Optionally run Phase 9 alert generation
        if getattr(args, 'alerts', False):
            try:
                from .phase9.alerts import generate_alerts
                prefix = capture_prefix

                threshold = float(getattr(args, 'alert_threshold', 0.5) or 0.5)
                alerts = generate_alerts(hosts_output, live_metrics=None, threshold=threshold)
                try:
                    # embed version meta into alerts bundle
                    if isinstance(alerts, dict):
                        alerts.setdefault('meta', {})
                        alerts['meta']['version'] = __version__
                except Exception:
                    pass

                def _round(o):
                    if isinstance(o, float):
                        return round(o, 3)
                    if isinstance(o, dict):
                        return {k: _round(o[k]) for k in sorted(o.keys())}
                    if isinstance(o, list):
                        return [_round(x) for x in o]
                    return o

                s = json.dumps(_round(alerts), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                out_path = getattr(args, 'out_alerts', None)
                snapshot_dir = getattr(args, 'live_snapshot_dir', None) or getattr(args, 'out_live_json', None)
                if out_path:
                    out_dir = os.path.dirname(out_path)
                    if out_dir:
                        os.makedirs(out_dir, exist_ok=True)
                    with open(out_path, "w") as fh:
                        fh.write(s)
                elif snapshot_dir and prefix:
                    os.makedirs(snapshot_dir, exist_ok=True)
                    a_path = os.path.join(snapshot_dir, f"{prefix}__phase9_alerts.json")
                    with open(a_path, "w", encoding="utf-8") as fh:
                        fh.write(s)
                else:
                    print(s)
            except Exception:
                log.exception("Phase 9 alert generation failed")

        summary = {"packets": pkt_count, "parsed": parsed_count, "flows": len(flows)}
        out = {"pcap_file": args.pcap, "summary": summary, "evidence": evidence, "heuristics": heuristics, "hosts": hosts_output}

        # make JSON-safe (convert bytes to hex strings)
        def _safe(obj):
            if isinstance(obj, dict):
                return {k: _safe(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_safe(v) for v in obj]
            if isinstance(obj, bytes):
                return obj.hex()
            if isinstance(obj, (str, int, float, bool)) or obj is None:
                return obj
            # fallback for objects like dpkt structs: ensure JSON-serializable
            try:
                return str(obj)
            except Exception:
                return None

        # keep backward-compatible top-level counters
        out["packets"] = summary["packets"]
        out["parsed"] = summary["parsed"]
        out["flows"] = summary["flows"]

        safe_out = _safe(out)

        # Determine default output path/directory
        out_base_dir = None
        if getattr(args, 'out', None):
            out_path = args.out
            out_base_dir = os.path.dirname(out_path) or '.'
        else:
            out_base_dir = os.path.join('.', 'satori-output')
            os.makedirs(out_base_dir, exist_ok=True)
            out_path = os.path.join(out_base_dir, 'out.json')

        # Always write machine JSON output
        s = json.dumps(safe_out, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(s)

        # include version in human-friendly summary header and machine meta
        try:
            if isinstance(safe_out, dict):
                safe_out.setdefault('meta', {})
                safe_out['meta']['version'] = __version__
        except Exception:
            pass

        # rewrite main out.json with versioned meta
        try:
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(safe_out, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        except Exception:
            log.exception('failed to write out.json with meta.version')

        # human-friendly summary to stdout unless json-only or quiet
        try:
            host_count = len(hosts_output) if isinstance(hosts_output, list) else 0
        except Exception:
            host_count = 0
        alerts_count = 0
        try:
            if getattr(args, 'alerts', False) and 'alerts' in locals():
                alerts_count = len(alerts)
        except Exception:
            alerts_count = 0

        if not getattr(args, 'json_only', False) and not getattr(args, 'quiet', False):
            print(f"Satori v{__version__} - Processed {pkt_count} packets ({parsed_count} parsed), flows={len(flows)}; hosts={host_count}; alerts={alerts_count}")
    elif args.cmd == "doctor":
        # run environment checks helper and emit human or JSON report
        try:
            import sys as _sys
            code, report = _doctor_checks()
            report.setdefault('meta', {})
            report['meta']['version'] = __version__
            if getattr(args, 'json', False):
                import json as _json
                # canonical JSON
                print(_json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
            else:
                # concise human summary
                ok = all(c.get('ok') for c in report.get('checks', []))
                print(f"Satori v{__version__} - Doctor checks: {'OK' if ok else 'ISSUES'}")
                for c in report.get('checks', []):
                    status = 'OK' if c.get('ok') else 'FAIL'
                    print(f"- {c.get('name')}: {status} ({c.get('detail')})")
            # ensure process exit code matches check contract
            _sys.exit(code)
        except SystemExit:
            raise
        except Exception:
            log.exception('doctor checks failed unexpectedly')
            import sys as _sys
            _sys.exit(10)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
