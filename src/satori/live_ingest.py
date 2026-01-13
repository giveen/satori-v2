"""Incremental live ingestion pipeline wiring.

Provides `feed_live_evidence()` which accepts a generator of Phase 1
normalized evidence dicts (such as produced by `capture_live()`) and
incrementally updates a host registry and optionally runs Phase 2-5
processing, invoking a user callback for each host update.

Design goals:
- Deterministic incorporation: evidence is inserted into per-host lists
  in timestamp order where possible.
- Do not mutate incoming evidence objects; operate on copies.
- Preserve canonicalization and SHA1 provenance from Phase2 utilities.
- Be robust to malformed evidence and callback failures.
"""
from __future__ import annotations

import copy
import logging
from typing import Callable, Generator, Iterable, Dict, Any, Optional, Tuple
import json
import time
from datetime import datetime
from pathlib import Path

from .host import HostRegistry
from .phase2.traits import extract_traits
from .phase2.scoring import score_host
from .phase2.os_inference import build_os_inference
from .tcp_fingerprint import build_tcp_fingerprint
from .phase3.aggregate import aggregate_hosts
from .phase4.temporal_aggregation import aggregate_temporal_os
from .phase5.report import build_phase5_summary
from .phase2.evidence import evidence_sha1

log = logging.getLogger("satori.live_ingest")


def _host_to_dict(host) -> Dict[str, Any]:
    return {
        "host_id": host.host_id,
        "ips": sorted(list(host.ips)),
        "macs": sorted(list(host.macs)),
        "first_seen": host.first_seen,
        "last_seen": host.last_seen,
        "evidence": list(host.evidence),
        "flows": sorted(list(host.flows)),
        "ambiguity": dict(host.ambiguity or {}),
        # placeholders that downstream phases may consult
        "tcp_fingerprint": getattr(host, "tcp_fingerprint", None),
        "ssh_fingerprint": getattr(host, "ssh_fingerprint", None),
    }


def _insert_evidence_sorted(evidence_list: list, ev: dict) -> None:
    """Insert `ev` into `evidence_list` keeping timestamp order deterministic.

    If `timestamp` is missing, append to the end. We copy the incoming
    evidence to avoid mutating caller-owned objects.
    """
    evc = copy.deepcopy(ev)
    ts = evc.get("timestamp")
    if ts is None:
        evidence_list.append(evc)
        return
    # find insertion index (stable: earlier timestamps first; ties by evidence_sha1)
    sid = evidence_sha1(evc)
    idx = 0
    for i, existing in enumerate(evidence_list):
        ets = existing.get("timestamp")
        if ets is None:
            # existing without ts considered older than timed ones
            idx = i + 1
            continue
        if ets > ts:
            break
        if ets == ts:
            # deterministic tie-breaker: compare sha1s
            try:
                esid = evidence_sha1(existing)
            except Exception:
                esid = ""
            if esid > sid:
                break
        idx = i + 1
    evidence_list.insert(idx, evc)


def _canonical_bytes(obj: Any) -> bytes:
    """Canonical JSON bytes: sort keys, round floats to 3 decimals, compact separators."""
    def _round(o):
        if isinstance(o, float):
            return round(o, 3)
        if isinstance(o, dict):
            return {k: _round(o[k]) for k in sorted(o.keys())}
        if isinstance(o, list):
            return [_round(x) for x in o]
        return o

    fixed = _round(obj)
    return json.dumps(fixed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _write_snapshot_file(path: Path, obj: Any, ndjson: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = _canonical_bytes(obj)
    if ndjson:
        # append a single-line JSON record
        with open(path, "ab") as fh:
            fh.write(data)
            fh.write(b"\n")
    else:
        with open(path, "wb") as fh:
            fh.write(data)


def feed_live_evidence(
    evidence_gen: Iterable[Dict[str, Any]],
    callback: Optional[Callable[[Dict[str, Any], Dict[str, Any]], None]] = None,
    apply_phases: Tuple[int, ...] = (2, 3, 4, 5),
    decay_params: Optional[Dict[str, Any]] = None,
    snapshot_dir: Optional[str] = None,
    snapshot_prefix: Optional[str] = None,
    snapshot_interval: Optional[float] = None,
    snapshot_batch_size: Optional[int] = None,
    ndjson: bool = False,
    live_metrics: bool = False,
    nmap_db_path: Optional[str] = None,
) -> Generator[Dict[str, Any], None, None]:
    """Consume an evidence generator and incrementally update host state.

    Yields the updated host dict after applying the selected phases. The
    optional `callback(host_dict, stage_results)` is invoked for each host
    update; `stage_results` contains per-phase outputs when requested.
    """
    registry = HostRegistry()

    # Track last-seen timestamp per host to maintain ordering guarantees
    last_ts_by_host: Dict[str, float] = {}

    # helper to materialize registry hosts to phase1-style dicts
    def _materialize_all() -> list:
        return [_host_to_dict(h) for h in registry.all_hosts()]

    # snapshot bookkeeping
    snap_dirpath = Path(snapshot_dir) if snapshot_dir else None
    last_snapshot_time = time.time()
    events_since_snapshot = 0

    for ev in evidence_gen:
        # validate evidence
        if not isinstance(ev, dict):
            log.warning("malformed evidence (not dict): %r", ev)
            continue

        # choose representative host ip if present, prefer src_ip in value
        v = ev.get("value") or {}
        ip = None
        mac = None
        try:
            if isinstance(v, dict):
                ip = v.get("src_ip") or v.get("ip") or v.get("host_ip") or v.get("dst_ip")
                mac = v.get("src_mac") or v.get("mac")
        except Exception:
            ip = None

        # fallback to host_id if present in evidence
        hid = ev.get("host_id")

        if not ip and hid:
            # try to extract ip from host_id if it encodes an ip (best-effort)
            if isinstance(hid, str) and ":" in hid:
                ip = hid.split(":")[0]

        if not ip:
            # cannot attach to a host deterministically; log and continue
            log.warning("evidence without attachable host/ip: %r", ev)
            continue

        ts = ev.get("timestamp")

        # get or create host
        host_obj = registry.get_or_create(ip, mac=mac, ts=ts)

        try:
            # insert evidence deterministically sorted
            _insert_evidence_sorted(host_obj.evidence, ev)
            # add flow refs
            if ev.get("flow_id"):
                host_obj.add_flow_ref(ev.get("flow_id"))
            # best-effort: if evidence contains top-level fingerprint dicts, attach
            if ev.get("attribute") in ("tcp.fingerprint", "tcp_fingerprint") and isinstance(ev.get("value"), dict):
                host_obj.tcp_fingerprint = copy.deepcopy(ev.get("value"))
            if ev.get("attribute") in ("ssh.fingerprint", "ssh_fingerprint") and isinstance(ev.get("value"), dict):
                host_obj.ssh_fingerprint = copy.deepcopy(ev.get("value"))
        except Exception:
            log.exception("failed to merge evidence: %r", ev)
            continue

        # Try to build/update a TCP fingerprint object from accumulated evidence
        try:
            tf = build_tcp_fingerprint(host_obj)
            # store as plain dict for downstream consumers
            host_obj.tcp_fingerprint = tf.__dict__ if tf is not None else None
        except Exception:
            # non-fatal: leave tcp_fingerprint as-is
            pass

        # update last seen
        if ts is not None:
            last_ts_by_host[host_obj.host_id] = float(ts)

        # materialize host dict for downstream processing
        host_dict = _host_to_dict(host_obj)

        stage_results: Dict[str, Any] = {}

        # Phase 2: traits, scoring, os_inference
        if 2 in apply_phases:
            try:
                traits = extract_traits(host_dict)
                scoring = score_host(traits, host_dict)
                osinf = build_os_inference(host_dict, nmap_db_path=nmap_db_path)
                host_dict["traits"] = traits
                host_dict["os_inference"] = osinf
                stage_results["phase2"] = {"traits": traits, "os_inference": osinf}
            except Exception:
                log.exception("phase2 processing failed for host %s", host_dict.get("host_id"))

        # Phase 3 aggregation (best-effort snapshot over current registry)
        if 3 in apply_phases:
            try:
                all_hosts = _materialize_all()
                aggs = aggregate_hosts(all_hosts)
                # determine aggregation id for this host by reusing phase3 logic
                # attach aggregated block if present
                # simple strategy: pick aggregation group that contains this host_id
                attached = None
                for aid, blk in aggs.items():
                    if host_dict.get("host_id") in (blk.get("members") or []):
                        attached = blk
                        break
                if attached:
                    host_dict["aggregated_os_inference"] = attached
                stage_results["phase3"] = aggs
            except Exception:
                log.exception("phase3 aggregation failed")

        # Phase 4 temporal aggregation
        if 4 in apply_phases:
            try:
                # aggregate_temporal_os expects list of host dicts
                tmp = aggregate_temporal_os(_materialize_all(), decay_params or {})
                # find matching temporal block for this host
                matched = [h for h in tmp if h.get("host_id") == host_dict.get("host_id")]
                if matched:
                    host_dict["temporal_os_inference"] = matched[0].get("temporal_os_inference")
                stage_results["phase4"] = {h.get("host_id"): h.get("temporal_os_inference") for h in tmp}
            except Exception:
                log.exception("phase4 temporal aggregation failed")

        # Phase 5 summary (coarse, snapshot-like)
        if 5 in apply_phases:
            try:
                # build_phase5_summary expects list of captures (each capture is list of hosts)
                # we treat current registry as a single capture
                p5 = build_phase5_summary([_materialize_all()], decay_params=decay_params or {})
                stage_results["phase5"] = p5
            except Exception:
                log.exception("phase5 reporting failed")

        # invoke user callback if provided; swallow exceptions
        if callback:
            try:
                callback(host_dict, stage_results)
            except Exception:
                log.exception("live ingest callback failed")

        # snapshotting policy: write per-host snapshot or batch metrics
        events_since_snapshot += 1
        now = time.time()
        do_snapshot = False
        if snapshot_batch_size and events_since_snapshot >= int(snapshot_batch_size):
            do_snapshot = True
        if snapshot_interval and (now - last_snapshot_time) >= float(snapshot_interval):
            do_snapshot = True

        if do_snapshot and snap_dirpath is not None:
            try:
                # per-host snapshot file (overwrite) for determinism
                # use optional prefix to tie snapshots to a source (e.g., pcap stem)
                hid = host_dict.get('host_id')
                if snapshot_prefix:
                    host_name = f"{snapshot_prefix}__{hid}.json"
                else:
                    host_name = f"{hid}.json"
                host_path = snap_dirpath / host_name
                _write_snapshot_file(host_path, host_dict, ndjson=ndjson)

                # optionally write live metrics (Phase4/5 summary)
                if live_metrics:
                    # compute current summaries deterministically
                    current_hosts = _materialize_all()
                    p5 = build_phase5_summary([current_hosts], decay_params=decay_params or {})
                    if snapshot_prefix:
                        metrics_name = f"{snapshot_prefix}__metrics.json"
                    else:
                        metrics_name = "__metrics.json"
                    metrics_path = snap_dirpath / metrics_name
                    _write_snapshot_file(metrics_path, p5, ndjson=ndjson)
            except Exception:
                log.exception("failed to write live snapshot files")
            last_snapshot_time = now
            events_since_snapshot = 0

        # live stdout/tabular reporting
        if ndjson is False and snap_dirpath is None:
            # if no snapshot dir, use stdout reporting only if requested via callback wrapper
            pass

        # If live_stdout or live_tabular requested, user may have provided a callback that handles printing.

        # yield updated host state
        yield host_dict

    # After generator completes, optionally write final snapshots for all hosts
    if snap_dirpath is not None:
        try:
            current_hosts = _materialize_all()

            # Phase3 aggregation and Phase4 temporal apply to all hosts
            try:
                aggs = aggregate_hosts(current_hosts)
            except Exception:
                log.exception("phase3 aggregation failed during final snapshot")
                aggs = {}

            try:
                tmp = aggregate_temporal_os(current_hosts, decay_params or {})
            except Exception:
                log.exception("phase4 temporal aggregation failed during final snapshot")
                tmp = []

            # build per-host enriched dict
            enriched = []
            for h in current_hosts:
                hd = dict(h)
                # phase2
                try:
                    traits = extract_traits(hd)
                    osinf = build_os_inference(hd, nmap_db_path=nmap_db_path)
                    hd["traits"] = traits
                    hd["os_inference"] = osinf
                except Exception:
                    log.exception("phase2 failed during final snapshot for %s", hd.get("host_id"))

                # attach aggregated block if present
                attached = None
                for aid, blk in (aggs or {}).items():
                    if hd.get("host_id") in (blk.get("members") or []):
                        attached = blk
                        break
                if attached:
                    hd["aggregated_os_inference"] = attached

                # attach temporal block
                matched = [x for x in (tmp or []) if x.get("host_id") == hd.get("host_id")]
                if matched:
                    hd["temporal_os_inference"] = matched[0].get("temporal_os_inference")

                enriched.append(hd)

            for h in enriched:
                hid = h.get('host_id')
                if snapshot_prefix:
                    host_name = f"{snapshot_prefix}__{hid}.json"
                else:
                    host_name = f"{hid}.json"
                host_path = snap_dirpath / host_name
                _write_snapshot_file(host_path, h, ndjson=ndjson)

            if live_metrics:
                p5 = build_phase5_summary([current_hosts], decay_params=decay_params or {})
                if snapshot_prefix:
                    metrics_name = f"{snapshot_prefix}__metrics.json"
                else:
                    metrics_name = "__metrics.json"
                metrics_path = snap_dirpath / metrics_name
                _write_snapshot_file(metrics_path, p5, ndjson=ndjson)

        except Exception:
            log.exception("failed to write final live snapshots")
