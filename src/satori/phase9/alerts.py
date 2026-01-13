"""Phase 9 alerting engine (deterministic, explainable).

Provides a simple, deterministic alert generator suitable for Phase9 T1.
"""
from __future__ import annotations

import copy
import datetime
import hashlib
import json
import math
from typing import List, Optional


def _iso_now():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _round_f(v):
    try:
        return round(float(v), 3)
    except Exception:
        return v


def _canonical_bytes(obj) -> bytes:
    def _round(o):
        if isinstance(o, float):
            return round(o, 3)
        if isinstance(o, dict):
            return {k: _round(o[k]) for k in sorted(o.keys())}
        if isinstance(o, list):
            return [_round(x) for x in o]
        return o

    s = json.dumps(_round(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return s.encode("utf-8")


def _sha1_hex(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()


def _entropy_from_candidates(candidates: List[dict]) -> float:
    # candidates: list of {name, score}
    if not candidates:
        return 0.0
    scores = [max(0.0, float(c.get("score", 0.0))) for c in candidates]
    s = sum(scores)
    if s <= 0:
        return 0.0
    ps = [x / s for x in scores]
    n = len(ps)
    if n <= 1:
        return 0.0
    H = -sum(p * math.log(p) for p in ps if p > 0)
    H_norm = H / math.log(n)
    return float(H_norm)


def generate_alerts(hosts: List[dict], live_metrics: Optional[dict] = None, threshold: float = 0.5) -> List[dict]:
    """Generate deterministic alerts from host summaries.

    - Does not mutate inputs (works on deep copy).
    - Rounds floats to 3 decimals for deterministic snapshots.
    - Sorts alerts by severity desc, then host_id asc.

    Expected host keys (best-effort):
    - host_id: str
    - phase7_anomaly_score: float in [0,1]
    - phase8_candidates: optional list of {name, score, evidence_refs}
    - evidence_refs: optional list of sha1 strings

    live_metrics may include key 'now' to override timestamp (ISO8601 string).
    """
    if hosts is None:
        return []
    hs = copy.deepcopy(hosts)
    now = None
    if isinstance(live_metrics, dict):
        now = live_metrics.get("now")
    if not now:
        now = _iso_now()

    alerts = []
    for h in hs:
        host_id = h.get("host_id") or h.get("ip") or "unknown"
        E = float(h.get("phase7_anomaly_score", 0.0) or 0.0)
        candidates = h.get("phase8_candidates") or h.get("os_inference_candidates")
        if not candidates:
            oi = h.get("os_inference")
            if isinstance(oi, dict):
                candidates = oi.get("candidates") or []
        candidates = candidates or []
        C = _entropy_from_candidates(candidates)
        # simple weighted combination for T1
        severity_raw = 0.6 * E + 0.4 * C
        severity = _round_f(severity_raw)

        # collect evidence refs
        ev = []
        for k in ("evidence_refs", "evidence", "evidence_sha1s"):
            v = h.get(k)
            if isinstance(v, list):
                ev.extend([x for x in v if isinstance(x, str)])
        # also include candidate evidence if present
        for c in candidates:
            if isinstance(c, dict):
                for k in ("evidence_refs", "evidence_sha1s"):
                    v = c.get(k)
                    if isinstance(v, list):
                        ev.extend([x for x in v if isinstance(x, str)])

        ev = sorted(set(ev))

        # create alerts when severity >= threshold
        if severity >= threshold:
            # create a deterministic alert_id using sha1 of host_id+canonical evidence
            ident_src = host_id + "|" + ",".join(ev)
            alert_id = "alrt-" + _sha1_hex(ident_src.encode("utf-8"))[:8]
            notes = None
            if E > 0.0 and C > 0.0:
                notes = f"anomaly={E:.3f},conflict={C:.3f}"

            alert = {
                "alert_id": alert_id,
                "host_id": host_id,
                "alert_type": "OS_CONFLICT" if C > 0.0 else "ANOMALY",
                "severity": severity,
                "timestamp": now,
                "evidence_refs": ev,
            }
            if notes:
                alert["notes"] = notes

            alerts.append(alert)

    # deterministic sort: severity desc, host_id asc
    alerts.sort(key=lambda a: (-float(a.get("severity", 0.0)), a.get("host_id", "")))
    # ensure rounding for all float fields
    for a in alerts:
        if "severity" in a:
            a["severity"] = _round_f(a["severity"])

    return alerts


def serialize_alerts_canonical(alerts: List[dict]) -> bytes:
    return _canonical_bytes(alerts)


def stream_alerts_ndjson(fh, alerts: List[dict]):
    """Write alerts as NDJSON to a file-like object fh."""
    for a in alerts:
        fh.write(json.dumps(a, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        fh.write("\n")


def feed_live_alerts(
    hosts: List[dict],
    live_metrics: Optional[dict] = None,
    alert_threshold: float = 0.5,
    snapshot_dir: Optional[str] = None,
    snapshot_interval: float = 10.0,
    snapshot_batch_size: int = 10,
    ndjson: bool = False,
    callback=None,
):
    """Process live host snapshots and emit per-host alert files and aggregate metrics.

    Behavior:
    - Non-mutating: operates on deep copies of inputs.
    - Uses a tiny state file in `snapshot_dir` to honor `snapshot_interval` and `snapshot_batch_size`.
    - Writes per-host files named `{prefix}__alerts__{host_id}.json` (or `.ndjson` when `ndjson=True`).
    - Writes aggregate metrics file `{prefix}__alerts_metrics.json`.
    - Calls `callback(alert, metrics)` for each alert or batch; exceptions are caught and logged.

    live_metrics may include:
    - now: ISO8601 timestamp to use instead of current time (useful for replay tests)
    - prefix: filename prefix for snapshots
    """
    import os
    import json as _json
    from pathlib import Path
    import copy as _copy

    if hosts is None:
        return
    hosts_copy = _copy.deepcopy(hosts)
    now = None
    if isinstance(live_metrics, dict):
        now = live_metrics.get("now")
    if not now:
        now = _iso_now()

    prefix = "capture"
    if isinstance(live_metrics, dict) and live_metrics.get("prefix"):
        prefix = live_metrics.get("prefix")

    if snapshot_dir:
        os.makedirs(snapshot_dir, exist_ok=True)
        state_path = os.path.join(snapshot_dir, ".alerts_state.json")
    else:
        state_path = None

    # Load state
    state = {"last_time": None, "counter": 0}
    if state_path and Path(state_path).exists():
        try:
            state = _json.loads(Path(state_path).read_text(encoding="utf-8"))
        except Exception:
            state = {"last_time": None, "counter": 0}

    # Decide whether to snapshot based on interval or batch
    do_snapshot = False
    try:
        if state.get("last_time") is None:
            do_snapshot = True
        else:
            # compare ISO timestamps lexicographically (both are Z-terminated)
            import datetime as _dt

            last = _dt.datetime.fromisoformat(state["last_time"].replace("Z", "+00:00"))
            cur = _dt.datetime.fromisoformat(now.replace("Z", "+00:00"))
            if (cur - last).total_seconds() >= float(snapshot_interval):
                do_snapshot = True
    except Exception:
        do_snapshot = True

    state["counter"] = int(state.get("counter", 0)) + len(hosts_copy)
    if state["counter"] >= int(snapshot_batch_size):
        do_snapshot = True

    alerts = []
    metrics = {"hosts": 0, "alerts_emitted": 0}

    if do_snapshot:
        for h in hosts_copy:
            # generate alerts for this single host
            host_alerts = generate_alerts([h], live_metrics={"now": now, "prefix": prefix}, threshold=alert_threshold)
            metrics["hosts"] += 1
            if not host_alerts:
                continue
            metrics["alerts_emitted"] += len(host_alerts)
            # write per-host file
            hid = h.get("host_id") or h.get("ip") or "unknown"
            fname_base = f"{prefix}__alerts__{hid}"
            if snapshot_dir:
                if ndjson:
                    fpath = Path(snapshot_dir) / (fname_base + ".ndjson")
                    # append each alert as NDJSON line
                    with open(fpath, "a", encoding="utf-8") as fh:
                        stream_alerts_ndjson(fh, host_alerts)
                else:
                    fpath = Path(snapshot_dir) / (fname_base + ".json")
                    # canonical JSON write
                    b = serialize_alerts_canonical(host_alerts)
                    fpath.write_bytes(b)

            # callback per alert
            for a in host_alerts:
                alerts.append(a)
                if callable(callback):
                    try:
                        callback(_copy.deepcopy(a), _copy.deepcopy(metrics))
                    except Exception:
                        # do not let callback failures interrupt processing
                        try:
                            import logging

                            logging.getLogger("satori.phase9").exception("alert callback failed")
                        except Exception:
                            pass

        # write aggregate metrics
        if snapshot_dir:
            metrics_path = Path(snapshot_dir) / (f"{prefix}__alerts_metrics.json")
            metrics_path.write_bytes(_json.dumps(metrics, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))

        # update state
        if state_path:
            state["last_time"] = now
            state["counter"] = 0
            Path(state_path).write_text(_json.dumps(state), encoding="utf-8")

    else:
        # not time yet; persist counter
        if state_path:
            Path(state_path).write_text(_json.dumps(state), encoding="utf-8")

    return {"alerts": alerts, "metrics": metrics, "did_snapshot": do_snapshot}
