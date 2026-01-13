from __future__ import annotations

import dataclasses
import math
import typing as t
from collections import defaultdict, Counter


@dataclasses.dataclass
class TCPStackFingerprint:
    ttl: dict
    window_size: dict
    mss: dict
    wscale: dict
    tcp_options_order: list
    ts_present: str
    ecn: str
    isn_behavior: str
    syn_ack_symmetry: str | None
    confidence: float


def _bin_ttl(val: int) -> int:
    if val is None:
        return None
    if val <= 32:
        return 32
    if val <= 64:
        return 64
    if val <= 128:
        return 128
    return 255


def _shannon_entropy(counts: Counter) -> float:
    total = sum(counts.values())
    if total == 0:
        return 0.0
    ent = 0.0
    for v in counts.values():
        p = v / total
        ent -= p * math.log2(p)
    return ent


def build_tcp_fingerprint(host) -> TCPStackFingerprint:
    """Reduce `host.evidence` into a canonical TCP/IP stack fingerprint.

    Read-only: operates only on `host.evidence` and `host.ambiguity`.
    """
    # collect values
    ttls = []
    wins = []
    msses = []
    wscales = []
    opts_orders = set()
    ts_values = set()
    ecn_values = set()
    isns_by_flow = defaultdict(list)

    for ev in host.evidence:
        attr = ev.get("attribute")
        val = ev.get("value")
        prov = ev.get("provenance") or {}
        flow_id = prov.get("flow_id") if isinstance(prov, dict) else None
        if attr == "ip.ttl":
            try:
                ttls.append(int(val))
            except Exception:
                pass
        elif attr == "tcp.window_size":
            try:
                wins.append(int(val))
            except Exception:
                pass
        elif attr == "tcp.mss":
            try:
                msses.append(int(val))
            except Exception:
                pass
        elif attr == "tcp.wscale":
            try:
                wscales.append(int(val))
            except Exception:
                pass
        elif attr == "tcp.opts_order":
            try:
                # value expected to be list like [2,1,3]
                tup = tuple(int(x) for x in (val or []))
                opts_orders.add(tup)
            except Exception:
                pass
        elif attr == "tcp.ts_present":
            ts_values.add(bool(val))
        elif attr == "tcp.ecn":
            # val expected dict {ece:bool,cwr:bool}
            try:
                if isinstance(val, dict):
                    ecn_values.add(bool(val.get("ece") or val.get("cwr")))
            except Exception:
                pass
        elif attr == "tcp.isn":
            try:
                isn = int(val)
                isns_by_flow[flow_id].append(isn)
            except Exception:
                pass

    # dedup and prepare sets for JSON
    ttl_set = sorted(set(ttls))
    win_set = sorted(set(wins))
    mss_set = sorted(set(msses))
    wscale_set = sorted(set(wscales))
    opts_list = [list(t) for t in sorted(opts_orders)]

    # infer initial TTL using heuristic: pick max observed and map to bin
    inferred_initial = None
    if ttl_set:
        inferred_initial = _bin_ttl(max(ttl_set))

    # ts_present: True/False/Mixed
    if not ts_values:
        ts_present = "unknown"
    elif len(ts_values) == 1:
        ts_present = "true" if True in ts_values and False not in ts_values else "false"
    else:
        ts_present = "mixed"

    # ecn: similar
    if not ecn_values:
        ecn = "unknown"
    elif len(ecn_values) == 1:
        ecn = "true" if True in ecn_values and False not in ecn_values else "false"
    else:
        ecn = "mixed"

    # ISN behavior heuristics
    all_isns = []
    for fl, lst in isns_by_flow.items():
        all_isns.extend(lst)

    isn_behavior = "unknown"
    if not all_isns:
        isn_behavior = "unknown"
    else:
        # compute LSB entropy over low 8 bits
        lsb_counts = Counter([i & 0xFF for i in all_isns])
        ent = _shannon_entropy(lsb_counts)
        # heuristic thresholds: entropy < 2 -> low entropy, >6 -> random
        if ent < 2.0:
            isn_behavior = "low_entropy"
        else:
            # check increments: compute diffs per flow where possible
            diffs = []
            for lst in isns_by_flow.values():
                if len(lst) >= 2:
                    # sort by value assuming temporal order unknown
                    s = sorted(lst)
                    diffs.extend([s[i+1]-s[i] for i in range(len(s)-1)])
            if diffs:
                mean = sum(diffs)/len(diffs)
                std = (sum((d-mean)**2 for d in diffs)/len(diffs))**0.5
                if mean > 0 and std/mean < 0.5:
                    isn_behavior = "incremental"
                else:
                    isn_behavior = "random"
            else:
                # fallback to random if no diffs
                isn_behavior = "random"

    # syn_ack_symmetry - mark present if any flow has multiple isn entries
    syn_ack_symmetry = None
    for fl, lst in isns_by_flow.items():
        if len(lst) >= 2:
            syn_ack_symmetry = "present"
            break
    if syn_ack_symmetry is None:
        syn_ack_symmetry = "unknown"

    # Confidence calculation
    required_fields = ["ttl", "window_size", "mss", "wscale", "tcp_options_order", "ts_present", "ecn", "isn_behavior"]
    present = 0
    if ttl_set:
        present += 1
    if win_set:
        present += 1
    if mss_set:
        present += 1
    if wscale_set:
        present += 1
    if opts_list:
        present += 1
    if ts_present != "unknown":
        present += 1
    if ecn != "unknown":
        present += 1
    if isn_behavior != "unknown":
        present += 1

    completeness = present / len(required_fields)
    confidence = 0.5 * completeness + 0.25
    # reduce confidence for ambiguity
    if host.ambiguity.get("nat_suspected") or host.ambiguity.get("shared_ip"):
        confidence *= 0.6

    fingerprint = TCPStackFingerprint(
        ttl={"observed_values": ttl_set, "inferred_initial": inferred_initial},
        window_size={"values": win_set},
        mss={"values": mss_set},
        wscale={"values": wscale_set},
        tcp_options_order=opts_list,
        ts_present=ts_present,
        ecn=ecn,
        isn_behavior=isn_behavior,
        syn_ack_symmetry=syn_ack_symmetry,
        confidence=round(float(max(0.0, min(1.0, confidence))), 3),
    )

    return fingerprint
