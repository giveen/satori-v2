"""Deterministic trait extraction from Phase 1 host summaries.

Pure functions that map Phase 1 host dicts into a sorted list of
normalized trait keys. No scoring or OS mapping performed here.
"""
from __future__ import annotations

from typing import List, Dict, Any, Tuple
from .evidence import evidence_sha1
import re


_NON_ALNUM_RE = re.compile(r"[^0-9a-z]+")


def _norm_token(s: str) -> str:
    if not isinstance(s, str):
        s = str(s)
    s = s.lower()
    s = s.strip()
    s = _NON_ALNUM_RE.sub("_", s)
    s = s.strip("_")
    return s


def _ttl_bin(val: int) -> str:
    try:
        v = int(val)
    except Exception:
        return None
    if v <= 48:
        return "32"
    if v <= 96:
        return "64"
    if v <= 192:
        return "128"
    return "255"


def _median_from_list(vals):
    vals = [int(x) for x in vals if isinstance(x, (int, float)) or (isinstance(x, str) and x.isdigit())]
    if not vals:
        return None
    vals = sorted(vals)
    l = len(vals)
    return vals[l // 2]


def _extract_tcp_traits(tcp: Dict[str, Any], evidence_list: List[Dict[str, Any]]) -> List[Tuple[str, bool, str]]:
    traits = []
    if not tcp:
        return traits

    # TTL
    ttl_info = tcp.get("ttl", {})
    inferred = ttl_info.get("inferred_initial")
    observed = ttl_info.get("observed_values") or []
    ttl_val = inferred if inferred is not None else (_median_from_list(observed) if observed else None)
    if ttl_val is not None:
        b = _ttl_bin(ttl_val)
        if b:
            traits.append((f"tcp:ttl:{b}", False, None))

    # window size
    ws = tcp.get("window_size", {}).get("values") or []
    wv = _median_from_list(ws)
    if wv is not None:
        traits.append((f"tcp:window:{int(wv)}", False, None))

    # mss
    mss = tcp.get("mss", {}).get("values") or []
    mv = _median_from_list(mss)
    if mv is not None:
        traits.append((f"tcp:mss:{int(mv)}", False, None))

    # wscale
    wsc = tcp.get("wscale", {}).get("values") or []
    if wsc:
        try:
            wsc_vals = sorted(int(x) for x in wsc)
            traits.append((f"tcp:wscale:{wsc_vals[-1]}", False, None))
        except Exception:
            pass

    # options: normalize to sorted order for deterministic output
    opts = tcp.get("tcp_options_order") or []
    if opts:
        opts_norm = [_norm_token(x) for x in opts]
        opts_sorted = sorted(x for x in opts_norm if x)
        if opts_sorted:
            traits.append((f"tcp:opts:{','.join(opts_sorted)}", False, None))

    # ts_present
    ts = tcp.get("ts_present")
    if ts is not None:
        val = "present" if str(ts).lower() == "present" else "absent"
        traits.append((f"tcp:ts:{val}", False, None))

    # Baseline detection: if confidence is baseline (0.25) and no tcp evidence
    baseline_conf = tcp.get("confidence")
    has_tcp_evidence = any((ev.get("protocol") == "tcp" or (ev.get("attribute") or "").startswith("tcp.")) for ev in (evidence_list or []))
    baseline_only = (baseline_conf is not None and float(baseline_conf) <= 0.25 and not has_tcp_evidence)
    # mark baseline flag on traits by setting second tuple element
    if baseline_only:
        traits = [(t, True, eid) for (t, _, eid) in traits]

    return traits


def _extract_ssh_traits(ssh: Dict[str, Any], evidence_list: List[Dict[str, Any]]) -> List[Tuple[str, bool, str]]:
    traits = []
    if not ssh:
        return traits

    # banner
    banners = ssh.get("ssh_banner") or []
    if banners:
        b = banners[0]
        bnorm = _norm_token(b)
        traits.append((f"ssh:banner:{bnorm}", False, None))

    # kex algorithms
    kexs = ssh.get("kex_algorithms") or []
    kex_names = set()
    for k in kexs:
        if not isinstance(k, str):
            continue
        # take token before '-' or '@' if present
        k0 = k.split("-")[0].split('@')[0]
        kex_names.add(_norm_token(k0))
    for k in sorted(x for x in kex_names if x):
        traits.append((f"ssh:kex:{k}", False, None))

    # hostkey algorithms
    hks = ssh.get("hostkey_algorithms") or []
    hk_names = set()
    for h in hks:
        if not isinstance(h, str):
            continue
        hk = h
        if hk.startswith("ssh-"):
            hk = hk[4:]
        hk_names.add(_norm_token(hk))
    for h in sorted(x for x in hk_names if x):
        traits.append((f"ssh:hostkey:{h}", False, None))

    # ciphers (collect both directions)
    ciphers = set()
    for k in (ssh.get("encryption_algorithms_c2s") or []) + (ssh.get("encryption_algorithms_s2c") or []):
        if not isinstance(k, str):
            continue
        c = k.split("@")[0]
        ciphers.add(_norm_token(c))
    for c in sorted(x for x in ciphers if x):
        traits.append((f"ssh:cipher:{c}", False, None))

    return traits


def _extract_dhcp_traits(host: Dict[str, Any]) -> List[Tuple[str, bool, str]]:
    traits = []
    for ev in host.get("evidence", []) or []:
        # support both normalized evidence items and legacy structures
        if not isinstance(ev, dict):
            continue
        attr = ev.get("attribute")
        if attr == "dhcp.param_request_list":
            val = ev.get("value")
            if isinstance(val, str) and val:
                traits.append((f"dhcp:prl:{_norm_token(val)}", False, evidence_sha1(ev)))
        # top-level dhcp blocks
        if ev.get("type") == "dhcp" and isinstance(ev.get("dhcp"), dict):
            opts = ev.get("dhcp", {}).get("options") or {}
            # message type
            mt = opts.get("53")
            if mt:
                try:
                    mt_i = int(mt, 16)
                    mt_map = {1: "discover", 2: "offer", 3: "request", 4: "decline", 5: "ack", 8: "inform"}
                    mname = mt_map.get(mt_i, f"type{mt_i}")
                    traits.append((f"dhcp:msg:{mname}", False, evidence_sha1(ev)))
                except Exception:
                    pass
            # vendor class typically option 60
            vendor = opts.get("60")
            if vendor:
                traits.append((f"dhcp:vendor:{_norm_token(vendor)}", False, evidence_sha1(ev)))

    return traits


def _extract_dns_ntp_traits(host: Dict[str, Any]) -> List[Tuple[str, bool, str]]:
    traits = []
    # DNS: EDNS presence
    for ev in host.get("evidence", []) or []:
        if not isinstance(ev, dict):
            continue
        attr = ev.get("attribute") or ""
        if "edns" in attr:
            traits.append(("dns:edns:present", False, evidence_sha1(ev)))
        if attr.startswith("dns.ttl"):
            val = ev.get("value")
            try:
                v = int(val)
                if v < 60:
                    traits.append(("dns:ttl:low", False, evidence_sha1(ev)))
                elif v < 3600:
                    traits.append(("dns:ttl:mid", False, evidence_sha1(ev)))
                else:
                    traits.append(("dns:ttl:high", False, evidence_sha1(ev)))
            except Exception:
                pass

    # NTP: client mode
    for ev in host.get("evidence", []) or []:
        if not isinstance(ev, dict):
            continue
        if ev.get("attribute") == "ntp.mode":
            val = ev.get("value")
            if val and str(val).lower().startswith("client"):
                traits.append(("ntp:mode:client", False, evidence_sha1(ev)))

    return traits


def extract_traits(host: Dict[str, Any]) -> List[str]:
    """Extract a sorted list of normalized trait strings from a Phase 1 host dict.

    Returns deterministic, lowercase, canonical trait keys.
    """
    # Defensive copy of inputs (we won't mutate host)
    tcp = host.get("tcp_fingerprint") or {}
    ssh = host.get("ssh_fingerprint") or {}
    evidence = list(host.get("evidence") or [])

    traits_with_meta = []
    traits_with_meta.extend(_extract_tcp_traits(tcp, evidence))
    traits_with_meta.extend(_extract_ssh_traits(ssh, evidence))
    traits_with_meta.extend(_extract_dhcp_traits(host))
    traits_with_meta.extend(_extract_dns_ntp_traits(host))

    # Deduplicate by trait key; keep first baseline flag True if any
    seen = {}
    for t, baseline, eid in traits_with_meta:
        if t in seen:
            # mark baseline if already true or new baseline true
            seen[t] = (seen[t][0] or baseline, seen[t][1] or eid)
        else:
            seen[t] = (baseline, eid)

    # Only return trait keys, deterministically sorted
    keys = sorted(seen.keys())
    return keys
