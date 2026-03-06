"""Deterministic OS scoring engine (Phase 2 T3).

Consumes trait keys and host metadata plus an embedded signature table
and returns per-OS raw/normalized/final scores with deterministic behavior.
"""
from __future__ import annotations

from typing import Dict, List, Any
import json
import os

from .evidence import evidence_sha1


_EPS = 1e-9


def _load_signature_table(path: str = None) -> Dict[str, Any]:
    if path is None:
        here = os.path.join(os.path.dirname(__file__), '..', '..')
        path = os.path.join(here, 'signatures', 'v1.json')
    with open(path, 'r') as fh:
        return json.load(fh)


def _protocol_of_trait(trait: str) -> str:
    if trait.startswith('tcp:'):
        return 'tcp'
    if trait.startswith('ssh:'):
        return 'ssh'
    if trait.startswith('dhcp:'):
        return 'dhcp'
    if trait.startswith('dns:'):
        return 'dns'
    if trait.startswith('ntp:'):
        return 'ntp'
    return 'other'


def _evidence_confidence_for_trait(trait: str, host: Dict[str, Any]) -> float:
    # try to find evidence entries matching trait attribute/value
    for ev in host.get('evidence', []) or []:
        if not isinstance(ev, dict):
            continue
        # check evidence_norm list
        for n in (ev.get('evidence_norm') or []):
            try:
                if trait in (str(n.get('attribute') or '')).lower() or trait in (str(n.get('value') or '')).lower():
                    return float(n.get('confidence_hint') or 0.0)
            except Exception:
                continue
        # top-level attribute
        if trait in (str(ev.get('attribute') or '')).lower() or trait in (str(ev.get('value') or '')).lower():
            return float(ev.get('confidence_hint') or 0.0)

    # fallback by protocol
    proto = _protocol_of_trait(trait)
    if proto == 'tcp':
        return float((host.get('tcp_fingerprint') or {}).get('confidence') or 0.0)
    if proto == 'ssh':
        return float((host.get('ssh_fingerprint') or {}).get('confidence') or 0.0)
    # For DHCP/DNS/NTP traits, look for matching protocol evidence and use its confidence_hint
    if proto in ('dhcp', 'dns', 'ntp'):
        prefix = proto + '.'
        best = 0.0
        for ev in host.get('evidence', []) or []:
            if not isinstance(ev, dict):
                continue
            attr = str(ev.get('attribute') or '')
            if attr.startswith(prefix):
                ch = float(ev.get('confidence_hint') or 0.3)
                if ch > best:
                    best = ch
        return best if best > 0.0 else 0.0
    # default weak confidence
    return 0.0


def _is_baseline_trait(trait: str, host: Dict[str, Any]) -> bool:
    proto = _protocol_of_trait(trait)
    if proto == 'tcp':
        tcp_conf = float((host.get('tcp_fingerprint') or {}).get('confidence') or 0.0)
        has_tcp_ev = any((ev.get('protocol') == 'tcp' or (ev.get('attribute') or '').startswith('tcp.')) for ev in (host.get('evidence') or []))
        return tcp_conf <= 0.25 and not has_tcp_ev
    if proto == 'ssh':
        ssh_conf = float((host.get('ssh_fingerprint') or {}).get('confidence') or 0.0)
        has_ssh_ev = any((ev.get('protocol') == 'ssh' or (ev.get('attribute') or '').startswith('ssh.')) for ev in (host.get('evidence') or []))
        return ssh_conf <= 0.2 and not has_ssh_ev
    return False


def score_host(traits: List[str], host: Dict[str, Any], sig_table: Dict[str, Any] = None) -> Dict[str, Any]:
    """Score a host deterministically and return per-OS score breakdown.

    Returns a dict mapping OS name -> { raw_score, normalized_score, final_score, traits_used, conflicts }
    """
    if sig_table is None:
        sig_table = _load_signature_table()

    # deterministic sorts
    traits = sorted(set(traits))
    os_names = set()
    for trait in sorted(sig_table.get('traits', {}).keys()):
        for osn in sig_table['traits'][trait].get('matches', {}).keys():
            os_names.add(osn)
    os_list = sorted(os_names)

    protocol_weights = sig_table.get('protocol_weights', {})
    ambiguity_penalties = sig_table.get('ambiguity_penalties', {})
    baseline_threshold = float(sig_table.get('baseline_threshold', 0.1))

    # Build per-protocol max evidence confidence for this host.
    # This ensures max_possible reflects only evidence actually available —
    # a DHCP-only host should not be penalised by un-observable TCP/SSH traits.
    proto_max_conf: dict = {}
    tcp_fp_conf = float((host.get('tcp_fingerprint') or {}).get('confidence') or 0.0)
    ssh_fp_conf = float((host.get('ssh_fingerprint') or {}).get('confidence') or 0.0)
    for _ev in (host.get('evidence') or []):
        if not isinstance(_ev, dict):
            continue
        _attr = str(_ev.get('attribute') or '')
        for _pfx in ('tcp', 'ssh', 'dhcp', 'dns', 'ntp'):
            if _attr.startswith(_pfx + '.'):
                _ch = float(_ev.get('confidence_hint') or 0.3)
                if _ch > proto_max_conf.get(_pfx, 0.0):
                    proto_max_conf[_pfx] = _ch
                break
    # Add TCP/SSH fingerprint confidence only when there is corroborating evidence
    # (prevents stub/default fingerprint skeletons from inflating max_possible).
    if tcp_fp_conf > 0 and 'tcp' in proto_max_conf:
        proto_max_conf['tcp'] = max(proto_max_conf['tcp'], tcp_fp_conf)
    elif tcp_fp_conf > 0.3:
        # fingerprint confidence high enough to be a real signal even without raw ev
        proto_max_conf['tcp'] = tcp_fp_conf
    if ssh_fp_conf > 0 and 'ssh' in proto_max_conf:
        proto_max_conf['ssh'] = max(proto_max_conf['ssh'], ssh_fp_conf)
    elif ssh_fp_conf > 0.2:
        proto_max_conf['ssh'] = ssh_fp_conf

    # Compute max_possible per OS as the sum of the BEST possible score from
    # each exclusive trait group (TTL, window, wscale, opts, ts, plus SSH and
    # DHCP traits). This prevents dividing by a number impossible to achieve
    # in a single host, and is constrained to only observed groups.
    _EXCLUSIVE_GROUPS = {
        "tcp:ttl": [], "tcp:window": [], "tcp:wscale": [], "tcp:opts": [],
        "tcp:ts": [], "tcp:mss": [], "ssh:kex": [], "ssh:hostkey": [],
        "ssh:cipher": [], "dhcp:prl": [], "dhcp:vendor": [],
    }
    # Reset and do proper accumulation with group-max logic
    max_possible = {osn: 0.0 for osn in os_list}
    # Determine which exclusive groups are actually represented in the observed
    # trait list so that unobserved groups don't inflate the max_possible
    # denominator and unfairly penalise OSes with richer signature coverage.
    observed_groups: set = set()
    for t in traits:
        for _pfx in _EXCLUSIVE_GROUPS:
            if t.startswith(_pfx + ":") or t == _pfx:
                observed_groups.add(_pfx)
                break
    group_bests: dict = {}  # (osn, group) -> best_contribution
    for trait, info in sig_table.get('traits', {}).items():
        proto = _protocol_of_trait(trait)
        pw = float(protocol_weights.get(proto, 1.0))
        # Scale by the maximum achievable evidence confidence for this protocol.
        # Traits from protocols with no evidence have eff_conf=0 and do not
        # inflate the denominator used for normalisation.
        eff_conf = proto_max_conf.get(proto, 0.0)
        if eff_conf <= 0.0:
            continue  # protocol not observed — skip for max_possible
        group = None
        for prefix in _EXCLUSIVE_GROUPS:
            if trait.startswith(prefix + ":") or trait == prefix:
                group = prefix
                break
        # For exclusive groups, only include if that group was actually observed —
        # this prevents well-characterised OSes (many signatures) from having
        # inflated max_possible relative to simpler ones.
        if group is not None and group not in observed_groups:
            continue
        for osn, strength in sorted(info.get('matches', {}).items()):
            contrib = float(strength) * pw * eff_conf
            if group is not None:
                key = (osn, group)
                if contrib > group_bests.get(key, 0.0):
                    group_bests[key] = contrib
            else:
                max_possible[osn] += contrib
    # Add group-best contributions to max_possible
    for (osn, group), best in group_bests.items():
        max_possible[osn] = max_possible.get(osn, 0.0) + best

    # compute raw scores
    raw_scores = {osn: 0.0 for osn in os_list}
    traits_used = {osn: [] for osn in os_list}
    conflicts = {osn: [] for osn in os_list}

    for trait in traits:
        info = sig_table.get('traits', {}).get(trait)
        if not info:
            continue
        proto = _protocol_of_trait(trait)
        pw = float(protocol_weights.get(proto, 1.0))
        ev_conf = _evidence_confidence_for_trait(trait, host)
        baseline = _is_baseline_trait(trait, host)
        baseline_mul = 0.2 if baseline else 1.0

        for osn, strength in sorted(info.get('matches', {}).items()):
            contrib = float(strength) * ev_conf * pw * baseline_mul
            raw_scores[osn] += contrib
            if contrib > 0:
                traits_used[osn].append((trait, contrib))

    # normalize and apply coverage/ambiguity
    # Infer protocol coverage from evidence attributes (host.protocol_count may be absent)
    evidence_protos = set()
    for ev in (host.get('evidence') or []):
        attr = str(ev.get('attribute') or '')
        if attr.startswith('tcp.') or attr.startswith('ip.'):
            evidence_protos.add('tcp')
        elif attr.startswith('ssh.'):
            evidence_protos.add('ssh')
        elif attr.startswith('dhcp.'):
            evidence_protos.add('dhcp')
        elif attr.startswith('dns.'):
            evidence_protos.add('dns')
        elif attr.startswith('ntp.'):
            evidence_protos.add('ntp')
    if (host.get('tcp_fingerprint') or {}).get('confidence', 0.0) > 0.25:
        evidence_protos.add('tcp')
    if (host.get('ssh_fingerprint') or {}).get('confidence', 0.0) > 0.2:
        evidence_protos.add('ssh')

    protocol_count = max(
        int(host.get('protocol_count') or len(host.get('protocols_seen') or [])),
        len(evidence_protos),
    )
    coverage_factor = min(1.0, 0.3 + 0.7 * min(protocol_count / 2.0, 1.0))
    # incorporate evidence_density optionally (small boost) — deterministic
    evidence_density = float(host.get('evidence_density') or 0.0)
    # scale density via arctan-like bounded function; here simple clamp
    density_factor = min(1.0, evidence_density / 10.0)
    coverage_factor = min(1.0, coverage_factor * (0.9 + 0.1 * density_factor))

    # compute total ambiguity penalty
    amb_flags = host.get('ambiguity') or {}
    total_amb_pen = 0.0
    if amb_flags.get('_nat_suspected') or amb_flags.get('nat_suspected'):
        total_amb_pen += float(ambiguity_penalties.get('nat_suspected', 0.0))
    if amb_flags.get('_shared_ip') or amb_flags.get('shared_ip'):
        total_amb_pen += float(ambiguity_penalties.get('shared_ip', 0.0))
    total_amb_pen = min(total_amb_pen, 1.0)

    results = {}
    for osn in os_list:
        raw = raw_scores.get(osn, 0.0)
        maxp = max_possible.get(osn, 0.0)
        normalized = raw / (maxp + _EPS) if maxp > 0 else 0.0
        # clamp
        if normalized < 0.0:
            normalized = 0.0
        if normalized > 1.0:
            normalized = 1.0

        final = normalized * coverage_factor * (1.0 - total_amb_pen)

        results[osn] = {
            'raw_score': raw,
            'normalized_score': normalized,
            'final_score': final,
            'traits_used': sorted(traits_used.get(osn, [])),
            'conflicts': [],
        }

    # filter by baseline_threshold is not applied here; caller may filter later.
    return results
