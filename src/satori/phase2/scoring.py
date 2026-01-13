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

    # precompute max_possible_score per OS from signature table
    max_possible = {osn: 0.0 for osn in os_list}
    for trait, info in sig_table.get('traits', {}).items():
        proto = _protocol_of_trait(trait)
        pw = float(protocol_weights.get(proto, 1.0))
        for osn, strength in sorted(info.get('matches', {}).items()):
            max_possible[osn] += float(strength) * pw

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
    results = {}
    protocol_count = int(host.get('protocol_count') or len(host.get('protocols_seen') or []))
    coverage_factor = min(1.0, 0.25 + 0.75 * min(protocol_count / 3.0, 1.0))
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
