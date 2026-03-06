"""Assemble deterministic, explainable `os_inference` blocks for Phase 2 (T4).

Consumes Phase 1 host dict, trait list, and scoring results and returns
an `os_inference` dict attached to the host (without mutating original host).
"""
from __future__ import annotations

from typing import Any, Dict, List
import copy
import json
import os
from math import isclose

from .evidence import evidence_sha1, canonicalize_evidence
from .traits import extract_traits
from .scoring import score_host, _load_signature_table
from ..nmap_lookup import lookup_os_from_nmap


_FLOAT_PREC = 3


def _round(f: float) -> float:
    return round(float(f) + 0.0, _FLOAT_PREC)


def _pointer_from_evidence(ev: Dict[str, Any]) -> List[Any]:
    # deterministic pointer: list of possible keys in fixed order if present
    ptr = []
    if 'source' in ev:
        ptr.append(ev.get('source'))
    if 'attribute' in ev:
        ptr.append(ev.get('attribute'))
    if 'flow_id' in ev:
        ptr.append(ev.get('flow_id'))
    if 'timestamp' in ev:
        ptr.append(ev.get('timestamp'))
    if 'packet_index' in ev:
        ptr.append(ev.get('packet_index'))
    return ptr


def _attrs_for_trait(trait: str) -> List[str]:
    """Return the evidence attribute names that correspond to this trait key."""
    # Map trait key prefix to the evidence attribute(s) that produced it.
    # This is the inverse of traits.py extract_*_traits().
    _MAP = {
        "tcp:ttl:": ["ip.ttl"],
        "tcp:window:": ["tcp.window_size"],
        "tcp:mss:": ["tcp.mss"],
        "tcp:wscale:": ["tcp.wscale"],
        "tcp:opts:": ["tcp.opts_order"],
        "tcp:ts:": ["tcp.ts_present"],
        "tcp:ecn:": ["tcp.ecn"],
        "tcp:isn:": ["tcp.isn"],
        "ssh:banner:": ["ssh.banner"],
        "ssh:kex:": ["ssh.kex_algorithms"],
        "ssh:hostkey:": ["ssh.hostkey_algorithms"],
        "ssh:cipher:": ["ssh.encryption_algorithms_c2s", "ssh.encryption_algorithms_s2c"],
        "ssh:mac:": ["ssh.mac_algorithms_c2s", "ssh.mac_algorithms_s2c"],
        "ssh:comp:": ["ssh.comp_algorithms_c2s", "ssh.comp_algorithms_s2c"],
        "ssh:software_family:": ["ssh.software_family"],
        "dhcp:vendor:": ["dhcp.vendor_class"],
        "dhcp:prl:": ["dhcp.param_request_list"],
        "dhcp:msg:": ["dhcp.message_type"],
        "dns:edns:": ["dns.edns"],
        "dns:ttl:": ["dns.ttl"],
        "ntp:mode:": ["ntp.mode"],
    }
    for prefix, attrs in _MAP.items():
        if trait.startswith(prefix):
            return attrs
    # fallback: derive from the first two colon-separated components
    parts = trait.split(":")
    if len(parts) >= 2:
        return [f"{parts[0]}.{parts[1]}"]
    return []


def _evidence_refs_for_trait(trait: str, host: Dict[str, Any]) -> List[Dict[str, Any]]:
    attrs = _attrs_for_trait(trait)
    refs = []
    for ev in host.get('evidence') or []:
        if not isinstance(ev, dict):
            continue
        attr = str(ev.get('attribute') or '')
        if attr in attrs:
            cid = evidence_sha1(ev)
            ptr = _pointer_from_evidence(ev)
            refs.append({
                'evidence_id': cid,
                'trait': trait,
                'contribution': 0.0,
                'pointer': ptr,
            })
    refs = sorted(refs, key=lambda r: (-r['contribution'], r['evidence_id']))
    return refs


def build_os_inference(host: Dict[str, Any], sig_table: Dict[str, Any] = None, nmap_db_path: str = None) -> Dict[str, Any]:
    """Return a new `os_inference` dict for given host without mutating host.

    Enforces determinism and provenance rules described in T4.
    """
    if sig_table is None:
        sig_table = _load_signature_table()

    # copy only for safety; do not mutate input host
    h = copy.deepcopy(host)

    traits = sorted(set(extract_traits(h)))
    scoring = score_host(traits, h, sig_table=sig_table)

    baseline_threshold = float(sig_table.get('baseline_threshold', 0.0))

    candidates = []

    # Build explanation by_trait
    by_trait: Dict[str, Dict[str, float]] = {}

    for trait in traits:
        info = sig_table.get('traits', {}).get(trait) or {}
        matches = info.get('matches', {})
        if not matches:
            continue
        # for each OS that has non-zero contribution in scoring, record exact contrib
        for osn in sorted(matches.keys()):
            # get raw contrib by recomputing per scoring implementation
            # We reuse score_host output to get per-candidate contributions via traits_used
            # Find contribution(s) for this trait in traits_used
            for cand_os, data in scoring.items():
                for t, contrib in data.get('traits_used', []):
                    if t == trait:
                        by_trait.setdefault(trait, {})[cand_os] = _round(contrib)

    # Build candidates list
    for osn, data in sorted(scoring.items()):
        raw = data.get('raw_score', 0.0)
        normalized = data.get('normalized_score', 0.0)
        final = data.get('final_score', 0.0)

        # filter by baseline threshold (normalized or final?) — use normalized against baseline
        if normalized < baseline_threshold:
            continue

        # collect traits matched and evidence refs
        traits_matched = sorted([t for t, _ in data.get('traits_used', [])])

        evidence_refs = []
        # For each trait matched, find evidence refs and attach contribution
        for t, contrib in sorted(data.get('traits_used', []), key=lambda x: x[0]):
            refs = _evidence_refs_for_trait(t, h)
            # attach contribution weight for this trait contribution to each evidence ref equally
            # If multiple evidence items produced the trait, split contribution proportionally by evidence presence
            if refs:
                per_ref = contrib / len(refs)
                for r in refs:
                    r['contribution'] = _round(per_ref)
                    evidence_refs.append(r)
            else:
                # no explicit evidence found; skip (do not create non-proven candidates)
                pass

        # ensure evidence_refs' sorting: contribution DESC, evidence_id ASC
        evidence_refs = sorted(evidence_refs, key=lambda r: (-r['contribution'], r['evidence_id']))

        # If candidate has no non-baseline evidence, omit (per acceptance)
        if not evidence_refs:
            continue

        cand = {
            'name': osn,
            'score': _round(final),
            'traits_matched': sorted(set(traits_matched)),
            'evidence_refs': evidence_refs,
            'conflicts': data.get('conflicts', []),
        }
        candidates.append(cand)

    # sort candidates by score DESC, number of evidence_refs DESC, name ASC
    candidates = sorted(candidates, key=lambda c: (-c['score'], -len(c['evidence_refs']), c['name']))

    # Build explanation summary deterministically: pick top candidate name if exists
    summary = ''
    if candidates:
        top = candidates[0]
        # summary must be deterministic, no free-form generation — construct from known tokens
        summary = f"{top['name']} ranked highest due to {', '.join(sorted(top['traits_matched']))}"

    explanation = {
        'summary': summary,
        'by_trait': {k: {on: v for on, v in sorted(vs.items())} for k, vs in sorted(by_trait.items())},
    }

    metadata = {
        'protocol_coverage': sorted(list(h.get('protocols_seen') or [])),
        'protocol_count': int(h.get('protocol_count') or len(h.get('protocols_seen') or [])),
        'evidence_density': float(h.get('evidence_density') or 0.0),
        'ambiguity_flags': {
            'nat_suspected': bool((h.get('ambiguity') or {}).get('nat_suspected') or (h.get('ambiguity') or {}).get('_nat_suspected')),
            'shared_ip': bool((h.get('ambiguity') or {}).get('shared_ip') or (h.get('ambiguity') or {}).get('_shared_ip')),
        }
    }

    os_inference = {
        'os_inference_schema_version': 'os_inference/v1',
        'signature_table_version': sig_table.get('version', 'sigs/v1') if sig_table else 'sigs/v1',
        'generated_by': 'phase2-v0.1',
        'candidates': candidates,
        'explanation': explanation,
        'metadata': metadata,
    }

    # Optionally augment candidates with Nmap DB lookup
    try:
        nmap_candidates = []
        if nmap_db_path:
            # derive a simple fingerprint dict for lookup (normalize shapes)
            tcp = h.get('tcp_fingerprint') if isinstance(h.get('tcp_fingerprint'), dict) else {}
            # normalize options, ttl, window into a simple form expected by lookup
            norm_tcp = {}
            opts = tcp.get('tcp_options_order') or tcp.get('options') or []
            if opts:
                norm_tcp['options'] = opts
            # ttl can be structure with inferred_initial or numeric
            ttl = None
            if isinstance(tcp.get('ttl'), dict):
                ttl = tcp.get('ttl', {}).get('inferred_initial')
            elif isinstance(tcp.get('ttl'), (int, float)):
                ttl = tcp.get('ttl')
            if ttl is not None:
                norm_tcp['ttl'] = int(ttl)
            # window size: median from window_size.values or direct numeric
            wv = None
            if isinstance(tcp.get('window_size'), dict):
                wv_list = tcp.get('window_size', {}).get('values') or []
                if wv_list:
                    wv = sorted(wv_list)[len(wv_list)//2]
            elif isinstance(tcp.get('window'), (int, float)):
                wv = tcp.get('window')
            if wv is not None:
                norm_tcp['window'] = int(wv)

            fp = {'tcp_fingerprint': norm_tcp, 'ssh_fingerprint': h.get('ssh_fingerprint') if isinstance(h.get('ssh_fingerprint'), dict) else {}}
            nmap_candidates = lookup_os_from_nmap(fp, db_path=nmap_db_path)
            # normalize shape to Phase2 candidate shape
            for nc in nmap_candidates:
                cand = {
                    'name': nc.get('name'),
                    'score': _round(nc.get('score', 0.0)),
                    'traits_matched': [],
                    'evidence_refs': [{'evidence_id': ref} for ref in (nc.get('evidence_refs') or [])],
                    'conflicts': [],
                }
                candidates.append(cand)
    except Exception:
        # fail gracefully: leave original candidates
        pass

    # sort and dedupe candidates deterministically
    # First, round scores and ensure stable ordering
    for c in candidates:
        if 'score' in c:
            c['score'] = _round(c['score'])

    # remove duplicate names keeping highest score
    seen = {}
    for c in candidates:
        name = c.get('name')
        if name in seen:
            # keep max score one
            if c.get('score', 0) > seen[name].get('score', 0):
                seen[name] = c
        else:
            seen[name] = c

    merged = list(seen.values())
    merged = sorted(merged, key=lambda c: (-c.get('score', 0.0), c.get('name')))

    os_inference['candidates'] = merged

    return os_inference
