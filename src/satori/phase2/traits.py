"""Deterministic trait extraction from Phase 1 host summaries.

Pure functions that map Phase 1 host dicts into a sorted list of
normalized trait keys. No scoring or OS mapping performed here.
"""
from __future__ import annotations

from typing import List, Dict, Any, Tuple
from .evidence import evidence_sha1
import re


_NON_ALNUM_RE = re.compile(r"[^0-9a-z]+")


def _kex_family(k: str) -> str:
    """Return a canonical KEX family name preserving discriminating DH subtype info."""
    k = k.lower().split('@')[0]
    # Diffie-Hellman variants — split semantically, not just by first '-' token
    if k.startswith('diffie-hellman-group-exchange'):
        return 'dh_gex'
    if k.startswith('diffie-hellman-group14'):
        return 'dh_group14'
    if k.startswith('diffie-hellman-group16'):
        return 'dh_group16'
    if k.startswith('diffie-hellman-group18'):
        return 'dh_group18'
    if k.startswith('diffie-hellman-group1'):
        return 'dh_group1'
    if k.startswith('diffie-hellman'):
        return 'dh_group14'  # unknown DH group — treat as group14 (most common)
    if k.startswith('ecdh'):
        return 'ecdh'  # covers nistp256/384/521 and other ecdh variants
    if k.startswith('curve25519'):
        return 'curve25519'
    if k.startswith('gss'):
        return 'gss'
    # fallback: take first hyphen-separated token
    return _norm_token(k.split('-')[0])


def _ssh_software_family(banner: str) -> str | None:
    """Extract OS-discriminating software family from an SSH banner string.

    Returns a compact lowercase identifier suitable for use in trait keys,
    or None if no recognizable pattern is found.
    """
    b = banner.lower()
    # Strip transport-layer prefix (SSH-2.0-, SSH-1.99-, etc.)
    for pfx in ('ssh-2.0-', 'ssh-1.99-', 'ssh-1.5-'):
        if b.startswith(pfx):
            b = b[len(pfx):]
            break
    if 'cisco' in b:
        return 'cisco'
    if 'dropbear' in b:
        return 'dropbear'
    if 'libssh2' in b:
        return 'libssh2'
    if 'libssh' in b:
        return 'libssh'
    if 'openssh' in b:
        # Distro-specific package build comments follow in the version string
        if 'ubuntu' in b:
            return 'openssh_ubuntu'
        if 'debian' in b:
            return 'openssh_debian'
        if 'freebsd' in b or 'hpn' in b:
            return 'openssh_freebsd'
        if 'raspbian' in b:
            return 'openssh_debian'  # Raspbian is Debian-based
        return 'openssh'
    return None


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

    # wscale — use the mode (most frequent observed value) to avoid outliers
    wsc = tcp.get("wscale", {}).get("values") or []
    if wsc:
        try:
            wsc_vals = [int(x) for x in wsc]
            mode_val = max(set(wsc_vals), key=wsc_vals.count)
            traits.append((f"tcp:wscale:{mode_val}", False, None))
        except Exception:
            pass

    # options: emit a separate trait for each individual opts pattern observed
    opts = tcp.get("tcp_options_order") or []
    seen_opts: set = set()
    for opt_pattern in opts:
        normed = _norm_token(opt_pattern)
        if normed and normed not in seen_opts:
            seen_opts.add(normed)
            traits.append((f"tcp:opts:{normed}", False, None))

    # ts_present — only emit when we have a definitive answer (not unknown/mixed)
    ts = tcp.get("ts_present")
    if ts is not None:
        ts_lower = str(ts).lower()
        if ts_lower in ("present", "true"):
            traits.append(("tcp:ts:present", False, None))
        elif ts_lower in ("absent", "false"):
            traits.append(("tcp:ts:absent", False, None))
        # unknown / mixed → don't emit any ts trait

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

    # banner — extract software family for OS-discriminating signal
    banners = ssh.get("ssh_banner") or []
    if banners:
        b = banners[0]
        fam = _ssh_software_family(b)
        if fam:
            traits.append((f"ssh:banner:{fam}", False, None))

    # kex algorithms — use _kex_family() to preserve DH subtype info
    kexs = ssh.get("kex_algorithms") or []
    kex_names = set()
    for k in kexs:
        if not isinstance(k, str):
            continue
        kex_names.add(_kex_family(k))
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


def _decode_dhcp_vendor(val) -> str | None:
    """Decode a DHCP vendor class value which may be hex-encoded bytes or raw ASCII."""
    if not val:
        return None
    if isinstance(val, bytes):
        return val.decode("ascii", errors="replace").strip() or None
    if isinstance(val, str):
        # If the evidence was serialised through make_evidence, bytes→hex was applied.
        # Try to hex-decode to recover the original ASCII text.
        try:
            decoded = bytes.fromhex(val).decode("ascii", errors="replace")
            if any(c.isalpha() for c in decoded):
                return decoded.strip()
        except Exception:
            pass
        return val.strip() or None
    return None


def _extract_dhcp_traits(host: Dict[str, Any]) -> List[Tuple[str, bool, str]]:
    traits = []
    for ev in host.get("evidence", []) or []:
        # support both normalized evidence items and legacy structures
        if not isinstance(ev, dict):
            continue
        attr = ev.get("attribute")

        if attr == "dhcp.param_request_list":
            val = ev.get("value")
            if isinstance(val, bytes):
                val = val.hex()
            if isinstance(val, str) and val:
                traits.append((f"dhcp:prl:{_norm_token(val)}", False, evidence_sha1(ev)))

        elif attr == "dhcp.vendor_class_id":
            text = _decode_dhcp_vendor(ev.get("value"))
            if text:
                normed = _norm_token(text[:50])
                if normed:
                    traits.append((f"dhcp:vendor:{normed}", False, evidence_sha1(ev)))

        # legacy top-level dhcp blocks (raw extractor dicts)
        if ev.get("type") == "dhcp" and isinstance(ev.get("dhcp"), dict):
            opts = ev.get("dhcp", {}).get("options") or {}
            # message type — option 53 (may be bytes, int, or hex string)
            mt_raw = opts.get(53) or opts.get("53")
            if mt_raw:
                try:
                    if isinstance(mt_raw, (bytes, bytearray)):
                        mt_i = mt_raw[0]
                    elif isinstance(mt_raw, int):
                        mt_i = mt_raw
                    else:
                        mt_i = int(str(mt_raw), 16)
                    mt_map = {1: "discover", 2: "offer", 3: "request", 4: "decline",
                              5: "ack", 8: "inform"}
                    mname = mt_map.get(mt_i, f"type{mt_i}")
                    traits.append((f"dhcp:msg:{mname}", False, evidence_sha1(ev)))
                except Exception:
                    pass
            # vendor class — option 60
            vendor_raw = opts.get(60) or opts.get("60")
            if vendor_raw:
                text = _decode_dhcp_vendor(vendor_raw)
                if text:
                    normed = _norm_token(text[:50])
                    if normed:
                        traits.append((f"dhcp:vendor:{normed}", False, evidence_sha1(ev)))

    return traits


def _extract_dns_ntp_traits(host: Dict[str, Any]) -> List[Tuple[str, bool, str]]:
    traits = []
    for ev in host.get("evidence", []) or []:
        if not isinstance(ev, dict):
            continue
        attr = ev.get("attribute") or ""

        # --- DNS ---
        if attr == "dns.edns_present":
            val = ev.get("value")
            if val is True or val == 1 or str(val).lower() == "true":
                traits.append(("dns:edns:present", False, evidence_sha1(ev)))
            elif val is False or val == 0 or str(val).lower() == "false":
                traits.append(("dns:edns:absent", False, evidence_sha1(ev)))

        elif attr == "dns.edns_buf_size":
            val = ev.get("value")
            try:
                v = int(val)
                # Bucket into known OS-correlated sizes
                if v >= 4096:
                    traits.append(("dns:edns_buf:4096", False, evidence_sha1(ev)))
                elif v >= 1280:
                    traits.append(("dns:edns_buf:1280", False, evidence_sha1(ev)))
                elif v >= 1232:
                    traits.append(("dns:edns_buf:1232", False, evidence_sha1(ev)))
                elif v >= 512:
                    traits.append(("dns:edns_buf:512", False, evidence_sha1(ev)))
            except Exception:
                pass

        elif attr.startswith("dns.ttl"):
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

        # --- NTP ---
        elif attr == "ntp.version":
            val = ev.get("value")
            try:
                v = int(val)
                if v in (2, 3, 4):
                    traits.append((f"ntp:version:{v}", False, evidence_sha1(ev)))
            except Exception:
                pass

        elif attr == "ntp.stratum":
            val = ev.get("value")
            try:
                v = int(val)
                # Only standard stratum values 0-15 are spec-defined
                if 0 <= v <= 15:
                    traits.append((f"ntp:stratum:{v}", False, evidence_sha1(ev)))
            except Exception:
                pass

        elif attr == "ntp.ref_id":
            val = ev.get("value")
            if isinstance(val, str) and val:
                normed = _norm_token(val)
                if normed:
                    traits.append((f"ntp:ref_id:{normed}", False, evidence_sha1(ev)))

        elif attr == "ntp.mode":
            val = ev.get("value")
            if val and str(val).lower().startswith("client"):
                traits.append(("ntp:mode:client", False, evidence_sha1(ev)))

    return traits


def _extract_tls_traits(host: Dict[str, Any]) -> List[Tuple[str, bool, str]]:
    """Extract TLS/JA3 traits from host evidence.

    Looks for ``tls.ja3`` evidence attributes and emits ``tls:ja3:{hash}`` traits.
    """
    traits = []
    for ev in host.get("evidence", []) or []:
        if not isinstance(ev, dict):
            continue
        attr = ev.get("attribute") or ""
        if attr == "tls.ja3":
            val = ev.get("value")
            if isinstance(val, str) and len(val) == 32 and all(c in "0123456789abcdef" for c in val):
                traits.append((f"tls:ja3:{val}", False, evidence_sha1(ev)))
    return traits


def _extract_tcp_ja4t_traits(host: Dict[str, Any]) -> List[Tuple[str, bool, str]]:
    """Extract JA4T composite TCP fingerprint traits from host evidence.

    Looks for ``tcp.ja4t`` evidence attributes and emits ``tcp:ja4t:{fingerprint}``
    traits.  Only the first (oldest, from SYN) JA4T value per host is used to
    avoid drift from retransmissions.
    """
    traits = []
    seen: set = set()
    for ev in host.get("evidence", []) or []:
        if not isinstance(ev, dict):
            continue
        if (ev.get("attribute") or "") == "tcp.ja4t":
            val = ev.get("value")
            if isinstance(val, str) and val and val not in seen:
                seen.add(val)
                traits.append((f"tcp:ja4t:{val}", False, evidence_sha1(ev)))
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
    traits_with_meta.extend(_extract_tls_traits(host))
    traits_with_meta.extend(_extract_tcp_ja4t_traits(host))

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
