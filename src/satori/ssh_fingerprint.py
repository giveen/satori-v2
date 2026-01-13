from __future__ import annotations

import dataclasses
import typing as t
from collections import defaultdict


@dataclasses.dataclass
class SSHFingerprint:
    ssh_banner: list
    ssh_software_family: list
    kex_algorithms: list
    hostkey_algorithms: list
    encryption_algorithms_c2s: list
    encryption_algorithms_s2c: list
    mac_algorithms_c2s: list
    mac_algorithms_s2c: list
    compression_algorithms_c2s: list
    compression_algorithms_s2c: list
    first_kex_packet_follows_present: bool
    provenance: dict
    confidence: float


def _uniq_preserve(seq):
    seen = set()
    out = []
    for x in seq:
        key = tuple(x) if isinstance(x, (list, tuple)) else x
        if key not in seen:
            seen.add(key)
            out.append(x)
    return out


def build_ssh_fingerprint(host) -> SSHFingerprint:
    """Aggregate SSH-related evidence from `host.evidence` into SSHFingerprint.

    Read-only reducer: uses only `host.evidence` and `host.ambiguity`.
    """
    banners = []
    families = []
    kexs = []
    hostkeys = []
    enc_c2s = []
    enc_s2c = []
    mac_c2s = []
    mac_s2c = []
    comp_c2s = []
    comp_s2c = []
    first_kex_present = False
    provenance = defaultdict(set)

    for ev in host.evidence:
        attr = ev.get("attribute")
        val = ev.get("value")
        prov = ev.get("provenance") or {}
        flow_id = prov.get("flow_id") if isinstance(prov, dict) else None
        if attr == "ssh.banner":
            banners.append(val)
            if flow_id:
                provenance["banner"].add(flow_id)
        elif attr == "ssh.software_family":
            families.append(val)
            if flow_id:
                provenance["software_family"].add(flow_id)
        elif attr == "ssh.kex_algorithms":
            # expect list
            kexs.extend(val or [])
            if flow_id:
                provenance["kex_algorithms"].add(flow_id)
        elif attr == "ssh.hostkey_algorithms":
            hostkeys.extend(val or [])
            if flow_id:
                provenance["hostkey_algorithms"].add(flow_id)
        elif attr == "ssh.encryption_algorithms_c2s":
            enc_c2s.extend(val or [])
            if flow_id:
                provenance["enc_c2s"].add(flow_id)
        elif attr == "ssh.encryption_algorithms_s2c":
            enc_s2c.extend(val or [])
            if flow_id:
                provenance["enc_s2c"].add(flow_id)
        elif attr == "ssh.mac_algorithms_c2s":
            mac_c2s.extend(val or [])
            if flow_id:
                provenance["mac_c2s"].add(flow_id)
        elif attr == "ssh.mac_algorithms_s2c":
            mac_s2c.extend(val or [])
            if flow_id:
                provenance["mac_s2c"].add(flow_id)
        elif attr == "ssh.comp_algorithms_c2s":
            comp_c2s.extend(val or [])
            if flow_id:
                provenance["comp_c2s"].add(flow_id)
        elif attr == "ssh.comp_algorithms_s2c":
            comp_s2c.extend(val or [])
            if flow_id:
                provenance["comp_s2c"].add(flow_id)
        elif attr == "ssh.first_kex_packet_follows":
            # boolean
            if val:
                first_kex_present = True
            if flow_id:
                provenance["first_kex"].add(flow_id)

    # Deduplicate and sort for deterministic output across runs
    banners_u = _uniq_preserve(banners)
    families_u = _uniq_preserve(families)
    kex_u = sorted(set(kexs))
    hostkeys_u = sorted(set(hostkeys))
    enc_c2s_u = sorted(set(enc_c2s))
    enc_s2c_u = sorted(set(enc_s2c))
    mac_c2s_u = sorted(set(mac_c2s))
    mac_s2c_u = sorted(set(mac_s2c))
    comp_c2s_u = sorted(set(comp_c2s))
    comp_s2c_u = sorted(set(comp_s2c))

    # Fields observed count -> confidence
    total_fields = 7  # banner, family, kex, hostkey, enc, mac, comp (first_kex is minor)
    present = 0
    if banners_u:
        present += 1
    if families_u:
        present += 1
    if kex_u:
        present += 1
    if hostkeys_u:
        present += 1
    if enc_c2s_u or enc_s2c_u:
        present += 1
    if mac_c2s_u or mac_s2c_u:
        present += 1
    if comp_c2s_u or comp_s2c_u:
        present += 1

    completeness = present / total_fields
    confidence = 0.2 + 0.6 * completeness
    # penalize for ambiguity
    if host.ambiguity.get("nat_suspected") or host.ambiguity.get("shared_ip"):
        confidence *= 0.6

    ssh_f = SSHFingerprint(
        ssh_banner=banners_u,
        ssh_software_family=families_u,
        kex_algorithms=kex_u,
        hostkey_algorithms=hostkeys_u,
        encryption_algorithms_c2s=enc_c2s_u,
        encryption_algorithms_s2c=enc_s2c_u,
        mac_algorithms_c2s=mac_c2s_u,
        mac_algorithms_s2c=mac_s2c_u,
        compression_algorithms_c2s=comp_c2s_u,
        compression_algorithms_s2c=comp_s2c_u,
        first_kex_packet_follows_present=first_kex_present,
        provenance={k: sorted(list(v)) for k, v in provenance.items()},
        confidence=round(float(max(0.0, min(1.0, confidence))), 3),
    )

    return ssh_f
