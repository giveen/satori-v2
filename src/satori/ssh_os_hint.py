from __future__ import annotations

import dataclasses
import typing as t


@dataclasses.dataclass
class SSHOSHint:
    os_family: str
    confidence: float
    provenance: list


_FAMILY_MAP = {
    "openssh": "Linux",
    "dropbear": "Embedded-Linux",
    "win32-openssh": "Windows",
    "windows": "Windows",
}


def _map_family(fam: str) -> str:
    if not fam:
        return "Unknown"
    lf = fam.lower()
    for k, v in _FAMILY_MAP.items():
        if k in lf:
            return v
    # fallback heuristics
    if "openssh" in lf:
        return "Linux"
    if "dropbear" in lf:
        return "Embedded-Linux"
    if "win" in lf:
        return "Windows"
    return "Unknown"


def build_ssh_os_hint(host) -> list[SSHOSHint]:
    # type: (object) -> list
    hints: list[SSHOSHint] = []
    sf = getattr(host, "ssh_fingerprint", None)
    if sf is None:
        return []

    # Determine candidate families from ssh_software_family and banners
    families = list(getattr(sf, "ssh_software_family", []) or [])
    # also inspect banners for heuristic cues
    banners = getattr(sf, "ssh_banner", []) or []
    for b in banners:
        try:
            bl = b.lower()
            if "openssh" in bl and "openssh" not in families:
                families.append("openssh")
            if "dropbear" in bl and "dropbear" not in families:
                families.append("dropbear")
            if "windows" in bl and "windows" not in families:
                families.append("windows")
        except Exception:
            continue

    # If no families found, return empty list
    if not families:
        return []

    # provenance union across relevant keys
    prov_map = getattr(sf, "provenance", {}) or {}
    def collect_prov():
        s = set()
        for k in ("banner", "software_family", "kex_algorithms", "hostkey_algorithms"):
            for v in prov_map.get(k, []):
                s.add(v)
        return sorted(list(s))

    base_conf = getattr(sf, "confidence", 0.0) if isinstance(getattr(sf, "confidence", None), float) else 0.0

    for fam in families:
        osf = _map_family(fam)
        # hint confidence: fraction of ssh fields observed scaled and capped at 0.3
        conf = base_conf * 0.5
        # penalty for ambiguity
        if getattr(host, "ambiguity", {}).get("nat_suspected") or getattr(host, "ambiguity", {}).get("shared_ip"):
            conf *= 0.6
        if conf > 0.3:
            conf = 0.3

        hints.append(SSHOSHint(os_family=osf, confidence=round(conf, 3), provenance=collect_prov()))

    return hints
