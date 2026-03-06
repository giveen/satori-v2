#!/usr/bin/env python3
"""
Import nmap-os-db and p0f.fp fingerprint databases into Satori's v1.json
signature file.

This script:
1. Parses nmap-os-db and p0f.fp TCP SYN signatures
2. Computes per-OS trait frequency scores
3. Merges (adds new / updates) traits in src/signatures/v1.json

Usage:
    python3 scripts/db_import/import_databases.py [--dry-run] [--verbose]

Options:
    --dry-run   Print computed traits without writing v1.json
    --verbose   Print detailed debug information
    --replace   Replace v1.json scores entirely (default: blend with existing)
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
V1_JSON = ROOT / "src" / "signatures" / "v1.json"
NMAP_DB = ROOT / "scripts" / "db_import" / "nmap-os-db"
P0F_DB = ROOT / "scripts" / "db_import" / "p0f.fp"

# ─────────────────────────────────────────────────────────────────────────────
# OS Name Normalisation
# ─────────────────────────────────────────────────────────────────────────────

# Satori canonical OS names  
SATORI_OS = {
    "Alpine Linux", "Android", "CentOS", "Cisco IOS", "Debian",
    "FreeBSD", "Linux", "OpenBSD", "RHEL", "Solaris",
    "Ubuntu", "Windows", "Windows Server", "iOS", "macOS",
}

# Map source OS strings → Satori canonical name
# (checked against both nmap Class[1] and p0f label class/name fields)
_NMAP_OS_MAP = {
    # Linux variants
    "linux": "Linux",
    "linux kernel": "Linux",
    "openwrt": "Linux",
    "dd-wrt": "Linux",
    "alpine linux": "Alpine Linux",
    "android": "Android",
    "android tv": "Android",
    # Windows
    "windows xp": "Windows",
    "windows vista": "Windows",
    "windows 7": "Windows",
    "windows 8": "Windows",
    "windows 8.1": "Windows",
    "windows 10": "Windows",
    "windows 11": "Windows",
    "windows nt": "Windows",
    "windows me": "Windows",
    "windows 95": "Windows",
    "windows 98": "Windows",
    "windows server 2003": "Windows Server",
    "windows server 2008": "Windows Server",
    "windows server 2012": "Windows Server",
    "windows server 2016": "Windows Server",
    "windows server 2019": "Windows Server",
    "windows server 2022": "Windows Server",
    # macOS / iOS
    "macos": "macOS",
    "mac os x": "macOS",
    "ios": "iOS",
    "darwin": "macOS",
    # BSD
    "freebsd": "FreeBSD",
    "openbsd": "OpenBSD",
    "netbsd": None,  # skip
    # Other Unix
    "solaris": "Solaris",
    "sunos": "Solaris",
    # Network equipment
    "cisco ios": "Cisco IOS",
    "cisco": "Cisco IOS",
    "ios xe": "Cisco IOS",
    "nx-os": "Cisco IOS",
}

# Windows Server version tokens (if nmap Class[2], i.e. OS version, is one of these)
WINDOWS_SERVER_VERSIONS = {"2000", "2003", "2008", "2012", "2016", "2019", "2022"}


def nmap_class_to_satori(vendor: str, os_family: str, os_gen: str, devtype: str) -> str | None:
    """Map nmap Class fields to a Satori canonical OS name."""
    vendor_l = vendor.strip().lower()
    os_l = os_family.strip().lower()
    gen_l = os_gen.strip().lower()

    # Direct lookup first
    if os_l in _NMAP_OS_MAP:
        result = _NMAP_OS_MAP[os_l]
        # Refine Windows vs Windows Server by version
        if result == "Windows" and gen_l in WINDOWS_SERVER_VERSIONS:
            return "Windows Server"
        return result

    # Compound checks
    if os_l.startswith("windows"):
        if any(sv in gen_l for sv in WINDOWS_SERVER_VERSIONS):
            return "Windows Server"
        if "mobile" in os_l or "pocketpc" in os_l or "ce" in os_l:
            return None  # skip mobile Windows
        return "Windows"

    if vendor_l in ("apple",):
        if os_l in ("macos", "mac os x"):
            return "macOS"
        if os_l == "ios":
            return "iOS"

    if vendor_l in ("cisco", "cisco systems"):
        return "Cisco IOS"

    if vendor_l in ("google",) and "android" in os_l:
        return "Android"

    return None  # unknown / skip


def p0f_label_to_satori(label_class: str, label_os: str) -> str | None:
    """Map p0f label class+os to Satori canonical OS name."""
    lc = label_class.strip().lower()
    los = label_os.strip().lower()

    lookup = f"{lc}:{los}"
    if "linux" in los and "android" in los:
        return None  # skip ambiguous p0f Android entries (use nmap for Android)
    if "linux" in los:
        return "Linux"
    if "windows" in los:
        return "Windows"
    if "mac os x" in los or "macos x" in los or "macos" in los:
        return "macOS"
    if los == "ios":
        return "iOS"
    if "freebsd" in los:
        return "FreeBSD"
    if "openbsd" in los:
        return "OpenBSD"
    if "solaris" in los:
        return "Solaris"
    if "android" in los:
        return "Android"
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Trait key normalisation helpers (matches traits.py logic)
# ─────────────────────────────────────────────────────────────────────────────

_NON_ALNUM_RE = re.compile(r"[^0-9a-z]+")


def norm_token(s: str) -> str:
    s = str(s).lower().strip()
    s = _NON_ALNUM_RE.sub("_", s)
    s = s.strip("_")
    return s


def opts_list_to_trait_key(kinds: list[int]) -> str:
    """Convert a list of TCP option kind ints to a Satori trait key suffix."""
    return norm_token(str(kinds))


# ─────────────────────────────────────────────────────────────────────────────
# TTL binning (matches traits.py)
# ─────────────────────────────────────────────────────────────────────────────

def ttl_bin(val: int) -> int | None:
    """Bin an observed initial TTL to the standard initial value."""
    try:
        v = int(val)
    except Exception:
        return None
    if v <= 32:
        return 32
    if v <= 64:
        return 64
    if v <= 128:
        return 128
    return 255


# ─────────────────────────────────────────────────────────────────────────────
# p0f.fp Parser
# ─────────────────────────────────────────────────────────────────────────────

# p0f option name → TCP kind number
P0F_OPT_KINDS = {
    "eol": 0,
    "nop": 1,
    "mss": 2,
    "ws":  3,
    "sok": 4,
    "sack": 4,
    "ts":  8,
    "md5": 19,
}


def parse_p0f_opts(olayout: str) -> list[int] | None:
    """Parse p0f olayout string (e.g. 'mss,sok,ts,nop,ws') → list of kinds."""
    if not olayout or olayout.strip() in ("*", ""):
        return None
    kinds = []
    for tok in olayout.split(","):
        tok = tok.strip().lower()
        # Handle eol+N
        base = tok.split("+")[0]
        if base in P0F_OPT_KINDS:
            kind = P0F_OPT_KINDS[base]
            if base != "eol":  # skip EOL (kind 0), rarely matches
                kinds.append(kind)
        # Unknown option → skip silently
    return kinds if kinds else None


def parse_p0f_sig(sig_str: str):
    """
    Parse a p0f SYN sig line.
    Format: ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass

    Returns dict with keys: ttl, mss, window, wscale, opts_kinds or None.
    """
    parts = sig_str.strip().split(":")
    if len(parts) < 8:
        return None
    _ver, ittl_s, _olen, mss_s, wwin_s, olayout, _quirks, _pclass = parts[:8]

    result = {}

    # TTL
    ittl_s = ittl_s.strip()
    if ittl_s not in ("*", ""):
        try:
            raw_ttl = int(ittl_s.rstrip("+"))  # '64+' means "at least 64"
            binned = ttl_bin(raw_ttl)
            if binned:
                result["ttl"] = binned
        except ValueError:
            pass

    # MSS
    mss_s = mss_s.strip()
    if mss_s not in ("*", ""):
        try:
            result["mss"] = int(mss_s)
        except ValueError:
            pass

    # Window size and scale
    wwin_s = wwin_s.strip()
    if "," in wwin_s:
        wsize_s, scale_s = wwin_s.split(",", 1)
        wsize_s = wsize_s.strip()
        scale_s = scale_s.strip()

        # Window size: could be value, mss*N, mtu*N, or *
        if wsize_s not in ("*", "") and not wsize_s.startswith("mss") and not wsize_s.startswith("mtu"):
            try:
                result["window"] = int(wsize_s)
            except ValueError:
                pass

        # Window scale
        if scale_s not in ("*", ""):
            try:
                result["wscale"] = int(scale_s)
            except ValueError:
                pass

    # Options layout
    opts = parse_p0f_opts(olayout)
    if opts:
        result["opts_kinds"] = opts
        # ts present if kind 8 in opts
        result["ts_present"] = 8 in opts

    return result if result else None


def load_p0f(path: Path, verbose: bool = False) -> list[tuple[str, dict]]:
    """
    Parse p0f.fp and return list of (satori_os, parsed_sig) tuples.
    Only parses [tcp:request] section.
    """
    records = []
    section = None
    current_label = None
    current_os = None

    with open(path, encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith(";"):
                continue

            # Section header
            if line.startswith("["):
                section = line.strip("[]")
                current_label = None
                current_os = None
                continue

            if section != "tcp:request":
                continue

            if line.startswith("label"):
                # label = type:class:OS:version
                val = line.split("=", 1)[1].strip()
                parts = val.split(":")
                if len(parts) >= 3:
                    ltype = parts[0].strip()   # s=specific, g=generic, !
                    lclass = parts[1].strip()  # unix, win, other, !
                    los = parts[2].strip()     # OS name
                    # Skip generic catch-all signatures (g:)
                    if ltype == "g":
                        current_os = None
                        continue
                    satori_os = p0f_label_to_satori(lclass, los)
                    current_os = satori_os
                    if verbose and satori_os:
                        print(f"  p0f label → {satori_os}  (from {val})")
                continue

            if line.startswith("sig") and current_os:
                val = line.split("=", 1)[1].strip()
                parsed = parse_p0f_sig(val)
                if parsed:
                    records.append((current_os, parsed))

    return records


# ─────────────────────────────────────────────────────────────────────────────
# nmap-os-db Parser
# ─────────────────────────────────────────────────────────────────────────────

# nmap OPS option string character → TCP kind
NMAP_OPT_KINDS = {
    'M': 2,   # MSS (followed by hex value)
    'N': 1,   # NOP
    'L': 1,   # another NOP token
    'S': 4,   # SACK permitted
    'W': 3,   # Window scale (followed by hex value)
    'T': 8,   # Timestamp (followed by two hex values)
    'E': 0,   # EOL (skip)
}


def parse_nmap_ops(ops_str: str) -> list[int] | None:
    """
    Parse nmap OPS option string, e.g. 'M5B4NNSW0NNNT11'.
    Returns list of TCP option kind ints.
    """
    if not ops_str or ops_str.strip() in ("*", ""):
        return None
    kinds = []
    i = 0
    s = ops_str.strip()
    while i < len(s):
        c = s[i].upper()
        if c == 'M':
            # MSS — consume hex digits
            j = i + 1
            while j < len(s) and s[j] in "0123456789ABCDEFabcdef":
                j += 1
            kinds.append(2)
            i = j
        elif c in ('N', 'L'):
            kinds.append(1)
            i += 1
        elif c == 'S':
            kinds.append(4)
            i += 1
        elif c == 'W':
            # Window scale — consume hex digits
            j = i + 1
            while j < len(s) and s[j] in "0123456789ABCDEFabcdef":
                j += 1
            kinds.append(3)
            i = j
        elif c == 'T':
            # Timestamp — consume up to 2 hex groups
            j = i + 1
            # first value
            while j < len(s) and s[j] in "0123456789ABCDEFabcdef":
                j += 1
            # second value (may start with another hex run)
            while j < len(s) and s[j] in "0123456789ABCDEFabcdef":
                j += 1
            kinds.append(8)
            i = j
        elif c == 'E':
            # EOL — skip
            i += 1
        elif c == '%':
            break  # end of option string (shouldn't happen if split correctly)
        else:
            i += 1  # unknown, skip
    return kinds if kinds else None


def parse_nmap_ops_mss(ops_str: str) -> int | None:
    """Extract MSS value from nmap OPS option string."""
    if not ops_str:
        return None
    m = re.match(r'^M([0-9A-Fa-f]+)', ops_str.strip())
    if m:
        try:
            return int(m.group(1), 16)
        except ValueError:
            pass
    return None


def parse_nmap_ops_wscale(ops_str: str) -> int | None:
    """Extract window scale value from nmap OPS option string."""
    if not ops_str:
        return None
    m = re.search(r'W([0-9A-Fa-f]+)', ops_str.strip())
    if m:
        try:
            return int(m.group(1), 16)
        except ValueError:
            pass
    return None


def parse_t_line(t_str: str) -> int | None:
    """
    Extract TTL from a nmap T1/T2/... line value string like:
    'R=Y%DF=Y%T=40%TG=40%S=Z%...'
    Returns binned TTL int or None.
    """
    # Prefer T= over TG= (TG is a guess)
    m_t = re.search(r'\bT=([0-9A-Fa-f]+(?:-[0-9A-Fa-f]+)?)', t_str)
    m_tg = re.search(r'\bTG=([0-9A-Fa-f]+)', t_str)

    ttl_hex = None
    if m_t:
        raw = m_t.group(1)
        # could be a range like "FA-104", take the TG guess instead
        if '-' in raw:
            if m_tg:
                ttl_hex = m_tg.group(1)
        else:
            ttl_hex = raw
    elif m_tg:
        ttl_hex = m_tg.group(1)

    if ttl_hex:
        try:
            return ttl_bin(int(ttl_hex, 16))
        except ValueError:
            pass
    return None


def parse_win_line(win_str: str) -> list[int]:
    """
    Extract window sizes from a nmap WIN line value string like:
    'W1=8000%W2=8000%W3=8000%W4=8000%W5=8000%W6=8000'
    Returns list of unique window sizes (decimal ints).
    """
    sizes = []
    for m in re.finditer(r'W\d=([0-9A-Fa-f]+)', win_str):
        try:
            sizes.append(int(m.group(1), 16))
        except ValueError:
            pass
    return list(set(sizes))


def load_nmap(path: Path, verbose: bool = False) -> list[tuple[str, dict]]:
    """
    Parse nmap-os-db and return list of (satori_os, feature_dict) tuples.
    feature_dict may contain: ttl, windows (list), opts_kinds, mss, wscale, ts_present
    """
    records = []
    current_os_names: list[str] = []
    current_data: dict = {}
    in_block = False

    def flush_block():
        nonlocal current_os_names, current_data, in_block
        if in_block and current_os_names and current_data:
            for os_name in current_os_names:
                records.append((os_name, dict(current_data)))
        current_os_names = []
        current_data = {}
        in_block = False

    with open(path, encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("Fingerprint "):
                flush_block()
                in_block = True
                continue

            if not in_block:
                continue

            if line.startswith("Class "):
                # Class <vendor> | <OS family> | <OS gen> | <devtype>
                body = line[len("Class "):].strip()
                parts = [p.strip() for p in body.split("|")]
                vendor = parts[0] if len(parts) > 0 else ""
                os_fam = parts[1] if len(parts) > 1 else ""
                os_gen = parts[2] if len(parts) > 2 else ""
                devtype = parts[3] if len(parts) > 3 else ""
                satori = nmap_class_to_satori(vendor, os_fam, os_gen, devtype)
                if satori and satori not in current_os_names:
                    current_os_names.append(satori)
                    if verbose:
                        print(f"  nmap class → {satori}  ({body})")
                continue

            # T1 line (only T1, not T2-T7 which sometimes probe weird packets)
            if line.startswith("T1("):
                body = line[3:].rstrip(")")
                ttl = parse_t_line(body)
                if ttl and "ttl" not in current_data:
                    current_data["ttl"] = ttl
                continue

            if line.startswith("WIN("):
                body = line[4:].rstrip(")")
                wins = parse_win_line(body)
                if wins:
                    current_data.setdefault("windows", set()).update(wins)
                continue

            if line.startswith("OPS("):
                body = line[4:].rstrip(")")
                # Parse O1 through O6 (all probes)
                for m in re.finditer(r'O\d=([^%]+)', body):
                    ops_str = m.group(1)
                    if ops_str in ("*", ""):
                        continue
                    kinds = parse_nmap_ops(ops_str)
                    if kinds:
                        key = tuple(kinds)
                        current_data.setdefault("opts_patterns", set()).add(key)

                    mss = parse_nmap_ops_mss(ops_str)
                    if mss and mss not in (0, 0xFFFF):
                        current_data.setdefault("mss_values", set()).add(mss)

                    wscale = parse_nmap_ops_wscale(ops_str)
                    if wscale is not None:
                        current_data.setdefault("wscale_values", set()).add(wscale)

                    # ts_present: if T appears in ops string
                    if re.search(r'T[0-9A-Fa-f]', ops_str):
                        current_data["ts_present"] = True
                continue

    flush_block()

    # Normalise dict values (sets → lists, etc.)
    result = []
    for os_name, d in records:
        normed = {}
        if "ttl" in d:
            normed["ttl"] = d["ttl"]
        if "windows" in d:
            normed["windows"] = sorted(d["windows"])
        if "opts_patterns" in d:
            normed["opts_patterns"] = [list(t) for t in d["opts_patterns"]]
        if "mss_values" in d:
            normed["mss_values"] = sorted(d["mss_values"])
        if "wscale_values" in d:
            normed["wscale_values"] = sorted(d["wscale_values"])
        if "ts_present" in d:
            normed["ts_present"] = d["ts_present"]
        if normed:
            result.append((os_name, normed))

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Score computation
# ─────────────────────────────────────────────────────────────────────────────

def build_counts(records: list[tuple[str, dict]]) -> dict[str, dict[str, int]]:
    """
    From records (os, feature_dict), build:
        trait_key → {os_name: count}
    where trait_key is like 'tcp:ttl:64', 'tcp:window:65535', etc.
    """
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    os_totals: dict[str, int] = defaultdict(int)

    for os_name, d in records:
        os_totals[os_name] += 1

        # TTL
        if "ttl" in d:
            key = f"tcp:ttl:{d['ttl']}"
            counts[key][os_name] += 1

        # Window sizes (p0f single value, nmap list)
        windows = d.get("windows") or []
        if isinstance(d.get("window"), int):
            windows = [d["window"]]
        for w in windows:
            key = f"tcp:window:{w}"
            counts[key][os_name] += 1

        # Single window (from p0f)
        if "window" in d:
            key = f"tcp:window:{d['window']}"
            counts[key][os_name] += 1

        # MSS
        for m in d.get("mss_values", []):
            key = f"tcp:mss:{m}"
            counts[key][os_name] += 1
        if "mss" in d:
            key = f"tcp:mss:{d['mss']}"
            counts[key][os_name] += 1

        # Wscale
        for ws in d.get("wscale_values", []):
            key = f"tcp:wscale:{ws}"
            counts[key][os_name] += 1
        if "wscale" in d:
            key = f"tcp:wscale:{d['wscale']}"
            counts[key][os_name] += 1

        # Options patterns
        for kinds in d.get("opts_patterns", []):
            key = f"tcp:opts:{opts_list_to_trait_key(kinds)}"
            counts[key][os_name] += 1
        if "opts_kinds" in d:
            key = f"tcp:opts:{opts_list_to_trait_key(d['opts_kinds'])}"
            counts[key][os_name] += 1

        # Timestamp presence
        if "ts_present" in d:
            ts_key = "tcp:ts:present" if d["ts_present"] else "tcp:ts:absent"
            counts[ts_key][os_name] += 1

    return dict(counts), dict(os_totals)


def counts_to_scores(
    counts: dict[str, dict[str, int]],
    os_totals: dict[str, int],
    min_count: int = 2,
) -> dict[str, dict[str, float]]:
    """
    Convert raw counts to match scores 0.0–1.0.

    Score(OS, trait) = P(trait | OS) = count(OS, trait) / total(OS)
    Then normalize each trait so the highest P gets 1.0.

    Traits where total across all OS < min_count are dropped.
    """
    scores: dict[str, dict[str, float]] = {}

    for trait_key, os_counts in counts.items():
        # Filter OS not in our canonical set
        os_counts = {k: v for k, v in os_counts.items() if k in SATORI_OS}
        if not os_counts:
            continue

        total = sum(os_counts.values())
        if total < min_count:
            continue

        # P(trait | OS)
        prec = {}
        for os_name, cnt in os_counts.items():
            tot_os = os_totals.get(os_name, 1)
            prec[os_name] = cnt / max(tot_os, 1)

        # Normalize: highest P → 1.0
        max_p = max(prec.values())
        if max_p == 0:
            continue

        normalized = {k: round(v / max_p, 3) for k, v in prec.items()}

        # Only include OS with score ≥ 0.05 (noise floor)
        normalized = {k: v for k, v in normalized.items() if v >= 0.05}
        if normalized:
            scores[trait_key] = normalized

    return scores


# ─────────────────────────────────────────────────────────────────────────────
# Merge into v1.json
# ─────────────────────────────────────────────────────────────────────────────

def merge_into_v1(
    db_scores: dict[str, dict[str, float]],
    existing: dict,
    blend_weight: float = 0.3,
    verbose: bool = False,
) -> tuple[dict, int, int]:
    """
    Merge database-derived scores into the existing v1.json traits dict.

    Strategy:
    - For NEW trait keys not in v1.json: add them as-is (from DB)
    - For EXISTING trait keys: blend scores using blend_weight
        new_score = (1 - blend_weight) * existing_score + blend_weight * db_score
      for OS names present in both.  New OS names from DB are added at
      reduced confidence (blend_weight * db_score) if db_score >= 0.3.

    Returns (updated_traits_dict, new_count, updated_count)
    """
    traits = existing.get("traits", {})
    new_count = 0
    updated_count = 0

    for trait_key, db_matches in db_scores.items():
        if trait_key not in traits:
            # Brand new trait
            traits[trait_key] = {
                "comment": f"Imported from nmap/p0f database",
                "matches": db_matches,
            }
            new_count += 1
            if verbose:
                print(f"  NEW   {trait_key}: {db_matches}")
        else:
            # Existing trait — blend
            existing_matches = traits[trait_key].get("matches", {})
            blended = dict(existing_matches)

            changed = False
            for os_name, db_score in db_matches.items():
                if os_name in existing_matches:
                    old = existing_matches[os_name]
                    new_val = round(
                        (1 - blend_weight) * old + blend_weight * db_score, 3
                    )
                    if abs(new_val - old) >= 0.01:
                        blended[os_name] = new_val
                        changed = True
                else:
                    # New OS for this trait
                    if db_score >= 0.3:
                        blended[os_name] = round(blend_weight * db_score, 3)
                        changed = True

            if changed:
                traits[trait_key]["matches"] = blended
                updated_count += 1
                if verbose:
                    print(f"  BLEND {trait_key}: {existing_matches} → {blended}")

    existing["traits"] = traits
    return existing, new_count, updated_count


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Import nmap-os-db + p0f.fp into v1.json")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print results without writing v1.json")
    parser.add_argument("--verbose", action="store_true",
                        help="Verbose debug output")
    parser.add_argument("--blend-weight", type=float, default=0.3,
                        help="Weight for DB scores when blending with existing (0=keep existing, 1=use DB only)")
    parser.add_argument("--min-count", type=int, default=3,
                        help="Minimum total count for a trait to be included")
    args = parser.parse_args()

    print("═" * 60)
    print("Satori DB Importer")
    print("═" * 60)

    # ── Load p0f ─────────────────────────────────────────────────
    print(f"\nLoading p0f: {P0F_DB}")
    p0f_records = load_p0f(P0F_DB, verbose=args.verbose)
    print(f"  Parsed {len(p0f_records)} p0f SYN records")

    os_dist_p0f = defaultdict(int)
    for os_name, _ in p0f_records:
        os_dist_p0f[os_name] += 1
    for k, v in sorted(os_dist_p0f.items()):
        print(f"    {k}: {v}")

    # ── Load nmap ─────────────────────────────────────────────────
    print(f"\nLoading nmap-os-db: {NMAP_DB}")
    nmap_records = load_nmap(NMAP_DB, verbose=args.verbose)
    print(f"  Parsed {len(nmap_records)} nmap fingerprint records")

    os_dist_nmap = defaultdict(int)
    for os_name, _ in nmap_records:
        os_dist_nmap[os_name] += 1
    for k, v in sorted(os_dist_nmap.items()):
        print(f"    {k}: {v}")

    # ── Combine all records ────────────────────────────────────────
    all_records = p0f_records + nmap_records
    print(f"\nTotal records: {len(all_records)}")

    counts, os_totals = build_counts(all_records)
    print(f"Trait keys extracted: {len(counts)}")

    scores = counts_to_scores(counts, os_totals, min_count=args.min_count)
    print(f"Trait keys after scoring (min_count={args.min_count}): {len(scores)}")

    # Print summary by trait category
    cats: dict[str, int] = defaultdict(int)
    for k in scores:
        cats[":".join(k.split(":")[:2])] += 1
    for cat, n in sorted(cats.items()):
        print(f"  {cat}: {n}")

    # ── Load existing v1.json ──────────────────────────────────────
    print(f"\nLoading existing: {V1_JSON}")
    with open(V1_JSON, encoding="utf-8") as f:
        v1 = json.load(f)
    existing_trait_count = len(v1.get("traits", {}))
    print(f"  Existing traits: {existing_trait_count}")

    # ── Merge ──────────────────────────────────────────────────────
    updated_v1, new_count, blend_count = merge_into_v1(
        scores, v1,
        blend_weight=args.blend_weight,
        verbose=args.verbose,
    )
    final_trait_count = len(updated_v1.get("traits", {}))

    print(f"\nMerge results:")
    print(f"  New traits added: {new_count}")
    print(f"  Existing traits blended: {blend_count}")
    print(f"  Total traits after merge: {final_trait_count}")

    if args.dry_run:
        print("\n[dry-run] Not writing v1.json")
        # Show a few new traits
        print("\nSample new/changed traits:")
        for k, v in list(scores.items())[:20]:
            print(f"  {k}: {v}")
        return 0

    # ── Write v1.json ──────────────────────────────────────────────
    with open(V1_JSON, "w", encoding="utf-8") as f:
        json.dump(updated_v1, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"\nWrote {V1_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
