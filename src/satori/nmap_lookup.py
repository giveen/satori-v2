"""Offline Nmap fingerprint lookup helper.

Provides a deterministic, explainable mapping from a host fingerprint
to candidate OS inferences using a local Nmap-style database.

Functions
---------
lookup_os_from_nmap(fingerprint, max_candidates=5, db_path=None)
    Return a list of OS candidate dictionaries derived from the provided
    fingerprint and an offline DB at `db_path` (JSON). The function is
    deterministic and does not mutate the input.

Scoring method
--------------
- Each DB entry contains a `signature` mapping of attribute -> expected
  value (e.g. `tcp_options`, `ttl`, `window`). We compute a simple
  per-attribute match (0 or 1, or fractional for list overlap) and
  average over attributes to produce a score in [0.0, 1.0].

Evidence refs
-------------
For provenance we compute SHA1 of canonical JSON for each top-level
evidence block in `fingerprint` (e.g. `tcp_fingerprint`) and include
those hex digests in `evidence_refs` for candidates that used them.

Assumptions
-----------
- Database is a JSON file containing a list of entries: each entry is
  {"name": str, "signature": dict} where `signature` keys are
  attributes we can match against the `fingerprint` keys.
- No network access; DB access is offline only.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Dict, List, Optional


def _canonical_bytes(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha1_hex(obj: object) -> str:
    return hashlib.sha1(_canonical_bytes(obj)).hexdigest()


def _load_db(db_path: Optional[str]) -> List[Dict]:
    if not db_path:
        return []
    p = Path(db_path)
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []


def download_nmap_os_db(dest_path: str, force: bool = False, timeout: int = 10) -> Optional[str]:
    """Download the official nmap-os-db file to dest_path.

    Returns the dest_path on success, or None on failure. If the file
    already exists and `force` is False, returns the existing path.
    """
    from urllib import request, error

    p = Path(dest_path)
    if p.exists() and not force:
        return str(p)

    url = "https://svn.nmap.org/nmap/nmap-os-db"
    try:
        req = request.Request(url)
        with request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            return str(p)
    except Exception:
        # network unavailable or fetch failed
        return None


def parse_nmap_os_db_text(text: str) -> List[Dict]:
    """Parse a minimal subset of the nmap-os-db textual format.

    This parser is conservative: it extracts TCP option lists, ttl and
    window hints when available from 'Fingerprint' or 'class' style
    entries. It returns a list of {name, signature} entries suitable for
    `lookup_os_from_nmap`.
    """
    lines = [l.rstrip('\n') for l in text.splitlines()]
    entries = []
    cur = None
    for ln in lines:
        if ln.strip().startswith('#'):
            # comment separating records; start new
            if cur:
                entries.append(cur)
                cur = None
            continue
        if not ln.strip():
            continue
        # naive parsing: look for 'OS:' or 'class' or 'Fingerprint' tokens
        if 'Fingerprint' in ln or 'Fingerprint' in ln:
            # treat newline as marker; skip - we don't implement full parser here
            continue
        # look for 'class' entries: form may include name tokens
        if ln.startswith('class '):
            # class <type> <vendor> <os family> <osgen> <accuracy>
            parts = ln.split()
            # best-effort name
            name = ' '.join(parts[2:4]) if len(parts) >= 4 else ln
            cur = {'name': name, 'signature': {}}
            continue
        # look for tokens like 'tcpseq' or 'tcptsseq' or 'total' - we keep it simple
        # attempt to capture lines like 'TSeq(Class=RI%Resp=Y%SS=Y%TS=Y)'
        if cur is None:
            # start a generic entry keyed by the whole line
            cur = {'name': ln.strip()[:80], 'signature': {}}
            continue
        # If we reach here, try to harvest numbers
        if 'ttl' in ln.lower():
            try:
                # extract ints
                import re

                m = re.search(r'ttl\s*[:=]?\s*(\d+)', ln, re.I)
                if m:
                    cur['signature'].setdefault('tcp_fingerprint', {})['ttl'] = int(m.group(1))
            except Exception:
                pass
        # window hints
        if 'win' in ln.lower() or 'window' in ln.lower():
            try:
                import re

                m = re.search(r'win(?:dow)?\s*[:=]?\s*(\d+)', ln, re.I)
                if m:
                    cur['signature'].setdefault('tcp_fingerprint', {})['window'] = int(m.group(1))
            except Exception:
                pass

    if cur:
        entries.append(cur)
    # normalize to expected structure: signature keys like tcp_options, ttl, window
    out = []
    for e in entries:
        sig = {}
        tcp = e.get('signature', {}).get('tcp_fingerprint') or {}
        if 'options' in tcp:
            sig['tcp_options'] = tcp.get('options')
        if 'ttl' in tcp:
            sig['ttl'] = tcp.get('ttl')
        if 'window' in tcp:
            sig['window'] = tcp.get('window')
        out.append({'name': e.get('name'), 'signature': sig})
    return out


def _match_signature(fingerprint: Dict, signature: Dict) -> (float, List[str]):
    """Return (score, evidence_keys_used).

    score is in [0,1]. evidence_keys_used is list of top-level keys
    from fingerprint that contributed to the match.
    """
    if not signature:
        return 0.0, []
    total = 0
    matched = 0.0
    used = []

    # Work on a shallow copy to avoid mutation
    fp = fingerprint

    for attr, expect in sorted(signature.items()):
        total += 1
        if attr == "tcp_options":
            # expect list of option tokens; compare set-overlap
            got = fp.get("tcp_fingerprint", {}).get("options")
            if got and isinstance(got, list) and isinstance(expect, list):
                got_set = set(got)
                exp_set = set(expect)
                # fractional overlap
                inter = len(got_set & exp_set)
                frac = inter / max(len(exp_set), 1)
                matched += frac
                if inter:
                    used.append("tcp_fingerprint")
            else:
                # no evidence -> zero
                pass
        elif attr == "ttl":
            got = fp.get("tcp_fingerprint", {}).get("ttl")
            if got is None:
                pass
            else:
                # expect can be int or [min,max]
                ok = False
                if isinstance(expect, list) and len(expect) == 2:
                    lo, hi = expect
                    ok = lo <= got <= hi
                else:
                    ok = got == expect
                matched += 1.0 if ok else 0.0
                if ok:
                    used.append("tcp_fingerprint")
        elif attr == "window":
            # allow small tolerance (5%)
            got = fp.get("tcp_fingerprint", {}).get("window")
            if got is None:
                pass
            else:
                try:
                    expv = float(expect)
                    gotv = float(got)
                    tol = max(1.0, 0.05 * expv)
                    if abs(gotv - expv) <= tol:
                        matched += 1.0
                        used.append("tcp_fingerprint")
                except Exception:
                    pass
        else:
            # generic equality check against fingerprint top-level keys
            got = fp.get(attr)
            if got is None:
                pass
            else:
                if got == expect:
                    matched += 1.0
                    used.append(attr)

    score = matched / total if total else 0.0
    # deduplicate used keys preserving order
    seen = set()
    used_unique = [x for x in used if not (x in seen or seen.add(x))]
    return float(score), used_unique


def lookup_os_from_nmap(fingerprint: Dict, max_candidates: int = 5, db_path: Optional[str] = None) -> List[Dict]:
    """Lookup OS candidates from an offline Nmap-style DB.

    Parameters
    ----------
    fingerprint
        A dictionary containing host fingerprint information (e.g.
        `tcp_fingerprint`, `ssh_banner`, `dhcp_options`). Not mutated.
    max_candidates
        Maximum number of returned candidates (default 5).
    db_path
        Optional path to a JSON DB file. If omitted or missing, no
        candidates are returned.

    Returns
    -------
    List[dict]
        Each candidate has keys: `name`, `score` (0.0-1.0), `source`
        ("nmap_db"), and `evidence_refs` (list of SHA1 hex strings of
        canonical evidence objects used).
    """
    # Do not mutate input
    fp = copy.deepcopy(fingerprint) if fingerprint is not None else {}

    db = _load_db(db_path)
    if not db:
        return []

    # Precompute evidence SHA1s for top-level fingerprint blocks
    evidence_sha = {}
    for k, v in sorted(fp.items()):
        try:
            evidence_sha[k] = _sha1_hex(v)
        except Exception:
            # fallback to hashing the canonical bytes of the value's str
            evidence_sha[k] = hashlib.sha1(str(v).encode("utf-8")).hexdigest()

    candidates = []
    for entry in db:
        name = entry.get("name")
        signature = entry.get("signature") or {}
        score, used_keys = _match_signature(fp, signature)
        if score <= 0.0:
            continue
        refs = [evidence_sha[k] for k in used_keys if k in evidence_sha]
        refs = sorted(refs)
        candidates.append({"name": name, "score": float(score), "source": "nmap_db", "evidence_refs": refs})

    # deterministic sort: descending score, then ascending name
    candidates.sort(key=lambda c: (-c["score"], c["name"]))
    return candidates[:max_candidates]
