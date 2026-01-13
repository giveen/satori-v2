import json
import random
from pathlib import Path
from satori.phase2.traits import extract_traits


def _load_dhcp_host():
    p = Path('tests/output/dhcp.pcap.summary.json')
    j = json.loads(p.read_text())
    for h in j.get('hosts', []):
        if h.get('evidence'):
            return h
    return None


def test_dhcp_traits_prl_and_determinism():
    h = _load_dhcp_host()
    assert h is not None
    t1 = extract_traits(h)
    t2 = extract_traits(h)
    assert t1 == t2
    # should include parameter request list trait
    assert any(k.startswith('dhcp:prl:') for k in t1)


def test_dhcp_trait_order_invariant():
    h = _load_dhcp_host()
    assert h is not None
    base_evidence = list(h.get('evidence', []))
    # shuffle many times and ensure same trait set
    expected = extract_traits(h)
    for _ in range(5):
        ev = list(base_evidence)
        random.shuffle(ev)
        h2 = dict(h)
        h2['evidence'] = ev
        assert extract_traits(h2) == expected
