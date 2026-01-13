import itertools
import copy
from pathlib import Path

from src.satori.live_capture import capture_live
from src.satori.phase2.evidence import evidence_sha1


def test_live_capture_replay_deterministic_and_schema():
    pcap = Path('tests/data/dns.cap')
    if not pcap.exists():
        # fallback to other small pcap if dns.cap not present
        pcap = Path('tests/data/dhcp.pcap')
    assert pcap.exists(), "No mini-pcap available for live capture test"

    # run twice and compare list of evidence SHA1s and order
    run1 = [e for i, e in zip(range(20), capture_live(pcap_file=str(pcap), max_packets=20))]
    run2 = [e for i, e in zip(range(20), capture_live(pcap_file=str(pcap), max_packets=20))]

    assert run1 and run2
    assert len(run1) == len(run2)

    sha1s1 = [evidence_sha1(e) for e in run1]
    sha1s2 = [evidence_sha1(e) for e in run2]

    assert sha1s1 == sha1s2

    # schema conformance: each evidence has required keys
    for ev in run1:
        assert isinstance(ev, dict)
        for k in ("schema_version", "source", "protocol", "attribute", "value", "timestamp"):
            assert k in ev


def test_live_capture_missing_pcap_handling():
    # missing file should raise RuntimeError
    try:
        gen = capture_live(pcap_file='tests/data/does_not_exist.pcap')
        items = list(gen)
        # if generator returns without raising, it should be empty
        assert items == []
    except RuntimeError:
        # acceptable behavior
        pass
