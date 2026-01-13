import itertools
import logging

from satori.live_capture import capture_live
from satori.live_ingest import feed_live_evidence
from satori.evidence import make_evidence
from tests.utils_phase2 import sha1_of_obj


def _collect_final_states(evidence_gen):
    hosts = {}
    for host in feed_live_evidence(evidence_gen, apply_phases=(2,)):
        hosts[host["host_id"]] = host
    return hosts


def test_replay_is_deterministic():
    # replay a small PCAP twice and ensure final host states are identical
    pcap = "tests/data/dhcp.pcap"
    gen1 = capture_live(pcap_file=pcap)
    s1 = _collect_final_states(gen1)

    gen2 = capture_live(pcap_file=pcap)
    s2 = _collect_final_states(gen2)

    # canonical sha1 per host_id should match between runs
    ids1 = {hid: sha1_of_obj(h) for hid, h in s1.items()}
    ids2 = {hid: sha1_of_obj(h) for hid, h in s2.items()}

    assert ids1 == ids2


def test_callback_invoked_and_exceptions_are_handled():
    pcap = "tests/data/dhcp.pcap"
    calls = []

    def cb(host, stages):
        calls.append((host["host_id"], stages.get("phase2") is not None))
        # simulate transient failure on first call
        if len(calls) == 1:
            raise RuntimeError("callback fail")

    gen = capture_live(pcap_file=pcap)
    # run ingest with callback; should not raise despite first callback failure
    hosts = {}
    for h in feed_live_evidence(gen, callback=cb, apply_phases=(2,)):
        hosts[h["host_id"]] = h

    assert calls, "callback should have been invoked"
    # subsequent calls must have succeeded (no exception escapes)
    assert len(hosts) >= 1


def test_malformed_evidence_is_skipped_and_processing_continues():
    # create a tiny generator mixing a valid evidence, a malformed item, and another valid
    e1 = make_evidence(source="test", protocol="udp", attribute="ip.packet", value={"src_ip": "10.0.0.1"}, timestamp=1.0)
    bad = "not-a-dict"
    e2 = make_evidence(source="test", protocol="udp", attribute="ip.packet", value={"src_ip": "10.0.0.1"}, timestamp=2.0)

    def gen():
        yield e1
        yield bad
        yield e2

    hosts = {}
    for h in feed_live_evidence(gen(), apply_phases=(2,)):
        hosts[h["host_id"]] = h

    # both valid evidence items should be present in final host evidence
    assert hosts, "hosts should be created"
    h = list(hosts.values())[0]
    assert len(h.get("evidence", [])) == 2
