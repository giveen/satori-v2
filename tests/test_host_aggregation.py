from satori.host import HostRegistry
from satori.evidence import make_evidence


def test_host_id_stability_and_mac_enrichment():
    r = HostRegistry()
    h1 = r.get_or_create("192.0.2.1")
    id1 = h1.host_id
    # same IP again -> same host
    h2 = r.get_or_create("192.0.2.1")
    assert h2.host_id == id1

    # same IP with same MAC -> same host and mac added
    h3 = r.get_or_create("192.0.2.1", "aa:bb:cc:00:11:22")
    assert h3.host_id == id1
    assert "aa:bb:cc:00:11:22" in h3.macs

    # same IP with different MAC -> same host_id, mac list grows
    h4 = r.get_or_create("192.0.2.1", "11:22:33:44:55:66")
    assert h4.host_id == id1
    assert "11:22:33:44:55:66" in h4.macs

    # deterministic across registries when created with same primary only
    r2 = HostRegistry()
    h_r2 = r2.get_or_create("192.0.2.1")
    assert h_r2.host_id == id1

    # deterministic when created with same primary+secondary inputs across registries
    r3 = HostRegistry()
    h3a = r3.get_or_create("10.9.9.9", "aa:bb:cc:00:11:22")
    r4 = HostRegistry()
    h4a = r4.get_or_create("10.9.9.9", "aa:bb:cc:00:11:22")
    assert h3a.host_id == h4a.host_id


def test_evidence_routing_and_ordering():
    r = HostRegistry()
    h = r.get_or_create("10.0.0.5")
    ev1 = make_evidence("tcp_extractor", "tcp", "tcp.mss", 1400, 0.6, host_id=None, flow_id="f1", timestamp=1.0, provenance={"flow_id": "f1"})
    ev2 = make_evidence("tcp_extractor", "tcp", "tcp.window_size", 29200, 0.6, host_id=None, flow_id="f1", timestamp=2.0, provenance={"flow_id": "f1"})
    # simulate routing by adding evidence to host
    h.add_evidence(ev1)
    h.add_evidence(ev2)
    assert len(h.evidence) == 2
    assert h.evidence[0]["attribute"] == "tcp.mss"
    assert h.evidence[1]["attribute"] == "tcp.window_size"


def test_ambiguity_detection_nat_and_shared_ip():
    r = HostRegistry()
    h = r.get_or_create("198.51.100.7")
    # multiple distinct TTLs should set nat_suspected
    ev_ttl1 = make_evidence("tcp_extractor", "ip", "ip.ttl", 64, 0.5, host_id=None, flow_id="f1", timestamp=1.0, provenance={"flow_id": "f1"})
    ev_ttl2 = make_evidence("tcp_extractor", "ip", "ip.ttl", 128, 0.5, host_id=None, flow_id="f1", timestamp=2.0, provenance={"flow_id": "f1"})
    h.add_evidence(ev_ttl1)
    assert not h.ambiguity.get("nat_suspected")
    h.add_evidence(ev_ttl2)
    assert h.ambiguity.get("nat_suspected") is True

    # multiple distinct MSS/window also mark nat_suspected
    h2 = r.get_or_create("198.51.100.8")
    ev_mss1 = make_evidence("tcp_extractor", "tcp", "tcp.mss", 1460, 0.6, host_id=None, flow_id="f2", timestamp=3.0, provenance={"flow_id": "f2"})
    ev_mss2 = make_evidence("tcp_extractor", "tcp", "tcp.mss", 1200, 0.6, host_id=None, flow_id="f2", timestamp=4.0, provenance={"flow_id": "f2"})
    h2.add_evidence(ev_mss1)
    assert not h2.ambiguity.get("nat_suspected")
    h2.add_evidence(ev_mss2)
    assert h2.ambiguity.get("nat_suspected") is True

    # shared IP via multiple DHCP client ids
    h3 = r.get_or_create("203.0.113.5")
    ev_dhcp1 = make_evidence("dhcp_extractor", "udp", "dhcp.vendor_class_id", "vendorA", 0.4, host_id=None, flow_id="f3", timestamp=5.0, provenance={"flow_id": "f3"})
    ev_dhcp2 = make_evidence("dhcp_extractor", "udp", "dhcp.vendor_class_id", "vendorB", 0.4, host_id=None, flow_id="f3", timestamp=6.0, provenance={"flow_id": "f3"})
    h3.add_evidence(ev_dhcp1)
    assert not h3.ambiguity.get("shared_ip")
    h3.add_evidence(ev_dhcp2)
    assert h3.ambiguity.get("shared_ip") is True

    # multiple MACs seen in same host -> shared_ip
    h4 = r.get_or_create("203.0.113.6")
    ev_mac1 = make_evidence("meta", "link", "host.mac", "aa:aa:aa:aa:aa:aa", 0.5, host_id=None, flow_id="f4", timestamp=7.0, provenance={"flow_id": "f4"})
    ev_mac2 = make_evidence("meta", "link", "host.mac", "bb:bb:bb:bb:bb:bb", 0.5, host_id=None, flow_id="f4", timestamp=8.0, provenance={"flow_id": "f4"})
    h4.add_evidence(ev_mac1)
    assert not h4.ambiguity.get("shared_ip")
    h4.add_evidence(ev_mac2)
    assert h4.ambiguity.get("shared_ip") is True


def test_non_interference_between_hosts():
    r = HostRegistry()
    h1 = r.get_or_create("10.1.1.1")
    h2 = r.get_or_create("10.1.1.2")
    ev1 = make_evidence("tcp_extractor", "tcp", "tcp.mss", 1400, 0.6, host_id=None, flow_id="f1", timestamp=1.0, provenance={"flow_id": "f1"})
    h1.add_evidence(ev1)
    assert len(h1.evidence) == 1
    assert len(h2.evidence) == 0

    # adding new hosts should not mutate existing hosts' ip sets
    _ = r.get_or_create("10.1.1.3")
    assert "10.1.1.1" in h1.ips
