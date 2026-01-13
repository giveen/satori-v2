from pathlib import Path
from satori.ingest import iter_packets
from satori.packet import parse_raw
from satori.flow import FlowEngine
from satori.extractors.dhcp import extract_from_flow


def test_dhcp_extraction_from_sample():
    repo = Path(__file__).resolve().parents[1]
    pcap = repo / "tests" / "data" / "dhcp.pcap"
    assert pcap.exists()

    fe = FlowEngine()
    for ts, raw in iter_packets(str(pcap)):
        meta = parse_raw(ts, raw)
        if meta is None:
            continue
        fe.ingest_packet(meta)

    flows = list(fe.flows())
    assert len(flows) > 0

    all_evidence = []
    for f in flows:
        ev = extract_from_flow(f)
        if ev:
            all_evidence.extend(ev)

    # Expect at least one DHCP evidence from the sample pcap
    assert len(all_evidence) >= 1
    # Check evidence structure
    e = all_evidence[0]
    assert e.get("type") == "dhcp"
    assert "dhcp" in e and "options" in e["dhcp"]
