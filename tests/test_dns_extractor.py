from pathlib import Path
from satori.ingest import iter_packets
from satori.packet import parse_raw
from satori.flow import FlowEngine
from satori.extractors.dns import extract_from_flow


def test_dns_extraction_from_sample():
    repo = Path(__file__).resolve().parents[1]
    pcap = repo / "tests" / "data" / "dns.cap"
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

    # Expect at least one DNS evidence from the sample pcap
    assert len(all_evidence) >= 1
    e = all_evidence[0]
    assert e.get("type") == "dns"
    assert "dns" in e and "queries" in e["dns"]
