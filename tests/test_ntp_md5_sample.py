from satori.ingest import iter_packets
from satori.packet import parse_raw
from satori.flow import FlowEngine
from satori.extractors.ntp import extract_from_flow


def test_ntp_md5_sample_present():
    pcap = "tests/data/NTP_with_MD5_key_foobar.pcap"
    fe = FlowEngine()
    for ts, raw in iter_packets(pcap):
        meta = parse_raw(ts, raw)
        if meta is None:
            continue
        fe.ingest_packet(meta)

    flows = list(fe.flows())
    all_ev = []
    for f in flows:
        all_ev.extend(extract_from_flow(f))

    assert len(all_ev) >= 1

    # Expect at least one NTP evidence with MD5 auth present and timestamps
    found_md5 = False
    for e in all_ev:
        ntp = e.get("ntp") or {}
        assert "li_desc" in ntp
        assert "xmit_ts" in ntp
        if ntp.get("auth_md5_present"):
            found_md5 = True
            assert ntp.get("auth_md5") is not None

    assert found_md5, "No NTP MD5 auth was detected in the sample"
