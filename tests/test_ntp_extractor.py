import dpkt
import socket
from pathlib import Path
from satori.ingest import iter_packets
from satori.packet import parse_raw
from satori.flow import FlowEngine
from satori.extractors.ntp import extract_from_flow


def build_ntp_pcap(path: str):
    # Build a minimal Ethernet/IP/UDP packet containing an NTP header (48 bytes)
    eth_src = b"\x00\x01\x02\x03\x04\x05"
    eth_dst = b"\x06\x07\x08\x09\x0a\x0b"
    src_ip = "192.0.2.10"
    dst_ip = "198.51.100.5"
    src_port = 12345
    dst_port = 123

    # craft minimal NTP header: VN=4, mode=3 (client), stratum=0
    first = (4 << 3) | 3
    ntp_hdr = bytes([first, 0, 0, 0]) + b"\x00" * 44

    eth = dpkt.ethernet.Ethernet()
    eth.src = eth_src
    eth.dst = eth_dst
    eth.type = dpkt.ethernet.ETH_TYPE_IP

    ip = dpkt.ip.IP()
    ip.v = 4
    ip.p = dpkt.ip.IP_PROTO_UDP
    ip.src = socket.inet_aton(src_ip)
    ip.dst = socket.inet_aton(dst_ip)

    udp = dpkt.udp.UDP()
    udp.sport = src_port
    udp.dport = dst_port
    udp.data = ntp_hdr
    udp.ulen = 8 + len(udp.data)

    ip.data = udp
    eth.data = ip

    with open(path, "wb") as fh:
        writer = dpkt.pcap.Writer(fh)
        writer.writepkt(bytes(eth), ts=1.0)
        writer.close()


def test_ntp_extractor_synthetic(tmp_path):
    pcap_path = tmp_path / "ntp_synth.pcap"
    build_ntp_pcap(str(pcap_path))

    fe = FlowEngine()
    for ts, raw in iter_packets(str(pcap_path)):
        meta = parse_raw(ts, raw)
        if meta is None:
            continue
        fe.ingest_packet(meta)

    flows = list(fe.flows())
    assert len(flows) == 1

    all_evidence = []
    for f in flows:
        all_evidence.extend(extract_from_flow(f))

    assert len(all_evidence) >= 1
    e = all_evidence[0]
    assert e.get("type") == "ntp"
    assert "ntp" in e and "vn" in e["ntp"]
