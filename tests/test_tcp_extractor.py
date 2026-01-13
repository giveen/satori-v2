import socket
from pathlib import Path
import dpkt

from satori.ingest import iter_packets
from satori.packet import parse_raw
from satori.flow import FlowEngine
from satori.extractors.tcp import extract_from_flow


def build_syn_pcap(path: str):
    eth = dpkt.ethernet.Ethernet()
    eth.src = b"\x00\x01\x02\x03\x04\x05"
    eth.dst = b"\x06\x07\x08\x09\x0a\x0b"
    eth.type = dpkt.ethernet.ETH_TYPE_IP

    ip = dpkt.ip.IP()
    ip.v = 4
    ip.p = dpkt.ip.IP_PROTO_TCP
    ip.src = socket.inet_aton("10.0.0.1")
    ip.dst = socket.inet_aton("10.0.0.2")
    ip.ttl = 64

    tcp = dpkt.tcp.TCP()
    tcp.sport = 49152
    tcp.dport = 80
    tcp.seq = 1000
    tcp.flags = dpkt.tcp.TH_SYN
    tcp.win = 29200
    # options: MSS(1460), NOP, NOP, WS(7), TS
    tcp.opts = b"\x02\x04\x05\xb4\x01\x01\x03\x03\x07\x08\x00\x00\x00\x00\x00\x00\x00\x00"
    tcp.off = 5 + (len(tcp.opts) + 3) // 4

    tcp.pack()
    ip.data = tcp
    eth.data = ip

    with open(path, "wb") as fh:
        w = dpkt.pcap.Writer(fh)
        w.writepkt(bytes(eth), ts=1.0)
        w.close()


def test_tcp_extractor_synthetic(tmp_path):
    p = tmp_path / "syn.pcap"
    build_syn_pcap(str(p))

    fe = FlowEngine()
    for ts, raw in iter_packets(str(p)):
        meta = parse_raw(ts, raw)
        if meta is None:
            continue
        fe.ingest_packet(meta)

    flows = list(fe.flows())
    assert len(flows) == 1

    ev = []
    for f in flows:
        ev.extend(extract_from_flow(f))

    assert len(ev) >= 1
    e = ev[0]
    assert e["type"] == "tcp"
    assert e["tcp"]["opts_order"][0] == 2  # MSS
    assert e["tcp"].get("mss") == 1460
    assert e["ip"]["ttl"] == 64
    # ISN captured from synthetic packet
    assert e["tcp"].get("isn") == 1000
    # ECN bits should not be set in this synthetic SYN
    assert e["tcp"]["ecn"]["ece"] is False
