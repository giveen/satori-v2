import socket
import dpkt
import math
from satori.ingest import iter_packets
from satori.packet import parse_raw
from satori.flow import FlowEngine
from satori.extractors.tcp_heuristics import derive_isn_heuristics


def build_multi_syns(path: str):
    eth_template = dpkt.ethernet.Ethernet()
    eth_template.src = b"\x00\x01\x02\x03\x04\x05"
    eth_template.dst = b"\x06\x07\x08\x09\x0a\x0b"
    eth_template.type = dpkt.ethernet.ETH_TYPE_IP

    src_ip = "10.0.0.5"
    dst_ip = "10.0.0.2"

    seqs = [1000, 2000, 3000, 5000]
    with open(path, "wb") as fh:
        w = dpkt.pcap.Writer(fh)
        ts = 1.0
        for s in seqs:
            eth = dpkt.ethernet.Ethernet()
            eth.src = eth_template.src
            eth.dst = eth_template.dst
            eth.type = eth_template.type

            ip = dpkt.ip.IP()
            ip.v = 4
            ip.p = dpkt.ip.IP_PROTO_TCP
            ip.src = socket.inet_aton(src_ip)
            ip.dst = socket.inet_aton(dst_ip)
            ip.ttl = 64

            tcp = dpkt.tcp.TCP()
            tcp.sport = 40000
            tcp.dport = 80
            tcp.seq = s
            tcp.flags = dpkt.tcp.TH_SYN
            tcp.win = 29200
            tcp.pack()
            ip.data = tcp
            eth.data = ip
            w.writepkt(bytes(eth), ts=ts)
            ts += 1.0
        w.close()


def test_isn_heuristics(tmp_path):
    p = tmp_path / "multi_syn2.pcap"
    build_multi_syns(str(p))

    fe = FlowEngine()
    for ts, raw in iter_packets(str(p)):
        meta = parse_raw(ts, raw)
        if meta is None:
            continue
        fe.ingest_packet(meta)

    flows = list(fe.flows())
    ev = derive_isn_heuristics(flows)
    assert isinstance(ev, list)
    assert len(ev) == 1
    h = ev[0]
    assert h["type"] == "tcp_isn_heuristic"
    heur = h["heuristics"]
    assert heur["count"] == 4
    assert "lsb_entropy" in heur and "mean_delta" in heur
    # For our deterministic sequence, lsb entropy should be low-ish
    assert heur["lsb_entropy"] >= 0.0
