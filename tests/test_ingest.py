"""Unit tests for ingestion and flow engine.

Creates a tiny synthetic pcap with a single TCP SYN packet using dpkt, then
validates that `iter_packets` yields the packet and `FlowEngine` groups it.
"""
import tempfile
import os
import dpkt
import socket

from satori.ingest import iter_packets
from satori.flow import FlowEngine
from satori.packet import parse_raw


def build_syn_pcap(path: str):
    eth_src = b"\x00\x01\x02\x03\x04\x05"
    eth_dst = b"\x06\x07\x08\x09\x0a\x0b"
    src_ip = "192.0.2.1"
    dst_ip = "198.51.100.2"
    src_port = 12345
    dst_port = 80

    eth = dpkt.ethernet.Ethernet()
    eth.src = eth_src
    eth.dst = eth_dst
    eth.type = dpkt.ethernet.ETH_TYPE_IP

    ip = dpkt.ip.IP()
    ip.v = 4
    ip.p = dpkt.ip.IP_PROTO_TCP
    ip.src = socket.inet_aton(src_ip)
    ip.dst = socket.inet_aton(dst_ip)

    tcp = dpkt.tcp.TCP()
    tcp.sport = src_port
    tcp.dport = dst_port
    tcp.flags = dpkt.tcp.TH_SYN
    tcp.seq = 1000
    # minimal options: MSS
    tcp.off = 5

    ip.data = tcp
    eth.data = ip

    with open(path, "wb") as fh:
        writer = dpkt.pcap.Writer(fh)
        writer.writepkt(bytes(eth), ts=1.0)
        writer.close()


def test_iter_and_flow(tmp_path):
    pcap_path = os.path.join(tmp_path, "minimal_syn.pcap")
    build_syn_pcap(pcap_path)

    # confirm ingestion yields at least one packet
    pkts = list(iter_packets(pcap_path))
    assert len(pkts) >= 1

    ts, raw = pkts[0]
    meta = parse_raw(ts, raw)
    assert meta is not None

    fe = FlowEngine()
    fe.ingest_packet(meta)
    flows = list(fe.flows())
    assert len(flows) == 1
    f = flows[0]
    assert f.src_ip == "192.0.2.1"
    assert f.dst_ip == "198.51.100.2"
    assert f.src_port == 12345
    assert f.dst_port == 80
