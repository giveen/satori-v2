import socket
import dpkt

from satori.ingest import iter_packets
from satori.packet import parse_raw
from satori.flow import FlowEngine
from satori.extractors.ssh import extract_from_flow


def build_ssh_banner_pcap(path: str):
    eth = dpkt.ethernet.Ethernet()
    eth.src = b"\x00\x01\x02\x03\x04\x05"
    eth.dst = b"\x06\x07\x08\x09\x0a\x0b"
    eth.type = dpkt.ethernet.ETH_TYPE_IP

    ip = dpkt.ip.IP()
    ip.v = 4
    ip.p = dpkt.ip.IP_PROTO_TCP
    ip.src = socket.inet_aton("192.0.2.5")
    ip.dst = socket.inet_aton("198.51.100.10")
    ip.ttl = 64

    tcp = dpkt.tcp.TCP()
    tcp.sport = 22
    tcp.dport = 54321
    tcp.seq = 1
    tcp.flags = dpkt.tcp.TH_ACK
    banner = b"SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\n"
    tcp.data = banner
    tcp.ulen = 20 + len(tcp.data)
    tcp.pack()

    ip.data = tcp
    eth.data = ip

    with open(path, "wb") as fh:
        w = dpkt.pcap.Writer(fh)
        w.writepkt(bytes(eth), ts=1.0)
        w.close()


def test_ssh_extractor_banner(tmp_path):
    p = tmp_path / "ssh_banner.pcap"
    build_ssh_banner_pcap(str(p))

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

    assert len(ev) == 1
    e = ev[0]
    assert e["type"] == "ssh"
    assert "OpenSSH" in e["ssh"]["banner"]
