import socket
import dpkt

from satori.ingest import iter_packets
from satori.packet import parse_raw
from satori.flow import FlowEngine
from satori.extractors.ssh import extract_from_flow


def build_kexinit_pcap(path: str):
    # construct a minimal KEXINIT payload (message 20)
    cookie = b"\x00" * 16
    kex = b"diffie-hellman-group14-sha1"
    hostkey = b"ssh-rsa"

    def nl(b: bytes) -> bytes:
        return len(b).to_bytes(4, "big") + b

    # build payload starting with message id 20
    payload = b"\x14" + cookie + nl(kex) + nl(hostkey)
    # append empty name-lists for remaining fields to be well-formed
    for _ in range(8):
        payload += (0).to_bytes(4, "big")
    # follow with boolean and reserved
    payload += b"\x00" + (0).to_bytes(4, "big")

    eth = dpkt.ethernet.Ethernet()
    eth.src = b"\x00\x01\x02\x03\x04\x05"
    eth.dst = b"\x06\x07\x08\x09\x0a\x0b"
    eth.type = dpkt.ethernet.ETH_TYPE_IP

    ip = dpkt.ip.IP()
    ip.v = 4
    ip.p = dpkt.ip.IP_PROTO_TCP
    ip.src = socket.inet_aton("192.0.2.7")
    ip.dst = socket.inet_aton("198.51.100.11")
    ip.ttl = 64

    tcp = dpkt.tcp.TCP()
    tcp.sport = 22
    tcp.dport = 54322
    tcp.seq = 1
    tcp.flags = dpkt.tcp.TH_ACK
    tcp.data = payload
    tcp.pack()

    ip.data = tcp
    eth.data = ip

    with open(path, "wb") as fh:
        w = dpkt.pcap.Writer(fh)
        w.writepkt(bytes(eth), ts=1.0)
        w.close()


def test_ssh_kex_parsing(tmp_path):
    p = tmp_path / "ssh_kex.pcap"
    build_kexinit_pcap(str(p))

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
    assert "kexinit" in e["ssh"]
    assert "diffie-hellman-group14-sha1" in e["ssh"]["kexinit"]["kex_algorithms"]
    assert "ssh-rsa" in e["ssh"]["kexinit"]["server_host_key_algorithms"]
