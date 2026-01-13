"""Live capture utilities with deterministic pcap replay for tests.

Provides `capture_live()` which yields normalized evidence dictionaries compatible
with Phase 1. For unit tests and deterministic runs, supply `pcap_file` to
replay an on-disk capture via the existing `iter_packets` reader. Live
interface capture is attempted via `scapy` if available but is optional.

Design notes:
- Replay mode (`pcap_file`) is deterministic (packet order by timestamp).
- Live mode (`interface`) yields packets as received; ordering is by capture
  timestamp if available. Live mode requires `scapy` and may be non-deterministic.
- All yielded evidence dicts are produced by `satori.evidence.make_evidence`
  so they conform to Phase 1 schema and can be SHA1'd by `phase2.evidence.evidence_sha1`.
"""
from __future__ import annotations

import time
import logging
from typing import Optional, Callable, Generator, List, Dict, Any
import os

from .ingest import iter_packets
from .packet import parse_raw
from .evidence import make_evidence
import dpkt

log = logging.getLogger("satori.live_capture")


def _yield_from_pcap(pcap_file: str, max_packets: Optional[int] = None) -> Generator[Dict[str, Any], None, None]:
    if not os.path.exists(pcap_file):
        raise RuntimeError(f"pcap file not found: {pcap_file}")
    idx = 0
    for ts, raw in iter_packets(pcap_file):
        pkt = parse_raw(ts, raw)
        if pkt is None:
            continue
        # build a minimal normalized evidence item per packet
        flow_id = f"{pkt.src_ip}:{pkt.src_port}-{pkt.dst_ip}:{pkt.dst_port}"
        ev = make_evidence(
            source="live_capture",
            protocol="tcp" if pkt.proto == getattr(pkt, "proto", None) or pkt.proto == 6 else ("udp" if pkt.proto == 17 else "ip"),
            attribute="ip.packet",
            value={"src_ip": pkt.src_ip, "dst_ip": pkt.dst_ip, "src_port": pkt.src_port, "dst_port": pkt.dst_port},
            confidence_hint=0.5,
            host_id=None,
            flow_id=flow_id,
            timestamp=ts,
            provenance={"pkt_index": idx},
        )
        yield ev
        # attempt to extract TCP SYN/options evidence to support fingerprinting
        try:
            eth = dpkt.ethernet.Ethernet(pkt.raw)
            ip = eth.data
            if isinstance(ip, dpkt.ip.IP) and getattr(ip, 'p', None) == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                flags = getattr(tcp, 'flags', 0) if hasattr(tcp, 'flags') else getattr(tcp, 'th_flags', 0)
                if flags & dpkt.tcp.TH_SYN:
                    # parse options from tcp raw header if present
                    try:
                        raw_tcp = bytes(tcp)
                        hdr_len = (getattr(tcp, 'off', 5) * 4)
                        opts_raw = raw_tcp[20:hdr_len] if len(raw_tcp) >= hdr_len else b""
                    except Exception:
                        opts_raw = b""

                    opt_kinds = []
                    mss = None
                    wscale = None
                    ts_present = False
                    i = 0
                    while i < len(opts_raw):
                        kind = opts_raw[i]
                        opt_kinds.append(kind)
                        if kind == 0:
                            break
                        if kind == 1:
                            i += 1
                            continue
                        if i + 1 >= len(opts_raw):
                            break
                        length = opts_raw[i + 1]
                        if length < 2:
                            break
                        val = opts_raw[i + 2 : i + length]
                        if kind == 2 and len(val) >= 2:
                            try:
                                mss = int.from_bytes(val[:2], 'big')
                            except Exception:
                                pass
                        if kind == 3 and len(val) >= 1:
                            try:
                                wscale = val[0]
                            except Exception:
                                pass
                        if kind == 8:
                            ts_present = True
                        i += length

                    provenance = {"pkt_index": idx}
                    try:
                        yield make_evidence('tcp_extractor', 'tcp', 'tcp.opts_order', opt_kinds, 0.6, None, flow_id, ts, provenance)
                        yield make_evidence('tcp_extractor', 'ip', 'ip.ttl', getattr(ip, 'ttl', None), 0.5, None, flow_id, ts, provenance)
                        yield make_evidence('tcp_extractor', 'tcp', 'tcp.window_size', getattr(tcp, 'win', None), 0.5, None, flow_id, ts, provenance)
                        if mss is not None:
                            yield make_evidence('tcp_extractor', 'tcp', 'tcp.mss', mss, 0.7, None, flow_id, ts, provenance)
                        if wscale is not None:
                            yield make_evidence('tcp_extractor', 'tcp', 'tcp.wscale', wscale, 0.7, None, flow_id, ts, provenance)
                        if ts_present:
                            yield make_evidence('tcp_extractor', 'tcp', 'tcp.ts_present', True, 0.7, None, flow_id, ts, provenance)
                        try:
                            yield make_evidence('tcp_extractor', 'tcp', 'tcp.isn', int(getattr(tcp, 'seq', None)), 0.6, None, flow_id, ts, provenance)
                        except Exception:
                            pass
                        try:
                            ece = bool(flags & dpkt.tcp.TH_ECE)
                            cwr = bool(flags & dpkt.tcp.TH_CWR)
                            yield make_evidence('tcp_extractor', 'tcp', 'tcp.ecn', {'ece': ece, 'cwr': cwr}, 0.5, None, flow_id, ts, provenance)
                        except Exception:
                            pass
                    except Exception:
                        pass
        except Exception:
            pass
        idx += 1
        if max_packets is not None and idx >= int(max_packets):
            break


def _sniff_live(interface: str, bpf_filter: Optional[str], max_packets: Optional[int], timeout: Optional[float]):
    try:
        from scapy.all import AsyncSniffer
    except Exception:
        raise RuntimeError("scapy not available for live sniffing")

    import collections
    queue = collections.deque()
    collected = 0

        def _prn(pkt):
        nonlocal collected
        ts = getattr(pkt, "time", time.time())
        raw = bytes(pkt)
        parsed = parse_raw(ts, raw)
        if parsed is None:
            return
        flow_id = f"{parsed.src_ip}:{parsed.src_port}-{parsed.dst_ip}:{parsed.dst_port}"
        ev = make_evidence(
            source="live_capture",
            protocol="tcp" if parsed.proto == 6 else ("udp" if parsed.proto == 17 else "ip"),
            attribute="ip.packet",
            value={"src_ip": parsed.src_ip, "dst_ip": parsed.dst_ip, "src_port": parsed.src_port, "dst_port": parsed.dst_port},
            confidence_hint=0.5,
            host_id=None,
            flow_id=flow_id,
            timestamp=ts,
            provenance={"live": True},
        )
        queue.append(ev)
            # also attempt TCP SYN/options extraction for live-sniffed packets
            try:
                eth = dpkt.ethernet.Ethernet(raw)
                ip = eth.data
                if isinstance(ip, dpkt.ip.IP) and getattr(ip, 'p', None) == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data
                    flags = getattr(tcp, 'flags', 0) if hasattr(tcp, 'flags') else getattr(tcp, 'th_flags', 0)
                    if flags & dpkt.tcp.TH_SYN:
                        try:
                            raw_tcp = bytes(tcp)
                            hdr_len = (getattr(tcp, 'off', 5) * 4)
                            opts_raw = raw_tcp[20:hdr_len] if len(raw_tcp) >= hdr_len else b""
                        except Exception:
                            opts_raw = b""

                        opt_kinds = []
                        mss = None
                        wscale = None
                        ts_present = False
                        i = 0
                        while i < len(opts_raw):
                            kind = opts_raw[i]
                            opt_kinds.append(kind)
                            if kind == 0:
                                break
                            if kind == 1:
                                i += 1
                                continue
                            if i + 1 >= len(opts_raw):
                                break
                            length = opts_raw[i + 1]
                            if length < 2:
                                break
                            val = opts_raw[i + 2 : i + length]
                            if kind == 2 and len(val) >= 2:
                                try:
                                    mss = int.from_bytes(val[:2], 'big')
                                except Exception:
                                    pass
                            if kind == 3 and len(val) >= 1:
                                try:
                                    wscale = val[0]
                                except Exception:
                                    pass
                            if kind == 8:
                                ts_present = True
                            i += length

                        provenance = {"live": True}
                        try:
                            queue.append(make_evidence('tcp_extractor', 'tcp', 'tcp.opts_order', opt_kinds, 0.6, None, flow_id, ts, provenance))
                            queue.append(make_evidence('tcp_extractor', 'ip', 'ip.ttl', getattr(ip, 'ttl', None), 0.5, None, flow_id, ts, provenance))
                            queue.append(make_evidence('tcp_extractor', 'tcp', 'tcp.window_size', getattr(tcp, 'win', None), 0.5, None, flow_id, ts, provenance))
                            if mss is not None:
                                queue.append(make_evidence('tcp_extractor', 'tcp', 'tcp.mss', mss, 0.7, None, flow_id, ts, provenance))
                            if wscale is not None:
                                queue.append(make_evidence('tcp_extractor', 'tcp', 'tcp.wscale', wscale, 0.7, None, flow_id, ts, provenance))
                            if ts_present:
                                queue.append(make_evidence('tcp_extractor', 'tcp', 'tcp.ts_present', True, 0.7, None, flow_id, ts, provenance))
                            try:
                                queue.append(make_evidence('tcp_extractor', 'tcp', 'tcp.isn', int(getattr(tcp, 'seq', None)), 0.6, None, flow_id, ts, provenance))
                            except Exception:
                                pass
                            try:
                                ece = bool(flags & dpkt.tcp.TH_ECE)
                                cwr = bool(flags & dpkt.tcp.TH_CWR)
                                queue.append(make_evidence('tcp_extractor', 'tcp', 'tcp.ecn', {'ece': ece, 'cwr': cwr}, 0.5, None, flow_id, ts, provenance))
                            except Exception:
                                pass
                        except Exception:
                            pass
            except Exception:
                pass
        collected += 1
        # if we've hit max_packets, request sniffer stop (handled in outer loop)
        try:
            if max_packets and collected >= int(max_packets):
                pass
        except Exception:
            pass

    sniffer = AsyncSniffer(iface=interface, filter=bpf_filter, prn=_prn, store=False)
    sniffer.start()
    try:
        import time as _time
        # stream out queued events as they arrive
        while sniffer.running:
            while queue:
                yield queue.popleft()
                # stop early if we've produced max_packets
                if max_packets and collected >= int(max_packets):
                    try:
                        sniffer.stop()
                    except Exception:
                        pass
                    break
            # small sleep to avoid busy loop
            _time.sleep(0.01)
        # drained any remaining
        while queue:
            yield queue.popleft()
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass


def capture_live(interface: Optional[str] = None, bpf_filter: Optional[str] = None, max_packets: Optional[int] = None, timeout: Optional[float] = None, pcap_file: Optional[str] = None, callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> Generator[Dict[str, Any], None, None]:
    """
    Capture live packets and yield normalized evidence dicts.

    Modes:
    - If `pcap_file` is provided, replay the file deterministically using `iter_packets`.
    - Otherwise attempt live capture on `interface` using scapy (if installed).

    Optional `callback` is invoked for each yielded evidence (for downstream processing).
    """
    try:
        if pcap_file:
            for ev in _yield_from_pcap(pcap_file, max_packets=max_packets):
                if callback:
                    try:
                        callback(ev)
                    except Exception:
                        log.exception("callback failed")
                yield ev
            return

        if interface is None:
            raise RuntimeError("no interface or pcap_file provided for capture")

        for ev in _sniff_live(interface, bpf_filter, max_packets, timeout):
            if callback:
                try:
                    callback(ev)
                except Exception:
                    log.exception("callback failed")
            yield ev

    except Exception as e:
        log.exception("live capture error: %s", e)
        # fail cleanly: stop generator
        return
