import json
from pathlib import Path
import shutil

from satori.live_capture import capture_live
from satori.live_ingest import feed_live_evidence
from tests.utils_phase2 import sha1_of_obj, canonical_json_bytes


def _run_and_collect_snapshots(pcap, snapshot_dir, batch_size=1, ndjson=False):
    # ensure clean dir
    p = Path(snapshot_dir)
    if p.exists():
        shutil.rmtree(p)
    p.mkdir(parents=True, exist_ok=True)

    gen = capture_live(pcap_file=pcap)
    hosts = {}
    for h in feed_live_evidence(gen, apply_phases=(2, 3, 4, 5), snapshot_dir=str(p), snapshot_batch_size=batch_size, ndjson=ndjson, live_metrics=True):
        hosts[h['host_id']] = h

    # collect snapshot file hashes
    hashes = {}
    for f in sorted(p.glob('*.json')):
        b = f.read_bytes()
        # canonical bytes should already be written
        try:
            obj = json.loads(b.decode('utf-8'))
        except Exception:
            # ndjson: take first line
            obj = json.loads(b.splitlines()[0].decode('utf-8'))
        hashes[f.name] = sha1_of_obj(obj)
    return hashes


def test_incremental_snapshots_are_deterministic(tmp_path):
    pcap = 'tests/data/dhcp.pcap'
    sd = tmp_path / 'snap1'

    h1 = _run_and_collect_snapshots(pcap, sd, batch_size=1, ndjson=False)
    h2 = _run_and_collect_snapshots(pcap, sd, batch_size=1, ndjson=False)

    assert h1 == h2


def test_ndjson_mode_writes_and_hashes(tmp_path):
    pcap = 'tests/data/dhcp.pcap'
    sd = tmp_path / 'snap_nd'

    h = _run_and_collect_snapshots(pcap, sd, batch_size=1, ndjson=True)
    assert h, 'NDJSON snapshots should be produced'
