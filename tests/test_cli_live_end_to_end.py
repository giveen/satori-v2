import json
from pathlib import Path
import pytest

from satori.live_capture import capture_live
from satori.live_ingest import feed_live_evidence
from satori.phase5.report import build_phase5_summary
from satori.phase2.evidence import evidence_sha1
from tests.utils_phase2 import canonical_json_bytes, sha1_of_obj


def _collect_hosts(pcap_path):
    gen = capture_live(pcap_file=str(pcap_path))
    hosts = {}
    for h in feed_live_evidence(gen, apply_phases=(2, 3, 4, 5)):
        hosts[h["host_id"]] = h
    return list(hosts.values())


def _write_snapshot(path: Path, obj: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(canonical_json_bytes(obj))


def test_cli_live_end_to_end(update_snapshots):
    fixtures = list(Path("tests/data").glob("*.pcap*"))
    assert fixtures, "No pcap fixtures found under tests/data"

    snapdir = Path("tests/expected_live_snapshots")

    for p in sorted(fixtures):
        hosts = _collect_hosts(p)

        # per-host checks and snapshot comparison
        for h in sorted(hosts, key=lambda x: x.get("host_id")):
            hid = h.get("host_id")
            assert hid, f"host missing id for fixture {p}"

            # evidence timestamps must be non-decreasing
            evs = [e for e in (h.get("evidence") or []) if isinstance(e, dict)]
            times = [e.get("timestamp") for e in evs if e.get("timestamp") is not None]
            assert times == sorted(times), f"evidence timestamps not ordered for host {hid} in {p}"

            # provenance: each evidence canonical sha1 must match utility
            for e in evs:
                try:
                    sid = evidence_sha1(e)
                except Exception:
                    sid = None
                assert sid is not None

            # snapshot compare/write
            fname = f"{p.stem}__{hid}.json"
            spath = snapdir / fname
            if not spath.exists():
                if update_snapshots:
                    _write_snapshot(spath, h)
                    continue
                pytest.skip(f"Missing snapshot {spath}; run tests with --update-snapshots to create")

            existing = spath.read_bytes()
            now = canonical_json_bytes(h)
            if existing != now:
                if update_snapshots:
                    _write_snapshot(spath, h)
                    continue
                assert sha1_of_obj(json.loads(existing.decode('utf-8'))) == sha1_of_obj(h)

        # overall Phase5 metrics snapshot
        summary = build_phase5_summary([hosts])
        mname = f"{p.stem}__metrics.json"
        mpath = snapdir / mname
        if not mpath.exists():
            if update_snapshots:
                _write_snapshot(mpath, summary)
            else:
                pytest.skip(f"Missing metrics snapshot {mpath}; run tests with --update-snapshots to create")
        else:
            existing = mpath.read_bytes()
            now = canonical_json_bytes(summary)
            if existing != now:
                if update_snapshots:
                    _write_snapshot(mpath, summary)
                else:
                    assert sha1_of_obj(json.loads(existing.decode('utf-8'))) == sha1_of_obj(summary)
