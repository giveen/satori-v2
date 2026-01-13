import json
import os
from satori.cli import main


def test_cli_replay_writes_live_json_and_out(tmp_path):
    pcap = "tests/data/dhcp.pcap"
    out_live = tmp_path / "live.json"
    out_path = tmp_path / "out.json"

    # run CLI in replay mode using --pcap-file and request live JSON
    argv = ["analyze", pcap, "--pcap-file", pcap, "--out-live-json", str(out_live), "--out", str(out_path)]
    main(argv)

    # verify live snapshot file written and contains JSON
    assert out_live.exists()
    with open(out_live, 'r') as fh:
        data = json.load(fh)
    assert 'host' in data and 'stages' in data

    # verify final output written
    assert out_path.exists()
    with open(out_path, 'r') as fh:
        out = json.load(fh)
    assert out.get('pcap_file') is not None
