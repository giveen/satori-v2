import json
from satori.cli import main
from pathlib import Path


def _run_cli(argv):
    # capture printed output by temporarily redirecting stdout
    import io, sys
    stdout = sys.stdout
    try:
        buf = io.StringIO()
        sys.stdout = buf
        main(argv)
        return buf.getvalue()
    finally:
        sys.stdout = stdout


def test_cli_live_stdout_deterministic():
    pcap = "tests/data/dhcp.pcap"
    argv = ["analyze", pcap, "--pcap-file", pcap, "--live-stdout"]
    out1 = _run_cli(argv)
    out2 = _run_cli(argv)
    # outputs should be identical across repeated runs
    assert out1 == out2
    # should contain at least one JSON object per run
    assert "{\"host_id\"" in out1
