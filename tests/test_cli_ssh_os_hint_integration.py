import copy
import dataclasses
import json

from satori.host import Host
from satori.ssh_fingerprint import SSHFingerprint
from satori.ssh_os_hint import build_ssh_os_hint


def _host_to_cli_json(host: Host) -> dict:
    hints = build_ssh_os_hint(host)
    return {
        "host_id": host.host_id,
        "ssh_os_hint": [dataclasses.asdict(x) for x in hints],
    }


def _make_host(host_id: str, ssh_fp: SSHFingerprint | None, ambiguity: dict | None = None) -> Host:
    h = Host(host_id=host_id, ips=set(["10.0.0.1"]), macs=set(), first_seen=None, last_seen=None, evidence=[], flows=set(["flow1"]), ambiguity=ambiguity or {})
    h.ssh_fingerprint = ssh_fp
    return h


def test_cli_includes_ssh_os_hint_for_various_hosts():
    # clean host with OpenSSH
    sf1 = SSHFingerprint(
        ssh_banner=["OpenSSH_8.2p1"],
        ssh_software_family=["openssh"],
        kex_algorithms=[],
        hostkey_algorithms=[],
        encryption_algorithms_c2s=[],
        encryption_algorithms_s2c=[],
        mac_algorithms_c2s=[],
        mac_algorithms_s2c=[],
        compression_algorithms_c2s=[],
        compression_algorithms_s2c=[],
        first_kex_packet_follows_present=False,
        provenance={"software_family": ["flowA"], "banner": ["flowA"]},
        confidence=0.8,
    )
    h1 = _make_host("host:clean", sf1)

    # host with multiple banners/families
    sf2 = SSHFingerprint(
        ssh_banner=["OpenSSH_7.9", "Dropbear_2018"],
        ssh_software_family=["openssh", "dropbear"],
        kex_algorithms=[],
        hostkey_algorithms=[],
        encryption_algorithms_c2s=[],
        encryption_algorithms_s2c=[],
        mac_algorithms_c2s=[],
        mac_algorithms_s2c=[],
        compression_algorithms_c2s=[],
        compression_algorithms_s2c=[],
        first_kex_packet_follows_present=False,
        provenance={"software_family": ["f2"], "banner": ["f2"]},
        confidence=0.6,
    )
    h2 = _make_host("host:multi", sf2)

    # ambiguous host
    sf3 = SSHFingerprint(
        ssh_banner=["OpenSSH_8.0"],
        ssh_software_family=["openssh"],
        kex_algorithms=[],
        hostkey_algorithms=[],
        encryption_algorithms_c2s=[],
        encryption_algorithms_s2c=[],
        mac_algorithms_c2s=[],
        mac_algorithms_s2c=[],
        compression_algorithms_c2s=[],
        compression_algorithms_s2c=[],
        first_kex_packet_follows_present=False,
        provenance={"software_family": ["flowX"], "banner": ["flowX"]},
        confidence=0.8,
    )
    h3 = _make_host("host:ambig", sf3, ambiguity={"nat_suspected": True})

    # host with no ssh evidence
    h4 = _make_host("host:none", None)

    hosts = [h1, h2, h3, h4]

    # produce CLI-like JSON for each host twice to test determinism
    out1 = [_host_to_cli_json(h) for h in hosts]
    out2 = [_host_to_cli_json(copy.deepcopy(h)) for h in hosts]

    # Ensure every host has ssh_os_hint field present
    for o in out1:
        assert "ssh_os_hint" in o

    # h1: single OpenSSH -> Linux, confidence capped to 0.3
    h1_hint = out1[0]["ssh_os_hint"]
    assert len(h1_hint) == 1
    assert h1_hint[0]["os_family"] == "Linux"
    assert h1_hint[0]["confidence"] == 0.3
    assert h1_hint[0]["provenance"] == ["flowA"]

    # h2: two families -> Linux and Embedded-Linux, each confidence capped 0.3
    h2_hints = out1[1]["ssh_os_hint"]
    assert {x["os_family"] for x in h2_hints} == {"Linux", "Embedded-Linux"}
    assert all(x["confidence"] == 0.3 for x in h2_hints)
    for x in h2_hints:
        assert "f2" in x["provenance"]

    # h3: ambiguous host should see penalty applied (0.8*0.5*0.6 = 0.24)
    h3_hint = out1[2]["ssh_os_hint"]
    assert len(h3_hint) == 1
    assert h3_hint[0]["confidence"] == 0.24

    # h4: no ssh evidence -> empty list
    assert out1[3]["ssh_os_hint"] == []

    # Determinism: JSON dumps should be identical when sorted
    s1 = json.dumps(out1, sort_keys=True)
    s2 = json.dumps(out2, sort_keys=True)
    assert s1 == s2
